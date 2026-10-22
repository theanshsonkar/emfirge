"""L50 resource tags: collected, branch-replaced within AWS limits, handed back exactly."""
import boto3
import pytest
from moto import mock_aws

from app.aws_api_ingest import translate_api_calls
from app.aws_collector import collect_ec2, collect_rds, collect_s3
from app.diffing import diff_infrastructure
from app.mutations import Change, apply_change, apply_changes
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

REGION = "us-east-1"
INSTANCE, GROUP, BUCKET, DB = "i-dl-web", "sg-dl-web", "dl-data-bucket", "db-dl-prod"


def tagged_base(**overrides):
    """The synthetic base with tags collected (as a current scan would have them)."""
    base = load_synthetic_base("delete")
    data = base.model_dump(mode="json")
    defaults = {"team": "web"}
    for section, key in (("ec2", "instances"), ("ec2", "security_groups"), ("ec2", "ebs_volumes"),
                         ("rds", "rds_instances"), ("s3", "buckets"), ("lambda_data", "functions")):
        for item in data[section][key]:
            item["tags"] = dict(overrides.get(item.get("id") or item.get("name"), defaults))
    return type(base).model_validate(data)


def tag(resource_type, ident, tags):
    return Change(op="modify", resource_type=resource_type, resource_id=ident, fields={"tags": tags})


def find(infra, ident):
    for items in (infra.ec2.instances, infra.ec2.security_groups, infra.rds.rds_instances, infra.s3.buckets,
                  infra.lambda_data.functions, infra.vpc.nat_gateway_details):
        for item in items:
            if (getattr(item, "id", None) or getattr(item, "name", None)) == ident:
                return item
    raise KeyError(ident)


@pytest.mark.parametrize("resource_type,ident", [
    ("ec2_instance", INSTANCE), ("security_group", GROUP), ("rds_instance", DB),
    ("s3_bucket", BUCKET), ("lambda_function", "dl-worker")])
def test_L50a_tags_are_a_complete_replacement_on_every_modifiable_type(resource_type, ident):
    base = tagged_base()
    branch = apply_change(base, tag(resource_type, ident, {"env": "prod"}))
    assert find(branch, ident).tags == {"env": "prod"} and find(base, ident).tags == {"team": "web"}
    cleared = apply_change(branch, tag(resource_type, ident, {}))
    assert find(cleared, ident).tags == {}


def test_L50b_aws_limits_and_reserved_prefix():
    base = tagged_base(**{INSTANCE: {"team": "web", "aws:cloudformation:stack-name": "app"}})
    for bad in (
        {f"k{i}": "v" for i in range(51)},
        {"": "v"},
        {"k" * 129: "v"},
        {"k": "v" * 257},
        {"aws:owner": "me"},
        {"aws:cloudformation:stack-name": "other"},
        {"k": 1},
        None,
        ["k"],
    ):
        with pytest.raises(ValueError):
            apply_change(base, tag("ec2_instance", INSTANCE, bad))
    # 50 user tags are fine; aws: tags do not count and are kept even when not listed.
    fifty = {f"k{i}": "v" for i in range(50)}
    branch = apply_change(base, tag("ec2_instance", INSTANCE, fifty))
    assert find(branch, INSTANCE).tags == {**fifty, "aws:cloudformation:stack-name": "app"}
    same = apply_change(base, tag("ec2_instance", INSTANCE, {"aws:cloudformation:stack-name": "app"}))
    assert find(same, INSTANCE).tags == {"aws:cloudformation:stack-name": "app"}


def test_L50c_adds_start_untagged_unless_tags_are_given():
    base = tagged_base()
    plain = apply_change(base, Change(op="add", resource_type="security_group", resource_id="sg-l50", fields={"name": "l50"}))
    assert find(plain, "sg-l50").tags == {}
    given = apply_change(base, Change(op="add", resource_type="security_group", resource_id="sg-l50", fields={"name": "l50", "tags": {"team": "x"}}))
    assert find(given, "sg-l50").tags == {"team": "x"}
    nat = apply_change(base, Change(op="add", resource_type="nat_gateway", resource_id="nat-l50",
                                    fields={"subnet_id": "subnet-dl-pub", "allocation_id": "eipalloc-l50", "tags": {"Name": "egress"}}))
    assert find(nat, "nat-l50").tags == {"Name": "egress"}


def test_L50d_tag_change_is_in_the_diff_and_never_changes_reachability_or_findings():
    base = tagged_base()
    branch = apply_changes(base, [tag("ec2_instance", INSTANCE, {"env": "prod"}), tag("s3_bucket", BUCKET, {})])
    diff = diff_infrastructure(base, branch)
    modified = {item["id"] for item in diff.resources_modified} if hasattr(diff, "resources_modified") else set()
    assert {INSTANCE, BUCKET} <= modified
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.native_added == [] and result.native_removed == []
    assert result.newly_internet_reachable == [] and result.no_longer_internet_reachable == []
    assert result.verdict == "pass", result.reasons


def test_L50e_tag_change_warns_when_iam_conditions_could_read_tags():
    base = tagged_base()
    data = base.model_dump(mode="json")
    data["iam"]["role_policies"][0]["access_statements"][0]["has_condition"] = True
    abac = type(base).model_validate(data)
    result = combined_verdict(abac, apply_change(abac, tag("ec2_instance", INSTANCE, {"env": "prod"})), run_scanners=False)
    assert result.verdict == "warn"
    reason = next(item for item in result.reasons if item["code"] == "tag_change_access_unmodeled")
    assert reason["resources"] == [INSTANCE]
    # The same conditions with no tag change raise nothing.
    untouched = combined_verdict(abac, apply_change(abac, tag("ec2_instance", INSTANCE, {"team": "web"})), run_scanners=False)
    assert all(item["code"] != "tag_change_access_unmodeled" for item in untouched.reasons)


def test_L50f_handback_is_exact():
    base = tagged_base(**{INSTANCE: {"team": "web", "old": "x"}, GROUP: {"team": "web"}})
    calls = build_api_calls(base, [tag("ec2_instance", INSTANCE, {"team": "api", "env": "prod"})])
    assert [(c["operation"], c["params"]) for c in calls] == [
        ("CreateTags", {"Resources": [INSTANCE], "Tags": [{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "api"}]}),
        ("DeleteTags", {"Resources": [INSTANCE], "Tags": [{"Key": "old"}]}),
    ]
    assert build_api_calls(base, [tag("security_group", GROUP, {"team": "web"})]) == []
    put = build_api_calls(base, [tag("s3_bucket", BUCKET, {"b": "2", "a": "1"})])
    assert [(c["operation"], c["params"]) for c in put] == [
        ("PutBucketTagging", {"Bucket": BUCKET, "Tagging": {"TagSet": [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}]}})]
    assert [c["operation"] for c in build_api_calls(base, [tag("s3_bucket", BUCKET, {})])] == ["DeleteBucketTagging"]
    nat = build_api_calls(base, [Change(op="add", resource_type="nat_gateway", resource_id="nat-l50",
                                        fields={"subnet_id": "subnet-dl-pub", "allocation_id": "eipalloc-l50", "tags": {"Name": "egress"}})])
    assert nat[0]["params"]["TagSpecifications"] == [{"ResourceType": "natgateway", "Tags": [{"Key": "Name", "Value": "egress"}]}]


@pytest.mark.parametrize("change,base_factory", [
    # Tags not collected: a replacement would need to know what to delete.
    (tag("ec2_instance", INSTANCE, {"env": "prod"}), lambda: load_synthetic_base("delete")),
    (tag("s3_bucket", BUCKET, {"env": "prod"}), lambda: load_synthetic_base("delete")),
    # PutBucketTagging would drop AWS-managed tags.
    (tag("s3_bucket", BUCKET, {"env": "prod"}), lambda: tagged_base(**{BUCKET: {"aws:cloudformation:stack-name": "app"}})),
    # RDS and Lambda tagging calls need the resource ARN.
    (tag("rds_instance", DB, {"env": "prod"}), tagged_base),
    (tag("lambda_function", "dl-worker", {"env": "prod"}), tagged_base),
])
def test_L50f_handback_gaps_stay_visible(change, base_factory):
    with pytest.raises(UnmappableChanges):
        build_api_calls(base_factory(), [change])


def test_L50g_collector_reads_tags_and_scan_equals_branch(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        ec2, s3 = boto3.client("ec2", region_name=REGION), boto3.client("s3", region_name=REGION)
        group = ec2.create_security_group(GroupName="l50", Description="l50", TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "team", "Value": "web"}]}])["GroupId"]
        image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        instance = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "team", "Value": "web"}, {"Key": "old", "Value": "x"}]}])["Instances"][0]["InstanceId"]
        s3.create_bucket(Bucket="l50-bucket")
        s3.create_bucket(Bucket="l50-untagged")
        s3.put_bucket_tagging(Bucket="l50-bucket", Tagging={"TagSet": [{"Key": "team", "Value": "data"}]})
        boto3.client("rds", region_name=REGION).create_db_instance(
            DBInstanceIdentifier="l50-db", DBInstanceClass="db.t3.micro", Engine="postgres",
            MasterUsername="u", MasterUserPassword="password123", AllocatedStorage=20,
            Tags=[{"Key": "team", "Value": "db"}])

        def scan():
            base = load_synthetic_base("delete")
            return type(base).model_validate({**base.model_dump(),
                "ec2": collect_ec2(None, None, None, REGION, []).model_dump(),
                "s3": collect_s3(None, None, None, REGION, []).model_dump(),
                "rds": collect_rds(None, None, None, REGION, []).model_dump()})

        before = scan()
        assert find(before, instance).tags == {"team": "web", "old": "x"}
        assert find(before, group).tags == {"team": "web"}
        assert (find(before, "l50-bucket").tags, find(before, "l50-untagged").tags) == ({"team": "data"}, {})
        assert find(before, "l50-db").tags == {"team": "db"}
        changes = [tag("ec2_instance", instance, {"team": "api", "env": "prod"}),
                   tag("s3_bucket", "l50-bucket", {"team": "data", "tier": "1"})]
        branch = apply_changes(before, changes)
        for item in build_api_calls(before, changes):
            client = boto3.client(item["service"], region_name=REGION)
            getattr(client, "".join("_" + ch.lower() if ch.isupper() else ch for ch in item["operation"]).lstrip("_"))(**item["params"])
        after = scan()
        for ident in (instance, "l50-bucket"):
            assert find(after, ident).tags == find(branch, ident).tags


def test_L50h_inputs_map_to_the_same_tag_change():
    api = translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "s3", "operation": "PutBucketTagging", "parameters": {"Bucket": BUCKET, "Tagging": {"TagSet": [{"Key": "env", "Value": "prod"}]}}},
        {"service": "s3", "operation": "DeleteBucketTagging", "parameters": {"Bucket": BUCKET}},
    ]})
    assert api["changes"] == [tag("s3_bucket", BUCKET, {"env": "prod"}), tag("s3_bucket", BUCKET, {})]
    plan = {"format_version": "1.2", "resource_changes": [{
        "address": "aws_s3_bucket.data", "type": "aws_s3_bucket", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": ["update"],
                   "before": {"bucket": BUCKET, "tags": {"env": "dev"}, "tags_all": {"env": "dev", "owner": "ops"}},
                   "after": {"bucket": BUCKET, "tags": {"env": "prod"}, "tags_all": {"env": "prod", "owner": "ops"}},
                   "after_unknown": {}}}]}
    result = translate_plan(plan)
    assert [c.fields for c in result["changes"]] == [{"tags": {"env": "prod", "owner": "ops"}}]


def test_L50h_ec2_create_tags_without_base_state_stays_visible():
    # CreateTags merges into tags we would need to read first; it stays an unmodeled change.
    result = translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "ec2", "operation": "CreateTags", "parameters": {"Resources": [INSTANCE], "Tags": [{"Key": "a", "Value": "b"}]}}]})
    assert result["changes"] == [] and result["unmodeled"]


def test_L50i_legacy_snapshot_without_tags_still_loads_and_branches():
    base = load_synthetic_base("delete")
    assert find(base, INSTANCE).tags is None
    branch = apply_change(base, tag("ec2_instance", INSTANCE, {"env": "prod"}))
    assert find(branch, INSTANCE).tags == {"env": "prod"}
