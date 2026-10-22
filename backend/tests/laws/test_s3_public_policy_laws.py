"""L49 public-by-policy S3 buckets: AWS's meaning of public, collected and branched alike."""
import json

import boto3
import pytest
from moto import mock_aws

from app.aws_collector import collect_s3
from app.mutations import Change, apply_change, apply_changes, mutation_capabilities
from app.s3_public import policy_is_public
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

BUCKET = "dl-data-bucket"
REGION = "us-east-1"


def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(principal="*", condition=None, effect="Allow", **extra):
    statement = {"Effect": effect, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{BUCKET}/*", **extra}
    if principal is not None:
        statement["Principal"] = principal
    if condition is not None:
        statement["Condition"] = condition
    return statement


PUBLIC = doc(allow())
PRIVATE = doc(allow({"AWS": "arn:aws:iam::111122223333:root"}))

POLICY_TABLE = [
    ("principal star", doc(allow()), True),
    ("AWS star", doc(allow({"AWS": "*"})), True),
    ("AWS list with star", doc(allow({"AWS": ["arn:aws:iam::111122223333:root", "*"]})), True),
    ("wildcard account principal", doc(allow({"AWS": "arn:aws:iam::*:root"})), True),
    ("fixed account principal", PRIVATE, False),
    ("service principal", doc(allow({"Service": "cloudtrail.amazonaws.com"})), False),
    ("NotPrincipal", doc(allow(None, NotPrincipal={"AWS": "arn:aws:iam::111122223333:root"})), True),
    ("deny only", doc(allow(effect="Deny")), False),
    ("deny star plus fixed allow", doc(allow(effect="Deny"), allow({"AWS": "arn:aws:iam::111122223333:root"})), False),
    ("one public statement among private ones", doc(allow({"Service": "cloudtrail.amazonaws.com"}), allow()), True),
    ("source vpce fixed", doc(allow(condition={"StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}})), False),
    ("source vpc wildcard", doc(allow(condition={"StringLike": {"aws:SourceVpc": "vpc-*"}})), True),
    ("source account fixed", doc(allow(condition={"StringEquals": {"aws:SourceAccount": "111122223333"}})), False),
    ("source arn fixed", doc(allow(condition={"ArnEquals": {"aws:SourceArn": "arn:aws:cloudfront::111122223333:distribution/E1"}})), False),
    ("org id fixed", doc(allow(condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})), False),
    ("source ip /24", doc(allow(condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})), False),
    ("source ip /8", doc(allow(condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})), False),
    ("source ip /1", doc(allow(condition={"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}})), True),
    ("source ip one broad of two", doc(allow(condition={"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "0.0.0.0/0"]}})), True),
    ("source ipv6 /32", doc(allow(condition={"IpAddress": {"aws:SourceIp": "2001:db8::/32"}})), False),
    ("source ipv6 /16", doc(allow(condition={"IpAddress": {"aws:SourceIp": "2001::/16"}})), True),
    ("negated operator", doc(allow(condition={"StringNotEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}})), True),
    ("not ip address", doc(allow(condition={"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}})), True),
    ("if exists", doc(allow(condition={"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1a2b3c4d"}})), True),
    ("unknown key", doc(allow(condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})), True),
    ("secure transport only", doc(allow(condition={"Bool": {"aws:SecureTransport": "true"}})), True),
    ("policy variable", doc(allow(condition={"StringEquals": {"aws:userid": "${aws:username}"}})), True),
    ("userid role wildcard", doc(allow(condition={"StringLike": {"aws:userid": "AROAEXAMPLE:*"}})), True),
    ("access point arn any name fixed account", doc(allow(condition={"StringLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-east-1:111122223333:accesspoint/*"}})), False),
    ("access point arn any account", doc(allow(condition={"StringLike": {"s3:DataAccessPointArn": "arn:aws:s3:us-east-1:*:accesspoint/*"}})), True),
    ("ForAllValues does not limit", doc(allow(condition={"ForAllValues:StringEquals": {"aws:SourceVpce": ["vpce-1a2b3c4d"]}})), True),
    ("ForAnyValue fixed limits", doc(allow(condition={"ForAnyValue:StringEquals": {"aws:SourceVpce": ["vpce-1a2b3c4d"]}})), False),
    ("single statement object", json.dumps({"Statement": allow()}), True),
    ("no statements", json.dumps({"Version": "2012-10-17", "Statement": []}), False),
]


@pytest.mark.parametrize("policy,expected", [(p, e) for _, p, e in POLICY_TABLE], ids=[n for n, _, _ in POLICY_TABLE])
def test_L49a_policy_table_follows_aws_meaning_of_public(policy, expected):
    assert policy_is_public(policy) is expected


@pytest.mark.parametrize("policy", ["not json", "[1, 2]", "\"text\""])
def test_L49a_invalid_policy_raises(policy):
    with pytest.raises(ValueError):
        policy_is_public(policy)


@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


def _scan():
    data = collect_s3(None, None, None, REGION, [])
    return data, {bucket.name: bucket for bucket in data.buckets}


def test_L49b_collector_reads_policy_acl_and_block_public_access(aws):
    for name in ("l49-policy", "l49-restricted", "l49-acl", "l49-auth", "l49-ignored", "l49-private"):
        aws.create_bucket(Bucket=name)
    for name in ("l49-policy", "l49-restricted"):
        aws.put_bucket_policy(Bucket=name, Policy=doc(allow(Resource=f"arn:aws:s3:::{name}/*")))
    aws.put_public_access_block(Bucket="l49-restricted", PublicAccessBlockConfiguration={"RestrictPublicBuckets": True})
    aws.put_bucket_acl(Bucket="l49-acl", ACL="public-read")
    aws.put_bucket_acl(Bucket="l49-auth", ACL="authenticated-read")
    aws.put_bucket_acl(Bucket="l49-ignored", ACL="public-read")
    aws.put_public_access_block(Bucket="l49-ignored", PublicAccessBlockConfiguration={"IgnorePublicAcls": True})
    data, buckets = _scan()
    assert sorted(data.public_buckets) == ["l49-acl", "l49-auth", "l49-policy"]
    assert (buckets["l49-policy"].policy_public, buckets["l49-policy"].acl_public, buckets["l49-policy"].is_public) == (True, False, True)
    assert (buckets["l49-restricted"].policy_public, buckets["l49-restricted"].restrict_public_buckets, buckets["l49-restricted"].is_public) == (True, True, False)
    assert (buckets["l49-ignored"].acl_public, buckets["l49-ignored"].ignore_public_acls, buckets["l49-ignored"].is_public) == (True, True, False)
    assert (buckets["l49-private"].policy_public, buckets["l49-private"].acl_public, buckets["l49-private"].block_public_policy) == (False, False, False)


def test_L49b_account_level_block_public_access_applies_to_every_bucket(aws):
    aws.create_bucket(Bucket="l49-acl")
    aws.put_bucket_acl(Bucket="l49-acl", ACL="public-read")
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    boto3.client("s3control", region_name=REGION).put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration={"IgnorePublicAcls": True, "BlockPublicPolicy": True})
    data, buckets = _scan()
    assert data.public_buckets == []
    assert (buckets["l49-acl"].ignore_public_acls, buckets["l49-acl"].block_public_policy, buckets["l49-acl"].restrict_public_buckets) == (True, True, False)


def modify(fields, ident=BUCKET):
    return Change(op="modify", resource_type="s3_bucket", resource_id=ident, fields=fields)


def bucket(infra, name=BUCKET):
    return next(item for item in infra.s3.buckets if item.name == name)


def collected_base(**parts):
    """The synthetic base with its bucket in the collected (non-legacy) shape."""
    defaults = {"acl_public": False, "policy_public": False, "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False}
    base = load_synthetic_base("delete")
    data = base.model_dump(mode="json")
    data["s3"]["buckets"][0].update({**defaults, **parts})
    return type(base).model_validate(data)


def test_L49c_branch_policy_change_recomputes_is_public_both_ways():
    base = collected_base()
    public = apply_change(base, modify({"policy": PUBLIC}))
    assert (bucket(public).policy_public, bucket(public).is_public) == (True, True)
    assert BUCKET in public.s3.public_buckets and BUCKET not in base.s3.public_buckets
    private = apply_change(public, modify({"policy": PRIVATE}))
    assert (bucket(private).policy_public, bucket(private).is_public, private.s3.public_buckets) == (False, False, [])
    removed = apply_change(public, modify({"policy": None}))
    assert (bucket(removed).policy_public, bucket(removed).is_public) == (False, False)


def test_L49c_block_public_access_settings_change_is_public():
    base = collected_base(restrict_public_buckets=True)
    restricted = apply_change(base, modify({"policy": PUBLIC}))
    assert (bucket(restricted).policy_public, bucket(restricted).is_public) == (True, False)
    lifted = apply_change(restricted, modify({"restrict_public_buckets": False}))
    assert bucket(lifted).is_public is True and BUCKET in lifted.s3.public_buckets
    acl = apply_change(collected_base(), modify({"acl_public": True}))
    assert bucket(acl).is_public is True
    ignored = apply_change(acl, modify({"ignore_public_acls": True}))
    assert bucket(ignored).is_public is False


def test_L49c_rejections():
    with pytest.raises(ValueError, match="BlockPublicPolicy"):
        apply_change(collected_base(block_public_policy=True), modify({"policy": PUBLIC}))
    with pytest.raises(ValueError, match="BlockPublicPolicy"):
        apply_change(collected_base(), modify({"policy": PUBLIC, "block_public_policy": True}))
    # Turning BlockPublicPolicy on does not touch an existing public policy (AWS keeps it).
    kept = apply_change(apply_change(collected_base(), modify({"policy": PUBLIC})), modify({"block_public_policy": True}))
    assert bucket(kept).is_public is True
    with pytest.raises(ValueError, match="is_public"):
        apply_change(collected_base(), modify({"policy": PUBLIC, "is_public": False}))
    with pytest.raises(ValueError, match="is_public"):
        apply_change(collected_base(), modify({"policy": PRIVATE, "is_public": True}))
    with pytest.raises(ValueError, match="JSON"):
        apply_change(collected_base(), modify({"policy": "not json"}))
    with pytest.raises(ValueError, match="policy_public"):
        apply_change(collected_base(), modify({"policy_public": True}))
    caps = {entry.resource_type: entry for entry in mutation_capabilities().resources}
    assert any(c.kind == "derived_field" and c.fields == ["policy_public"] for c in caps["s3_bucket"].constraints)
    consistent = apply_change(collected_base(), modify({"policy": PUBLIC, "is_public": True}))
    assert bucket(consistent).is_public is True


def test_L49c_direct_is_public_without_policy_stays_allowed():
    base = load_synthetic_base("delete")
    branch = apply_change(base, modify({"is_public": True}))
    assert bucket(branch).is_public is True and BUCKET in branch.s3.public_buckets


def test_L49c_legacy_snapshot_keeps_its_acl_answer_through_stacked_changes():
    base = load_synthetic_base("delete")
    assert bucket(base).acl_public is None and bucket(base).policy_public is None
    public = apply_changes(base, [modify({"policy": PUBLIC}), modify({"policy": PRIVATE})])
    assert bucket(public).is_public is False, "a policy made public then private again must not stay public"
    data = base.model_dump(mode="json")
    data["s3"]["buckets"][0]["is_public"] = True  # old ACL-derived answer
    data["s3"]["public_buckets"] = [BUCKET]
    legacy_public = type(base).model_validate(data)
    still = apply_change(legacy_public, modify({"policy": PRIVATE}))
    assert (bucket(still).acl_public, bucket(still).is_public) == (True, True)


def test_L49c_add_with_policy_is_evaluated():
    base = load_synthetic_base("delete")
    added = apply_change(base, Change(op="add", resource_type="s3_bucket", resource_id="l49-new",
                                      fields={"policy": doc(allow(Resource="arn:aws:s3:::l49-new/*"))}))
    assert (bucket(added, "l49-new").policy_public, bucket(added, "l49-new").is_public) == (True, True)
    assert "l49-new" in added.s3.public_buckets
    with pytest.raises(ValueError, match="BlockPublicPolicy"):
        apply_change(base, Change(op="add", resource_type="s3_bucket", resource_id="l49-blocked",
                                  fields={"policy": PUBLIC, "block_public_policy": True}))


def test_L49d_scan_equals_branch(aws):
    aws.create_bucket(Bucket=BUCKET)
    from app.models import AWSInfrastructure
    base_s3, _ = _scan()
    base = AWSInfrastructure.model_validate({**load_synthetic_base("delete").model_dump(), "s3": base_s3.model_dump()})
    branch = apply_change(base, modify({"policy": PUBLIC}))
    aws.put_bucket_policy(Bucket=BUCKET, Policy=PUBLIC)
    after, buckets = _scan()
    fields = ("is_public", "policy", "acl_public", "policy_public", "block_public_acls",
              "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
    assert {f: getattr(bucket(branch), f) for f in fields} == {f: getattr(buckets[BUCKET], f) for f in fields}
    assert branch.s3.public_buckets == after.public_buckets == [BUCKET]


def test_L49e_public_policy_blocks_the_verdict():
    base = collected_base()
    branch = apply_change(base, modify({"policy": PUBLIC}))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "block", result.reasons
    assert {(item["rule_id"], item["resource_id"]) for item in result.native_added} >= {("EMFIRGE-S3-001", BUCKET)}
    restricted = collected_base(restrict_public_buckets=True)
    assert combined_verdict(restricted, apply_change(restricted, modify({"policy": PUBLIC})), run_scanners=False).verdict != "block"


def test_L49f_handback_maps_policy_and_block_public_access():
    base = collected_base()
    put = modify({"policy": PUBLIC})
    assert [(c["service"], c["operation"]) for c in build_api_calls(base, [put])] == [("s3", "PutBucketPolicy")]
    bpa = build_api_calls(base, [modify({"restrict_public_buckets": True, "policy": PUBLIC})])
    assert [c["operation"] for c in bpa] == ["PutPublicAccessBlock", "PutBucketPolicy"]
    assert bpa[0]["params"]["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": True}
    # Unknown settings (older snapshot) would be sent as False and could switch a real setting off.
    with pytest.raises(UnmappableChanges):
        build_api_calls(load_synthetic_base("delete"), [modify({"restrict_public_buckets": True})])


def test_L49g_api_rejects_a_public_policy_under_block_public_policy(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = collected_base(block_public_policy=True)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l49-api", "name": "l49-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    rejected = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "s3_bucket", "resource_id": BUCKET, "fields": {"policy": PUBLIC}})
    assert rejected.status_code == 422, rejected.text
    for fields in ({"block_public_policy": False}, {"policy": PUBLIC}):
        response = client.post(f"/branches/{branch_id}/changes", json={
            "op": "modify", "resource_type": "s3_bucket", "resource_id": BUCKET, "fields": fields})
        assert response.status_code == 200, response.text
    assert client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "block"


def test_L49h_api_ingest_maps_bucket_policy_and_block_public_access_calls():
    from app.aws_api_ingest import translate_api_calls

    def ingest(operation, parameters):
        return translate_api_calls({"format": "aws-api-calls/1", "calls": [
            {"service": "s3", "operation": operation, "parameters": parameters}]})

    put = ingest("PutBucketPolicy", {"Bucket": BUCKET, "Policy": PUBLIC})
    assert put["changes"] == [modify({"policy": PUBLIC})] and put["unmodeled"] == []
    as_object = ingest("PutBucketPolicy", {"Bucket": BUCKET, "Policy": json.loads(PUBLIC)})
    assert policy_is_public(as_object["changes"][0].fields["policy"])
    assert ingest("DeleteBucketPolicy", {"Bucket": BUCKET})["changes"] == [modify({"policy": None})]
    bpa = ingest("PutPublicAccessBlock", {"Bucket": BUCKET, "PublicAccessBlockConfiguration": {"RestrictPublicBuckets": True}})
    assert bpa["changes"] == [modify({"block_public_acls": False, "ignore_public_acls": False,
                                      "block_public_policy": False, "restrict_public_buckets": True})]
    # Incomplete calls stay visible as unmodeled risky changes, never a silent pass.
    incomplete = ingest("PutBucketPolicy", {})
    assert incomplete["changes"] == [] and incomplete["unmodeled"][0]["risk"] == "risky"
    base = collected_base()
    branch = apply_changes(base, put["changes"])
    assert branch.s3.public_buckets == [BUCKET]
    assert combined_verdict(base, branch, run_scanners=False).verdict == "block"


def test_L49h_cli_gives_the_same_change_as_the_api():
    from app.aws_api_ingest import translate_api_calls
    from app.aws_cli_ingest import parse_cli_commands

    cli = translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [
        f"aws s3api put-bucket-policy --bucket {BUCKET} --policy '{PUBLIC}'",
        f"aws s3api put-public-access-block --bucket {BUCKET} --public-access-block-configuration "
        "'{\"BlockPublicPolicy\": true, \"RestrictPublicBuckets\": true}'",
    ]}))
    assert cli["changes"] == [modify({"policy": PUBLIC}), modify({
        "block_public_acls": False, "ignore_public_acls": False,
        "block_public_policy": True, "restrict_public_buckets": True})]
