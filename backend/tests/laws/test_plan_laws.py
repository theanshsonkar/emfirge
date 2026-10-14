from tests.incidents.synthetic_base import load_synthetic_base
import json
import shlex

import botocore.session
from botocore import xform_name
from hypothesis import HealthCheck, given, settings, strategies as st

from app import plan_ingest
from tests.test_plan_ingest import _post, plan_client  # noqa: F401


aws_provider = st.one_of(
    st.sampled_from([
        "registry.terraform.io/hashicorp/aws",
        "registry.opentofu.org/hashicorp/aws",
        "registry.terraform.io/hashicorp/awscc",
        "registry.terraform.io/hashicorp/AWS",
    ]),
    st.none(),
)
unmodeled_aws_type = st.one_of(
    st.sampled_from([
        "aws_dynamodb_table", "aws_efs_file_system", "aws_rds_cluster", "aws_kms_key",
        "aws_secretsmanager_secret", "aws_sqs_queue", "awscc_rds_db_cluster",
    ]),
    st.from_regex(r"aws_[a-z]{3,12}", fullmatch=True),
    st.from_regex(r"awscc_[a-z]{3,12}", fullmatch=True),
).filter(lambda t: t not in plan_ingest._RESOURCE_MAP)
non_aws_word = st.one_of(
    st.sampled_from(["random", "null", "local", "tls", "time", "http", "kubernetes",
                     "google", "azurerm", "cloudflare"]),
    st.from_regex(r"[a-z]{2,10}", fullmatch=True),
).filter(lambda w: w not in {"aws", "awscc"})
non_aws_provider = st.builds(
    lambda host, ns, name: f"{host}/{ns}/{name}",
    st.sampled_from(["registry.terraform.io", "registry.opentofu.org"]),
    st.one_of(st.sampled_from(["hashicorp", "example"]), st.from_regex(r"[a-z]{2,8}", fullmatch=True)),
    non_aws_word,
)
non_aws_type = st.one_of(
    st.builds(lambda name, suffix: f"{name}_{suffix}", non_aws_word,
              st.from_regex(r"[a-z]{2,8}", fullmatch=True)),
    st.sampled_from(sorted(plan_ingest._RESOURCE_MAP)),
)
any_action = st.sampled_from([["create"], ["update"], ["delete"], ["delete", "create"], ["create", "delete"]])
delete_action = st.sampled_from([["delete"], ["delete", "create"], ["create", "delete"]])
aws_nondelete_action = st.sampled_from([["create"], ["update"]])
before_after = st.dictionaries(
    st.from_regex(r"[a-z]{1,8}", fullmatch=True),
    st.one_of(st.integers(-5, 5), st.booleans(), st.text(alphabet="abcxyz", max_size=6)),
    max_size=3,
)


def _entry(address, typ, provider, actions, before, after):
    result = {"address": address, "mode": "managed", "type": typ, "name": "x",
              "change": {"actions": actions, "before": before, "after": after}}
    if provider is not None:
        result["provider_name"] = provider
    return result


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(data=st.data())
def test_L10_unmodeled_aws_delete_or_replace_blocks(plan_client, monkeypatch, data):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    provider = data.draw(aws_provider)
    typ = data.draw(unmodeled_aws_type)
    actions = data.draw(delete_action)
    required = (typ, provider, actions, data.draw(before_after), data.draw(before_after))
    extras = []
    for _ in range(data.draw(st.integers(0, 4))):
        if data.draw(st.booleans()):
            extras.append((data.draw(non_aws_type), data.draw(non_aws_provider),
                           data.draw(any_action), data.draw(before_after), data.draw(before_after)))
        else:
            extras.append((data.draw(unmodeled_aws_type), data.draw(aws_provider),
                           data.draw(aws_nondelete_action), data.draw(before_after), data.draw(before_after)))
    entries = extras[:]
    entries.insert(data.draw(st.integers(0, len(entries))), required)
    payload = {"format_version": "1.2", "resource_changes": [
        _entry(f"{typ}.r{index}", typ, provider, actions, before, after)
        for index, (typ, provider, actions, before, after) in enumerate(entries)
    ]}
    branch_id, _, response = _post(plan_client, payload)
    assert response.status_code == 200
    assert len(response.json()["unmodeled"]) == len(entries)
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert "unmodeled_delete" in {reason["code"] for reason in result["reasons"]}


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(data=st.data(), entries=st.lists(
    st.tuples(non_aws_provider, non_aws_type, any_action, before_after, before_after),
    min_size=1, max_size=5,
))
def test_L11_non_aws_provider_warns_never_blocks_never_passes(plan_client, monkeypatch, data, entries):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    payload = {"format_version": "1.2", "resource_changes": [
        _entry(f"{typ}.r{index}", typ, provider, actions, before, after)
        for index, (provider, typ, actions, before, after) in enumerate(entries)
    ]}
    branch_id, _, response = _post(plan_client, payload)
    assert response.status_code == 200
    body = response.json()
    assert body["applied"] == []
    assert len(body["unmodeled"]) == len(entries)
    assert all(item["outside_view"] is True for item in body["unmodeled"])
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "warn"
    assert {reason["code"] for reason in result["reasons"]} == {"outside_view"}


def test_L15_terraform_and_aws_api_deletions_are_equivalent(plan_client):
    def compare(terraform_item, api_call):
        tf_branch, _, tf_response = _post(plan_client, {"format_version": "1.0", "resource_changes": [terraform_item]})
        assert tf_response.status_code == 200, tf_response.text
        tf_body = tf_response.json()
        assert tf_body["applied"]
        assert tf_body["rejected"] == []
        api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "aws-api-law"}).json()["branch_id"]
        api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [api_call]})
        assert api_response.status_code == 200, api_response.text
        api_body = api_response.json()
        assert api_body["applied"]
        assert api_body["rejected"] == []
        tf_verdict = plan_client.get(f"/branches/{tf_branch}/verdict").json()
        api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
        tf_reasons = {(item["code"], item["level"]) for item in tf_verdict["reasons"]}
        assert tf_reasons
        assert tf_reasons == {(item["code"], item["level"]) for item in api_verdict["reasons"]}
        assert tf_verdict["verdict"] == api_verdict["verdict"]

    compare(
        {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
         "change": {"actions": ["delete"], "before": {"identifier": "db-dl-prod", "skip_final_snapshot": True, "delete_automated_backups": True}, "after": None}},
        {"service": "rds", "operation": "DeleteDBInstance", "parameters": {"DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True, "DeleteAutomatedBackups": True}},
    )
    compare(
        {"address": "aws_instance.instance", "mode": "managed", "type": "aws_instance",
         "change": {"actions": ["delete"], "before": {"id": "i-dl-web"}, "after": None}},
        {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}},
    )



def test_L16_terraform_and_aws_api_public_ssh_are_equivalent(plan_client):
    base = load_synthetic_base("delete")
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-dl-web")
    before = [{"from_port": rule.get("from_port"), "to_port": rule.get("to_port"),
               "protocol": rule.get("protocol"), "cidr_blocks": rule.get("ip_ranges", []),
               "security_groups": rule.get("source_sg_ids", [])} for rule in sg.rules]
    public_ssh = {"from_port": 22, "to_port": 22, "protocol": "tcp",
                  "cidr_blocks": ["0.0.0.0/0"], "security_groups": []}
    tf_branch, _, tf_response = _post(plan_client, {"format_version": "1.0", "resource_changes": [{
        "address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group",
        "name": "web", "change": {"actions": ["update"], "before": {"id": sg.id, "ingress": before},
        "after": {"id": sg.id, "ingress": before + [public_ssh]}}}]})
    assert tf_response.status_code == 200, tf_response.text
    tf_body = tf_response.json()
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l16-api"}).json()["branch_id"]
    api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{"service": "ec2",
        "operation": "AuthorizeSecurityGroupIngress", "parameters": {"GroupId": sg.id,
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}}]})
    assert api_response.status_code == 200, api_response.text
    api_body = api_response.json()
    for body in (tf_body, api_body):
        assert body["applied"] and body["rejected"] == []
    tf_verdict = plan_client.get(f"/branches/{tf_branch}/verdict").json()
    api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
    assert tf_verdict["verdict"] == api_verdict["verdict"]
    assert {(r["code"], r["level"]) for r in tf_verdict["reasons"]}
    assert {(r["code"], r["level"]) for r in tf_verdict["reasons"]} == {(r["code"], r["level"]) for r in api_verdict["reasons"]}


@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(prefix=st.one_of(
    st.sampled_from(["Delete", "Terminate", "Purge", "Deregister", "Release", "Remove",
                     "Detach", "Disassociate", "Revoke", "Stop", "Disable", "Create",
                     "Put", "Tag", "Start", "Modify", "Update", "Attach", "Associate",
                     "Enable", "Run"]),
    st.builds(lambda suffix: "Put" + suffix + "Policy",
              st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True)),
    st.builds(lambda suffix: "Put" + suffix + "Acl",
              st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True)),
), suffix=st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True))
def test_L16_unmapped_aws_call_block_rule(plan_client, monkeypatch, prefix, suffix):
    from app import branches
    from app.aws_api_ingest import _DELETE_PREFIXES, _MAPPED
    import re

    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    operation = prefix + suffix
    assert not any((service, operation) in _MAPPED for service in ("custom", "ec2", "s3", "iam", "rds", "lambda"))
    risky = operation.startswith(("Detach", "Disassociate", "Revoke", "Stop", "Disable")) or bool(re.fullmatch(r"Put[A-Za-z0-9]*(Policy|Acl)", operation))
    delete = operation.startswith(_DELETE_PREFIXES)
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "aws-api-law"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [
        {"service": "custom", "operation": operation, "parameters": {}}
    ]})
    assert response.status_code == 200, response.text
    reasons = plan_client.get(f"/branches/{branch_id}/verdict").json()["reasons"]
    expected = "unmodeled_delete" if delete else "unmodeled_risky_change" if risky else "unmodeled_change"
    expected_level = "block" if delete or risky else "warn"
    assert any(reason["code"] == expected and reason["level"] == expected_level for reason in reasons)
    assert "pass" not in {reason["code"] for reason in reasons}


def _l18_model(service, operation):
    return botocore.session.get_session().get_service_model(service).operation_model(operation)


def _l18_render_call(call):
    service = "s3api" if call["service"] == "s3" else call["service"]
    operation = call["operation"]
    model = _l18_model(call["service"], operation)
    members = model.input_shape.members if model.input_shape else {}
    command = f"aws {service} {xform_name(operation, '-')} "
    for name, value in call.get("parameters", {}).items():
        member = members[name]
        option = f"--{xform_name(name, '-')}"
        if member.type_name == "boolean":
            command += option if value else f"--no-{xform_name(name, '-')}"
        elif member.type_name == "list" and member.member.type_name not in {"structure", "map"}:
            command += option + " " + " ".join(shlex.quote(str(item)) for item in value)
        elif member.type_name in {"structure", "map"} or (member.type_name == "list" and member.member.type_name in {"structure", "map"}):
            command += option + " " + shlex.quote(json.dumps(value))
        else:
            command += option + " " + shlex.quote(str(value))
        command += " "
    return command.rstrip()


def _l18_sg_permission(data):
    ports = data.draw(st.one_of(st.sampled_from([22, 3389, 443]), st.integers(1, 65535)))
    ipv4 = data.draw(st.lists(st.sampled_from(["0.0.0.0/0", "10.0.0.0/8"]), min_size=0, max_size=2, unique=True))
    ipv6 = data.draw(st.lists(st.just("::/0"), min_size=0, max_size=1, unique=True))
    if not ipv4 and not ipv6:
        ipv4 = ["0.0.0.0/0"]
    permission = {"IpProtocol": "tcp", "FromPort": ports, "ToPort": ports}
    if ipv4:
        permission["IpRanges"] = [{"CidrIp": value} for value in ipv4]
    if ipv6:
        permission["Ipv6Ranges"] = [{"CidrIpv6": value} for value in ipv6]
    return permission


def _l18_call(data, ids):
    instance_id, volume_id, snapshot_id, group_id, db_id, bucket, function, role = ids
    kind = data.draw(st.sampled_from([
        "TerminateInstances", "DeleteVolume", "DeleteSnapshot", "DeleteSecurityGroup",
        "DeleteDBInstance", "ModifyDBInstance", "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress", "DeleteBucket", "DeleteFunction", "DeleteRole", "unmapped",
    ]))
    if kind == "TerminateInstances":
        return {"service": "ec2", "operation": kind, "parameters": {"InstanceIds": [instance_id]}}
    if kind == "DeleteVolume":
        return {"service": "ec2", "operation": kind, "parameters": {"VolumeId": volume_id}}
    if kind == "DeleteSnapshot":
        return {"service": "ec2", "operation": kind, "parameters": {"SnapshotId": snapshot_id}}
    if kind == "DeleteSecurityGroup":
        return {"service": "ec2", "operation": kind, "parameters": {"GroupId": group_id}}
    if kind == "DeleteDBInstance":
        return {"service": "rds", "operation": kind, "parameters": {
            "DBInstanceIdentifier": db_id,
            "SkipFinalSnapshot": data.draw(st.booleans()),
            "DeleteAutomatedBackups": data.draw(st.booleans()),
        }}
    if kind == "ModifyDBInstance":
        return {"service": "rds", "operation": kind, "parameters": {
            "DBInstanceIdentifier": db_id,
            "DeletionProtection": data.draw(st.booleans()),
            "BackupRetentionPeriod": data.draw(st.integers(0, 35)),
            "PubliclyAccessible": data.draw(st.booleans()),
        }}
    if kind in {"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"}:
        return {"service": "ec2", "operation": kind, "parameters": {
            "GroupId": group_id, "IpPermissions": [_l18_sg_permission(data)],
        }}
    if kind == "DeleteBucket":
        return {"service": "s3", "operation": kind, "parameters": {"Bucket": bucket}}
    if kind == "DeleteFunction":
        return {"service": "lambda", "operation": kind, "parameters": {"FunctionName": function}}
    if kind == "DeleteRole":
        return {"service": "iam", "operation": kind, "parameters": {"RoleName": role}}
    operation = data.draw(st.sampled_from(_L18_UNMAPPED_EC2_OPERATIONS))
    return {"service": "ec2", "operation": operation, "parameters": {}}


_L18_MAPPED_EC2_OPERATIONS = {
    "TerminateInstances", "DeleteVolume", "DeleteSnapshot", "DeleteSecurityGroup",
    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
}
_L18_EC2_OPERATIONS = botocore.session.get_session().get_service_model("ec2").operation_names
_L18_UNMAPPED_EC2_OPERATIONS = tuple(sorted(
    operation for operation in _L18_EC2_OPERATIONS
    if not operation.startswith(("Describe", "Get", "List"))
    and operation not in _L18_MAPPED_EC2_OPERATIONS
))


def _l18_ids():
    base = load_synthetic_base("delete")
    return (
        base.ec2.instances[0].id, base.ec2.ebs_volumes[0].id, base.ec2.ebs_snapshots[0].id,
        base.ec2.security_groups[0].id, base.rds.rds_instances[0].id, base.s3.buckets[0].name,
        base.lambda_data.functions[0].name, base.iam.role_policies[0].role_name,
    )


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(data=st.data())
def test_L18_aws_cli_and_aws_api_are_equivalent(plan_client, monkeypatch, data):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    calls = [_l18_call(data, _l18_ids()) for _ in range(data.draw(st.integers(1, 3)))]
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l18-api"}).json()["branch_id"]
    cli_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l18-cli"}).json()["branch_id"]
    api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": calls,
    })
    cli_response = plan_client.post(f"/branches/{cli_branch}/plans/aws-cli", json={
        "format": "aws-cli/1", "commands": [_l18_render_call(call) for call in calls],
    })
    assert api_response.status_code == 200, api_response.text
    assert cli_response.status_code == 200, cli_response.text
    api_body, cli_body = api_response.json(), cli_response.json()
    assert api_body["rejected"] == cli_body["rejected"]
    assert len(api_body["unmodeled"]) == len(cli_body["unmodeled"])
    api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
    cli_verdict = plan_client.get(f"/branches/{cli_branch}/verdict").json()
    assert api_verdict["verdict"] == cli_verdict["verdict"]
    assert {reason["code"] for reason in api_verdict["reasons"]} == {reason["code"] for reason in cli_verdict["reasons"]}
    assert len(api_body["rejected"]) == len(cli_body["rejected"])
    assert len(api_body["unmodeled"]) == len(cli_body["unmodeled"])
    api_diff = plan_client.get(f"/branches/{api_branch}/diff").json()
    cli_diff = plan_client.get(f"/branches/{cli_branch}/diff").json()
    assert api_diff["modeled_state_unchanged"] == cli_diff["modeled_state_unchanged"]


def test_L18_sanity(plan_client):
    call = {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}}
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l18-sanity-api"}).json()["branch_id"]
    cli_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l18-sanity-cli"}).json()["branch_id"]
    assert plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [call]}).status_code == 200
    assert plan_client.post(f"/branches/{cli_branch}/plans/aws-cli", json={"format": "aws-cli/1", "commands": [_l18_render_call(call)]}).status_code == 200
    assert plan_client.get(f"/branches/{api_branch}/verdict").json()["verdict"] != "pass"
    assert plan_client.get(f"/branches/{cli_branch}/verdict").json()["verdict"] != "pass"


# L19 uses the same modeled AWS API surface as L18, rendered independently into
# CloudFormation describe-change-set records rather than through the CLI parser.
_L19_CALLS = st.sampled_from([
    {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}},
    {"service": "ec2", "operation": "DeleteVolume", "parameters": {"VolumeId": "vol-dl-data"}},
    {"service": "ec2", "operation": "DeleteSecurityGroup", "parameters": {"GroupId": "sg-dl-web"}},
    {"service": "rds", "operation": "DeleteDBInstance", "parameters": {"DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True}},
    {"service": "s3", "operation": "DeleteBucket", "parameters": {"Bucket": "dl-artifacts"}},
    {"service": "lambda", "operation": "DeleteFunction", "parameters": {"FunctionName": "dl-worker"}},
    {"service": "iam", "operation": "DeleteRole", "parameters": {"RoleName": "DlAppRole"}},
    {"service": "rds", "operation": "ModifyDBInstance", "parameters": {"DBInstanceIdentifier": "db-dl-prod", "DeletionProtection": False}},
    {"service": "ec2", "operation": "AuthorizeSecurityGroupIngress", "parameters": {"GroupId": "sg-dl-web", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}},
])


def _l19_item(call):
    p = call["parameters"]
    service, operation = call["service"], call["operation"]
    deletes = {("ec2", "TerminateInstances"): ("AWS::EC2::Instance", "i-dl-web"),
               ("ec2", "DeleteVolume"): ("AWS::EC2::Volume", p["VolumeId"]),
               ("ec2", "DeleteSecurityGroup"): ("AWS::EC2::SecurityGroup", p["GroupId"]),
               ("rds", "DeleteDBInstance"): ("AWS::RDS::DBInstance", p["DBInstanceIdentifier"]),
               ("s3", "DeleteBucket"): ("AWS::S3::Bucket", p["Bucket"]),
               ("lambda", "DeleteFunction"): ("AWS::Lambda::Function", p["FunctionName"]),
               ("iam", "DeleteRole"): ("AWS::IAM::Role", p["RoleName"])}
    if (service, operation) in deletes:
        typ, physical = deletes[(service, operation)]
        rc = {"Action": "Remove", "LogicalResourceId": "L19", "PhysicalResourceId": physical, "ResourceType": typ, "Replacement": "False"}
        if operation == "DeleteDBInstance":
            rc["PolicyAction"] = "Delete"
        return {"Type": "Resource", "ResourceChange": rc}
    if operation == "ModifyDBInstance":
        before = {"Properties": {"DeletionProtection": True}}
        after = {"Properties": {"DeletionProtection": p["DeletionProtection"]}}
        return {"Type": "Resource", "ResourceChange": {"Action": "Modify", "LogicalResourceId": "L19", "PhysicalResourceId": p["DBInstanceIdentifier"], "ResourceType": "AWS::RDS::DBInstance", "Replacement": "False", "BeforeContext": json.dumps(before), "AfterContext": json.dumps(after)}}
    permission = p["IpPermissions"][0]
    before = {"Properties": {"SecurityGroupIngress": []}}
    after = {"Properties": {"SecurityGroupIngress": [{"IpProtocol": permission["IpProtocol"], "FromPort": permission["FromPort"], "ToPort": permission["ToPort"], "CidrIp": permission["IpRanges"][0]["CidrIp"]}]}}
    return {"Type": "Resource", "ResourceChange": {"Action": "Modify", "LogicalResourceId": "L19", "PhysicalResourceId": p["GroupId"], "ResourceType": "AWS::EC2::SecurityGroup", "Replacement": "False", "BeforeContext": json.dumps(before), "AfterContext": json.dumps(after)}}


@settings(max_examples=20, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(calls=st.lists(_L19_CALLS, min_size=1, max_size=3))
def test_L19_cloudformation_and_aws_api_are_equivalent(plan_client, calls):
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l19-api"}).json()["branch_id"]
    cfn_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l19-cfn"}).json()["branch_id"]
    api = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": calls})
    cfn = plan_client.post(f"/branches/{cfn_branch}/plans/cloudformation", json={"Changes": [_l19_item(call) for call in calls]})
    assert api.status_code == cfn.status_code == 200, (api.text, cfn.text)
    api_body, cfn_body = api.json(), cfn.json()
    assert len(api_body["rejected"]) == len(cfn_body["rejected"])
    assert len(api_body["unmodeled"]) == len(cfn_body["unmodeled"])
    api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
    cfn_verdict = plan_client.get(f"/branches/{cfn_branch}/verdict").json()
    assert api_verdict["verdict"] == cfn_verdict["verdict"]
    assert {(r["code"], r["level"]) for r in api_verdict["reasons"]} == {(r["code"], r["level"]) for r in cfn_verdict["reasons"]}
    assert plan_client.get(f"/branches/{api_branch}/diff").json()["modeled_state_unchanged"] == plan_client.get(f"/branches/{cfn_branch}/diff").json()["modeled_state_unchanged"]


def test_L19_sanity(plan_client):
    call = {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}}
    api = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l19-sanity-api"}).json()["branch_id"]
    cfn = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l19-sanity-cfn"}).json()["branch_id"]
    assert plan_client.post(f"/branches/{api}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [call]}).status_code == 200
    assert plan_client.post(f"/branches/{cfn}/plans/cloudformation", json={"Changes": [_l19_item(call)]}).status_code == 200
    assert plan_client.get(f"/branches/{api}/verdict").json()["verdict"] != "pass"
    assert plan_client.get(f"/branches/{cfn}/verdict").json()["verdict"] != "pass"
