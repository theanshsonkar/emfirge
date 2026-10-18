from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.laws.test_broad_data_access_laws import _infra, _role as broad_role, _graph as broad_graph
import json
import boto3
import pytest
from moto import mock_aws

from app.aws_api_ingest import translate_api_calls
from app.models import (
    AccessStatement,
    EC2Instance,
    PolicyDocumentRecord,
    RolePolicy,
)
from app.mutations import Change, apply_change


ROLE_ARN = "arn:aws:iam::123456789012:role/AppRole"
INSTANCE_ID = "i-iam-law"


def _statement(action, resource="*"):
    return AccessStatement(effect="allow", actions=[action], resources=[resource])


def _doc(name, action, *, kind="inline", arn=None):
    return PolicyDocumentRecord(name=name, kind=kind, arn=arn, statements=[_statement(action)])


def _role(records=None):
    records = records
    return RolePolicy(
        role_name="AppRole", role_arn=ROLE_ARN,
        policy_names=[record.name for record in records or []],
        policy_documents=records,
        access_statements=([] if records is None else [s for r in records for s in r.statements]),
    )


def _iam_doc(operation, parameters):
    return {"format": "aws-api-calls/1", "calls": [{"service": "iam", "operation": operation, "parameters": parameters}]}


def _ec2_doc(parameters):
    return {"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "ModifyInstanceMetadataOptions", "parameters": parameters}]}


def _translate(doc, role, *, instance=None):
    return translate_api_calls(
        doc, role_policies=[role] if role is not None else None,
        ec2_instances=[instance] if instance is not None else None,
    )


def test_L46a_put_role_policy_new_name_matches_handwritten_typed_breakdown(plan_client):
    role_arn = ROLE_ARN
    body = _iam_doc("PutRolePolicy", {"RoleName": "DlAppRole", "PolicyName": "new", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}})
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "api"}).json()["branch_id"]
    api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json=body)
    assert api_response.status_code == 200, api_response.text
    typed_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "typed"}).json()["branch_id"]
    expected = {"op": "modify", "resource_type": "iam_role_policy", "resource_id": "arn:aws:iam::000000000000:role/DlAppRole",
                "fields": {"access_statements": [{"effect": "allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::dl-data-bucket/*"]}, {"effect": "allow", "actions": ["s3:GetObject"], "resources": ["*"]}]}}
    assert plan_client.post(f"/branches/{typed_branch}/changes", json=expected).status_code == 200
    api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
    typed_verdict = plan_client.get(f"/branches/{typed_branch}/verdict").json()
    assert api_verdict["verdict"] == typed_verdict["verdict"]
    assert {(x["code"], x["level"]) for x in api_verdict["reasons"]} == {(x["code"], x["level"]) for x in typed_verdict["reasons"]}


def test_L46b_put_role_policy_replaces_one_inline_policy_and_keeps_others():
    old = _doc("one", "s3:GetObject")
    other = _doc("two", "s3:PutObject")
    result = _translate(_iam_doc("PutRolePolicy", {"RoleName": "AppRole", "PolicyName": "one", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"}}}), _role([old, other]))
    assert result["changes"][0].fields["policy_documents"] == [_doc("one", "s3:DeleteObject").model_dump(mode="json"), other.model_dump(mode="json")]
    assert result["changes"][0].fields["access_statements"] == [_statement("s3:DeleteObject").model_dump(mode="json"), _statement("s3:PutObject").model_dump(mode="json")]


def test_L46c_unknown_existing_is_unseen_but_unknown_new_appends():
    unknown_role = _role(None).model_copy(update={"policy_names": ["one"]})
    existing = _translate(_iam_doc("PutRolePolicy", {"RoleName": "AppRole", "PolicyName": "one", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "x", "Resource": "*"}}}), unknown_role)
    assert existing["changes"] == [] and existing["unmodeled"][0]["unseen"] is True
    new = _translate(_iam_doc("PutRolePolicy", {"RoleName": "AppRole", "PolicyName": "new", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "x", "Resource": "*"}}}), _role(None))
    assert new["changes"] and "policy_documents" not in new["changes"][0].fields


def test_L46d_managed_attach_detach_delete_and_rejections_are_state_aware():
    arn = "arn:aws:iam::123456789012:policy/Managed"
    managed = _doc("Managed", "s3:GetObject", kind="managed", arn=arn)
    target = _role([])
    source = _role([managed]).model_copy(update={"role_name": "OtherRole", "role_arn": "arn:aws:iam::123456789012:role/OtherRole"})
    attached = _translate(_iam_doc("AttachRolePolicy", {"RoleName": "AppRole", "PolicyArn": arn}), target)
    # A source role must be included in the current branch lookup.
    attached = translate_api_calls(_iam_doc("AttachRolePolicy", {"RoleName": "AppRole", "PolicyArn": arn}), role_policies=[target, source])
    assert attached["changes"]
    assert _translate(_iam_doc("DetachRolePolicy", {"RoleName": "AppRole", "PolicyArn": arn}), _role([managed]))["changes"]
    assert _translate(_iam_doc("DeleteRolePolicy", {"RoleName": "AppRole", "PolicyName": "one"}), _role([_doc("one", "x")]))["changes"]
    assert _translate(_iam_doc("DetachRolePolicy", {"RoleName": "AppRole", "PolicyArn": arn}), _role(None))["unmodeled"][0]["unseen"]
    assert _translate(_iam_doc("DetachRolePolicy", {"RoleName": "AppRole", "PolicyArn": arn}), _role([]))["unmodeled"]


def test_L46e_put_then_delete_same_name_restores_original_statements():
    original = _doc("one", "s3:GetObject")
    doc = {"format": "aws-api-calls/1", "calls": [
        {"service": "iam", "operation": "PutRolePolicy", "parameters": {"RoleName": "AppRole", "PolicyName": "one", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}}}},
        {"service": "iam", "operation": "DeleteRolePolicy", "parameters": {"RoleName": "AppRole", "PolicyName": "one"}},
    ]}
    result = _translate(doc, _role([original]))
    assert result["changes"][-1].fields["access_statements"] == []


def test_L46f_imds_optional_maps_and_http_endpoint_is_unknown():
    instance = EC2Instance(id=INSTANCE_ID, type="t3.micro", state="running", imdsv2_required=True)
    optional = _translate(_ec2_doc({"InstanceId": INSTANCE_ID, "HttpTokens": "optional"}), None, instance=instance)
    assert optional["changes"][0].fields == {"imdsv2_required": False}
    endpoint = _translate(_ec2_doc({"InstanceId": INSTANCE_ID, "HttpEndpoint": "disabled"}), None, instance=instance)
    assert endpoint["changes"] == [] and endpoint["unknown_fields"][0]["field"] == "HttpEndpoint"


def test_L46g_cli_and_api_routes_share_iam_and_imds_translation(plan_client):
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "api"}).json()["branch_id"]
    cli_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "cli"}).json()["branch_id"]
    api = {"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "ModifyInstanceMetadataOptions", "parameters": {"InstanceId": "i-dl-web", "HttpTokens": "optional"}}]}
    cli = {"format": "aws-cli/1", "commands": ["aws ec2 modify-instance-metadata-options --instance-id i-dl-web --http-tokens optional"]}
    assert plan_client.post(f"/branches/{api_branch}/plans/aws-api", json=api).status_code == 200
    assert plan_client.post(f"/branches/{cli_branch}/plans/aws-cli", json=cli).status_code == 200
    assert plan_client.get(f"/branches/{api_branch}/verdict").json()["verdict"] == plan_client.get(f"/branches/{cli_branch}/verdict").json()["verdict"]


def test_L46h_typed_policy_documents_must_match_and_statements_only_clear_records():
    role = _role([_doc("one", "x")])
    with pytest.raises(ValueError):
        apply_change(__import__("app.models", fromlist=["AWSInfrastructure"]).AWSInfrastructure(iam={"role_policies": [role]}), Change(op="modify", resource_type="iam_role_policy", resource_id=ROLE_ARN, fields={"policy_documents": [_doc("one", "x")], "access_statements": [_statement("different")] }))
    state = __import__("app.models", fromlist=["AWSInfrastructure"]).AWSInfrastructure(iam={"role_policies": [role]})
    changed = apply_change(state, Change(op="modify", resource_type="iam_role_policy", resource_id=ROLE_ARN, fields={"access_statements": []}))
    assert changed.iam.role_policies[0].policy_documents is None


def test_L46i_moto_roundtrip_matches_collector_and_adapter():
    region = "us-east-1"
    creds = {"aws_access_key_id": "testing", "aws_secret_access_key": "testing", "aws_session_token": "testing"}
    with mock_aws():
        iam = boto3.client("iam", region_name=region, **creds)
        ec2 = boto3.client("ec2", region_name=region, **creds)
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role = iam.create_role(RoleName="AppRole", AssumeRolePolicyDocument=json.dumps(trust))["Role"]
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="app-sg", Description="app", VpcId=vpc)["GroupId"]
        instance = ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[sg])["Instances"][0]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        calls = {"format": "aws-api-calls/1", "calls": [
            {"service": "iam", "operation": "PutRolePolicy", "parameters": {"RoleName": "AppRole", "PolicyName": "inline", "PolicyDocument": json.dumps(policy)}},
            {"service": "ec2", "operation": "ModifyInstanceMetadataOptions", "parameters": {"InstanceId": instance["InstanceId"], "HttpTokens": "optional"}},
        ]}
        warnings = []
        from app.aws_collector import collect_ec2, collect_iam
        from app.models import AWSInfrastructure
        before_iam = collect_iam("testing", "testing", "testing", region, warnings)
        before_ec2 = collect_ec2("testing", "testing", "testing", region, warnings)
        collected_role = next(item for item in before_iam.role_policies if item.role_name == "AppRole")
        collected_instance = next(item for item in before_ec2.instances if item.id == instance["InstanceId"])
        predicted = translate_api_calls(calls, role_policies=[collected_role], ec2_instances=[collected_instance])
        assert {change.resource_type for change in predicted["changes"]} == {"iam_role_policy"}
        assert predicted["changes"][0].fields["policy_documents"]
        iam.put_role_policy(RoleName="AppRole", PolicyName="inline", PolicyDocument=json.dumps(policy))
        ec2.modify_instance_metadata_options(InstanceId=instance["InstanceId"], HttpTokens="optional")
        after_iam = collect_iam("testing", "testing", "testing", region, warnings)
        after_ec2 = collect_ec2("testing", "testing", "testing", region, warnings)
        actual_role = next(item for item in after_iam.role_policies if item.role_name == "AppRole")
        actual_instance = next(item for item in after_ec2.instances if item.id == instance["InstanceId"])
        assert [item.model_dump(mode="json") for item in actual_role.access_statements] == [item for change in predicted["changes"] if change.resource_type == "iam_role_policy" for item in change.fields["access_statements"]]
        assert [item.model_dump(mode="json") for item in actual_role.policy_documents] == [item for change in predicted["changes"] if change.resource_type == "iam_role_policy" for item in change.fields["policy_documents"]]
        assert actual_instance.imdsv2_required is False



def test_L46j_w1a_w1b_api_verdict_matches_typed_route(plan_client, monkeypatch):
    base = _infra(public=True, role=broad_role(action="s3:GetObject", resource="arn:aws:s3:::app-logs/*"))
    monkeypatch.setattr("app.main.get_infrastructure_for_analysis", lambda _id: base)
    monkeypatch.setattr("app.verdict.build_graph", broad_graph)
    monkeypatch.setattr("app.diffing.build_graph_pair", lambda before, after: (broad_graph(before), broad_graph(after)))
    base_statements = [{"effect": "Allow", "actions": ["s3:GetObject"],
                        "resources": ["arn:aws:s3:::app-logs/*"],
                        "is_not_action": False, "is_not_resource": False,
                        "has_condition": False}]

    def compare_case(policy_statement, expected_verdict):
        api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "w1-api"}).json()["branch_id"]
        typed_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "w1-typed"}).json()["branch_id"]
        api_body = _iam_doc("PutRolePolicy", {
            "RoleName": "OrdersRole", "PolicyName": "web-policy",
            "PolicyDocument": {"Statement": policy_statement},
        })
        api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json=api_body)
        assert api_response.status_code == 200, api_response.text
        assert api_response.json()["applied"], api_response.json()
        typed_statements = base_statements + [{"effect": "allow", "actions": policy_statement["Action"] if isinstance(policy_statement["Action"], list) else [policy_statement["Action"]],
                                                "resources": policy_statement["Resource"] if isinstance(policy_statement["Resource"], list) else [policy_statement["Resource"]],
                                                "is_not_action": False, "is_not_resource": False, "has_condition": False}]
        typed_response = plan_client.post(f"/branches/{typed_branch}/changes", json={
            "op": "modify", "resource_type": "iam_role_policy",
            "resource_id": "arn:aws:iam::123:role/OrdersRole",
            "fields": {"access_statements": typed_statements},
        })
        assert typed_response.status_code == 200, typed_response.text
        api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
        typed_verdict = plan_client.get(f"/branches/{typed_branch}/verdict").json()
        assert api_verdict["verdict"] == typed_verdict["verdict"] == expected_verdict
        assert {(item["code"], item["level"]) for item in api_verdict["reasons"]} == {(item["code"], item["level"]) for item in typed_verdict["reasons"]}

    compare_case({"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}, "block")
    compare_case({"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                  "Resource": ["arn:aws:s3:::app-logs/*"]}, "pass")
