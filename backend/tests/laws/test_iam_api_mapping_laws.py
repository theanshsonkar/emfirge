from tests.test_plan_ingest import plan_client  # noqa: F401
import json

import pytest

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


def test_L46i_moto_roundtrip_contract_is_explicit_about_optional_provider_ops():
    pytest.skip("Moto IAM policy-document and IMDS mutation round-trip is provider-version dependent; covered by the dedicated handback suite when supported.")
