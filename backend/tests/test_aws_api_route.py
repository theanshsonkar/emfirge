import hashlib
import hashlib
import json

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_plan_ingest import _branch
from tests.incidents.synthetic_base import load_synthetic_base
from tests.laws.test_tenant_isolation import tenant_client  # noqa: F401


def _post(client, payload, raw=None):
    branch_id = _branch(client)
    body = raw if raw is not None else json.dumps(payload, separators=(",", ":")).encode()
    response = client.post(f"/branches/{branch_id}/plans/aws-api", content=body)
    return branch_id, body, response


def test_valid_terminate_and_rds_delete(plan_client):
    raw = json.dumps({"format": "aws-api-calls/1", "calls": [
        {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}},
        {"service": "rds", "operation": "DeleteDBInstance", "parameters": {
            "DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True,
            "DeleteAutomatedBackups": True,
        }},
    ]}, separators=(",", ":")).encode()
    branch_id, body, response = _post(plan_client, {}, raw)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["applied"] == ["calls[0] ec2.TerminateInstances", "calls[1] rds.DeleteDBInstance"]
    assert result["input_sha256"] == hashlib.sha256(body).hexdigest()
    assert plan_client.get(f"/branches/{branch_id}/verdict").status_code == 200


def test_unmodeled_aws_api_reasons(plan_client):
    for operation, expected_code, expected_level in (("DeleteVpc", "unmodeled_delete", "block"), ("PutBucketPolicy", "unmodeled_change", "warn")):
        branch_id, _, response = _post(plan_client, {"format": "aws-api-calls/1", "calls": [
            {"service": "ec2" if operation == "DeleteVpc" else "s3", "operation": operation, "parameters": {}}
        ]})
        assert response.status_code == 200, response.text
        reasons = plan_client.get(f"/branches/{branch_id}/verdict").json()["reasons"]
        matching = [item for item in reasons if item["code"] == expected_code]
        assert matching and matching[0]["level"] == expected_level
        assert "AWS API call" in matching[0]["message"]


def test_malformed_aws_api_does_not_echo_input(plan_client):
    bodies = [
        (b'{"format":"aws-api-calls/1", "calls":[BROKEN-MARKER]}', "BROKEN-MARKER"),
        (b'{"format":"wrong", "marker":"WRONG-MARKER"}', "WRONG-MARKER"),
        (b'{"format":"aws-api-calls/1", "calls":[], "marker":"EMPTY-MARKER"}', "EMPTY-MARKER"),
        (b'{"format":"aws-api-calls/1", "calls":[{"service":"ec2","operation":"TerminateInstances","parameters":{"InstanceIds":"STRING-MARKER"}}]}', "STRING-MARKER"),
    ]
    for body, marker in bodies:
        _, _, response = _post(plan_client, {}, body)
        assert response.status_code == 422
        assert marker not in response.text


def test_aws_api_handback_preserves_raw_input(plan_client):
    raw = b'''{  "calls" : [ { "parameters" : { "InstanceIds" : [ "i-dl-web" ] }, "operation" : "TerminateInstances", "service" : "ec2" } ] , "format" : "aws-api-calls/1" }\n'''
    branch_id, _, response = _post(plan_client, {}, raw)
    assert response.status_code == 200, response.text
    plan_id = response.json()["plan_id"]
    handback = plan_client.get(f"/branches/{branch_id}/plans/{plan_id}/handback")
    assert handback.status_code == 200
    values = handback.json()
    assert values["plan_text"].encode() == raw
    verified = plan_client.post("/handback/verify", json={"plan_id": plan_id, "verdict_id": values["verdict_id"], "plan_text": values["plan_text"]})
    assert verified.json() == {"ok": True}
    changed = values["plan_text"][:-1] + ("0" if values["plan_text"][-1] != "0" else "1")
    conflict = plan_client.post("/handback/verify", json={"plan_id": plan_id, "verdict_id": values["verdict_id"], "plan_text": changed})
    assert conflict.status_code == 409
    assert conflict.json() == {"ok": False, "reason_code": "input_hash_mismatch"}


def test_unknown_aws_api_branch_matches_terraform(plan_client):
    body = json.dumps({"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "DescribeInstances", "parameters": {}}]}).encode()
    aws = plan_client.post("/branches/not-a-branch/plans/aws-api", content=body)
    terraform = plan_client.post("/branches/not-a-branch/plans/terraform", content=b'{"format_version":"1.0","resource_changes":[]}')
    assert aws.status_code == terraform.status_code == 404
    assert aws.json() == terraform.json()


def test_iam_delete_role_resolves_existing_name_and_rejects_unknown(plan_client):
    branch_id, _, response = _post(plan_client, {"format": "aws-api-calls/1", "calls": [
        {"service": "iam", "operation": "DeleteRole", "parameters": {"RoleName": "DlAppRole"}},
    ]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applied"]
    assert body["rejected"] == []
    verdict = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert "plan_delete_rejected" not in {reason["code"] for reason in verdict["reasons"]}

    unknown_branch, _, unknown_response = _post(plan_client, {"format": "aws-api-calls/1", "calls": [
        {"service": "iam", "operation": "DeleteRole", "parameters": {"RoleName": "does-not-exist"}},
    ]})
    assert unknown_response.status_code == 200, unknown_response.text
    unknown_body = unknown_response.json()
    assert unknown_body["applied"] == []
    assert unknown_body["rejected"]
    unknown_verdict = plan_client.get(f"/branches/{unknown_branch}/verdict").json()
    assert any(reason["code"] == "plan_delete_rejected" and reason["level"] == "block"
               for reason in unknown_verdict["reasons"])


def test_aws_api_plan_is_tenant_isolated(tenant_client):
    from tests.laws.test_isolation_branches import _assert_hidden, _create_a_branch

    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    body = {"format": "aws-api-calls/1", "calls": [
        {"service": "ec2", "operation": "DescribeInstances", "parameters": {}},
    ]}
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/plans/aws-api", method="post", json_body=body)
    assert client.get(f"/branches/{branch_id}", headers={"X-API-Key": key_a}).status_code == 200


_PUBLIC_SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}


def _api_post(client, calls):
    branch_id = client.post("/branches", json={"base_analysis_id": "delete", "name": "api-sg"}).json()["branch_id"]
    response = client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": calls})
    assert response.status_code == 200, response.text
    return branch_id, response.json()


def _branch_rules(branch_id, sg_id):
    from app import branches
    branch = branches.get_branch(branch_id)
    state = branch.base.model_copy(deep=True)
    from app.mutations import apply_changes
    state = apply_changes(state, branch.changes)
    return next(sg.rules for sg in state.ec2.security_groups if sg.id == sg_id)


def test_authorize_public_ssh_applies_and_exposes_specific_reason(plan_client):
    branch_id, body = _api_post(plan_client, [{"service": "ec2", "operation": "AuthorizeSecurityGroupIngress",
        "parameters": {"GroupId": "sg-dl-web", **_PUBLIC_SSH}}])
    assert body["applied"] and body["rejected"] == []
    verdict = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert verdict["verdict"] != "pass"
    # introduced_critical_exposure means the branch adds a Critical internet exposure.
    assert any(reason["code"] == "introduced_critical_exposure" for reason in verdict["reasons"])


def test_authorize_then_revoke_same_document_restores_base_rules(plan_client):
    branch_id, body = _api_post(plan_client, [
        {"service": "ec2", "operation": "AuthorizeSecurityGroupIngress",
         "parameters": {"GroupId": "sg-dl-web", **_PUBLIC_SSH}},
        {"service": "ec2", "operation": "RevokeSecurityGroupIngress",
         "parameters": {"GroupId": "sg-dl-web", **_PUBLIC_SSH}},
    ])
    assert len(body["applied"]) == 2 and body["rejected"] == []
    base = load_synthetic_base("delete")
    expected = next(sg.rules for sg in base.ec2.security_groups if sg.id == "sg-dl-web")
    assert _branch_rules(branch_id, "sg-dl-web") == expected


def test_revoke_without_match_warns_unknown_plan_values(plan_client):
    branch_id, body = _api_post(plan_client, [{"service": "ec2", "operation": "RevokeSecurityGroupIngress",
        "parameters": {"GroupId": "sg-dl-web", **_PUBLIC_SSH}}])
    assert body["applied"] == []
    verdict = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert any(reason["code"] == "unknown_plan_values" and reason["level"] == "warn"
               for reason in verdict["reasons"])


def test_modify_rds_deletion_protection_and_backup_retention_applies(plan_client):
    _, body = _api_post(plan_client, [{"service": "rds", "operation": "ModifyDBInstance",
        "parameters": {"DBInstanceIdentifier": "db-dl-prod", "DeletionProtection": False,
                        "BackupRetentionPeriod": 0}}])
    assert body["applied"] and body["rejected"] == []
