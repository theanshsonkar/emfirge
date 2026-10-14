import json

import pytest

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_aws_api_route import _branch
from tests.laws.test_tenant_isolation import tenant_client  # noqa: F401


def _cli_post(client, command, *, raw=None):
    branch_id = _branch(client)
    body = raw if raw is not None else json.dumps(
        {"format": "aws-cli/1", "commands": [command]}, separators=(",", ":")
    ).encode()
    response = client.post(f"/branches/{branch_id}/plans/aws-cli", content=body)
    return branch_id, body, response


def _api_post(client, call):
    branch_id = _branch(client)
    response = client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [call]})
    assert response.status_code == 200, response.text
    return branch_id, response


def _verdict(client, branch_id):
    return client.get(f"/branches/{branch_id}/verdict").json()


def test_cli_route_matches_api_verdicts_and_reason_codes(plan_client):
    cases = [
        (
            "aws ec2 terminate-instances --instance-ids i-dl-web",
            {"service": "ec2", "operation": "TerminateInstances",
             "parameters": {"InstanceIds": ["i-dl-web"]}},
        ),
        (
            "aws rds delete-db-instance --db-instance-identifier db-dl-prod --skip-final-snapshot",
            {"service": "rds", "operation": "DeleteDBInstance",
             "parameters": {"DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True}},
        ),
        (
            "aws rds modify-db-instance --db-instance-identifier db-dl-prod --no-deletion-protection",
            {"service": "rds", "operation": "ModifyDBInstance",
             "parameters": {"DBInstanceIdentifier": "db-dl-prod", "DeletionProtection": False}},
        ),
        (
            'aws ec2 authorize-security-group-ingress --group-id sg-dl-web --ip-permissions '
            "'[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\"}]}]'",
            {"service": "ec2", "operation": "AuthorizeSecurityGroupIngress",
             "parameters": {"GroupId": "sg-dl-web", "IpPermissions": [
                 {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                  "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
             ]}},
        ),
    ]
    for command, api_call in cases:
        cli_branch, _, cli_response = _cli_post(plan_client, command)
        assert cli_response.status_code == 200, cli_response.text
        api_branch, _ = _api_post(plan_client, api_call)
        cli_verdict = _verdict(plan_client, cli_branch)
        api_verdict = _verdict(plan_client, api_branch)
        assert cli_verdict["verdict"] == api_verdict["verdict"]
        assert {(item["code"], item["level"]) for item in cli_verdict["reasons"]} == {
            (item["code"], item["level"]) for item in api_verdict["reasons"]
        }


def test_cli_unmodeled_commands_have_api_reason_levels(plan_client):
    for command, code, level in (
        ("aws ec2 stop-instances --instance-ids i-dl-web", "unmodeled_risky_change", "block"),
        ("aws ec2 create-tags --resources i-dl-web --tags '[{\"Key\":\"Name\",\"Value\":\"web\"}]'",
         "unmodeled_change", "warn"),
    ):
        branch_id, _, response = _cli_post(plan_client, command)
        assert response.status_code == 200, response.text
        verdict = _verdict(plan_client, branch_id)
        assert verdict["verdict"] == level
        assert any(item["code"] == code and item["level"] == level for item in verdict["reasons"])


def test_cli_route_preserves_raw_handback_and_rejects_changed_text(plan_client):
    branch_id = _branch(plan_client)
    raw = b'''{  "commands" : [ "aws ec2 terminate-instances   --instance-ids i-dl-web" ] , "format" : "aws-cli/1" }\n'''
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-cli", content=raw)
    assert response.status_code == 200, response.text
    plan_id = response.json()["plan_id"]
    handback_response = plan_client.get(f"/branches/{branch_id}/plans/{plan_id}/handback")
    assert handback_response.status_code == 200
    handback = handback_response.json()
    assert handback["plan_text"].encode() == raw
    verified = plan_client.post("/handback/verify", json={
        "plan_id": plan_id, "verdict_id": handback["verdict_id"], "plan_text": handback["plan_text"]})
    assert verified.json() == {"ok": True}
    changed = handback["plan_text"][:-1] + ("0" if handback["plan_text"][-1] != "0" else "1")
    rejected = plan_client.post("/handback/verify", json={
        "plan_id": plan_id, "verdict_id": handback["verdict_id"], "plan_text": changed})
    assert rejected.status_code == 409
    assert rejected.json() == {"ok": False, "reason_code": "input_hash_mismatch"}


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-ids i-1 | tee x",
    "aws --endpoint-url https://example.invalid ec2 terminate-instances --instance-ids i-1",
    "aws ec2 authorize-security-group-ingress --group-id sg-dl-web --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22",
    "aws ec2 authorize-security-group-ingress --group-id sg-dl-web --ip-permissions file://permissions.json",
])
def test_cli_route_rejects_unsafe_or_unsupported_input_with_command_number(plan_client, command):
    _, _, response = _cli_post(plan_client, command)
    assert response.status_code == 422
    assert "Command 1" in response.json()["detail"]


def test_cli_plan_and_handback_are_tenant_isolated(tenant_client):
    from tests.laws.test_isolation_branches import _assert_hidden, _create_a_branch

    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    raw = json.dumps({"format": "aws-cli/1", "commands": [
        "aws ec2 terminate-instances --instance-ids i-dl-web"
    ]}, separators=(",", ":")).encode()
    hidden = _assert_hidden(
        client, key_b, branch_id, "/branches/A_BRANCH/plans/aws-cli",
        method="post", content=raw)
    assert hidden.status_code == 404
    created = client.post(f"/branches/{branch_id}/plans/aws-cli", headers={"X-API-Key": key_a}, content=raw)
    assert created.status_code == 200, created.text
    plan_id = created.json()["plan_id"]
    _assert_hidden(
        client, key_b, branch_id, f"/branches/A_BRANCH/plans/{plan_id}/handback")
    assert client.get(f"/branches/{branch_id}", headers={"X-API-Key": key_a}).status_code == 200
