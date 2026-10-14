import json

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_aws_api_route import _branch


def test_cli_route_matches_api_and_preserves_handback(plan_client):
    branch_id = _branch(plan_client)
    raw = json.dumps({"format": "aws-cli/1", "commands": [
        "aws ec2 terminate-instances --instance-ids i-dl-web"
    ]}, separators=(",", ":")).encode() + b"\n"
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-cli", content=raw)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applied"] == ["calls[0] ec2.TerminateInstances"]
    handback = plan_client.get(f"/branches/{branch_id}/plans/{body['plan_id']}/handback").json()
    assert handback["plan_text"].encode() == raw
    verified = plan_client.post("/handback/verify", json={
        "plan_id": body["plan_id"], "verdict_id": handback["verdict_id"], "plan_text": handback["plan_text"]})
    assert verified.json() == {"ok": True}


def test_cli_route_rejects_shell_operator(plan_client):
    branch_id = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-cli", json={
        "format": "aws-cli/1", "commands": ["aws ec2 terminate-instances --instance-ids i-1 | tee x"]})
    assert response.status_code == 422
