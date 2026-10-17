import pytest

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_aws_api_route import _branch


def test_L25_regional_change_cannot_be_judged_against_wrong_snapshot(plan_client):
    branch_id = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{
            "service": "ec2", "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["i-dl-web"]}, "region": "us-east-1",
        }],
    })
    assert response.status_code == 422
    assert response.json()["detail"].startswith("region_mismatch")
    assert "ap-south-1" in response.text and "us-east-1" in response.text
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["plans"] == []
