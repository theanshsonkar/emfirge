import json

import pytest

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_aws_api_route import _branch


def _api(client, call):
    branch_id = _branch(client)
    response = client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [call],
    })
    return branch_id, response


def test_api_explicit_matching_region_is_judged(plan_client):
    _, response = _api(plan_client, {
        "service": "ec2", "operation": "TerminateInstances",
        "parameters": {"InstanceIds": ["i-dl-web"]}, "region": "ap-south-1",
    })
    assert response.status_code == 200
    assert response.json()["applied"]
def test_api_explicit_different_region_is_refused_with_both_regions(plan_client):
    branch_id, response = _api(plan_client, {
        "service": "ec2", "operation": "TerminateInstances",
        "parameters": {"InstanceIds": ["i-dl-web"]}, "region": "us-east-1",
    })
    assert response.status_code == 422
    assert response.json()["detail"].startswith("region_mismatch")
    assert "us-east-1" in response.text and "ap-south-1" in response.text
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["plans"] == []


def test_cli_explicit_different_region_is_refused(plan_client):
    branch_id = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-cli", json={
        "format": "aws-cli/1",
        "commands": ["aws ec2 terminate-instances --instance-ids i-dl-web --region us-east-1"],
    })
    assert response.status_code == 422
    assert response.json()["detail"].startswith("region_mismatch")
    assert "us-east-1" in response.text and "ap-south-1" in response.text


def test_no_region_uses_snapshot_region_and_global_services_are_allowed(plan_client):
    _, no_region = _api(plan_client, {
        "service": "ec2", "operation": "TerminateInstances",
        "parameters": {"InstanceIds": ["i-dl-web"]},
    })
    assert no_region.status_code == 200
    _, iam = _api(plan_client, {
        "service": "iam", "operation": "DeleteRole",
        "parameters": {"RoleName": "DlAppRole"}, "region": "ap-south-1",
    })
    assert iam.status_code == 200


def test_cloudformation_region_is_checked(plan_client):
    branch_id = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch_id}/plans/cloudformation", json={
        "region": "us-east-1", "Changes": [{
            "Type": "Resource", "ResourceChange": {
                "Action": "Remove", "ResourceType": "AWS::EC2::Instance",
                "PhysicalResourceId": "i-dl-web",
            },
        }],
    })
    assert response.status_code == 422
    assert response.json()["detail"].startswith("region_mismatch")
    assert "us-east-1" in response.text and "ap-south-1" in response.text
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["plans"] == []
