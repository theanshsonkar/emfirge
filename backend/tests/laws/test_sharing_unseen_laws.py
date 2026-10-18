import json

import pytest

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_aws_api_route import _post as api_post
from tests.test_aws_cli_route import _cli_post
from tests.test_plan_ingest import _post as tf_post


def _verdict(client, branch):
    return client.get(f"/branches/{branch}/verdict").json()


def _assert_unseen(verdict):
    assert verdict["verdict"] == "block"
    reasons = [r for r in verdict["reasons"] if r["code"] == "unseen_change"]
    assert reasons and reasons[0]["level"] == "block"
    assert reasons[0]["message"].startswith("Emfirge can't see this: ")
    assert "does not read sharing yet" in reasons[0]["message"]


@pytest.mark.parametrize("service, operation, parameters", [
    ("ec2", "ModifySnapshotAttribute", {"SnapshotId": "snap-0123456789abcdef0", "Attribute": "createVolumePermission"}),
    ("ec2", "ModifySnapshotAttribute", {"SnapshotId": "snap-0123456789abcdef0", "UserIds": ["123456789012"]}),
    ("ec2", "ModifyImageAttribute", {"ImageId": "ami-0123456789abcdef0", "Attribute": "launchPermission"}),
    ("ec2", "ModifyImageAttribute", {"ImageId": "ami-0123456789abcdef0", "LaunchPermission": {"Add": [{"UserId": "123456789012"}]}}),
    ("ec2", "DisableSnapshotBlockPublicAccess", {}),
    ("ec2", "DisableImageBlockPublicAccess", {}),
    ("rds", "ModifyDBSnapshotAttribute", {"DBSnapshotIdentifier": "snap", "AttributeName": "restore"}),
    ("rds", "ModifyDBClusterSnapshotAttribute", {"DBClusterSnapshotIdentifier": "snap", "AttributeName": "RESTORE"}),
])
def test_L44_api_sharing_is_unseen(plan_client, service, operation, parameters):
    branch, _body, response = api_post(plan_client, {"format": "aws-api-calls/1", "calls": [{"service": service, "operation": operation, "parameters": parameters}]})
    assert response.status_code == 200, response.text
    _assert_unseen(_verdict(plan_client, branch))


def test_L44_api_sharing_cli_route_is_unseen(plan_client):
    command = "aws ec2 modify-snapshot-attribute --snapshot-id snap-0123456789abcdef0 --attribute createVolumePermission --operation-type add --user-ids 123456789012"
    branch, _body, response = _cli_post(plan_client, command)
    assert response.status_code == 200, response.text
    _assert_unseen(_verdict(plan_client, branch))


@pytest.mark.parametrize("typ", [
    "aws_snapshot_create_volume_permission", "aws_ami_launch_permission",
    "aws_ebs_snapshot_block_public_access", "aws_ec2_image_block_public_access",
])
def test_L44_terraform_sharing_resources_are_unseen(plan_client, typ):
    payload = {"format_version": "1.0", "resource_changes": [{
        "address": f"{typ}.x", "mode": "managed", "type": typ,
        "change": {"actions": ["create"], "before": None, "after": {"id": "x"}, "after_unknown": {}},
    }]}
    branch, _body, response = tf_post(plan_client, payload)
    assert response.status_code == 200, response.text
    _assert_unseen(_verdict(plan_client, branch))


@pytest.mark.parametrize("typ", ["aws_db_snapshot", "aws_db_cluster_snapshot"])
def test_L44_terraform_snapshot_shared_accounts_are_unseen(plan_client, typ):
    payload = {"format_version": "1.0", "resource_changes": [{
        "address": f"{typ}.x", "mode": "managed", "type": typ,
        "change": {"actions": ["update"], "before": {"shared_accounts": []},
                    "after": {"shared_accounts": ["123456789012"]}, "after_unknown": {}},
    }]}
    branch, _body, response = tf_post(plan_client, payload)
    assert response.status_code == 200, response.text
    _assert_unseen(_verdict(plan_client, branch))


def test_L44_description_only_and_unshared_snapshot_are_not_unseen(plan_client):
    branch, _body, response = api_post(plan_client, {"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "ModifyImageAttribute", "parameters": {"ImageId": "ami-0123456789abcdef0", "Description": "new"}}]})
    assert response.status_code == 200
    assert "unseen_change" not in {r["code"] for r in _verdict(plan_client, branch)["reasons"]}
    payload = {"format_version": "1.0", "resource_changes": [{
        "address": "aws_db_snapshot.x", "mode": "managed", "type": "aws_db_snapshot",
        "change": {"actions": ["update"], "before": {"shared_accounts": []}, "after": {"shared_accounts": []}, "after_unknown": {}},
    }]}
    branch, _body, response = tf_post(plan_client, payload)
    assert response.status_code == 200
    assert "unseen_change" not in {r["code"] for r in _verdict(plan_client, branch)["reasons"]}
