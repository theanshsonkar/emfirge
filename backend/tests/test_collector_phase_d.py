from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from app.aws_collector import collect_ec2, collect_iam, collect_rds

KEYS = ("key", "secret", "token", "ap-south-1")


def aws_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "test")


def make_paginator(pages=None, error=None):
    mock = MagicMock()
    mock.paginate.side_effect = error
    if error is None:
        mock.paginate.return_value = pages or [{}]
    return mock


def make_ec2_client(network=None, volumes=None, snapshots=None):
    client = MagicMock()
    client.describe_instances.return_value = {"Reservations": []}
    client.describe_security_groups.return_value = {"SecurityGroups": []}
    client.describe_addresses.return_value = {"Addresses": []}
    paginators = {
        "describe_network_interfaces": make_paginator(network),
        "describe_volumes": make_paginator(volumes),
        "describe_snapshots": make_paginator(snapshots),
    }
    client.get_paginator.side_effect = lambda name: paginators[name]
    client._phase_d_paginators = paginators
    return client


def patch_ec2(mocker, client):
    elb = MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": []}
    autoscaling = MagicMock()
    autoscaling.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    mocker.patch("app.aws_collector.boto3.client", side_effect=lambda service, **_: {
        "ec2": client, "elbv2": elb, "autoscaling": autoscaling
    }[service])


def test_ec2_phase_d_values_and_two_page_pagination(mocker):
    ec2 = make_ec2_client(
        network=[{"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Attachment": {"InstanceId": "i-1"}}]},
                 {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-2", "InterfaceType": "vpc_endpoint"}]}],
        volumes=[{"Volumes": [{"VolumeId": "vol-1", "Size": 8, "VolumeType": "gp3", "State": "in-use",
                                "Attachments": [{"InstanceId": "i-1"}]}]},
                 {"Volumes": [{"VolumeId": "vol-2", "Size": 20, "VolumeType": "gp2", "State": "available"}]}],
        snapshots=[{"Snapshots": [{"SnapshotId": "snap-1", "VolumeId": "vol-1", "State": "completed"}]},
                   {"Snapshots": [{"SnapshotId": "snap-2", "VolumeId": "vol-2", "State": "pending"}]}],
    )
    patch_ec2(mocker, ec2)
    data = collect_ec2(*KEYS, [])
    assert data.collection_status["ebs_volumes"] == "ok"
    assert data.collection_status["ebs_snapshots"] == "ok"
    assert data.network_interfaces_status == "ok"
    assert [v.id for v in data.ebs_volumes] == ["vol-1", "vol-2"]
    assert data.ebs_volumes[0].attached_to == "i-1"
    assert [s.id for s in data.ebs_snapshots] == ["snap-1", "snap-2"]
    assert [n.id for n in data.network_interfaces] == ["eni-1", "eni-2"]


def test_ec2_snapshot_paginator_uses_self_owner_filter(mocker):
    ec2 = make_ec2_client(snapshots=[{"Snapshots": []}])
    patch_ec2(mocker, ec2)
    collect_ec2(*KEYS, [])
    ec2._phase_d_paginators["describe_snapshots"].paginate.assert_called_once_with(OwnerIds=["self"])


@pytest.mark.parametrize("kind", ["network", "volumes", "snapshots"])
@pytest.mark.parametrize("code, expected", [("AccessDenied", "denied"), ("UnauthorizedOperation", "denied"), ("OtherError", "error")])
def test_ec2_phase_d_client_errors(mocker, kind, code, expected):
    ec2 = make_ec2_client()
    ec2.get_paginator.side_effect = lambda name: make_paginator(error=aws_error(code)) if {
        "describe_network_interfaces": "network", "describe_volumes": "volumes", "describe_snapshots": "snapshots"
    }.get(name) == kind else make_paginator([{}])
    patch_ec2(mocker, ec2)
    warnings = []
    data = collect_ec2(*KEYS, warnings)
    key = {"network": "network_interfaces", "volumes": "ebs_volumes", "snapshots": "ebs_snapshots"}[kind]
    actual = data.network_interfaces_status if kind == "network" else data.collection_status[key]
    assert actual == expected
    if expected == "denied":
        assert warnings
    assert (data.network_interfaces is None if kind == "network" else
            data.ebs_volumes == [] if kind == "volumes" else data.ebs_snapshots == [])


def make_rds_client(db_pages=None, error=None):
    client = MagicMock()
    client.describe_db_instances.return_value = {"DBInstances": [{
        "DBInstanceIdentifier": "db-1", "Engine": "postgres", "BackupRetentionPeriod": 7,
        "DeletionProtection": False, "StorageEncrypted": True,
    }]}
    client.get_paginator.return_value = make_paginator(db_pages, error)
    return client


def test_rds_phase_d_mapping_and_pagination(mocker):
    rds = make_rds_client([{"DBSnapshots": [{"DBSnapshotIdentifier": "snap-1", "DBInstanceIdentifier": "db-1"}]},
                           {"DBSnapshots": [{"DBSnapshotIdentifier": "snap-2", "DBInstanceIdentifier": "db-2"}]}])
    mocker.patch("app.aws_collector.boto3.client", return_value=rds)
    data = collect_rds(*KEYS, [])
    instance = data.rds_instances[0]
    assert (instance.engine, instance.backup_retention_days, instance.deletion_protection) == ("postgres", 7, False)
    assert [s.id for s in data.rds_snapshots] == ["snap-1", "snap-2"]
    assert data.collection_status["rds_snapshots"] == "ok"


@pytest.mark.parametrize("code, expected", [("AccessDenied", "denied"), ("UnauthorizedOperation", "denied"), ("OtherError", "error")])
def test_rds_snapshot_client_errors(mocker, code, expected):
    rds = make_rds_client(error=aws_error(code))
    mocker.patch("app.aws_collector.boto3.client", return_value=rds)
    warnings = []
    data = collect_rds(*KEYS, warnings)
    assert data.collection_status["rds_snapshots"] == expected
    assert data.rds_snapshots == []
    if expected == "denied":
        assert warnings


def make_iam_client(role_error=None):
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {}}
    iam.list_users.return_value = {"Users": []}
    iam.generate_credential_report.return_value = {}
    iam.get_credential_report.return_value = {"Content": b"user,password_last_used\n"}
    iam.get_paginator.side_effect = lambda name: {
        "list_instance_profiles": make_paginator([{"InstanceProfiles": []}]),
        "list_roles": make_paginator([{"Roles": [{"RoleName": "TestRole", "Arn": "arn:role", "AssumeRolePolicyDocument": {"Statement": []}}]}]),
    }[name]
    if role_error:
        iam.get_role.side_effect = role_error
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    iam.list_role_policies.return_value = {"PolicyNames": []}
    return iam


@pytest.mark.parametrize("code, expected", [(None, "ok"), ("AccessDenied", "denied"), ("UnauthorizedOperation", "denied"), ("OtherError", "error")])
def test_iam_role_last_used_status_and_mapping(mocker, code, expected):
    last_used = datetime(2026, 9, 30, tzinfo=timezone.utc)
    iam = make_iam_client(None if code is None else aws_error(code))
    if code is None:
        iam.get_role.return_value = {"Role": {"RoleLastUsed": {"LastUsedDate": last_used}}}
    mocker.patch("app.aws_collector.boto3.client", return_value=iam)
    warnings = []
    data = collect_iam(*KEYS, warnings)
    assert data.collection_status["iam_role_last_used"] == expected
    if expected in ("denied", "error"):
        assert warnings
