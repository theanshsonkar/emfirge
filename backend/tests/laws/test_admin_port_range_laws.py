"""L58 admin ports in ranges: SSH/RDP are open when any internet rule's tcp (or all-traffic) port range contains 22/3389."""
from unittest.mock import MagicMock

import pytest

from app.aws_collector import collect_ec2
from app.models import AWSInfrastructure, EC2Data, EC2Instance, SecurityGroup
from app.mutations import recompute_derived_state
from app.rules import check_rdp_open, check_ssh_open

KEYS = ("key", "secret", "token", "ap-south-1")
V4, V6 = "0.0.0.0/0", "::/0"

# (id, protocol, from, to, source, ssh_open, rdp_open)
CASES = [
    ("exact22", "tcp", 22, 22, V4, True, False),
    ("exact3389", "tcp", 3389, 3389, V4, False, True),
    ("range_0_100", "tcp", 0, 100, V4, True, False),
    ("range_20_25", "tcp", 20, 25, V4, True, False),
    ("range_3000_4000", "tcp", 3000, 4000, V4, False, True),
    ("all_traffic_none_ports", "-1", None, None, V4, True, True),
    ("all_traffic_full_range", "-1", 0, 65535, V4, True, True),
    ("tcp_full_range", "tcp", 0, 65535, V4, True, True),
    ("udp_22", "udp", 22, 22, V4, False, False),
    ("udp_3389", "udp", 3389, 3389, V4, False, False),
    ("tcp_23_80", "tcp", 23, 80, V4, False, False),
    ("ipv6_ssh", "tcp", 22, 22, V6, True, False),
    ("ipv6_all_traffic", "-1", None, None, V6, True, True),
    ("private_source", "tcp", 22, 22, "10.0.0.0/8", False, False),
    ("private_all_traffic", "-1", None, None, "10.0.0.0/8", False, False),
    ("port_2222", "tcp", 2222, 2222, V4, False, False),
]
IDS = [c[0] for c in CASES]


def _permission(protocol, lo, hi, source):
    perm = {"IpProtocol": protocol, "IpRanges": [], "Ipv6Ranges": []}
    if lo is not None:
        perm["FromPort"], perm["ToPort"] = lo, hi
    perm["Ipv6Ranges" if ":" in source else "IpRanges"].append({"CidrIpv6" if ":" in source else "CidrIp": source})
    return perm


def _collect(mocker, perm):
    sg = {"GroupId": "sg-l58", "GroupName": "l58", "IpPermissions": [perm], "IpPermissionsEgress": []}
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {"Reservations": []}
    ec2.describe_security_groups.return_value = {"SecurityGroups": [sg]}
    ec2.describe_addresses.return_value = {"Addresses": []}
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    ec2.get_paginator.return_value = MagicMock(paginate=lambda: [{}])
    elb, asg = MagicMock(), MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": []}
    asg.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    mocker.patch("app.aws_collector.boto3.client", side_effect=lambda service, **_: {"ec2": ec2, "elbv2": elb, "autoscaling": asg}[service])
    return collect_ec2(*KEYS, [])


def _branch_infra(protocol, lo, hi, source):
    rule = {"from_port": lo, "to_port": hi, "protocol": protocol, "ip_ranges": [source]}
    return AWSInfrastructure(region="us-east-1", ec2=EC2Data(
        instances=[EC2Instance(id="i-l58", type="t3.micro", state="running", sg_ids=["sg-l58"])],
        security_groups=[SecurityGroup(id="sg-l58", name="l58", attached_to=["i-l58"], rules=[rule])],
    ))


@pytest.mark.parametrize("name,protocol,lo,hi,source,ssh,rdp", CASES, ids=IDS)
def test_L58a_collector_summary_and_rules_agree(mocker, name, protocol, lo, hi, source, ssh, rdp):
    data = _collect(mocker, _permission(protocol, lo, hi, source))
    assert data.ssh_open_to_internet is ssh
    assert data.rdp_open_to_internet is rdp
    infra = AWSInfrastructure(region="us-east-1", ec2=data)
    assert (check_ssh_open(infra) is not None) is ssh
    assert (check_rdp_open(infra) is not None) is rdp


@pytest.mark.parametrize("name,protocol,lo,hi,source,ssh,rdp", CASES, ids=IDS)
def test_L58a_branch_recompute_and_rules_agree(name, protocol, lo, hi, source, ssh, rdp):
    infra = recompute_derived_state(_branch_infra(protocol, lo, hi, source))
    assert infra.ec2.ssh_open_to_internet is ssh
    assert infra.ec2.rdp_open_to_internet is rdp
    assert (check_ssh_open(infra) is not None) is ssh
    assert (check_rdp_open(infra) is not None) is rdp
    if ssh:
        assert infra.ec2.ssh_security_group_id == "sg-l58"
    if rdp:
        assert infra.ec2.rdp_security_group_id == "sg-l58"
