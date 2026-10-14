from unittest.mock import MagicMock

from app.aws_collector import collect_ec2
from app.egraph import subnet_has_igw_route
from app.fix_mutations import _fix_ssh_open
from app.tf_parser import _map_sg_attrs


KEYS = ("key", "secret", "token", "ap-south-1")


def _ec2_client(sg):
    client = MagicMock()
    client.describe_instances.return_value = {"Reservations": []}
    client.describe_security_groups.return_value = {"SecurityGroups": [sg]}
    client.describe_addresses.return_value = {"Addresses": []}
    client.describe_route_tables.return_value = {"RouteTables": []}
    client.get_paginator.return_value = MagicMock(paginate=lambda: [{}])
    return client


def test_collector_collects_ipv6_sg_rules_and_flags(mocker):
    sg = {
        "GroupId": "sg-v6", "GroupName": "v6",
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]},
        ],
        "IpPermissionsEgress": [
            {"IpProtocol": "-1", "IpRanges": [],
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        ],
    }
    ec2 = _ec2_client(sg)
    elb, asg = MagicMock(), MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": []}
    asg.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    mocker.patch("app.aws_collector.boto3.client", side_effect=lambda service, **_: {"ec2": ec2, "elbv2": elb, "autoscaling": asg}[service])

    data = collect_ec2(*KEYS, [])
    group = data.security_groups[0]
    assert "::/0" in group.rules[0]["ip_ranges"]
    assert "::/0" in group.egress_rules[0]["ip_ranges"]
    assert data.ssh_open_to_internet is True
    assert data.rdp_open_to_internet is False


def test_ipv6_non_internet_cidr_does_not_open_ssh(mocker):
    sg = {
        "GroupId": "sg-v6", "GroupName": "v6",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]}],
        "IpPermissionsEgress": [],
    }
    ec2 = _ec2_client(sg)
    elb, asg = MagicMock(), MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": []}
    asg.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    mocker.patch("app.aws_collector.boto3.client", side_effect=lambda service, **_: {"ec2": ec2, "elbv2": elb, "autoscaling": asg}[service])
    assert collect_ec2(*KEYS, []).ssh_open_to_internet is False


def test_ipv6_default_igw_route_is_public_but_eigw_is_not():
    def graph(target):
        return {
            "nodes": [{"id": "rtb-1", "base": {"routes": [{"destination_cidr": "::/0", "target_type": target}]} }],
            "edges": [{"src": "subnet-1", "dst": "rtb-1", "relationship": "ASSOCIATED_WITH"}],
        }
    assert subnet_has_igw_route("subnet-1", graph("internet_gateway")) is True
    assert subnet_has_igw_route("subnet-1", graph("egress_only_internet_gateway")) is False


def test_tf_parser_ipv6_any_matches_ipv4_any():
    assert _map_sg_attrs({"ipv6_cidr_blocks": ["::/0"], "from_port": "22"})["open_to_internet"] is True
    assert _map_sg_attrs({"cidr_blocks": ["0.0.0.0/0"], "from_port": "22"})["open_to_internet"] is True


def test_fix_ssh_open_removes_ipv6_any():
    infra = {"ec2": {"security_groups": [{"id": "sg-v6", "rules": [
        {"from_port": 22, "to_port": 22, "ip_ranges": ["::/0"]},
    ]}]}}
    assert _fix_ssh_open(infra, "sg-v6") is True
    assert infra["ec2"]["security_groups"][0]["rules"] == []
