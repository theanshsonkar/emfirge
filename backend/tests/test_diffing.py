import copy

from app.diffing import diff_infrastructure
from app.models import (
    AWSInfrastructure,
    EC2Data,
    EC2Instance,
    NetworkACL,
    NACLEntry,
    Route,
    RouteTable,
    SecurityGroup,
    VPCData,
    VPCSubnet,
)
from app.mutations import Change, apply_change, apply_changes


def _internet_infra(*, open_ssh=False):
    instance = EC2Instance(
        id="i-public", type="t3.micro", state="running", sg_ids=["sg-app"],
        subnet_id="subnet-public", has_public_ip=True, imdsv2_required=True,
    )
    sg = SecurityGroup(
        id="sg-app", name="app", attached_to=["i-public"],
        rules=([{"from_port": 22, "to_port": 22, "protocol": "6",
                 "ip_ranges": ["0.0.0.0/0"]}] if open_ssh else []),
    )
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=1, instance_ids=["i-public"], instances=[instance],
            security_groups=[sg], ssh_open_to_internet=open_ssh,
            ssh_security_group_id="sg-app" if open_ssh else None,
        ),
        vpc=VPCData(
            total_vpcs=1, internet_gateways=["igw-main"],
            subnets=[VPCSubnet(id="subnet-public", vpc_id="vpc-main",
                               cidr="10.0.1.0/24", resources=["i-public"], is_public=True)],
            route_tables=[RouteTable(
                id="rt-public", vpc_id="vpc-main", associated_subnet_ids=["subnet-public"],
                routes=[Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id="igw-main")],
            )],
            nacls=[NetworkACL(
                id="acl-public", vpc_id="vpc-main", associated_subnet_ids=["subnet-public"],
                entries=[NACLEntry(rule_number=100, protocol="6", rule_action="allow",
                                   egress=False, cidr_block="0.0.0.0/0", port_from=22, port_to=22)],
            )],
        ),
    )


def _ssh_finding_ids(result):
    return {item["rule_id"] for item in result.added_findings + result.removed_findings
            if item["rule_id"] == "EMFIRGE-EC2-002"}


def test_add_ec2_reports_node_and_structural_edges_without_removals():
    base = _internet_infra()
    branch = apply_change(base, Change(
        op="add", resource_type="ec2_instance", resource_id="i-added",
        fields={"type": "t3.small", "state": "running", "sg_ids": ["sg-app"],
                "subnet_id": "subnet-public", "has_public_ip": True},
    ))
    result = diff_infrastructure(base, branch)
    assert result.added_nodes == ["i-added"]
    assert result.removed_nodes == []
    assert {tuple(edge.values()) for edge in result.added_edges} >= {
        ("i-added", "sg-app", "uses_security_group"),
        ("i-added", "subnet-public", "in_subnet"),
    }
    assert result.removed_edges == []


def test_delete_internet_reachable_ec2_reports_edges_and_reachability():
    base = _internet_infra(open_ssh=True)
    branch = apply_change(base, Change(op="delete", resource_type="ec2_instance", resource_id="i-public"))
    result = diff_infrastructure(base, branch)
    assert "i-public" in result.removed_nodes
    assert result.added_nodes == []
    assert result.removed_edges
    assert any("i-public" in (edge["from"], edge["to"]) for edge in result.removed_edges)
    assert "i-public" in result.no_longer_internet_reachable


def test_open_sg_makes_public_instance_reachable_and_adds_ssh_finding():
    base = _internet_infra()
    branch = apply_changes(base, [
        Change(op="modify", resource_type="security_group", resource_id="sg-app", fields={
            "rules": [{"from_port": 22, "to_port": 22, "protocol": "6", "ip_ranges": ["0.0.0.0/0"]}],
        }),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-public", fields={
            "sg_ids": ["sg-app"],
        }),
    ])
    result = diff_infrastructure(base, branch)
    assert "i-public" in result.newly_internet_reachable
    assert "EMFIRGE-EC2-002" in _ssh_finding_ids(result)
    assert any(item["rule_id"] == "EMFIRGE-EC2-002" for item in result.added_findings)
    assert result.score_delta < 0


def test_close_sg_removes_ssh_finding_and_improves_score():
    base = _internet_infra(open_ssh=True)
    branch = apply_change(base, Change(
        op="modify", resource_type="security_group", resource_id="sg-app", fields={"rules": []},
    ))
    result = diff_infrastructure(base, branch)
    assert "i-public" in result.no_longer_internet_reachable
    assert any(item["rule_id"] == "EMFIRGE-EC2-002" for item in result.removed_findings)
    assert result.score_delta > 0


def test_identical_infrastructure_is_a_no_op():
    base = _internet_infra()
    result = diff_infrastructure(base, copy.deepcopy(base))
    assert result.added_nodes == result.removed_nodes == result.modified_nodes == []
    assert result.added_edges == result.removed_edges == []
    assert result.added_findings == result.removed_findings == []
    assert result.newly_internet_reachable == result.no_longer_internet_reachable == []
    assert result.score_delta == 0


def test_repeated_diff_is_deterministic_and_does_not_mutate_inputs():
    base = _internet_infra()
    branch = apply_change(base, Change(
        op="modify", resource_type="security_group", resource_id="sg-app",
        fields={"name": "renamed"},
    ))
    base_before = base.model_dump_json()
    branch_before = branch.model_dump_json()
    first = diff_infrastructure(base, branch)
    second = diff_infrastructure(base, branch)
    assert first.model_dump() == second.model_dump()
    assert base.model_dump_json() == base_before
    assert branch.model_dump_json() == branch_before
