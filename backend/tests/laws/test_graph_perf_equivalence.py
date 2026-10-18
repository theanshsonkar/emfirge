"""Law L31: optimized graph construction is equivalent to the reference."""
from __future__ import annotations

import copy
import json
import random
from pathlib import Path

from app.egraph import build_graph
from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, LambdaData, LambdaFunction,
    RDSData, RDSInstance, SecurityGroup, VPCData, VPCSubnet, RouteTable,
    Route, NetworkACL, NACLEntry, VPCPeeringConnection,
)

GOLDEN_DIR = Path(__file__).parents[1] / "data" / "graph_golden"


def _canonical(graph):
    nodes = [node.model_dump(mode="json") for node in graph.nodes]
    edges = [edge.model_dump(mode="json") for edge in graph.edges]
    nodes.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    edges.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    return {"nodes": nodes, "edges": edges}


def _rule(rnd, sg_ids, index):
    choices = [
        {"from_port": 443, "to_port": 443, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0", "::/0"]},
        {"from_port": 0, "to_port": 65535, "protocol": "-1", "source_sg_ids": [sg_ids[index % len(sg_ids)]], "ip_ranges": []},
        {"from_port": 22, "to_port": 22, "protocol": "tcp", "source_sg_ids": [sg_ids[index % len(sg_ids)]], "ip_ranges": ["10.0.0.0/8"]},
    ]
    return copy.deepcopy(choices[rnd.randrange(len(choices))])


def make_account(seed: int, scale: int | None = None) -> AWSInfrastructure:
    rnd = random.Random(seed)
    count = scale if scale is not None else rnd.randint(8, 40)
    vpcs = [f"vpc-{seed:02d}-a", f"vpc-{seed:02d}-b"]
    sg_count = rnd.randint(3, 8)
    sgs = []
    sg_ids = [f"sg-{seed:02d}-{i:02d}" for i in range(sg_count)]
    for i, sg_id in enumerate(sg_ids):
        ingress = [_rule(rnd, sg_ids, i), _rule(rnd, sg_ids, i + 1)]
        # Every group has a self-reference and a CIDR/all-protocol rule.
        ingress.append({"from_port": None, "to_port": None, "protocol": "-1", "source_sg_ids": [sg_id], "ip_ranges": []})
        egress = [{"from_port": 0, "to_port": 65535, "protocol": "-1", "dest_sg_ids": [sg_ids[(i + 1) % sg_count]], "ip_ranges": []}]
        sgs.append(SecurityGroup(id=sg_id, name=f"account-{seed}-sg-{i}", rules=ingress, egress_rules=egress))

    subnet_count = rnd.randint(2, 6)
    subnets = []
    for i in range(subnet_count):
        vpc = vpcs[i % 2]
        subnets.append(VPCSubnet(id=f"subnet-{seed:02d}-{i:02d}", vpc_id=vpc, cidr=f"10.{seed}.{i}.0/24"))
    route_tables = []
    for vpc in vpcs:
        members = [s.id for s in subnets if s.vpc_id == vpc]
        route_tables.append(RouteTable(
            id=f"rtb-{seed:02d}-{vpc[-1]}", vpc_id=vpc, is_main=True,
            associated_subnet_ids=members,
            routes=[
                Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id=f"igw-{seed:02d}"),
                Route(destination_cidr="10.99.0.0/16", target_type="nat_gateway", target_id=f"nat-{seed:02d}"),
                Route(destination_cidr="10.{0}.0.0/16".format(seed), target_type="vpc_peering", target_id=f"pcx-{seed:02d}"),
            ],
        ))
    a_subnets = [s.id for s in subnets if s.vpc_id == vpcs[0]]
    b_subnets = [s.id for s in subnets if s.vpc_id == vpcs[1]]
    nacls = []
    for i, subnet in enumerate(subnets):
        # Deny is first for selected subnets; allow follows to exercise ordering.
        entries = [NACLEntry(rule_number=100, protocol="-1", rule_action="deny", egress=False, cidr_block="10.0.0.0/8", port_from=0, port_to=65535)]
        if i % 3:
            entries.insert(0, NACLEntry(rule_number=50, protocol="-1", rule_action="allow", egress=False, cidr_block="10.0.0.0/8", port_from=0, port_to=65535))
        entries.append(NACLEntry(rule_number=110, protocol="-1", rule_action="allow", egress=True, cidr_block="0.0.0.0/0", port_from=0, port_to=65535))
        nacls.append(NetworkACL(id=f"acl-{seed:02d}-{i:02d}", vpc_id=subnet.vpc_id, associated_subnet_ids=[subnet.id], entries=entries))

    instances, rds, lambdas = [], [], []
    for i in range(count):
        subnet = subnets[i % len(subnets)]
        selected = [sg_ids[i % sg_count], sg_ids[(i + 1) % sg_count]]
        kind = i % 3
        if kind == 0:
            instances.append(EC2Instance(id=f"i-{seed:02d}-{i:03d}", type="t3.micro", state="running", sg_ids=selected, subnet_id=subnet.id, has_public_ip=(i % 4 == 0)))
        elif kind == 1:
            rds.append(RDSInstance(id=f"db-{seed:02d}-{i:03d}", sg_ids=selected, subnet_id=subnet.id, encrypted=True))
        else:
            lambdas.append(LambdaFunction(name=f"fn-{seed:02d}-{i:03d}", vpc_id=subnet.vpc_id, subnet_ids=[subnet.id, subnets[(i + 1) % len(subnets)].id], sg_ids=selected))
    # Resource membership is collector metadata and deliberately includes multiple subnets.
    by_id = {x.id: x for x in instances + rds}
    for fn in lambdas:
        for sid in fn.subnet_ids:
            pass
    for subnet in subnets:
        subnet.resources = [rid for rid, obj in by_id.items() if obj.subnet_id == subnet.id] + [fn.name for fn in lambdas if subnet.id in fn.subnet_ids]
    return AWSInfrastructure(
        region="us-east-1", ec2=EC2Data(instances=instances, security_groups=sgs),
        rds=RDSData(rds_instances=rds), lambda_data=LambdaData(functions=lambdas),
        vpc=VPCData(subnets=subnets, route_tables=route_tables, internet_gateways=[f"igw-{seed:02d}"], nat_gateways=[f"nat-{seed:02d}"], nacls=nacls,
                    vpc_peering_connections=[VPCPeeringConnection(id=f"pcx-{seed:02d}", requester_vpc_id=vpcs[0], accepter_vpc_id=vpcs[1], status="active")]),
    )


def shuffled(infra, seed):
    result = copy.deepcopy(infra)
    rnd = random.Random(seed)
    for service in (result.ec2, result.rds, result.lambda_data, result.vpc):
        for field in service.model_fields:
            value = getattr(service, field, None)
            if isinstance(value, list):
                rnd.shuffle(value)
    return result


def test_L31_graph_perf_equivalence_and_order_independence():
    counts = []
    for seed in range(1, 13):
        infra = make_account(seed)
        actual = _canonical(build_graph(infra))
        expected = json.loads((GOLDEN_DIR / f"seed_{seed}.json").read_text())
        assert actual == expected, f"seed {seed} differs from oracle"
        assert actual == _canonical(build_graph(shuffled(infra, seed + 1000)))
        count = sum(edge["relationship"] == "can_reach" for edge in actual["edges"])
        counts.append(count)
    print("can_reach counts:", ", ".join(f"seed_{i + 1}={n}" for i, n in enumerate(counts)))
    assert sum(count >= 10 for count in counts) >= 5
    assert sum(count > 0 for count in counts) >= 3
    # The fixture explicitly contains cross-subnet peering paths and deny-first NACLs.
    assert all(any(route.target_type == "vpc_peering" for route in table.routes) for table in make_account(1).vpc.route_tables)
    assert all(any(entry.rule_action == "deny" for entry in acl.entries) for acl in make_account(1).vpc.nacls)
