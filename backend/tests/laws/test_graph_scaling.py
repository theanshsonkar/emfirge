"""Law L31 scaling bound for realistic security graph snapshots."""
from __future__ import annotations

import time

from app.egraph import INTERNAL_REACH_EDGE_BUDGET, build_graph
from app.graph_schema import validate_graph
from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, LambdaData, LambdaFunction,
    RDSData, RDSInstance, SecurityGroup, VPCData, VPCSubnet, RouteTable, Route,
)
from app.verdict import combined_verdict


def scaling_infra(size: int) -> AWSInfrastructure:
    sg_ids = [f"sg-scale-{i:02d}" for i in range(40)]
    sgs = [SecurityGroup(
        id=sg_id, name=sg_id,
        rules=[{"from_port": 0, "to_port": 65535, "protocol": "-1", "source_sg_ids": [sg_ids[(i + 1) % 40]]}],
        egress_rules=[{"from_port": 0, "to_port": 65535, "protocol": "-1", "dest_sg_ids": [sg_ids[(i + 1) % 40]]}],
    ) for i, sg_id in enumerate(sg_ids)]
    subnets = [VPCSubnet(id=f"subnet-scale-{i:02d}", vpc_id=f"vpc-scale-{i % 2}", cidr=f"10.{i}.0.0/16") for i in range(10)]
    sets = [sg_ids[i * 5:(i + 1) * 5] for i in range(8)]
    ec2, rds, functions = [], [], []
    for i in range(size):
        subnet = subnets[i % len(subnets)]
        selected = sets[i % len(sets)]
        if i % 3 == 0:
            ec2.append(EC2Instance(id=f"i-scale-{i:04d}", type="t3.micro", state="running", sg_ids=selected, subnet_id=subnet.id))
        elif i % 3 == 1:
            rds.append(RDSInstance(id=f"db-scale-{i:04d}", sg_ids=selected, subnet_id=subnet.id, encrypted=True))
        else:
            functions.append(LambdaFunction(name=f"fn-scale-{i:04d}", vpc_id=subnet.vpc_id, subnet_ids=[subnet.id], sg_ids=selected))
    for subnet in subnets:
        subnet.resources = [obj.id for obj in ec2 + rds if obj.subnet_id == subnet.id] + [fn.name for fn in functions if subnet.id in fn.subnet_ids]
    tables = []
    for vpc_index in range(2):
        vpc_id = f"vpc-scale-{vpc_index}"
        members = [s.id for s in subnets if s.vpc_id == vpc_id]
        tables.append(RouteTable(id=f"rtb-scale-{vpc_index}", vpc_id=vpc_id, is_main=True, associated_subnet_ids=members, routes=[Route(destination_cidr="10.0.0.0/8", target_type="nat_gateway", target_id="nat-scale")]))
    return AWSInfrastructure(
        region="us-east-1", ec2=EC2Data(instances=ec2, security_groups=sgs),
        rds=RDSData(rds_instances=rds), lambda_data=LambdaData(functions=functions),
        vpc=VPCData(subnets=subnets, route_tables=tables, nat_gateways=["nat-scale"]),
    )


def test_L31_realistic_300_instances_under_30_seconds():
    started = time.perf_counter()
    graph = build_graph(scaling_infra(300))
    elapsed = time.perf_counter() - started
    print(f"realistic 300: {elapsed:.3f}s, nodes={len(graph.nodes)}")
    assert len(graph.nodes) >= 300 + 40 + 10 + 2
    assert elapsed < 30.0


def test_L32_reachability_is_independent_of_account_size():
    sg = SecurityGroup(
        id="sg-self", name="sg-self",
        rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "source_sg_ids": ["sg-self"]}],
        egress_rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "dest_sg_ids": ["sg-self"]}],
    )
    subnet = VPCSubnet(id="subnet-self", vpc_id="vpc-self", cidr="10.0.0.0/16")
    instances = [EC2Instance(id=f"i-self-{i:03d}", type="t3.micro", state="running",
                             sg_ids=["sg-self"], subnet_id=subnet.id) for i in range(150)]
    subnet.resources = [instance.id for instance in instances]

    def account(items):
        return AWSInfrastructure(
            region="us-east-1", ec2=EC2Data(instances=items, security_groups=[sg.model_copy(deep=True)]),
            vpc=VPCData(subnets=[subnet.model_copy(deep=True)]),
        )

    def pairs(graph):
        return {(edge.src, edge.dst) for edge in graph.edges if edge.relationship == "can_reach"}

    full_graph = build_graph(account(instances))
    assert validate_graph(full_graph) == []
    full_pairs = pairs(full_graph)
    assert ("i-self-000", "i-self-001") in full_pairs
    assert len(full_pairs) >= 150 * 149
    first_pairs = pairs(build_graph(account(instances[:75])))
    second_pairs = pairs(build_graph(account(instances[75:])))
    assert first_pairs == {(src, dst) for src, dst in full_pairs if src < "i-self-075" and dst < "i-self-075"}
    assert second_pairs == {(src, dst) for src, dst in full_pairs if src >= "i-self-075" and dst >= "i-self-075"}


def test_L32_budget_is_explicit():
    sg = SecurityGroup(
        id="sg-self", name="sg-self",
        rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "source_sg_ids": ["sg-self"]}],
        egress_rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "dest_sg_ids": ["sg-self"]}],
    )
    subnet = VPCSubnet(id="subnet-self", vpc_id="vpc-self", cidr="10.0.0.0/16")
    instances = [EC2Instance(id=f"i-self-{i:03d}", type="t3.micro", state="running",
                             sg_ids=["sg-self"], subnet_id=subnet.id) for i in range(400)]
    subnet.resources = [instance.id for instance in instances]
    account = AWSInfrastructure(
        region="us-east-1", ec2=EC2Data(instances=instances, security_groups=[sg]),
        vpc=VPCData(subnets=[subnet]),
    )

    started = time.perf_counter()
    graph = build_graph(account)
    elapsed = time.perf_counter() - started
    can_reach = [edge for edge in graph.edges if edge.relationship == "can_reach"]
    assert len(can_reach) <= INTERNAL_REACH_EDGE_BUDGET
    assert any(warning.get("kind") == "internal_reachability_budget_exceeded" for warning in graph.warnings)
    assert elapsed < 30.0
    result = combined_verdict(account, account, run_scanners=False)
    assert any(item.startswith("graph_internal_reachability_truncated") for item in result.collection_warnings)
