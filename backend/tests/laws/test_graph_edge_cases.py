"""Law 30: graph construction survives incomplete and unusually large snapshots."""
from __future__ import annotations

import copy
import time
import tracemalloc
from typing import get_args, get_origin, Union

import pytest

from app.egraph import INTERNAL_REACH_EDGE_BUDGET, build_graph, get_internet_reachable_set
from app.graph_schema import validate_graph
from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, IAMData, RolePolicy, S3Data,
    S3Bucket, VPCData, VPCSubnet, SecurityGroup,
)
from app.mutations import Change, SUPPORTED_RESOURCE_TYPES, apply_change
from app.demo_seed import build_demo_infrastructure
from tests.laws.coverage_snapshot import build_coverage_infrastructure


def _is_optional(annotation) -> bool:
    origin = get_origin(annotation)
    return origin in (Union, getattr(__import__("types"), "UnionType", object)) and type(None) in get_args(annotation)


def _collection_paths(value, prefix=()):
    """Return nested service-model list fields containing resource models."""
    paths = []
    if not hasattr(value, "model_fields"):
        return paths
    for name in value.model_fields:
        child = getattr(value, name, None)
        if isinstance(child, list):
            if child and hasattr(child[0], "model_fields"):
                paths.append(prefix + (name,))
        elif hasattr(child, "model_fields"):
            paths.extend(_collection_paths(child, prefix + (name,)))
    return paths


def _without_path(snapshot, path):
    result = copy.deepcopy(snapshot)
    parent = result
    for name in path[:-1]:
        parent = getattr(parent, name)
    setattr(parent, path[-1], [])
    return result


def _resource_paths(snapshot):
    for path in _collection_paths(snapshot):
        items = snapshot
        for name in path:
            items = getattr(items, name)
        yield path, items


def test_L30_empty_every_resource_collection_is_valid():
    demo = build_demo_infrastructure()
    paths = list(_collection_paths(demo))
    assert paths, "fixture must expose resource collections"
    for path in paths:
        graph = build_graph(_without_path(demo, path))
        assert validate_graph(graph) == [], path


def test_L30_optional_resource_fields_can_be_null():
    snapshot = build_coverage_infrastructure()
    tested = 0
    for path, resources in _resource_paths(snapshot):
        for index, resource in enumerate(resources):
            optional = [name for name, field in resource.model_fields.items() if _is_optional(field.annotation)]
            if not optional:
                continue
            changed = copy.deepcopy(snapshot)
            parent = changed
            for name in path[:-1]:
                parent = getattr(parent, name)
            collection = getattr(parent, path[-1])
            replacement = copy.deepcopy(collection[index])
            for name in optional:
                setattr(replacement, name, None)
            collection[index] = replacement
            graph = build_graph(changed)
            assert validate_graph(graph) == [], (path, index, optional)
            tested += 1
    assert tested, "coverage snapshot must contain optional resource fields"


def test_L30_dangling_references_emit_no_dangling_edges():
    base = build_coverage_infrastructure()
    cases = []
    case = copy.deepcopy(base)
    case.ec2.security_groups = []
    cases.append(case)
    case = copy.deepcopy(base)
    case.vpc.subnets = []
    cases.append(case)
    case = copy.deepcopy(base)
    case.iam.role_policies = []
    cases.append(case)
    case = copy.deepcopy(base)
    case.vpc.internet_gateways = []
    case.vpc.internet_gateway_attachments = []
    cases.append(case)
    for snapshot in cases:
        graph = build_graph(snapshot)
        assert validate_graph(graph) == []
        ids = {node.id for node in graph.nodes}
        assert all(edge.src in ids and edge.dst in ids for edge in graph.edges)


def _coverage_resources(snapshot):
    locations = {
        "ec2_instance": snapshot.ec2.instances,
        "security_group": snapshot.ec2.security_groups,
        "ebs_volume": snapshot.ec2.ebs_volumes,
        "ebs_snapshot": snapshot.ec2.ebs_snapshots,
        "rds_instance": snapshot.rds.rds_instances,
        "rds_snapshot": snapshot.rds.rds_snapshots,
        "s3_bucket": snapshot.s3.buckets,
        "iam_role": snapshot.iam.role_policies,
        "lambda_function": snapshot.lambda_data.functions,
    }
    for resource_type, resources in locations.items():
        for resource in resources:
            if resource_type in {"s3_bucket", "lambda_function"}:
                resource_id = resource.name
            elif resource_type == "iam_role":
                resource_id = resource.role_arn
            else:
                resource_id = resource.id
            yield resource_type, resource_id


def test_L30_supported_deletes_rebuild_without_deleted_edges():
    base = build_coverage_infrastructure()
    supported = []
    skipped = []
    for resource_type, resource_id in _coverage_resources(base):
        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            skipped.append(resource_type)
            continue
        # SG deletion is correctly rejected while references remain; it is a skipped
        # delete rather than permission to weaken the graph invariant.
        try:
            branch = apply_change(base, Change(op="delete", resource_type=resource_type, resource_id=resource_id))
        except (ValueError, TypeError):
            skipped.append(resource_type)
            continue
        graph = build_graph(branch)
        assert validate_graph(graph) == [], (resource_type, resource_id)
        assert resource_id not in {node.id for node in graph.nodes}
        assert all(resource_id not in (edge.src, edge.dst) for edge in graph.edges)
        supported.append(resource_type)
    print(f"delete counts: applied={len(supported)} skipped={sorted(set(skipped))}")
    assert supported


def test_L30_duplicate_security_group_ids_have_unique_nodes():
    snapshot = build_coverage_infrastructure()
    snapshot.ec2.security_groups.append(copy.deepcopy(snapshot.ec2.security_groups[0]))
    graph = build_graph(snapshot)
    ids = [node.id for node in graph.nodes]
    assert len(ids) == len(set(ids))


def _huge_snapshot() -> AWSInfrastructure:
    sg_count, subnet_count, role_count, instance_count, bucket_count = 200, 100, 100, 1000, 200
    sgs = [SecurityGroup(id=f"sg-huge-{i}", name=f"huge-{i}",
                         rules=[{"protocol": "tcp", "from_port": 443, "to_port": 443,
                                 "ip_ranges": ["10.0.0.0/8"]}]) for i in range(sg_count)]
    subnets = [VPCSubnet(id=f"subnet-huge-{i}", vpc_id="vpc-huge", cidr=f"10.{i // 256}.{i % 256}.0/24") for i in range(subnet_count)]
    instances = []
    for i in range(instance_count):
        shared = [sgs[(2 * i) % 20].id, sgs[(2 * i + 1) % 20].id]
        unique = [sgs[20 + (i % 180)].id] if i % 5 == 0 else []
        instances.append(EC2Instance(id=f"i-huge-{i}", type="t3.micro", state="running",
                                     subnet_id=subnets[i % subnet_count].id,
                                     sg_ids=shared + unique))
    roles = [RolePolicy(role_name=f"HugeRole{i}", role_arn=f"arn:aws:iam::000000000000:role/HugeRole{i}") for i in range(role_count)]
    buckets = [S3Bucket(name=f"huge-bucket-{i}") for i in range(bucket_count)]
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(instances=instances, security_groups=sgs),
        s3=S3Data(buckets=buckets),
        iam=IAMData(role_policies=roles),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def test_L30_huge_account_stays_within_bounds():
    snapshot = _huge_snapshot()
    tracemalloc.start()
    started = time.perf_counter()
    graph = build_graph(snapshot)
    build_seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    validate_started = time.perf_counter()
    assert validate_graph(graph) == []
    assert len(graph.nodes) <= 1700
    assert len(graph.edges) <= INTERNAL_REACH_EDGE_BUDGET + 4000
    assert any(warning.get("kind") == "internal_reachability_budget_exceeded" for warning in graph.warnings)
    reachable_started = time.perf_counter()
    get_internet_reachable_set(graph)
    reachable_seconds = time.perf_counter() - reachable_started
    print(f"huge graph: build={build_seconds:.3f}s peak={peak / 1024 / 1024:.1f}MB validate={time.perf_counter() - validate_started:.3f}s reach={reachable_seconds:.3f}s")
    assert build_seconds < 20
    assert peak < 1.5 * 1024**3
    assert reachable_seconds < 20
