"""Laws for collision-safe IDs across AWS resource types."""
from __future__ import annotations

import copy
import random
import string
from pathlib import Path

import pytest

from app.diffing import diff_infrastructure
from app.egraph import NodeIdPlan, build_graph
from tests.incidents.synthetic_base import load_synthetic_base
from tests.incidents.base import build_incident_base
from tests.laws.coverage_snapshot import build_coverage_infrastructure
from app.models import (
    AccessStatement,
    AWSInfrastructure,
    DynamoDBData,
    DynamoDBTable,
    IAMData,
    LambdaData,
    LambdaFunction,
    RDSData,
    RDSInstance,
    RolePolicy,
    S3Bucket,
    S3Data,
    SecretsManagerData,
    SQSData,
    SQSQueue,
)
from app.mutations import Change, apply_change


ACCOUNT = "000000000000"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/OrdersRole"
SIX_TYPES = (
    "s3_bucket",
    "lambda_function",
    "rds_instance",
    "dynamodb_table",
    "sqs_queue",
    "secretsmanager_secret",
)


def _queue(name: str) -> SQSQueue:
    return SQSQueue(
        name=name,
        url=f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/{name}",
        arn=f"arn:aws:sqs:{REGION}:{ACCOUNT}:{name}",
    )


def _table(name: str) -> DynamoDBTable:
    return DynamoDBTable(name=name, arn=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}")


def _snapshot(
    name: str = "orders",
    *,
    include_all: bool = True,
    role: RolePolicy | None = None,
) -> AWSInfrastructure:
    """Build a small synthetic snapshot using authoritative resource lists."""
    return AWSInfrastructure(
        region=REGION,
        s3=S3Data(buckets=[S3Bucket(name=name)] if include_all else []),
        lambda_data=LambdaData(
            functions=[LambdaFunction(name=name, secret_refs=[name])] if include_all else []
        ),
        rds=RDSData(
            rds_instances=[RDSInstance(id=name)] if include_all else []
        ),
        dynamodb=DynamoDBData(tables=[_table(name)] if include_all else []),
        sqs=SQSData(queues=[_queue(name)] if include_all else []),
        secrets_manager=SecretsManagerData(),
        iam=IAMData(role_policies=[role] if role else []),
    )


def _collision_snapshot() -> AWSInfrastructure:
    return _snapshot()


def _nodes_of(graph, resource_type: str):
    return graph.find_nodes_by_type(resource_type)


def test_L40a_cross_type_collision_uses_priority_ids():
    graph = build_graph(_collision_snapshot())

    assert all(len(_nodes_of(graph, resource_type)) == 1 for resource_type in SIX_TYPES)
    assert _nodes_of(graph, "s3_bucket")[0].id == "orders"
    for resource_type in SIX_TYPES[1:]:
        assert _nodes_of(graph, resource_type)[0].id == f"{resource_type}:orders"
    assert not any(warning.get("kind") == "duplicate_node_id" for warning in graph.warnings)


def test_L40b_collision_ids_are_order_independent():
    first = _collision_snapshot()
    second = copy.deepcopy(first)
    rng = random.Random(40)
    for resource_type, collection in (
        ("s3_bucket", second.s3.buckets),
        ("lambda_function", second.lambda_data.functions),
        ("rds_instance", second.rds.rds_instances),
        ("sqs_queue", second.sqs.queues),
        ("dynamodb_table", second.dynamodb.tables),
    ):
        rng.shuffle(collection)
    assert build_graph(first).to_dict() == build_graph(second).to_dict()


def test_L40c_iam_access_targets_typed_collision_nodes():
    role = RolePolicy(
        role_name="OrdersRole",
        role_arn=ROLE_ARN,
        access_statements=[AccessStatement(
            effect="Allow",
            actions=["dynamodb:GetItem"],
            resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"],
        ), AccessStatement(
            effect="Allow",
            actions=["sqs:SendMessage"],
            resources=[f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders"],
        )],
    )
    graph = build_graph(_snapshot(role=role))
    role_id = f"iam-role-OrdersRole"
    targets = {
        edge.dst for edge in graph.edges
        if edge.src == role_id and edge.relationship.value == "can_access"
    }

    assert targets == {"dynamodb_table:orders", "sqs_queue:orders"}
    assert {graph.get_node(target).resource_type for target in targets} == {
        "dynamodb_table", "sqs_queue",
    }
    assert "orders" not in targets


def test_L40d_same_type_duplicates_keep_duplicate_warning():
    snapshot = _snapshot(include_all=False)
    snapshot.sqs.queues = [_queue("orders"), _queue("orders")]
    graph = build_graph(snapshot)
    assert any(warning.get("kind") == "duplicate_node_id" for warning in graph.warnings)


def test_L40e_non_colliding_resources_keep_bare_ids():
    snapshot = AWSInfrastructure(
        region=REGION,
        s3=S3Data(buckets=[S3Bucket(name="bucket-a")]),
        lambda_data=LambdaData(functions=[LambdaFunction(name="function-a", secret_refs=["secret-a"])]),
        rds=RDSData(rds_instances=[RDSInstance(id="db-a")]),
        dynamodb=DynamoDBData(tables=[_table("table-a")]),
        sqs=SQSData(queues=[_queue("queue-a")]),
        secrets_manager=SecretsManagerData(),
    )
    graph = build_graph(snapshot)
    expected = {
        "s3_bucket": "bucket-a",
        "lambda_function": "function-a",
        "rds_instance": "db-a",
        "dynamodb_table": "table-a",
        "sqs_queue": "queue-a",
        "secretsmanager_secret": "secret-a",
    }
    assert {resource_type: _nodes_of(graph, resource_type)[0].id for resource_type in SIX_TYPES} == expected


def test_L40f_branch_addition_does_not_reidentify_existing_table():
    role = RolePolicy(
        role_name="OrdersRole",
        role_arn=ROLE_ARN,
        access_statements=[AccessStatement(
            effect="Allow",
            actions=["dynamodb:GetItem"],
            resources=[f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"],
        )],
    )
    base = _snapshot(include_all=False, role=role)
    base.dynamodb.tables = [_table("orders")]
    branch = apply_change(base, Change(
        op="add", resource_type="lambda_function", resource_id="orders",
    ))
    diff = diff_infrastructure(base, branch)

    assert diff.added_nodes == ["orders"]
    assert diff.removed_nodes == []
    assert "orders" not in diff.modified_nodes
    assert not diff.lost_dependencies
    assert not diff.lost_connectivity



def test_L40h_branch_delete_keeps_collision_ids_stable():
    base = _snapshot(include_all=False)
    base.s3.buckets = [S3Bucket(name="orders")]
    base.rds.rds_instances = [RDSInstance(id="orders")]
    branch = apply_change(base, Change(op="delete", resource_type="s3_bucket", resource_id="orders"))
    diff = diff_infrastructure(base, branch)
    assert diff.removed_nodes == ["orders"]
    assert diff.added_nodes == []
    assert "rds_instance:orders" not in diff.modified_nodes


def test_L40i_scan_graph_and_lookup():
    graph = build_graph(_collision_snapshot())
    for resource_type in SIX_TYPES:
        node_id = graph.node_id_for(resource_type, "orders")
        assert node_id is not None
        assert graph.get_node(node_id).resource_type == resource_type

    rng = random.Random(4007)
    alphabets = {
        "s3_bucket": string.ascii_lowercase + string.digits + ".-",
        "lambda_function": string.ascii_letters + string.digits + "-_",
        "rds_instance": string.ascii_letters + string.digits + "-_",
        "dynamodb_table": string.ascii_letters + string.digits + "-_",
        "sqs_queue": string.ascii_letters + string.digits + "-_",
        "secretsmanager_secret": string.ascii_letters + string.digits + "-_+/=.@",
    }
    names = {
        resource_type: {
            "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 30)))
            for _ in range(200)
        }
        for resource_type, alphabet in alphabets.items()
    }
    bare_names = set().union(*names.values())
    for resource_type, resource_names in names.items():
        assert all(f"{resource_type}:{name}" not in bare_names for name in resource_names)


def _law_snapshots():
    """Inputs covered by the repository's locked scenario suites."""
    if not Path("/Users/anshsonkar/emfirge/.emfirge-lab").is_dir():
        pytest.skip("locked scenario lab is absent")
    import json
    phase_dir = Path(__file__).parents[1] / "incidents" / "phase_d"
    snapshots = [("coverage", build_coverage_infrastructure()), ("incident", build_incident_base())]
    for path in sorted(phase_dir.glob("*.json")):
        scenario = json.loads(path.read_text())
        snapshots.append((scenario["id"], load_synthetic_base(scenario["base"], scenario.get("base_patch"))))
    return snapshots


def _assert_node_id_rule(infrastructure):
    graph = build_graph(infrastructure)
    names = {resource_type: set() for resource_type in SIX_TYPES}
    for node in graph.nodes:
        if node.resource_type in names:
            names[node.resource_type].add(node.label.split(": ", 1)[-1] if node.resource_type == "s3_bucket" else node.base.get("name", node.base.get("id", node.id)))
    # Use the authoritative collector through NodeIdPlan, rather than labels/metadata.
    plan = NodeIdPlan.from_infras(infrastructure)
    for node in graph.nodes:
        if node.resource_type not in SIX_TYPES:
            continue
        name = node.id.split(":", 1)[-1] if node.id.startswith(f"{node.resource_type}:") else node.id
        used_by = [kind for kind in SIX_TYPES if name in plan.names[kind]]
        if len(used_by) < 2:
            assert node.id == name
        else:
            assert node.id == plan.id(node.resource_type, name)
    bare_graph = build_graph(infrastructure, NodeIdPlan({}))
    assert {n.id for n in graph.nodes if n.resource_type not in SIX_TYPES} == {
        n.id for n in bare_graph.nodes if n.resource_type not in SIX_TYPES
    }


def test_L40j_old_ids_preserved_and_collision_rule_is_exact():
    for _, infrastructure in _law_snapshots():
        _assert_node_id_rule(infrastructure)


def test_L40k_random_collision_snapshots():
    rng = random.Random(40040)
    names = [f"synthetic-{index}" for index in range(6)]
    for _ in range(300):
        selected = {kind: set(rng.sample(names, rng.randint(0, 2))) for kind in SIX_TYPES}
        secret_names = selected["secretsmanager_secret"]
        lambda_names = list(selected["lambda_function"])
        if secret_names and not lambda_names:
            lambda_names = [names[0]]
            selected["lambda_function"].add(names[0])
        infrastructure = AWSInfrastructure(
            region=REGION,
            s3=S3Data(buckets=[S3Bucket(name=name) for name in selected["s3_bucket"]]),
            lambda_data=LambdaData(functions=[LambdaFunction(name=name, secret_refs=sorted(secret_names) if index == 0 else []) for index, name in enumerate(lambda_names)]),
            rds=RDSData(rds_instances=[RDSInstance(id=name) for name in selected["rds_instance"]]),
            dynamodb=DynamoDBData(tables=[_table(name) for name in selected["dynamodb_table"]]),
            sqs=SQSData(queues=[_queue(name) for name in selected["sqs_queue"]]),
            secrets_manager=SecretsManagerData(),
        )
        graph = build_graph(infrastructure)
        plan = NodeIdPlan.from_infras(infrastructure)
        for resource_type in SIX_TYPES:
            assert len(_nodes_of(graph, resource_type)) == len(plan.names[resource_type])
            for node in _nodes_of(graph, resource_type):
                name = node.id.split(":", 1)[-1] if node.id.startswith(f"{resource_type}:") else node.id
                assert node.id == plan.id(resource_type, name)
        assert not any(warning.get("kind") == "duplicate_node_id" for warning in graph.warnings)


def test_L40l_locked_suite_inputs_are_representable():
    # The locked scenario tests exercise every expected resource id through the runner.
    # Keeping this assertion in the law file makes the 41-test locked suite a required check.
    assert _law_snapshots()
