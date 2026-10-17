"""Law 27: every emitted graph node and edge has a declared schema."""
import pytest

from app.egraph import Edge, Graph, Node, RelationshipType, build_graph
from app.graph_schema import EDGE_SCHEMAS, KEY_TYPES, LAYER_NAMES, NODE_SCHEMAS, validate_edge, validate_node
from app.demo_seed import build_demo_infrastructure
from tests.incidents.synthetic_base import load_synthetic_base
from tests.laws.coverage_snapshot import build_coverage_infrastructure


def _snapshots():
    from tests import conftest
    values = [(name, getattr(conftest, name).__wrapped__()) for name in
              ("clean_infra", "nightmare_infra", "empty_infra")]
    values.append(("demo", build_demo_infrastructure()))
    values.append(("delete_base", load_synthetic_base("delete")))
    values.append(("coverage", build_coverage_infrastructure()))
    return values


ALL_SNAPSHOTS = _snapshots()
EMITTED_RESOURCE_TYPES = frozenset({
    "ec2_instance", "lambda_function", "ecs_tasks", "load_balancer", "api_gateway",
    "elasticache_cluster", "s3_bucket", "ebs_volume", "rds_instance", "dynamodb_table",
    "sqs_queue", "secretsmanager_secret", "security_group", "network_acl", "vpc_subnet",
    "vpc", "vpc_peering_connection", "cloudfront_distribution", "iam_role", "internet",
    "route_table", "internet_gateway", "nat_gateway", "transit_gateway_attachment",
    "vpn_gateway", "interface_endpoint", "elastic_ip",
})


def test_L27_every_node_matches_its_schema():
    for _, infrastructure in ALL_SNAPSHOTS:
        graph = build_graph(infrastructure)
        for node in graph.nodes:
            assert validate_node(node) == [], node


def test_L27_every_edge_matches_its_schema():
    for _, infrastructure in ALL_SNAPSHOTS:
        graph = build_graph(infrastructure)
        for edge in graph.edges:
            assert validate_edge(edge, graph) == [], edge


def test_L27_every_emitted_type_has_a_schema():
    assert all(member in EDGE_SCHEMAS for member in RelationshipType)
    assert all(resource_type in NODE_SCHEMAS for resource_type in EMITTED_RESOURCE_TYPES)


def test_L27_unknown_field_is_a_violation():
    node = Node(id="x", type="ec2_instance", label="x", base={"unknown": 1})
    violations = validate_node(node)
    assert violations and "unknown" in " ".join(violations)


def test_L27_unknown_type_is_a_violation():
    node = Node(id="x", type="not_a_resource", label="x")
    violations = validate_node(node)
    assert violations and "not_a_resource" in " ".join(violations)


def test_L27_wrong_endpoint_types_is_a_violation():
    graph = Graph([Node(id="a", type="ec2_instance", label="a"),
                   Node(id="b", type="rds_instance", label="b")], [])
    edge = Edge(src="a", dst="b", relationship=RelationshipType.uses_security_group)
    violations = validate_edge(edge, graph)
    assert violations and "endpoint" in " ".join(violations).lower()


def test_L27_no_dangling_edges():
    for _, infrastructure in ALL_SNAPSHOTS:
        graph = build_graph(infrastructure)
        node_ids = {node.id for node in graph.nodes}
        assert all(edge.src in node_ids and edge.dst in node_ids for edge in graph.edges)


def test_L27_coverage_snapshot_exercises_every_type():
    graph = build_graph(build_coverage_infrastructure())
    assert {node.resource_type for node in graph.nodes} == set(NODE_SCHEMAS)
    unreachable = {RelationshipType.REACHES_VIA_SG}
    assert {edge.relationship for edge in graph.edges} == set(RelationshipType) - {RelationshipType.UNKNOWN} - unreachable


@pytest.mark.xfail(strict=True, reason="known_gap: REACHES_VIA_SG is not emitted by build_graph coverage topology")
def test_L27_coverage_snapshot_known_unreachable_relationships():
    graph = build_graph(build_coverage_infrastructure())
    assert RelationshipType.REACHES_VIA_SG in {edge.relationship for edge in graph.edges}


def test_L27_undeclared_security_key_is_a_violation():
    node = Node(id="x", type="ec2_instance", label="x", security={"not_declared": True})
    assert "undeclared key security.not_declared" in " ".join(validate_node(node))


def test_L27_wrong_value_type_is_a_violation():
    node = Node(id="x", type="ec2_instance", label="x", base={"instance_type": 42})
    violations = validate_node(node)
    assert "wrong type for base.instance_type" in " ".join(violations)


def test_L27_every_schema_key_has_an_explicit_type():
    catch_all = (str, int, bool, list, dict, type(None))
    for schema in NODE_SCHEMAS.values():
        for layer in LAYER_NAMES:
            for key in (*schema.required.get(layer, {}), *schema.optional.get(layer, {})):
                assert KEY_TYPES[key]
                assert KEY_TYPES[key] != catch_all


def test_L27_none_is_rejected_where_not_declared():
    graph = build_graph(ALL_SNAPSHOTS[0][1])
    node = next(node for node in graph.nodes if node.resource_type == "ec2_instance")
    node.base["sg_ids"] = None
    violations = validate_node(node)
    assert "wrong type for base.sg_ids" in " ".join(violations)
