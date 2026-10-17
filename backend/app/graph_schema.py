"""Declared schemas for the provider-neutral infrastructure graph."""
from dataclasses import dataclass
from typing import Any

from app.egraph import Graph, Node, Edge, NodeCategory, RelationshipType

GRAPH_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class NodeSchema:
    resource_type: str
    category: str
    required: dict[str, frozenset[str]]
    optional: dict[str, frozenset[str]]


def _node(resource_type, category, required=(), optional=()):
    return NodeSchema(resource_type, category, {"base": frozenset(required)},
                      {"base": frozenset(optional)})


NODE_SCHEMAS = {
    "ec2_instance": _node("ec2_instance", "compute", ("instance_type", "state", "subnet_id", "sg_ids", "has_public_ip")),
    "lambda_function": _node("lambda_function", "compute", ("role_arn", "vpc_id", "subnet_ids", "sg_ids", "subnet_count")),
    "ecs_tasks": _node("ecs_tasks", "compute", optional=("is_virtual",)),
    "load_balancer": _node("load_balancer", "network", ("type", "target_count")),
    "api_gateway": _node("api_gateway", "network", ("api_type", "endpoint_type", "auth_type", "has_waf")),
    "elasticache_cluster": _node("elasticache_cluster", "database", ("engine", "node_type", "vpc_id", "sg_ids", "subnet_group")),
    "s3_bucket": _node("s3_bucket", "storage", ("is_public", "has_cloudfront", "has_policy", "is_empty")),
    "ebs_volume": _node("ebs_volume", "storage", ("state", "size_gb", "volume_type", "availability_zone")),
    "rds_instance": _node("rds_instance", "database", ("publicly_accessible", "encrypted", "sg_ids", "subnet_id")),
    "dynamodb_table": _node("dynamodb_table", "database", ("arn", "encryption_type", "pitr_enabled", "billing_mode")),
    "sqs_queue": _node("sqs_queue", "storage", ("arn", "encrypted", "is_public")),
    "secretsmanager_secret": _node("secretsmanager_secret", "storage", ("source",)),
    "security_group": _node("security_group", "network_boundary", ("name", "rules_count", "rules", "egress_rules", "attached_instances")),
    "network_acl": _node("network_acl", "network_boundary", ("entries", "is_default", "vpc_id")),
    "vpc_subnet": _node("vpc_subnet", "network", ("vpc_id", "cidr", "resource_count")),
    "vpc": _node("vpc", "network", ("is_default", "subnet_count", "source")),
    "vpc_peering_connection": _node("vpc_peering_connection", "network", ("requester_vpc_id", "accepter_vpc_id", "status")),
    "cloudfront_distribution": _node("cloudfront_distribution", "edge", ("origin_bucket",)),
    "iam_role": _node("iam_role", "identity", ("arn", "trusted_services", "trust_allows_external", "trust_has_conditions", "has_privilege_escalation"), ("source", "has_admin", "policies", "privilege_escalation_paths")),
    "internet": _node("internet", "other", ("is_virtual",)),
    "route_table": _node("route_table", "network", ("routes", "is_main", "vpc_id")),
    "internet_gateway": _node("internet_gateway", "network_boundary"),
    "nat_gateway": _node("nat_gateway", "network"),
    "transit_gateway_attachment": _node("transit_gateway_attachment", "network_boundary", ("vpc_id",)),
    "vpn_gateway": _node("vpn_gateway", "network_boundary", ("vpc_id",)),
    "interface_endpoint": _node("interface_endpoint", "network_boundary", ("vpc_id",)),
    "elastic_ip": _node("elastic_ip", "other", ("public_ip", "is_attached")),
}

# Relationship endpoint pairs are deliberately literal: this is the contract
# consumed by debug tooling and tests, not a rule used while building graphs.
EDGE_SCHEMAS = {
    RelationshipType.uses_security_group: frozenset({("ec2_instance", "security_group"), ("rds_instance", "security_group"), ("lambda_function", "security_group"), ("elasticache_cluster", "security_group")} ),
    RelationshipType.in_subnet: frozenset({("ec2_instance", "vpc_subnet"), ("lambda_function", "vpc_subnet"), ("rds_instance", "vpc_subnet")} ),
    RelationshipType.uses_iam_role: frozenset({("ec2_instance", "iam_role"), ("lambda_function", "iam_role")} ),
    RelationshipType.attached_to_instance: frozenset({("ebs_volume", "ec2_instance"), ("security_group", "ec2_instance"), ("security_group", "rds_instance")} ),
    RelationshipType.REACHES: frozenset({("internet", "security_group"), ("internet", "api_gateway")} ),
    RelationshipType.REACHES_VIA_SG: frozenset({("internet", "ec2_instance")} ),
    RelationshipType.targets_instance: frozenset({("load_balancer", "ec2_instance")} ),
    RelationshipType.serves_from_bucket: frozenset({("cloudfront_distribution", "s3_bucket")} ),
    RelationshipType.in_vpc: frozenset({("lambda_function", "vpc")} ),
    RelationshipType.REFERENCES_SECRET: frozenset({("lambda_function", "secretsmanager_secret")} ),
    RelationshipType.USES_ROLE: frozenset({("ecs_tasks", "iam_role")} ),
    RelationshipType.belongs_to_vpc: frozenset({("vpc_subnet", "vpc")} ),
    RelationshipType.contains_resource: frozenset({("vpc_subnet", "ec2_instance"), ("vpc_subnet", "rds_instance"), ("vpc_subnet", "lambda_function")} ),
    RelationshipType.ASSOCIATED_WITH: frozenset({("vpc_subnet", "route_table")} ),
    RelationshipType.PROTECTED_BY: frozenset({("vpc_subnet", "network_acl")} ),
    RelationshipType.ROUTES_TO: frozenset({("route_table", "internet_gateway"), ("route_table", "nat_gateway"), ("route_table", "vpc_peering_connection")} ),
    RelationshipType.PEERED_WITH: frozenset({("vpc_peering_connection", "vpc")} ),
    RelationshipType.can_access: frozenset({("iam_role", t) for t in ("s3_bucket", "rds_instance", "lambda_function", "secretsmanager_secret", "dynamodb_table", "sqs_queue")} ),
    RelationshipType.CAN_ASSUME: frozenset({("iam_role", "iam_role")} ),
    RelationshipType.CAN_REACH: frozenset({("ec2_instance", "rds_instance"), ("rds_instance", "ec2_instance"), ("lambda_function", "rds_instance"), ("rds_instance", "lambda_function")} ),
    RelationshipType.UNKNOWN: frozenset(),
}

EDGE_ATTRS = {
    RelationshipType.REACHES: frozenset({"ports", "reason", "confidence"}),
    RelationshipType.REACHES_VIA_SG: frozenset({"ports", "reason", "confidence"}),
    RelationshipType.can_access: frozenset({"actions", "effect", "has_condition", "confidence", "access_level", "privilege_escalation"}),
    RelationshipType.CAN_ASSUME: frozenset({"conditional", "confidence", "reason"}),
    RelationshipType.CAN_REACH: frozenset({"ports", "reason", "confidence", "flagged"}),
}


def _value(obj: Any, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def validate_node(node) -> list[str]:
    violations = []
    resource_type = _value(node, "resource_type", _value(node, "type"))
    schema = NODE_SCHEMAS.get(resource_type)
    if schema is None:
        return [f"unknown resource_type: {resource_type}"]
    category = _value(node, "category")
    category = getattr(category, "value", category)
    if category != schema.category:
        violations.append(f"wrong category for {resource_type}: {category}")
    for layer in set(schema.required) | set(schema.optional):
        values = _value(node, layer)
        values = values or {}
        allowed = schema.required.get(layer, frozenset()) | schema.optional.get(layer, frozenset())
        for key in schema.required.get(layer, frozenset()):
            if key not in values:
                violations.append(f"missing required key {layer}.{key} for {resource_type}")
        for key in values:
            if key not in allowed:
                violations.append(f"undeclared key {layer}.{key} for {resource_type}")
    return violations


def validate_edge(edge, graph) -> list[str]:
    violations = []
    relationship = _value(edge, "relationship")
    if isinstance(relationship, str):
        try:
            relationship = RelationshipType(relationship)
        except ValueError:
            try: relationship = RelationshipType[relationship]
            except KeyError: return [f"unknown relationship: {relationship}"]
    pairs = EDGE_SCHEMAS.get(relationship)
    if pairs is None:
        return [f"unknown relationship: {relationship}"]
    src, dst = _value(edge, "src", _value(edge, "from")), _value(edge, "dst", _value(edge, "to"))
    nodes = {n.id: n for n in getattr(graph, "nodes", [])}
    src_type, dst_type = _value(nodes.get(src), "resource_type", _value(nodes.get(src), "type")), _value(nodes.get(dst), "resource_type", _value(nodes.get(dst), "type"))
    if (src_type, dst_type) not in pairs:
        violations.append(f"disallowed endpoint types for {relationship.value}: {src_type} -> {dst_type}")
    attrs = _value(edge, "attrs", {}) or {}
    for key in attrs:
        if key not in EDGE_ATTRS.get(relationship, frozenset()):
            violations.append(f"undeclared attrs key {key} for {relationship.value}")
    return violations


def validate_graph(graph) -> list[str]:
    violations = []
    for node in getattr(graph, "nodes", []): violations.extend(validate_node(node))
    for edge in getattr(graph, "edges", []): violations.extend(validate_edge(edge, graph))
    return violations
