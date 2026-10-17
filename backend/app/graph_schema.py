"""Declared schemas for the provider-neutral infrastructure graph."""
from dataclasses import dataclass
from typing import Any

from app.egraph import Graph, Node, Edge, NodeCategory, RelationshipType, GRAPH_SCHEMA_VERSION


LAYER_NAMES = ("base", "security", "cost", "limits", "telemetry")


@dataclass(frozen=True)
class NodeSchema:
    resource_type: str
    category: str
    required: dict[str, dict[str, tuple[type, ...]]]
    optional: dict[str, dict[str, tuple[type, ...]]]


KEY_TYPES: dict[str, tuple[type, ...]] = {
    "instance_type": (str,),
    "state": (str, type(None)),
    "subnet_id": (str, type(None)),
    "sg_ids": (list,),
    "has_public_ip": (bool, type(None)),
    "role_arn": (str, type(None)),
    "vpc_id": (str, type(None)),
    "subnet_ids": (list,),
    "subnet_count": (int,),
    "is_virtual": (bool,),
    "type": (str,),
    "target_count": (int,),
    "api_type": (str,),
    "endpoint_type": (str,),
    "auth_type": (str,),
    "has_waf": (bool,),
    "engine": (str,),
    "node_type": (str,),
    "subnet_group": (str, type(None)),
    "is_public": (bool,),
    "has_cloudfront": (bool,),
    "has_policy": (bool,),
    "is_empty": (bool,),
    "size_gb": (int,),
    "volume_type": (str,),
    "availability_zone": (str, type(None)),
    "publicly_accessible": (bool,),
    "encrypted": (bool,),
    "arn": (str,),
    "encryption_type": (str,),
    "pitr_enabled": (bool,),
    "billing_mode": (str,),
    "source": (str,),
    "name": (str,),
    "rules_count": (int,),
    "rules": (list,),
    "egress_rules": (list,),
    "attached_instances": (list,),
    "entries": (list,),
    "is_default": (bool,),
    "cidr": (str, type(None)),
    "resource_count": (int,),
    "collected": (bool,),
    "requester_vpc_id": (str,),
    "accepter_vpc_id": (str,),
    "status": (str, type(None)),
    "origin_bucket": (str,),
    "trusted_services": (list,),
    "trust_allows_external": (bool,),
    "trust_has_conditions": (bool,),
    "has_privilege_escalation": (bool,),
    "has_admin": (bool,),
    "policies": (list,),
    "privilege_escalation_paths": (list,),
    "routes": (list,),
    "is_main": (bool,),
    "id": (str,),
    "transit_gateway_id": (str,),
    "service_name": (str, type(None)),
    "public_ip": (str,),
    "is_attached": (bool,),
}


def _node(resource_type, category, required=(), optional=()):
    required_keys = {key: KEY_TYPES[key] for key in required}
    optional_keys = {key: KEY_TYPES[key] for key in optional}
    return NodeSchema(resource_type, category,
                      {layer: (required_keys.copy() if layer == "base" else {}) for layer in LAYER_NAMES},
                      {layer: (optional_keys.copy() if layer == "base" else {}) for layer in LAYER_NAMES})


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
    "vpc": _node("vpc", "network", optional=("is_default", "subnet_count", "source", "collected")),
    "vpc_peering_connection": _node("vpc_peering_connection", "network", ("requester_vpc_id", "accepter_vpc_id", "status")),
    "cloudfront_distribution": _node("cloudfront_distribution", "edge", ("origin_bucket",)),
    "iam_role": _node("iam_role", "identity", ("arn", "trusted_services", "trust_allows_external", "trust_has_conditions", "has_privilege_escalation"), ("source", "has_admin", "policies", "privilege_escalation_paths")),
    "internet": _node("internet", "other", ("is_virtual",)),
    "route_table": _node("route_table", "network", ("routes", "is_main", "vpc_id")),
    "internet_gateway": _node("internet_gateway", "network_boundary", optional=("id",)),
    "nat_gateway": _node("nat_gateway", "network", optional=("id",)),
    "transit_gateway_attachment": _node("transit_gateway_attachment", "network_boundary", ("vpc_id",), ("id", "transit_gateway_id", "state")),
    "vpn_gateway": _node("vpn_gateway", "network_boundary", ("vpc_id",), ("id", "state")),
    "interface_endpoint": _node("interface_endpoint", "network_boundary", ("vpc_id",), ("id", "service_name")),
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
    RelationshipType.CAN_REACH: frozenset({("ec2_instance", "rds_instance"), ("rds_instance", "ec2_instance"), ("lambda_function", "rds_instance"), ("rds_instance", "lambda_function"), ("lambda_function", "ec2_instance"), ("ec2_instance", "lambda_function")} ),
    RelationshipType.UNKNOWN: frozenset(),
}

# Explicit edge-attribute catalog. Types are observed in ALL_SNAPSHOTS and in
# build_graph's ingress/internal/IAM emitters (egraph.py:780, 1008, 2166).
EDGE_ATTR_TYPES: dict[RelationshipType, dict[str, tuple[type, ...]]] = {
    RelationshipType.REACHES: {
        "ports": (list,), "reason": (str,), "confidence": (str,),
    },
    RelationshipType.REACHES_VIA_SG: {
        "ports": (list,), "reason": (str,), "confidence": (str,),
    },
    RelationshipType.can_access: {
        "actions": (list,), "effect": (str,), "has_condition": (bool,),
        "confidence": (str,), "access_level": (str,), "privilege_escalation": (bool,),
    },
    RelationshipType.CAN_ASSUME: {
        "conditional": (bool,), "confidence": (str,), "reason": (str,),
    },
    RelationshipType.CAN_REACH: {
        "ports": (list,), "reason": (str,), "confidence": (str,), "flagged": (bool,),
    },
}

# Backwards-compatible key-only view for callers that import EDGE_ATTRS.
EDGE_ATTRS = {
    relationship: frozenset(attrs) for relationship, attrs in EDGE_ATTR_TYPES.items()
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
    # Iterate the node's layers, rather than only layers declared by the schema.
    for layer in LAYER_NAMES:
        values = _value(node, layer) or {}
        if not isinstance(values, dict):
            continue
        required = schema.required.get(layer, {})
        optional = schema.optional.get(layer, {})
        allowed = {**required, **optional}
        for key in required:
            if key not in values:
                violations.append(f"missing required key {layer}.{key} for {resource_type}")
        for key, value in values.items():
            if key not in allowed:
                violations.append(f"undeclared key {layer}.{key} for {resource_type}")
                continue
            if not isinstance(value, allowed[key]):
                violations.append(f"wrong type for {layer}.{key} on {resource_type}: got {type(value)}")
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
    nodes = getattr(graph, "_node_index", None)
    if nodes is None:
        nodes = {n.id: n for n in getattr(graph, "nodes", [])}
    src_type, dst_type = _value(nodes.get(src), "resource_type", _value(nodes.get(src), "type")), _value(nodes.get(dst), "resource_type", _value(nodes.get(dst), "type"))
    if (src_type, dst_type) not in pairs:
        violations.append(f"disallowed endpoint types for {relationship.value}: {src_type} -> {dst_type}")
    attrs = _value(edge, "attrs", {}) or {}
    declared_attrs = EDGE_ATTR_TYPES.get(relationship, {})
    for key, value in attrs.items():
        if key not in declared_attrs:
            violations.append(f"undeclared attrs key {key} for {relationship.value}")
        elif not isinstance(value, declared_attrs[key]):
            violations.append(f"wrong type for attrs.{key} on {relationship.value}: got {type(value)}")
    return violations


def validate_graph(graph) -> list[str]:
    violations = []
    for node in getattr(graph, "nodes", []): violations.extend(validate_node(node))
    for edge in getattr(graph, "edges", []): violations.extend(validate_edge(edge, graph))
    return violations
