"""
Graph module for building infrastructure relationship graphs.

Transforms collected AWS infrastructure data into a graph representation
with nodes (resources) and edges (relationships between resources).
"""

import copy
import fnmatch
import re
from collections.abc import Mapping as MappingABC
from enum import Enum
from types import MappingProxyType
from typing import ClassVar, Dict, List, Any, Optional, Set, Mapping

from pydantic import BaseModel, Field, model_validator

from app.models import AWSInfrastructure
import app.iam_classifier as iam_classifier


_ACCESS_LEVEL_ORDER = {
    "Unknown": 0,
    "Read": 1,
    "List": 2,
    "Tagging": 3,
    "Write": 4,
    "Permissions management": 5,
}


def _annotate_access_attrs(attrs):
    """Additive IAM annotations; classification failures preserve the edge."""
    result = dict(attrs)
    actions = result.get("actions", []) or []
    levels = set()
    escalation = False
    try:
        for action in actions:
            levels.update(iam_classifier.classify_action(action))
            escalation = escalation or iam_classifier.is_privilege_escalation(action)
    except Exception:
        levels = {"Unknown"}
        escalation = False
    result["access_level"] = max(levels or {"Unknown"}, key=_ACCESS_LEVEL_ORDER.get)
    result["privilege_escalation"] = escalation
    return result


class NodeCategory(str, Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    NETWORK_BOUNDARY = "network_boundary"
    IDENTITY = "identity"
    PERMISSION = "permission"
    EDGE = "edge"
    OTHER = "other"


class RelationshipType(str, Enum):
    uses_security_group = "uses_security_group"
    in_subnet = "in_subnet"
    uses_iam_role = "uses_iam_role"
    attached_to_instance = "attached_to_instance"
    REACHES = "REACHES"
    REACHES_VIA_SG = "REACHES_VIA_SG"
    targets_instance = "targets_instance"
    serves_from_bucket = "serves_from_bucket"
    in_vpc = "in_vpc"
    REFERENCES_SECRET = "REFERENCES_SECRET"
    USES_ROLE = "USES_ROLE"
    belongs_to_vpc = "belongs_to_vpc"
    contains_resource = "contains_resource"
    ASSOCIATED_WITH = "associated_with"
    PROTECTED_BY = "protected_by"
    ROUTES_TO = "routes_to"
    PEERED_WITH = "peered_with"
    can_access = "can_access"
    CAN_ASSUME = "can_assume"
    CAN_REACH = "can_reach"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


TRAVERSABLE_RELATIONSHIPS = frozenset({
    "REACHES",
    "REACHES_VIA_SG",
    "CAN_REACH",
    "can_access",
    "can_assume",
    "uses_iam_role",
    "USES_ROLE",
    "REFERENCES_SECRET",
    "serves_from_bucket",
})


_RESOURCE_CATEGORIES = {
    "ec2_instance": NodeCategory.COMPUTE,
    "lambda_function": NodeCategory.COMPUTE,
    "ecs_tasks": NodeCategory.COMPUTE,
    "load_balancer": NodeCategory.NETWORK,
    "api_gateway": NodeCategory.NETWORK,
    "elasticache_cluster": NodeCategory.DATABASE,
    "s3_bucket": NodeCategory.STORAGE,
    "ebs_volume": NodeCategory.STORAGE,
    "rds_instance": NodeCategory.DATABASE,
    "dynamodb_table": NodeCategory.DATABASE,
    "sqs_queue": NodeCategory.STORAGE,
    "secretsmanager_secret": NodeCategory.STORAGE,
    "security_group": NodeCategory.NETWORK_BOUNDARY,
    "network_acl": NodeCategory.NETWORK_BOUNDARY,
    "vpc_subnet": NodeCategory.NETWORK,
    "vpc": NodeCategory.NETWORK,
    "vpc_peering_connection": NodeCategory.NETWORK,
    "cloudfront_distribution": NodeCategory.EDGE,
    "iam_role": NodeCategory.IDENTITY,
}


class Node(BaseModel, MappingABC):
    """Provider-neutral graph node with a backwards-compatible mapping API."""

    _SHIM_KEYS: ClassVar[tuple[str, ...]] = (
        "id",
        "type",
        "label",
        "metadata",
        "provider",
        "category",
        "resource_type",
        "base",
        "security",
        "cost",
        "limits",
        "telemetry",
    )

    id: str
    provider: str = "aws"
    category: NodeCategory = NodeCategory.OTHER
    resource_type: str
    label: str
    base: Dict[str, Any] = Field(default_factory=dict)
    security: Optional[Dict[str, Any]] = None
    cost: Optional[Dict[str, Any]] = None
    limits: Optional[Dict[str, Any]] = None
    telemetry: Optional[Dict[str, Any]] = None

    @model_validator(mode="before")
    @classmethod
    def _compat_input(cls, value):
        if isinstance(value, cls):
            return value
        data = dict(value)
        data["resource_type"] = data.get("resource_type", data.get("type", ""))
        metadata = data.pop("metadata", None)
        if metadata is not None:
            # Deep copy protects the graph from mutable collector/fixture input.
            data["base"] = copy.deepcopy(metadata)
        data["category"] = data.get("category") or _RESOURCE_CATEGORIES.get(
            data["resource_type"], NodeCategory.OTHER
        )
        return data

    @property
    def metadata(self) -> Mapping[str, Any]:
        merged: Dict[str, Any] = {}
        for layer in (self.base, self.security, self.cost, self.limits, self.telemetry):
            if layer:
                merged.update(layer)
        return MappingProxyType(copy.deepcopy(merged))

    def __getitem__(self, key):
        if key == "type":
            return self.resource_type
        if key == "metadata":
            return self.metadata
        if key in {"id", "provider", "category", "resource_type", "label", "base", "security", "cost", "limits", "telemetry"}:
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        return key in self._SHIM_KEYS

    def keys(self):
        return self._SHIM_KEYS

    def __iter__(self):
        return iter(self._SHIM_KEYS)

    def __len__(self):
        return len(self._SHIM_KEYS)

    def items(self):
        return tuple((key, self[key]) for key in self._SHIM_KEYS)

    def as_legacy_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.resource_type, "label": self.label, "metadata": dict(self.metadata)}


class Edge(BaseModel):
    """Provider-neutral graph edge with legacy ``from``/``to`` access."""

    src: str
    dst: str
    relationship: RelationshipType
    directed: bool = True
    weight: Optional[int] = None
    attrs: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _compat_input(cls, value):
        if isinstance(value, cls):
            return value
        data = dict(value)
        data["src"] = data.get("src", data.get("from"))
        data["dst"] = data.get("dst", data.get("to"))
        relationship = data.get("relationship", RelationshipType.UNKNOWN)
        if isinstance(relationship, str) and relationship in RelationshipType.__members__:
            relationship = RelationshipType[relationship]
        data["relationship"] = RelationshipType(relationship)
        if data.get("weight") is None:
            data["weight"] = EDGE_WEIGHTS.get(data["relationship"].value, 3)
        return data

    def __getitem__(self, key):
        if key == "from":
            return self.src
        if key == "to":
            return self.dst
        if key == "relationship":
            return self.relationship.value
        if key in {"src", "dst", "directed", "weight", "attrs"}:
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        return key in {"from", "to", "relationship", "src", "dst", "directed", "weight", "attrs"}

    def as_legacy_dict(self) -> Dict[str, Any]:
        return {"from": self.src, "to": self.dst, "relationship": self.relationship.value}


class Graph:
    """
    Graph data structure for AWS infrastructure relationships.
    
    Provides query methods to traverse and analyze the infrastructure graph.
    """
    
    def __init__(self, nodes: List[Node | Dict[str, Any]], edges: List[Edge | Dict[str, Any]]):
        """Initialize the graph and normalize legacy dictionaries to typed models."""
        self.nodes: List[Node] = [node if isinstance(node, Node) else Node.model_validate(node) for node in nodes]
        self.edges: List[Edge] = [edge if isinstance(edge, Edge) else Edge.model_validate(edge) for edge in edges]

        # Build lookup indexes for efficient queries
        self._node_index = {node['id']: node for node in self.nodes}
        self._edges_by_source: Dict[str, List[Edge]] = {}
        self._edges_by_target: Dict[str, List[Edge]] = {}
        self._nodes_by_type: Dict[str, List[Node]] = {}

        for edge in self.edges:
            from_id = edge['from']
            to_id = edge['to']
            self._edges_by_source.setdefault(from_id, []).append(edge)
            self._edges_by_target.setdefault(to_id, []).append(edge)

        for node in self.nodes:
            node_type = node['type']
            self._nodes_by_type.setdefault(node_type, []).append(node)
    
    def get_neighbors(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes connected to the given node (both inbound and outbound).
        
        Args:
            node_id: ID of the node to find neighbors for
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of neighbor nodes
        """
        neighbors = []
        neighbor_ids = set()
        
        # Get outbound neighbors
        for edge in self._edges_by_source.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                target_id = edge['to']
                if target_id not in neighbor_ids and target_id in self._node_index:
                    neighbors.append(self._node_index[target_id])
                    neighbor_ids.add(target_id)
        
        # Get inbound neighbors
        for edge in self._edges_by_target.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                source_id = edge['from']
                if source_id not in neighbor_ids and source_id in self._node_index:
                    neighbors.append(self._node_index[source_id])
                    neighbor_ids.add(source_id)
        
        return neighbors
    
    def get_inbound(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes that point TO this node (inbound edges).
        
        Args:
            node_id: ID of the target node
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of source nodes that point to this node
        """
        inbound_nodes = []
        
        for edge in self._edges_by_target.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                source_id = edge['from']
                if source_id in self._node_index:
                    inbound_nodes.append(self._node_index[source_id])
        
        return inbound_nodes
    
    def get_outbound(self, node_id: str, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find all nodes that this node points TO (outbound edges).
        
        Args:
            node_id: ID of the source node
            relationship_type: Optional filter by relationship type
        
        Returns:
            List of target nodes that this node points to
        """
        outbound_nodes = []
        
        for edge in self._edges_by_source.get(node_id, []):
            if relationship_type is None or edge['relationship'] == relationship_type:
                target_id = edge['to']
                if target_id in self._node_index:
                    outbound_nodes.append(self._node_index[target_id])
        
        return outbound_nodes
    
    def find_nodes_by_type(self, node_type: str) -> List[Dict[str, Any]]:
        """
        Find all nodes of a specific type.
        
        Args:
            node_type: Type of nodes to find (e.g., 'ec2_instance', 's3_bucket')
        
        Returns:
            List of nodes matching the type
        """
        return self._nodes_by_type.get(node_type, [])
    
    def has_connection(self, from_id: str, to_id: str, relationship: Optional[str] = None) -> bool:
        """
        Check if an edge exists between two nodes.
        
        Args:
            from_id: Source node ID
            to_id: Target node ID
            relationship: Optional specific relationship type to check
        
        Returns:
            True if the connection exists, False otherwise
        """
        for edge in self._edges_by_source.get(from_id, []):
            if edge['to'] == to_id:
                if relationship is None or edge['relationship'] == relationship:
                    return True
        
        return False
    
    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a node by its ID.
        
        Args:
            node_id: ID of the node to retrieve
        
        Returns:
            Node dictionary or None if not found
        """
        return self._node_index.get(node_id)
    
    def to_dict(self) -> Dict[str, List[Dict[str, Any]]]:
        """Convert the graph to its serializable legacy dictionary representation."""
        return {
            'nodes': [node.as_legacy_dict() for node in self.nodes],
            'edges': [edge.as_legacy_dict() for edge in self.edges],
        }


def _match_arn_to_node_id(arn: str, node_id_set: Set[str]) -> Optional[str]:
    """
    Match a policy Resource ARN to an existing graph node ID.

    Handles S3, RDS, Lambda, and Secrets Manager ARN formats.
    Returns None if no match found (cross-account, non-existent resource, or wildcard).
    """
    if not arn or arn == '*':
        return None

    # S3: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/*
    if ':s3:::' in arn:
        bucket = arn.split(':s3:::')[1].split('/')[0]
        if bucket == '*':
            return None
        if bucket in node_id_set:
            return bucket
        return None

    # RDS: arn:aws:rds:REGION:ACCOUNT:db:INSTANCE-ID
    if ':rds:' in arn and ':db:' in arn:
        rds_id = arn.split(':db:')[-1]
        if rds_id in node_id_set:
            return rds_id
        return None

    # Lambda: arn:aws:lambda:REGION:ACCOUNT:function:NAME
    if ':lambda:' in arn and ':function:' in arn:
        func_name = arn.split(':function:')[-1].split(':')[0]
        if func_name in node_id_set:
            return func_name
        return None

    # Secrets Manager: arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME-SUFFIX
    if ':secretsmanager:' in arn and ':secret:' in arn:
        secret_raw = arn.split(':secret:')[-1]
        # AWS appends a 6-char random suffix after a hyphen; try both with and without
        if secret_raw in node_id_set:
            return secret_raw
        # Strip last -XXXXXX suffix (6 random chars)
        stripped = re.sub(r'-[A-Za-z0-9]{6}$', '', secret_raw)
        if stripped in node_id_set:
            return stripped
        return None

    # DynamoDB: arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE-NAME
    if ':dynamodb:' in arn and ':table/' in arn:
        table_name = arn.split(':table/')[-1].split('/')[0]
        if table_name in node_id_set:
            return table_name
        return None

    # SQS: arn:aws:sqs:REGION:ACCOUNT:QUEUE-NAME
    if ':sqs:' in arn:
        queue_name = arn.split(':')[-1]
        if queue_name in node_id_set:
            return queue_name
        return None

    return None


def _match_wildcard_arn_to_service(arn: str) -> Optional[str]:
    """
    Determine which service a wildcard Resource ARN targets.

    Returns the node type string if the ARN uses a wildcard pattern for a
    supported service, or None otherwise.
    """
    if not arn or arn == '*':
        return None
    # S3 with wildcard in bucket name: arn:aws:s3:::prod-* or arn:aws:s3:::*
    if ':s3:::' in arn:
        bucket_part = arn.split(':s3:::')[1].split('/')[0]
        if '*' in bucket_part:
            return 's3_bucket'
    # RDS with wildcard: arn:aws:rds:...:db:*
    if ':rds:' in arn and ':db:' in arn:
        rds_part = arn.split(':db:')[-1]
        if '*' in rds_part:
            return 'rds_instance'
    # DynamoDB with wildcard: arn:aws:dynamodb:...:table/*
    if ':dynamodb:' in arn and ':table/' in arn:
        table_part = arn.split(':table/')[-1].split('/')[0]
        if '*' in table_part:
            return 'dynamodb_table'
    # SQS with wildcard: arn:aws:sqs:...:*
    if ':sqs:' in arn:
        queue_part = arn.split(':')[-1]
        if '*' in queue_part:
            return 'sqs_queue'
    return None


def _value(obj, key, default=None):
    if isinstance(obj, MappingABC):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _iam_action_overlap(left: str, right: str) -> bool:
    """Conservatively determine whether two IAM action patterns overlap."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return (left == '*' or right == '*' or
            fnmatch.fnmatchcase(left.lower(), right.lower()) or
            fnmatch.fnmatchcase(right.lower(), left.lower()))


def _policy_resource_matches(resource: str, node: MappingABC) -> bool:
    """Match a policy resource against a supported data node."""
    if not isinstance(resource, str) or resource == '*':
        return resource == '*'
    node_id = _value(node, 'id', '')
    node_type = _value(node, 'type', _value(node, 'resource_type', ''))
    matched = _match_arn_to_node_id(resource, {node_id})
    if matched == node_id:
        return True
    service_type = _match_wildcard_arn_to_service(resource)
    if service_type != node_type:
        return False
    if ':s3:::' in resource:
        pattern = resource.split(':s3:::', 1)[1].split('/')[0]
    elif ':db:' in resource:
        pattern = resource.split(':db:', 1)[1]
    elif ':table/' in resource:
        pattern = resource.split(':table/', 1)[1].split('/')[0]
    elif ':sqs:' in resource:
        pattern = resource.rsplit(':', 1)[-1]
    else:
        return False
    return fnmatch.fnmatchcase(node_id, pattern)


_IAM_SERVICE_FOR_NODE_TYPE = {
    's3_bucket': 's3',
    'rds_instance': 'rds',
    'lambda_function': 'lambda',
    'secretsmanager_secret': 'secretsmanager',
    'dynamodb_table': 'dynamodb',
    'sqs_queue': 'sqs',
}


def _statement_value(statement, key, default=None):
    """Read a normalized statement from either a model or mapping."""
    return _value(statement, key, default)


def _action_applies_to_node(action, node, is_not_action=False) -> bool:
    """Return whether an IAM action pattern can address this data node type."""
    if is_not_action:
        # NotAction is intentionally conservative: its complement is uncertain,
        # but it must not create service-specific false negatives.
        return True
    if not isinstance(action, str) or action == '*':
        return action == '*'
    service = _IAM_SERVICE_FOR_NODE_TYPE.get(_value(node, 'type', _value(node, 'resource_type', '')))
    if not service:
        return False
    prefix = action.split(':', 1)[0].lower() if ':' in action else None
    return prefix == service


def _statement_action_applies(statement, node) -> bool:
    actions = list(_statement_value(statement, 'actions', []) or [])
    return bool(_statement_value(statement, 'is_not_action', False)) or any(
        _action_applies_to_node(action, node, _statement_value(statement, 'is_not_action', False))
        for action in actions
    )


def _statement_resource_matches(statement, node) -> bool:
    resources = list(_statement_value(statement, 'resources', []) or [])
    if _statement_value(statement, 'is_not_resource', False):
        return not any(_policy_resource_matches(resource, node) for resource in resources)
    return any(_policy_resource_matches(resource, node) for resource in resources)


def _relationship(edge):
    value = _value(edge, "relationship", "")
    return getattr(value, "value", value)


def _graph_edges(graph):
    if hasattr(graph, "edges"):
        return list(graph.edges)
    return list(graph.get("edges", [])) if isinstance(graph, MappingABC) else []


def _graph_node(graph, node_id):
    if hasattr(graph, "get_node"):
        return graph.get_node(node_id)
    nodes = graph.get("nodes", []) if isinstance(graph, MappingABC) else []
    return next((node for node in nodes if _value(node, "id") == node_id), None)


def _is_relationship(edge, name):
    value = str(_relationship(edge)).lower()
    return value in {name.lower(), name.replace("_", "").lower()}


def is_traversable_relationship(edge) -> bool:
    """Return whether an edge represents an allowed movement relationship.

    Accepts both typed ``Edge`` instances and legacy mapping-shaped edges, and
    never mutates the edge.
    """
    relationship = _value(edge, "relationship", "")
    value = getattr(relationship, "value", relationship)
    name = getattr(relationship, "name", None)
    if value in TRAVERSABLE_RELATIONSHIPS or name in TRAVERSABLE_RELATIONSHIPS:
        return True
    # RelationshipType.CAN_REACH is serialized as its lowercase enum value.
    return value == "can_reach" and "CAN_REACH" in TRAVERSABLE_RELATIONSHIPS


def filter_traversable_edges(edges):
    """Return only movement edges from an iterable of typed or legacy edges."""
    return [edge for edge in edges if is_traversable_relationship(edge)]


def subnet_has_igw_route(subnet_id, graph) -> Optional[bool]:
    """Return whether an associated route table has an exact default IGW route."""
    associated = [edge for edge in _graph_edges(graph)
                  if _value(edge, "src", _value(edge, "from")) == subnet_id
                  and _is_relationship(edge, "ASSOCIATED_WITH")]
    if not associated:
        return None
    saw_data = False
    for edge in associated:
        route_table = _graph_node(graph, _value(edge, "dst", _value(edge, "to")))
        data = _value(route_table, "base", {}) if route_table else {}
        routes = _value(data, "routes") if data else None
        if routes is None and route_table is not None:
            routes = _value(_value(route_table, "metadata", {}) or {}, "routes")
        if not isinstance(routes, (list, tuple)):
            continue
        saw_data = True
        for route in routes:
            if (_value(route, "destination_cidr") == "0.0.0.0/0" and
                    str(_value(route, "target_type", "")).lower() == "internet_gateway"):
                return True
    return False if saw_data else None


def _port_overlap(request_from, request_to, entry_from, entry_to):
    request_from = 0 if request_from is None else request_from
    request_to = 65535 if request_to is None else request_to
    entry_from = 0 if entry_from is None else entry_from
    entry_to = 65535 if entry_to is None else entry_to
    try:
        return int(request_from) <= int(entry_to) and int(entry_from) <= int(request_to)
    except (TypeError, ValueError):
        return True


def nacl_allows_inbound(subnet_id, port_from, port_to, protocol, graph) -> tuple[bool, str]:
    """Evaluate associated inbound NACL entries using AWS first-match ordering."""
    acl_edges = [edge for edge in _graph_edges(graph)
                 if _value(edge, "src", _value(edge, "from")) == subnet_id
                 and _is_relationship(edge, "PROTECTED_BY")]
    if not acl_edges:
        return True, "assumed"
    entries = []
    for edge_index, edge in enumerate(acl_edges):
        acl = _graph_node(graph, _value(edge, "dst", _value(edge, "to")))
        data = _value(acl, "base", {}) if acl else {}
        raw_entries = _value(data, "entries") if data else None
        if raw_entries is None and acl:
            raw_entries = _value(_value(acl, "metadata", {}) or {}, "entries")
        if isinstance(raw_entries, (list, tuple)):
            entries.extend((edge_index, item) for item in raw_entries)
    def sort_key(pair):
        number = _value(pair[1], "rule_number", 10**9)
        return (number if isinstance(number, (int, float)) else 10**9, pair[0])
    entries.sort(key=sort_key)
    wanted_protocol = str(protocol or "-1").lower()
    wanted_protocol = {"tcp": "6", "udp": "17", "icmp": "1"}.get(wanted_protocol, wanted_protocol)
    for _, entry in entries:
        if _value(entry, "egress", None) is not False:
            continue
        if _value(entry, "cidr_block") != "0.0.0.0/0":
            continue
        entry_protocol = str(_value(entry, "protocol", "-1")).lower()
        if entry_protocol not in {"-1", "all", wanted_protocol}:
            continue
        if not _port_overlap(port_from, port_to, _value(entry, "port_from"), _value(entry, "port_to")):
            continue
        return str(_value(entry, "rule_action", "")).lower() == "allow", "high"
    return False, "high"


def internet_ingress(resource_node, subnet_id, sg_list, graph) -> list[dict]:
    """Return deterministic, gated public ingress evidence for a resource."""
    resource_type = _value(resource_node, "resource_type", _value(resource_node, "type"))
    is_ec2 = resource_type == "ec2_instance"
    public_ip = None
    if is_ec2:
        base = _value(resource_node, "base", None)
        if base is None:
            base = _value(resource_node, "metadata", {}) or {}
        public_ip = _value(base, "has_public_ip", None)
        if public_ip is False:
            return []
    route = subnet_has_igw_route(subnet_id, graph) if subnet_id else None
    if route is False:
        return []
    public_ip_suffix = f" + {'public IP' if public_ip is True else 'public IP assumed'}" if is_ec2 else ""
    results = []
    for sg_ref in sg_list or []:
        sg = sg_ref if isinstance(sg_ref, MappingABC) or isinstance(sg_ref, Node) else _graph_node(graph, sg_ref)
        if sg is None:
            continue
        sg_id = _value(sg, "id", str(sg_ref))
        data = _value(sg, "base", {}) or {}
        rules = _value(data, "rules")
        if rules is None:
            rules = _value(_value(sg, "metadata", {}) or {}, "rules")
        for rule in rules if isinstance(rules, (list, tuple)) else []:
            ranges = _value(rule, "ip_ranges", []) or []
            public = next((str(cidr) for cidr in ranges if str(cidr) in {"0.0.0.0/0", "::/0"}), None)
            if public is None:
                continue
            from_port, to_port = _value(rule, "from_port"), _value(rule, "to_port")
            ports = ["all"] if from_port is None or to_port is None else [from_port, to_port]
            nacl, nacl_confidence = nacl_allows_inbound(subnet_id, from_port, to_port, _value(rule, "protocol", "-1"), graph) if subnet_id else (True, "assumed")
            if not nacl:
                continue
            route_text = "IGW route" if route is True else "IGW route uncertain"
            nacl_text = "NACL allow" if nacl_confidence == "high" else "NACL assumed"
            port_text = "all" if ports == ["all"] else f"{from_port}-{to_port}"
            result = {"ports": ports, "reason": f"{route_text} + SG {public}:{port_text} + {nacl_text}{public_ip_suffix}", "confidence": "high" if route is True and nacl_confidence == "high" and (not is_ec2 or public_ip is True) else "assumed"}
            if result not in results:
                results.append(result)
    return results




def _node_data(node):
    base = _value(node, "base", None)
    if base is None:
        base = _value(node, "metadata", {}) or {}
    return base or {}


def _resource_subnets(node, graph):
    data = _node_data(node)
    ids = []
    for key in ("subnet_id", "subnet_ids"):
        value = _value(data, key)
        if isinstance(value, (list, tuple)):
            ids.extend(str(item) for item in value if item)
        elif value:
            ids.append(str(value))
    node_id = _value(node, "id")
    for edge in _graph_edges(graph):
        if _value(edge, "src", _value(edge, "from")) != node_id:
            continue
        if _is_relationship(edge, "in_subnet"):
            subnet_id = _value(edge, "dst", _value(edge, "to"))
            if subnet_id and subnet_id not in ids:
                ids.append(subnet_id)
    return sorted(set(ids))


def _subnet_vpc(subnet_id, graph):
    subnet = _graph_node(graph, subnet_id)
    if subnet is None:
        return None
    data = _node_data(subnet)
    vpc_id = _value(data, "vpc_id")
    if vpc_id:
        return vpc_id
    for edge in _graph_edges(graph):
        if (_value(edge, "src", _value(edge, "from")) == subnet_id and
                _is_relationship(edge, "belongs_to_vpc")):
            return _value(edge, "dst", _value(edge, "to"))
    return None


def _subnet_cidr(subnet_id, graph):
    subnet = _graph_node(graph, subnet_id)
    return _value(_node_data(subnet), "cidr") if subnet else None


def _resource_vpc(node, graph):
    subnets = _resource_subnets(node, graph)
    return _subnet_vpc(subnets[0], graph) if subnets else None


def _route_table_ids_for_subnet(subnet_id, graph):
    return sorted({_value(edge, "dst", _value(edge, "to")) for edge in _graph_edges(graph)
                   if _value(edge, "src", _value(edge, "from")) == subnet_id
                   and _is_relationship(edge, "associated_with")})


def route_between(a_node, b_node, graph):
    """Classify the modeled or conservatively assumed route between resources."""
    a_vpc, b_vpc = _resource_vpc(a_node, graph), _resource_vpc(b_node, graph)
    if not a_vpc or not b_vpc:
        return "assumed_flagged", "placement unknown"
    if a_vpc == b_vpc:
        return "routed_high", "same-VPC local"
    peering_nodes = list(graph.find_nodes_by_type("vpc_peering_connection") if hasattr(graph, "find_nodes_by_type") else [])
    for peering in sorted(peering_nodes, key=lambda node: _value(node, "id", "")):
        data = _node_data(peering)
        if {_value(data, "requester_vpc_id"), _value(data, "accepter_vpc_id")} != {a_vpc, b_vpc}:
            continue
        if _value(data, "status", "") != "active":
            continue
        peering_id = _value(peering, "id")
        sides_ok = True
        for resource in (a_node, b_node):
            if not any(any(str(_value(route, "target_type", "")).lower() == "vpc_peering" and
                           _value(route, "target_id") == peering_id
                           for route in (_node_data(_graph_node(graph, table_id)).get("routes", []) or []))
                         for subnet_id in _resource_subnets(resource, graph)
                         for table_id in _route_table_ids_for_subnet(subnet_id, graph)):
                sides_ok = False
                break
        if sides_ok:
            return "routed_high", "active peering"
    # VPN/on-prem and PrivateLink provider/consumer paths are a known coverage gap;
    # they are not modeled here.
    if any(_value(_node_data(node), "vpc_id") in {a_vpc, b_vpc}
           for node in (graph.find_nodes_by_type("transit_gateway_attachment")
                        if hasattr(graph, "find_nodes_by_type") else [])):
        return "assumed_flagged", "possible via unmodeled Transit Gateway"
    return "blocked", "no modeled cross-VPC path"


def _protocol_matches(rule_protocol, requested):
    rule = str(rule_protocol if rule_protocol is not None else "-1").lower()
    wanted = str(requested if requested is not None else "-1").lower()
    aliases = {"tcp": "6", "udp": "17", "icmp": "1"}
    return rule in {"-1", "all", wanted, aliases.get(wanted, wanted)} or aliases.get(rule, rule) == wanted


def _rule_ports(rule):
    return _value(rule, "from_port"), _value(rule, "to_port")


def _rule_matches(rule, port_range):
    return (_protocol_matches(_value(rule, "protocol", "-1"), port_range[2]) and
            _port_overlap(port_range[0], port_range[1], *_rule_ports(rule)))


def _sg_ids(node):
    data = _node_data(node)
    ids = _value(data, "sg_ids", _value(data, "security_groups", [])) or []
    return sorted({str(item) for item in ids if item})


def _sg_rules(node, graph, key):
    result = []
    for sg_id in _sg_ids(node):
        sg = _graph_node(graph, sg_id)
        if sg is not None:
            result.append((sg, _node_data(sg).get(key, []) or []))
    return result


def _rule_scope(rule, peer_sg_ids, peer_cidr, sg_reference_key):
    """Match only the SG reference key valid for this traffic direction."""
    refs = set(_value(rule, sg_reference_key, []) or [])
    ranges = {str(item) for item in (_value(rule, "ip_ranges", []) or [])}
    return bool(refs & set(peer_sg_ids) or
                any(_cidr_covers(cidr, peer_cidr) for cidr in ranges))


def sg_allows_ab(a_node, b_node, graph, port_range):
    """Evaluate directional SG egress from A and ingress to B."""
    a_sgs, b_sgs = _sg_ids(a_node), _sg_ids(b_node)
    a_subnets, b_subnets = _resource_subnets(a_node, graph), _resource_subnets(b_node, graph)
    a_cidr = _subnet_cidr(a_subnets[0], graph) if a_subnets else None
    b_cidr = _subnet_cidr(b_subnets[0], graph) if b_subnets else None
    egress = [rule for _, rules in _sg_rules(a_node, graph, "egress_rules") for rule in rules]
    ingress = [rule for _, rules in _sg_rules(b_node, graph, "rules") for rule in rules]
    if not egress:
        egress_ok, egress_real = True, False
    else:
        egress_ok = any(_rule_matches(rule, port_range) and
                        _rule_scope(rule, b_sgs, b_cidr, "dest_sg_ids")
                        for rule in egress)
        egress_real = True
    ingress_ok = any(_rule_matches(rule, port_range) and
                     _rule_scope(rule, a_sgs, a_cidr, "source_sg_ids")
                     for rule in ingress)
    return egress_ok and ingress_ok, "high" if egress_real and ingress_ok else "assumed"


def _nacl_subnets(subnet_id, graph):
    return [_graph_node(graph, _value(edge, "dst", _value(edge, "to"))) for edge in _graph_edges(graph)
            if _value(edge, "src", _value(edge, "from")) == subnet_id and _is_relationship(edge, "protected_by")]


def _cidr_covers(cidr, opposite_cidr):
    if not cidr or not opposite_cidr:
        return False
    if cidr == "0.0.0.0/0":
        return True
    try:
        import ipaddress
        return ipaddress.ip_network(opposite_cidr, strict=False).subnet_of(
            ipaddress.ip_network(cidr, strict=False)
        )
    except ValueError:
        return cidr == opposite_cidr


def _nacl_denies(entries, opposite_cidr, port_range, egress):
    """Return whether the first applicable NACL entry is a clear DENY."""
    applicable = []
    for entry in sorted(entries, key=lambda item: _value(item, "rule_number", 10**9)):
        if bool(_value(entry, "egress", False)) != egress:
            continue
        if not _cidr_covers(_value(entry, "cidr_block"), opposite_cidr):
            continue
        if not _protocol_matches(_value(entry, "protocol", "-1"), port_range[2]):
            continue
        if not _port_overlap(port_range[0], port_range[1], *_rule_ports(entry)):
            continue
        applicable.append(entry)
    if not applicable:
        return False
    return str(_value(applicable[0], "rule_action", "")).lower() == "deny"


def nacl_internal_ok(a_node, b_node, graph, port_range):
    a_subnets, b_subnets = _resource_subnets(a_node, graph), _resource_subnets(b_node, graph)
    if not a_subnets or not b_subnets:
        return True, "assumed"
    a_cidr, b_cidr = _subnet_cidr(a_subnets[0], graph), _subnet_cidr(b_subnets[0], graph)
    a_acls = [acl for subnet in a_subnets for acl in _nacl_subnets(subnet, graph) if acl]
    b_acls = [acl for subnet in b_subnets for acl in _nacl_subnets(subnet, graph) if acl]
    for acl in b_acls:
        if _nacl_denies(_node_data(acl).get("entries", []) or [], a_cidr, port_range, egress=False):
            return False, "high"
    for acl in a_acls:
        if _nacl_denies(_node_data(acl).get("entries", []) or [], b_cidr, port_range, egress=True):
            return False, "high"
    return True, "high" if a_acls or b_acls else "assumed"


def internal_reachable(a_node, b_node, graph):
    ingress = [rule for _, rules in _sg_rules(b_node, graph, "rules") for rule in rules]
    results = []
    route_status, route_reason = route_between(a_node, b_node, graph)
    if not ingress or route_status == "blocked":
        return results
    for rule in sorted(ingress, key=lambda item: (str(_value(item, "from_port")), str(_value(item, "to_port")), str(_value(item, "protocol", "-1")), str(item))):
        from_port, to_port = _rule_ports(rule)
        ports = [0, 65535] if from_port is None or to_port is None else [int(from_port), int(to_port)]
        port_range = (ports[0], ports[1], _value(rule, "protocol", "-1"))
        allowed, sg_confidence = sg_allows_ab(a_node, b_node, graph, port_range)
        if not allowed:
            continue
        nacl_ok, nacl_confidence = nacl_internal_ok(a_node, b_node, graph, port_range)
        if not nacl_ok:
            continue
        confidence = "high" if route_status == "routed_high" and sg_confidence == "high" and nacl_confidence == "high" else "assumed"
        evidence = {"ports": ports, "reason": f"{route_reason} + SG allow + NACL {'allow' if nacl_confidence == 'high' else 'assumed'}", "confidence": confidence, "flagged": route_status == "assumed_flagged"}
        if evidence not in results:
            results.append(evidence)
    return results
def build_graph(infrastructure: AWSInfrastructure) -> Graph:

    """
    Build a graph representation of AWS infrastructure from collected data.
    
    Focuses on EC2, S3, RDS, Lambda, and VPC services.
    
    Args:
        infrastructure: AWSInfrastructure object with collected relationship data
    
    Returns:
        Graph object with nodes and edges, providing query methods for traversal
    """
    nodes = []
    edges = []
    
    # ── EC2 NODES ─────────────────────────────────────────────────
    # EC2 Instances
    for instance in infrastructure.ec2.instances:
        # Handle both dict and Pydantic model formats
        if isinstance(instance, dict):
            instance_id = instance['id']
            instance_type = instance['type']
            instance_state = instance['state']
            sg_ids = instance.get('sg_ids', [])
            subnet_id = instance.get('subnet_id')
            has_public_ip = instance.get('has_public_ip')
        else:
            instance_id = instance.id
            instance_type = instance.type
            instance_state = instance.state
            sg_ids = instance.sg_ids
            subnet_id = instance.subnet_id
            has_public_ip = instance.has_public_ip
        
        nodes.append({
            'id': instance_id,
            'type': 'ec2_instance',
            'label': f"EC2: {instance_id}",
            'metadata': {
                'instance_type': instance_type,
                'state': instance_state,
                'subnet_id': subnet_id,
                'sg_ids': sg_ids,
                'has_public_ip': has_public_ip
            }
        })
        
        # Edge: Instance -> Security Group
        for sg_id in sg_ids:
            edges.append({
                'from': instance_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })
        
        # Edge: Instance -> Subnet
        if subnet_id:
            edges.append({
                'from': instance_id,
                'to': subnet_id,
                'relationship': 'in_subnet'
            })
        
        # Edge: Instance -> IAM Role (via instance profile)
        instance_profile_arn = instance.get('instance_profile_arn') if isinstance(instance, dict) else getattr(instance, 'instance_profile_arn', None)
        if instance_profile_arn:
            profile_name = instance_profile_arn.split('/')[-1]
            profile_roles = getattr(infrastructure.iam, 'instance_profile_roles', {}) or {}
            mapping = profile_roles.get(instance_profile_arn)
            if not isinstance(mapping, dict):
                mapping = profile_roles.get(profile_name)
            actual_role_name = mapping.get('role_name') if isinstance(mapping, dict) else None
            actual_role_arn = mapping.get('role_arn') if isinstance(mapping, dict) else None
            if not (isinstance(actual_role_name, str) and actual_role_name):
                actual_role_name = profile_name
            if not (isinstance(actual_role_arn, str) and actual_role_arn):
                actual_role_arn = instance_profile_arn
            role_id = f"iam-role-{actual_role_name}"
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {actual_role_name}",
                    'metadata': {'arn': actual_role_arn, 'source': 'instance_profile'}
                })
            edges.append({
                'from': instance_id,
                'to': role_id,
                'relationship': 'uses_iam_role'
            })
    
    # Security Groups
    for sg in infrastructure.ec2.security_groups:
        # Handle both dict and Pydantic model formats
        if isinstance(sg, dict):
            sg_id = sg['id']
            sg_name = sg['name']
            rules = sg.get('rules', [])
            egress_rules = sg.get('egress_rules', [])
            attached_to = sg.get('attached_to', [])
        else:
            sg_id = sg.id
            sg_name = sg.name
            rules = sg.rules
            egress_rules = sg.egress_rules
            attached_to = sg.attached_to
        
        nodes.append({
            'id': sg_id,
            'type': 'security_group',
            'label': f"SG: {sg_name}",
            'metadata': {
                'name': sg_name,
                'rules_count': len(rules),
                'rules': rules,
                'egress_rules': egress_rules,
                'attached_instances': attached_to
            }
        })
        
        # Edge: Security Group -> Instance (attached_to)
        for instance_id in attached_to:
            edges.append({
                'from': sg_id,
                'to': instance_id,
                'relationship': 'attached_to_instance'
            })
    
    # ── INTERNET REACHABILITY ─────────────────────────────────────
    # Evaluate against route-table and NACL relationships without using the
    # legacy is_public/public_subnet_ids approximation.
    snapshot_nodes = list(nodes)
    snapshot_edges = list(edges)
    known_ids = {_value(node, 'id') for node in snapshot_nodes}
    for subnet in infrastructure.vpc.subnets:
        subnet_id = _value(subnet, 'id')
        if subnet_id not in known_ids:
            snapshot_nodes.append({'id': subnet_id, 'type': 'vpc_subnet', 'label': f'Subnet: {subnet_id}', 'metadata': {}})
            known_ids.add(subnet_id)
    for route_table in infrastructure.vpc.route_tables:
        route_table_id = _value(route_table, 'id')
        routes = [_value(route, 'model_dump', lambda: route)() if hasattr(route, 'model_dump') else route for route in (_value(route_table, 'routes', []) or [])]
        if route_table_id not in known_ids:
            snapshot_nodes.append({'id': route_table_id, 'type': 'route_table', 'label': f'Route Table: {route_table_id}', 'base': {'routes': routes}})
            known_ids.add(route_table_id)
        for subnet_id in _value(route_table, 'associated_subnet_ids', []) or []:
            snapshot_edges.append({'from': subnet_id, 'to': route_table_id, 'relationship': 'associated_with'})
    for nacl in infrastructure.vpc.nacls:
        nacl_id = _value(nacl, 'id')
        entries = [_value(entry, 'model_dump', lambda: entry)() if hasattr(entry, 'model_dump') else entry for entry in (_value(nacl, 'entries', []) or [])]
        if nacl_id not in known_ids:
            snapshot_nodes.append({'id': nacl_id, 'type': 'network_acl', 'label': f'Network ACL: {nacl_id}', 'base': {'entries': entries}})
            known_ids.add(nacl_id)
        for subnet_id in _value(nacl, 'associated_subnet_ids', []) or []:
            snapshot_edges.append({'from': subnet_id, 'to': nacl_id, 'relationship': 'protected_by'})
    reachability_graph = Graph(snapshot_nodes, snapshot_edges)
    internet_node_added = False
    sg_evidence = {}
    instance_evidence = {}
    instance_by_id = {_value(instance, 'id'): instance for instance in infrastructure.ec2.instances}
    for sg in infrastructure.ec2.security_groups:
        sg_id = _value(sg, 'id')
        attached_to = _value(sg, 'attached_to', []) or []
        for instance_id in attached_to:
            instance = instance_by_id.get(instance_id)
            subnet_id = _value(instance, 'subnet_id') if instance is not None else None
            resource_node = _graph_node(reachability_graph, instance_id) or {'id': instance_id}
            evidence = internet_ingress(resource_node, subnet_id, [sg_id], reachability_graph)
            if evidence:
                chosen = sorted(evidence, key=lambda item: (str(item['ports']), item['reason'], item['confidence']))[0]
                instance_evidence[instance_id] = chosen
            sg_node = _graph_node(reachability_graph, sg_id) or {'id': sg_id, 'type': 'security_group'}
            sg_evidence_for_sg = internet_ingress(sg_node, subnet_id, [sg_id], reachability_graph)
            if sg_evidence_for_sg:
                chosen_sg = sorted(sg_evidence_for_sg, key=lambda item: (str(item['ports']), item['reason'], item['confidence']))[0]
                sg_evidence[sg_id] = min((sg_evidence.get(sg_id), chosen_sg), key=lambda item: (str(item['ports']), item['reason'], item['confidence'])) if sg_id in sg_evidence else chosen_sg
    for instance_id, evidence in sorted(instance_evidence.items()):
        if not internet_node_added:
            nodes.append({'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}})
            internet_node_added = True
        edges.append({'from': 'INTERNET', 'to': instance_id, 'relationship': 'REACHES_VIA_SG', 'attrs': evidence})
    for sg_id, evidence in sorted(sg_evidence.items()):
        edges.append({'from': 'INTERNET', 'to': sg_id, 'relationship': 'REACHES', 'attrs': evidence})

    # Load Balancers
    for lb in infrastructure.ec2.load_balancers:
        # Handle both dict and Pydantic model formats
        if isinstance(lb, dict):
            lb_arn = lb['arn']
            lb_type = lb['type']
            target_instances = lb.get('target_instances', [])
        else:
            lb_arn = lb.arn
            lb_type = lb.type
            target_instances = lb.target_instances
        
        lb_id = lb_arn.split('/')[-1]  # Extract short ID from ARN
        nodes.append({
            'id': lb_arn,
            'type': 'load_balancer',
            'label': f"LB: {lb_id}",
            'metadata': {
                'type': lb_type,
                'target_count': len(target_instances)
            }
        })
        
        # Edge: Load Balancer -> EC2 Instance
        for instance_id in target_instances:
            edges.append({
                'from': lb_arn,
                'to': instance_id,
                'relationship': 'targets_instance'
            })
    
    # ── S3 NODES ──────────────────────────────────────────────────
    for bucket in infrastructure.s3.buckets:
        # Handle both dict and Pydantic model formats
        if isinstance(bucket, dict):
            bucket_name = bucket['name']
            is_public = bucket.get('is_public', False)
            has_cloudfront = bucket.get('has_cloudfront', False)
            policy = bucket.get('policy')
            is_empty = bucket.get('is_empty', False)
        else:
            bucket_name = bucket.name
            is_public = bucket.is_public
            has_cloudfront = bucket.has_cloudfront
            policy = bucket.policy
            is_empty = bucket.is_empty
        
        nodes.append({
            'id': bucket_name,
            'type': 's3_bucket',
            'label': f"S3: {bucket_name}",
            'metadata': {
                'is_public': is_public,
                'has_cloudfront': has_cloudfront,
                'has_policy': policy is not None,
                'is_empty': is_empty
            }
        })
        
        # Edge: S3 Bucket -> CloudFront (if has_cloudfront is True)
        if has_cloudfront:
            # Create a virtual CloudFront node for this bucket
            cf_id = f"cloudfront-{bucket_name}"
            nodes.append({
                'id': cf_id,
                'type': 'cloudfront_distribution',
                'label': f"CloudFront: {bucket_name}",
                'metadata': {
                    'origin_bucket': bucket_name
                }
            })
            edges.append({
                'from': cf_id,
                'to': bucket_name,
                'relationship': 'serves_from_bucket'
            })
    
    # ── RDS NODES ─────────────────────────────────────────────────
    for rds in infrastructure.rds.rds_instances:
        # Handle both dict and Pydantic model formats
        if isinstance(rds, dict):
            rds_id = rds['id']
            sg_ids = rds.get('sg_ids', [])
            subnet_id = rds.get('subnet_id')
            publicly_accessible = rds.get('publicly_accessible', False)
            encrypted = rds.get('encrypted', False)
        else:
            rds_id = rds.id
            sg_ids = rds.sg_ids
            subnet_id = rds.subnet_id
            publicly_accessible = rds.publicly_accessible
            encrypted = rds.encrypted
        
        nodes.append({
            'id': rds_id,
            'type': 'rds_instance',
            'label': f"RDS: {rds_id}",
            'metadata': {
                'publicly_accessible': publicly_accessible,
                'encrypted': encrypted,
                'sg_ids': sg_ids,
                'subnet_id': subnet_id
            }
        })
        
        # Edge: RDS -> Security Group
        for sg_id in sg_ids:
            edges.append({
                'from': rds_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })
    
    # ── LAMBDA NODES ──────────────────────────────────────────────
    for func in infrastructure.lambda_data.functions:
        # Handle both dict and Pydantic model formats
        if isinstance(func, dict):
            func_name = func['name']
            role_arn = func.get('role_arn')
            vpc_id = func.get('vpc_id')
            subnet_ids = func.get('subnet_ids', [])
            sg_ids = func.get('sg_ids', [])
        else:
            func_name = func.name
            role_arn = func.role_arn
            vpc_id = func.vpc_id
            subnet_ids = func.subnet_ids
            sg_ids = getattr(func, 'sg_ids', [])
        
        nodes.append({
            'id': func_name,
            'type': 'lambda_function',
            'label': f"Lambda: {func_name}",

            'metadata': {
                'role_arn': role_arn,
                'vpc_id': vpc_id,
                'subnet_ids': subnet_ids,
                'sg_ids': sg_ids,
                'subnet_count': len(subnet_ids)
            }
        })
        
        # Edge: Lambda -> IAM Role
        if role_arn:
            role_name = role_arn.split('/')[-1]
            role_id = f"iam-role-{role_name}"
            
            # Create IAM Role node if it doesn't exist
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {role_name}",
                    'metadata': {
                        'arn': role_arn
                    }
                })
            
            edges.append({
                'from': func_name,
                'to': role_id,
                'relationship': 'uses_iam_role'
            })
        
        # Edge: Lambda -> VPC
        if vpc_id:
            edges.append({
                'from': func_name,
                'to': vpc_id,
                'relationship': 'in_vpc'
            })
        
        # Edge: Lambda -> Subnet
        for subnet_id in subnet_ids:
            edges.append({
                'from': func_name,
                'to': subnet_id,
                'relationship': 'in_subnet'
            })
        
        # Edge: Lambda -> Secrets (env var refs)
        secret_refs = func.get('secret_refs', []) if isinstance(func, dict) else func.secret_refs
        for secret_id in secret_refs:
            if not any(n['id'] == secret_id for n in nodes):
                nodes.append({
                    'id': secret_id,
                    'type': 'secretsmanager_secret',
                    'label': f"Secret: {secret_id}",
                    'metadata': {'source': 'lambda_env'}
                })
            edges.append({
                'from': func_name,
                'to': secret_id,
                'relationship': 'REFERENCES_SECRET'
            })
    
    # ── ECS NODES ─────────────────────────────────────────────────
    if infrastructure.ecs.task_role_arns:
        nodes.append({
            'id': 'ecs_tasks',
            'type': 'ecs_tasks',
            'label': 'ECS Tasks',
            'metadata': {'is_virtual': True}
        })
        for role_arn in infrastructure.ecs.task_role_arns:
            role_name = role_arn.split('/')[-1]
            role_id = f"iam-role-{role_name}"
            if not any(n['id'] == role_id for n in nodes):
                nodes.append({
                    'id': role_id,
                    'type': 'iam_role',
                    'label': f"IAM Role: {role_name}",
                    'metadata': {'arn': role_arn, 'source': 'ecs_task'}
                })
            edges.append({
                'from': 'ecs_tasks',
                'to': role_id,
                'relationship': 'USES_ROLE'
            })

    # ── VPC NODES ─────────────────────────────────────────────────
    for subnet in infrastructure.vpc.subnets:
        # Handle both dict and Pydantic model formats
        if isinstance(subnet, dict):
            subnet_id = subnet['id']
            vpc_id = subnet['vpc_id']
            cidr = subnet.get('cidr')
            resources = subnet.get('resources', [])
        else:
            subnet_id = subnet.id
            vpc_id = subnet.vpc_id
            cidr = subnet.cidr
            resources = subnet.resources
        
        nodes.append({
            'id': subnet_id,
            'type': 'vpc_subnet',
            'label': f"Subnet: {subnet_id}",
            'metadata': {
                'vpc_id': vpc_id,
                'cidr': cidr,
                'resource_count': len(resources)
            }
        })
        
        # Edge: Subnet -> VPC
        edges.append({
            'from': subnet_id,
            'to': vpc_id,
            'relationship': 'belongs_to_vpc'
        })
        
        # Edge: Subnet -> Resources (EC2, Lambda, etc.)
        for resource_id in resources:
            edges.append({
                'from': subnet_id,
                'to': resource_id,
                'relationship': 'contains_resource'
            })
    
    # Route tables and network boundary nodes
    for route_table in infrastructure.vpc.route_tables:
        if isinstance(route_table, dict):
            route_table_id = route_table['id']
            route_table_vpc_id = route_table['vpc_id']
            is_main = route_table.get('is_main', False)
            associated_subnet_ids = route_table.get('associated_subnet_ids', [])
            route_data = route_table.get('routes', [])
        else:
            route_table_id = route_table.id
            route_table_vpc_id = route_table.vpc_id
            is_main = route_table.is_main
            associated_subnet_ids = route_table.associated_subnet_ids
            route_data = route_table.routes
        if not any(node['id'] == route_table_id for node in nodes):
            nodes.append({
                'id': route_table_id,
                'type': 'route_table',
                'category': 'network',
                'label': f"Route Table: {route_table_id}",
                'base': {
                    'routes': [
                        route.model_dump() if hasattr(route, 'model_dump') else route
                        for route in route_data
                    ],
                    'is_main': is_main,
                    'vpc_id': route_table_vpc_id,
                },
            })

    node_ids = {node['id'] for node in nodes}
    for gateway_id in infrastructure.vpc.internet_gateways:
        if gateway_id not in node_ids:
            nodes.append({
                'id': gateway_id,
                'type': 'internet_gateway',
                'category': 'network_boundary',
                'label': f"Internet Gateway: {gateway_id}",
            })
            node_ids.add(gateway_id)
    for gateway_id in infrastructure.vpc.nat_gateways:
        if gateway_id not in node_ids:
            nodes.append({
                'id': gateway_id,
                'type': 'nat_gateway',
                'category': 'network',
                'label': f"NAT Gateway: {gateway_id}",
            })
            node_ids.add(gateway_id)

    # Network ACLs and their subnet protection relationships.
    for nacl in infrastructure.vpc.nacls:
        if isinstance(nacl, dict):
            nacl_id = nacl['id']
            nacl_vpc_id = nacl['vpc_id']
            nacl_is_default = nacl.get('is_default', False)
            associated_subnet_ids = nacl.get('associated_subnet_ids', [])
            entry_data = nacl.get('entries', [])
        else:
            nacl_id = nacl.id
            nacl_vpc_id = nacl.vpc_id
            nacl_is_default = nacl.is_default
            associated_subnet_ids = nacl.associated_subnet_ids
            entry_data = nacl.entries

        if nacl_id in node_ids:
            continue

        entries = [
            entry.model_dump() if hasattr(entry, 'model_dump') else entry
            for entry in entry_data
        ]
        nodes.append(Node(
            id=nacl_id,
            resource_type='network_acl',
            category=NodeCategory.NETWORK_BOUNDARY,
            label=f"Network ACL: {nacl_id}",
            base={
                'entries': entries,
                'is_default': nacl_is_default,
                'vpc_id': nacl_vpc_id,
            },
        ))
        node_ids.add(nacl_id)

        for subnet_id in associated_subnet_ids:
            if subnet_id in node_ids:
                edges.append({
                    'from': subnet_id,
                    'to': nacl_id,
                    'relationship': RelationshipType.PROTECTED_BY,
                })

    # Create VPC nodes from subnets before route-target wiring so peering
    # connections and route targets can safely reference them.
    node_ids = {node['id'] for node in nodes}
    vpc_ids = set()
    for subnet in infrastructure.vpc.subnets:
        vpc_ids.add(subnet['vpc_id'] if isinstance(subnet, dict) else subnet.vpc_id)

    for vpc_id in vpc_ids:
        if not vpc_id or vpc_id in node_ids:
            continue
        subnet_count = sum(
            1 for subnet in infrastructure.vpc.subnets
            if (subnet['vpc_id'] if isinstance(subnet, dict) else subnet.vpc_id) == vpc_id
        )
        nodes.append({
            'id': vpc_id,
            'type': 'vpc',
            'label': f"VPC: {vpc_id}",
            'metadata': {
                'is_default': vpc_id == infrastructure.vpc.default_vpc_id,
                'subnet_count': subnet_count
            }
        })
        node_ids.add(vpc_id)

    # VPC peering connections and their endpoint VPCs.
    for connection in infrastructure.vpc.vpc_peering_connections:
        if isinstance(connection, dict):
            connection_id = connection.get('id')
            requester_vpc_id = connection.get('requester_vpc_id')
            accepter_vpc_id = connection.get('accepter_vpc_id')
            status = connection.get('status')
        else:
            connection_id = connection.id
            requester_vpc_id = connection.requester_vpc_id
            accepter_vpc_id = connection.accepter_vpc_id
            status = connection.status

        if not connection_id or connection_id in node_ids:
            continue
        nodes.append({
            'id': connection_id,
            'type': 'vpc_peering_connection',
            'category': 'network',
            'label': f"VPC Peering: {connection_id}",
            'base': {
                'requester_vpc_id': requester_vpc_id,
                'accepter_vpc_id': accepter_vpc_id,
                'status': status,
            },
        })
        node_ids.add(connection_id)

        for vpc_id in (requester_vpc_id, accepter_vpc_id):
            if not vpc_id:
                continue
            if vpc_id not in node_ids:
                nodes.append({
                    'id': vpc_id,
                    'type': 'vpc',
                    'category': 'network',
                    'label': f"VPC: {vpc_id}",
                    'base': {'collected': False},
                })
                node_ids.add(vpc_id)
            edges.append({
                'from': connection_id,
                'to': vpc_id,
                'relationship': RelationshipType.PEERED_WITH,
            })

    # Unmodeled cross-VPC mechanisms are represented as typed presence nodes so
    # reachability can conservatively flag them without inventing topology.
    for resource_type, records in (
        ('transit_gateway_attachment', infrastructure.vpc.transit_gateway_attachments),
        ('vpn_gateway', infrastructure.vpc.vpn_gateways),
        ('interface_endpoint', infrastructure.vpc.interface_endpoints),
    ):
        for record in records:
            data = record if isinstance(record, dict) else record.model_dump()
            mechanism_id = data.get('id')
            vpc_id = data.get('vpc_id')
            if not mechanism_id or not vpc_id:
                continue
            node_id = mechanism_id if mechanism_id not in node_ids else f'{mechanism_id}-{vpc_id}'
            if node_id in node_ids:
                continue
            base = {'vpc_id': vpc_id, **{key: value for key, value in data.items() if key != 'vpc_id'}}
            nodes.append({'id': node_id, 'type': resource_type, 'category': 'network_boundary',
                          'label': f'{resource_type}: {mechanism_id}', 'base': base})
            node_ids.add(node_id)

    # Subnet -> route table associations and route table -> collected targets.
    for route_table in infrastructure.vpc.route_tables:
        if isinstance(route_table, dict):
            route_table_id = route_table['id']
            associated_subnet_ids = route_table.get('associated_subnet_ids', [])
            route_data = route_table.get('routes', [])
        else:
            route_table_id = route_table.id
            associated_subnet_ids = route_table.associated_subnet_ids
            route_data = route_table.routes
        for subnet_id in associated_subnet_ids:
            if subnet_id in node_ids and route_table_id in node_ids:
                edges.append({
                    'from': subnet_id,
                    'to': route_table_id,
                    'relationship': 'associated_with',
                })
        for route in route_data:
            target_type = route.get('target_type') if isinstance(route, dict) else route.target_type
            target_id = route.get('target_id') if isinstance(route, dict) else route.target_id
            if target_type in {'internet_gateway', 'nat_gateway', 'vpc_peering'}:
                if route_table_id in node_ids and target_id in node_ids:
                    edges.append({
                        'from': route_table_id,
                        'to': target_id,
                        'relationship': 'routes_to',
                    })

    # ── EBS VOLUME NODES ──────────────────────────────────────────
    # Unattached volumes (state=available) — no edges, isolated for orphan detection
    for vol in infrastructure.ec2.ebs_volumes:
        vol_id = vol['id'] if isinstance(vol, dict) else vol.id
        size_gb = vol['size_gb'] if isinstance(vol, dict) else vol.size_gb
        volume_type = vol['volume_type'] if isinstance(vol, dict) else vol.volume_type
        az = vol['availability_zone'] if isinstance(vol, dict) else vol.availability_zone
        nodes.append({
            'id': vol_id,
            'type': 'ebs_volume',
            'label': f"EBS: {size_gb}GB",
            'metadata': {
                'size_gb': size_gb,
                'volume_type': volume_type,
                'availability_zone': az,
            }
        })

    # ── ELASTIC IP NODES ──────────────────────────────────────────
    # All EIPs — no edges, orphan detection filters by is_attached
    for eip in infrastructure.ec2.elastic_ips:
        alloc_id = eip['allocation_id'] if isinstance(eip, dict) else eip.allocation_id
        public_ip = eip['public_ip'] if isinstance(eip, dict) else eip.public_ip
        is_attached = eip['is_attached'] if isinstance(eip, dict) else eip.is_attached
        nodes.append({
            'id': alloc_id,
            'type': 'elastic_ip',
            'label': f"EIP: {public_ip}",
            'metadata': {
                'public_ip': public_ip,
                'is_attached': is_attached,
            }
        })

    # ── API GATEWAY NODES ─────────────────────────────────────────
    for api in infrastructure.api_gateway.apis:
        if isinstance(api, dict):
            api_id = api['id']
            api_name = api['name']
            api_type = api['api_type']
            endpoint_type = api['endpoint_type']
            auth_type = api['auth_type']
            has_waf = api.get('has_waf', False)
        else:
            api_id = api.id
            api_name = api.name
            api_type = api.api_type
            endpoint_type = api.endpoint_type
            auth_type = api.auth_type
            has_waf = api.has_waf

        nodes.append({
            'id': api_id,
            'type': 'api_gateway',
            'label': f"API GW: {api_name}",
            'metadata': {
                'api_type': api_type,
                'endpoint_type': endpoint_type,
                'auth_type': auth_type,
                'has_waf': has_waf,
            }
        })

        # Edge: INTERNET -> api_gateway (if endpoint is public)
        if endpoint_type != 'PRIVATE':
            if not internet_node_added:
                nodes.append({
                    'id': 'INTERNET',
                    'type': 'internet',
                    'label': 'Internet',
                    'metadata': {'is_virtual': True}
                })
                internet_node_added = True
            edges.append({
                'from': 'INTERNET',
                'to': api_id,
                'relationship': 'REACHES',
                'attrs': {'ports': [], 'reason': 'public API Gateway endpoint', 'confidence': 'high'}
            })

    # ── ELASTICACHE NODES ─────────────────────────────────────────
    for cluster in infrastructure.elasticache.clusters:
        if isinstance(cluster, dict):
            cluster_id = cluster['id']
            engine = cluster['engine']
            node_type_val = cluster['node_type']
            sg_ids = cluster.get('sg_ids', [])
            vpc_id = cluster.get('vpc_id')
        else:
            cluster_id = cluster.id
            engine = cluster.engine
            node_type_val = cluster.node_type
            sg_ids = cluster.sg_ids
            vpc_id = cluster.vpc_id

        nodes.append({
            'id': cluster_id,
            'type': 'elasticache_cluster',
            'label': f"ElastiCache: {cluster_id}",
            'metadata': {
                'engine': engine,
                'node_type': node_type_val,
                'vpc_id': vpc_id,
                'sg_ids': sg_ids,
                'subnet_group': cluster.get('subnet_group') if isinstance(cluster, dict) else cluster.subnet_group,
            }
        })

        # Edge: elasticache_cluster -> security_group
        for sg_id in sg_ids:
            edges.append({
                'from': cluster_id,
                'to': sg_id,
                'relationship': 'uses_security_group'
            })

    # ── SQS NODES ────────────────────────────────────────────────
    for queue in infrastructure.sqs.queues:
        if isinstance(queue, dict):
            queue_name = queue['name']
            queue_arn = queue['arn']
            encrypted = queue.get('encrypted', False)
            is_public = queue.get('is_public', False)
        else:
            queue_name = queue.name
            queue_arn = queue.arn
            encrypted = queue.encrypted
            is_public = queue.is_public

        nodes.append({
            'id': queue_name,
            'type': 'sqs_queue',
            'label': f"SQS: {queue_name}",
            'metadata': {
                'arn': queue_arn,
                'encrypted': encrypted,
                'is_public': is_public,
            }
        })

    # ── DYNAMODB NODES ────────────────────────────────────────────
    for table in infrastructure.dynamodb.tables:
        if isinstance(table, dict):
            table_name = table['name']
            table_arn = table['arn']
            encryption_type = table.get('encryption_type', 'DEFAULT')
            pitr_enabled = table.get('pitr_enabled', False)
            billing_mode = table.get('billing_mode', 'PROVISIONED')
        else:
            table_name = table.name
            table_arn = table.arn
            encryption_type = table.encryption_type
            pitr_enabled = table.pitr_enabled
            billing_mode = table.billing_mode

        nodes.append({
            'id': table_name,
            'type': 'dynamodb_table',
            'label': f"DynamoDB: {table_name}",
            'metadata': {
                'arn': table_arn,
                'encryption_type': encryption_type,
                'pitr_enabled': pitr_enabled,
                'billing_mode': billing_mode,
            }
        })

    # ── IAM POLICY EDGES (can_access) ────────────────────────────────
    # Create edges from IAM roles to data stores based on parsed policy documents.
    # This enables BFS to trace full attack paths: EC2 → Role → S3/RDS.
    node_id_set = {n['id'] for n in nodes}
    MAX_EDGES_PER_ROLE = 50  # cap to prevent graph explosion from overprivileged roles

    # Every role node carries trust fields, including roles discovered via a
    # workload relationship rather than IAM policy collection.
    for node in nodes:
        if node['type'] == 'iam_role':
            node.setdefault('metadata', {})
            node['metadata'].setdefault('trusted_services', [])
            node['metadata'].setdefault('trust_allows_external', False)
            node['metadata'].setdefault('trust_has_conditions', False)
            node['metadata'].setdefault('has_privilege_escalation', False)

    for role_policy in infrastructure.iam.role_policies:
        role_name = role_policy.role_name if not isinstance(role_policy, dict) else role_policy['role_name']
        role_arn = role_policy.role_arn if not isinstance(role_policy, dict) else role_policy['role_arn']
        has_admin = role_policy.has_admin if not isinstance(role_policy, dict) else role_policy.get('has_admin', False)
        accessible_resources = role_policy.accessible_resources if not isinstance(role_policy, dict) else role_policy.get('accessible_resources', [])
        policy_names = role_policy.policy_names if not isinstance(role_policy, dict) else role_policy.get('policy_names', [])
        trusted_role_arns = role_policy.trusted_role_arns if not isinstance(role_policy, dict) else role_policy.get('trusted_role_arns', [])
        trusted_services = role_policy.trusted_services if not isinstance(role_policy, dict) else role_policy.get('trusted_services', [])
        trust_allows_external = role_policy.trust_allows_external if not isinstance(role_policy, dict) else role_policy.get('trust_allows_external', False)
        trust_has_conditions = role_policy.trust_has_conditions if not isinstance(role_policy, dict) else role_policy.get('trust_has_conditions', False)

        role_id = f"iam-role-{role_name}"

        # An EC2 profile may have created a profile-name role node before IAM
        # role policy enrichment. Migrate that node to the actual role identity
        # rather than creating a duplicate role node.
        profile_roles = getattr(infrastructure.iam, 'instance_profile_roles', {}) or {}
        for profile_key, profile_mapping in profile_roles.items():
            if not isinstance(profile_mapping, dict):
                continue
            if (profile_mapping.get('role_name') != role_name or
                    profile_mapping.get('role_arn') != role_arn):
                continue
            profile_basename = profile_key.split('/')[-1] if isinstance(profile_key, str) else None
            stale_id = f"iam-role-{profile_basename}" if profile_basename else None
            if not stale_id or stale_id == role_id:
                continue
            stale_node = next((node for node in nodes if node['id'] == stale_id), None)
            if stale_node is None:
                continue
            if role_id not in node_id_set:
                stale_node['id'] = role_id
                stale_node['label'] = f"IAM Role: {role_name}"
                node_id_set.discard(stale_id)
                node_id_set.add(role_id)
            else:
                nodes.remove(stale_node)
                node_id_set.discard(stale_id)
            for edge in edges:
                if edge.get('from') == stale_id:
                    edge['from'] = role_id
                if edge.get('to') == stale_id:
                    edge['to'] = role_id
            break

        # Create role node if it doesn't exist yet (role not used by any Lambda/ECS/EC2)
        if role_id not in node_id_set:
            nodes.append({
                'id': role_id,
                'type': 'iam_role',
                'label': f"IAM Role: {role_name}",
                'metadata': {
                    'arn': role_arn,
                    'has_admin': has_admin,
                    'policies': policy_names,
                    'trusted_services': list(trusted_services),
                    'trust_allows_external': trust_allows_external,
                    'trust_has_conditions': trust_has_conditions,
                    'has_privilege_escalation': False,
                }
            })
            node_id_set.add(role_id)

        role_node = next(node for node in nodes if node['id'] == role_id)
        # Workload relationships may discover the role first with an instance
        # profile ARN. Enrich the same metadata layer used by the node (legacy
        # metadata or typed/base) so canonical role ARNs win without replacing
        # the node or its other metadata.
        if isinstance(role_node, Node):
            role_metadata = role_node.base
        elif 'base' in role_node:
            role_metadata = role_node.setdefault('base', {})
        else:
            role_metadata = role_node.setdefault('metadata', {})
        role_metadata.setdefault('arn', role_arn)
        if (isinstance(role_arn, str) and role_arn.startswith('arn:')
                and ':role/' in role_arn):
            role_metadata['arn'] = role_arn
        role_metadata['has_admin'] = has_admin
        role_metadata['policies'] = policy_names
        role_metadata['trusted_services'] = list(trusted_services)
        role_metadata['trust_allows_external'] = trust_allows_external
        role_metadata['trust_has_conditions'] = trust_has_conditions
        role_metadata.setdefault('has_privilege_escalation', False)

        data_nodes = [n for n in nodes if n['type'] in (
            's3_bucket', 'rds_instance', 'lambda_function', 'secretsmanager_secret',
            'dynamodb_table', 'sqs_queue')]
        access_statements = role_policy.access_statements if not isinstance(role_policy, dict) else role_policy.get('access_statements', [])
        edge_count = 0
        access_edge_targets = set()

        def add_access_edge(target, attrs):
            nonlocal edge_count
            target_key = (role_id, target['id'])
            if edge_count >= MAX_EDGES_PER_ROLE or target_key in access_edge_targets:
                return
            annotated_attrs = _annotate_access_attrs(attrs)
            edges.append({'from': role_id, 'to': target['id'],
                          'relationship': 'can_access', 'attrs': annotated_attrs})
            if annotated_attrs['privilege_escalation']:
                role_metadata['has_privilege_escalation'] = True
            access_edge_targets.add(target_key)
            edge_count += 1

        if access_statements:
            # Evaluate each target independently so unrelated conditions/denies
            # cannot lower confidence or suppress another resource's edge.
            for target in data_nodes:
                relevant = [stmt for stmt in access_statements
                            if str(_statement_value(stmt, 'effect', '')).lower() in {'allow', 'deny'}
                            and _statement_resource_matches(stmt, target)
                            and _statement_action_applies(stmt, target)]
                allows = [stmt for stmt in relevant
                          if str(_statement_value(stmt, 'effect', '')).lower() == 'allow'
                          and (_statement_value(stmt, 'is_not_action', False) or
                               bool(_statement_value(stmt, 'actions', [])))]
                if not allows:
                    continue
                allow_actions = []
                for stmt in allows:
                    for action in (_statement_value(stmt, 'actions', []) or []):
                        if action not in allow_actions:
                            allow_actions.append(action)
                clear_deny = any(
                    str(_statement_value(stmt, 'effect', '')).lower() == 'deny'
                    and not _statement_value(stmt, 'has_condition', False)
                    and not _statement_value(stmt, 'is_not_action', False)
                    and not _statement_value(stmt, 'is_not_resource', False)
                    and any(_iam_action_overlap(deny_action, allow_action)
                            for deny_action in (_statement_value(stmt, 'actions', []) or [])
                            for allow_action in allow_actions)
                    for stmt in relevant)
                if clear_deny:
                    continue
                relevant_denies = [stmt for stmt in relevant
                                   if str(_statement_value(stmt, 'effect', '')).lower() == 'deny'
                                   and (_statement_value(stmt, 'is_not_action', False) or
                                        any(_iam_action_overlap(deny_action, allow_action)
                                            for deny_action in (_statement_value(stmt, 'actions', []) or [])
                                            for allow_action in allow_actions))]
                uncertainty_statements = allows + relevant_denies
                uncertainty = any(
                    _statement_value(stmt, 'has_condition', False) or
                    _statement_value(stmt, 'is_not_action', False) or
                    _statement_value(stmt, 'is_not_resource', False)
                    for stmt in uncertainty_statements)
                add_access_edge(target, {
                    'actions': allow_actions or ['*'],
                    'effect': 'allow',
                    'has_condition': any(_statement_value(stmt, 'has_condition', False) for stmt in uncertainty_statements),
                    'confidence': 'assumed' if uncertainty else 'high',
                })
        elif has_admin:
            # Legacy admin shortcut when no structured statements were parsed.
            for target in data_nodes:
                add_access_edge(target, {'actions': ['*'], 'effect': 'allow',
                                         'has_condition': False, 'confidence': 'assumed'})
        else:
            # Exact old fallback for RolePolicy data produced by older scans.
            for arn in accessible_resources:
                if edge_count >= MAX_EDGES_PER_ROLE:
                    break
                if arn == '*':
                    for target in data_nodes:
                        add_access_edge(target, {'actions': ['*'], 'effect': 'allow',
                                                 'has_condition': False, 'confidence': 'assumed'})
                    break
                target_id = _match_arn_to_node_id(arn, node_id_set)
                if target_id:
                    target = next((n for n in data_nodes if n['id'] == target_id), None)
                    if target:
                        add_access_edge(target, {'actions': ['*'], 'effect': 'allow',
                                                 'has_condition': False, 'confidence': 'assumed'})
                    continue
                service_type = _match_wildcard_arn_to_service(arn)
                if service_type:
                    for target in data_nodes:
                        if target['type'] == service_type and _policy_resource_matches(arn, target):
                            add_access_edge(target, {'actions': ['*'], 'effect': 'allow',
                                                     'has_condition': False, 'confidence': 'assumed'})

    # Trust edges are resolved only after every role node has been created.
    # Match principals by the full ARN stored on role-node metadata; never
    # synthesize nodes for services, accounts, or external principals.
    role_nodes_by_arn = {}
    for node in nodes:
        if node['type'] != 'iam_role':
            continue
        node_arn = _node_data(node).get('arn')
        if isinstance(node_arn, str) and node_arn:
            role_nodes_by_arn.setdefault(node_arn, node['id'])

    trust_edges = []
    seen_trust_edges = set()
    for role_policy in sorted(
        infrastructure.iam.role_policies,
        key=lambda policy: (policy.role_arn if not isinstance(policy, dict) else policy.get('role_arn', ''),
                            policy.role_name if not isinstance(policy, dict) else policy.get('role_name', '')),
    ):
        target_arn = role_policy.role_arn if not isinstance(role_policy, dict) else role_policy.get('role_arn', '')
        target_id = role_nodes_by_arn.get(target_arn)
        if not target_id:
            continue
        principals = role_policy.trusted_role_arns if not isinstance(role_policy, dict) else role_policy.get('trusted_role_arns', [])
        conditional = role_policy.trust_has_conditions if not isinstance(role_policy, dict) else role_policy.get('trust_has_conditions', False)
        for principal_arn in sorted(set(principal for principal in principals if isinstance(principal, str))):
            source_id = role_nodes_by_arn.get(principal_arn)
            if not source_id or (source_id, target_id) in seen_trust_edges:
                continue
            seen_trust_edges.add((source_id, target_id))
            trust_edges.append({
                'from': source_id,
                'to': target_id,
                'relationship': RelationshipType.CAN_ASSUME,
                'attrs': {
                    'conditional': bool(conditional),
                    'confidence': 'assumed' if conditional else 'high',
                    'reason': 'trust policy allows sts:AssumeRole',
                },
            })
    edges.extend(trust_edges)

    # Profile-node migration can retarget an edge onto a role already used by
    # another workload, and repeated policy observations can produce the same
    # access edge. Keep the first edge (including its attrs) and deduplicate
    # only these relationships; CAN_ASSUME has its own semantics and remains
    # handled by seen_trust_edges above.
    deduplicated_edges = []
    seen_role_relationships = set()
    for edge in edges:
        relationship = edge.get('relationship')
        relationship_value = relationship.value if isinstance(relationship, RelationshipType) else relationship
        if relationship_value in {'uses_iam_role', 'can_access'}:
            edge_key = (edge.get('from'), edge.get('to'), relationship_value)
            if edge_key in seen_role_relationships:
                continue
            seen_role_relationships.add(edge_key)
        deduplicated_edges.append(edge)
    edges = deduplicated_edges

    # Additive internal reachability edges are evaluated only after the full
    # topology is available; existing edge order and algorithms remain intact.
    reachability_graph = Graph(nodes=nodes, edges=edges)
    eligible = []
    for node in reachability_graph.nodes:
        resource_type = node.resource_type
        data = _node_data(node)
        if resource_type == 'ec2_instance' and _sg_ids(node) and _resource_subnets(node, reachability_graph):
            eligible.append(node)
        elif resource_type == 'rds_instance' and _sg_ids(node) and _resource_subnets(node, reachability_graph):
            eligible.append(node)
        elif resource_type == 'lambda_function' and _sg_ids(node) and _resource_subnets(node):
            eligible.append(node)
    eligible.sort(key=lambda node: node.id)
    existing_can_reach = {(edge['from'], edge['to']) for edge in edges
                          if _is_relationship(edge, RelationshipType.CAN_REACH.value)}
    for source in eligible:
        for target in eligible:
            if source.id == target.id or (source.id, target.id) in existing_can_reach:
                continue
            evidence = internal_reachable(source, target, reachability_graph)
            if evidence:
                # A pair gets one stable edge even when several target ingress
                # rules independently provide evidence.
                item = min(evidence, key=lambda value: (
                    tuple(value.get("ports", [])), value.get("reason", ""),
                    value.get("confidence", ""), bool(value.get("flagged", False))))
                edges.append({'from': source.id, 'to': target.id,
                              'relationship': RelationshipType.CAN_REACH,
                              'attrs': {key: item[key] for key in ("ports", "reason", "confidence", "flagged")}})
                existing_can_reach.add((source.id, target.id))

    return Graph(nodes=nodes, edges=edges)


SLICE_CATEGORIES = {
    'scale_traffic':  ['ec2_instance', 'rds_instance', 'lambda_function', 'load_balancer', 'elasticache_cluster', 'api_gateway', 'sqs_queue'],
    'attack_surface': ['internet', 'security_group', 'ec2_instance', 'api_gateway'],
    'data_exposure':  ['s3_bucket', 'rds_instance', 'secretsmanager_secret', 'iam_role', 'dynamodb_table', 'sqs_queue'],
    'general':        None,
}


# Edge weights for Dijkstra — lower = easier to exploit.
# Scale: 0 = metadata (no exploit step), 1 = trivial, 2 = easy, 3 = medium,
#         4 = hard, 5 = very hard (cross-boundary).
EDGE_WEIGHTS: Dict[str, int] = {
    'REACHES': 1,              # Internet → SG: trivial, automated scanners
    'REACHES_VIA_SG': 1,       # Internet → instance: direct exposure
    'attached_to_instance': 0, # SG → instance: implicit, not an exploit step
    'targets_instance': 2,     # LB → instance: need to bypass LB
    'uses_iam_role': 3,        # Instance → role: need shell + credential theft
    'can_access': 2,           # Role → data store: have creds, call API
    'uses_security_group': 0,  # Instance → SG: metadata relationship
    'in_subnet': 0,            # Resource → subnet: metadata
    'contains_resource': 0,    # Subnet → resource: metadata
    'belongs_to_vpc': 0,       # Subnet → VPC: metadata
    'serves_from_bucket': 1,   # CloudFront → S3: CDN origin access
    'REFERENCES_SECRET': 2,    # Lambda → secret: need function access
    'USES_ROLE': 3,            # ECS → role: need container access
    'in_vpc': 0,               # Lambda → VPC: metadata
}


def dijkstra_from_internet(graph: Graph) -> Dict[str, Dict[str, Any]]:
    """
    Dijkstra's algorithm from INTERNET node — finds lowest-cost (easiest exploit)
    paths to all reachable resources.

    Unlike BFS which counts hops, this weights edges by exploit difficulty.
    A path with 5 hops but all trivial edges (cost=5) is MORE dangerous than
    a path with 2 hops requiring credential theft (cost=6).

    Args:
        graph: Infrastructure graph with INTERNET node

    Returns:
        Dict mapping node_id -> {distance: int, previous: str|None}
        distance = total exploit cost from INTERNET (lower = easier to attack)
        previous = previous node on the easiest path (for path reconstruction)
        Returns empty dict if no INTERNET node exists.
    """
    import heapq

    if 'INTERNET' not in graph._node_index:
        return {}

    distances: Dict[str, int] = {'INTERNET': 0}
    previous: Dict[str, Optional[str]] = {'INTERNET': None}
    visited: Set[str] = set()
    heap = [(0, 'INTERNET')]  # (cost, node_id)

    while heap:
        cost, node_id = heapq.heappop(heap)

        if node_id in visited:
            continue
        visited.add(node_id)

        for edge in graph._edges_by_source.get(node_id, []):
            neighbor = edge['to']
            if neighbor in visited:
                continue

            edge_type = edge['relationship']
            if isinstance(edge, Edge):
                # Typed edges carry the authoritative weight. Keep the fallback
                # for callers that may still provide legacy edge dictionaries.
                weight = edge.weight if edge.weight is not None else EDGE_WEIGHTS.get(edge_type, 3)
            else:
                weight = edge.get('weight')
                if weight is None:
                    weight = EDGE_WEIGHTS.get(edge_type, 3)

            new_cost = cost + weight

            if neighbor not in distances or new_cost < distances[neighbor]:
                distances[neighbor] = new_cost
                previous[neighbor] = node_id
                heapq.heappush(heap, (new_cost, neighbor))

    # Build result dict (exclude INTERNET itself)
    result: Dict[str, Dict[str, Any]] = {}
    for nid in distances:
        if nid == 'INTERNET':
            continue
        result[nid] = {
            'distance': distances[nid],
            'previous': previous.get(nid),
        }

    return result


def betweenness_centrality(graph: Graph, source_nodes: Optional[List[str]] = None) -> Dict[str, float]:
    """
    Calculate betweenness centrality for all nodes in the graph.

    Betweenness centrality measures how often a node appears on shortest paths
    between other nodes. High centrality = chokepoint. Hardening a high-centrality
    node eliminates the most attack paths simultaneously.

    Uses Brandes' algorithm (O(V*E)), efficient for graphs under 10K nodes.

    Args:
        graph: Infrastructure graph
        source_nodes: Optional list of source node IDs to compute from.
                      If None, uses INTERNET + all internet-reachable nodes.
                      Limiting sources keeps computation focused on attack-relevant paths.

    Returns:
        Dict mapping node_id -> centrality score (float, normalized).
        Higher = more shortest paths pass through this node.
        Returns empty dict if graph has fewer than 3 nodes.
    """
    from collections import deque

    all_node_ids = list(graph._node_index.keys())
    if len(all_node_ids) < 3:
        return {}

    # Initialize centrality scores
    centrality: Dict[str, float] = {nid: 0.0 for nid in all_node_ids}

    # Determine source nodes for BFS
    if source_nodes is None:
        if 'INTERNET' in graph._node_index:
            reachable = get_internet_reachable_set(graph)
            sources = ['INTERNET'] + [nid for nid in reachable if nid != 'INTERNET']
        else:
            sources = all_node_ids
    else:
        sources = source_nodes

    # Brandes' algorithm — BFS from each source, accumulate dependency
    for s in sources:
        stack: List[str] = []
        predecessors: Dict[str, List[str]] = {nid: [] for nid in all_node_ids}
        sigma: Dict[str, int] = {nid: 0 for nid in all_node_ids}
        sigma[s] = 1
        dist: Dict[str, int] = {nid: -1 for nid in all_node_ids}
        dist[s] = 0
        queue = deque([s])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for edge in graph._edges_by_source.get(v, []):
                w = edge['to']
                if w not in graph._node_index:
                    continue
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    predecessors[w].append(v)

        # Back-propagation of dependencies
        delta: Dict[str, float] = {nid: 0.0 for nid in all_node_ids}
        while stack:
            w = stack.pop()
            for v in predecessors[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                centrality[w] += delta[w]

    # Normalize to 0-1 range
    n = len(sources)
    if n > 2:
        norm = 1.0 / ((n - 1) * (n - 2))
        centrality = {nid: round(score * norm, 6) for nid, score in centrality.items()}

    return centrality


def get_internet_reachable_set(graph: Graph) -> set:
    """
    BFS from INTERNET node — returns a flat set of all reachable resource IDs.

    Used by graph-aware rules to determine if a resource is internet-reachable.
    Returns empty set if no INTERNET node exists (conservative: rules won't downgrade).
    """
    if not graph or 'INTERNET' not in graph._node_index:
        return set()

    visited = set()
    queue = ['INTERNET']
    visited.add('INTERNET')

    while queue:
        current = queue.pop(0)
        for edge in filter_traversable_edges(graph._edges_by_source.get(current, [])):
            neighbor = edge['to']
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

    visited.discard('INTERNET')
    return visited


def get_attack_path_to(graph: Graph, target_id: str) -> Optional[List[str]]:
    """
    BFS from INTERNET to target — returns shortest path as list of node IDs.

    Used by graph-aware rules to populate the attack_path field on findings.
    Returns None if target is not reachable from INTERNET.

    Args:
        graph: Infrastructure graph with INTERNET node
        target_id: ID of the target resource

    Returns:
        List of node IDs from INTERNET to target (inclusive), or None if unreachable.
    """
    if not graph or 'INTERNET' not in graph._node_index:
        return None
    if target_id not in graph._node_index:
        return None

    visited = set()
    queue = [('INTERNET', ['INTERNET'])]
    visited.add('INTERNET')

    while queue:
        current, path = queue.pop(0)
        for edge in filter_traversable_edges(graph._edges_by_source.get(current, [])):
            neighbor = edge['to']
            if neighbor == target_id:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None


def bfs_from_internet(graph: Graph) -> dict:
    """
    BFS traversal from the INTERNET node to find all reachable resources.

    Returns nodes in BFS order with their depth (distance from internet),
    plus all edges between reachable nodes.

    Args:
        graph: Full infrastructure graph

    Returns:
        Dict with 'nodes', 'edges', 'category', 'layers' keys.
        'layers' maps node_id -> BFS depth (0 = INTERNET itself).
        Returns empty result if no INTERNET node exists.
    """
    if 'INTERNET' not in graph._node_index:
        return {'nodes': [], 'edges': [], 'category': 'attack_surface', 'layers': {}}

    visited = set()
    queue = ['INTERNET']
    layers = {'INTERNET': 0}
    visited.add('INTERNET')

    while queue:
        current = queue.pop(0)
        depth = layers[current]
        for edge in filter_traversable_edges(graph._edges_by_source.get(current, [])):
            neighbor = edge['to']
            if neighbor not in visited:
                visited.add(neighbor)
                layers[neighbor] = depth + 1
                queue.append(neighbor)

    edges = []
    for nid in visited:
        for edge in filter_traversable_edges(graph._edges_by_source.get(nid, [])):
            if edge['to'] in visited:
                edges.append(edge)

    return {
        'nodes': [graph._node_index[nid] for nid in visited if nid in graph._node_index],
        'edges': edges,
        'category': 'attack_surface',
        'layers': layers,
    }


def get_simulation_slice(graph: Graph, category: str) -> dict:
    """
    Return a subgraph relevant to the given simulation category.

    For 'attack_surface' and 'general', uses real BFS traversal from the INTERNET
    node so the slice reflects actual reachability, not just node type filtering.
    Falls back to type-based filtering if no INTERNET node exists.

    Args:
        graph: Full infrastructure graph
        category: One of 'scale_traffic', 'attack_surface', 'data_exposure', 'cost', 'general'

    Returns:
        Dict with 'nodes', 'edges', 'category', and 'layers' keys.
        'layers' maps node_id -> BFS depth (only populated for BFS-based slices).
    """
    if category in ('attack_surface', 'general', 'recommendations'):
        result = bfs_from_internet(graph)
        if result['nodes']:
            return result
        # fallback: no INTERNET node — return first 50 nodes
        node_ids = set(list(graph._node_index.keys())[:50])
    elif category == 'data_exposure':
        # BFS first — return data-type nodes reachable from internet
        DATA_TYPES = {'s3_bucket', 'rds_instance', 'secretsmanager_secret', 'iam_role'}
        bfs_result = bfs_from_internet(graph)
        bfs_ids = {n['id'] for n in bfs_result['nodes']}
        bfs_layers = bfs_result.get('layers', {})
        data_node_ids = set()
        for t in DATA_TYPES:
            for n in graph.find_nodes_by_type(t):
                data_node_ids.add(n['id'])
        reachable_data_ids = data_node_ids & bfs_ids

        # If no data nodes are BFS-reachable, fall back to ALL data nodes.
        # S3 buckets and RDS have no direct internet edge in the graph so the
        # BFS intersection is always empty — returning empty gives Claude nothing
        # to reason about and produces "empty infrastructure graph" errors.
        if reachable_data_ids:
            node_ids = reachable_data_ids
            layers = {nid: bfs_layers[nid] for nid in node_ids if nid in bfs_layers}
        else:
            node_ids = data_node_ids
            layers = {}

        if not node_ids:
            return {'nodes': [], 'edges': [], 'category': category, 'layers': {}}

        edges = []
        for nid in node_ids:
            for edge in graph._edges_by_source.get(nid, []):
                if edge['to'] in node_ids:
                    edges.append(edge)

        return {
            'nodes': [graph._node_index[nid] for nid in node_ids if nid in graph._node_index],
            'edges': edges,
            'category': category,
            'layers': layers,
        }
    else:
        node_types = SLICE_CATEGORIES.get(category, None)
        node_ids = set()
        if node_types:
            for t in node_types:
                for n in graph.find_nodes_by_type(t):
                    node_ids.add(n['id'])
        else:
            node_ids = set(list(graph._node_index.keys())[:50])

    edges = []
    for nid in node_ids:
        for edge in graph._edges_by_source.get(nid, []):
            if edge['to'] in node_ids:
                edges.append(edge)

    return {
        'nodes': [graph._node_index[nid] for nid in node_ids if nid in graph._node_index],
        'edges': edges,
        'category': category,
        'layers': {},
    }


def validate_simulation_response(response: dict, graph: Graph) -> dict:
    """
    Strip any node IDs from a simulation response that no longer exist in the graph.

    Ensures LLM-generated stage node_ids and recommendation affected_node_ids
    only reference real nodes, preventing downstream KeyErrors.

    Args:
        response: Simulation response dict with 'stages' and 'recommendations' keys
        graph: Infrastructure graph to validate against

    Returns:
        Cleaned response dict (mutates in place and returns)
    """
    for stage in response.get('stages', []):
        stage['node_ids'] = [nid for nid in stage.get('node_ids', []) if graph.get_node(nid)]
    for rec in response.get('recommendations', []):
        rec['affected_node_ids'] = [nid for nid in rec.get('affected_node_ids', []) if graph.get_node(nid)]
    return response


def classify_query(query: str) -> str:
    """
    Classify a simulation query into one of four categories based on keywords.

    Args:
        query: Free-text user query

    Returns:
        Category string: 'scale_traffic' | 'attack_surface' | 'data_exposure' | 'cost' | 'general'
    """
    q = query.lower()
    if any(w in q for w in ['user', 'traffic', 'scale', 'load', 'concurrent', 'request', 'rps', 'handle']):
        return 'scale_traffic'
    if any(w in q for w in ['attack', 'breach', 'hack', 'reach', 'internet', 'exploit', 'attacker', 'compromise', 'steal', 'access']):
        return 'attack_surface'
    if any(w in q for w in ['data', 'bucket', 'database', 'secret', 'leak', 'exposed', 's3', 'rds']):
        return 'data_exposure'
    if any(w in q for w in ['cost', 'bill', 'expensive', 'optimize', 'spend', 'saving']):
        return 'cost'
    recommendations_keywords = [
        'best', 'improve', 'recommend', 'suggest', 'should', 'help', 'advice',
        'fix', 'what can', 'how can', 'priority', 'focus',
    ]
    if any(k in q for k in recommendations_keywords):
        return 'recommendations'
    return 'general'


def format_graph_for_claude(slice_dict: dict) -> str:
    """
    Format a graph slice as a compact text representation for Claude prompts.

    Includes BFS depth on each node when available (depth=N means N hops from internet).
    Only emits metadata fields relevant to security/reliability analysis.

    Args:
        slice_dict: Dict with 'nodes', 'edges', 'category', 'layers' keys

    Returns:
        Multi-line string describing nodes and edges with depth annotations
    """
    layers = slice_dict.get('layers', {})
    lines = [f"INFRASTRUCTURE GRAPH (category: {slice_dict['category']}):", "Nodes:"]
    for n in slice_dict['nodes']:
        meta = {k: v for k, v in n.get('metadata', {}).items()
                if k in ('instance_type', 'state', 'public_ip', 'is_public',
                         'engine', 'multi_az', 'runtime', 'policy_names',
                         'open_ports', 'instance_profile')}
        depth = layers.get(n['id'], '?')
        lines.append(f"  - {n['id']} [{n['type']}] depth={depth} {meta}")
    lines.append("Edges:")
    for e in slice_dict['edges']:
        lines.append(f"  - {e['from']} --{e['relationship']}--> {e['to']}")
    return "\n".join(lines)


def find_orphaned_resources(graph: Graph) -> List[Dict[str, Any]]:
    """
    Find orphaned resources - nodes with zero inbound AND zero outbound edges.
    
    These are resources that exist but have no relationships with other infrastructure,
    indicating they may be unused and costing money unnecessarily.
    
    Special handling for S3 buckets:
    - Skip buckets that are not empty (have stored objects)
    - Skip buckets with production-related names
    - Only flag empty buckets with test/temporary names
    
    Args:
        graph: Infrastructure graph to analyze
    
    Returns:
        List of orphaned resources with type, ID, label, and estimated cost impact
    """
    orphaned = []
    
    # Cost estimates per resource type (monthly USD)
    cost_estimates = {
        'ec2_instance': {'amount': 10.0, 'unit': 'per instance'},
        'rds_instance': {'amount': 25.0, 'unit': 'per instance'},
        's3_bucket': {'amount': 1.0, 'unit': 'per bucket (storage varies)'},
        'lambda_function': {'amount': 0.5, 'unit': 'per function (if unused)'},
        'load_balancer': {'amount': 18.0, 'unit': 'per load balancer'},
        'vpc': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'vpc_subnet': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'security_group': {'amount': 0.0, 'unit': 'free (but cleanup recommended)'},
        'iam_role': {'amount': 0.0, 'unit': 'free (but security risk if unused)'},
        'cloudfront_distribution': {'amount': 1.0, 'unit': 'per distribution'},
        'ebs_volume': {'amount': 0.0, 'unit': 'per GB × $0.10/mo'},
        'elastic_ip': {'amount': 3.65, 'unit': 'per unattached EIP'},
    }
    
    # Production keywords - buckets with these names are likely in use
    production_keywords = [
        'prod', 'production', 'app', 'data', 'backup', 'reports', 
        'logs', 'assets', 'uploads', 'archive', 'static', 'media'
    ]
    
    # Reason strings per resource type
    orphan_reasons = {
        's3_bucket':       'Empty S3 bucket with no active use',
        'security_group':  'Security group not attached to any resource',
        'ebs_volume':      'Unattached EBS volume (available state)',
        'elastic_ip':      'Elastic IP not associated with any instance',
        'ec2_instance':    'EC2 instance with no network relationships',
        'rds_instance':    'RDS instance with no security group attachments',
        'lambda_function': 'Lambda function with no role, VPC, or secret refs',
        'load_balancer':   'Load balancer with no target instances',
    }

    for node in graph.nodes:
        node_id = node['id']
        node_type = node['type']
        
        # Get inbound and outbound connections
        inbound = graph.get_inbound(node_id)
        outbound = graph.get_outbound(node_id)
        
        # Resource is orphaned if it has NO connections at all
        if len(inbound) == 0 and len(outbound) == 0:
            # Special handling for S3 buckets to avoid false positives
            if node_type == 's3_bucket':
                bucket_name = node_id.lower()
                is_empty = node['metadata'].get('is_empty', False)
                
                # Skip bucket if it's not empty (has objects stored)
                if not is_empty:
                    continue
                
                # Skip bucket if name contains production keywords
                has_production_keyword = any(keyword in bucket_name for keyword in production_keywords)
                if has_production_keyword:
                    continue
            
            # EBS volumes: cost is dynamic (size_gb × $0.10/mo)
            if node_type == 'ebs_volume':
                size_gb = node.get('metadata', {}).get('size_gb', 0)
                cost = round(size_gb * 0.10, 2)
                orphaned.append({
                    **node,
                    'estimated_monthly_cost': cost,
                    'cost_unit': f"{size_gb}GB × $0.10/mo",
                    'reason': orphan_reasons['ebs_volume'],
                })
                continue

            # Elastic IPs: only flag unattached ones
            if node_type == 'elastic_ip':
                if not node.get('metadata', {}).get('is_attached', True):
                    orphaned.append({
                        **node,
                        'estimated_monthly_cost': 3.65,
                        'cost_unit': 'per unattached EIP',
                        'reason': orphan_reasons['elastic_ip'],
                    })
                continue

            # Security groups: flag if unattached (no instances, no internet edges)
            if node_type == 'security_group':
                orphaned.append({
                    **node,
                    'estimated_monthly_cost': 0.0,
                    'cost_unit': 'security hygiene',
                    'reason': orphan_reasons['security_group'],
                })
                continue

            cost_info = cost_estimates.get(node_type, {'amount': 0.0, 'unit': 'unknown'})
            
            orphaned.append({
                'id': node_id,
                'type': node_type,
                'label': node['label'],
                'metadata': node['metadata'],
                'estimated_monthly_cost': cost_info['amount'],
                'cost_unit': cost_info['unit'],
                'reason': orphan_reasons.get(node_type, 'Orphaned resource — no active relationships'),
            })
    
    return orphaned


def find_attack_path(graph: Graph, resource_id: str, max_hops: int = 5) -> List[Dict[str, Any]]:
    """
    Find attack path from a resource to data stores using BFS traversal.
    
    Performs breadth-first search from the given resource_id, following outbound edges
    until reaching a data store node (rds_instance, s3_bucket, secrets_manager_secret).
    Stops traversal once depth exceeds max_hops.
    
    Args:
        graph: Infrastructure graph to analyze
        resource_id: Starting resource ID for attack path analysis
        max_hops: Maximum BFS depth before stopping (default 5)
    
    Returns:
        Ordered list of node dictionaries representing the full attack path.
        Returns empty list if no path to data store is found.
    """
    from collections import deque
    
    # Target node types that represent data stores
    data_store_types = {'rds_instance', 's3_bucket', 'secrets_manager_secret', 'dynamodb_table'}
    
    # Check if starting resource exists
    start_node = graph.get_node(resource_id)
    if not start_node:
        return []
    
    # BFS setup — queue stores (current_id, path_to_current, depth)
    queue = deque([(resource_id, [start_node], 0)])
    visited = {resource_id}
    
    while queue:
        current_id, path, depth = queue.popleft()
        current_node = graph.get_node(current_id)
        
        # Check if current node is a data store
        if current_node and current_node['type'] in data_store_types:
            return path
        
        # Stop expanding if we've reached the hop limit
        if depth >= max_hops:
            continue
        
        # Explore both outbound AND inbound movement neighbors — lateral movement goes both ways.
        neighbors = []
        neighbor_ids = set()
        for edge in filter_traversable_edges(graph._edges_by_source.get(current_id, [])):
            neighbor_id = edge['to']
            if neighbor_id not in neighbor_ids and neighbor_id in graph._node_index:
                neighbors.append(graph._node_index[neighbor_id])
                neighbor_ids.add(neighbor_id)
        for edge in filter_traversable_edges(graph._edges_by_target.get(current_id, [])):
            neighbor_id = edge['from']
            if neighbor_id not in neighbor_ids and neighbor_id in graph._node_index:
                neighbors.append(graph._node_index[neighbor_id])
                neighbor_ids.add(neighbor_id)
        for neighbor in neighbors:
            neighbor_id = neighbor['id']
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                new_path = path + [neighbor]
                queue.append((neighbor_id, new_path, depth + 1))
    
    # No path to data store found
    return []


def calculate_blast_radius(graph: Graph, resource_id: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Calculate blast radius from a resource using DIRECTIONAL BFS (outbound only).
    
    Performs breadth-first search from the given resource_id, traversing ONLY
    outbound edges (downstream from the compromised resource). This answers:
    "If this resource is compromised, what can an attacker reach FROM here?"
    
    Does NOT traverse inbound edges (upstream), which would inflate the count
    with resources that protect/contain this resource rather than resources at risk.
    
    Args:
        graph: Infrastructure graph to analyze
        resource_id: Starting resource ID for blast radius calculation
        max_hops: Maximum BFS depth before stopping (default 5)
    
    Returns:
        Dictionary with count of reachable resources and list of resource IDs:
        {"count": int, "resource_ids": [list of strings]}
    """
    from collections import deque
    
    # Check if starting resource exists
    start_node = graph.get_node(resource_id)
    if not start_node:
        return {"count": 0, "resource_ids": []}
    
    # BFS setup — queue stores (current_id, depth)
    queue = deque([(resource_id, 0)])
    visited = {resource_id}
    
    while queue:
        current_id, depth = queue.popleft()
        
        # Stop expanding if we've reached the hop limit
        if depth >= max_hops:
            continue
        
        # Get OUTBOUND neighbors only (edges where current_id is the source)
        # Also include edges where current_id is the TARGET of "REACHES" or
        # "REACHES_VIA_SG" relationships (internet reaching into infra)
        outbound_ids = set()
        
        # Outbound: edges FROM this node
        for edge in filter_traversable_edges(graph._edges_by_source.get(current_id, [])):
            outbound_ids.add(edge['to'])

        # Also follow inbound REACHES edges (internet → resource means resource is exposed).
        for edge in graph._edges_by_target.get(current_id, []):
            if _relationship(edge) in {'REACHES', 'REACHES_VIA_SG'}:
                outbound_ids.add(edge['from'])
        
        for neighbor_id in outbound_ids:
            if neighbor_id not in visited and neighbor_id != 'INTERNET':
                visited.add(neighbor_id)
                queue.append((neighbor_id, depth + 1))
    
    # Remove the starting resource from the count (don't include self)
    reachable_ids = list(visited - {resource_id})
    
    return {
        "count": len(reachable_ids),
        "resource_ids": reachable_ids
    }


def find_critical_resources(graph: Graph, findings: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
    """
    Identify the most critical nodes by counting how many findings reference each node
    via their attack_path lists.

    Ranking: (1) finding count descending, (2) max severity descending.

    Args:
        graph: Infrastructure graph
        findings: List of finding dicts (each may have 'attack_path', 'severity', 'blast_radius')
        top_n: Maximum number of results to return (default 5)

    Returns:
        List of dicts with node_id, label, type, finding_count, max_severity, blast_radius
    """
    SEVERITY_ORDER = {'Critical': 4, 'Moderate': 3, 'Low': 2, 'High': 1}

    # Count findings per node and track max severity + blast radius
    node_finding_count: Dict[str, int] = {}
    node_max_severity: Dict[str, str] = {}
    node_blast_radius: Dict[str, int] = {}

    for finding in findings:
        path = finding.get('attack_path', [])
        blast = finding.get('blast_radius', 0) or 0
        # Mirror graph endpoint: if no path but blast_radius > 0, use resource_id
        if not path and blast > 0 and finding.get('resource_id'):
            path = [finding['resource_id']]
        if not path:
            continue
        severity = finding.get('severity', 'Low')

        for node_id in path:
            node_finding_count[node_id] = node_finding_count.get(node_id, 0) + 1
            # Keep highest severity seen for this node
            current = node_max_severity.get(node_id, 'Low')
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(current, 0):
                node_max_severity[node_id] = severity
            # Keep highest blast radius seen for this node
            if blast > node_blast_radius.get(node_id, 0):
                node_blast_radius[node_id] = blast

    if not node_finding_count:
        return []

    # Sort: finding_count desc, then severity desc
    sorted_nodes = sorted(
        node_finding_count.keys(),
        key=lambda nid: (
            node_finding_count[nid],
            SEVERITY_ORDER.get(node_max_severity.get(nid, 'Low'), 0),
        ),
        reverse=True,
    )

    results = []
    for node_id in sorted_nodes[:top_n]:
        node = graph.get_node(node_id)
        if not node:
            continue
        results.append({
            'node_id': node_id,
            'label': node.get('label', node_id),
            'type': node.get('type', 'unknown'),
            'finding_count': node_finding_count[node_id],
            'max_severity': node_max_severity.get(node_id, 'Low'),
            'blast_radius': node_blast_radius.get(node_id, 0),
        })

    return results
