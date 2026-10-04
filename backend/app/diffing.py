"""Pure infrastructure and graph diffing helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.egraph import build_graph, get_internet_reachable_set
from app.rules import find_toxic_combos, run_all_checks
from app.scoring import calculate_score


class DiffResult(BaseModel):
    """Deterministic result of comparing two infrastructure snapshots."""

    added_nodes: list[str] = Field(default_factory=list)
    removed_nodes: list[str] = Field(default_factory=list)
    modified_nodes: list[str] = Field(default_factory=list)
    added_edges: list[dict] = Field(default_factory=list)
    removed_edges: list[dict] = Field(default_factory=list)
    deletion_impacts: list[dict] = Field(default_factory=list)
    lost_dependencies: list[dict] = Field(default_factory=list)
    lost_connectivity: list[dict] = Field(default_factory=list)
    coverage_warnings: list[str] = Field(default_factory=list)
    collection_warnings: list[str] = Field(default_factory=list)
    added_findings: list[dict] = Field(default_factory=list)
    removed_findings: list[dict] = Field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    newly_internet_reachable: list[str] = Field(default_factory=list)
    no_longer_internet_reachable: list[str] = Field(default_factory=list)
    # True only when the complete canonical infrastructure snapshots match.
    # A false value may reflect modeled data not represented in graph deltas.
    modeled_state_unchanged: bool = False


_LAYER_FIELDS = ("base", "security", "cost", "limits", "telemetry")


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _canonical_value(value: Any) -> Any:
    """Convert supported values into a recursively deterministic JSON shape."""
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump())
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(value[key])
            for key in sorted(value, key=lambda key: str(key))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical_value(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(_canonical_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def modeled_state_unchanged(before: Any, after: Any) -> bool:
    """Return true only when complete normalized infrastructure models match."""
    return _canonical_json(before) == _canonical_json(after)


def _node_structure(node: Any) -> tuple[str, str]:
    """Return only the resource type and normalized layered node data.

    Graph nodes are normally typed ``Node`` models, but callers may provide
    legacy dictionaries with ``type``/``metadata``.  Treat legacy metadata as
    the base layer so equivalent representations compare identically.
    """
    resource_type = _value(node, "resource_type", _value(node, "type", ""))
    layers = {}
    for field in _LAYER_FIELDS:
        value = _value(node, field)
        if value is not None:
            layers[field] = value
    if "base" not in layers:
        metadata = _value(node, "metadata")
        if metadata is not None:
            layers["base"] = metadata
    return str(resource_type), _canonical_json(layers)


def _edge_identity(edge: Any) -> tuple[str, str, str]:
    relationship = _value(edge, "relationship", "")
    if isinstance(relationship, Enum):
        relationship = relationship.value
    return (str(_value(edge, "src", _value(edge, "from", ""))),
            str(_value(edge, "dst", _value(edge, "to", ""))),
            str(relationship))


def _edge_dict(identity: tuple[str, str, str]) -> dict:
    source, target, relationship = identity
    return {"from": source, "to": target, "relationship": relationship}


def diff_graphs(base_graph: Any, branch_graph: Any) -> dict:
    """Return a pure structural diff between two graph objects."""
    base_nodes = {_value(node, "id", ""): node for node in (base_graph.nodes if base_graph else [])}
    branch_nodes = {_value(node, "id", ""): node for node in (branch_graph.nodes if branch_graph else [])}
    base_ids = set(base_nodes)
    branch_ids = set(branch_nodes)

    base_edges = {_edge_identity(edge) for edge in (base_graph.edges if base_graph else [])}
    branch_edges = {_edge_identity(edge) for edge in (branch_graph.edges if branch_graph else [])}

    return {
        "added_nodes": sorted(branch_ids - base_ids),
        "removed_nodes": sorted(base_ids - branch_ids),
        "modified_nodes": sorted(
            node_id for node_id in base_ids & branch_ids
            if _node_structure(base_nodes[node_id]) != _node_structure(branch_nodes[node_id])
        ),
        "added_edges": [_edge_dict(edge) for edge in sorted(branch_edges - base_edges)],
        "removed_edges": [_edge_dict(edge) for edge in sorted(base_edges - branch_edges)],
    }


def _is_concrete_resource_node(node: Any) -> bool:
    """Ignore explicit virtual, reference-derived, and uncollected graph nodes."""
    node_id = _value(node, "id", "")
    resource_type = _value(node, "resource_type", _value(node, "type", ""))
    if not node_id or not resource_type:
        return False
    category = _value(node, "category", "")
    if isinstance(category, Enum):
        category = category.value
    if str(category) == "edge":
        return False
    metadata = _value(node, "base")
    if not isinstance(metadata, Mapping):
        metadata = _value(node, "metadata", {})
    metadata = metadata if isinstance(metadata, Mapping) else {}
    return not (
        metadata.get("is_virtual") is True
        or bool(metadata.get("source"))
        or metadata.get("collected") is False
    )


def _deletion_impacts(base_graph: Any, branch_graph: Any) -> list[dict[str, Any]]:
    """Describe concrete resources removed from the branch and surviving neighbors."""
    base_nodes = {
        _value(node, "id", ""): node for node in (base_graph.nodes if base_graph else [])
        if _is_concrete_resource_node(node)
    }
    branch_nodes = {
        _value(node, "id", ""): node for node in (branch_graph.nodes if branch_graph else [])
        if _is_concrete_resource_node(node)
    }
    removed_ids = sorted(
        node_id for node_id, node in base_nodes.items()
        if node_id not in branch_nodes
        or _value(node, "resource_type", _value(node, "type", ""))
        != _value(branch_nodes[node_id], "resource_type", _value(branch_nodes[node_id], "type", ""))
    )
    impacts = []
    for removed_id in removed_ids:
        removed_node = base_nodes[removed_id]
        related_relationships: dict[str, set[str]] = {}
        for edge in (base_graph.edges if base_graph else []):
            source, target, relationship = _edge_identity(edge)
            if source == removed_id and target in branch_nodes:
                related_relationships.setdefault(target, set()).add(relationship)
            elif target == removed_id and source in branch_nodes:
                related_relationships.setdefault(source, set()).add(relationship)
        impacts.append({
            "removed_resource": {
                "id": str(removed_id),
                "resource_type": str(_value(removed_node, "resource_type", _value(removed_node, "type", ""))),
            },
            "surviving_related_resources": [
                {
                    "id": str(node_id),
                    "resource_type": str(_value(branch_nodes[node_id], "resource_type",
                                                 _value(branch_nodes[node_id], "type", ""))),
                    "relationships": sorted(related_relationships[node_id]),
                }
                for node_id in sorted(related_relationships)
            ],
            "possible_consequence": (
                "This concrete resource was removed from the modeled branch. "
                "The snapshot cannot determine whether removal disrupts service operation or affects stored data."
            ),
        })
    return impacts


def _finding_field(finding: Any, name: str, default: str = "") -> str:
    value = _value(finding, name, default)
    return "" if value is None else str(value)


def _flatten_findings(findings: dict) -> dict[tuple[str, str], dict]:
    flattened: dict[tuple[str, str], dict] = {}
    for bucket in findings.values():
        if not isinstance(bucket, (list, tuple)):
            continue
        for finding in bucket:
            rule_id = _finding_field(finding, "rule_id")
            resource_id = _finding_field(finding, "resource_id")
            key = (rule_id, resource_id)
            flattened.setdefault(key, {
                "rule_id": rule_id,
                "resource_id": resource_id,
                "severity": _finding_field(finding, "severity"),
            })
    return flattened


def _finding_sort(item: dict) -> tuple[str, str, str]:
    return (item["rule_id"], item["resource_id"], item["severity"])


def _iam_policy_changed(base_infra: Any, branch_infra: Any) -> bool:
    """Detect changes to the collected, normalized role-policy model."""
    def policies(infra: Any) -> dict[str, Any]:
        iam = _value(infra, "iam", {})
        role_policies = _value(iam, "role_policies", []) or []
        return {
            str(_value(policy, "role_arn", "")): _canonical_json(policy)
            for policy in role_policies
        }

    return policies(base_infra) != policies(branch_infra)


def diff_infrastructure(base_infra: Any, branch_infra: Any) -> DiffResult:
    """Compare infrastructure snapshots without mutating either input."""
    base_graph = build_graph(base_infra)
    branch_graph = build_graph(branch_infra)
    graph_diff = diff_graphs(base_graph, branch_graph)
    coverage_warnings = []
    collection_warnings = sorted({
        str(item).strip()
        for infra in (base_infra, branch_infra)
        for item in (_value(infra, "warnings", []) or [])
        if str(item).strip()
    })
    if collection_warnings:
        coverage_warnings.append(
            f"source snapshot has {len(collection_warnings)} collection warning(s); "
            "branch prediction is incomplete"
        )
    if _iam_policy_changed(base_infra, branch_infra):
        coverage_warnings.append(
            "IAM policy impact is a graph approximation; Organizations SCPs, permissions boundaries, "
            "resource policies, session policies, and full condition evaluation are outside this model"
        )
    # These edges describe a modeled consumer/capability. Losing one can break
    # a workload even when removing the target also clears security findings.
    # Keep this separate from generic removed edges (containment, exposure,
    # etc.) and do not claim that the workload actually makes the API call.
    dependency_relationships = {"can_access", "REFERENCES_SECRET", "uses_iam_role", "USES_ROLE"}
    surviving = {node.id for node in branch_graph.nodes}
    lost_dependencies = [
        edge for edge in graph_diff["removed_edges"]
        if edge["relationship"] in dependency_relationships
        and edge["from"] in surviving
    ]
    lost_connectivity = [
        edge for edge in graph_diff["removed_edges"]
        if edge["relationship"] == "can_reach"
        and edge["from"] in surviving and edge["to"] in surviving
    ]
    deletion_impacts = _deletion_impacts(base_graph, branch_graph)

    base_findings = run_all_checks(base_infra, base_graph)
    branch_findings = run_all_checks(branch_infra, branch_graph)
    # Deliberately invoke combo detection for parity with the normal scan path;
    # toxic combinations are intentionally not part of DiffResult.
    find_toxic_combos(base_findings, base_graph, base_infra)
    find_toxic_combos(branch_findings, branch_graph, branch_infra)

    before = _flatten_findings(base_findings)
    after = _flatten_findings(branch_findings)
    added_keys = set(after) - set(before)
    removed_keys = set(before) - set(after)
    added_findings = sorted((after[key] for key in added_keys), key=_finding_sort)
    removed_findings = sorted((before[key] for key in removed_keys), key=_finding_sort)

    base_score = calculate_score(base_findings, infrastructure=base_infra)["overall_risk_score"]
    branch_score = calculate_score(branch_findings, infrastructure=branch_infra)["overall_risk_score"]
    base_reachable = get_internet_reachable_set(base_graph)
    branch_reachable = get_internet_reachable_set(branch_graph)

    return DiffResult(
        **graph_diff,
        lost_dependencies=lost_dependencies,
        lost_connectivity=lost_connectivity,
        deletion_impacts=deletion_impacts,
        coverage_warnings=coverage_warnings,
        collection_warnings=collection_warnings,
        added_findings=added_findings,
        removed_findings=removed_findings,
        score_before=int(base_score),
        score_after=int(branch_score),
        score_delta=int(branch_score) - int(base_score),
        newly_internet_reachable=sorted(branch_reachable - base_reachable),
        no_longer_internet_reachable=sorted(base_reachable - branch_reachable),
        modeled_state_unchanged=modeled_state_unchanged(base_infra, branch_infra),
    )
