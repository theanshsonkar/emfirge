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
    added_findings: list[dict] = Field(default_factory=list)
    removed_findings: list[dict] = Field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    newly_internet_reachable: list[str] = Field(default_factory=list)
    no_longer_internet_reachable: list[str] = Field(default_factory=list)


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


def diff_infrastructure(base_infra: Any, branch_infra: Any) -> DiffResult:
    """Compare infrastructure snapshots without mutating either input."""
    base_graph = build_graph(base_infra)
    branch_graph = build_graph(branch_infra)
    graph_diff = diff_graphs(base_graph, branch_graph)

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
        added_findings=added_findings,
        removed_findings=removed_findings,
        score_before=int(base_score),
        score_after=int(branch_score),
        score_delta=int(branch_score) - int(base_score),
        newly_internet_reachable=sorted(branch_reachable - base_reachable),
        no_longer_internet_reachable=sorted(base_reachable - branch_reachable),
    )
