"""Deterministic combined native and Checkov verdicts."""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping, List

from pydantic import BaseModel, Field

from app import cost, limits
from app.diffing import diff_infrastructure
from app.egraph import build_graph, get_internet_reachable_set
from app.models import AWSInfrastructure
from app.scanners import run_checkov, run_cloudsplaining, run_trivy


Severity = Literal["critical", "high", "medium", "low"]


class CombinedVerdict(BaseModel):
    verdict: Literal["pass", "warn", "block"]
    native_added: list[dict[str, Any]] = Field(default_factory=list)
    native_removed: list[dict[str, Any]] = Field(default_factory=list)
    scanner_added: list[dict[str, Any]] = Field(default_factory=list)
    scanner_removed: list[dict[str, Any]] = Field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    newly_internet_reachable: list[str] = Field(default_factory=list)
    no_longer_internet_reachable: list[str] = Field(default_factory=list)
    scanner_available: bool = False
    cost_delta_monthly_usd: float = 0.0
    cost_unknown_notes: List[str] = Field(default_factory=list)
    introduces_privilege_escalation: bool = False
    limits_introduced: List[dict] = Field(default_factory=list)
    limits_resolved: List[dict] = Field(default_factory=list)
    summary: str


_SEVERITIES = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _severity(value: Any) -> str:
    return _SEVERITIES.get(_text(value).lower(), "low")


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _role_ids_with_privilege_escalation(graph: Any) -> set[str]:
    nodes = _value(graph, "nodes", []) or []
    escalating = set()
    for node in nodes:
        if _text(_value(node, "resource_type", _value(node, "type", ""))) != "iam_role":
            continue
        base = _value(node, "base", None)
        if base is None:
            base = _value(node, "metadata", {}) or {}
        if isinstance(base, Mapping) and base.get("has_privilege_escalation") is True:
            node_id = _value(node, "id")
            if node_id is not None:
                escalating.add(str(node_id))
    return escalating


def _cost_details(base_infra: AWSInfrastructure, branch_infra: AWSInfrastructure) -> tuple[float, List[str]]:
    try:
        delta = cost.cost_delta(base_infra, branch_infra)
        monthly = _value(delta, "monthly_delta_usd", 0.0)
        notes = _value(delta, "unknown_notes", []) or []
        return float(monthly), [str(note) for note in notes]
    except Exception:
        return 0.0, []


def _graph_escalation_details(base_infra: AWSInfrastructure, branch_infra: AWSInfrastructure) -> tuple[set[str], set[str]]:
    try:
        base_graph = build_graph(base_infra)
        branch_graph = build_graph(branch_infra)
        base_escalating = _role_ids_with_privilege_escalation(base_graph)
        branch_escalating = _role_ids_with_privilege_escalation(branch_graph)
        return branch_escalating - base_escalating, set(get_internet_reachable_set(branch_graph))
    except Exception:
        return set(), set()


def _native_finding(finding: Any) -> dict[str, Any]:
    rule_id = _text(_value(finding, "rule_id"))
    resource = _text(_value(finding, "resource_id"))
    return {
        "source": "native",
        "check_id": rule_id,
        "resource": resource,
        "severity": _severity(_value(finding, "severity")),
        "title": rule_id,
        "rule_id": rule_id,
        "resource_id": resource,
    }


def _sort_finding(item: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        _text(item.get("check_id")),
        _text(item.get("resource")),
        _text(item.get("severity")),
        _text(item.get("title")),
        _text(item.get("guideline")),
        _text(item.get("source")),
    )


def _scanner_finding(finding: Any) -> dict[str, Any] | None:
    check_id = _text(_value(finding, "check_id"))
    resource = _text(_value(finding, "resource"))
    if not check_id or not resource:
        return None
    title = _text(_value(finding, "title", _value(finding, "check_name", "")))
    guideline_value = _value(finding, "guideline", _value(finding, "guideline_url"))
    guideline = None if guideline_value is None else _text(guideline_value)
    source = _text(_value(finding, "source", "checkov")) or "checkov"
    return {
        "source": source,
        "check_id": check_id,
        "resource": resource,
        "severity": _severity(_value(finding, "severity")),
        "title": title,
        "guideline": guideline,
    }


def _scanner_map(result: Any) -> dict[tuple[str, str, str], dict[str, Any]] | None:
    """Return a deterministic scanner finding map, or None when unavailable."""
    if result is None:
        return None
    available = _value(result, "available", None)
    if available is False:
        return None
    findings = _value(result, "findings", result if isinstance(result, list) else None)
    if findings is None and isinstance(result, Mapping):
        # A direct finding dictionary is also a useful test/mock shape.
        findings = [result] if "check_id" in result else None
    if not isinstance(findings, (list, tuple)):
        return None
    selected: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in findings:
        normalized = _scanner_finding(raw)
        if normalized is None:
            continue
        key = (normalized["source"], normalized["check_id"], normalized["resource"])
        current = selected.get(key)
        if current is None or _sort_finding(normalized) < _sort_finding(current):
            selected[key] = normalized
    return selected


def _privilege_escalation(finding: Mapping[str, Any]) -> bool:
    text = " ".join(_text(finding.get(field)) for field in ("check_id", "title", "guideline", "rule_id"))
    lowered = text.lower()
    if re.search(r"privilege\s+escalation", lowered):
        return True
    if re.search(r"iam\s*:\s*passrole|\bpassrole\b", lowered):
        return True
    if re.search(r"\badministrator(?:access)?\b|\badmin\s+access\b", lowered):
        return True
    if re.search(r"\b(?:iam|action)\s*[:=]\s*\*", lowered):
        return True
    if "wildcard" in lowered and re.search(r"\b(?:iam|action)\b", lowered):
        return True
    return False


def _serialize_limit_finding(finding: Any) -> dict[str, Any]:
    """Serialize a limit finding without mutating the Pydantic model."""
    if hasattr(finding, "model_dump"):
        return dict(finding.model_dump())
    if hasattr(finding, "dict"):
        return dict(finding.dict())
    return dict(finding)


def _limit_sort_key(item: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(_text(item.get(field)) for field in ("check", "scope", "status", "current", "limit", "basis"))


def combined_verdict(
    base_infra: AWSInfrastructure,
    branch_infra: AWSInfrastructure,
    run_scanners: bool = True,
) -> CombinedVerdict:
    diff = diff_infrastructure(base_infra, branch_infra)
    limit_delta = limits.limits_delta(base_infra, branch_infra)
    limits_introduced = sorted(
        (_serialize_limit_finding(item) for item in limit_delta.introduced),
        key=_limit_sort_key,
    )
    limits_resolved = sorted(
        (_serialize_limit_finding(item) for item in limit_delta.resolved),
        key=_limit_sort_key,
    )
    introduced_capacity_breaches = [
        item for item in limits_introduced if item.get("status") == "exceeded"
    ]
    cost_delta_monthly_usd, cost_unknown_notes = _cost_details(base_infra, branch_infra)
    introduced_escalating_roles, branch_reachable = _graph_escalation_details(base_infra, branch_infra)
    introduces_privilege_escalation = bool(introduced_escalating_roles)
    native_added = sorted((_native_finding(item) for item in diff.added_findings), key=_sort_finding)
    native_removed = sorted((_native_finding(item) for item in diff.removed_findings), key=_sort_finding)

    scanner_available = False
    scanner_added: list[dict[str, Any]] = []
    scanner_removed: list[dict[str, Any]] = []
    if run_scanners:
        scanner_results = ((run_checkov, "checkov"), (run_trivy, "trivy"), (run_cloudsplaining, "cloudsplaining"))
        base_scans: dict[str, dict[tuple[str, str, str], dict[str, Any]] | None] = {}
        branch_scans: dict[str, dict[tuple[str, str, str], dict[str, Any]] | None] = {}
        for scanner, name in scanner_results:
            try:
                base_scans[name] = _scanner_map(scanner(base_infra))
            except Exception:
                base_scans[name] = None
            try:
                branch_scans[name] = _scanner_map(scanner(branch_infra))
            except Exception:
                branch_scans[name] = None

        available_scanners = {
            name for name in base_scans
            if base_scans[name] is not None and branch_scans[name] is not None
        }
        scanner_available = bool(available_scanners)
        if scanner_available:
            base_scan = {}
            branch_scan = {}
            for name in available_scanners:
                base_scan.update(base_scans[name] or {})
                branch_scan.update(branch_scans[name] or {})
            scanner_added = sorted(
                (branch_scan[key] for key in set(branch_scan) - set(base_scan)),
                key=_sort_finding,
            )
            scanner_removed = sorted(
                (base_scan[key] for key in set(base_scan) - set(branch_scan)),
                key=_sort_finding,
            )

    new_findings = native_added + scanner_added
    reachable = set(diff.newly_internet_reachable)
    blocking = any(
        item["severity"] in {"critical", "high"}
        and (_text(item.get("resource")) in reachable or _privilege_escalation(item))
        for item in new_findings
    )
    introduced_reachable = introduced_escalating_roles & branch_reachable
    if blocking or introduced_reachable:
        verdict = "block"
    elif new_findings or diff.newly_internet_reachable or introduces_privilege_escalation:
        verdict = "warn"
    else:
        verdict = "pass"
    if verdict == "pass" and introduced_capacity_breaches:
        verdict = "warn"

    unavailable = " (scanner unavailable)" if run_scanners and not scanner_available else ""
    cost_summary = "cost unknown" if cost_unknown_notes else f"cost_delta={cost_delta_monthly_usd:.2f}"
    privilege_summary = "; privilege escalation introduced" if introduces_privilege_escalation else ""
    capacity_summary = ""
    if introduced_capacity_breaches:
        breaches = ",".join(
            f"{item.get('check')}/{item.get('scope')}" for item in introduced_capacity_breaches
        )
        capacity_summary = f"; capacity_breaches={breaches}"
    summary = (
        f"verdict={verdict}; native_added={len(native_added)}; scanner_added={len(scanner_added)}; "
        f"native_removed={len(native_removed)}; scanner_removed={len(scanner_removed)}; "
        f"newly_reachable={len(diff.newly_internet_reachable)}; score={diff.score_before}->{diff.score_after} "
        f"(delta={diff.score_delta}); {cost_summary}{privilege_summary}{capacity_summary}{unavailable}"
    )
    return CombinedVerdict(
        verdict=verdict,
        native_added=native_added,
        native_removed=native_removed,
        scanner_added=scanner_added,
        scanner_removed=scanner_removed,
        score_before=diff.score_before,
        score_after=diff.score_after,
        score_delta=diff.score_delta,
        newly_internet_reachable=sorted(diff.newly_internet_reachable),
        no_longer_internet_reachable=sorted(diff.no_longer_internet_reachable),
        scanner_available=scanner_available,
        cost_delta_monthly_usd=cost_delta_monthly_usd,
        cost_unknown_notes=cost_unknown_notes,
        introduces_privilege_escalation=introduces_privilege_escalation,
        limits_introduced=limits_introduced,
        limits_resolved=limits_resolved,
        summary=summary,
    )
