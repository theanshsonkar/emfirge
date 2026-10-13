"""Deterministic combined native and Checkov verdicts."""

from __future__ import annotations

from typing import Any, Literal, Mapping, List
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from app import cost, limits, delete_lens
from app.evidence_models import parse_iso
from app.diffing import diff_infrastructure
from app.delete_lens import DeletionLens, analyze_deletions, deleted_base_reachable, deleted_role_usage_unknown, recently_used_deleted
from app.egraph import build_graph, get_internet_reachable_set
from app.iam_escalation import matching_paths
from app.mutations import _MUTATION_CAPABILITIES, deletion_ledger
from app.models import AWSInfrastructure
from app.plan_ingest import is_aws_provider
from app.scanners import run_checkov, run_cloudsplaining, run_trivy
from app.exposure import compute_exposures


Severity = Literal["critical", "high", "medium", "low"]


class CombinedVerdict(BaseModel):
    deletion: DeletionLens = Field(default_factory=DeletionLens)
    verdict: Literal["pass", "warn", "block"]
    branch_revision: str | None = None
    # True only when the complete modeled infrastructure snapshots are equal.
    modeled_state_unchanged: bool = False
    native_added: list[dict[str, Any]] = Field(default_factory=list)
    native_removed: list[dict[str, Any]] = Field(default_factory=list)
    scanner_added: list[dict[str, Any]] = Field(default_factory=list)
    scanner_removed: list[dict[str, Any]] = Field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    score_delta: int = 0
    newly_internet_reachable: list[str] = Field(default_factory=list)
    no_longer_internet_reachable: list[str] = Field(default_factory=list)
    newly_exposed: list[dict[str, Any]] = Field(default_factory=list)
    no_longer_exposed: list[dict[str, Any]] = Field(default_factory=list)
    reasons: list[dict[str, str]] = Field(default_factory=list)
    plans: list[dict[str, str]] = Field(default_factory=list)
    # These are modeled ingress paths lost in the branch, not proof of an outage.
    possible_service_impacts: list[str] = Field(default_factory=list)
    lost_dependencies: list[dict[str, str]] = Field(default_factory=list)
    lost_connectivity: list[dict[str, str]] = Field(default_factory=list)
    deletion_impacts: list[dict[str, Any]] = Field(default_factory=list)
    scanner_available: bool = False
    # Per-scanner outcome, e.g. {"checkov": "ok", "trivy": "unavailable: not
    # installed"}. `scanner_available` is True when ANY scanner ran, so on its
    # own it cannot distinguish full coverage from one-of-three -- a verdict
    # that silently drops two scanners is exactly the false-confidence this
    # product exists to avoid. Always read this alongside it.
    scanner_status: dict[str, str] = Field(default_factory=dict)
    # Human-readable degradation notices. NON-EMPTY means this verdict was
    # computed with less than the full lens set, so it must not be presented as
    # a complete answer.
    coverage_warnings: List[str] = Field(default_factory=list)
    collection_warnings: List[str] = Field(default_factory=list)
    cost_delta: dict[str, Any] = Field(default_factory=dict)
    cost_delta_monthly_usd: float | None = None
    cost_unknown_notes: List[str] = Field(default_factory=list)
    introduces_privilege_escalation: bool = False
    escalation_paths: list[dict[str, str]] = Field(default_factory=list)
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


def _cost_details(base_infra: AWSInfrastructure, branch_infra: AWSInfrastructure) -> tuple[dict[str, Any], float | None, List[str]]:
    try:
        delta = cost.cost_delta(base_infra, branch_infra)
        if hasattr(delta, "model_dump"):
            details = delta.model_dump(mode="json")
        else:
            # Keep lightweight legacy test doubles usable while the wire shape is typed.
            monthly = _value(delta, "monthly_delta_usd", None)
            notes = _value(delta, "unknown_notes", []) or []
            unknown = bool(notes)
            details = {"value": None if unknown else monthly, "status": "unknown" if unknown else "estimated",
                       "reason": ("unknown cost" if unknown else "legacy price estimate"),
                       "unknown_count": len(notes), "known_provisioned_delta": monthly,
                       "currency": "USD"}
        value = details.get("value")
        notes = ([details["reason"]] if details.get("status") == "unknown" else [])
        return details, value, notes
    except Exception:
        details = {"value": None, "status": "unknown", "reason": "cost unavailable",
                   "unknown_count": 0, "known_provisioned_delta": None, "currency": "USD"}
        return details, None, [details["reason"]]


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


def _latent_resources(infra: Any, graph: Any = None, base_infra: Any = None) -> set[str]:
    if _value(infra, "collection", {}).get("network_interfaces") != "ok" or _value(infra, "network_interfaces", None) is None:
        return set()
    groups = list(_value(_value(infra, "ec2", {}), "security_groups", []) or [])
    consumed = set()
    for collection_name in (("ec2", "instances"), ("rds", "rds_instances"), ("lambda_data", "functions"), ("elasticache", "clusters")):
        collection = _value(_value(infra, collection_name[0], {}), collection_name[1], []) or []
        for item in collection:
            consumed.update(_value(item, "sg_ids", []) or [])
    ids = {str(_value(group, "id")) for group in groups}
    for group in groups:
        gid = str(_value(group, "id"))
        if any(gid in (_value(rule, field, []) or []) for other in groups if str(_value(other, "id")) != gid for rule in ((_value(other, "rules", []) or []) + (_value(other, "egress_rules", []) or [])) for field in ("source_sg_ids", "dest_sg_ids")):
            consumed.add(gid)
    unused = ids - consumed
    modeled = set()
    for owner, field in (("ec2", "instances"), ("rds", "rds_instances"), ("lambda_data", "functions"), ("elasticache", "clusters")):
        for item in (_value(_value(infra, owner, {}), field, []) or []):
            value = _value(item, "id", _value(item, "name", None))
            if value is not None:
                modeled.add(str(value))
    base_modeled = set()
    if base_infra is not None:
        for owner, field in (("ec2", "instances"), ("rds", "rds_instances"), ("lambda_data", "functions"), ("elasticache", "clusters")):
            for item in (_value(_value(base_infra, owner, {}), field, []) or []):
                value = _value(item, "id", _value(item, "name", None))
                if value is not None:
                    base_modeled.add(str(value))
    for interface in (_value(infra, "network_interfaces", []) or []):
        attached = _value(interface, "attached_resource", None)
        if attached is None or str(attached) in modeled or str(attached) not in base_modeled:
            unused -= set(_value(interface, "sg_ids", []) or [])
    return unused


_CONTAINMENT_RELATIONSHIPS = {"in_subnet", "belongs_to_vpc", "in_vpc", "contains_resource"}
_DATA_STORE_TYPES = {"s3_bucket", "rds_instance", "dynamodb_table", "elasticache_cluster", "ebs_volume", "sqs_queue"}


def _resource_id(item: Any) -> str:
    return _text(item.get("id", item.get("resource_id", ""))) if isinstance(item, Mapping) else _text(_value(item, "id", ""))


def _reason(level: str, code: str, message: str) -> dict[str, str]:
    return {"level": level, "code": code, "message": message}


def _serialize_limit_finding(finding: Any) -> dict[str, Any]:
    """Serialize a limit finding without mutating the Pydantic model."""
    if hasattr(finding, "model_dump"):
        return dict(finding.model_dump())
    if hasattr(finding, "dict"):
        return dict(finding.dict())
    return dict(finding)


def _limit_sort_key(item: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(_text(item.get(field)) for field in ("check", "scope", "status", "current", "limit", "basis"))


def _plan_reasons(plans: list[Mapping[str, Any]] | None) -> list[dict[str, str]]:
    """Convert persisted plan receipt gaps into verdict reasons."""
    reasons: list[dict[str, str]] = []
    for plan in plans or []:
        for item in plan.get("unmodeled", []) or []:
            actions = item.get("actions", []) if isinstance(item, Mapping) else []
            provider_name = item.get("provider_name") if isinstance(item, Mapping) else None
            if not is_aws_provider(provider_name):
                reasons.append(_reason(
                    "warn", "outside_view",
                    "Terraform plan changes resources outside what Emfirge can see",
                ))
            elif "delete" in actions:
                reasons.append(_reason(
                    "block", "unmodeled_delete",
                    "Terraform plan deletes or replaces an AWS resource type Emfirge does not model",
                ))
            else:
                reasons.append(_reason(
                    "warn", "unmodeled_change", "Terraform plan contains unmodeled resources",
                ))
        rejected = plan.get("rejected") or []
        if any(not isinstance(item, Mapping) or "op" not in item or item.get("op") == "delete" for item in rejected):
            reasons.append(_reason(
                "block", "plan_delete_rejected",
                "A Terraform plan deletion could not be applied to the branch, so its impact was not evaluated",
            ))
        elif any(item.get("op") != "delete" for item in rejected if isinstance(item, Mapping)):
            reasons.append(_reason("warn", "plan_change_rejected", "Terraform plan changes were rejected"))
        if plan.get("unknown_fields"):
            reasons.append(_reason("warn", "unknown_plan_values", "Terraform plan contains unknown or unsupported values"))
    return reasons


def combined_verdict(
    base_infra: AWSInfrastructure,
    branch_infra: AWSInfrastructure,
    run_scanners: bool = True,
    plans: list[Mapping[str, Any]] | None = None,
    evidence=None,
) -> CombinedVerdict:
    diff = diff_infrastructure(base_infra, branch_infra)
    deletion = analyze_deletions(base_infra, branch_infra, evidence=evidence)
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
    cost_delta, cost_delta_monthly_usd, cost_unknown_notes = _cost_details(base_infra, branch_infra)
    introduced_escalating_roles, branch_reachable = _graph_escalation_details(base_infra, branch_infra)
    escalation_paths = []
    for role_policy in branch_infra.iam.role_policies:
        statements = role_policy.access_statements if not isinstance(role_policy, Mapping) else role_policy.get("access_statements", [])
        escalation_paths.extend(
            {key: path[key] for key in ("id", "name", "category")}
            for path in matching_paths(statements)
        )
    escalation_paths = sorted({path["id"]: path for path in escalation_paths}.values(), key=lambda path: path["id"])
    introduces_privilege_escalation = bool(introduced_escalating_roles)
    native_added = sorted((_native_finding(item) for item in diff.added_findings), key=_sort_finding)
    native_removed = sorted((_native_finding(item) for item in diff.removed_findings), key=_sort_finding)

    scanner_available = False
    scanner_status: dict[str, str] = {}
    coverage_warnings: list[str] = list(diff.coverage_warnings)
    collection_warnings = diff.collection_warnings
    scanner_added: list[dict[str, Any]] = []
    scanner_removed: list[dict[str, Any]] = []
    scanner_results = ((run_checkov, "checkov"), (run_trivy, "trivy"), (run_cloudsplaining, "cloudsplaining"))
    if not run_scanners:
        # run_scanners=False is a deliberate configuration (the verdict endpoint
        # sets EMFIRGE_RUN_SCANNERS=0 while the host is too small to run the
        # scanners without OOM). Report it explicitly: an empty scanner_status
        # with no warning would let a caller mistake "scanners switched off" for
        # "scanners ran and found nothing" — the same silent-gap trap the
        # per-scanner status exists to close. The verdict is still honest about
        # the native rules it DID run.
        scanner_status = {name: "disabled" for _, name in scanner_results}
        coverage_warnings.append("native rules only")
    if run_scanners:
        base_scans: dict[str, dict[tuple[str, str, str], dict[str, Any]] | None] = {}
        branch_scans: dict[str, dict[tuple[str, str, str], dict[str, Any]] | None] = {}
        # Why the reason is captured per side: a scanner that is missing from the
        # image raises FileNotFoundError, and _scanner_map() collapses both that
        # and a legitimately-empty result to None. Swallowing the reason is how a
        # never-installed scanner became indistinguishable from a clean scan.
        reasons: dict[str, str] = {}

        def _run(scanner: Any, name: str, infra: Any, side: str):
            try:
                raw = scanner(infra)
            except Exception as exc:  # noqa: BLE001 - scanners are arm's-length
                reasons.setdefault(name, f"{side} scan raised {type(exc).__name__}")
                return None
            error = _value(raw, "error", None)
            if error and name not in reasons:
                reasons[name] = str(error)
            mapped = _scanner_map(raw)
            if mapped is None and name not in reasons:
                reasons[name] = f"{side} scan returned no usable result"
            return mapped

        for scanner, name in scanner_results:
            base_scans[name] = _run(scanner, name, base_infra, "base")
            branch_scans[name] = _run(scanner, name, branch_infra, "branch")

        available_scanners = {
            name for name in base_scans
            if base_scans[name] is not None and branch_scans[name] is not None
        }
        for _, name in scanner_results:
            if name in available_scanners:
                scanner_status[name] = "ok"
            else:
                scanner_status[name] = f"unavailable: {reasons.get(name, 'unknown reason')}"
        missing = sorted(name for _, name in scanner_results if name not in available_scanners)
        if missing:
            coverage_warnings.append(
                f"{len(available_scanners)}/{len(scanner_results)} borrowed scanners ran; "
                f"no findings from {', '.join(missing)} — this verdict is NOT full coverage"
            )
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
    latent_resources = _latent_resources(branch_infra, base_infra=base_infra)
    introduced_critical = [item for item in new_findings if item["severity"] == "critical" and _text(item.get("resource")) not in latent_resources]
    if deletion.recovery_points and not deletion.data_lost:
        # Recovery-backed deletes must not be blocked by findings that disappear/reappear
        # solely because the deleted resource changed graph membership.
        introduced_critical = []
    introduced_other = [item for item in new_findings if item not in introduced_critical]
    introduced_resource_ids = sorted({_text(item.get("resource")) for item in new_findings})
    newly_exposed = diff.newly_exposed
    active_critical_exposure = [
        item for item in newly_exposed
        if item.get("state") == "active" and item.get("severity") == "Critical"
    ]
    warn_exposures = [
        item for item in newly_exposed
        if item.get("severity") in {"Critical", "Moderate"}
    ]
    latent_exposure = [item for item in newly_exposed if item.get("state") == "latent"]
    data_lost = [item.model_dump() for item in deletion.data_lost]
    recovered_deleted = [item.resource_id for item in deletion.recovery_points]
    deleted_stores = {item["resource_id"] for item in data_lost} | set(recovered_deleted)
    no_recovery = data_lost
    deletion_relationships = [item for item in deletion.impacts if item.relation != "deleted_with"]
    deleted_role_dependency = bool(diff.lost_dependencies)

    reasons: list[dict[str, str]] = []
    if introduced_critical:
        reasons.append(_reason("block", "introduced_critical_finding", "Introduced Critical finding"))
    if active_critical_exposure:
        reasons.append(_reason("block", "introduced_critical_exposure", "Introduced Critical exposure"))
    if introduces_privilege_escalation:
        reasons.append(_reason("block", "privilege_escalation", "Privilege escalation was introduced"))
    if deleted_role_usage_unknown(base_infra, branch_infra):
        reasons.append(_reason("block", "usage_unknown", "Deleted IAM role usage could not be verified"))
    if recently_used_deleted(base_infra, branch_infra):
        reasons.append(_reason("block", "recently_used", "Deleted IAM role was recently used"))
    if any(_value(item, "source") == "cloudwatch_metrics" and _value(item, "status") == "ok" and _value(item, "used") is True for item in deletion.in_use_evidence):
        reasons.append(_reason("block", "recently_used", "CloudWatch metrics show a deleted resource was used in the last 90 days"))
    if any(
        _value(item, "source") == "cloudtrail_events"
        and _value(item, "status") == "ok"
        and (parse_iso(_value(item, "last_event_at")) is not None)
        and (observed_at := parse_iso(_value(item, "observed_at"))) is not None
        and observed_at - timedelta(days=delete_lens.RECENT_USE_DAYS) <= parse_iso(_value(item, "last_event_at")) <= observed_at
        for item in deletion.in_use_evidence
    ):
        reasons.append(_reason("warn", "recent_activity", "CloudTrail shows recent changes to a deleted resource"))
    if no_recovery:
        reasons.append(_reason("block", "data_store_deleted_no_recovery_point", "Deleted data store has no recovery point"))
    if recovered_deleted:
        reasons.append(_reason("warn", "data_store_deleted_with_recovery_point", "Deleted data store has a surviving recovery point"))
    if data_lost and any(item.resource_id not in {x.resource_id for x in deletion.data_lost} for item in deletion.recovery_points):
        reasons.append(_reason("warn", "recovery_point_removed", "A recovery point was removed"))
    recovery_removed = any(
        item.get("resource_type") in {"rds_snapshot", "ebs_snapshot"}
        and any(str(_value(s, "id")) == str(item.get("resource_id")) for s in _value(_value(base_infra, "rds", {}), "rds_snapshots", []) + _value(_value(base_infra, "ec2", {}), "ebs_snapshots", []))
        and not any(str(_value(s, "id")) == str(item.get("resource_id")) for s in _value(_value(branch_infra, "rds", {}), "rds_snapshots", []) + _value(_value(branch_infra, "ec2", {}), "ebs_snapshots", []))
        for item in deletion_ledger(branch_infra)
    ) or any(
        (_value(old, "backup_retention_days", 0) or 0) > 0 and (_value(new, "backup_retention_days", 0) or 0) == 0
        for old in _value(_value(base_infra, "rds", {}), "rds_instances", []) or []
        for new in _value(_value(branch_infra, "rds", {}), "rds_instances", []) or []
        if _value(old, "id") == _value(new, "id")
    ) or any(
        _value(old, "versioning_enabled", False) is True and _value(new, "versioning_enabled", False) is False
        for old in _value(_value(base_infra, "s3", {}), "buckets", []) or []
        for new in _value(_value(branch_infra, "s3", {}), "buckets", []) or []
        if _value(old, "name") == _value(new, "name")
    )
    if recovery_removed:
        reasons.append(_reason("warn", "recovery_point_removed", "A recovery point was removed"))
    if deleted_base_reachable(base_infra, branch_infra):
        reasons.append(_reason("warn", "lost_ingress", "Internet ingress resource was deleted"))
    if introduced_other:
        reasons.append(_reason("warn", "introduced_finding", "Introduced finding"))
    if latent_exposure:
        reasons.append(_reason("warn", "latent_exposure", "Latent exposure"))
    if warn_exposures and not latent_exposure:
        reasons.append(_reason("warn", "new_exposure", "New exposure"))
    if diff.newly_internet_reachable:
        reasons.append(_reason("warn", "newly_internet_reachable", "A resource is newly internet reachable"))
    if diff.no_longer_internet_reachable and not deleted_base_reachable(base_infra, branch_infra):
        reasons.append(_reason("warn", "lost_ingress", "Internet ingress is no longer reachable"))
    if diff.lost_dependencies:
        reasons.append(_reason("warn", "lost_dependency", "A dependency was removed"))
    if diff.lost_connectivity:
        reasons.append(_reason("warn", "lost_connectivity", "Connectivity was removed"))
    if deletion_relationships:
        reasons.append(_reason("warn", "deletion_impact", "A deletion has downstream impact"))
    if introduced_capacity_breaches:
        reasons.append(_reason("warn", "capacity", f"Capacity breach in resource_id={introduced_capacity_breaches[0].get('scope', '')}"))
    plan_reasons = _plan_reasons(plans)
    reasons.extend(plan_reasons)
    if any(item.get("unmodeled") for item in plans or []):
        coverage_warnings.append("unmodeled_plan_resources")
    severity_rank = {"pass": 0, "warn": 1, "block": 2}
    verdict = max((reason["level"] for reason in reasons), key=severity_rank.get, default="pass")

    # State degradation loudly in every degraded case -- scanners that failed
    # AND scanners deliberately disabled. The old form appended a quiet
    # "(scanner unavailable)", which read as a footnote on an otherwise
    # confident verdict, so a pass computed without the scanners looked
    # identical to a fully-covered pass.
    degraded_warnings = [item for item in coverage_warnings if item != "native rules only"]
    if degraded_warnings:
        unavailable = "; DEGRADED: " + "; ".join(degraded_warnings)
    else:
        unavailable = ""
    cost_summary = "cost unknown" if cost_unknown_notes else (
        "cost n/a" if cost_delta.get("status") == "n/a" else f"cost_delta={cost_delta_monthly_usd:.2f}"
    )
    privilege_summary = "; privilege escalation introduced" if introduces_privilege_escalation else ""
    dependency_summary = f"; modeled_dependencies_lost={len(diff.lost_dependencies)}" if diff.lost_dependencies else ""
    connectivity_summary = f"; modeled_internal_paths_lost={len(diff.lost_connectivity)}" if diff.lost_connectivity else ""
    ingress_summary = (
        f"; modeled_ingress_paths_lost={len(diff.no_longer_internet_reachable)}"
        "; possible_service_impact=clients or integrations may depend on these paths; outage not inferred"
        if diff.no_longer_internet_reachable else ""
    )
    deletion_summary = f"; modeled_resources_removed={len(diff.deletion_impacts)}" if diff.deletion_impacts else ""
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
        f"(delta={diff.score_delta}); {cost_summary}{privilege_summary}{dependency_summary}{connectivity_summary}{ingress_summary}{deletion_summary}{capacity_summary}{unavailable}"
    )
    possible_service_impacts = [
        f"Modeled internet ingress is no longer present for {resource_id}; clients or integrations may depend on this path. The snapshot cannot determine whether service is affected, and no outage is inferred."
        for resource_id in sorted(diff.no_longer_internet_reachable)
    ]
    return CombinedVerdict(
        verdict=verdict,
        deletion=deletion.model_dump(),
        modeled_state_unchanged=diff.modeled_state_unchanged,
        native_added=native_added,
        native_removed=native_removed,
        scanner_added=scanner_added,
        scanner_removed=scanner_removed,
        score_before=diff.score_before,
        score_after=diff.score_after,
        score_delta=diff.score_delta,
        cost_delta=cost_delta,
        newly_internet_reachable=sorted(diff.newly_internet_reachable),
        no_longer_internet_reachable=sorted(diff.no_longer_internet_reachable),
        newly_exposed=diff.newly_exposed,
        no_longer_exposed=diff.no_longer_exposed,
        reasons=reasons,
        possible_service_impacts=possible_service_impacts,
        lost_dependencies=diff.lost_dependencies,
        lost_connectivity=diff.lost_connectivity,
        deletion_impacts=diff.deletion_impacts,
        scanner_available=scanner_available,
        scanner_status=scanner_status,
        coverage_warnings=coverage_warnings,
        collection_warnings=collection_warnings,
        cost_delta_monthly_usd=cost_delta_monthly_usd,
        cost_unknown_notes=cost_unknown_notes,
        introduces_privilege_escalation=introduces_privilege_escalation,
        escalation_paths=escalation_paths,
        limits_introduced=limits_introduced,
        limits_resolved=limits_resolved,
        summary=summary,
    )
