"""Deterministic combined native and Checkov verdicts."""

from __future__ import annotations

from typing import Any, Literal, Mapping, List
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from app import cost, limits, delete_lens
from app.evidence_models import parse_iso
from app.tags import has_conditional_iam_statement, retagged_resources
from app.diffing import diff_infrastructure
from app.delete_lens import DeletionLens, analyze_deletions, deleted_base_reachable, deleted_role_usage_unknown, recently_used_deleted
from app.egraph import build_graph, build_graph_pair, get_internet_reachable_set

_ORIGINAL_BUILD_GRAPH = build_graph


def _comparison_graphs(base_infra, branch_infra):
    # Preserve callers' test/mocking hook while production uses union-stable IDs.
    if build_graph is not _ORIGINAL_BUILD_GRAPH:
        return build_graph(base_infra), build_graph(branch_infra)
    return build_graph_pair(base_infra, branch_infra)
from app.iam_escalation import matching_paths
from app.mutations import _MUTATION_CAPABILITIES, deletion_ledger
from app.models import AWSInfrastructure
from app.plan_ingest import is_aws_provider
from app.scanners import loss_summary, run_checkov, run_cloudsplaining, run_trivy, scanner_loss as compute_scanner_loss
from app.exposure import compute_exposures


Severity = Literal["critical", "high", "medium", "low"]


class CombinedVerdict(BaseModel):
    deletion: DeletionLens = Field(default_factory=DeletionLens)
    verdict: Literal["pass", "warn", "block"]
    branch_revision: str | None = None
    status: str = "open"
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
    reasons: list[dict[str, Any]] = Field(default_factory=list)
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
    # Everything the Terraform handed to the scanners omits or synthesizes
    # (resources, fields, assumed values) for the branch; see app/serializer.py.
    scanner_loss: list[dict[str, Any]] = Field(default_factory=list)
    # Human-readable degradation notices. NON-EMPTY means this verdict was
    # computed with less than the full lens set, so it must not be presented as
    # a complete answer.
    coverage_warnings: List[str] = Field(default_factory=list)
    collection_warnings: List[str] = Field(default_factory=list)
    cost_delta: dict[str, Any] = Field(default_factory=dict)
    resources_added: list[dict] = Field(default_factory=list)
    resources_removed: list[dict] = Field(default_factory=list)
    resources_modified: list[dict] = Field(default_factory=list)
    cost_before: dict = Field(default_factory=dict)
    cost_after: dict = Field(default_factory=dict)
    cost_changes: list[dict] = Field(default_factory=list)
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
        base_graph, branch_graph = _comparison_graphs(base_infra, branch_infra)
        base_escalating = _role_ids_with_privilege_escalation(base_graph)
        branch_escalating = _role_ids_with_privilege_escalation(branch_graph)
        return branch_escalating - base_escalating, set(get_internet_reachable_set(branch_graph))
    except Exception:
        return set(), set()


def _native_finding(finding: Any) -> dict[str, Any]:
    rule_id = _text(_value(finding, "rule_id"))
    resource = _text(_value(finding, "resource_id"))
    result = {
        "source": "native",
        "check_id": rule_id,
        "resource": resource,
        "severity": _severity(_value(finding, "severity")),
        "title": rule_id,
        "rule_id": rule_id,
        "resource_id": resource,
    }
    metadata = _value(finding, "metadata", None)
    if metadata:
        result["metadata"] = metadata
    return result


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
    resource_map = _value(result, "resource_map", None)
    if not isinstance(resource_map, Mapping):
        resource_map = {}
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
        # Checkov reports "resource.<name>", Trivy "<type>.<name>" or the bare
        # name; either way the last segment is the Terraform name.
        mapped = resource_map.get(normalized["resource"].rsplit(".", 1)[-1])
        if isinstance(mapped, (tuple, list)) and len(mapped) == 2:
            mapped = {"resource_type": mapped[0], "id": mapped[1]}
        if isinstance(mapped, Mapping) and mapped.get("id"):
            normalized["resource"] = str(mapped["id"])
            normalized["resource_type"] = str(mapped.get("resource_type", ""))
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


def _resource_ids(values: Any) -> list[str]:
    """Normalize attributable resource ids deterministically."""
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    result: set[str] = set()
    for value in values:
        if isinstance(value, Mapping):
            value = value.get("resource_id", value.get("resource", value.get("id", "")))
        else:
            value = _value(value, "resource_id", _value(value, "id", value))
        value = _text(value)
        if value:
            result.add(value)
    return sorted(result)


def _edge_resource_ids(items: Any) -> list[str]:
    ids: list[str] = []
    for item in items or []:
        ids.extend(_resource_ids([_value(item, "from"), _value(item, "to")]))
    return _resource_ids(ids)


def _deletion_resource_ids(items: Any) -> list[str]:
    ids: list[str] = []
    for item in items or []:
        ids.extend(_resource_ids([_value(item, "removed_resource", {})]))
        ids.extend(_resource_ids(_value(item, "surviving_related_resources", []) or []))
    return _resource_ids(ids)


def _reason(level: str, code: str, message: str, resources: list[str] | None = None) -> dict[str, Any]:
    reason: dict[str, Any] = {"level": level, "code": code, "message": message}
    if resources:
        unique = []
        seen = set()
        for resource in resources:
            resource = _text(resource)
            if resource and resource not in seen:
                seen.add(resource)
                unique.append(resource)
        if unique:
            total = len(unique)
            reason["resources"] = unique[:50]
            if total > 50:
                reason["resources_total"] = total
    return reason


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
            source_label = "AWS API call" if isinstance(item, Mapping) and item.get("source") == "aws_api" else "Terraform plan"
            address = item.get("address") if isinstance(item, Mapping) else None
            addresses = _resource_ids([address])
            if item.get("stateless_replace"):
                suffix = "; its DNS name will change, so clients that use the old name will break" if item.get("type") in {"aws_lb", "aws_alb"} else ""
                reasons.append(_reason(
                    "warn", "stateless_replace",
                    f"Terraform plan replaces {item.get('type')} without changing its network or security settings{suffix}", addresses,
                ))
            elif item.get("unseen"):
                detail = item.get("detail") or ("cannot tell which security group this rule belongs to" if item.get("unresolvable_parent")
                          else f"{item.get('type')} changes network access and Emfirge does not read it yet")
                reasons.append(_reason("block", "unseen_change", f"Emfirge can't see this: {detail}", addresses))
            elif not is_aws_provider(provider_name):
                reasons.append(_reason("warn", "outside_view", f"{source_label} changes resources outside what Emfirge can see", addresses))
            elif "delete" in actions:
                reasons.append(_reason("block", "unmodeled_delete", f"{source_label} deletes or replaces an AWS resource type Emfirge does not model", addresses))
            elif item.get("risk") == "risky" and source_label == "AWS API call":
                operation = item.get("type", "AWS API call").split(".", 1)[-1]
                reasons.append(_reason("block", "unmodeled_risky_change", f"Unmodeled AWS API call {operation} can remove access or protections; blocked until Emfirge models it.", addresses))
            else:
                reasons.append(_reason("warn", "unmodeled_change", f"{source_label} contains unmodeled resources", addresses))
        rejected = plan.get("rejected") or []
        rejected_addresses = _resource_ids(item.get("address") for item in rejected if isinstance(item, Mapping))
        if any(not isinstance(item, Mapping) or "op" not in item or item.get("op") == "delete" for item in rejected):
            reasons.append(_reason("block", "plan_delete_rejected", "A Terraform plan deletion could not be applied to the branch, so its impact was not evaluated", rejected_addresses))
        elif any(item.get("op") != "delete" for item in rejected if isinstance(item, Mapping)):
            reasons.append(_reason("warn", "plan_change_rejected", "Terraform plan changes were rejected", rejected_addresses))
        if plan.get("unknown_fields"):
            unknown_addresses = _resource_ids(item.get("address") for item in plan.get("unknown_fields", []) if isinstance(item, Mapping))
            reasons.append(_reason("warn", "unknown_plan_values", "Terraform plan contains unknown or unsupported values", unknown_addresses))
    return reasons


def combined_verdict(
    base_infra: AWSInfrastructure,
    branch_infra: AWSInfrastructure,
    run_scanners: bool = True,
    plans: list[Mapping[str, Any]] | None = None,
    evidence=None,
    policy_notes: list[str] | None = None,
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
    coverage_warnings.extend(policy_notes or [])
    collection_warnings = diff.collection_warnings
    scanner_added: list[dict[str, Any]] = []
    scanner_removed: list[dict[str, Any]] = []
    scanner_loss: list[dict[str, Any]] = []
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
        try:
            scanner_loss = compute_scanner_loss(branch_infra)
        except Exception:  # noqa: BLE001 - the report must never break a verdict
            scanner_loss = []
        loss_note = loss_summary(scanner_loss)
        if loss_note:
            coverage_warnings.append(loss_note)
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
    ledger = deletion_ledger(branch_infra)
    deleted_resource_ids = _resource_ids(item.get("resource_id") for item in ledger)
    deleted_role_ids = _resource_ids(
        item.get("resource_id") for item in ledger if item.get("resource_type") == "iam_role"
    )
    no_recovery = data_lost
    deletion_relationships = [item for item in deletion.impacts if item.relation != "deleted_with"]
    cloudtrail_unknown_ids = _resource_ids(
        _value(item, "resource_id") for item in deletion.in_use_evidence
        if _value(item, "source") == "cloudtrail_events"
        and _value(item, "status") in {"denied", "error", "incomplete", "unknown"}
    )
    cloudwatch_used_ids = _resource_ids(
        _value(item, "resource_id") for item in deletion.in_use_evidence
        if _value(item, "source") == "cloudwatch_metrics"
        and _value(item, "status") == "ok" and _value(item, "used") is True
    )
    cloudtrail_recent_ids = _resource_ids(
        _value(item, "resource_id") for item in deletion.in_use_evidence
        if _value(item, "source") == "cloudtrail_events"
        and _value(item, "status") == "ok"
        and (parse_iso(_value(item, "last_event_at")) is not None)
        and (observed_at := parse_iso(_value(item, "observed_at"))) is not None
        and observed_at - timedelta(days=delete_lens.RECENT_USE_DAYS) <= parse_iso(_value(item, "last_event_at")) <= observed_at
    )
    removed_recovery_point_ids = _resource_ids(
        item.get("resource_id") for item in ledger
        if item.get("resource_type") in {"rds_snapshot", "ebs_snapshot"}
    )
    no_recovery = data_lost
    deleted_role_dependency = bool(diff.lost_dependencies)

    reasons: list[dict[str, str]] = []
    base_instance_ids = {
        _text(_value(item, "id"))
        for item in (_value(_value(base_infra, "ec2", {}), "instances", []) or [])
    }
    unspecified_ids = []
    for instance in (_value(_value(branch_infra, "ec2", {}), "instances", []) or []):
        instance_id = _text(_value(instance, "id"))
        if (instance_id and instance_id not in base_instance_ids
                and (not _value(instance, "subnet_id") or not (_value(instance, "sg_ids", []) or []))):
            unspecified_ids.append(instance_id)
    if unspecified_ids:
        if "unspecified_change_fields" not in coverage_warnings:
            coverage_warnings.append("unspecified_change_fields")
        reasons.append(_reason(
            "warn", "unspecified_values",
            "A change leaves network placement unspecified; AWS would pick defaults Emfirge cannot predict",
            unspecified_ids,
        ))
    unspecified_snapshot_ids = [
        _text(_value(item, "id")) for item in (_value(_value(branch_infra, "rds", {}), "rds_snapshots", []) or [])
        if _text(_value(item, "id")) not in {
            _text(_value(base_item, "id")) for base_item in (_value(_value(base_infra, "rds", {}), "rds_snapshots", []) or [])
        } and not _value(item, "db_instance_id")
    ]
    if unspecified_snapshot_ids:
        if "unspecified_change_fields" not in coverage_warnings:
            coverage_warnings.append("unspecified_change_fields")
        reasons.append(_reason(
            "warn", "unspecified_values",
            "A change leaves a snapshot source database unspecified; Emfirge cannot tell which database it protects",
            unspecified_snapshot_ids,
        ))
    base_nat_ids = set(_value(_value(base_infra, "vpc", {}), "nat_gateways", []) or [])
    unspecified_nat_ids = [
        _text(_value(item, "id")) for item in (_value(_value(branch_infra, "vpc", {}), "nat_gateway_details", []) or [])
        if _text(_value(item, "id")) not in base_nat_ids and (
            not _value(item, "subnet_id")
            or (_value(item, "connectivity_type") == "public" and not _value(item, "allocation_id"))
        )
    ]
    if unspecified_nat_ids:
        if "unspecified_change_fields" not in coverage_warnings:
            coverage_warnings.append("unspecified_change_fields")
        reasons.append(_reason(
            "warn", "unspecified_values",
            "A change leaves a NAT gateway's subnet or public Elastic IP unspecified; AWS requires them and Emfirge will not guess",
            unspecified_nat_ids,
        ))
    base_volume_ids = {_text(_value(item, "id")) for item in (_value(_value(base_infra, "ec2", {}), "ebs_volumes", []) or [])}
    unspecified_volume_ids = [
        _text(_value(item, "id")) for item in (_value(_value(branch_infra, "ec2", {}), "ebs_volumes", []) or [])
        if _text(_value(item, "id")) not in base_volume_ids and not _value(item, "availability_zone")
    ]
    if unspecified_volume_ids:
        if "unspecified_change_fields" not in coverage_warnings:
            coverage_warnings.append("unspecified_change_fields")
        reasons.append(_reason(
            "warn", "unspecified_values",
            "A change leaves an EBS volume's availability zone unspecified; AWS requires it and Emfirge will not guess",
            unspecified_volume_ids,
        ))
    base_role_ids = {_text(_value(item, 'role_arn')) for item in (_value(_value(base_infra, 'iam', {}), 'role_policies', []) or [])}
    unspecified_role_ids = [_text(_value(item, 'role_arn')) for item in (_value(_value(branch_infra, 'iam', {}), 'role_policies', []) or []) if _text(_value(item, 'role_arn')) not in base_role_ids and not _value(item, 'trust_external_unrestricted') and not _value(item, 'trust_allows_external') and not _value(item, 'trust_has_conditions')]
    if unspecified_role_ids:
        if 'unspecified_change_fields' not in coverage_warnings: coverage_warnings.append('unspecified_change_fields')
        reasons.append(_reason('warn', 'unspecified_values', 'A change leaves a role trust policy unspecified; Emfirge cannot tell who can assume it', unspecified_role_ids))
    retagged = retagged_resources(base_infra, branch_infra) if isinstance(branch_infra, AWSInfrastructure) and isinstance(base_infra, AWSInfrastructure) else []
    if retagged and has_conditional_iam_statement(branch_infra):
        reasons.append(_reason(
            "warn", "tag_change_access_unmodeled",
            "Tags changed and some IAM policies have conditions; Emfirge does not evaluate tag-based (ABAC) conditions, so access may change",
            retagged,
        ))
    if introduced_critical:
        reasons.append(_reason("block", "introduced_critical_finding", "Introduced Critical finding", _resource_ids(item.get("resource") for item in introduced_critical)))
    broad_access_findings = [
        item for item in diff.added_findings
        if _text(_value(item, "rule_id")) == "EMFIRGE-IAM-008"
    ]
    # Native diff findings are deliberately reduced to a stable wire shape;
    # recover the role from the branch graph for the explainable resource list.
    broad_branch_graph = _comparison_graphs(base_infra, branch_infra)[1] if broad_access_findings else None
    for finding in sorted(broad_access_findings, key=lambda item: (_text(_value(item, "resource_id")), _text(_value(item, "severity")))):
        metadata = _value(finding, "metadata", {}) or {}
        compute_id = _text(_value(finding, "resource_id"))
        role_id = _text(metadata.get("role_id"))
        if not role_id and broad_branch_graph is not None:
            role_nodes = broad_branch_graph.get_outbound(compute_id, "uses_iam_role") + broad_branch_graph.get_outbound(compute_id, "USES_ROLE")
            if role_nodes:
                role_id = sorted(_text(_value(node, "id")) for node in role_nodes)[0]
        action = _text(metadata.get("matched_action_pattern"))
        resource = _text(metadata.get("matched_resource_pattern"))
        level = "block" if _severity(_value(finding, "severity")) == "critical" else "warn"
        message = f"Internet can reach a {_text(_value(finding, 'resource_type'))} whose role can read data broadly ({action})"
        resources = [compute_id, role_id]
        matched_buckets = metadata.get("matched_buckets") or []
        if matched_buckets:
            bucket_ids = []
            for bucket in matched_buckets:
                bucket_id = broad_branch_graph.node_id_for("s3_bucket", bucket) if broad_branch_graph is not None else None
                bucket_ids.append(bucket_id or bucket)
            resources += bucket_ids
            n = len(matched_buckets)
            message += f": path {_text(_value(finding, 'resource_type'))} -> role -> {n} bucket" + ("s" if n != 1 else "") + " (in order in resources)"
        reasons.append(_reason(
            level, "internet_to_broad_data_access", message,
            resources=resources,
        ))
    if active_critical_exposure:
        reasons.append(_reason("block", "introduced_critical_exposure", "Introduced Critical exposure", _resource_ids(item.get("resource_id") for item in active_critical_exposure)))
    if introduces_privilege_escalation:
        reasons.append(_reason("block", "privilege_escalation", "Privilege escalation was introduced", _resource_ids(introduced_escalating_roles)))
    if deleted_role_usage_unknown(base_infra, branch_infra):
        reasons.append(_reason("block", "usage_unknown", "Deleted IAM role usage could not be verified", deleted_role_ids))
    if recently_used_deleted(base_infra, branch_infra):
        reasons.append(_reason("block", "recently_used", "Deleted IAM role was recently used", deleted_role_ids))
    if any(
        _value(item, "source") == "cloudtrail_events"
        and _value(item, "status") in {"denied", "error", "incomplete", "unknown"}
        for item in deletion.in_use_evidence
    ):
        reasons.append(_reason("block", "usage_unknown", "CloudTrail usage could not be verified for a deleted resource", cloudtrail_unknown_ids))
    if any(_value(item, "source") == "cloudwatch_metrics" and _value(item, "status") == "ok" and _value(item, "used") is True for item in deletion.in_use_evidence):
        reasons.append(_reason("block", "recently_used", "CloudWatch metrics show a deleted resource was used in the last 90 days", cloudwatch_used_ids))
    if any(
        _value(item, "source") == "cloudtrail_events"
        and _value(item, "status") == "ok"
        and (parse_iso(_value(item, "last_event_at")) is not None)
        and (observed_at := parse_iso(_value(item, "observed_at"))) is not None
        and observed_at - timedelta(days=delete_lens.RECENT_USE_DAYS) <= parse_iso(_value(item, "last_event_at")) <= observed_at
        for item in deletion.in_use_evidence
    ):
        reasons.append(_reason("warn", "recent_activity", "CloudTrail shows recent changes to a deleted resource", cloudtrail_recent_ids))
    if no_recovery:
        reasons.append(_reason("block", "data_store_deleted_no_recovery_point", "Deleted data store has no recovery point", _resource_ids(item.get("resource_id") for item in no_recovery)))
    if recovered_deleted:
        reasons.append(_reason("warn", "data_store_deleted_with_recovery_point", "Deleted data store has a surviving recovery point", _resource_ids(recovered_deleted)))
    if data_lost and any(item.resource_id not in {x.resource_id for x in deletion.data_lost} for item in deletion.recovery_points):
        reasons.append(_reason("warn", "recovery_point_removed", "A recovery point was removed", removed_recovery_point_ids))
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
        reasons.append(_reason("warn", "recovery_point_removed", "A recovery point was removed", removed_recovery_point_ids))
    if deleted_base_reachable(base_infra, branch_infra):
        reasons.append(_reason("warn", "lost_ingress", "Internet ingress resource was deleted", _resource_ids(diff.no_longer_internet_reachable)))
    if introduced_other:
        reasons.append(_reason("warn", "introduced_finding", "Introduced finding", _resource_ids(item.get("resource") for item in introduced_other)))
    if latent_exposure:
        reasons.append(_reason("warn", "latent_exposure", "Latent exposure", _resource_ids(item.get("resource_id") for item in latent_exposure)))
    if warn_exposures and not latent_exposure:
        reasons.append(_reason("warn", "new_exposure", "New exposure", _resource_ids(item.get("resource_id") for item in warn_exposures)))
    if diff.newly_internet_reachable:
        reasons.append(_reason("warn", "newly_internet_reachable", "A resource is newly internet reachable", _resource_ids(diff.newly_internet_reachable)))
    if diff.no_longer_internet_reachable and not deleted_base_reachable(base_infra, branch_infra):
        reasons.append(_reason("warn", "lost_ingress", "Internet ingress is no longer reachable", _resource_ids(diff.no_longer_internet_reachable)))
    if diff.lost_dependencies:
        reasons.append(_reason("warn", "lost_dependency", "A dependency was removed", _edge_resource_ids(diff.lost_dependencies)))
    if diff.lost_connectivity:
        reasons.append(_reason("warn", "lost_connectivity", "Connectivity was removed", _edge_resource_ids(diff.lost_connectivity)))
    if deletion_relationships:
        reasons.append(_reason("warn", "deletion_impact", "A deletion has downstream impact", _deletion_resource_ids(diff.deletion_impacts)))
    if introduced_capacity_breaches:
        reasons.append(_reason("warn", "capacity", f"Capacity breach in resource_id={introduced_capacity_breaches[0].get('scope', '')}", _resource_ids(item.get("scope") for item in introduced_capacity_breaches)))
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
        resources_added=diff.resources_added,
        resources_removed=diff.resources_removed,
        resources_modified=diff.resources_modified,
        cost_before=diff.cost_before,
        cost_after=diff.cost_after,
        cost_changes=diff.cost_changes,
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
        scanner_loss=scanner_loss,
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
