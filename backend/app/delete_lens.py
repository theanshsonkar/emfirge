"""Sequence-aware deletion analysis for branch verdicts."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.egraph import DEPENDENCY_EDGES, build_graph, get_internet_reachable_set
from app.mutations import deletion_ledger
from app.evidence_models import EvidenceRecord, METRIC_SPECS

# matches the default unused-access tracking period of AWS IAM Access Analyzer.
RECENT_USE_DAYS = 90
_FIXED_CANNOT_SEE = {"app_code_references", "dns_records", "other_accounts", "data_contents", "cloudtrail_events", "cloudwatch_metrics"}
_COLLECTION_KEYS = {"network_interfaces", "ebs_volumes", "ebs_snapshots", "rds_snapshots", "iam_role_last_used"}

class DataLost(BaseModel):
    resource_id: str
    resource_type: str
    why: str
class RecoveryPoint(BaseModel):
    resource_id: str
    kind: str
    source_id: str
class DeletionImpact(BaseModel):
    resource_id: str
    resource_type: str
    relation: str
    depth: int
    via: str
class DeletionCoverage(BaseModel):
    can_see: list[str] = Field(default_factory=list)
    cannot_see: list[str] = Field(default_factory=list)
class DeletionLens(BaseModel):
    data_lost: list[DataLost] = Field(default_factory=list)
    recovery_points: list[RecoveryPoint] = Field(default_factory=list)
    impacts: list[DeletionImpact] = Field(default_factory=list)
    max_depth: int = 0
    coverage: DeletionCoverage = Field(default_factory=DeletionCoverage)
    in_use_evidence: list[EvidenceRecord] = Field(default_factory=list)


def _v(obj: Any, key: str, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

def _state_items(infra: Any, owner: str, field: str):
    return list(_v(_v(infra, owner, {}), field, []) or [])

def _all_nodes(infra: Any):
    return build_graph(infra).nodes

def _find(items, ident):
    return next((x for x in items if str(_v(x, "id", _v(x, "name", ""))) == str(ident)), None)

def _parse_time(value: Any):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

def analyze_deletions(base: Any, branch: Any, evidence=None) -> DeletionLens:
    evidence = evidence or []
    ledger = deletion_ledger(branch)
    base_graph = build_graph(base)
    final_graph = build_graph(branch)
    base_nodes = {str(_v(n, "id")): n for n in base_graph.nodes}
    final_ids = {str(_v(n, "id")) for n in final_graph.nodes}
    deleted = list(ledger)
    # A delete-only resource may not have a graph node; ledger state is authoritative.
    deleted_ids = {str(x.get("resource_id")) for x in ledger}
    for node in base_graph.nodes:
        metadata = _v(node, "base", {}) or {}
        if metadata.get("arn") in deleted_ids:
            deleted_ids.add(str(_v(node, "id")))
    deleted_base_ids = {str(x.get("resource_id")) for x in deleted}
    snapshots_rds = _state_items(branch, "rds", "rds_snapshots")
    snapshots_ebs = _state_items(branch, "ec2", "ebs_snapshots")
    recovery: list[RecoveryPoint] = []
    lost: list[DataLost] = []
    for item in deleted:
        rid, typ = str(item["resource_id"]), str(item["resource_type"])
        before = item.get("state_before") or {}
        options = item.get("options") or {}
        recovered = False
        if typ == "s3_bucket":
            recovered = bool(before.get("is_empty") is True)
            if recovered:
                recovery.append(RecoveryPoint(resource_id=rid, kind="empty_bucket", source_id=rid))
        elif typ == "rds_instance":
            final_id = options.get("final_db_snapshot_identifier")
            snap = next((s for s in snapshots_rds if str(_v(s, "id")) == str(final_id) and _v(s, "status") == "available"), None) if final_id else None
            snap = snap or next((s for s in snapshots_rds if str(_v(s, "db_instance_id")) == rid and _v(s, "status") == "available"), None)
            retained = options.get("delete_automated_backups") is False and int(before.get("backup_retention_days") or 0) > 0
            recovered = bool(snap or retained)
            if snap:
                recovery.append(RecoveryPoint(resource_id=rid, kind="rds_snapshot", source_id=str(_v(snap, "id"))))
            elif retained:
                recovery.append(RecoveryPoint(resource_id=rid, kind="automated_backup", source_id=rid))
        elif typ == "ebs_volume":
            snap = next((s for s in snapshots_ebs if str(_v(s, "volume_id")) == rid and _v(s, "state") == "completed"), None)
            recovered = bool(snap)
            if snap:
                recovery.append(RecoveryPoint(resource_id=rid, kind="ebs_snapshot", source_id=str(_v(snap, "id"))))
        if typ in {"s3_bucket", "rds_instance", "ebs_volume"} and not recovered:
            lost.append(DataLost(resource_id=rid, resource_type=typ, why="deleted_without_surviving_recovery_point"))
    deleted_set = {str(x.get("resource_id")) for x in ledger}
    scoped = [item for item in evidence if str(_v(item, "resource_id", "")) in deleted_set]
    for item in scoped:
        if _v(item, "resource_type") == "s3_bucket" and _v(item, "status") == "ok" and _v(item, "holds_data") is True:
            rid = str(_v(item, "resource_id"))
            if not any(x.resource_id == rid for x in lost):
                lost.append(DataLost(resource_id=rid, resource_type="s3_bucket", why="deleted_without_surviving_recovery_point"))
    # BFS follows dependency direction only; implicit deletes are represented at depth one.
    impacts: list[DeletionImpact] = []
    seen = set(deleted_ids)
    queue = deque((rid, 0, "deleted") for rid in sorted(deleted_ids))
    for item in ledger:
        if item.get("implicit") and str(item["resource_id"]) in final_ids:
            continue
        if item.get("implicit") and str(item["resource_id"]) in base_nodes and str(item["resource_id"]) not in {entry.resource_id for entry in lost}:
            impacts.append(DeletionImpact(resource_id=str(item["resource_id"]), resource_type=str(item["resource_type"]), relation=f"deleted_with:{item.get('via')}", depth=1, via=str(item.get("via") or "")))
    while queue:
        source, depth, via = queue.popleft()
        if depth >= 10:
            continue
        for edge in base_graph.edges:
            rel = str(_v(edge, "relationship", ""))
            if hasattr(_v(edge, "relationship", ""), "value"):
                rel = _v(edge, "relationship").value
            direction = DEPENDENCY_EDGES.get(rel)
            target = str(_v(edge, "dst")); origin = str(_v(edge, "src"))
            dependent = origin if direction == "source_depends_on_target" and target == source else target if direction == "target_depends_on_source" and origin == source else None
            if dependent and dependent in final_ids and dependent not in seen:
                seen.add(dependent)
                node = base_nodes.get(dependent)
                impacts.append(DeletionImpact(resource_id=dependent, resource_type=str(_v(node, "resource_type", _v(node, "type", ""))), relation=rel, depth=depth + 1, via=source))
                queue.append((dependent, depth + 1, dependent))
    # A deleted node itself is not an impact; implicit resources are intentionally retained above.
    impacts = sorted(impacts, key=lambda x: (x.depth, x.resource_id, x.relation))
    statuses = _v(base, "collection", {}) or {}
    can = sorted(k for k, v in statuses.items() if v == "ok" and k in _COLLECTION_KEYS)
    cannot = sorted(_FIXED_CANNOT_SEE | {k for k, v in statuses.items() if v != "ok" and k in _COLLECTION_KEYS})
    deleted_resource_ids = {str(x.get("resource_id")) for x in ledger}
    for item in scoped:
        status = _v(item, "status")
        if status in {"denied", "error"} and _v(item, "used") is None:
            resource_id = str(_v(item, "resource_id"))
            reason = "access denied" if status == "denied" else "read error"
            entry = f"recent use of {resource_id}: could not check ({reason})"
            if entry not in cannot:
                cannot.append(entry)
    for source in ("cloudtrail_events", "cloudwatch_metrics"):
        in_scope = deleted_resource_ids if source == "cloudtrail_events" else {
            str(x.get("resource_id")) for x in ledger if str(x.get("resource_type")) in METRIC_SPECS
        }
        if not in_scope:
            continue
        records = {
            str(_v(item, "resource_id")): item
            for item in scoped if _v(item, "source") == source and str(_v(item, "resource_id")) in in_scope
        }
        if len(records) == len(in_scope) and all(
            _v(records[rid], "status") == "ok"
            or (_v(records[rid], "status") == "no_data" and str(_v(records[rid], "resource_type")) != "s3_bucket")
            for rid in in_scope
        ):
            if source in cannot:
                cannot.remove(source)
            if source not in can:
                can.append(source)
    can = sorted(can)
    cannot = sorted(cannot)
    return DeletionLens(data_lost=lost, recovery_points=sorted(recovery, key=lambda x: (x.resource_id, x.kind)), impacts=impacts, max_depth=max((x.depth for x in impacts), default=0), coverage=DeletionCoverage(can_see=can, cannot_see=cannot), in_use_evidence=scoped)


def deleted_ids(lens: DeletionLens, branch: Any) -> set[str]:
    return {str(x.get("resource_id")) for x in deletion_ledger(branch)}


def _deleted_role_usage_codes(base: Any, branch: Any) -> set[str]:
    collection = _v(base, "collection", {}) or {}
    status_ok = collection.get("iam_role_last_used") == "ok"
    roles = {
        str(_v(role, "role_arn", "")): role
        for role in (_v(_v(base, "iam", {}), "role_policies", []) or [])
    }
    codes: set[str] = set()
    for item in deletion_ledger(branch):
        if item.get("resource_type") != "iam_role":
            continue
        role = roles.get(str(item.get("resource_id")))
        if not status_ok or role is None:
            codes.add("usage_unknown")
            continue
        value = _v(role, "last_used_at", None)
        if isinstance(value, str) and value and _parse_time(value) is None:
            codes.add("usage_unknown")
        elif value is not None and _parse_time(value) is None:
            codes.add("usage_unknown")
        elif value is not None:
            stamp = _parse_time(_v(base, "collected_at", None)) or datetime.now(timezone.utc)
            cutoff = stamp - timedelta(days=RECENT_USE_DAYS)
            if _parse_time(value) >= cutoff:
                codes.add("recently_used")
    return codes


def recently_used_deleted(base: Any, branch: Any) -> bool:
    """Return whether a deleted role was used within the recent-use window."""
    return "recently_used" in _deleted_role_usage_codes(base, branch)


def deleted_role_usage_unknown(base: Any, branch: Any) -> bool:
    """Return whether deleted-role last-used evidence is unavailable."""
    return "usage_unknown" in _deleted_role_usage_codes(base, branch)


def deleted_base_reachable(base: Any, branch: Any) -> bool:
    return bool(get_internet_reachable_set(build_graph(base)) & {str(x.get("resource_id")) for x in deletion_ledger(branch)})
