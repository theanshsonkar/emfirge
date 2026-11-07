"""Sequence-aware deletion analysis for branch verdicts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.egraph import build_graph, build_graph_pair, dependency_closure, get_internet_reachable_set
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
class RecoveryUnknown(BaseModel):
    """A deleted data store whose data loss cannot be judged: what it holds or what recovers it is not known."""
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
    recovery_unknown: list[RecoveryUnknown] = Field(default_factory=list)
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

DATA_STORE_TYPES = frozenset({"s3_bucket", "rds_instance", "ebs_volume", "dynamodb_table"})

# Provider documentation the DynamoDB judgment rests on.
DYNAMODB_ITEM_COUNT_URL = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html"
DYNAMODB_SYSTEM_BACKUP_URL = "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html"

# why codes of RecoveryUnknown
HOLDS_DATA_UNKNOWN = "holds_data_unknown"
RECOVERY_SOURCE_UNKNOWN = "recovery_source_unknown"


def _table_recovery(rid: str, before: dict) -> tuple[RecoveryPoint | None, str | None]:
    """DynamoDB table: (recovery point, why unknown).

    * an AVAILABLE on-demand backup restores the table after it is gone (Restore.Tutorial);
    * with point-in-time recovery on, DeleteTable makes a system backup kept 35 days
      (PointInTimeRecovery_Howitworks, BackupSummary BackupType SYSTEM);
    * ItemCount 0 is "reported empty": AWS refreshes ItemCount about every six hours
      (TableDescription), so the data answer carries that as a caveat.
    Nothing known to recover and a count that is None (not reported) is unknown, not empty;
    items but an unreadable PITR / backup source is unknown, not lost.
    """
    if before.get("has_backup") is True:
        return RecoveryPoint(resource_id=rid, kind="dynamodb_backup", source_id=rid), None
    if before.get("pitr_enabled") is True:
        return RecoveryPoint(resource_id=rid, kind="dynamodb_system_backup", source_id=rid), None
    count = before.get("item_count")
    if count == 0 and before.get("item_count_reported") is True:
        return RecoveryPoint(resource_id=rid, kind="reported_empty_table", source_id=rid), None
    if count is None or count == 0:
        # None: not reported. 0 without the marker: an older scan stored a missing count as 0.
        return None, HOLDS_DATA_UNKNOWN
    if before.get("has_backup") is None or before.get("pitr_enabled") is None:
        return None, RECOVERY_SOURCE_UNKNOWN
    return None, None


def recovery_assessment(typ: str, rid: str, before: Any, options: Any, rds_snapshots: Any, ebs_snapshots: Any) -> tuple[RecoveryPoint | None, str | None]:
    """(recovery point that survives deleting ``rid``, why that is unknown). Both None: data is lost."""
    if typ == "dynamodb_table":
        return _table_recovery(rid, before or {})
    return recovery_point_for(typ, rid, before, options, rds_snapshots, ebs_snapshots), None


def recovery_point_for(typ: str, rid: str, before: Any, options: Any, rds_snapshots: Any, ebs_snapshots: Any) -> RecoveryPoint | None:
    """The recovery point that survives deleting ``rid``, or None.

    ``before`` is the resource state, ``options`` the delete options (defaults
    when empty), the snapshot lists are the snapshots that exist. One truth for
    the deletion lens and the context query's ``data`` question.
    """
    before = before or {}
    options = options or {}
    if typ == "dynamodb_table":
        return _table_recovery(rid, before)[0]
    if typ == "s3_bucket":
        if before.get("is_empty") is True:
            return RecoveryPoint(resource_id=rid, kind="empty_bucket", source_id=rid)
    elif typ == "rds_instance":
        final_id = options.get("final_db_snapshot_identifier")
        snap = next((s for s in rds_snapshots if str(_v(s, "id")) == str(final_id) and _v(s, "status") == "available"), None) if final_id else None
        snap = snap or next((s for s in rds_snapshots if str(_v(s, "db_instance_id")) == rid and _v(s, "status") == "available"), None)
        retained = options.get("delete_automated_backups") is False and int(before.get("backup_retention_days") or 0) > 0
        if snap:
            return RecoveryPoint(resource_id=rid, kind="rds_snapshot", source_id=str(_v(snap, "id")))
        if retained:
            return RecoveryPoint(resource_id=rid, kind="automated_backup", source_id=rid)
    elif typ == "ebs_volume":
        snap = next((s for s in ebs_snapshots if str(_v(s, "volume_id")) == rid and _v(s, "state") == "completed"), None)
        if snap:
            return RecoveryPoint(resource_id=rid, kind="ebs_snapshot", source_id=str(_v(snap, "id")))
    return None


def analyze_deletions(base: Any, branch: Any, evidence=None) -> DeletionLens:
    evidence = evidence or []
    ledger = deletion_ledger(branch)
    base_graph, final_graph = build_graph_pair(base, branch)
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
    unknown_recovery: list[RecoveryUnknown] = []
    for item in deleted:
        rid, typ = str(item["resource_id"]), str(item["resource_type"])
        before = item.get("state_before") or {}
        options = item.get("options") or {}
        point, unknown_why = recovery_assessment(typ, rid, before, options, snapshots_rds, snapshots_ebs)
        recovered = point is not None
        if point is not None:
            recovery.append(point)
        if typ in DATA_STORE_TYPES and not recovered and unknown_why is not None:
            unknown_recovery.append(RecoveryUnknown(resource_id=rid, resource_type=typ, why=unknown_why))
        elif typ in DATA_STORE_TYPES and not recovered:
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
    for item in ledger:
        if item.get("implicit") and str(item["resource_id"]) in final_ids:
            continue
        if item.get("implicit") and str(item["resource_id"]) in base_nodes and str(item["resource_id"]) not in {entry.resource_id for entry in lost}:
            impacts.append(DeletionImpact(resource_id=str(item["resource_id"]), resource_type=str(item["resource_type"]), relation=f"deleted_with:{item.get('via')}", depth=1, via=str(item.get("via") or "")))
    for step in dependency_closure(base_graph, sorted(deleted_ids), direction="dependents", max_depth=10, allowed=final_ids):
        node = base_nodes.get(step.node_id)
        impacts.append(DeletionImpact(resource_id=step.node_id, resource_type=str(_v(node, "resource_type", _v(node, "type", ""))), relation=step.relationship, depth=step.depth, via=step.via))
    # A deleted node itself is not an impact; implicit resources are intentionally retained above.
    impacts = sorted(impacts, key=lambda x: (x.depth, x.resource_id, x.relation))
    statuses = _v(base, "collection", {}) or {}
    can = sorted(k for k, v in statuses.items() if v == "ok" and k in _COLLECTION_KEYS)
    cannot = sorted(_FIXED_CANNOT_SEE | {k for k, v in statuses.items() if v != "ok" and k in _COLLECTION_KEYS})
    deleted_resource_ids = {str(x.get("resource_id")) for x in ledger}
    for item in scoped:
        status = _v(item, "status")
        if status in {"denied", "error", "incomplete", "unknown"} and _v(item, "used") is None:
            resource_id = str(_v(item, "resource_id"))
            reason = "access denied" if status == "denied" else "read error" if status == "error" else "incomplete history"
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
    return DeletionLens(data_lost=lost, recovery_points=sorted(recovery, key=lambda x: (x.resource_id, x.kind)), recovery_unknown=unknown_recovery, impacts=impacts, max_depth=max((x.depth for x in impacts), default=0), coverage=DeletionCoverage(can_see=can, cannot_see=cannot), in_use_evidence=scoped)


def deleted_ids(lens: DeletionLens, branch: Any) -> set[str]:
    return {str(x.get("resource_id")) for x in deletion_ledger(branch)}


def role_recent_use(base: Any, role: Any, reference: datetime | None) -> bool | None:
    """Whether an IAM role was used within RECENT_USE_DAYS of ``reference``; None when unknown.

    None covers: last-used collection not ok, no such role, an unparseable
    timestamp, or no reference time. A readable "never used" is False.
    """
    collection = _v(base, "collection", {}) or {}
    if collection.get("iam_role_last_used") != "ok" or role is None:
        return None
    value = _v(role, "last_used_at", None)
    if value is None:
        return False
    stamp = _parse_time(value)
    if stamp is None or reference is None:
        return None
    return stamp >= reference - timedelta(days=RECENT_USE_DAYS)


def _deleted_role_usage_codes(base: Any, branch: Any) -> set[str]:
    roles = {
        str(_v(role, "role_arn", "")): role
        for role in (_v(_v(base, "iam", {}), "role_policies", []) or [])
    }
    reference = _parse_time(_v(base, "collected_at", None)) or datetime.now(timezone.utc)
    codes: set[str] = set()
    for item in deletion_ledger(branch):
        if item.get("resource_type") != "iam_role":
            continue
        used = role_recent_use(base, roles.get(str(item.get("resource_id"))), reference)
        if used is None:
            codes.add("usage_unknown")
        elif used:
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
