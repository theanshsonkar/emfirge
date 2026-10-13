"""Persistence-backed infrastructure simulation branches.

A branch stores one immutable base snapshot and an ordered list of ``Change``
models. Missing branch IDs raise ``BranchNotFoundError``; discarded branches
remain queryable but cannot accept new changes.
"""

from __future__ import annotations

import json
import hashlib
import os
import uuid
from typing import Any, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app import cost
from app.database import BranchLog, PlanLog, SessionLocal
from app.diffing import DiffResult, diff_infrastructure, modeled_state_unchanged
from app.egraph import build_graph
from app.models import AWSInfrastructure


def save_plan(plan_id: str, branch_id: str, input_sha256: str, raw_input: str,
              branch_revision_after: str, rejected: list, unmodeled: list,
              unknown_fields: list) -> None:
    """Persist one raw plan and its ingest outcome."""
    def operation(session):
        session.add(PlanLog(
            plan_id=plan_id, branch_id=branch_id, input_sha256=input_sha256,
            raw_input=raw_input, branch_revision_after=branch_revision_after,
            rejected_json=json.dumps(rejected, separators=(",", ":")),
            unmodeled_json=json.dumps(unmodeled, separators=(",", ":")),
            unknown_fields_json=json.dumps(unknown_fields, separators=(",", ":")),
        ))
    _with_session(operation)


def get_plan(plan_id: str) -> dict | None:
    """Return the immutable persisted plan receipt, or ``None`` if unknown."""
    session = SessionLocal()
    try:
        row = session.query(PlanLog).filter(PlanLog.plan_id == plan_id).first()
        if row is None:
            return None
        return {
            "plan_id": row.plan_id,
            "branch_id": row.branch_id,
            "input_sha256": row.input_sha256,
            "raw_input": row.raw_input,
            "branch_revision_after": row.branch_revision_after,
        }
    except OperationalError:
        return None
    finally:
        session.close()


def list_plans(branch_id: str) -> list[dict]:
    session = SessionLocal()
    try:
        rows = session.query(PlanLog).filter(PlanLog.branch_id == branch_id).order_by(PlanLog.created_at, PlanLog.plan_id).all()
        return [{"plan_id": row.plan_id, "input_sha256": row.input_sha256,
                 "rejected": json.loads(row.rejected_json or "[]"),
                 "unmodeled": json.loads(row.unmodeled_json or "[]"),
                 "unknown_fields": json.loads(row.unknown_fields_json or "[]")} for row in rows]
    except OperationalError:
        return []
    finally:
        session.close()
from app.mutations import Change, apply_change, apply_changes


MAX_OPEN_BRANCHES_PER_BASE = int(os.getenv("EMFIRGE_MAX_OPEN_BRANCHES", "10"))


class BranchNotFoundError(ValueError):
    """Raised when a requested branch does not exist."""


class BranchLimitError(ValueError):
    """Raised when a base analysis has reached its open-branch limit."""


class BranchConflictError(ValueError):
    """Raised when an agent's branch view is stale or a concurrent write wins."""


class InvalidRollbackTargetError(ValueError):
    """Raised when a rollback target is outside the branch's current history."""


class Branch(BaseModel):
    branch_id: str
    name: str
    base: AWSInfrastructure
    changes: list[Change] = Field(default_factory=list)
    status: str
    base_analysis_id: Optional[str] = None
    last_change_modeled_state_unchanged: Optional[bool] = None


class BranchChangeRecord(BaseModel):
    """Normalized persisted mutation without request-only concurrency metadata."""

    op: str
    resource_type: str
    resource_id: str
    fields: dict[str, Any] = Field(default_factory=dict)


class BranchDetail(BaseModel):
    """Read-only branch metadata and ordered changes, excluding the base snapshot."""

    branch_id: str
    name: str
    status: str
    base_analysis_id: Optional[str] = None
    num_changes: int
    changes: list[BranchChangeRecord] = Field(default_factory=list)
    branch_revision: str


class BranchSummary(BaseModel):
    branch_id: str
    name: str
    branch_revision: str
    score_after: int
    score_delta: int
    added_nodes: int
    removed_nodes: int
    newly_internet_reachable: int
    no_longer_internet_reachable: int
    added_findings: int
    removed_findings: int
    lost_dependencies: int = 0
    lost_connectivity: int = 0
    deletion_impacts: int = 0
    has_privilege_escalation: bool
    cost_delta: dict[str, Any] = Field(default_factory=dict)
    cost_delta_monthly_usd: float | None = None


class ComparisonResult(BaseModel):
    base_analysis_id: Optional[str] = None
    branches: List[BranchSummary] = Field(default_factory=list)
    ranking: List[str] = Field(default_factory=list)
    has_mixed_bases: bool = False
    base_analysis_ids: List[Optional[str]] = Field(default_factory=list)
    comparison_warnings: List[str] = Field(default_factory=list)


def _model_dump(value: Any) -> dict:
    if isinstance(value, AWSInfrastructure):
        return value.model_dump(mode="json")
    return AWSInfrastructure.model_validate(value).model_dump(mode="json")


def branch_revision(branch: Branch) -> str:
    """Fingerprint one loaded branch's normalized base and persisted changes."""
    normalized = {
        "base": _model_dump(branch.base),
        "changes": [
            change.model_dump(
                mode="json", exclude={"expected_change_count", "branch_revision"},
            )
            for change in branch.changes
        ],
    }
    payload = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_branch(session, branch_id: str) -> BranchLog:
    row = session.query(BranchLog).filter(BranchLog.branch_id == branch_id).first()
    if row is None:
        raise BranchNotFoundError(f"Branch not found: {branch_id}")
    return row


def _decode(row: BranchLog) -> Branch:
    base = AWSInfrastructure.model_validate(json.loads(row.base_infra_json))
    raw_changes = json.loads(row.changes_json or "[]")
    changes = [Change.model_validate(change) for change in raw_changes]
    return Branch(
        branch_id=row.branch_id,
        name=row.name,
        base=base,
        changes=changes,
        status=row.status,
        base_analysis_id=row.base_analysis_id,
    )


def _with_session(operation):
    session = SessionLocal()
    try:
        result = operation(session)
        session.commit()
        return result
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _lock_branch_quota(session, base_analysis_id: str) -> None:
    """Serialize quota check-and-insert in the database transaction.

    PostgreSQL uses a transaction-scoped advisory lock for this base ID. SQLite
    has no advisory locks, so an immediate write transaction serializes its
    database writers. These are the two database families supported by the
    backend and its tests; other dialects must choose a lock strategy explicitly.
    """
    dialect = session.bind.dialect.name
    if dialect == "postgresql":
        session.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED"))
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:base_analysis_id))"),
            {"base_analysis_id": base_analysis_id},
        )
    elif dialect == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError(
            f"Branch quota serialization is not supported for database dialect {dialect!r}"
        )


def create_branch(base_infra: AWSInfrastructure | dict, name: str,
                  base_analysis_id: Optional[str] = None) -> str:
    """Create an open branch and return its UUID string."""
    base_json = json.dumps(_model_dump(base_infra), sort_keys=True, separators=(",", ":"))

    def operation(session):
        if base_analysis_id is not None:
            _lock_branch_quota(session, base_analysis_id)
            open_count = session.query(BranchLog).filter(
                BranchLog.base_analysis_id == base_analysis_id,
                BranchLog.status == "open",
            ).count()
            if open_count >= MAX_OPEN_BRANCHES_PER_BASE:
                raise BranchLimitError(
                    f"Open branch limit ({MAX_OPEN_BRANCHES_PER_BASE}) reached for "
                    f"base_analysis_id={base_analysis_id!r}; currently {open_count} open branches"
                )
        branch_id = str(uuid.uuid4())
        session.add(BranchLog(
            branch_id=branch_id,
            name=name,
            base_analysis_id=base_analysis_id,
            base_infra_json=base_json,
            changes_json='[]',
            status='open',
        ))
        return branch_id

    return _with_session(operation)


def get_branch(branch_id: str) -> Branch:
    """Return a decoded branch view, including immutable base and changes."""
    session = SessionLocal()
    try:
        return _decode(_load_branch(session, branch_id))
    finally:
        session.close()


def read_branch(branch_id: str) -> BranchDetail:
    """Read safe branch metadata and its ordered normalized change log."""
    branch = get_branch(branch_id)
    changes = [
        BranchChangeRecord.model_validate(
            change.model_dump(mode="json", exclude={"expected_change_count"})
        )
        for change in branch.changes
    ]
    return BranchDetail(
        branch_id=branch.branch_id,
        name=branch.name,
        status=branch.status,
        base_analysis_id=branch.base_analysis_id,
        num_changes=len(changes),
        changes=changes,
        branch_revision=branch_revision(branch),
    )


def fork_branch(
    branch_id: str, name: str, expected_branch_revision: Optional[str] = None,
) -> tuple[str, int]:
    """Atomically copy an open branch's base and change log into a new branch."""
    # base_analysis_id is immutable. Resolve it before opening the write
    # transaction so the lock is acquired before that transaction's snapshot.
    quota_base_id = get_branch(branch_id).base_analysis_id

    def operation(session):
        if quota_base_id is not None:
            _lock_branch_quota(session, quota_base_id)
        parent = _load_branch(session, branch_id)
        if parent.status != "open":
            raise ValueError(f"Branch is not open: {branch_id}")
        base_analysis_id = parent.base_analysis_id
        parent_view = _decode(parent)
        if (expected_branch_revision is not None
                and expected_branch_revision != branch_revision(parent_view)):
            raise BranchConflictError("Branch revision is stale; reload the branch and retry")

        # Capture all copied columns before attempting the compare-and-swap.
        base_json = parent.base_infra_json
        changes_json = parent.changes_json or "[]"
        base_analysis_id = parent.base_analysis_id

        # Synchronize with append/rollback/discard, whose writes also compare
        # changes_json. A successful conditional update holds the row write
        # lock until the child insert commits, so the copied log is one instant.
        locked = session.query(BranchLog).filter(
            BranchLog.branch_id == branch_id,
            BranchLog.status == "open",
            BranchLog.base_infra_json == base_json,
            BranchLog.changes_json == changes_json,
        ).update(
            {BranchLog.changes_json: changes_json, BranchLog.updated_at: parent.updated_at},
            synchronize_session=False,
        )
        if locked != 1:
            raise BranchConflictError("Branch changed during fork; reload it and retry")

        if base_analysis_id is not None:
            open_count = session.query(BranchLog).filter(
                BranchLog.base_analysis_id == base_analysis_id,
                BranchLog.status == "open",
            ).count()
            if open_count >= MAX_OPEN_BRANCHES_PER_BASE:
                raise BranchLimitError(
                    f"Open branch limit ({MAX_OPEN_BRANCHES_PER_BASE}) reached for "
                    f"base_analysis_id={base_analysis_id!r}; currently {open_count} open branches"
                )

        child_id = str(uuid.uuid4())
        session.add(BranchLog(
            branch_id=child_id,
            name=name,
            base_analysis_id=base_analysis_id,
            base_infra_json=base_json,
            changes_json=changes_json,
            status="open",
        ))
        return child_id, len(json.loads(changes_json))

    return _with_session(operation)


def apply_change_to_branch(branch_id: str, change: Change | dict) -> Branch:
    """Append one validated change in order; only open branches are mutable."""
    change_model = Change.model_validate(change)

    def operation(session):
        row = _load_branch(session, branch_id)
        if row.status != 'open':
            raise ValueError(f"Branch is not open: {branch_id}")
        previous_json = row.changes_json or '[]'
        changes = json.loads(previous_json)
        persisted_branch = _decode(row)
        if (change_model.expected_change_count is not None
                and change_model.expected_change_count != len(changes)):
            raise BranchConflictError(
                f"Branch changed: expected {change_model.expected_change_count} change(s), "
                f"found {len(changes)}"
            )
        if (change_model.branch_revision is not None
                and change_model.branch_revision != branch_revision(persisted_branch)):
            raise BranchConflictError("Branch revision is stale; reload the branch and retry")
        base = AWSInfrastructure.model_validate(json.loads(row.base_infra_json))
        # Validate the candidate against the persisted state in this transaction.
        # API-side preflight is useful for early errors, but direct callers
        # must not be able to store an unrebuildable branch.
        before = apply_changes(base, [Change.model_validate(item) for item in changes])
        after = apply_change(before, change_model)
        changes.append(change_model.model_dump(
            mode='json', exclude={'expected_change_count', 'branch_revision'},
        ))
        next_json = json.dumps(changes, sort_keys=True, separators=(",", ":"))
        updated = session.query(BranchLog).filter(
            BranchLog.branch_id == branch_id,
            BranchLog.status == 'open',
            BranchLog.changes_json == previous_json,
        ).update({BranchLog.changes_json: next_json}, synchronize_session=False)
        if updated != 1:
            raise BranchConflictError("Branch changed during append; reload it and retry")
        session.expire(row)
        branch = _decode(row)
        branch.last_change_modeled_state_unchanged = modeled_state_unchanged(before, after)
        return branch

    return _with_session(operation)


def rollback_last(
    branch_id: str,
    expected_change_count: Optional[int] = None,
    expected_branch_revision: Optional[str] = None,
) -> Branch:
    """Remove the most recent change; an empty change list is a safe no-op."""
    def operation(session):
        row = _load_branch(session, branch_id)
        if row.status != 'open':
            raise ValueError(f"Branch is not open: {branch_id}")
        previous_json = row.changes_json or '[]'
        changes = json.loads(previous_json)
        if expected_change_count is not None and expected_change_count != len(changes):
            raise BranchConflictError(
                f"Branch changed: expected {expected_change_count} change(s), found {len(changes)}"
            )
        if (expected_branch_revision is not None
                and expected_branch_revision != branch_revision(_decode(row))):
            raise BranchConflictError("Branch revision is stale; reload the branch and retry")
        if changes:
            changes.pop()
            next_json = json.dumps(changes, sort_keys=True, separators=(",", ":"))
            updated = session.query(BranchLog).filter(
                BranchLog.branch_id == branch_id,
                BranchLog.status == 'open',
                BranchLog.changes_json == previous_json,
            ).update({BranchLog.changes_json: next_json}, synchronize_session=False)
            if updated != 1:
                raise BranchConflictError("Branch changed during rollback; reload it and retry")
            session.expire(row)
        elif expected_branch_revision is not None:
            confirmed = session.query(BranchLog).filter(
                BranchLog.branch_id == branch_id,
                BranchLog.status == 'open',
                BranchLog.changes_json == previous_json,
            ).update(
                {BranchLog.changes_json: previous_json, BranchLog.updated_at: row.updated_at},
                synchronize_session=False,
            )
            if confirmed != 1:
                raise BranchConflictError("Branch changed during rollback; reload it and retry")
        return _decode(row)

    return _with_session(operation)


def rollback_to_change_count(
    branch_id: str,
    target_change_count: int,
    expected_branch_revision: Optional[str] = None,
) -> Branch:
    """Truncate an open branch's ordered change log to an existing count.

    The observed revision and previous JSON are checked in the same transaction
    as a conditional update so an append cannot be silently erased.
    """
    if type(target_change_count) is not int or target_change_count < 0:
        raise InvalidRollbackTargetError("target_change_count must be a non-negative integer")

    def operation(session):
        row = _load_branch(session, branch_id)
        if row.status != 'open':
            raise ValueError(f"Branch is not open: {branch_id}")
        previous_json = row.changes_json or '[]'
        changes = json.loads(previous_json)
        current_count = len(changes)
        if target_change_count > current_count:
            raise InvalidRollbackTargetError(
                f"target_change_count must be between 0 and {current_count}"
            )
        if (expected_branch_revision is not None
                and expected_branch_revision != branch_revision(_decode(row))):
            raise BranchConflictError("Branch revision is stale; reload the branch and retry")

        next_json = json.dumps(changes[:target_change_count], sort_keys=True, separators=(",", ":"))
        updated = session.query(BranchLog).filter(
            BranchLog.branch_id == branch_id,
            BranchLog.status == 'open',
            BranchLog.changes_json == previous_json,
        ).update({BranchLog.changes_json: next_json}, synchronize_session=False)
        if updated != 1:
            raise BranchConflictError("Branch changed during rollback; reload it and retry")
        session.expire(row)
        return _decode(row)

    return _with_session(operation)


def discard_branch(
    branch_id: str,
    expected_change_count: Optional[int] = None,
    expected_branch_revision: Optional[str] = None,
) -> Branch:
    """Discard an open branch, optionally guarding the observed change count."""
    def operation(session):
        row = _load_branch(session, branch_id)
        previous_json = row.changes_json or '[]'
        changes = json.loads(previous_json)
        if expected_change_count is not None and expected_change_count != len(changes):
            raise BranchConflictError(
                f"Branch changed: expected {expected_change_count} change(s), found {len(changes)}"
            )
        if (expected_branch_revision is not None
                and expected_branch_revision != branch_revision(_decode(row))):
            raise BranchConflictError("Branch revision is stale; reload the branch and retry")
        if row.status != 'open':
            if expected_change_count is None and row.status == 'discarded':
                return _decode(row)
            raise BranchConflictError(f"Branch is not open: {branch_id}")
        updated = session.query(BranchLog).filter(
            BranchLog.branch_id == branch_id,
            BranchLog.status == 'open',
            BranchLog.changes_json == previous_json,
        ).update({BranchLog.status: 'discarded'}, synchronize_session=False)
        if updated != 1:
            raise BranchConflictError("Branch changed during discard; reload it and retry")
        session.expire(row)
        return _decode(row)

    return _with_session(operation)


def list_branches(base_analysis_id: Optional[str] = None) -> list[Branch]:
    """List branches, optionally restricted to one base analysis."""
    session = SessionLocal()
    try:
        query = session.query(BranchLog)
        if base_analysis_id is not None:
            query = query.filter(BranchLog.base_analysis_id == base_analysis_id)
        return [_decode(row) for row in query.order_by(BranchLog.created_at, BranchLog.branch_id).all()]
    finally:
        session.close()


def rebuild_branch_infra(branch_id: str) -> AWSInfrastructure:
    """Rebuild a fresh infrastructure model from base plus ordered changes."""
    branch = get_branch(branch_id)
    return rebuild_branch_state(branch)


def rebuild_branch_state(branch: Branch) -> AWSInfrastructure:
    """Rebuild from one already-loaded branch snapshot without rereading storage."""
    return apply_changes(branch.base, branch.changes)


def get_branch_diff(branch_id: str) -> DiffResult:
    """Diff the immutable base snapshot against the current rebuilt state."""
    branch = get_branch(branch_id)
    rebuilt = rebuild_branch_state(branch)
    diff = diff_infrastructure(branch.base, rebuilt)
    return diff.model_copy(update={"branch_revision": branch_revision(branch)})


def compare_branches(branch_ids: List[str]) -> ComparisonResult:
    """Compare requested branches and rank them safest-first deterministically."""
    if not branch_ids:
        return ComparisonResult()

    summaries: list[BranchSummary] = []
    base_analysis_ids: list[Optional[str]] = []
    base_snapshots: list[str] = []
    for branch_id in branch_ids:
        branch = get_branch(branch_id)
        rebuilt = rebuild_branch_state(branch)
        diff = diff_infrastructure(branch.base, rebuilt)
        graph = build_graph(rebuilt)
        has_privilege_escalation = any(
            node.resource_type == "iam_role"
            and node.base.get("has_privilege_escalation") is True
            for node in graph.nodes
        )
        base_analysis_ids.append(branch.base_analysis_id)
        base_snapshots.append(json.dumps(_model_dump(branch.base), sort_keys=True, separators=(",", ":")))
        cost_result = cost.cost_delta(branch.base, rebuilt)
        summaries.append(BranchSummary(
            branch_id=branch.branch_id,
            name=branch.name,
            branch_revision=branch_revision(branch),
            score_after=diff.score_after,
            score_delta=diff.score_delta,
            added_nodes=len(diff.added_nodes),
            removed_nodes=len(diff.removed_nodes),
            newly_internet_reachable=len(diff.newly_internet_reachable),
            no_longer_internet_reachable=len(diff.no_longer_internet_reachable),
            added_findings=len(diff.added_findings),
            removed_findings=len(diff.removed_findings),
            lost_dependencies=len(diff.lost_dependencies),
            lost_connectivity=len(diff.lost_connectivity),
            deletion_impacts=len(diff.deletion_impacts),
            has_privilege_escalation=has_privilege_escalation,
            cost_delta=cost_result.model_dump(mode="json"),
            cost_delta_monthly_usd=cost_result.value,
        ))

    mixed_bases = len(set(base_analysis_ids)) > 1 or len(set(base_snapshots)) > 1
    ranked = sorted(
        summaries,
        key=lambda summary: (
            # Unknown cost is never treated as zero; known estimates rank first.
            summary.cost_delta_monthly_usd is None,
            bool(summary.lost_dependencies),
            bool(summary.lost_connectivity),
            bool(summary.deletion_impacts),
            # A security score can improve when ingress is cut off. Rank a
            # branch preserving modeled external paths ahead of one that loses
            # them, while leaving the security score visible in each summary.
            summary.no_longer_internet_reachable,
            bool(summary.newly_internet_reachable),
            -summary.score_after,
            summary.name,
            summary.branch_id,
        ),
    )
    return ComparisonResult(
        base_analysis_id=base_analysis_ids[0],
        branches=summaries,
        ranking=[] if mixed_bases else [summary.branch_id for summary in ranked],
        has_mixed_bases=mixed_bases,
        base_analysis_ids=base_analysis_ids,
        comparison_warnings=(
            ["Branches have different base snapshots or analysis IDs; ranking is unavailable"]
            if mixed_bases else []
        ),
    )
