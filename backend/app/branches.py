"""Persistence-backed infrastructure simulation branches.

A branch stores one immutable base snapshot and an ordered list of ``Change``
models. Missing branch IDs raise ``BranchNotFoundError``; discarded branches
remain queryable but cannot accept new changes.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from app.database import BranchLog, SessionLocal
from app.diffing import DiffResult, diff_infrastructure
from app.egraph import build_graph
from app.models import AWSInfrastructure
from app.mutations import Change, apply_changes


MAX_OPEN_BRANCHES_PER_BASE = int(os.getenv("EMFIRGE_MAX_OPEN_BRANCHES", "10"))


class BranchNotFoundError(ValueError):
    """Raised when a requested branch does not exist."""


class BranchLimitError(ValueError):
    """Raised when a base analysis has reached its open-branch limit."""


class Branch(BaseModel):
    branch_id: str
    name: str
    base: AWSInfrastructure
    changes: list[Change] = Field(default_factory=list)
    status: str
    base_analysis_id: Optional[str] = None


class BranchSummary(BaseModel):
    branch_id: str
    name: str
    score_after: int
    score_delta: int
    added_nodes: int
    removed_nodes: int
    newly_internet_reachable: int
    no_longer_internet_reachable: int
    added_findings: int
    removed_findings: int
    has_privilege_escalation: bool


class ComparisonResult(BaseModel):
    base_analysis_id: Optional[str] = None
    branches: List[BranchSummary] = Field(default_factory=list)
    ranking: List[str] = Field(default_factory=list)
    has_mixed_bases: bool = False
    base_analysis_ids: List[Optional[str]] = Field(default_factory=list)


def _model_dump(value: Any) -> dict:
    if isinstance(value, AWSInfrastructure):
        return value.model_dump(mode="json")
    return AWSInfrastructure.model_validate(value).model_dump(mode="json")


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


def create_branch(base_infra: AWSInfrastructure | dict, name: str,
                  base_analysis_id: Optional[str] = None) -> str:
    """Create an open branch and return its UUID string."""
    base_json = json.dumps(_model_dump(base_infra), sort_keys=True, separators=(",", ":"))

    def operation(session):
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


def apply_change_to_branch(branch_id: str, change: Change | dict) -> Branch:
    """Append one validated change in order; only open branches are mutable."""
    change_model = Change.model_validate(change)

    def operation(session):
        row = _load_branch(session, branch_id)
        if row.status != 'open':
            raise ValueError(f"Branch is not open: {branch_id}")
        changes = json.loads(row.changes_json or '[]')
        changes.append(change_model.model_dump(mode='json'))
        row.changes_json = json.dumps(changes, sort_keys=True, separators=(",", ":"))
        return _decode(row)

    return _with_session(operation)


def rollback_last(branch_id: str) -> Branch:
    """Remove the most recent change; an empty change list is a safe no-op."""
    def operation(session):
        row = _load_branch(session, branch_id)
        changes = json.loads(row.changes_json or '[]')
        if changes:
            changes.pop()
            row.changes_json = json.dumps(changes, sort_keys=True, separators=(",", ":"))
        return _decode(row)

    return _with_session(operation)


def discard_branch(branch_id: str) -> Branch:
    """Soft-delete a branch by marking it discarded."""
    def operation(session):
        row = _load_branch(session, branch_id)
        row.status = 'discarded'
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
    return apply_changes(branch.base, branch.changes)


def get_branch_diff(branch_id: str) -> DiffResult:
    """Diff the immutable base snapshot against the current rebuilt state."""
    branch = get_branch(branch_id)
    rebuilt = apply_changes(branch.base, branch.changes)
    return diff_infrastructure(branch.base, rebuilt)


def compare_branches(branch_ids: List[str]) -> ComparisonResult:
    """Compare requested branches and rank them safest-first deterministically."""
    if not branch_ids:
        return ComparisonResult()

    summaries: list[BranchSummary] = []
    base_analysis_ids: list[Optional[str]] = []
    for branch_id in branch_ids:
        branch = get_branch(branch_id)
        diff = get_branch_diff(branch_id)
        rebuilt = rebuild_branch_infra(branch_id)
        graph = build_graph(rebuilt)
        has_privilege_escalation = any(
            node.resource_type == "iam_role"
            and node.base.get("has_privilege_escalation") is True
            for node in graph.nodes
        )
        base_analysis_ids.append(branch.base_analysis_id)
        summaries.append(BranchSummary(
            branch_id=branch.branch_id,
            name=branch.name,
            score_after=diff.score_after,
            score_delta=diff.score_delta,
            added_nodes=len(diff.added_nodes),
            removed_nodes=len(diff.removed_nodes),
            newly_internet_reachable=len(diff.newly_internet_reachable),
            no_longer_internet_reachable=len(diff.no_longer_internet_reachable),
            added_findings=len(diff.added_findings),
            removed_findings=len(diff.removed_findings),
            has_privilege_escalation=has_privilege_escalation,
        ))

    ranked = sorted(
        summaries,
        key=lambda summary: (
            -summary.score_after,
            summary.newly_internet_reachable,
            summary.name,
            summary.branch_id,
        ),
    )
    return ComparisonResult(
        base_analysis_id=base_analysis_ids[0],
        branches=summaries,
        ranking=[summary.branch_id for summary in ranked],
        has_mixed_bases=len(set(base_analysis_ids)) > 1,
        base_analysis_ids=base_analysis_ids,
    )
