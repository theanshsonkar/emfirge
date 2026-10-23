"""Opt-in provider policy checks: which policies to check, and how results change a verdict.

Cloud-neutral shape: the evidence record says "the provider answered public /
not_public / unknown for this policy, the local logic answered X".  Calling the
provider lives in app.aws_policy_checks.  Provider evidence can only make a
verdict stricter, never more lenient; disagreements are reported as notes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy.exc import OperationalError

from app.database import BranchPolicyCheckLog, SessionLocal
from app.s3_public import effective_is_public, policy_is_public
from app.trust_policy import external_trust

MAX_POLICIES = 50
PRICE_PER_CALL_USD = 0.002  # about; AWS pricing page example, see PRICING_URL
PRICING_URL = "https://aws.amazon.com/iam/access-analyzer/pricing/"
SOURCE = "aws_access_analyzer"
AWS_TYPES = {"s3_bucket": "AWS::S3::Bucket", "iam_role": "AWS::IAM::AssumeRolePolicyDocument"}
NOT_RUN_NOTE = "AWS policy check not run; local logic used"


class PolicyRef(BaseModel):
    resource_type: str
    resource_id: str
    side: Literal["base", "branch"]
    aws_resource_type: str
    policy_sha256: str
    local_answer: Literal["public", "not_public"]
    document: str = Field(default="", exclude=True)


class PolicyEvidenceRecord(BaseModel):
    resource_type: str
    resource_id: str
    side: Literal["base", "branch"]
    provider_answer: Literal["public", "not_public", "unknown"]
    local_answer: Literal["public", "not_public"]
    source: str = SOURCE
    checked_at: str
    status: str = "ok"  # ok | denied | throttled | invalid | error
    reasons: list[str] = Field(default_factory=list)
    branch_revision: str = ""


class PolicyCheckEstimate(BaseModel):
    estimate_id: str
    branch_revision: str
    policies: list[PolicyRef]
    call_count: int
    price_per_call_usd: float
    approximate_cost_usd: float
    pricing_url: str
    aws_calls_made: int = 0
    notes: list[str] = Field(default_factory=list)
    max_policies: int = MAX_POLICIES


def _norm(policy: Any) -> str:
    try:
        doc = json.loads(policy) if isinstance(policy, str) else policy
        return json.dumps(doc, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(policy)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _bucket_local(policy: str) -> str:
    try:
        return "public" if policy_is_public(policy) else "not_public"
    except ValueError:
        return "public"  # unreadable policy: fail closed, like the local rules


def _trust_docs(branch_infra: Any, changes: list) -> dict[str, Any]:
    """Latest trust policy per role from the branch's own add/modify changes.

    The snapshot keeps only parsed trust flags, not the base trust document, so
    only branch-side trust policies can be sent for checking.
    """
    roles = {p.role_arn: p for p in branch_infra.iam.role_policies}
    docs: dict[str, Any] = {}
    for change in changes:
        if getattr(change, "resource_type", "") != "iam_role":
            continue
        rid = getattr(change, "resource_id", "")
        arn = next((a for a, p in roles.items() if a == rid or p.role_name == rid), None)
        if arn is None and getattr(change, "op", "") == "add" and rid.startswith("arn:"):
            arn = rid
        if getattr(change, "op", "") == "delete" and arn:
            docs.pop(arn, None)
        elif arn and "trust_policy" in (getattr(change, "fields", None) or {}):
            docs[arn] = change.fields["trust_policy"]
    return {a: d for a, d in docs.items() if a in roles}


def policies_to_check(base: Any, branch_infra: Any, changes: list) -> tuple[list[PolicyRef], list[str]]:
    refs: list[PolicyRef] = []
    base_buckets = {b.name: b for b in base.s3.buckets}
    for bucket in sorted(branch_infra.s3.buckets, key=lambda b: b.name):
        if not bucket.policy:
            continue
        before = base_buckets.get(bucket.name)
        if before is not None and before.policy and _norm(before.policy) == _norm(bucket.policy):
            continue
        for side, item in (("base", before), ("branch", bucket)):
            if item is not None and item.policy:
                refs.append(PolicyRef(resource_type="s3_bucket", resource_id=item.name, side=side, aws_resource_type=AWS_TYPES["s3_bucket"], policy_sha256=_sha(_norm(item.policy)), local_answer=_bucket_local(item.policy), document=item.policy))
    for arn, doc in sorted(_trust_docs(branch_infra, changes).items()):
        text = doc if isinstance(doc, str) else json.dumps(doc)
        try:
            local = "public" if external_trust(doc, arn)[1] else "not_public"
        except Exception:
            local = "public"
        refs.append(PolicyRef(resource_type="iam_role", resource_id=arn, side="branch", aws_resource_type=AWS_TYPES["iam_role"], policy_sha256=_sha(_norm(text)), local_answer=local, document=text))
    notes = []
    if any(r.resource_type == "iam_role" for r in refs):
        notes.append("Role trust policies: only the branch side is checked; the scanned snapshot does not keep the base trust policy text.")
    return refs, notes


def build_estimate(base: Any, branch_infra: Any, changes: list, branch_revision: str) -> PolicyCheckEstimate:
    refs, notes = policies_to_check(base, branch_infra, changes)
    payload = {"revision": branch_revision, "policies": [[r.resource_type, r.resource_id, r.side, r.policy_sha256] for r in refs]}
    estimate_id = _sha(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return PolicyCheckEstimate(estimate_id=estimate_id, branch_revision=branch_revision, policies=refs, call_count=len(refs), price_per_call_usd=PRICE_PER_CALL_USD, approximate_cost_usd=round(len(refs) * PRICE_PER_CALL_USD, 4), pricing_url=PRICING_URL, notes=notes)


# Storage: own table; results are bound to the branch revision they were run on.

def save_policy_evidence(branch_id: str, branch_revision: str, estimate_id: str, records: list[PolicyEvidenceRecord]) -> None:
    session = SessionLocal()
    try:
        session.add(BranchPolicyCheckLog(branch_id=branch_id, branch_revision=branch_revision, estimate_id=estimate_id, records_json=json.dumps([r.model_dump(mode="json") for r in records], separators=(",", ":"))))
        session.commit()
    finally:
        session.close()


def list_policy_evidence(branch_id: str, branch_revision: str) -> tuple[list[PolicyEvidenceRecord], bool]:
    """Latest record per policy for this revision, and whether older-revision results were ignored."""
    session = SessionLocal()
    try:
        rows = session.query(BranchPolicyCheckLog).filter(BranchPolicyCheckLog.branch_id == branch_id).order_by(BranchPolicyCheckLog.created_at, BranchPolicyCheckLog.id).all()
    except OperationalError:
        return [], False
    finally:
        session.close()
    latest: dict[tuple, PolicyEvidenceRecord] = {}
    stale = False
    for row in rows:
        if row.branch_revision != branch_revision:
            stale = True
            continue
        for item in json.loads(row.records_json or "[]"):
            rec = PolicyEvidenceRecord.model_validate(item)
            latest[(rec.resource_type, rec.resource_id, rec.side)] = rec
    return list(latest.values()), stale


def apply_policy_evidence(base: Any, branch_infra: Any, changes: list, records: list[PolicyEvidenceRecord], stale: bool = False) -> list[str]:
    """Make branch_infra stricter where the provider says public; return coverage notes."""
    refs, _ = policies_to_check(base, branch_infra, changes)
    if not refs:
        return []
    notes: list[str] = []
    if not records:
        if stale:
            notes.append("AWS policy check results are for an older branch revision and were ignored")
        return notes + [NOT_RUN_NOTE]
    by_key = {(r.resource_type, r.resource_id, r.side): r for r in records}
    buckets = {b.name: b for b in branch_infra.s3.buckets}
    roles = {p.role_arn: p for p in branch_infra.iam.role_policies}
    for ref in refs:
        rec = by_key.get((ref.resource_type, ref.resource_id, ref.side))
        label = f"{ref.resource_type} {ref.resource_id}" + (" (base)" if ref.side == "base" else "")
        if rec is None or rec.provider_answer == "unknown":
            if ref.side == "branch":
                why = f" ({rec.status})" if rec is not None else ""
                notes.append(f"AWS policy check for {label} did not complete{why}; local logic used")
            continue
        if rec.provider_answer == "public" and ref.local_answer == "not_public":
            notes.append(f"AWS Access Analyzer reports {label} public; local logic disagreed")
            if ref.side != "branch":
                continue
            if ref.resource_type == "s3_bucket" and ref.resource_id in buckets:
                b = buckets[ref.resource_id]
                b.policy_public = True
                b.is_public = effective_is_public(b.acl_public, True, b.ignore_public_acls, b.restrict_public_buckets)
                branch_infra.s3.public_buckets = [x.name for x in branch_infra.s3.buckets if x.is_public]
            elif ref.resource_type == "iam_role" and ref.resource_id in roles:
                roles[ref.resource_id].trust_allows_external = True
                roles[ref.resource_id].trust_external_unrestricted = True
        elif rec.provider_answer == "not_public" and ref.local_answer == "public":
            notes.append(f"AWS Access Analyzer reports {label} not public; local logic reports public and was kept (stricter)")
    return notes


def verdict_inputs(branch_id: str, branch: Any, rebuilt: Any, revision: str) -> list[str]:
    """Apply stored policy evidence for the current revision to `rebuilt`; return notes."""
    records, stale = list_policy_evidence(branch_id, revision)
    return apply_policy_evidence(branch.base, rebuilt, branch.changes, records, stale)
