"""AWS adapter for the check.

Turns the AWS-specific parts of a branch into the neutral ``CheckInputs`` that
the cloud-neutral core (``check_facts``) assembles with the verdict. Every AWS
truth is reused from where it already lives, never re-derived:

  * the verdict                verdict.combined_verdict (delete lens, exposure, cost, lost dependencies)
  * recovery points removed    verdict.recovery_removals
  * introduced escalation      verdict.introduced_privilege_escalation_ids
  * role last-used             aws_context.role_use_lines (the delete lens's own role_recent_use)
  * baseline (no changes)      aws_context.answer_for_infra
  * outside-world services     aws_outside_world

What this module adds is the reading of a few modeled fields the diff does not
carry as facts yet (admin access, logging, public buckets, role trust, account
settings). Read-only: no AWS call, no database access.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from app.aws_context import answer_for_infra, node_id_for, role_use_lines, safe_warning
from app.aws_outside_world import classify_action
from app.aws_permissions import (
    NOTE_ACTION_CATALOG, NOTE_APP_CODE, NOTE_MANAGED_NOT_RECORDED, compute_users, role_node_id, role_node_ids,
    role_permission_diff, statements_differ,
)
from app.check_facts import ChangeLine, CheckInputs, CheckResult, PermissionChange, PlanGap, assemble, is_unchanged
from app.cost import PRICE_TABLE_AS_OF, PRICE_TABLE_REGION
from app.egraph import Graph, build_graph_pair
from app.evidence_models import EvidenceRecord
from app.models import AWSInfrastructure
from app.verdict import CombinedVerdict, combined_verdict, introduced_privilege_escalation_ids, recovery_removals

# Collection sources (infra.collection keys) each damage depends on.
DAMAGE_SOURCES: dict[str, tuple[str, ...]] = {
    "data": ("ebs_snapshots", "ebs_volumes", "rds_snapshots"),
    "exposure": ("network_interfaces",),
    "money": ("ebs_volumes",),
    "availability": ("iam_role_last_used", "network_interfaces"),
    "control": (),
}
ACCOUNT_SETTINGS = ("cloudtrail", "guardduty", "kms", "config")


def _role_ids(graph: Graph) -> dict[str, str]:
    return {str(node.base.get("arn")): node.id for node in graph.find_nodes_by_type("iam_role") if node.base.get("arn")}


def _role_id(arn: str, name: str, ids: Mapping[str, str]) -> str:
    return ids.get(arn) or f"iam-role-{name}"


def _external(role: Any) -> bool:
    return bool(role.trust_allows_external or getattr(role, "trust_external_unrestricted", False))


def _role_lines(base: AWSInfrastructure, branch: AWSInfrastructure, base_graph: Graph, branch_graph: Graph
                ) -> tuple[list[ChangeLine], list[ChangeLine]]:
    """(control lines for admin access, exposure lines for external trust) between base and branch roles."""
    base_ids, branch_ids = _role_ids(base_graph), _role_ids(branch_graph)
    old = {r.role_arn: r for r in base.iam.role_policies}
    new = {r.role_arn: r for r in branch.iam.role_policies}
    control: list[ChangeLine] = []
    exposure: list[ChangeLine] = []
    for arn in sorted(set(old) | set(new)):
        before, after = old.get(arn), new.get(arn)
        rid = _role_id(arn, (after or before).role_name, branch_ids if after else base_ids)
        was_admin, is_admin = bool(before and before.has_admin), bool(after and after.has_admin)
        if was_admin and not is_admin:
            control.append(ChangeLine(rid, "iam_role", "admin_access_removed"))
        elif is_admin and not was_admin:
            control.append(ChangeLine(rid, "iam_role", "admin_access_added"))
        was_external, is_external = bool(before and _external(before)), bool(after and _external(after))
        if is_external and not was_external:
            exposure.append(ChangeLine(rid, "iam_role", "newly_trusts_external_account", "external_trust"))
        elif was_external and not is_external:
            exposure.append(ChangeLine(rid, "iam_role", "no_longer_trusts_external_account", "external_trust"))
    return control, exposure


def _permission_inputs(base: AWSInfrastructure, branch: AWSInfrastructure, base_graph: Graph, branch_graph: Graph
                       ) -> tuple[list[PermissionChange], list[tuple[str, str, Optional[str]]], list[tuple[str, str]]]:
    """Action-level changes of roles present on both sides whose identity-policy statements differ.

    Returns (facts, unknown notes, checked notes). Which actions the application code calls is unknown for every
    changed role that compute uses.
    """
    old = {r.role_arn: r for r in base.iam.role_policies}
    new = {r.role_arn: r for r in branch.iam.role_policies}
    base_ids, branch_ids = role_node_ids(base_graph), role_node_ids(branch_graph)
    changes: list[PermissionChange] = []
    doubts: set[tuple[str, str, Optional[str]]] = set()
    compared = 0
    for arn in sorted(set(old) & set(new)):
        before, after = old[arn], new[arn]
        if not statements_differ(before, after):
            continue
        compared += 1
        rid = role_node_id(after, branch_ids)
        users = sorted(set(compute_users(base_graph, role_node_id(before, base_ids))) | set(compute_users(branch_graph, rid)))
        diff = role_permission_diff(before, after, base_graph, branch_graph)
        for change, items in (("permission_removed", diff.removed), ("permission_added", diff.added)):
            for action, targets in items.items():
                changes.append(PermissionChange(rid, "iam_role", change, action, targets, users))  # type: ignore[arg-type]
        for topic, reason in diff.notes:
            doubts.add((topic, reason, rid))
        if users:
            doubts.add((*NOTE_APP_CODE, rid))
        if before.policy_documents is None:
            doubts.add((*NOTE_MANAGED_NOT_RECORDED, rid))
    if compared:
        doubts.add((*NOTE_ACTION_CATALOG, None))
    checked = ([("permissions", f"{compared} roles whose identity policy statements changed were compared action by action "
                                "for the resources the graph links them to")] if compared else [])
    return changes, sorted(doubts, key=lambda d: (d[0], d[1], d[2] or "")), checked


def _user_lines(base: AWSInfrastructure, branch: AWSInfrastructure) -> list[ChangeLine]:
    before, after = set(base.iam.users_with_admin_policy), set(branch.iam.users_with_admin_policy)
    return ([ChangeLine(f"iam-user-{name}", "iam_user", "admin_access_removed") for name in sorted(before - after)]
            + [ChangeLine(f"iam-user-{name}", "iam_user", "admin_access_added") for name in sorted(after - before)])


def _bucket_lines(base: AWSInfrastructure, branch: AWSInfrastructure) -> tuple[list[ChangeLine], list[ChangeLine]]:
    """(control lines for access logging, exposure lines for public access) between base and branch buckets."""
    old = {b.name: b for b in base.s3.buckets}
    new = {b.name: b for b in branch.s3.buckets}
    control: list[ChangeLine] = []
    exposure: list[ChangeLine] = []
    for name in sorted(set(old) | set(new)):
        before, after = old.get(name), new.get(name)
        was_public, is_public = bool(before and before.is_public), bool(after and after.is_public)
        if is_public and not was_public:
            exposure.append(ChangeLine(name, "s3_bucket", "became_public", "public"))
        elif was_public and not is_public:
            exposure.append(ChangeLine(name, "s3_bucket", "no_longer_public", "public"))
        if before is not None and after is not None:
            if before.logging_enabled is True and after.logging_enabled is not True:
                control.append(ChangeLine(name, "s3_bucket", "logging_disabled", "logging_enabled"))
            elif before.logging_enabled is not True and after.logging_enabled is True:
                control.append(ChangeLine(name, "s3_bucket", "logging_enabled", "logging_enabled"))
    return control, exposure


def _setting_lines(base: AWSInfrastructure, branch: AWSInfrastructure) -> list[ChangeLine]:
    lines = []
    for section in ACCOUNT_SETTINGS:
        before, after = getattr(base, section).model_dump(), getattr(branch, section).model_dump()
        for attribute in sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k)):
            lines.append(ChangeLine(None, section, "account_setting_changed", attribute))
    return lines


def _escalation_lines(base: AWSInfrastructure, branch: AWSInfrastructure, types: Mapping[str, str]) -> list[ChangeLine]:
    return [ChangeLine(rid, types.get(rid) or ("iam_user" if rid.startswith("iam-user-") else "iam_role"),
                       "privilege_escalation_path_added")
            for rid in sorted(introduced_privilege_escalation_ids(base, branch))]


def plan_gaps(plans: Optional[Sequence[Mapping[str, Any]]]) -> list[PlanGap]:
    """Every plan item the branch could not model or apply, from the stored plan receipts."""
    gaps: list[PlanGap] = []
    for plan in plans or []:
        for item in plan.get("unmodeled") or []:
            if isinstance(item, Mapping):
                gaps.append(PlanGap("unmodeled", str(item.get("type") or "unknown"), item.get("address")))
        for item in plan.get("rejected") or []:
            gaps.append(PlanGap("rejected", None, item.get("address") if isinstance(item, Mapping) else None))
        for item in plan.get("unknown_fields") or []:
            gaps.append(PlanGap("unknown_values", None, item.get("address") if isinstance(item, Mapping) else None))
    return gaps


def build_inputs(base: AWSInfrastructure, branch: AWSInfrastructure, verdict: CombinedVerdict, *, branch_id: str,
                 base_analysis_id: Optional[str], branch_revision: Optional[str],
                 plans: Optional[Sequence[Mapping[str, Any]]] = None) -> CheckInputs:
    base_graph, branch_graph = build_graph_pair(base, branch)
    types = {n.id: n.resource_type for graph in (base_graph, branch_graph) for n in graph.nodes}
    gaps = plan_gaps(plans)
    role_control, role_exposure = _role_lines(base, branch, base_graph, branch_graph)
    bucket_control, bucket_exposure = _bucket_lines(base, branch)
    control = (role_control + _user_lines(base, branch) + bucket_control + _setting_lines(base, branch)
               + _escalation_lines(base, branch, types))
    uses: dict[str, Optional[bool]] = {}
    # one line per base role, in role order: keyed by graph id and by ARN (a delete names the ARN)
    for role, line in zip(base.iam.role_policies, role_use_lines(base, base_graph)):
        uses[line.resource_id] = uses[role.role_arn] = line.used
    permission_changes, permission_doubts, permission_checked = _permission_inputs(base, branch, base_graph, branch_graph)
    baseline = (answer_for_infra("baseline", base, analysis_id=base_analysis_id)
                if is_unchanged(verdict, gaps) else None)
    warnings = tuple(sorted({safe_warning(w) for infra in (base, branch) for w in infra.warnings}))
    return CheckInputs(
        branch_id=branch_id, base_analysis_id=base_analysis_id, branch_revision=branch_revision,
        classify=classify_action, plan_gaps=gaps, resource_types=types,
        exposure_lines=role_exposure + bucket_exposure, control_lines=control,
        recovery_removals=recovery_removals(base, branch), uses=uses,
        collection=dict(base.collection), needs=DAMAGE_SOURCES, warnings=warnings,
        permission_changes=permission_changes, permission_doubts=permission_doubts,
        permission_checked=permission_checked,
        checked_notes={
            "money": [("price_table", f"AWS {PRICE_TABLE_REGION} on-demand list prices as of {PRICE_TABLE_AS_OF}")],
            "control": [("modeled_fields", f"{len(branch.iam.role_policies)} roles, {len(branch.s3.buckets)} buckets and "
                                           f"{len(ACCOUNT_SETTINGS)} account-level settings compared between the base and the branch")],
        },
        unknown_notes={
            "data": [("data_store_types", "only s3_bucket, rds_instance and ebs_volume are assessed for recovery; "
                                          "other data stores (tables, queues, caches, secrets) have no recovery assessment")],
            "control": [("account_settings", "a branch cannot change audit trail, threat detection, key management or configuration recording "
                                             "settings, so changes to them are not modeled")],
        },
        baseline=baseline,
    )


def check_for_branch(base: AWSInfrastructure, branch: AWSInfrastructure, *, branch_id: str,
                     base_analysis_id: Optional[str], branch_revision: Optional[str],
                     plans: Optional[Sequence[Mapping[str, Any]]] = None,
                     evidence: Optional[Sequence[EvidenceRecord]] = None,
                     policy_notes: Optional[Sequence[str]] = None,
                     verdict: Optional[CombinedVerdict] = None,
                     run_scanners: bool = False) -> CheckResult:
    """The check for one branch. Computes the verdict the same way /verdict does unless one is passed in."""
    if verdict is None:
        kwargs: dict[str, Any] = {"run_scanners": run_scanners}
        if plans:
            kwargs["plans"] = list(plans)
        if evidence:
            kwargs["evidence"] = list(evidence)
        if policy_notes:
            kwargs["policy_notes"] = list(policy_notes)
        verdict = combined_verdict(base, branch, **kwargs)
    inputs = build_inputs(base, branch, verdict, branch_id=branch_id, base_analysis_id=base_analysis_id,
                          branch_revision=branch_revision, plans=plans)
    return assemble(verdict, inputs)
