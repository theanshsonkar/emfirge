"""Check: "what does this branch damage?" answered with facts about consequences.

CORE module, cloud-neutral (L56 entry ``set()``). It assembles a ``CheckResult``
from the verdict the branch already has (``CombinedVerdict``: delete lens, diff
exposure fields, cost changes, lost dependencies) and a small neutral
``CheckInputs`` bundle that an adapter (``aws_check``) builds from provider
data. Nothing is recomputed here: every fact is read off a field that the
verdict, the delete lens, the diff or the cost estimate already owns.

An answer is never a verdict. There is no pass/warn/block, no score, no
severity, no rule or reason id and no advice anywhere in ``CheckResult``. The
agent is the engineer; Emfirge only says what is true, what was looked at and
what is unknown.

Six damage questions, always all six, always in this order:
  data, exposure, money, availability, control, outside_world

No AI, no clock, no randomness, no I/O: the same inputs give identical output
(every list is sorted).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict

from app.context_query import VIRTUAL_NODE_IDS, ContextResponse, KnownItem, UnknownItem
from app.cost import ResourceCost, unknown_reason
from app.delete_lens import (
    DATA_STORE_TYPES, DYNAMODB_ITEM_COUNT_URL, DYNAMODB_SYSTEM_BACKUP_URL, HOLDS_DATA_UNKNOWN,
)
from app.verdict import DATA_HOLDING_TYPES, CombinedVerdict

DAMAGES: tuple[str, ...] = ("data", "exposure", "money", "availability", "control", "outside_world")
DIFF_DAMAGES: tuple[str, ...] = DAMAGES[:5]
CHANGE_KINDS: tuple[str, ...] = ("added", "removed", "modified")
MAX_DEPENDENCY_DEPTH = 10


# ── response models (extra="forbid" everywhere) ───────────────────

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChangeSet(_Strict):
    change: Literal["added", "removed", "modified"]
    resource_ids: list[str]


class DataFact(_Strict):
    resource_id: str
    resource_type: str
    change: Literal["deleted", "recovery_removed"]
    has_recovery_point: Optional[bool]
    recovery_resource_ids: list[str]


class ExposureFact(_Strict):
    resource_id: str
    resource_type: str
    change: Literal["newly_exposed", "no_longer_exposed", "became_internet_reachable",
                    "no_longer_internet_reachable", "became_public", "no_longer_public",
                    "newly_trusts_external_account", "no_longer_trusts_external_account"]
    protocol: Optional[str]
    ports: list[int]
    source: Optional[str]
    resource_ids: list[str]
    state: str


class MoneyFact(_Strict):
    resource_id: Optional[str]
    resource_type: Optional[str]
    change: Literal["added", "removed", "modified", "total"]
    before_monthly_usd: Optional[float]
    after_monthly_usd: Optional[float]


class AvailabilityFact(_Strict):
    resource_id: str
    resource_type: str
    change: Literal["dependency_removed", "internal_path_removed", "dependent_of_deleted", "deleted_along_with",
                    "internet_path_removed", "schedule_disabled", "schedule_deleted"]
    path: list[str]
    depth: Optional[int]
    recently_used: Optional[bool]


class EdgeOriginFact(_Strict):
    """A cache behavior of an edge distribution now passes the viewer Host header to the storage origin it serves.

    ``resource_id`` is the distribution, ``resource_ids`` the storage resources it serves from, ``path_pattern`` the
    behavior, the policy ids what carries the header, ``source_url`` the provider documentation of the behavior.
    """
    resource_id: str
    resource_type: str
    change: Literal["origin_receives_host_header"]
    resource_ids: list[str]
    path_pattern: str
    cache_policy_id: Optional[str]
    origin_request_policy_id: Optional[str]
    source_url: str


class PermissionFact(_Strict):
    """One action a role may (no longer) call on the listed resources, from collected identity policies.

    ``resource_id`` is the role; ``resource_ids`` the resources the action is about; ``affected_node_ids`` the
    resources that use the role. Which actions application code calls is never claimed.
    """
    resource_id: str
    resource_type: str
    change: Literal["permission_removed", "permission_added"]
    action: str
    resource_ids: list[str]
    affected_node_ids: list[str]


class ControlFact(_Strict):
    resource_id: Optional[str]
    resource_type: Optional[str]
    change: str
    attribute: Optional[str]


class OutsideFact(_Strict):
    action: str
    service: str
    reason: str
    source_url: str
    resource_id: Optional[str]


class ScheduleFact(_Strict):
    """A timer that now runs its target. ``resource_ids`` are the collected targets; what they do outside is not claimed."""
    resource_id: str
    resource_type: str
    change: Literal["schedule_enabled", "schedule_added_enabled", "schedule_changed"]
    schedule_expression: Optional[str]
    resource_ids: list[str]
    action: Optional[str]
    service: str
    reason: str
    source_url: str


Fact = Union[DataFact, ExposureFact, MoneyFact, AvailabilityFact, EdgeOriginFact, PermissionFact, ControlFact, OutsideFact, ScheduleFact]


class DamageAnswer(_Strict):
    damage: Literal["data", "exposure", "money", "availability", "control", "outside_world"]
    facts: list[Fact]
    checked: list[KnownItem]
    unknown: list[UnknownItem]


class CheckResult(_Strict):
    branch_id: str
    base_analysis_id: Optional[str]
    branch_revision: Optional[str]
    changes: list[ChangeSet]
    answers: list[DamageAnswer]
    baseline: Optional[ContextResponse]


# ── neutral inputs (built by an adapter) ──────────────────────────

@dataclass(frozen=True)
class OutsideEntry:
    """What the table says about one action: ``outside`` False for a known read, True for an action that leaves the cloud."""
    service: str
    reason: str
    source_url: str
    outside: bool = True


@dataclass(frozen=True)
class ChangeLine:
    """A modeled change an adapter read off provider fields (exposure or control)."""
    resource_id: Optional[str]
    resource_type: Optional[str]
    change: str
    attribute: Optional[str] = None


@dataclass(frozen=True)
class PlanGap:
    """Something a plan carried that the branch could not model or apply."""
    kind: Literal["unmodeled", "rejected", "unknown_values"]
    action: Optional[str] = None
    address: Optional[str] = None


@dataclass(frozen=True)
class PermissionChange:
    """One action of one role that went from allowed to not allowed (or back) on the listed resources."""
    resource_id: str
    resource_type: str
    change: Literal["permission_removed", "permission_added"]
    action: str
    resource_ids: Sequence[str]
    affected_node_ids: Sequence[str] = ()


@dataclass(frozen=True)
class ScheduleChange:
    """A timer whose effective state or timing changed on the branch (an adapter read it off provider fields)."""
    resource_id: str
    resource_type: str
    change: Literal["schedule_enabled", "schedule_added_enabled", "schedule_changed", "schedule_disabled",
                    "schedule_deleted"]
    schedule_expression: Optional[str]
    target_ids: Sequence[str]
    entry: OutsideEntry


@dataclass
class CheckInputs:
    branch_id: str
    base_analysis_id: Optional[str]
    branch_revision: Optional[str]
    # action name ("service.Operation" or a plan resource type) -> table entry, or None
    classify: Callable[[str], Optional[OutsideEntry]] = lambda _action: None
    plan_gaps: Sequence[PlanGap] = ()
    resource_types: Mapping[str, str] = field(default_factory=dict)
    exposure_lines: Sequence[ChangeLine] = ()
    control_lines: Sequence[ChangeLine] = ()
    recovery_removals: Sequence[tuple[str, str]] = ()
    # resource id -> used within the window (True/False) or None when it cannot be told
    uses: Mapping[str, Optional[bool]] = field(default_factory=dict)
    collection: Mapping[str, str] = field(default_factory=dict)
    needs: Mapping[str, Sequence[str]] = field(default_factory=dict)
    warnings: Sequence[str] = ()
    permission_changes: Sequence[PermissionChange] = ()
    # (topic, reason, resource_id) notes about the action-level comparison; shown in availability
    permission_doubts: Sequence[tuple[str, str, Optional[str]]] = ()
    permission_checked: Sequence[tuple[str, str]] = ()
    schedule_changes: Sequence[ScheduleChange] = ()
    # (topic, reason, resource_id) notes about schedules; shown in outside_world
    schedule_doubts: Sequence[tuple[str, str, Optional[str]]] = ()
    schedules_compared: int = 0
    # facts and (topic, reason, resource_id) doubts an adapter read for the availability answer
    availability_facts: Sequence[Any] = ()
    availability_doubts: Sequence[tuple[str, str, Optional[str]]] = ()
    checked_notes: Mapping[str, Sequence[tuple[str, str]]] = field(default_factory=dict)
    unknown_notes: Mapping[str, Sequence[tuple[str, str]]] = field(default_factory=dict)
    baseline: Optional[ContextResponse] = None


# ── helpers ───────────────────────────────────────────────────────

_Note = tuple[str, str, Optional[str]]


class _Draft:
    """One answer under construction: facts, checked notes, unknown notes."""

    def __init__(self, damage: str) -> None:
        self.damage = damage
        self.facts: list[Any] = []
        self.checked: list[_Note] = []
        self.unknown: list[_Note] = []

    def check(self, topic: str, detail: str, resource_id: Optional[str] = None) -> None:
        self.checked.append((topic, detail, resource_id))

    def doubt(self, topic: str, reason: str, resource_id: Optional[str] = None) -> None:
        self.unknown.append((topic, reason, resource_id))


def _fact_key(fact: Any) -> tuple[str, str, str]:
    return (getattr(fact, "resource_id", None) or getattr(fact, "action", "") or "",
            getattr(fact, "change", "") or "", fact.model_dump_json())


def _unique_facts(facts: Sequence[Any]) -> list[Any]:
    seen: dict[str, Any] = {}
    for fact in facts:
        seen.setdefault(fact.model_dump_json(), fact)
    return sorted(seen.values(), key=_fact_key)


def _padded(notes: Sequence[_Note]) -> list[_Note]:
    return sorted(set(notes), key=lambda n: (n[0], n[1], n[2] or ""))


def _ids(items: Any, key: str = "id") -> list[str]:
    return sorted({str(item[key]) for item in items or [] if str(item.get(key, "")) not in VIRTUAL_NODE_IDS and item.get(key)})


def _usage(verdict: CombinedVerdict, inputs: CheckInputs) -> tuple[dict[str, Optional[bool]], list[_Note]]:
    """Recent use per resource: stored evidence records first, then the adapter's last-used lines."""
    by_id: dict[str, list[Any]] = {}
    for record in verdict.deletion.in_use_evidence:
        by_id.setdefault(record.resource_id, []).append(record)
    uses: dict[str, Optional[bool]] = dict(inputs.uses)
    doubts: list[_Note] = []
    for rid, records in by_id.items():
        flags = [r.used for r in records]
        # any recorded use wins; unused is only claimed when no source is unknown
        uses[rid] = True if any(f is True for f in flags) else None if any(f is None for f in flags) else False
        for record in sorted(records, key=lambda r: r.source):
            if record.used is None:
                doubts.append(("recent_use", f"{record.source} evidence status is '{record.status}'", rid))
    return uses, doubts


def _type_of(rid: str, types: Mapping[str, str]) -> str:
    return types.get(rid, "unknown")


def _type_map(verdict: CombinedVerdict, inputs: CheckInputs) -> dict[str, str]:
    types: dict[str, str] = dict(inputs.resource_types)
    for items in (verdict.resources_added, verdict.resources_removed, verdict.resources_modified):
        for item in items:
            if item.get("id") and item.get("resource_type"):
                types[str(item["id"])] = str(item["resource_type"])
    for lost in verdict.deletion.data_lost:
        types[lost.resource_id] = lost.resource_type
    for impact in verdict.deletion.impacts:
        types[impact.resource_id] = impact.resource_type
    return types


# ── the six answers ───────────────────────────────────────────────

_RECOVERY_UNKNOWN = {
    True: "the item count of this table is not a reliable emptiness proof (not reported, 0, or stored by an older scan that wrote a missing count as 0; AWS updates ItemCount only about every six hours, so recent items may not be counted: " + DYNAMODB_ITEM_COUNT_URL + "), so whether it held data is unknown, and no on-demand backup or point-in-time recovery is known either; rescan to know",
    False: "the backup or point-in-time recovery settings of this table could not be read, so whether a recovery point exists is unknown",
}


def _data(verdict: CombinedVerdict, inputs: CheckInputs, types: Mapping[str, str], removed_ids: Sequence[str]) -> _Draft:
    draft = _Draft("data")
    for lost in verdict.deletion.data_lost:
        draft.facts.append(DataFact(resource_id=lost.resource_id, resource_type=lost.resource_type, change="deleted",
                                    has_recovery_point=False, recovery_resource_ids=[]))
    for point in verdict.deletion.recovery_points:
        draft.facts.append(DataFact(
            resource_id=point.resource_id, resource_type=_type_of(point.resource_id, types), change="deleted",
            has_recovery_point=True,
            recovery_resource_ids=[point.source_id] if point.source_id != point.resource_id else []))
    for unknown in verdict.deletion.recovery_unknown:
        draft.facts.append(DataFact(resource_id=unknown.resource_id, resource_type=unknown.resource_type, change="deleted",
                                    has_recovery_point=None, recovery_resource_ids=[]))
        draft.doubt("recovery_unknown", _RECOVERY_UNKNOWN[unknown.why == HOLDS_DATA_UNKNOWN], unknown.resource_id)
    if any(point.kind == "dynamodb_system_backup" for point in verdict.deletion.recovery_points):
        draft.check("table_system_backup", "deleting a table with point-in-time recovery on makes AWS keep a system backup for 35 days "
                                           f"that the table can be restored from: {DYNAMODB_SYSTEM_BACKUP_URL}")
    for rid, rtype in inputs.recovery_removals:
        draft.facts.append(DataFact(resource_id=rid, resource_type=rtype, change="recovery_removed",
                                    has_recovery_point=None, recovery_resource_ids=[]))
    assessed = [rid for rid in removed_ids if types.get(rid) in DATA_STORE_TYPES]
    draft.check("deleted_data_stores", f"{len(removed_ids)} removed resources compared against surviving snapshots and backups; "
                                        f"{len(assessed)} of them are data stores whose recovery was assessed")
    draft.check("recovery_points", f"{len(verdict.deletion.recovery_points)} deleted data stores have a surviving recovery point; "
                                   f"{len(verdict.deletion.data_lost)} have none")
    draft.check("recovery_removed", f"{len(inputs.recovery_removals)} recovery points removed by the branch "
                                    "(snapshots deleted, automated backups, versioning or point-in-time recovery turned off)")
    for rid in removed_ids:
        if types.get(rid) in DATA_HOLDING_TYPES - DATA_STORE_TYPES:
            draft.doubt("recovery_not_assessed", "this removed resource holds data but only buckets, databases, volumes and DynamoDB tables get a recovery assessment", rid)
    draft.doubt("data_contents", "what a data store holds is not read; recovery is judged from snapshots, backups and bucket emptiness only")
    return draft


def _exposure(verdict: CombinedVerdict, inputs: CheckInputs, types: Mapping[str, str]) -> _Draft:
    draft = _Draft("exposure")
    for change, items in (("newly_exposed", verdict.newly_exposed), ("no_longer_exposed", verdict.no_longer_exposed)):
        for item in items:
            draft.facts.append(ExposureFact(
                resource_id=str(item["resource_id"]), resource_type=str(item["resource_type"]), change=change,
                protocol=item.get("protocol"), ports=[int(item["from_port"]), int(item["to_port"])],
                source=item.get("source"), resource_ids=[str(item["via_sg"])] if item.get("via_sg") else [],
                state=str(item["state"])))
    for change, ids in (("became_internet_reachable", verdict.newly_internet_reachable),
                        ("no_longer_internet_reachable", verdict.no_longer_internet_reachable)):
        for rid in ids:
            draft.facts.append(ExposureFact(resource_id=rid, resource_type=_type_of(rid, types), change=change,
                                            protocol=None, ports=[], source=None, resource_ids=[], state="reachable"))
    for line in inputs.exposure_lines:
        draft.facts.append(ExposureFact(resource_id=line.resource_id or "", resource_type=line.resource_type or "unknown",
                                        change=line.change, protocol=None, ports=[], source=None, resource_ids=[],
                                        state=line.attribute or "changed"))
    draft.check("ingress_rules", f"{len(verdict.newly_exposed)} ingress paths opened and {len(verdict.no_longer_exposed)} closed, "
                                 "compared between the base and the branch")
    draft.check("internet_reachability", f"{len(verdict.newly_internet_reachable)} resources became and "
                                         f"{len(verdict.no_longer_internet_reachable)} stopped being reachable from the internet in the graph")
    draft.check("public_and_trust", f"{len(inputs.exposure_lines)} public-access and external-trust changes read from modeled fields")
    draft.doubt("observed_traffic", "observed traffic, host firewalls and application-level controls are not collected")
    return draft


def _money(verdict: CombinedVerdict, inputs: CheckInputs) -> _Draft:
    draft = _Draft("money")
    for change in verdict.cost_changes:
        before_basis, after_basis = change.get("before_basis"), change.get("after_basis")
        kind = "added" if before_basis is None else "removed" if after_basis is None else "modified"
        draft.facts.append(MoneyFact(resource_id=str(change["resource_id"]), resource_type=str(change["resource_type"]), change=kind,
                                     before_monthly_usd=change.get("before_monthly_usd"),
                                     after_monthly_usd=change.get("after_monthly_usd")))
        for side, basis in (("before_monthly_usd", before_basis), ("after_monthly_usd", after_basis)):
            if basis is not None and basis != "free" and change.get(side) is None:
                draft.doubt("cost", unknown_reason(ResourceCost(resource_id=str(change["resource_id"]),
                                                                resource_type=str(change["resource_type"]),
                                                                monthly_usd=None, basis=basis)),
                            str(change["resource_id"]))
    if verdict.cost_changes:
        draft.facts.append(MoneyFact(resource_id=None, resource_type=None, change="total",
                                     before_monthly_usd=verdict.cost_before.get("known_monthly_usd"),
                                     after_monthly_usd=verdict.cost_after.get("known_monthly_usd")))
        before_unknown = int(verdict.cost_before.get("unknown_count") or 0)
        after_unknown = int(verdict.cost_after.get("unknown_count") or 0)
        if before_unknown or after_unknown:
            draft.doubt("cost_total", f"{before_unknown} resources on the base and {after_unknown} on the branch have no known price; "
                                      "the totals add up the priced resources only")
    draft.check("cost_changes", f"{len(verdict.cost_changes)} cost-bearing resources changed between the base and the branch")
    draft.doubt("usage_charges", "only provisioned list-price charges are estimated; usage-based charges, discounts and taxes are not included")
    return draft


def _endpoint_use(ids: Sequence[str], affected: set[str], uses: Mapping[str, Optional[bool]]) -> Optional[bool]:
    """Recent use of the removed or changed end(s) of an edge; None when neither end is known to have changed."""
    ends = [rid for rid in ids if rid in affected]
    if not ends:
        return None
    flags = [uses.get(rid) for rid in ends]
    return True if any(f is True for f in flags) else None if any(f is None for f in flags) else False


def _chain(rid: str, via: Mapping[str, str]) -> list[str]:
    """Ids from the deleted root to ``rid`` following each impact's ``via``."""
    path = [rid]
    while path[-1] in via and via[path[-1]] not in path and len(path) <= MAX_DEPENDENCY_DEPTH + 1:
        path.append(via[path[-1]])
    return list(reversed(path))


def _permission_fact(item: PermissionChange) -> PermissionFact:
    return PermissionFact(resource_id=item.resource_id, resource_type=item.resource_type, change=item.change,
                          action=item.action, resource_ids=sorted(set(item.resource_ids)),
                          affected_node_ids=sorted(set(item.affected_node_ids)))


def _availability(verdict: CombinedVerdict, inputs: CheckInputs, types: Mapping[str, str],
                  uses: Mapping[str, Optional[bool]], use_doubts: Sequence[_Note],
                  affected_ids: Sequence[str]) -> _Draft:
    draft = _Draft("availability")
    changed = set(affected_ids)
    for change, edges in (("dependency_removed", verdict.lost_dependencies), ("internal_path_removed", verdict.lost_connectivity)):
        for edge in edges:
            rid, other = str(edge["from"]), str(edge["to"])
            draft.facts.append(AvailabilityFact(resource_id=rid, resource_type=_type_of(rid, types), change=change,
                                                path=[rid, other], depth=1, recently_used=_endpoint_use([rid, other], changed, uses)))
    # every delete-lens impact: implicit co-deletes ("deleted_with:<parent>") and true dependents alike
    impacts = list(verdict.deletion.impacts)
    via = {i.resource_id: i.via for i in impacts}
    for impact in impacts:
        path = _chain(impact.resource_id, via)
        along = impact.relation.startswith("deleted_with")
        draft.facts.append(AvailabilityFact(resource_id=impact.resource_id, resource_type=impact.resource_type,
                                            change="deleted_along_with" if along else "dependent_of_deleted",
                                            path=path, depth=impact.depth, recently_used=uses.get(path[0])))
    for rid in verdict.no_longer_internet_reachable:
        draft.facts.append(AvailabilityFact(resource_id=rid, resource_type=_type_of(rid, types), change="internet_path_removed",
                                            path=[rid], depth=0, recently_used=uses.get(rid)))
    for item in inputs.permission_changes:
        if item.change == "permission_removed":
            draft.facts.append(_permission_fact(item))
    for item in inputs.schedule_changes:
        if item.change in ("schedule_disabled", "schedule_deleted"):
            for target in sorted(set(item.target_ids)) or [None]:
                draft.facts.append(AvailabilityFact(
                    resource_id=item.resource_id, resource_type=item.resource_type, change=item.change,  # type: ignore[arg-type]
                    path=[item.resource_id] + ([target] if target else []), depth=1 if target else 0, recently_used=None))
    draft.facts.extend(inputs.availability_facts)
    for topic, reason, rid in inputs.availability_doubts:
        draft.doubt(topic, reason, rid)
    for topic, reason, rid in inputs.permission_doubts:
        draft.doubt(topic, reason, rid)
    for topic, detail in inputs.permission_checked:
        draft.check(topic, detail)
    draft.check("dependencies", f"{len(verdict.lost_dependencies)} lost dependencies and {len(verdict.lost_connectivity)} lost internal paths "
                                "compared between the base and the branch")
    draft.check("deleted_dependents", f"{len(impacts)} resources that depend on or go down with a deleted resource found by walking dependency edges "
                                      f"up to {MAX_DEPENDENCY_DEPTH} levels")
    draft.check("internet_paths", f"{len(verdict.no_longer_internet_reachable)} resources lost their modeled internet path")
    known_use = sorted(rid for rid in affected_ids if uses.get(rid) is not None)
    if known_use:
        draft.check("recent_use", f"recent use was read for {len(known_use)} removed or modified resources")
    for rid in affected_ids:
        if rid not in uses:
            draft.doubt("recent_use", "recent use not checked: no usage evidence was gathered for this resource", rid)
        elif uses[rid] is None and not any(n[2] == rid for n in use_doubts):
            draft.doubt("recent_use", "recent use could not be determined from the collected last-used data", rid)
    draft.unknown.extend(use_doubts)
    draft.doubt("app_code_references", "application code, DNS records and other accounts that use these resources are not visible")
    return draft


def _control(inputs: CheckInputs) -> _Draft:
    draft = _Draft("control")
    for line in inputs.control_lines:
        draft.facts.append(ControlFact(resource_id=line.resource_id, resource_type=line.resource_type,
                                       change=line.change, attribute=line.attribute))
    for item in inputs.permission_changes:
        if item.change == "permission_added":
            draft.facts.append(_permission_fact(item))
    draft.check("control_changes", f"{len(inputs.control_lines)} control changes read from modeled fields between the base and the branch")
    draft.doubt("other_policy_layers", "permission boundaries, organization policies and resource policies are not collected, so effective access can differ")
    return draft


def _outside_world(inputs: CheckInputs, changed_typed: int) -> _Draft:
    draft = _Draft("outside_world")
    classified = 0
    reads = 0
    for gap in inputs.plan_gaps:
        if gap.kind != "unmodeled" or not gap.action:
            continue
        entry = inputs.classify(gap.action)
        if entry is None:
            draft.doubt("unclassified_action", f"not classified: {gap.action} is not in the table of actions that leave the cloud",
                        gap.address)
            continue
        if not entry.outside:
            reads += 1
            continue
        classified += 1
        draft.facts.append(OutsideFact(action=gap.action, service=entry.service, reason=entry.reason,
                                       source_url=entry.source_url, resource_id=gap.address))
    for item in inputs.schedule_changes:
        if item.change not in ("schedule_disabled", "schedule_deleted"):
            draft.facts.append(ScheduleFact(
                resource_id=item.resource_id, resource_type=item.resource_type, change=item.change,  # type: ignore[arg-type]
                schedule_expression=item.schedule_expression, resource_ids=sorted(set(item.target_ids)), action=None,
                service=item.entry.service, reason=item.entry.reason, source_url=item.entry.source_url))
    for topic, reason, rid in inputs.schedule_doubts:
        draft.doubt(topic, reason, rid)
    draft.check("schedules", f"{inputs.schedules_compared} schedules compared between the base and the branch for a timer that starts running")
    draft.check("typed_changes", f"{changed_typed} typed changes were compared; whether they reach a party outside the account is not assessed, "
                                 "only schedules and the plan actions in the table are")
    draft.check("plan_actions", f"{classified} unmodeled plan actions matched the table of actions that leave the cloud")
    if reads:
        draft.check("read_only_actions", f"{reads} plan actions are reads by name (Get, List or Describe) of a service in the table and are not treated as leaving the cloud")
    draft.doubt("service_table", "only actions of the services in the table are classified; any other action is reported as unclassified, never skipped silently")
    return draft


# ── assembly ──────────────────────────────────────────────────────

def _coverage(draft: _Draft, inputs: CheckInputs, with_warnings: bool) -> None:
    for source in sorted(set(inputs.needs.get(draft.damage, ()))):
        status = inputs.collection.get(source)
        if status == "ok":
            draft.check(source, "collected ok")
        elif status is None:
            draft.doubt(source, "collection status was not recorded for this snapshot, so it cannot be said to have been checked")
        else:
            draft.doubt(source, f"collection status is '{status}'; what it would show is not in the snapshot")
    if with_warnings:
        for warning in sorted(set(inputs.warnings)):
            draft.doubt("collector_skipped", str(warning))
    for topic, text in inputs.checked_notes.get(draft.damage, ()):
        draft.check(topic, text)
    for topic, text in inputs.unknown_notes.get(draft.damage, ()):
        draft.doubt(topic, text)


def _plan_unknowns(draft: _Draft, inputs: CheckInputs) -> None:
    for gap in inputs.plan_gaps:
        if gap.kind == "unmodeled":
            draft.doubt("unmodeled_item", f"not modeled on the branch: {gap.action}", gap.address)
        elif gap.kind == "rejected":
            draft.doubt("plan_change_not_applied", "a plan change was rejected and not applied to the branch, so its consequences were not evaluated", gap.address)
        else:
            draft.doubt("plan_values_unknown", "a plan value was unknown or unsupported, so the change was applied without it", gap.address)


def _finish(draft: _Draft) -> DamageAnswer:
    return DamageAnswer(
        damage=draft.damage,  # type: ignore[arg-type]
        facts=_unique_facts(draft.facts),
        checked=[KnownItem(topic=t, detail=d, resource_id=r) for t, d, r in _padded(draft.checked)],
        unknown=[UnknownItem(topic=t, reason=d, resource_id=r) for t, d, r in _padded(draft.unknown)],
    )


def is_unchanged(verdict: CombinedVerdict, plan_gaps: Sequence[PlanGap]) -> bool:
    """True when the branch changes nothing the snapshot models and carries no plan items."""
    return not (_ids(verdict.resources_added) or _ids(verdict.resources_removed) or _ids(verdict.resources_modified)
                or plan_gaps) and verdict.modeled_state_unchanged


def assemble(verdict: CombinedVerdict, inputs: CheckInputs) -> CheckResult:
    """The check answer for one branch: facts read off ``verdict`` plus the adapter's neutral lines."""
    added = _ids(verdict.resources_added)
    removed = _ids(verdict.resources_removed)
    modified = _ids(verdict.resources_modified)
    types = _type_map(verdict, inputs)
    uses, use_doubts = _usage(verdict, inputs)
    affected = sorted(set(removed) | set(modified))
    drafts = {
        "data": _data(verdict, inputs, types, removed),
        "exposure": _exposure(verdict, inputs, types),
        "money": _money(verdict, inputs),
        "availability": _availability(verdict, inputs, types, uses, use_doubts, affected),
        "control": _control(inputs),
        "outside_world": _outside_world(inputs, len(added) + len(removed) + len(modified)),
    }
    for damage in DAMAGES:
        _coverage(drafts[damage], inputs, with_warnings=damage in DIFF_DAMAGES)
        if damage in DIFF_DAMAGES or damage == "outside_world":
            _plan_unknowns(drafts[damage], inputs)
    unchanged = is_unchanged(verdict, inputs.plan_gaps)
    return CheckResult(
        branch_id=inputs.branch_id,
        base_analysis_id=inputs.base_analysis_id,
        branch_revision=inputs.branch_revision,
        changes=[ChangeSet(change="added", resource_ids=added), ChangeSet(change="removed", resource_ids=removed),
                 ChangeSet(change="modified", resource_ids=modified)],
        answers=[_finish(drafts[damage]) for damage in DAMAGES],
        baseline=inputs.baseline if unchanged else None,
    )
