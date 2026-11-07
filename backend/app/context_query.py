"""Read-only context query: "what is true in my cloud?" answered with facts.

CORE module, cloud-neutral (L56 entry ``set()``). It works on two neutral
inputs only: the egraph ``Graph`` and a ``FactsBundle`` of plain dataclasses
that an adapter (``aws_context``) builds from provider data. Anything that needs
provider knowledge (tags, recovery points, prices, last-used, exposure rules)
arrives already reduced to bundle lines.

What an answer is:
  * facts   typed records, never a verdict, advice, score or fix;
  * known   what was checked;
  * unknown what was not checked, and why (a degraded source is never a silent
    "nothing found").

No AI, no clock, no randomness: the same graph and bundle give identical output
(every list is sorted). No I/O of any kind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.egraph import Graph, dependency_closure, get_internet_reachable_set

Question = Literal["inventory", "resource", "depends_on", "dependents", "reachable",
                   "access", "data", "cost", "live", "marks", "baseline"]
QUESTIONS: tuple[str, ...] = (
    "inventory", "resource", "depends_on", "dependents", "reachable",
    "access", "data", "cost", "live", "marks", "baseline",
)
RESOURCE_REQUIRED = frozenset({"resource", "depends_on", "dependents"})

# Edge types that give an identity access to / the ability to assume another node.
ACCESS_RELATIONSHIPS = frozenset({"can_access", "can_assume"})
VIRTUAL_NODE_IDS = frozenset({"INTERNET"})
MAX_DEPENDENCY_DEPTH = 10

OWNER_INTENT_REASON = "emfirge.md is not built yet; only resource tags are shown"


class ResourceNotFound(LookupError):
    """The asked resource is not part of the snapshot (message never echoes the id)."""


# ── request / response models (extra="forbid" everywhere) ─────────

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContextRequest(_Strict):
    question: Question
    analysis_id: Optional[str] = Field(default=None, max_length=128)
    branch_id: Optional[str] = Field(default=None, max_length=128)
    resource_id: Optional[str] = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _check(self) -> "ContextRequest":
        if self.analysis_id is not None and self.branch_id is not None:
            raise ValueError("analysis_id and branch_id are exclusive; send one or neither")
        if self.resource_id is not None and not self.resource_id.strip():
            raise ValueError("resource_id must not be blank")
        if self.question in RESOURCE_REQUIRED and self.resource_id is None:
            raise ValueError(f"resource_id is required for {self.question}")
        if self.question == "baseline" and self.resource_id is not None:
            raise ValueError("baseline answers for the whole snapshot; resource_id is not accepted")
        return self


class SourceInfo(_Strict):
    kind: Literal["scan", "branch"]
    analysis_id: Optional[str]
    branch_id: Optional[str]
    collected_at: Optional[str]
    region: Optional[str]


class KnownItem(_Strict):
    topic: str
    detail: str
    # the resource a note is about; never put an id or name inside topic/detail
    resource_id: Optional[str] = None


class UnknownItem(_Strict):
    topic: str
    reason: str
    resource_id: Optional[str] = None


class InventoryFact(_Strict):
    resource_id: str
    resource_type: str
    category: str
    region: Optional[str]


class EdgeFact(_Strict):
    relationship: str
    source: str
    target: str


class ResourceFact(_Strict):
    resource_id: str
    resource_type: str
    category: str
    tags: Optional[dict[str, str]]
    edges: list[EdgeFact]


class DependencyFact(_Strict):
    resource_id: str
    resource_type: str
    relationship: str
    depth: int
    path: list[str]


class ReachableFact(_Strict):
    resource_id: str
    resource_type: str
    protocol: Optional[str]
    ports: list[int]
    source: Optional[str]
    resource_ids: list[str]
    state: str


class ActionAllow(_Strict):
    """One action a role is allowed (``allow``) or conditionally allowed (``conditional``) on the listed resources."""
    action: str
    effect: Literal["allow", "conditional"]
    resource_ids: list[str]


class AccessFact(_Strict):
    resource_id: str
    resource_ids: list[str]
    escalation: list[str]
    permissions: list[ActionAllow]


class DataFact(_Strict):
    resource_id: str
    resource_type: str
    has_recovery_point: Optional[bool]
    recovery_resource_ids: list[str]
    recovery_kinds: list[str]


class CostFact(_Strict):
    resource_id: str
    resource_type: str
    monthly_usd: Optional[float]
    basis: str


class LiveFact(_Strict):
    resource_id: str
    used: Optional[bool]
    last_used_at: Optional[str]
    window_days: int
    basis: Literal["scan:last_used", "branch:evidence"]


class MarksFact(_Strict):
    resource_id: str
    tags: dict[str, str]


class BaselineFact(_Strict):
    topic: str
    count: int


Fact = Union[InventoryFact, ResourceFact, DependencyFact, ReachableFact, AccessFact,
             DataFact, CostFact, LiveFact, MarksFact, BaselineFact]


class ContextResponse(_Strict):
    question: Question
    source: SourceInfo
    facts: list[Fact]
    known: list[KnownItem]
    unknown: list[UnknownItem]


# ── neutral facts bundle (built by an adapter) ────────────────────

@dataclass(frozen=True)
class Note:
    topic: str
    text: str


@dataclass(frozen=True)
class TagLine:
    """User tags of one resource; ``tags`` None means the tags were not collected."""
    resource_id: str
    resource_type: str
    tags: Optional[Mapping[str, str]]


@dataclass(frozen=True)
class DataLine:
    """Recovery state of one data store; ``has_recovery_point`` None means it cannot be told."""
    resource_id: str
    resource_type: str
    has_recovery_point: Optional[bool]
    recovery_resource_ids: tuple[str, ...] = ()
    recovery_kinds: tuple[str, ...] = ()


@dataclass(frozen=True)
class CostLine:
    resource_id: str
    resource_type: str
    monthly_usd: Optional[float]
    basis: str
    unknown_reason: Optional[str] = None


@dataclass(frozen=True)
class UseLine:
    resource_id: str
    used: Optional[bool]
    last_used_at: Optional[str]
    window_days: int
    basis: str
    unknown_topic: Optional[str] = None
    unknown_reason: Optional[str] = None


@dataclass(frozen=True)
class ExposureLine:
    resource_id: str
    resource_type: str
    protocol: str
    from_port: int
    to_port: int
    source: str
    via: str
    state: str


@dataclass(frozen=True)
class PermissionEntry:
    """An action-level allow of one identity (from the neutral permission expansion)."""
    resource_id: str
    action: str
    effect: str
    target_ids: tuple[str, ...]


@dataclass(frozen=True)
class PermissionNote:
    """What the expansion could not decide for one identity (topic and text carry no identifiers)."""
    resource_id: str
    topic: str
    text: str


@dataclass
class FactsBundle:
    source: SourceInfo
    # per-source collection status ("ok" / "denied" / "error"); absent = not recorded
    collection: Mapping[str, str] = field(default_factory=dict)
    # question -> collection sources that question depends on
    needs: Mapping[str, Sequence[str]] = field(default_factory=dict)
    # services the collector skipped (free text, from the snapshot)
    warnings: Sequence[str] = ()
    tags: Sequence[TagLine] = ()
    data: Sequence[DataLine] = ()
    costs: Sequence[CostLine] = ()
    uses: Sequence[UseLine] = ()
    exposures: Sequence[ExposureLine] = ()
    permissions: Sequence[PermissionEntry] = ()
    permission_notes: Sequence[PermissionNote] = ()
    # adapter-supplied per-question notes
    known: Mapping[str, Sequence[Note]] = field(default_factory=dict)
    unknown: Mapping[str, Sequence[Note]] = field(default_factory=dict)


# ── the answer ────────────────────────────────────────────────────

@dataclass
class _Ctx:
    graph: Graph
    bundle: FactsBundle
    resource_id: Optional[str]
    nodes: dict[str, Any]


_Result = tuple[list[Any], list[tuple[str, ...]], list[tuple[str, ...]]]

# What no snapshot can show, per question. Provider-neutral wording.
_FIXED_UNKNOWN: dict[str, tuple[tuple[str, str], ...]] = {
    "inventory": (("unmodeled_types", "only resource types the snapshot models are listed; other types are not inventoried"),),
    "resource": (("app_code_references", "application code that references this resource is not visible"),
                 ("dns_records", "DNS records that point at this resource are not collected"),
                 ("other_accounts", "other accounts that use this resource are not visible")),
    "depends_on": (("app_code_references", "application code that references these resources is not visible"),
                   ("dns_records", "DNS records are not collected"),
                   ("other_accounts", "other accounts are not visible")),
    "dependents": (("app_code_references", "application code that references this resource is not visible"),
                   ("dns_records", "DNS records that point at this resource are not collected"),
                   ("other_accounts", "other accounts that use this resource are not visible")),
    "reachable": (("observed_traffic", "observed traffic, host firewalls and application-level controls are not collected"),),
    "access": (("other_policy_layers", "permission boundaries, organization policies and resource policies are not collected, so effective access can differ"),),
    "data": (("data_contents", "what a data store holds is not read; recovery is judged from snapshots and bucket emptiness only"),),
    "cost": (("usage_charges", "only provisioned list-price charges are estimated; usage-based charges, discounts and taxes are not included"),),
    "live": (("recent_use", "a scan snapshot holds last-used only where the provider reports it; other resources have no usage evidence unless evidence rows were stored for a branch"),),
    "marks": (),
    "baseline": (),
}


def _real_nodes(ctx: _Ctx) -> list[Any]:
    return [node for node in ctx.graph.nodes if node.id not in VIRTUAL_NODE_IDS]


def _wanted(ctx: _Ctx, resource_id: str) -> bool:
    return ctx.resource_id is None or ctx.resource_id == resource_id


def _inventory(ctx: _Ctx) -> _Result:
    region = ctx.bundle.source.region
    facts = [InventoryFact(resource_id=n.id, resource_type=n.resource_type,
                           category=n.category.value, region=region)
             for n in _real_nodes(ctx) if _wanted(ctx, n.id)]
    facts.sort(key=lambda f: (f.resource_type, f.resource_id))
    known = [("graph", f"{len(_real_nodes(ctx))} resources in the snapshot graph")]
    return facts, known, []


def _user_tags(ctx: _Ctx, resource_id: str) -> Optional[dict[str, str]]:
    for line in ctx.bundle.tags:
        if line.resource_id == resource_id:
            return None if line.tags is None else {k: line.tags[k] for k in sorted(line.tags)}
    return None


def _resource(ctx: _Ctx) -> _Result:
    node = ctx.nodes[ctx.resource_id]
    edges = [EdgeFact(relationship=e.relationship.value, source=e.src, target=e.dst)
             for e in ctx.graph.edges if node.id in (e.src, e.dst)]
    edges.sort(key=lambda e: (e.relationship, e.source, e.target))
    fact = ResourceFact(resource_id=node.id, resource_type=node.resource_type,
                        category=node.category.value, tags=_user_tags(ctx, node.id), edges=edges)
    known = [("graph", f"{len(edges)} relationships touch this resource")]
    return [fact], known, []


def _closure(ctx: _Ctx, direction: str) -> _Result:
    root = ctx.resource_id
    steps = dependency_closure(ctx.graph, [root], direction=direction, max_depth=MAX_DEPENDENCY_DEPTH)
    paths: dict[str, list[str]] = {root: [root]}
    facts = []
    for step in steps:  # BFS order: a step's via is always already pathed
        paths[step.node_id] = paths[step.via] + [step.node_id]
        facts.append(DependencyFact(resource_id=step.node_id, resource_type=ctx.nodes[step.node_id].resource_type,
                                    relationship=step.relationship, depth=step.depth, path=paths[step.node_id]))
    facts.sort(key=lambda f: (f.depth, f.resource_id, f.relationship))
    known = [("graph", f"walked dependency edges up to {MAX_DEPENDENCY_DEPTH} levels; {len(facts)} resources found")]
    return facts, known, []


def _reachable(ctx: _Ctx) -> _Result:
    facts = [ReachableFact(resource_id=e.resource_id, resource_type=e.resource_type, protocol=e.protocol,
                           ports=[e.from_port, e.to_port], source=e.source, resource_ids=[e.via], state=e.state)
             for e in ctx.bundle.exposures]
    reachable = get_internet_reachable_set(ctx.graph)
    covered = {e.resource_id for e in ctx.bundle.exposures}
    for rid in sorted(reachable - covered):
        facts.append(ReachableFact(resource_id=rid, resource_type=ctx.nodes[rid].resource_type, protocol=None,
                                   ports=[], source=None, resource_ids=[], state="reachable"))
    facts = [f for f in facts if _wanted(ctx, f.resource_id)]
    facts.sort(key=lambda f: (f.resource_id, f.state, f.protocol or "", f.ports, f.source or "", f.resource_ids))
    known = [("exposures", f"{len(ctx.bundle.exposures)} ingress exposures evaluated"),
             ("graph", f"{len(reachable)} resources reachable from the internet in the graph")]
    return facts, known, []


def _access(ctx: _Ctx) -> _Result:
    targets: dict[str, set[str]] = {}
    for edge in ctx.graph.edges:
        if edge.relationship.value in ACCESS_RELATIONSHIPS:
            targets.setdefault(edge.src, set()).add(edge.dst)
    entries: dict[str, list[PermissionEntry]] = {}
    for entry in ctx.bundle.permissions:
        entries.setdefault(entry.resource_id, []).append(entry)
    facts = []
    for node in _real_nodes(ctx):
        if node.category.value != "identity" and node.id not in targets:
            continue
        if not _wanted(ctx, node.id):
            continue
        paths = node.base.get("privilege_escalation_paths") or []
        facts.append(AccessFact(resource_id=node.id, resource_ids=sorted(targets.get(node.id, ())),
                                escalation=sorted({str(p) for p in paths}),
                                permissions=[ActionAllow(action=e.action, effect=e.effect,  # type: ignore[arg-type]
                                                         resource_ids=sorted(e.target_ids))
                                             for e in sorted(entries.get(node.id, ()), key=lambda e: (e.action, e.effect))]))
    facts.sort(key=lambda f: f.resource_id)
    known = [("identity_policies", f"{len(facts)} identities with access relationships read from collected policies"),
             ("escalation_paths", "privilege escalation paths are matched from collected identity policy statements"),
             ("action_permissions", f"{sum(len(f.permissions) for f in facts)} action-level allows expanded from collected identity policies")]
    unknown = [(n.topic, n.text, n.resource_id) for n in ctx.bundle.permission_notes if _wanted(ctx, n.resource_id)]
    return facts, known, unknown


def _data(ctx: _Ctx) -> _Result:
    facts = [DataFact(resource_id=l.resource_id, resource_type=l.resource_type,
                      has_recovery_point=l.has_recovery_point,
                      recovery_resource_ids=sorted(l.recovery_resource_ids),
                      recovery_kinds=sorted(l.recovery_kinds))
             for l in ctx.bundle.data if _wanted(ctx, l.resource_id)]
    facts.sort(key=lambda f: (f.resource_type, f.resource_id))
    return facts, [("data_stores", f"{len(facts)} data stores assessed")], []


def _cost(ctx: _Ctx) -> _Result:
    lines = [l for l in ctx.bundle.costs if _wanted(ctx, l.resource_id)]
    facts = [CostFact(resource_id=l.resource_id, resource_type=l.resource_type,
                      monthly_usd=l.monthly_usd, basis=l.basis) for l in lines]
    facts.sort(key=lambda f: (f.resource_type, f.resource_id))
    unknown = [("cost", l.unknown_reason or "price is not available", l.resource_id)
               for l in lines if l.monthly_usd is None]
    priced = [l.monthly_usd for l in lines if l.monthly_usd is not None]
    known = [("pricing", f"{len(priced)} of {len(lines)} resources priced; known monthly total {sum(priced):.2f} USD")]
    return facts, known, unknown


def _live(ctx: _Ctx) -> _Result:
    lines = [l for l in ctx.bundle.uses if _wanted(ctx, l.resource_id)]
    facts = [LiveFact(resource_id=l.resource_id, used=l.used, last_used_at=l.last_used_at,
                      window_days=l.window_days, basis=l.basis) for l in lines]
    facts.sort(key=lambda f: (f.resource_id, f.basis))
    unknown = [(l.unknown_topic or "recent_use", l.unknown_reason, l.resource_id)
               for l in lines if l.unknown_reason]
    known = [("recent_use", f"{len(facts)} resources have a recorded last-used")]
    return facts, known, unknown


def _marks(ctx: _Ctx) -> _Result:
    lines = [l for l in ctx.bundle.tags if _wanted(ctx, l.resource_id)]
    facts = [MarksFact(resource_id=l.resource_id, tags={k: l.tags[k] for k in sorted(l.tags)})
             for l in lines if l.tags is not None]
    facts.sort(key=lambda f: f.resource_id)
    missing: dict[str, int] = {}
    for line in lines:
        if line.tags is None:
            missing[line.resource_type] = missing.get(line.resource_type, 0) + 1
    unknown = [("owner_intent", OWNER_INTENT_REASON)]
    unknown += [(f"tags:{rtype}", f"tags were not collected for {n} {rtype} resource(s)")
                for rtype, n in sorted(missing.items())]
    return facts, [("tags", f"{len(facts)} resources with collected tags")], unknown


_PER_QUESTION: dict[str, Callable[[_Ctx], _Result]] = {
    "inventory": _inventory, "resource": _resource,
    "depends_on": lambda ctx: _closure(ctx, "depends_on"),
    "dependents": lambda ctx: _closure(ctx, "dependents"),
    "reachable": _reachable, "access": _access, "data": _data,
    "cost": _cost, "live": _live, "marks": _marks,
}


def _coverage(question: str, bundle: FactsBundle) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    known: list[tuple[str, ...]] = []
    unknown: list[tuple[str, ...]] = []
    for source in sorted(set(bundle.needs.get(question, ()))):
        status = bundle.collection.get(source)
        if status == "ok":
            known.append((source, "collected ok"))
        elif status is None:
            unknown.append((source, "collection status was not recorded for this snapshot, so it cannot be said to have been checked"))
        else:
            unknown.append((source, f"collection status is '{status}'; what it would show is not in the snapshot"))
    for warning in sorted(set(bundle.warnings)):
        unknown.append(("collector_skipped", str(warning)))
    unknown.extend(_FIXED_UNKNOWN.get(question, ()))
    known.extend((n.topic, n.text) for n in bundle.known.get(question, ()))
    unknown.extend((n.topic, n.text) for n in bundle.unknown.get(question, ()))
    return known, unknown


def _run(question: str, ctx: _Ctx) -> _Result:
    facts, known, unknown = _PER_QUESTION[question](ctx)
    cov_known, cov_unknown = _coverage(question, ctx.bundle)
    return facts, known + cov_known, unknown + cov_unknown


def _baseline(ctx: _Ctx) -> _Result:
    nodes = _real_nodes(ctx)
    counts: dict[str, int] = {"resources": len(nodes), "relationships": len(ctx.graph.edges)}
    for node in nodes:
        key = f"resources:{node.resource_type}"
        counts[key] = counts.get(key, 0) + 1
    for edge in ctx.graph.edges:
        key = f"relationships:{edge.relationship.value}"
        counts[key] = counts.get(key, 0) + 1
    known: list[tuple[str, ...]] = []
    unknown: list[tuple[str, ...]] = []
    results: dict[str, _Result] = {}
    for question in ("inventory", "reachable", "access", "data", "cost", "live", "marks"):
        results[question] = _run(question, ctx)
        known += results[question][1]
        unknown += results[question][2]
    counts["internet_reachable"] = len(get_internet_reachable_set(ctx.graph))
    counts["exposures"] = len(ctx.bundle.exposures)
    access = results["access"][0]
    counts["identities"] = len(access)
    counts["identities_with_escalation_paths"] = sum(1 for f in access if f.escalation)
    data = results["data"][0]
    counts["data_stores"] = len(data)
    counts["data_stores_with_recovery_point"] = sum(1 for f in data if f.has_recovery_point is True)
    counts["data_stores_without_recovery_point"] = sum(1 for f in data if f.has_recovery_point is False)
    counts["data_stores_recovery_unknown"] = sum(1 for f in data if f.has_recovery_point is None)
    cost = results["cost"][0]
    counts["priced_resources"] = sum(1 for f in cost if f.monthly_usd is not None)
    counts["unpriced_resources"] = sum(1 for f in cost if f.monthly_usd is None)
    marks = results["marks"][0]
    counts["resources_with_tags"] = len(marks)
    counts["resources_tags_not_collected"] = sum(1 for l in ctx.bundle.tags if l.tags is None)
    live = results["live"][0]
    counts["last_used_within_window"] = sum(1 for f in live if f.used is True)
    counts["last_used_outside_window"] = sum(1 for f in live if f.used is False)
    counts["last_used_unknown"] = sum(1 for f in live if f.used is None)
    facts = [BaselineFact(topic=t, count=c) for t, c in sorted(counts.items())]
    return facts, known, unknown


def _padded(notes: Sequence[tuple[str, ...]]) -> list[tuple[str, str, Optional[str]]]:
    """Notes are (topic, text) or (topic, text, resource_id); unique and in a stable order."""
    full = {(n[0], n[1], n[2] if len(n) > 2 else None) for n in notes}
    return sorted(full, key=lambda n: (n[0], n[1], n[2] or ""))


def answer(question: str, graph: Graph, bundle: FactsBundle, resource_id: Optional[str] = None) -> ContextResponse:
    """Answer one question from the snapshot graph and the neutral facts bundle."""
    if question not in QUESTIONS:
        raise ValueError(f"unknown question: {question}")
    nodes = {n.id: n for n in graph.nodes}
    if resource_id is not None:
        known_ids = set(nodes)
        for lines in (bundle.tags, bundle.data, bundle.costs, bundle.uses):
            known_ids.update(l.resource_id for l in lines)
        known_ids.update(l.resource_id for l in bundle.exposures)
        if resource_id not in known_ids or (question in RESOURCE_REQUIRED and resource_id not in nodes):
            raise ResourceNotFound("resource not found in this snapshot")
    ctx = _Ctx(graph=graph, bundle=bundle, resource_id=resource_id, nodes=nodes)
    facts, known, unknown = _baseline(ctx) if question == "baseline" else _run(question, ctx)
    return ContextResponse(
        question=question, source=bundle.source, facts=facts,
        known=[KnownItem(topic=t, detail=d, resource_id=r) for t, d, r in _padded(known)],
        unknown=[UnknownItem(topic=t, reason=d, resource_id=r) for t, d, r in _padded(unknown)],
    )
