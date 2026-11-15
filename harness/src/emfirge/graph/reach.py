"""Reach: for each change, what else in the account it affects, by which chain, and how sure that is.

A link "A names B" is read in two directions:

  USES     A names the changed X (directly or through others): A depends on X and breaks or changes with it.
           Followed backwards from X, up to `depth` links. This is the main answer for every change.
  REACHED  X names B: what X acts on, what a new X points at, or what loses a user when X goes. Followed forwards.

What the DEFAULT report holds, by kind of change (the rule; everything else found goes to `maybe`):

  deleted   who uses X; and, one link forward, what X named (it loses a user: a deleted role takes access away).
  created   who names X now; and, one link forward, what X names (a new resource has no behaviour yet).
  action    who uses X; and what X reaches, `depth` links forward (X runs: a started schedule runs a function that
            writes through its role).
  modified  who uses X, and what the change did to X's references:
              * no changed field holds a reference (a memory size, a state flag): forward reach is not news. The
                report is who uses X. What X reaches goes to `maybe`.
              * a changed field holds a reference: the references it lost and gained, and what the new references
                reach. A repoint (one field moved from O to N) adds what X reaches that still names O and not N
                (out of step), and what else uses O (on the old target). An exact reference that was dropped (an id
                removed from a rule) adds the users of what it named: they relied on the pairing that was undone.

Two more relations, for every kind of change:

  THROUGH     R names the deleted X (or a repoint's old target O) and exactly one other resource T, under a different
              field, and nothing else uses R: R is a pipe between them (a subscription from a topic to a queue, a
              mapping from a queue to a function), so T is affected at the far end. A resource that names many
              things, names both under one field (a role's list of grants), or is itself used, is not a pipe. A
              pipe stops carrying only when an end goes or is moved, so a modify of X does not reach through it.
  DOWNSTREAM  R uses something X reaches (X -> ... -> B <- R): a distribution serving a bucket a function writes.
              Whether X writes, reads or only sits next to B cannot be told from settings: always `maybe`.

A chain is as strong as its weakest link, and only strong links are built on. Two resources that name each other
(a policy and the roles it is attached to, each listing the other) give no direction: beyond the first link, a chain
does not continue across such a pair. Weak findings go to `maybe`.
Duplicates of one resource under different ids are folded by the index (ReferenceIndex.canonical).

The index of the account before is built once and kept (keyed by a digest of the states); the index after is
derived from it, reading again only what changed.
"""
from __future__ import annotations

import hashlib
import pickle
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from emfirge.core.model import Affected, Change, ChangeType, ResourceRef, Unknown

from .fields import changed_paths, under
from .index import Edge, ReferenceIndex, Strength
from .vocabulary import Vocabulary

DEFAULT_DEPTH = 3


class Relation(str, Enum):
    USES = 'uses'
    THROUGH = 'through'
    REACHED = 'reached'
    DOWNSTREAM = 'downstream'
    NO_LONGER_NAMED = 'no-longer-named'
    NOW_NAMED = 'now-named'
    BEHIND_LOST_LINK = 'behind-lost-link'
    OUT_OF_STEP = 'out-of-step'
    ON_OLD_TARGET = 'on-old-target'


# When one resource is reached in several ways, the most telling one is kept.
_PRIORITY = [Relation.OUT_OF_STEP, Relation.NO_LONGER_NAMED, Relation.NOW_NAMED, Relation.USES, Relation.THROUGH,
             Relation.BEHIND_LOST_LINK, Relation.REACHED, Relation.ON_OLD_TARGET, Relation.DOWNSTREAM]


@dataclass(frozen=True)
class Impact:
    """One affected resource for one change. chain: the edges from the changed resource (origin) out to ref."""
    ref: ResourceRef
    origin: ResourceRef
    relation: Relation
    strength: Strength
    chain: tuple[Edge, ...]
    because: str
    firm: bool = True                 # False: shown apart, in `maybe`

    @property
    def via(self) -> tuple[ResourceRef, ...]:
        """The resources between the changed one and ref, in chain order."""
        nodes: list[ResourceRef] = []
        for e in self.chain:
            for r in (e.source, e.target):
                if r not in nodes and r not in (self.origin, self.ref):
                    nodes.append(r)
        return tuple(nodes)

    def to_affected(self) -> Affected:
        return Affected(ref=self.ref, because=self.because, via=self.via, strength=self.strength.label)


@dataclass(frozen=True)
class ChangeReport:
    change: Change
    affected: tuple[Impact, ...]
    maybe: tuple[Impact, ...]
    unknowns: tuple[Unknown, ...]


@dataclass(frozen=True)
class GraphReport:
    changes: tuple[ChangeReport, ...]
    index_seconds: float = 0.0
    edges: Mapping[str, int] = field(default_factory=dict)

    def affected(self) -> list[Affected]:
        return [i.to_affected() for c in self.changes for i in c.affected]

    def unknowns(self) -> list[Unknown]:
        return [u for c in self.changes for u in c.unknowns]


class Graph:
    """What a set of changes affects, from the account's settings before and the branch's settings after."""

    def __init__(self, vocabulary: Vocabulary, depth: int = DEFAULT_DEPTH) -> None:
        self._vocab = vocabulary
        self._depth = depth
        self._kept: tuple[str, ReferenceIndex] | None = None     # the last account index, by digest of its states

    def index(self, before: Mapping[ResourceRef, Any]) -> ReferenceIndex:
        """The index of the account's states, built once per distinct account state."""
        digest = _digest(before)
        if digest is not None and self._kept is not None and self._kept[0] == digest:
            return self._kept[1]
        built = ReferenceIndex.build(before, self._vocab)
        self._kept = (digest, built) if digest is not None else None
        return built

    def affects(self, changes: Sequence[Change], before: Mapping[ResourceRef, Any],
                after: Mapping[ResourceRef, Any] | None = None) -> GraphReport:
        """before: every resource's state in the account. after: the branch's state of resources it created or
        modified (others are as before; deleted ones are gone)."""
        t = time.perf_counter()
        after = dict(after or {})
        deleted = {c.ref for c in changes if c.type is ChangeType.DELETED}
        old = self.index(before)
        now = old.with_changes({r: s for r, s in after.items() if r not in deleted}, deleted)
        seconds = round(time.perf_counter() - t, 3)
        reports = tuple(_ChangeJudge(c, old, now, self._depth, before, after).report() for c in changes)
        return GraphReport(reports, seconds, {'before': old.edge_count(), 'after': now.edge_count()})


def _digest(states: Mapping[ResourceRef, Any]) -> str | None:
    try:
        return hashlib.sha256(pickle.dumps(states, protocol=pickle.HIGHEST_PROTOCOL)).hexdigest()
    except (pickle.PicklingError, TypeError, AttributeError):
        return None


class _ChangeJudge:
    """Judges one change against the two indexes."""

    def __init__(self, change: Change, old: ReferenceIndex, now: ReferenceIndex, depth: int,
                 before: Mapping[ResourceRef, Any], after: Mapping[ResourceRef, Any]) -> None:
        self.change, self.x = change, now.canonical(change.ref)
        self.old, self.now, self.depth = old, now, depth
        self.known_before, self.known_after = change.ref in before, change.ref in after
        self.changed = changed_paths(before[change.ref], after[change.ref]) if self.known_before and self.known_after else set()
        self.unknowns: list[Unknown] = []
        self.unclear: set[tuple[ResourceRef, str]] = set()
        self.found: list[Impact] = []

    def report(self) -> ChangeReport:
        self._check_known()
        self._uses()
        self._reached()
        self._compare()
        self._through()
        self._downstream()
        kept = _keep_best(self.found)
        return ChangeReport(self.change, tuple(i for i in kept if i.firm), tuple(i for i in kept if not i.firm), tuple(self.unknowns))

    # -- what is known ------------------------------------------------------------------------------------------
    def _check_known(self) -> None:
        kind = self.change.type
        if not self.known_before and not self.known_after:
            self._unknown(f'{self.x}: no settings are known for it, so what it affects cannot be told')
        elif kind in (ChangeType.CREATED, ChangeType.MODIFIED) and not self.known_after:
            self._unknown(f'{self.x}: its new settings are not known, so what it now names cannot be told')

    def _unknown(self, what: str) -> None:
        self.unknowns.append(Unknown(what=what, where='graph', ref=self.change.ref))

    # -- the two directions -------------------------------------------------------------------------------------
    def _uses(self) -> None:
        for ref, chain in _search(self.x, self._backward(self.now), self.depth, self._mutual(self.now)).items():
            self._add(ref, Relation.USES, chain, _chain_words(chain, backwards=True))

    def _reached(self) -> None:
        kind = self.change.type
        index = self.old if kind is ChangeType.DELETED else self.now
        depth = self.depth if kind in (ChangeType.MODIFIED, ChangeType.ACTION) else 1
        for ref, chain in _search(self.x, self._forward(index), depth, self._mutual(index)).items():
            lead = f'loses a user: {self.x} named it' if kind is ChangeType.DELETED else f'{self.x} reaches it'
            news = kind is not ChangeType.MODIFIED or under(chain[0].path, self.changed)
            self._add(ref, Relation.REACHED, chain, f'{lead} ({_chain_words(chain, backwards=False)})',
                      firm=None if news else False)

    def _downstream(self) -> None:
        if self.change.type is ChangeType.DELETED:
            return
        reached = [i for i in self.found if i.relation is Relation.REACHED and i.strength >= Strength.TEXT]
        for impact in reached:
            for e in _best_per_neighbour((e.source, e) for e in self.now.named_by(impact.ref)):
                if e.source == self.x or any(e.source in (c.source, c.target) for c in impact.chain):
                    continue
                self._add(e.source, Relation.DOWNSTREAM, impact.chain + (e,),
                          f'uses {impact.ref}, which {self.x} reaches: may see what the change does there '
                          f'({_edge_words(e)})', firm=False)

    def _through(self) -> None:
        """Pipes: a direct user of X (or of the old target) that leads to exactly one other resource (see notes)."""
        deleted = self.change.type is ChangeType.DELETED
        direct = [i for i in self.found if i.firm and ((deleted and i.relation is Relation.USES and len(i.chain) == 1)
                                                        or i.relation is Relation.ON_OLD_TARGET)]
        for impact in direct:
            pipe, near = impact.ref, impact.chain[-1].target
            if impact.chain[-1].source != pipe or self._is_used(pipe, near):
                continue
            ends = {e.target: e for e in _best_per_neighbour((e.target, e) for e in self.now.names(pipe)) if e.strength is Strength.STRONG}
            if len(ends) != 2 or near not in ends:
                continue
            far = next(t for t in ends if t != near)
            if far == self.x or _field(ends[far].path) == _field(ends[near].path):
                continue
            self._add(far, Relation.THROUGH, impact.chain + (ends[far],),
                      f'{pipe} connects {near} to it, and {pipe} {impact.relation.value.replace("-", " ")} '
                      f'({_edge_words(ends[far])})')

    def _is_used(self, ref: ResourceRef, near: ResourceRef) -> bool:
        return any(e.strength is Strength.STRONG and e.source not in (near, self.x) for e in self.now.named_by(ref))

    def _mutual(self, index: ReferenceIndex) -> Callable[[ResourceRef, ResourceRef], bool]:
        return lambda a, b: any(e.target == b and e.strength is Strength.STRONG for e in index.names(a)) and \
            any(e.target == a and e.strength is Strength.STRONG for e in index.names(b))

    def _backward(self, index: ReferenceIndex) -> Callable[[ResourceRef], list[tuple[ResourceRef, Edge]]]:
        return lambda r: [(e.source, e) for e in index.named_by(r)]

    def _forward(self, index: ReferenceIndex) -> Callable[[ResourceRef], list[tuple[ResourceRef, Edge]]]:
        return lambda r: [(e.target, e) for e in index.names(r)]

    # -- before and after ---------------------------------------------------------------------------------------
    def _compare(self) -> None:
        if not (self.known_before and self.known_after) or self.change.type is ChangeType.DELETED:
            return
        before = {(e.target, e.path): e for e in self.old.names(self.x)}
        after = {(e.target, e.path): e for e in self.now.names(self.x)}
        named_before, named_after = {t for t, _ in before}, {t for t, _ in after}
        repoints: list[tuple[Edge, Edge]] = []
        for (target, path), e in before.items():
            if target in named_after:
                continue
            moved = [_repointed(a) for (t, p), a in after.items() if p == path and t not in named_before]
            e = _repointed(e) if moved else e
            repoints += [(e, a) for a in moved]
            if not moved:
                self._value_now_names_nothing(e)
                self._behind_lost_link(e)
            self._add(target, Relation.NO_LONGER_NAMED, (e,), f'{self.x} no longer names it (was {_edge_words(e)})')
        moved_to = {a.target: a for _, a in repoints}
        for (target, path), a in after.items():
            if target not in named_before:
                a = moved_to.get(target, a)
                self._add(target, Relation.NOW_NAMED, (a,), f'{self.x} now names it ({_edge_words(a)})')
        for old_edge, new_edge in repoints:
            self._repoint(old_edge, new_edge)

    def _value_now_names_nothing(self, e: Edge) -> None:
        """One unknown per (old target, new value): the same setting often shows in several reads."""
        value = self.now.leaf_at(self.change.ref, e.path)
        if value is not None and value != self.old.leaf_at(self.change.ref, e.path) and (e.target, value) not in self.unclear:
            self.unclear.add((e.target, value))
            self._unknown(f'{self.x}: {e.path} named {e.target} and now holds {value[:80]!r}, which names nothing '
                          'known in the account (a resource outside what was read, or a mistake)')

    def _behind_lost_link(self, lost: Edge) -> None:
        """An exact reference (an id, an own address) dropped from X: the users of its target relied on that pairing."""
        if lost.how != 'exact':
            return
        for e in _best_per_neighbour((e.source, e) for e in self.now.named_by(lost.target)):
            if e.source != self.x:
                self._add(e.source, Relation.BEHIND_LOST_LINK, (lost, e),
                          f'{self.x} no longer names {lost.target}, which this uses ({_edge_words(e)})')

    def _repoint(self, old_edge: Edge, new_edge: Edge) -> None:
        o, n = old_edge.target, new_edge.target
        move = f'{self.x} moved {old_edge.path} from {o} to {n}'
        out_of_step = set()
        for ref, chain in _search(self.x, self._forward(self.now), self.depth).items():
            if ref in (o, n):
                continue
            to_old = [e for e in self.now.names(ref) if e.target == o]
            if to_old and not any(e.target == n for e in self.now.names(ref)):
                e = max(to_old, key=lambda e: e.strength)
                out_of_step.add(ref)
                self._add(ref, Relation.OUT_OF_STEP, chain + (e,), f'{move}; this still names {o} and not {n} ({_edge_words(e)})')
        for e in _best_per_neighbour((e.source, e) for e in self.now.named_by(o)):
            if e.source not in out_of_step and e.source not in (self.x, n):
                self._add(e.source, Relation.ON_OLD_TARGET, (old_edge, e), f'{move}; this still uses {o} ({_edge_words(e)})')

    def _add(self, ref: ResourceRef, relation: Relation, chain: tuple[Edge, ...], because: str, firm: bool | None = None) -> None:
        if ref == self.x or not chain:
            return
        strength = min(e.strength for e in chain)
        if firm is None:
            firm = strength >= Strength.TEXT
        self.found.append(Impact(ref, self.x, relation, strength, chain, because, firm))


def _repointed(e: Edge) -> Edge:
    """The same field of the changed resource named one resource before and another after: whatever the shape of
    the value, that field holds resource names. The link is as sure as an exact id."""
    return Edge(e.source, e.target, Strength.STRONG, f'{e.how}, field repointed', e.path, e.snippet)


def _search(start: ResourceRef, step: Callable[[ResourceRef], list[tuple[ResourceRef, Edge]]], depth: int,
            mutual: Callable[[ResourceRef, ResourceRef], bool] = lambda a, b: False) -> dict[ResourceRef, tuple[Edge, ...]]:
    """The strongest chain (then the shortest) from start to every resource within depth links. A link that is not
    strong, or a link beyond the first between two resources that name each other, may end a chain but is not built
    on. Cycles are cut: a chain never visits a resource twice."""
    best: dict[ResourceRef, tuple[Strength, tuple[Edge, ...]]] = {}
    frontier: dict[ResourceRef, tuple[Edge, ...]] = {start: ()}
    for _ in range(depth):
        nxt: dict[ResourceRef, tuple[Edge, ...]] = {}
        for node, chain in frontier.items():
            on_chain = {start} | {r for e in chain for r in (e.source, e.target)}
            for edge in _best_per_neighbour(step(node)):
                other = edge.source if edge.target == node else edge.target
                if other in on_chain:
                    continue
                new = chain + (edge,)
                strength = min(e.strength for e in new)
                if other not in best or strength > best[other][0]:
                    best[other] = (strength, new)
                    if strength is Strength.STRONG and not (chain and mutual(node, other)):
                        nxt[other] = new
        frontier = nxt
    return {r: c for r, (_, c) in best.items()}


def _field(path: str) -> str:
    """The key a value sits under: 'a.b[0].Endpoint' -> 'Endpoint'; packed and list parts ignored."""
    last = path.replace('<', '.').replace('>', '').split('.')[-1]
    return last.split('[', 1)[0]


def _best_per_neighbour(pairs: Iterable[tuple[ResourceRef, Edge]]) -> list[Edge]:
    best: dict[ResourceRef, Edge] = {}
    for other, e in pairs:
        if other not in best or e.strength > best[other].strength:
            best[other] = e
    return list(best.values())


def _rank(i: Impact) -> tuple[int, int, int]:
    return _PRIORITY.index(i.relation), -i.strength, len(i.chain)


def _keep_best(found: list[Impact]) -> list[Impact]:
    """At most one firm and one loose impact per resource. The firm one is the most telling relation, then the
    strongest, then the shortest chain. A loose one is kept beside it only when it says something more telling (the
    function still reaches the table through its role, AND its settings no longer name the table)."""
    by_ref: dict[ResourceRef, list[Impact]] = {}
    for i in found:
        by_ref.setdefault(i.ref, []).append(i)
    kept = []
    for items in by_ref.values():
        firm = min((i for i in items if i.firm), key=_rank, default=None)
        loose = min((i for i in items if not i.firm), key=_rank, default=None)
        kept += [i for i in (firm, loose) if i is not None and (i is firm or firm is None or _rank(i)[0] < _rank(firm)[0])]
    return sorted(kept, key=lambda i: (_rank(i), str(i.ref)))


def _edge_words(e: Edge) -> str:
    return f'{e.source} names {e.target} at {e.path}, {e.how}: {e.snippet!r}'


def _chain_words(chain: tuple[Edge, ...], backwards: bool) -> str:
    if len(chain) == 1:
        return _edge_words(chain[0])
    order = reversed(chain) if backwards else iter(chain)
    return '; then '.join(_edge_words(e) for e in order)
