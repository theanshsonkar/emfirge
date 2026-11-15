"""Reach: for each change, what else in the account it affects, by which chain, and how sure that is.

A link "A names B" can be read two ways, and a change is judged with both:

  USES        A names the changed X (directly or through others): A depends on X and breaks or changes with it.
              Followed backwards from X, up to `depth` links. This is the main answer for every change.
  REACHED     X names B: what X acts on (modified, action), what a new X now points at (created), or what loses
              a user (deleted). Followed forwards from X: `depth` links for a change to an existing X (a schedule
              starts a function that writes through its role); one link for a delete (a deleted role takes access
              away from the buckets it names; what those buckets name is not affected) and for a create (a new
              resource has no behaviour yet: what it names is the news, not what those things name in turn).
  DOWNSTREAM  R uses something X reaches: X -> ... -> B <- R. A function that writes into a bucket changes what a
              distribution serves from it. Whether X writes, reads or merely sits next to B cannot be told from
              settings alone, so these are always in the `maybe` list, never in the default report.

Comparing X's links before and after the change (modified or created on the branch) adds:

  NO_LONGER_NAMED  X named B before and does not now (an environment variable dropped or repointed).
  NOW_NAMED        X names B now and did not before.
  OUT_OF_STEP      a repoint: the same field of X named O and now names N. Whatever X reaches that still names O
                   and not N is out of step (the role still allows only the old bucket).
  ON_OLD_TARGET    a repoint: what else uses O keeps using it (the distribution still serves the old bucket).

A chain is as strong as its weakest link. Only strong links are built on: a text or weak link may end a chain but
no chain goes on through it (a probable link is reported; a probable link of a probable link is not). Weak results and
DOWNSTREAM go to `maybe`, so the default report is what the settings show for certain, or as plain text.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Sequence

from emfirge.core.model import Affected, Change, ChangeType, ResourceRef, Unknown

from .index import Edge, ReferenceIndex, Strength
from .vocabulary import Vocabulary

DEFAULT_DEPTH = 3


class Relation(str, Enum):
    USES = 'uses'
    REACHED = 'reached'
    DOWNSTREAM = 'downstream'
    NO_LONGER_NAMED = 'no-longer-named'
    NOW_NAMED = 'now-named'
    OUT_OF_STEP = 'out-of-step'
    ON_OLD_TARGET = 'on-old-target'


# When one resource is reached in several ways, the most telling one is kept.
_PRIORITY = [Relation.OUT_OF_STEP, Relation.NO_LONGER_NAMED, Relation.NOW_NAMED, Relation.USES, Relation.REACHED,
             Relation.ON_OLD_TARGET, Relation.DOWNSTREAM]


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

    def affects(self, changes: Sequence[Change], before: Mapping[ResourceRef, Any],
                after: Mapping[ResourceRef, Any] | None = None) -> GraphReport:
        """before: every resource's state in the account. after: the branch's state of resources it created or
        modified (others are as before; deleted ones are gone)."""
        t = time.perf_counter()
        after = dict(after or {})
        deleted = {c.ref for c in changes if c.type is ChangeType.DELETED}
        old = ReferenceIndex.build(before, self._vocab)
        now_states = {r: s for r, s in before.items() if r not in deleted} | {r: s for r, s in after.items() if r not in deleted}
        now = ReferenceIndex.build(now_states, self._vocab, ghosts={r: before[r] for r in deleted if r in before})
        seconds = round(time.perf_counter() - t, 3)
        reports = tuple(_ChangeJudge(c, old, now, self._depth, before, after).report() for c in changes)
        return GraphReport(reports, seconds, {'before': old.edge_count(), 'after': now.edge_count()})


class _ChangeJudge:
    """Judges one change against the two indexes."""

    def __init__(self, change: Change, old: ReferenceIndex, now: ReferenceIndex, depth: int,
                 before: Mapping[ResourceRef, Any], after: Mapping[ResourceRef, Any]) -> None:
        self.change, self.x = change, change.ref
        self.old, self.now, self.depth = old, now, depth
        self.known_before, self.known_after = self.x in before, self.x in after
        self.unknowns: list[Unknown] = []
        self.unclear: set[tuple[ResourceRef, str]] = set()
        self.found: list[Impact] = []

    def report(self) -> ChangeReport:
        self._check_known()
        self._uses()
        self._reached()
        self._compare()
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
        self.unknowns.append(Unknown(what=what, where='graph', ref=self.x))

    # -- the three directions -----------------------------------------------------------------------------------
    def _uses(self) -> None:
        for ref, chain in _search(self.x, lambda r: [(e.source, e) for e in self.now.named_by(r)], self.depth).items():
            self._add(ref, Relation.USES, chain, _chain_words(chain, backwards=True))

    def _reached(self) -> None:
        deleted = self.change.type is ChangeType.DELETED
        index = self.old if deleted else self.now
        depth = self.depth if self.change.type in (ChangeType.MODIFIED, ChangeType.ACTION) else 1
        for ref, chain in _search(self.x, lambda r: [(e.target, e) for e in index.names(r)], depth).items():
            lead = f'loses a user: {self.x} named it' if deleted else f'{self.x} reaches it'
            self._add(ref, Relation.REACHED, chain, f'{lead} ({_chain_words(chain, backwards=False)})')

    def _downstream(self) -> None:
        if self.change.type is ChangeType.DELETED:
            return
        reached = [i for i in self.found if i.relation is Relation.REACHED and i.strength >= Strength.TEXT]
        for impact in reached:
            for e in _best_per_neighbour((e.source, e) for e in self.now.named_by(impact.ref)):
                if e.source == self.x or any(e.source in (c.source, c.target) for c in impact.chain):
                    continue
                chain = impact.chain + (e,)
                self._add(e.source, Relation.DOWNSTREAM, chain,
                          f'uses {impact.ref}, which {self.x} reaches: may see what the change does there '
                          f'({_edge_words(e)})', firm=False)

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
        value = self.now.leaf_at(self.x, e.path)
        if value is not None and value != self.old.leaf_at(self.x, e.path) and (e.target, value) not in self.unclear:
            self.unclear.add((e.target, value))
            self._unknown(f'{self.x}: {e.path} named {e.target} and now holds {value[:80]!r}, which names nothing '
                          'known in the account (a resource outside what was read, or a mistake)')

    def _repoint(self, old_edge: Edge, new_edge: Edge) -> None:
        o, n = old_edge.target, new_edge.target
        move = f'{self.x} moved {old_edge.path} from {o} to {n}'
        reached = _search(self.x, lambda r: [(e.target, e) for e in self.now.names(r)], self.depth)
        out_of_step = set()
        for ref, chain in reached.items():
            if ref in (o, n):
                continue
            to_old = [e for e in self.now.names(ref) if e.target == o]
            if to_old and not any(e.target == n for e in self.now.names(ref)):
                e = max(to_old, key=lambda e: e.strength)
                out_of_step.add(ref)
                self._add(ref, Relation.OUT_OF_STEP, chain + (e,),
                          f'{move}; this still names {o} and not {n} ({_edge_words(e)})')
        for e in _best_per_neighbour((e.source, e) for e in self.now.named_by(o)):
            if e.source in out_of_step or e.source in (self.x, n):
                continue
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


def _search(start: ResourceRef, step: Callable[[ResourceRef], list[tuple[ResourceRef, Edge]]], depth: int) -> dict[ResourceRef, tuple[Edge, ...]]:
    """The strongest chain (then the shortest) from start to every resource within depth links. A link that is not
    strong may end a chain but is not built on. Cycles are cut: a chain never visits a resource twice."""
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
                    if strength is Strength.STRONG:
                        nxt[other] = new
        frontier = nxt
    return {r: c for r, (_, c) in best.items()}


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
