"""BranchUndoProver: gate.ports.UndoProver for AWS. It puts a sealed branch's changes back on the engine, re-reads,
and compares with the reads taken when each resource was copied.

  1 Which calls: every successful changing call in the journal that named a created or modified resource. Deleted
    resources and actions are not tried (their static fact stands). Changes made by the same call are proven
    together: they come back together or not at all.
  2 The state at the end of the session is read until it stops moving (it tells clocks, and shows what each call set).
  3 Each call is planned (plan.py) and run (inverse.py), newest first, on the engine only.
  4 The reads are taken again until they stop moving or match. Then, per change:
      yes      every inverse ran, every read of every resource in the change equals its read at copy time (a
               created resource is gone), and nothing else the session touched differs.
      no       a read differs: the fields are named.
      unknown  a call could not be planned or was refused, a resource has no reads to compare, or the answers did
               not stop moving.

The proof consumes the engine. The branch hands over its engine once (Branch.begin_proof) and refuses to answer for
its state afterwards, so the diff must be read first. The facts are made on the first prove() call and kept.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from emfirge.branch import Branch
from emfirge.branch.baseline import Answer
from emfirge.branch.journal import Entry
from emfirge.branch.overlay import State
from emfirge.core.model import Call, Change, ChangeType, ResourceRef, Undo, UndoFact

from ..codec import AwsCodec
from .compare import Difference, Window, compare
from .inverse import Runner
from .model import MISSING, Models
from .observe import Door, Reader, Snapshot, Timing
from .plan import NoPlan, Read, View, mentions, plan

TRIED = (ChangeType.CREATED, ChangeType.MODIFIED)
NOT_TRIED = {ChangeType.DELETED: 'a deleted resource is not put back on the branch: its static fact stands',
             ChangeType.ACTION: 'a call that left no trace in any read cannot be proven by putting it back'}


@dataclass
class Group:
    """Changes made by the same calls, proven together."""
    refs: set[ResourceRef]
    entries: list[Entry] = field(default_factory=list)
    blocked: str = ''          # why the group is not tried
    failures: list[str] = field(default_factory=list)


def prover_for(branch: Branch, changes: Sequence[Change], codec: AwsCodec, timing: Timing = Timing()) -> 'BranchUndoProver':
    """The prover for a sealed branch whose diff (`changes`) was read. From here on the branch's state reads fail."""
    return BranchUndoProver(branch.begin_proof(), changes, codec, timing)


class BranchUndoProver:
    def __init__(self, door: Door, changes: Sequence[Change], codec: AwsCodec, timing: Timing = Timing(),
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time) -> None:
        self._door, self._changes, self._codec, self._timing, self._clock = door, tuple(changes), codec, timing, clock
        self._models = Models(codec)
        self._reader = Reader(door, timing, sleep, clock)
        self._runner = Runner(door, codec, timing, sleep, clock)
        self._facts: dict[ResourceRef, UndoFact] | None = None
        self._noise: frozenset[tuple[ResourceRef, int, str]] = frozenset()   # learned while settling
        self._side: set[ResourceRef] = set()      # changed, but named by no call: a side effect of other calls
        self.seconds = 0.0

    def prove(self, change: Change) -> UndoFact:
        if self._facts is None:
            start = self._clock()
            self._facts = self._prove_all()
            self.seconds = self._clock() - start
        return self._facts.get(change.ref) or UndoFact(change.ref, Undo.UNKNOWN,
                                                       ('this change was not in the diff the prover was given',))

    # ------------------------------------------------------------------ the whole proof
    def _prove_all(self) -> dict[ResourceRef, UndoFact]:
        held = self._door.held()
        tried = {c.ref: c for c in self._changes if c.type in TRIED}
        facts = {c.ref: UndoFact(c.ref, Undo.UNKNOWN, (NOT_TRIED[c.type],)) for c in self._changes if c.ref not in tried}
        groups = self._groups(tried, {c.ref for c in self._changes if c.type is ChangeType.DELETED})
        watched = [r for r, s in held.items() if s is State.COPIED or (r in tried and s is State.BORN)]
        end = self._reader.settle(watched, self._moved)
        self._noise = end.noise
        born = {r for r in tried if held.get(r) is State.BORN}
        start = self._clock()
        self._undo(groups, end.snapshot, born)
        window = lambda: Window(start, self._clock(), self._timing.slack)
        leaving = [r for g in groups if not g.blocked and not g.failures for r in g.refs & born]
        after = self._reader.settle(watched, self._moved, lambda s: self._clean(s, end.snapshot, tried, window()),
                                    end.noise, lambda s: any(not self._gone(r, end.snapshot, s)[0] for r in leaving))
        self._noise = after.noise
        for group in groups:
            for ref in group.refs:
                facts[ref] = self._fact(ref, group, end.snapshot, after.snapshot, after.stable, born, window())
        return facts

    def _groups(self, tried: dict[ResourceRef, Change], deleted: set[ResourceRef]) -> list[Group]:
        """Union of changes over the journal entries they share. A group sharing a call with a deleted resource is
        blocked: that call also deleted something, and deletions are not put back. (A resource a call named but left
        no trace on is compared like any other copied resource, see _collateral.)"""
        groups = [Group({r}) for r in tried]
        for e in (e for e in self._door.entries() if e.succeeded):
            named = set(e.refs) | set(e.born)
            mine = [g for g in groups if g.refs & named]
            if not mine:
                continue
            merged = Group(set().union(*(g.refs for g in mine)), [x for g in mine for x in g.entries] + [e],
                           next((g.blocked for g in mine if g.blocked), ''))
            merged.entries.sort(key=lambda x: x.n)
            if named & deleted and not merged.blocked:
                merged.blocked = (f'{e.call} also deleted {", ".join(sorted(str(r) for r in named & deleted))}, '
                                  'which is not put back on the branch')
            groups = [g for g in groups if all(g is not m for m in mine)] + [merged]
        self._side = {r for g in groups if not g.entries for r in g.refs}
        return groups

    def _undo(self, groups: list[Group], end: Snapshot, born: set[ResourceRef]) -> None:
        """Put back every call of every group that is tried, newest first across the whole session."""
        todo = {e.n: (e, g) for g in groups if not g.blocked for e in g.entries}
        creators = {r: next(e.n for e in g.entries if r in e.refs or r in e.born)
                    for g in groups if not g.blocked for r in g.refs & born}
        for n in sorted(todo, reverse=True):
            e, group = todo[n]
            if group.failures:
                continue
            try:
                p = plan(e, self._view(e, None), self._view(e, end), self._models, self._names)
            except NoPlan as x:
                if not self._superseded(e, group, born, creators):
                    group.failures.append(f'{e.call} could not be planned: {x}')
                continue
            for step in p.steps:
                ran = self._runner.run(step, frozenset(e.refs) | frozenset(e.born))
                if not ran.ok:
                    group.failures.append(f'{e.call} ({p.strategy}): {ran.why}')
                    break

    @staticmethod
    def _superseded(e: Entry, group: Group, born: set[ResourceRef], creators: dict[ResourceRef, int]) -> bool:
        """A later call on a resource created on the branch needs no undo of its own: deleting the resource takes
        it back. Not so for the call that created it, or a call that also named a resource that stays."""
        named = (set(e.refs) | set(e.born)) & group.refs
        return bool(named) and named <= born and all(creators[r] != e.n for r in named)

    def _names(self, service: str, operation: str, args: dict) -> tuple[ResourceRef, ...]:
        try:
            return self._door.refs(self._codec.encode(service, operation, args)).primary
        except Exception:   # args that cannot be written as a request name nothing
            return ()

    def _view(self, e: Entry, snapshot: Snapshot | None) -> View:
        """The reads of the resources `e` named, parsed: at copy time (snapshot None) or from `snapshot`."""
        reads = []
        for ref in dict.fromkeys(e.refs + e.born):
            calls = self._reader.calls(ref)
            if snapshot is None:
                answers: Iterable[Answer] = (b.e0 for b in self._door.baselines(ref))
            else:
                answers = snapshot.get(ref, ())
            for call, answer in zip(calls, answers):
                reads.append(Read(call.operation, self._models.parsed(call, answer), listed=not call.params))
        ids = tuple(r.id for r in e.refs + e.born) + tuple(
            v for v in self._models.identifying(e.service, e.operation, dict(e.params)).values() if isinstance(v, str))
        return View(tuple(r for r in reads if r.body is not MISSING), ids)

    # ------------------------------------------------------------------ comparing
    def _moved(self, a: Snapshot, b: Snapshot) -> set[tuple[ResourceRef, int, str]]:
        """Where two rounds of reads differ, apart from each read's noise at copy time (status only, for reads
        without a baseline)."""
        out = set()
        for ref, answers in b.items():
            base = self._door.baselines(ref)
            for i, (x, y) in enumerate(zip(a.get(ref, ()), answers)):
                if x.status != y.status or i >= len(base):
                    out |= {(ref, i, '(status)')} if x.status != y.status else set()
                    continue
                focus = self._focus(ref, base[i].call)
                diffs = compare('', x, None, y, focus, base[i].noise, frozenset(), Window(0, 0)).differences
                out |= {(ref, i, d.path) for d in diffs}
        return out

    def _focus(self, ref: ResourceRef, call: Call) -> Callable[[object], object]:
        return lambda body: self._door.focus(ref, call, body)

    def _diffs(self, ref: ResourceRef, end: Snapshot, now: Snapshot, window: Window,
               set_names: frozenset[str]) -> tuple[list[Difference], list[Difference]]:
        """(differences, clocks) of a copied resource against its reads at copy time."""
        real, clocks = [], []
        e1s = end.get(ref, ())
        for i, b in enumerate(self._door.baselines(ref)):
            learned = frozenset(p for r, j, p in self._noise if r == ref and j == i)
            out = compare(b.call.operation, b.e0, e1s[i] if i < len(e1s) else None, now[ref][i],
                          self._focus(ref, b.call), b.noise | learned, set_names, window)
            real += out.differences
            clocks += out.clocks
        return real, clocks

    def _gone(self, ref: ResourceRef, end: Snapshot, now: Snapshot) -> tuple[bool, int]:
        """(no read shows it any more, how many reads showed it at the end of the session and do not now)."""
        evidence = 0
        for call, e1, n in zip(self._reader.calls(ref), end.get(ref, ()), now.get(ref, ())):
            then, after = self._shows(ref, call, e1), self._shows(ref, call, n)
            if after is True:
                return False, evidence
            evidence += then is True and after is False
        return True, evidence

    def _shows(self, ref: ResourceRef, call: Call, answer: Answer) -> bool | None:
        """True: the answer shows the resource; False: it shows it is not there; None: it says neither. An answer
        that does not mention the resource's id says nothing (an empty list of its exports answers 'ok' either way)."""
        if not answer.ok:
            return False
        held = self._door.holds(ref, call, answer.body)
        if held is not None:
            return held
        return True if call.params and mentions(answer.body, (ref.id,)) else None

    def _set_names(self, refs: set[ResourceRef]) -> frozenset[str]:
        """Names of every member the session's calls on these resources set: such a field is never a clock."""
        out: set[str] = set()
        for e in self._door.entries():
            if (set(e.refs) | set(e.born)) & refs:
                out |= _names_in(e.params)
        return frozenset(out)

    def _clean(self, now: Snapshot, end: Snapshot, tried: dict[ResourceRef, Change], window: Window) -> bool:
        names = self._set_names(set(tried))
        for ref in now:
            if ref in tried and tried[ref].type is ChangeType.CREATED:
                if not self._gone(ref, end, now)[0]:
                    return False
            elif self._diffs(ref, end, now, window, names)[0]:
                return False
        return True

    # ------------------------------------------------------------------ the fact
    def _fact(self, ref: ResourceRef, group: Group, end: Snapshot, now: Snapshot, stable: bool,
              born: set[ResourceRef], window: Window) -> UndoFact:
        if group.blocked:
            return UndoFact(ref, Undo.UNKNOWN, (group.blocked,))
        names = self._set_names(group.refs)
        reasons, differs, reads, clocks = [], [], 0, []
        for r in sorted(group.refs, key=str):
            if r in born:
                gone, evidence = self._gone(r, end, now)
                reads += evidence
                if not gone:
                    differs.append(f'{r} is still there after its creation was put back')
                elif not evidence:
                    reasons.append(f'no read of {r} showed it, so its going cannot be seen')
                continue
            if not self._door.baselines(r):
                reasons.append(f'{r} has no reads taken at copy time to compare with')
                continue
            d, c = self._diffs(r, end, now, window, names)
            reads += len(self._door.baselines(r))
            differs += [f'{r}: {x}' for x in d]
            clocks += c
        differs += self._collateral(group, end, now, window)
        if group.failures:
            return UndoFact(ref, Undo.UNKNOWN, tuple(group.failures + differs[:8]))
        if differs and not stable:
            return UndoFact(ref, Undo.UNKNOWN, (f'the answers were still changing after {self._timing.limit:.0f} s',
                                                *differs[:8]))
        if differs:
            return UndoFact(ref, Undo.NO, tuple(['put back on the branch, but it does not come back the same: '
                                                 + '; '.join(differs[:12])]))
        if reasons:
            return UndoFact(ref, Undo.UNKNOWN, tuple(reasons))
        note = f' (times that move on every write: {", ".join(sorted({f"{x.read}.{x.path}" for x in clocks}))})' if clocks else ''
        return UndoFact(ref, Undo.YES, (f'put back on the branch and compared: {reads} reads, no difference{note}',))

    def _collateral(self, group: Group, end: Snapshot, now: Snapshot, window: Window) -> list[str]:
        """Differences on copied resources outside the group that every put-back must leave as they were: those the
        session did not change (or named with no trace), and those it changed only as a side effect of its calls
        (named by none of them: putting back the calls must take the side effect back too)."""
        tried = {c.ref for c in self._changes if c.type in TRIED} - self._side
        out = []
        for r in now:
            if r not in tried and r not in group.refs and self._door.held().get(r) is State.COPIED:
                d, _ = self._diffs(r, end, now, window, frozenset())
                out += [f'{r} (not a change of the session that was put back): {x}' for x in d]
        return out


def _names_in(o: object) -> set[str]:
    if isinstance(o, dict):
        return set(o) | {n for v in o.values() for n in _names_in(v)}
    if isinstance(o, list):
        return {n for v in o for n in _names_in(v)}
    return set()
