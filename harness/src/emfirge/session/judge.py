"""Judge one session's branch: seal -> diff -> settings of the account -> graph -> lenses -> undo facts -> verdict.

Cloud-neutral: every cloud part comes in through Parts, so the pipeline is the same for any cloud and can be tested
with fakes. It never raises for a lens (run_lenses turns a failing lens into an unknown); anything else that fails is
Emfirge's own failure and is raised to the caller (exit 2).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

from emfirge.branch.lifecycle import Stage
from emfirge.core.model import Affected, Change
from emfirge.core.ports import Reversibility
from emfirge.gate import AffectedRule, Decision, UndoProver, decide, undo_facts
from emfirge.graph import Graph, GraphReport
from emfirge.lenses import Lens, LensResult, LensView, run_lenses

from .ports import Held, Reading, StateReader

ProverFactory = Callable[[Sequence[Change]], UndoProver]


@dataclass(frozen=True)
class Parts:
    """The parts a cloud plug-in gives. outside: lenses that run outside tools against the two read-only endpoints;
    they run before the seal, while the branch still answers reads. prover is optional: it is made from the diff
    once everything else has read the branch (a proof may use the branch up); without one, a modified resource stays
    'not yet proven', which the gate turns into ask."""
    reader: StateReader
    graph: Graph
    lenses: Sequence[Lens]
    reversibility: Reversibility
    outside: Sequence[Lens] = ()
    prover: ProverFactory | None = None
    rule: AffectedRule = AffectedRule.STRICT


@dataclass(frozen=True)
class Judgement:
    """The verdict and everything the report shows.
    seconds   time per step after the command ended
    real      how the real account was touched: reads that passed the read-only door, and calls it blocked"""
    decision: Decision
    graph: GraphReport | None
    reading: Reading
    seconds: Mapping[str, float] = field(default_factory=dict)
    real: Mapping[str, int] = field(default_factory=dict)

    @property
    def maybe(self) -> tuple[Affected, ...]:
        if self.graph is None:
            return ()
        return tuple(i.to_affected() for c in self.graph.changes for i in c.maybe)


class _Clock:
    def __init__(self) -> None:
        self.seconds: dict[str, float] = {}

    def lap(self, name: str, since: float) -> float:
        now = time.perf_counter()
        self.seconds[name] = round(self.seconds.get(name, 0.0) + now - since, 3)
        return now


def judge(held: Held, parts: Parts, endpoints: tuple[str, str] = ('', ''),
          env: Mapping[str, str] | None = None) -> Judgement:
    """The whole pipeline for a branch whose session has ended. endpoints: (before, after) for outside lenses."""
    clock = _Clock()
    t = time.perf_counter()
    outside = run_lenses(parts.outside, LensView((), endpoints[0], endpoints[1], dict(env or {}))) \
        if parts.outside else LensResult()
    t = clock.lap('outside_lenses', t)
    held.seal()
    changes = tuple(held.changes())
    t = clock.lap('seal_and_diff', t)
    reading, graph = _affects(parts, held, changes, clock)
    t = time.perf_counter()
    lensed = run_lenses(parts.lenses, LensView(changes)) + outside
    t = clock.lap('lenses', t)
    prover = parts.prover(changes) if parts.prover and changes else None
    undo = undo_facts(changes, parts.reversibility, prover)
    unknowns = (*held.unknowns(), *reading.unknowns, *(graph.unknowns() if graph else ()), *lensed.unknowns)
    decision = decide(changes, undo, lensed.findings, unknowns, graph.affected() if graph else (),
                      affected_rule=parts.rule)
    held.move(Stage.JUDGED)
    clock.lap('gate', t)
    stats = held.stats()
    return Judgement(decision, graph, reading, clock.seconds,
                     {'reads': int(stats.get('real_reads', 0)), 'blocked': int(stats.get('real_blocked', 0))})


def _affects(parts: Parts, held: Held, changes: tuple[Change, ...], clock: _Clock) -> tuple[Reading, GraphReport | None]:
    """The account's settings around the changes, and what the changes affect. Nothing is read when nothing changed."""
    if not changes:
        return Reading({}), None
    t = time.perf_counter()
    reading = parts.reader.before(changes)
    after = parts.reader.after(held.states_after())
    t = clock.lap('reader', t)
    graph = parts.graph.affects(changes, reading.states, after)
    clock.lap('graph', t)
    return reading, graph
