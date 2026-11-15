"""Reading the resources a proof looks at, on the engine, until their answers stop moving (a bounded wait).

Why wait: an engine, like AWS, finishes some changes after answering (a function 'InProgress', a table 'DELETING').
Comparing too early would call a change that is still landing a difference, or the reverse.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol

from emfirge.branch.baseline import Answer, Baseline
from emfirge.branch.journal import Entry
from emfirge.branch.overlay import State
from emfirge.core.model import Call, Refs, ResourceRef

Snapshot = dict[ResourceRef, tuple[Answer, ...]]
"""Each resource's answers, in the order of Door.reads(ref)."""


class Door(Protocol):
    """What the prover uses of a sealed branch (emfirge.branch.proving.ProofDoor)."""

    def held(self) -> dict[ResourceRef, State]: ...
    def entries(self) -> tuple[Entry, ...]: ...
    def baselines(self, ref: ResourceRef) -> list[Baseline]: ...
    def reads(self, ref: ResourceRef) -> list[Call]: ...
    def refs(self, call: Call) -> Refs: ...
    def send(self, call: Call) -> Answer: ...
    def focus(self, ref: ResourceRef, call: Call, body: Any) -> Any: ...
    def holds(self, ref: ResourceRef, call: Call, body: Any) -> bool | None: ...


@dataclass(frozen=True)
class Timing:
    limit: float = 30.0       # longest wait for answers to stop moving, in seconds
    interval: float = 0.5     # between two rounds of reads
    busy: float = 15.0        # longest retry of an inverse call the engine says is busy
    slack: float = 5.0        # how far the engine's clock may be from ours
    calm: int = 3             # rounds in a row with no change that count as stopped


Moved = Callable[[Snapshot, Snapshot], set[tuple[ResourceRef, int, str]]]
"""(ref, read index, path) of every place two rounds of reads differ."""


@dataclass(frozen=True)
class Settled:
    snapshot: Snapshot
    stable: bool              # `done` held, or the answers stopped moving, before the limit
    seconds: float
    noise: frozenset[tuple[ResourceRef, int, str]] = frozenset()   # places that moved in every round


class Reader:
    def __init__(self, door: Door, timing: Timing, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._door, self._timing, self._sleep, self._clock = door, timing, sleep, clock
        self._calls: dict[ResourceRef, list[Call]] = {}

    def calls(self, ref: ResourceRef) -> list[Call]:
        if ref not in self._calls:
            self._calls[ref] = self._door.reads(ref)
        return self._calls[ref]

    def read(self, refs: Iterable[ResourceRef]) -> Snapshot:
        return {ref: tuple(self._door.send(c) for c in self.calls(ref)) for ref in refs}

    def settle(self, refs: list[ResourceRef], moved: Moved, done: Callable[[Snapshot], bool] = lambda s: False,
               noise: frozenset[tuple[ResourceRef, int, str]] = frozenset(),
               pending: Callable[[Snapshot], bool] = lambda s: False) -> Settled:
        """Read until `done` holds, or nothing moves for `calm` rounds in a row while nothing is `pending` (a table
        that holds still at DELETING is still on its way out), or the limit passes.

        A place that moves in `calm` rounds of one wait, with nothing sent in between, is noise (a presigned URL,
        a clock that ticks on every read). A change landing moves once or twice and then stops."""
        start, streak = self._clock(), 0
        moves: dict[tuple[ResourceRef, int, str], int] = {}
        prev = self.read(refs)
        while not done(prev) and streak < self._timing.calm:
            if self._clock() - start >= self._timing.limit:
                return Settled(prev, False, self._clock() - start, noise)
            self._sleep(self._timing.interval)
            cur = self.read(refs)
            now_moved = moved(prev, cur)
            for place in now_moved:
                moves[place] = moves.get(place, 0) + 1
            noise = noise | frozenset(p for p, n in moves.items() if n >= self._timing.calm)
            streak = streak + 1 if not now_moved - noise and not pending(cur) else 0
            prev = cur
        return Settled(prev, True, self._clock() - start, noise)
