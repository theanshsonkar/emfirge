"""The door an undo prover gets to a sealed branch: the engine (in client ids) and the branch's records, nothing else.

Why a door and not the branch itself: putting changes back on the engine consumes the branch's state (the engine no
longer holds the changes). So the order is fixed and checked: seal, read the diff (and whatever else reads branch
state), then open this door. Opening it marks the branch spent: from then on Branch.changes(), states_after(), drift()
and copy() raise EngineSpent instead of answering from an engine that was put back. The door sends only to the
engine: it has no way to reach the real account.
"""
from __future__ import annotations

import threading
from typing import Any

from emfirge.core.model import Call, Refs, ResourceRef
from emfirge.core.ports import CannotTell, Catalog, Outcomes

from .baseline import Answer, Baseline, Baselines
from .journal import Entry, Journal
from .overlay import Overlay, State
from .sides import Sides


class EngineSpent(Exception):
    """Branch state was asked for after an undo prover used the engine. Read the diff before proving."""


class ProofDoor:
    def __init__(self, sides: Sides, catalog: Catalog, outcomes: Outcomes | None, overlay: Overlay,
                 baselines: Baselines, journal: Journal, lock: threading.RLock) -> None:
        self._sides, self._catalog, self._outcomes = sides, catalog, outcomes
        self._overlay, self._baselines, self._journal, self._lock = overlay, baselines, journal, lock

    def held(self) -> dict[ResourceRef, State]:
        """Every resource the branch met, with its state at the end of the session."""
        return self._overlay.held()

    def entries(self) -> tuple[Entry, ...]:
        return self._journal.entries()

    def baselines(self, ref: ResourceRef) -> list[Baseline]:
        """The reads of a copied resource taken at copy time (E0 is the engine's answer)."""
        return self._baselines.of(ref)

    def reads(self, ref: ResourceRef) -> list[Call]:
        """The reads that show a resource's state: its baselines' reads when it was copied, else the catalog's."""
        base = self._baselines.of(ref)
        if base:
            return [b.call for b in base]
        return [self._sides.codec.encode(*r) for r in self._catalog.reads_of(ref)]

    def refs(self, call: Call) -> Refs:
        """Which resources a call names, as the branch's own catalog says."""
        return self._catalog.refs(call)

    def send(self, call: Call) -> Answer:
        """`call` (in client ids) to the engine only; the answer in client ids."""
        with self._lock:
            return self._sides.engine_answer(call)

    def opaque(self, call: Call) -> bool:
        """The call's request or answer payload is the customer's data."""
        return self._sides.opaque(call)

    def focus(self, ref: ResourceRef, call: Call, body: Any) -> Any:
        """The part of an answer that is about `ref` (its item, for a list read)."""
        return self._sides.about(ref, call, body)

    def holds(self, ref: ResourceRef, call: Call, body: Any) -> bool | None:
        """True when a list in the answer holds `ref`, False when the answer has lists that could but do not,
        None when the answer has no such list (it says nothing either way)."""
        if self._outcomes is None or not isinstance(body, (dict, list)):
            return None
        try:
            slots = [s for s in self._outcomes.listed(call, body) if ref.type in s.types or ref in s.refs]
        except CannotTell:
            return None
        if not slots:
            return None
        return any(ref in s.refs for s in slots)
