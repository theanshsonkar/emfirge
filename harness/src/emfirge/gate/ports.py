"""The gate's own plug boundary: proving on the branch that a change can be put back.

Static facts (core.ports.Reversibility, from what the provider publishes) can say "no" for sure, and "yes" only for
a created thing that can be deleted again. A modified resource is "yes" only once someone has actually put it back
on the branch and found it equal to before. That someone is an UndoProver. It is cloud-neutral here; a plug-in or
the branch implements it against its engine.
"""
from __future__ import annotations

from typing import Protocol

from emfirge.core.model import Change, UndoFact


class UndoProver(Protocol):
    """Puts one change back on a copy of the branch and compares the state with the state before the change.

    Returns YES only when every read of the resource, ids and versions included, is equal again; NO with the
    differences in plain words when it is not; UNKNOWN when it could not try (no undo call found, the engine refused).
    It must never touch the real account."""

    def prove(self, change: Change) -> UndoFact: ...
