"""Where each resource stands on a branch, and so who answers for it.

Every resource starts `live` (untouched: the real account answers). A change that names it copies it into the engine
first; from then on the engine answers for it. `opaque` is terminal: the copy failed or nobody can copy the type, and
every later call naming it is refused, the same way each time.
"""
from __future__ import annotations

from enum import Enum

from emfirge.core.model import ResourceRef

from .lifecycle import IllegalMove


class State(str, Enum):
    LIVE = 'live'          # not touched: the real account, live
    COPIED = 'copied'      # copied into the engine: the real account's live answer plus the branch's own change
    ABSENT = 'absent'      # the real account does not have it: the engine
    BORN = 'born'          # created on the branch: the engine
    DELETED = 'deleted'    # deleted on the branch: the engine (it says "not found")
    OPAQUE = 'opaque'      # could not be copied: nobody, every call naming it is refused


MOVES: dict[State, frozenset[State]] = {
    State.LIVE: frozenset({State.COPIED, State.ABSENT, State.OPAQUE}),
    State.COPIED: frozenset({State.DELETED}),
    State.ABSENT: frozenset({State.BORN}),
    State.BORN: frozenset({State.DELETED}),
    State.DELETED: frozenset({State.BORN}),
    State.OPAQUE: frozenset(),
}

ENGINE_ANSWERS = frozenset({State.COPIED, State.ABSENT, State.BORN, State.DELETED})
"""States the engine can answer a change for."""

ANSWERED_BY: dict[State, str] = {
    State.LIVE: 'real',
    State.COPIED: 'real, with the branch change laid over',
    State.ABSENT: 'engine',
    State.BORN: 'engine',
    State.DELETED: 'engine',
    State.OPAQUE: 'nobody (refused)',
}


class Overlay:
    """The state of every resource the branch has met. Resources it never met are live."""

    def __init__(self) -> None:
        self._states: dict[ResourceRef, State] = {}
        self._why: dict[ResourceRef, str] = {}
        self._from_real: set[ResourceRef] = set()

    def state(self, ref: ResourceRef) -> State:
        return self._states.get(ref, State.LIVE)

    def why_opaque(self, ref: ResourceRef) -> str:
        return self._why.get(ref, '')

    def move(self, ref: ResourceRef, to: State, why: str = '') -> None:
        now = self.state(ref)
        if to not in MOVES[now]:
            raise IllegalMove(f'{ref} cannot go from {now.value} to {to.value}')
        self._states[ref] = to
        if to is State.OPAQUE:
            self._why[ref] = why
        if to is State.COPIED:
            self._from_real.add(ref)

    def from_real(self) -> frozenset[ResourceRef]:
        """Resources that were copied from the real account (so deleting them is a real deletion)."""
        return frozenset(self._from_real)

    def held(self) -> dict[ResourceRef, State]:
        """Every resource that is not live, with its state."""
        return dict(self._states)

    def held_types(self, states: frozenset[State] = ENGINE_ANSWERS) -> frozenset[str]:
        return frozenset(r.type for r, s in self._states.items() if s in states)

    def changed_anything(self) -> bool:
        """True once the branch holds any resource whose answer differs from the live account's."""
        return any(s in (State.COPIED, State.BORN, State.DELETED) for s in self._states.values())
