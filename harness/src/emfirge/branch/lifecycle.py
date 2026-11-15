"""The life of one branch: open -> sealed -> judged -> verified, or discarded on the way.

One table says which moves are legal; anything else raises, so a bug can never, say, accept calls on a branch whose
diff was already judged.
"""
from __future__ import annotations

from enum import Enum


class Stage(str, Enum):
    OPEN = 'open'            # accepting calls
    SEALED = 'sealed'        # the session ended; nothing more is accepted; the diff is fixed
    JUDGED = 'judged'        # the gate's verdict is attached
    VERIFIED = 'verified'    # the real change was made and the real account matches the diff
    DISCARDED = 'discarded'  # thrown away


MOVES: dict[Stage, frozenset[Stage]] = {
    Stage.OPEN: frozenset({Stage.SEALED, Stage.DISCARDED}),
    Stage.SEALED: frozenset({Stage.JUDGED, Stage.DISCARDED}),
    Stage.JUDGED: frozenset({Stage.VERIFIED, Stage.DISCARDED}),
    Stage.VERIFIED: frozenset(),
    Stage.DISCARDED: frozenset(),
}


class IllegalMove(Exception):
    """A state machine was asked for a move its table does not allow."""


class Lifecycle:
    """The branch's stage. Only `move` changes it."""

    def __init__(self) -> None:
        self._stage = Stage.OPEN
        self._history: list[Stage] = [Stage.OPEN]

    @property
    def stage(self) -> Stage:
        return self._stage

    @property
    def history(self) -> tuple[Stage, ...]:
        return tuple(self._history)

    @property
    def accepting(self) -> bool:
        """Only an open branch takes calls."""
        return self._stage is Stage.OPEN

    def move(self, to: Stage) -> None:
        if to not in MOVES[self._stage]:
            raise IllegalMove(f'a branch cannot go from {self._stage.value} to {to.value}')
        self._stage = to
        self._history.append(to)
