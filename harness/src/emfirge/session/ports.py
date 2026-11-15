"""What a session needs from the parts it does not own: the branch it judges, the reader of the account's settings,
and the bench a cloud plug-in sets up (a branch on a live local endpoint). Cloud-neutral: written against
emfirge.core only, so a second cloud plugs in by implementing these.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from emfirge.branch.lifecycle import Stage
from emfirge.core.model import Change, ResourceRef, Unknown


class Held(Protocol):
    """The part of emfirge.branch.Branch a session uses. A Protocol so the pipeline can be tested with a fake."""

    def seal(self) -> None: ...
    def changes(self) -> list[Change]: ...
    def states_after(self) -> dict[ResourceRef, dict[str, Any]]: ...
    def unknowns(self) -> tuple[Unknown, ...]: ...
    def stats(self) -> dict[str, Any]: ...
    def move(self, to: Stage) -> None: ...


@dataclass(frozen=True)
class Reading:
    """The account's settings as the graph reads them, and what reading them cost.
    states    every resource read, keyed the way the branch names resources
    unknowns  what the reader could not read (it stopped at its budget, a read was refused)
    reads     how many reads it sent to the real account
    counts    other measurements (resources found, services listed, ...)"""
    states: Mapping[ResourceRef, Any]
    unknowns: tuple[Unknown, ...] = ()
    reads: int = 0
    counts: Mapping[str, int] = field(default_factory=dict)


class StateReader(Protocol):
    """Reads the real account's settings around a change set, and puts the branch's own states in the same shape."""

    def before(self, changes: Sequence[Change]) -> Reading:
        """The settings of the changed resources and of what may name them or be named by them."""

    def after(self, states: Mapping[ResourceRef, Any]) -> dict[ResourceRef, Any]:
        """The branch's states (Branch.states_after) in the shape `before` gives, so the two can be compared."""


class Bench(Protocol):
    """A branch served on a local endpoint, set up by a cloud plug-in. Closing it stops everything it started."""
    held: Held
    url: str                     # where the agent's tools talk to the branch

    def client_env(self, base: Mapping[str, str]) -> dict[str, str]:
        """`base` changed so the cloud's tools can reach only the branch (a guard against accidents, not a sandbox)."""

    def lens_endpoints(self) -> tuple[str, str]:
        """(before, after): read-only endpoints on the real account and on the branch, for outside tools."""

    def close(self) -> None: ...
