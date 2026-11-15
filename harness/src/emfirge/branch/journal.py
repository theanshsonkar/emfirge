"""The ordered log of changing calls the branch let through to the engine. Append only.

Each entry keeps what a later undo prover needs: the call (service, operation, every parameter as the client sent it),
the resources it named (`refs`: everything; `primary`: what it acts on), the resources it bore, the engine's answer
status, and the answer itself as plain data (ids the service gave out are in it)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from emfirge.core.model import ResourceRef


@dataclass(frozen=True)
class Entry:
    n: int
    service: str
    operation: str
    params: Mapping[str, Any]
    status: int
    refs: tuple[ResourceRef, ...]
    born: tuple[ResourceRef, ...] = field(default=())
    primary: tuple[ResourceRef, ...] = field(default=())
    answer: Any = None             # the answer as the client got it, as plain data (bytes when not structured)

    @property
    def call(self) -> str:
        return f'{self.service}.{self.operation}'

    @property
    def succeeded(self) -> bool:
        return self.status < 300

    def acts_on(self, ref: ResourceRef) -> bool:
        """The call acted on `ref` (or bore it), as opposed to only naming it (a role passed to a schedule)."""
        return ref in self.primary or ref in self.born


class Journal:
    def __init__(self) -> None:
        self._entries: list[Entry] = []

    def add(self, service: str, operation: str, params: Mapping[str, Any], status: int, refs: tuple[ResourceRef, ...],
            born: tuple[ResourceRef, ...] = (), primary: tuple[ResourceRef, ...] = (), answer: Any = None) -> Entry:
        e = Entry(len(self._entries) + 1, service, operation, params, status, refs, born, primary, answer)
        self._entries.append(e)
        return e

    def entries(self) -> tuple[Entry, ...]:
        return tuple(self._entries)

    def calls_on(self, ref: ResourceRef) -> tuple[str, ...]:
        """The successful changing calls that acted on `ref` (or bore it), in order."""
        return tuple(e.call for e in self._entries if e.succeeded and e.acts_on(ref))

    def changed(self, ref: ResourceRef) -> bool:
        """A successful changing call acted on `ref` since the branch opened."""
        return any(e.succeeded and e.acts_on(ref) for e in self._entries)

    def members_sent(self, ref: ResourceRef) -> frozenset[str]:
        """Every member name (at any depth, lower case) the successful calls acting on `ref` sent: what the calls set.
        A field whose name is not here changed without a call setting it (the service computed it)."""
        out: set[str] = set()
        for e in self._entries:
            if e.succeeded and e.acts_on(ref):
                out |= _keys(e.params)
        return frozenset(out)


def _keys(o: Any) -> set[str]:
    if isinstance(o, dict):
        return {str(k).lower() for k in o} | {k for v in o.values() for k in _keys(v)}
    if isinstance(o, list):
        return {k for v in o for k in _keys(v)}
    return set()
