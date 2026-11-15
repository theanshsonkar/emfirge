"""The ordered log of changing calls the branch let through to the engine. Append only."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from emfirge.core.model import ResourceRef


@dataclass(frozen=True)
class Entry:
    n: int
    call: str                                  # 'lambda.UpdateFunctionConfiguration'
    params: Mapping[str, Any]
    status: int
    refs: tuple[ResourceRef, ...]
    born: tuple[ResourceRef, ...] = field(default=())

    @property
    def succeeded(self) -> bool:
        return self.status < 300


class Journal:
    def __init__(self) -> None:
        self._entries: list[Entry] = []

    def add(self, call: str, params: Mapping[str, Any], status: int, refs: tuple[ResourceRef, ...],
            born: tuple[ResourceRef, ...] = ()) -> Entry:
        e = Entry(len(self._entries) + 1, call, params, status, refs, born)
        self._entries.append(e)
        return e

    def entries(self) -> tuple[Entry, ...]:
        return tuple(self._entries)

    def calls_on(self, ref: ResourceRef) -> tuple[str, ...]:
        """The successful changing calls that named `ref` (or bore it), in order."""
        return tuple(e.call for e in self._entries if e.succeeded and (ref in e.refs or ref in e.born))
