"""What the engine and the real account answered right after a resource was copied (E0 and R0).

Why: E0 -> now is the branch's own change (laid over live real answers, and shown in the diff); R0 -> now is what
changed in the real account under the branch since the copy. Fields that differ between two identical reads of the
engine in a row (request ids, clocks) are noise, learned per read, not from a list of names.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any

from emfirge.core.model import Call, ResourceRef

from . import transplant


@dataclass(frozen=True)
class Answer:
    status: int
    body: Any          # plain nested data, or bytes when the answer is not structured

    @property
    def ok(self) -> bool:
        return self.status < 300


@dataclass(frozen=True)
class Baseline:
    ref: ResourceRef
    call: Call
    e0: Answer
    r0: Answer
    noise: frozenset[str] = frozenset()

    @property
    def key(self) -> str:
        return key_of(self.call)


def key_of(call: Call) -> str:
    """A read's identity: the same operation with the same parameters is the same read."""
    return call.name + json.dumps(call.params, sort_keys=True, default=str)


def noise_between(a: Any, b: Any) -> frozenset[str]:
    """Paths where two answers to the same read, with nothing changed in between, differ."""
    if not transplant.structured(a, b):
        return frozenset()
    return frozenset(p for p, _, _ in transplant.changed_paths(a, b))


class Baselines:
    def __init__(self) -> None:
        self._by_ref: dict[ResourceRef, list[Baseline]] = {}

    def set(self, ref: ResourceRef, baselines: list[Baseline]) -> None:
        self._by_ref[ref] = baselines

    def of(self, ref: ResourceRef) -> list[Baseline]:
        return list(self._by_ref.get(ref, []))

    def all(self) -> dict[ResourceRef, list[Baseline]]:
        return {r: list(b) for r, b in self._by_ref.items()}

    def find(self, ref: ResourceRef, call: Call) -> Baseline | None:
        k = key_of(call)
        return next((b for b in self._by_ref.get(ref, []) if b.key == k), None)

    def fold(self, ref: ResourceRef, before: list[Answer], after: list[Answer]) -> None:
        """Copying something else changed `ref` in the engine (a mapping added to a function): that change belongs
        to the copy, not to the branch, so it is folded into E0."""
        out = []
        for b, x, y in zip(self._by_ref.get(ref, []), before, after):
            if b.e0.ok and x.ok and y.ok and transplant.structured(b.e0.body, x.body, y.body):
                b = replace(b, e0=Answer(b.e0.status, transplant.lay(x.body, y.body, b.e0.body)))
            out.append(b)
        self._by_ref[ref] = out
