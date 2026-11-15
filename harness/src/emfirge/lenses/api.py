"""The lens contract: what a lens is given, what it answers, and the runner that asks every lens.

A lens looks at what a branch holds and reports facts about one concern (data, public access, money, permissions, or
an outside tool). It reports only what the change makes new. When it cannot judge something it says so with an
Unknown: silence would read as "nothing new", which is a claim the lens did not check.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Protocol, Sequence

from emfirge.core.model import Change, Finding, Unknown


@dataclass(frozen=True)
class LensView:
    """What every lens gets to look at.
    changes          what the branch holds, at state level
    before_endpoint  where an outside tool reads the real account (read-only); '' when there is none
    after_endpoint   where an outside tool reads the branch; '' when there is none
    env              the environment an outside tool runs in (the endpoint variable is added per run)"""
    changes: Sequence[Change]
    before_endpoint: str = ''
    after_endpoint: str = ''
    env: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LensResult:
    findings: tuple[Finding, ...] = ()
    unknowns: tuple[Unknown, ...] = ()

    def __add__(self, other: 'LensResult') -> 'LensResult':
        return LensResult(self.findings + other.findings, self.unknowns + other.unknowns)


class Lens(Protocol):
    name: str

    def look(self, view: LensView) -> LensResult:
        """Facts the change makes new, and what this lens could not judge. Same view, same answer."""


def run_lenses(lenses: Iterable[Lens], view: LensView) -> LensResult:
    """Every lens, in the order given. A lens that fails becomes an Unknown: the run never crashes and never goes
    quiet, because a missing answer must stop an automatic go-ahead like any other unknown."""
    total = LensResult()
    for lens in lenses:
        total = total + _one(lens, view)
    return LensResult(_unique(total.findings), _unique(total.unknowns))


def _one(lens: Lens, view: LensView) -> LensResult:
    name = getattr(lens, 'name', type(lens).__name__)
    try:
        result = lens.look(view)
    except Exception as exc:  # noqa: BLE001 - any failure of a lens is reported, never raised
        return LensResult(unknowns=(Unknown(f'the {name} lens failed: {type(exc).__name__}: {exc}', f'lens:{name}'),))
    if not isinstance(result, LensResult):
        return LensResult(unknowns=(Unknown(f'the {name} lens gave no answer', f'lens:{name}'),))
    return result


def _unique(items: tuple) -> tuple:
    """The same fact said twice (two reads of one policy) is one fact. Order is kept."""
    seen: list = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return tuple(seen)
