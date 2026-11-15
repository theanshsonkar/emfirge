"""The branch's change at state level, as core.model.Change objects. Pure: the caller reads the answers.

Created, deleted and modified come from the overlay and from E0 -> now of each baseline read; a changing call that
left no trace in any read (an invoke, a send) is an action. The same comparison against the real account (R0 -> now)
says what changed in the real account under the branch since the copy.
"""
from __future__ import annotations

from typing import Any, Callable

from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef

from . import transplant
from .baseline import Answer, Baseline
from .journal import Journal
from .overlay import State

Now = Callable[[Baseline], Answer]
"""The same read as a baseline, answered now (by the engine, or by the real account)."""
Focus = Callable[[Baseline, Any], Any]
"""The part of an answer that is about the baseline's resource (its item, for a list read)."""


def changes(held: dict[ResourceRef, State], from_real: frozenset[ResourceRef], baselines: dict[ResourceRef, list[Baseline]],
            engine_now: Now, focus: Focus, journal: Journal) -> list[Change]:
    out = []
    for ref, state in sorted(held.items(), key=lambda x: str(x[0])):
        calls = journal.calls_on(ref)
        if state is State.BORN:
            out.append(Change(ref, ChangeType.CREATED, calls=calls))
        elif state is State.DELETED and ref in from_real:
            out.append(Change(ref, ChangeType.DELETED, calls=calls))
        elif state is State.COPIED:
            fields = _fields(baselines.get(ref, []), lambda b: b.e0, engine_now, focus)
            if fields:
                out.append(Change(ref, ChangeType.MODIFIED, fields, calls))
            elif calls:
                out.append(Change(ref, ChangeType.ACTION, calls=calls))
    return out


def drift(baselines: dict[ResourceRef, list[Baseline]], real_now: Now, focus: Focus) -> list[Change]:
    """What changed in the real account since each copy: what a later merge would have to reconcile."""
    out = []
    for ref, bs in sorted(baselines.items(), key=lambda x: str(x[0])):
        fields = _fields(bs, lambda b: b.r0, real_now, focus)
        if fields:
            out.append(Change(ref, ChangeType.MODIFIED, fields))
    return out


def _fields(baselines: list[Baseline], then: Callable[[Baseline], Answer], now: Now, focus: Focus) -> tuple[FieldChange, ...]:
    seen: dict[tuple[str, str, str], FieldChange] = {}
    for b in baselines:
        a, n = then(b), now(b)
        if a.status != n.status:
            f = FieldChange(f'({b.call.operation})', a.status, n.status)
            seen.setdefault((f.path, repr(f.before), repr(f.after)), f)
            continue
        x, y = focus(b, a.body), focus(b, n.body)
        if not a.ok or not transplant.structured(x, y):
            continue
        for path, before, after in transplant.without(b.noise, transplant.changed_paths(x, y)):
            f = FieldChange(path, before, after)
            seen.setdefault((path, repr(before), repr(after)), f)
    return tuple(seen.values())
