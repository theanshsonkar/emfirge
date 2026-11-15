"""The branch's change at state level, as core.model.Change objects. Pure: the caller reads the answers.

Every FieldChange path starts with the read it came from ('<Read>.<field>.<field>'), because a bare field name says
nothing to a lens. Created resources carry their settings (before None), deleted ones their state at copy time
(after None), modified ones E0 -> now of each baseline read. A resource created and then deleted on the branch is no
change. A changing call that acted on a resource (not one that only named it) but left no trace in its reads (an
invoke, a send) is an action. A field that changed although no call acting on the resource sent it, or anything
above it, is marked `derived` (a clock, a hash, a revision the service computes): kept, for consumers to weigh.
The same comparison against the real account (R0 -> now) says what changed in the real account under the branch
since the copy.
"""
from __future__ import annotations

from dataclasses import replace
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
Settings = Callable[[ResourceRef], list[tuple[str, Any]]]
"""(path, value) of each setting of a resource born on the branch, path starting with the read's name."""


def changes(held: dict[ResourceRef, State], from_real: frozenset[ResourceRef], baselines: dict[ResourceRef, list[Baseline]],
            engine_now: Now, focus: Focus, journal: Journal, born_settings: Settings) -> list[Change]:
    out = []
    for ref, state in sorted(held.items(), key=lambda x: str(x[0])):
        calls = journal.calls_on(ref)
        sent = journal.members_sent(ref)
        if state is State.BORN:
            fields = tuple(FieldChange(p, None, v, derived(p, sent)) for p, v in born_settings(ref))
            out.append(Change(ref, ChangeType.CREATED, fields, calls))
        elif state is State.DELETED and ref in from_real:
            out.append(Change(ref, ChangeType.DELETED, _last_state(baselines.get(ref, []), focus), calls))
        elif state is State.COPIED:
            fields = tuple(replace(f, derived=derived(f.path, sent))
                           for f in _fields(baselines.get(ref, []), lambda b: b.e0, engine_now, focus))
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


def derived(path: str, sent: frozenset[str]) -> bool:
    """No call acting on the resource sent this field or anything above it (the first segment is the read's name;
    a path that is only the read's name is a change of the read's answer status, never derived)."""
    fields = path.split('.')[1:]
    return bool(fields) and not any(f.lower() in sent for f in fields)


def named(read: str, path: str) -> str:
    return f'{read}.{path}' if path else read


def _leafwise(path: str, before: Any, after: Any) -> list[tuple[str, Any, Any]]:
    """A value that became a mapping (an empty setting now filled in), or a mapping that became a value, as one
    change per leaf: each setting is then named by its own field, not by its container."""
    def under(sub: str) -> str:
        return f'{path}.{sub}' if path else sub
    if isinstance(after, dict) and after and not isinstance(before, dict):
        return [(under(p), None, v) for p, v in transplant.leaves(after)]
    if isinstance(before, dict) and before and not isinstance(after, dict):
        return [(under(p), v, None) for p, v in transplant.leaves(before)]
    return [(path, before, after)]


def _last_state(baselines: list[Baseline], focus: Focus) -> tuple[FieldChange, ...]:
    """The real state when the resource was copied, each setting going away."""
    seen: dict[str, FieldChange] = {}
    for b in baselines:
        if b.r0.ok:
            for path, value in transplant.leaves(focus(b, b.r0.body)):
                if not any(path == p or path.startswith(p + '.') for p in b.noise):
                    seen.setdefault(named(b.call.operation, path), FieldChange(named(b.call.operation, path), value, None))
    return tuple(seen.values())


def _fields(baselines: list[Baseline], then: Callable[[Baseline], Answer], now: Now, focus: Focus) -> tuple[FieldChange, ...]:
    seen: dict[tuple[str, str, str], FieldChange] = {}
    for b in baselines:
        a, n = then(b), now(b)
        read = b.call.operation
        if a.status != n.status:
            f = FieldChange(read, a.status, n.status)
            seen.setdefault((f.path, repr(f.before), repr(f.after)), f)
            continue
        x, y = focus(b, a.body), focus(b, n.body)
        if not a.ok or not transplant.structured(x, y):
            continue
        for path, before, after in transplant.without(b.noise, transplant.changed_paths(x, y)):
            for leaf, was, became in _leafwise(path, before, after):
                f = FieldChange(named(read, leaf), was, became)
                seen.setdefault((f.path, repr(was), repr(became)), f)
    return tuple(seen.values())
