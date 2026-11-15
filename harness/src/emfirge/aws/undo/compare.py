"""Compare a resource's reads after the undo with the same reads at copy time. Pure.

Every field counts: ids, version numbers, revision ids, list contents. Two kinds of field are set aside, both learned
from the answers themselves, never from a list of names:
  noise   a field that differed between two identical reads taken a moment apart at copy time (a request id).
  clock   a field holding a time that moved when the session's call ran, and moved again to the moment the undo ran
          (a "last modified" time): a time at copy time, no earlier at the end of the session, and the moment of the
          undo afterwards. Any write moves it, so it cannot come back; it is named in the proof's reason.
          A field the call itself set is never a clock: what the agent set must come back exactly.
"""
from __future__ import annotations

import email.utils
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from emfirge.branch import transplant
from emfirge.branch.baseline import Answer

ISO = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')
RFC1123 = re.compile(r'^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} (GMT|[+-]\d{4})$')

Focus = Callable[[Any], Any]
"""The part of an answer that is about the resource (its item, in a list answer)."""


@dataclass(frozen=True)
class Difference:
    read: str          # the read's operation
    path: str          # dotted path in the answer ('' for the whole answer, '(status)' for the answer's status)
    before: Any
    after: Any

    def __str__(self) -> str:
        where = f'{self.read}.{self.path}' if self.path else self.read
        return f'{where}: {_short(self.before)} -> {_short(self.after)}'


@dataclass(frozen=True)
class Window:
    """When the undo ran (seconds since the epoch), with a tolerance for the engine's clock."""
    start: float
    end: float
    slack: float = 5.0

    def holds(self, t: float) -> bool:
        return self.start - self.slack <= t <= self.end + self.slack


@dataclass(frozen=True)
class Outcome:
    differences: tuple[Difference, ...]
    clocks: tuple[Difference, ...]


def compare(read: str, e0: Answer, e1: Answer | None, now: Answer, focus: Focus, noise: frozenset[str],
            set_names: frozenset[str], window: Window) -> Outcome:
    """`now` against `e0` (copy time). `e1` is the same read at the end of the session, used to tell a clock."""
    if e0.status != now.status:
        return Outcome((Difference(read, '(status)', e0.status, now.status),), ())
    if not e0.ok:
        return Outcome((), ())
    x, y = focus(e0.body), focus(now.body)
    if not transplant.structured(x, y):
        return Outcome(() if x == y else (Difference(read, '', x, y),), ())
    mid = focus(e1.body) if e1 is not None and e1.ok else None
    real, clocks = [], []
    for op in transplant.diff(x, y):
        path = '.'.join(map(str, op.path))
        if any(path == p or path.startswith(p + '.') for p in noise):
            continue
        d = Difference(read, path, value_at(x, op.path), None if op.remove else op.value)
        clock = is_clock(op.path, d.before, d.after, set_names, window) and _not_back(value_at(mid, op.path), d.before)
        (clocks if clock else real).append(d)
    return Outcome(tuple(real), tuple(clocks))


def is_clock(path: tuple[Any, ...], before: Any, after: Any, set_names: frozenset[str], window: Window) -> bool:
    """Both values are times, the later one is the moment the undo ran, and the call did not set this field."""
    if path and str(path[-1]) in set_names:
        return False
    tb, ta = time_of(before), time_of(after)
    return tb is not None and ta is not None and ta > tb and window.holds(ta)


def _not_back(during: Any, before: Any) -> bool:
    """At the end of the session the field was a time no earlier than at copy time: a clock only moves forward.
    (With one-second clocks, the session's own write may not have moved it yet.)"""
    t, b = time_of(during), time_of(before)
    return t is not None and b is not None and t >= b


def time_of(v: Any) -> float | None:
    """Seconds since the epoch when `v` is written as a time in one of the forms AWS answers with, else None."""
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp()
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r'\d{10}(\d{3})?(\.\d+)?', v)):
        n = float(v)
        return n if 1e9 <= n < 1e10 else n / 1000 if 1e12 <= n < 1e13 else None
    if isinstance(v, str) and ISO.match(v):
        text = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', v.replace('Z', '+00:00'))
        return time_of(datetime.fromisoformat(text))
    if isinstance(v, str) and RFC1123.match(v):
        return email.utils.parsedate_to_datetime(v).timestamp()
    return None


def value_at(body: Any, path: tuple[Any, ...]) -> Any:
    for k in path:
        if not isinstance(body, dict) or k not in body:
            return None
        body = body[k]
    return body


def _short(v: Any, n: int = 80) -> str:
    s = repr(v)
    return s if len(s) <= n else s[:n] + '...'
