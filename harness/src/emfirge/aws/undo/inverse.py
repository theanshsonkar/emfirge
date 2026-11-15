"""Run planned inverse calls on the branch's engine, through the proof door (ids translated, the real account
unreachable).

Each call must act only on resources the original call named or created, as the branch's own catalog says: a plan
that would touch anything else is not run. A refused call is retried the generic ways experiment 11 measured: while
the engine says it is busy; with maps cut to the keys the original call set; without an optional member the error
names (or without all of them).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from emfirge.branch.baseline import Answer
from emfirge.core.model import ResourceRef

from ..codec import AwsCodec
from .observe import Door, Timing
from .plan import Step

BUSY_WORDS = ('Conflict', 'InUse', 'Concurrent', 'TooMany', 'Throttl')
"""Words AWS error codes use for 'try again later' (ResourceConflictException, ResourceInUseException, ...)."""
MAX_DROPS = 6


@dataclass(frozen=True)
class Ran:
    ok: bool
    why: str = ''             # plain words when not ok
    calls: int = 0            # calls sent to the engine


class Runner:
    def __init__(self, door: Door, codec: AwsCodec, timing: Timing, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._door, self._codec, self._timing, self._sleep, self._clock = door, codec, timing, sleep, clock

    def run(self, step: Step, allowed: frozenset[ResourceRef]) -> Ran:
        """One planned step; `allowed` are the resources the original call named or created."""
        try:
            return self._run(step, allowed)
        except (KeyError, TypeError, ValueError) as e:   # botocore could not write the args as a request
            return Ran(False, f'{step.operation} could not be written as a request: {type(e).__name__}: {e}')

    def _run(self, step: Step, allowed: frozenset[ResourceRef]) -> Ran:
        stray = self._stray(step.service, step.operation, dict(step.args), allowed)
        if stray:
            return Ran(False, stray)
        answer, sent = self._send(step.service, step.operation, dict(step.args))
        if answer.ok:
            return Ran(True, calls=sent)
        if step.narrowed is not None:
            answer, n = self._send(step.service, step.operation, dict(step.narrowed))
            sent += n
            if answer.ok:
                return Ran(True, calls=sent)
        return self._without_options(step, answer, sent)

    def _without_options(self, step: Step, answer: Answer, sent: int) -> Ran:
        """Drop an optional member the error names, else all optional members, and try again."""
        args, optional = dict(step.args), list(step.optional)
        for _ in range(MAX_DROPS):
            if not optional:
                break
            message = error_of(answer)[1].lower()
            drop = [k for k in optional if k.lower() in message][:1] or list(optional)
            for k in drop:
                args.pop(k, None)
                optional.remove(k)
            answer, n = self._send(step.service, step.operation, args)
            sent += n
            if answer.ok:
                return Ran(True, calls=sent)
        code, message = error_of(answer)
        return Ran(False, f'the engine refused {step.operation}: {code}: {message[:160]}', sent)

    def _stray(self, service: str, operation: str, args: dict[str, Any], allowed: frozenset[ResourceRef]) -> str:
        refs = self._door.refs(self._codec.encode(service, operation, args))
        if not refs.primary or not refs.complete:
            return f'{operation} would act on something the catalog cannot name, so it was not run'
        outside = [str(r) for r in refs.primary if r not in allowed]
        return f'{operation} would act on {", ".join(outside)}, which the call did not name' if outside else ''

    def _send(self, service: str, operation: str, args: dict[str, Any]) -> tuple[Answer, int]:
        """Send, retrying while the engine says it is busy (bounded)."""
        start, sent = self._clock(), 0
        while True:
            answer = self._door.send(self._codec.encode(service, operation, args))
            sent += 1
            if answer.ok or not busy(answer) or self._clock() - start >= self._timing.busy:
                return answer, sent
            self._sleep(self._timing.interval)


def busy(answer: Answer) -> bool:
    code = error_of(answer)[0]
    return answer.status in (409, 429) or answer.status >= 500 or any(w in code for w in BUSY_WORDS)


def error_of(answer: Answer) -> tuple[str, str]:
    """(code, message) of an error answer, in any of AWS's error shapes."""
    code, message = _first(answer.body, ('__type', 'Code', 'code')), _first(answer.body, ('Message', 'message'))
    return str(code or answer.status).rsplit('#', 1)[-1], str(message or '')


def _first(o: Any, keys: tuple[str, ...]) -> Any:
    if isinstance(o, dict):
        for k in keys:
            if isinstance(o.get(k), str):
                return o[k]
        for v in o.values():
            found = _first(v, keys)
            if found is not None:
                return found
    elif isinstance(o, list):
        for v in o:
            found = _first(v, keys)
            if found is not None:
                return found
    return None
