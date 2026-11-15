"""The data lens: data that the change can lose, or whose safety net it removes.

  deleted     a resource is deleted; whether it holds data comes from `holds_data` (the integrator knows, from the
              cloud's published resource types); None means it cannot be told, and that is said
  protection  on a resource that already existed, a protection is switched off, removed, or shortened; found by
              the names of settings (deletion protection, versioning, retention, expiry, encryption, dry-run ...)
  emptied     a call whose verb empties a store (purge, truncate, delete objects or items ...)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from emfirge.core.model import Change, ChangeType, FieldChange, Finding, ResourceRef, Unknown

from ..api import LensResult, LensView
from . import patterns
from .report import fact, status_unknown, unknown
from .state import as_number, as_switch, is_status, leaves, nodes, operation, short
from .vocabulary import DataWords, Protection

NAME = 'data'
HoldsData = Callable[[ResourceRef], bool | None]


@dataclass(frozen=True)
class DataLens:
    holds_data: HoldsData | None = None
    words: DataWords = patterns.DATA
    name: str = NAME

    def look(self, view: LensView) -> LensResult:
        findings: list[Finding] = []
        unknowns: list[Unknown] = []
        for change in view.changes:
            if change.type is ChangeType.DELETED:
                f, u = self._deleted(change)
                findings += f
                unknowns += u
                continue
            if change.type is not ChangeType.CREATED:    # a new resource has no protection to lose
                for field in change.fields:
                    if field.derived:
                        continue           # computed by the service (a clock, a count): no call of the session set it
                    if is_status(field):
                        u = status_unknown(NAME, field, change, self.words.status_words)
                        unknowns += [u] if u else []
                    else:
                        findings += self._protections(change, field)
            findings += self._emptied(change)
        return LensResult(tuple(findings), tuple(unknowns))

    def _deleted(self, change: Change) -> tuple[list[Finding], list[Unknown]]:
        holds = self.holds_data(change.ref) if self.holds_data else None
        if holds is None:
            return [], [unknown(NAME, 'deleted, and whether it holds data cannot be told', change)]
        if holds:
            return [fact(NAME, 'store_deleted', 'deleted; it holds data, and the data goes with it', change,
                         calls=list(change.calls))], []
        return [], []

    def _emptied(self, change: Change) -> list[Finding]:
        calls = [c for c in change.calls if self.words.emptying_operations.search(operation(c))]
        if not calls:
            return []
        return [fact(NAME, 'emptied', f'{short(calls)} removes data inside it', change, calls=calls)]

    def _protections(self, change: Change, field: FieldChange) -> list[Finding]:
        out: list[Finding] = []
        for rule in self.words.protections:
            check = {'switch': self._switch, 'present': self._present, 'retention': self._retention, 'expiry': self._expiry}[rule.kind]
            out += [fact(NAME, code, message, change, path, before=b, after=a, protection=rule.name)
                    for code, message, path, b, a in check(rule, field)]
        return out

    def _claimed(self, rule: Protection, shape: str) -> bool:
        """A setting is judged by the first protection whose path fits it (retention-in-days before any retention)."""
        return next((r for r in self.words.protections if r.path.search(shape)), None) is rule

    def _switches_on(self, rule: Protection, value: Any, path: str) -> dict[str, Any]:
        return {n.shape: n.value for n in leaves(value, path) if self._claimed(rule, n.shape)
                and as_switch(n.value, self.words.on, self.words.off) is True}

    def _switch(self, rule: Protection, field: FieldChange) -> list[tuple]:
        before = self._switches_on(rule, field.before, field.path)
        after = self._switches_on(rule, field.after, field.path)
        values = {n.shape: n.value for n in leaves(field.after, field.path)}
        return [('protection_off', f'{rule.name} switched off ({s}: {before[s]} -> {values.get(s, "removed")})',
                 s, before[s], values.get(s)) for s in sorted(set(before) - set(after))]

    def _present(self, rule: Protection, field: FieldChange) -> list[tuple]:
        def there(value: Any) -> dict[str, Any]:
            return {n.shape: n.value for n in nodes(value, field.path) if self._claimed(rule, n.shape)
                    and n.value not in (None, '', {}, [])}
        before, after = there(field.before), there(field.after)
        gone = sorted(set(before) - set(after))
        top = [s for s in gone if not any(s != o and s.startswith(o) for o in gone)]   # the setting, not each part of it
        return [('protection_off', f'{rule.name} removed ({s})', s, before[s], None) for s in top]

    def _numbers(self, rule: Protection, value: Any, path: str) -> dict[str, float]:
        found: dict[str, float] = {}
        for n in leaves(value, path):
            number = as_number(n.value)
            if number is not None and self._claimed(rule, n.shape):
                found[n.shape] = min(number, found.get(n.shape, number))
        return found

    def _retention(self, rule: Protection, field: FieldChange) -> list[tuple]:
        before = self._numbers(rule, field.before, field.path)
        after = self._numbers(rule, field.after, field.path)
        out = []
        for s in sorted(set(before) | set(after)):
            b, a = before.get(s), after.get(s)
            if a is not None and ((b is not None and a < b) or (b is None and rule.unset_is_forever)):
                out.append(('retention_shortened', f'{rule.name} shortened ({s}: {_n(b, "forever")} -> {_n(a)})', s, b, a))
        return out

    def _expiry(self, rule: Protection, field: FieldChange) -> list[tuple]:
        before = self._numbers(rule, field.before, field.path)
        after = self._numbers(rule, field.after, field.path)
        return [('expiry_added', f'data now expires ({s}: {_n(before.get(s), "never")} -> {_n(after[s])} days)', s, before.get(s), after[s])
                for s in sorted(after) if s not in before or after[s] < before[s]]


def _n(value: float | None, none: str = 'none') -> str:
    return none if value is None else f'{value:g}'
