"""The money lens: facts about what may cost more. Small and honest: it says what grew, not what it costs.

  created     new resources, counted by type
  class       a machine size or class changed ('t3.micro -> m5.large'); a step down the size ladder is not news
  growth      a size or count went up ('MemorySize 256 -> 1024')
  plan        how something is billed changed
  running     something that was off now runs
  commitment  a call that commits money or raises a limit (a purchase, a quota increase)

Dollars come only from `price` (monthly change in USD for one change, or None); without it the lens says that no
price was looked up, so a reader never takes the facts for a full cost picture.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from emfirge.core.model import Change, ChangeType, FieldChange, Finding, Unknown

from ..api import LensResult, LensView
from . import patterns
from .report import fact, unknown
from .state import as_number, as_switch, is_status, leaves, operation, short
from .vocabulary import MoneyWords

NAME = 'money'
SET_BY_SERVICE_IGNORED = frozenset({'class_changed', 'size_up'})
"""A size or class the service computed (a bigger CodeSize after a code upload) is not a money fact: no call of the
session set it. A plan, a switch or a commitment is judged whoever set it."""
Price = Callable[[Change], float | None]


@dataclass(frozen=True)
class MoneyLens:
    price: Price | None = None
    words: MoneyWords = patterns.MONEY
    name: str = NAME

    def look(self, view: LensView) -> LensResult:
        findings = self._created(view.changes)
        for change in view.changes:
            if change.type is ChangeType.MODIFIED:
                findings += [f for field in change.fields if not is_status(field) for f in self._field(change, field)]
            findings += self._commitments(change)
        return self._priced(view.changes, findings)

    def _created(self, changes: Sequence[Change]) -> list[Finding]:
        born = [c for c in changes if c.type is ChangeType.CREATED]
        if not born:
            return []
        by_type = Counter(c.ref.type for c in born)
        types = ', '.join(f'{n} {t}' for t, n in sorted(by_type.items()))
        return [Finding(NAME, f'{NAME}.resources_created', f'{len(born)} new resources of {len(by_type)} types ({types})',
                        tuple(c.ref for c in born), {'path': '', 'before': None, 'after': dict(sorted(by_type.items()))})]

    def _field(self, change: Change, field: FieldChange) -> list[Finding]:
        before, after = _scalars(field.before, field.path), _scalars(field.after, field.path)
        out = []
        for shape in sorted(set(before) | set(after)):
            b, a = before.get(shape), after.get(shape)
            if b == a:
                continue
            said = self._judge(shape, b, a)
            if said and not (field.derived and said[0] in SET_BY_SERVICE_IGNORED):
                code, message = said
                out.append(fact(NAME, code, message, change, shape, before=b, after=a))
        return out

    def _judge(self, shape: str, b: Any, a: Any) -> tuple[str, str] | None:
        w = self.words
        name = shape.rsplit('.', 1)[-1]
        if w.class_keys.search(shape) and a is not None:
            return None if self._smaller_or_same(b, a) else ('class_changed', f'{name} {b} -> {a}')
        if w.plan_keys.search(shape) and a is not None:
            return 'plan_changed', f'{name} {b} -> {a}'
        if w.running_keys.search(shape) and as_switch(b, w.on, w.off) is False and as_switch(a, w.on, w.off) is True:
            return 'switched_on', f'{name} {b} -> {a}: it now runs, and what runs is billed'
        nb, na = as_number(b), as_number(a)
        if w.growth_keys.search(shape) and not w.growth_ignore.search(name) and na is not None and na > (nb or 0):
            return 'size_up', f'{name} {b} -> {a}'
        return None

    def _smaller_or_same(self, b: Any, a: Any) -> bool:
        """Only a step down within one family is known to cost less; another family is a change of unknown cost."""
        if not (isinstance(b, str) and isinstance(a, str)) or '.' not in b or '.' not in a:
            return False
        (fb, sb), (fa, sa) = b.rsplit('.', 1), a.rsplit('.', 1)
        rb, ra = self._rank(sb), self._rank(sa)
        return fb == fa and rb is not None and ra is not None and ra <= rb

    def _rank(self, size: str) -> int | None:
        if size in self.words.ladder:
            return self.words.ladder.index(size)
        numbered = self.words.numbered_size.match(size)
        return len(self.words.ladder) + int(numbered.group(1)) if numbered else None

    def _commitments(self, change: Change) -> list[Finding]:
        calls = [c for c in change.calls if self.words.commitment_operations.search(operation(c))]
        if not calls:
            return []
        return [fact(NAME, 'commitment_call', f'{short(calls)} commits money or raises a limit', change, calls=calls)]

    def _priced(self, changes: Sequence[Change], findings: list[Finding]) -> LensResult:
        if not findings:
            return LensResult()
        if self.price is None:
            return LensResult(tuple(findings), (Unknown('no price was looked up: the money facts are not in dollars', f'lens:{NAME}'),))
        touched = {ref for f in findings for ref in f.refs}
        priced = [(c, self.price(c)) for c in changes if c.ref in touched]
        total = sum(usd for _, usd in priced if usd is not None)
        unknowns = tuple(unknown(NAME, 'no price was found for this change', c) for c, usd in priced if usd is None)
        summary = Finding(NAME, f'{NAME}.monthly_estimate', f'about {total:+.2f} USD a month for the priced changes',
                          tuple(c.ref for c, usd in priced if usd is not None), {'path': '', 'before': None, 'after': round(total, 2)})
        return LensResult(tuple(findings) + (summary,), unknowns)


def _scalars(value: Any, path: str) -> dict[str, Any]:
    """Setting -> value. Where a list holds several items of one shape, the largest number stands for them."""
    out: dict[str, Any] = {}
    for n in leaves(value, path):
        if n.shape in out and as_number(out[n.shape]) is not None and as_number(n.value) is not None:
            out[n.shape] = max(out[n.shape], n.value, key=as_number)
        else:
            out.setdefault(n.shape, n.value)
    return out
