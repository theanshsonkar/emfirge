"""The verdict: go or ask, from facts only. Pure and deterministic: the same facts, in any order, give the same
Decision.

go needs all of these, and nothing else is ever asked of the owner (no rules to write):
  * every change can be put back exactly (Undo.YES), or there is no change at all;
  * no lens flagged anything;
  * nothing is unknown;
  * the affected rule holds:
      STRICT (the default)  nothing outside the change set is reached with strong evidence. A change that is
                            undoable on paper can still break what depends on it while it is live (a redeploy that
                            turns a paused schedule back on; a cache setting that breaks the site in front of a
                            bucket): what it reaches is the owner's call.
      LOOSE                 affected things are shown, but do not stop go.
Anything else is ask. Every reason carries a stable code from REASONS, plain words and the refs it is about.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from emfirge.core.model import Affected, Change, Finding, ResourceRef, Undo, UndoFact, Unknown

STRONG = 'strong'


class Verdict(str, Enum):
    GO = 'go'
    ASK = 'ask'

    @property
    def exit_code(self) -> int:
        """The exit code of `emf run` for this verdict (README: 0 go, 3 ask)."""
        return 0 if self is Verdict.GO else 3


class AffectedRule(str, Enum):
    STRICT = 'strict'
    LOOSE = 'loose'


class Code(str, Enum):
    """Reason codes. Their order here is the order reasons are listed in."""
    CANNOT_UNDO = 'cannot-undo'
    UNDO_UNKNOWN = 'undo-unknown'
    FLAGGED = 'flagged'
    UNKNOWN = 'unknown'
    AFFECTS = 'affects'
    NOTHING_CHANGED = 'nothing-changed'
    ALL_UNDOABLE = 'all-undoable'


REASONS: dict[Code, tuple[Verdict, str]] = {
    Code.CANNOT_UNDO: (Verdict.ASK, '{ref} cannot be put back: {why}'),
    Code.UNDO_UNKNOWN: (Verdict.ASK, 'Emfirge cannot tell if {ref} can be put back: {why}'),
    Code.FLAGGED: (Verdict.ASK, '{lens} flagged: {why}'),
    Code.UNKNOWN: (Verdict.ASK, 'Emfirge could not tell: {why}'),
    Code.AFFECTS: (Verdict.ASK, '{ref} is outside the change, and the change reaches it: {why}'),
    Code.NOTHING_CHANGED: (Verdict.GO, 'The agent changed nothing.'),
    Code.ALL_UNDOABLE: (Verdict.GO, 'Every change can be put back exactly. Nothing was flagged. Nothing is unknown.'),
}
"""Each code: the verdict it leads to, and its plain words."""

_NO_FACT = 'no undo fact was given for this change'


@dataclass(frozen=True)
class Reason:
    code: Code
    words: str
    refs: tuple[ResourceRef, ...] = ()


@dataclass(frozen=True)
class Facts:
    """Everything a verdict is decided on, in a fixed order."""
    changes: tuple[Change, ...]
    undo: tuple[UndoFact, ...]
    findings: tuple[Finding, ...]
    unknowns: tuple[Unknown, ...]
    affected: tuple[Affected, ...]

    @classmethod
    def of(cls, changes: Iterable[Change], undo: Iterable[UndoFact], findings: Iterable[Finding],
           unknowns: Iterable[Unknown], affected: Iterable[Affected]) -> 'Facts':
        return cls(tuple(sorted(changes, key=lambda c: (str(c.ref), c.type.value))),
                   tuple(sorted(undo, key=lambda u: (str(u.ref), u.undo.value, u.reasons))),
                   tuple(sorted(findings, key=lambda f: (f.lens, f.code, f.message, tuple(map(str, f.refs))))),
                   tuple(sorted(unknowns, key=lambda u: (u.where, u.what, str(u.ref or '')))),
                   tuple(sorted(affected, key=lambda a: (str(a.ref), a.strength, a.because, tuple(map(str, a.via))))))

    def undo_of(self, ref: ResourceRef) -> UndoFact | None:
        return next((u for u in self.undo if u.ref == ref), None)


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reasons: tuple[Reason, ...]
    rule: AffectedRule
    facts: Facts

    @property
    def exit_code(self) -> int:
        return self.verdict.exit_code


def decide(changes: Iterable[Change], undo_facts: Iterable[UndoFact], findings: Iterable[Finding],
           unknowns: Iterable[Unknown], affected: Iterable[Affected], *,
           affected_rule: AffectedRule = AffectedRule.STRICT) -> Decision:
    """go or ask, with every reason. See the module docstring for the rule."""
    facts = Facts.of(changes, undo_facts, findings, unknowns, affected)
    asks = [*_undo_reasons(facts), *_finding_reasons(facts), *_unknown_reasons(facts)]
    if affected_rule is AffectedRule.STRICT:
        asks += _affects_reasons(facts)
    if asks:
        return Decision(Verdict.ASK, _ordered(asks), affected_rule, facts)
    code = Code.ALL_UNDOABLE if facts.changes else Code.NOTHING_CHANGED
    return Decision(Verdict.GO, (_reason(code),), affected_rule, facts)


def _undo_reasons(facts: Facts) -> list[Reason]:
    out = []
    for change in facts.changes:
        fact = facts.undo_of(change.ref)
        undo = fact.undo if fact else Undo.UNKNOWN
        why = _first(fact.reasons) if fact and fact.reasons else _NO_FACT
        if undo is Undo.NO:
            out.append(_reason(Code.CANNOT_UNDO, (change.ref,), ref=change.ref, why=why))
        elif undo is Undo.UNKNOWN:
            out.append(_reason(Code.UNDO_UNKNOWN, (change.ref,), ref=change.ref, why=why))
    return out


def _finding_reasons(facts: Facts) -> list[Reason]:
    return [_reason(Code.FLAGGED, f.refs, lens=f.lens, why=f.message) for f in facts.findings]


def _unknown_reasons(facts: Facts) -> list[Reason]:
    return [_reason(Code.UNKNOWN, (u.ref,) if u.ref else (), why=u.what) for u in facts.unknowns]


def _affects_reasons(facts: Facts) -> list[Reason]:
    """One reason per resource outside the change set that is reached with strong evidence."""
    changed = {c.ref for c in facts.changes}
    because: dict[ResourceRef, list[str]] = {}
    for a in facts.affected:
        if a.strength == STRONG and a.ref not in changed and a.because not in because.setdefault(a.ref, []):
            because[a.ref].append(a.because)
    return [_reason(Code.AFFECTS, (ref,), ref=ref, why='; '.join(why)) for ref, why in because.items() if why]


def _first(reasons: tuple[str, ...]) -> str:
    """The first reason, and how many more there are: a reason line stays short, the report lists them all."""
    more = len(reasons) - 1
    return reasons[0] + (f' (and {more} more)' if more else '')


def _reason(code: Code, refs: Iterable[ResourceRef] = (), **words: object) -> Reason:
    _, template = REASONS[code]
    return Reason(code, template.format(**words), tuple(refs))


def _ordered(reasons: list[Reason]) -> tuple[Reason, ...]:
    order = list(Code)
    unique = dict.fromkeys(reasons)
    return tuple(sorted(unique, key=lambda r: (order.index(r.code), tuple(map(str, r.refs)), r.words)))
