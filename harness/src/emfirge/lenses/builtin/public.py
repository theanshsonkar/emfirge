"""The public lens: something becomes reachable by everyone, that was not before.

Four generic detectors, each run on the value before and after one changed setting; only facts of `after` that
`before` lacks are reported:
  policy   an Allow to everyone that no fixed condition narrows
  range    an address range meaning the whole internet, newly allowed (with the ports beside it)
  flag     a switch whose name says public turned on, or one that blocks public access turned off
  value    a value that means everyone in a known place ('AllUsers'); the only part with per-service lines, as data
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from emfirge.core.model import Change, ChangeType, FieldChange, Finding, Unknown

from ..api import LensResult, LensView
from . import patterns
from .policy import added, grants, is_everyone, limited
from .report import fact, status_unknown, unread_creation
from .state import Node, as_switch, is_status, leaves, short
from .vocabulary import PolicyWords, PublicWords

NAME = 'public'


@dataclass(frozen=True)
class PublicLens:
    words: PublicWords = patterns.PUBLIC
    policy: PolicyWords = patterns.POLICY
    name: str = NAME

    def look(self, view: LensView) -> LensResult:
        findings: list[Finding] = []
        unknowns: list[Unknown] = []
        for change in view.changes:
            if change.type is ChangeType.DELETED:
                continue    # a deletion can close access, never open it
            blind = unread_creation(NAME, change, 'whether everyone can reach it')
            if blind:
                unknowns.append(blind)
                continue
            for field in change.fields:
                if is_status(field):
                    u = status_unknown(NAME, field, change, self.words.status_words)
                    unknowns += [u] if u else []
                else:
                    findings += self._field(change, field)
        return LensResult(tuple(findings), tuple(unknowns))

    def _field(self, change: Change, field: FieldChange) -> list[Finding]:
        out = self._policy(change, field)
        for detector in (self._ranges, self._flags, self._values):
            new = detector(field.after, field.path) - detector(field.before, field.path)
            out += [self._say(change, field, item) for item in sorted(new)]
        lost = sorted(s for _, s in self._blocks(field.before, field.path) - self._blocks(field.after, field.path))
        if lost:   # one setting switched off is one fact, however many flags it has
            out.append(fact(NAME, 'block_off', f'public access is no longer blocked by {short(lost, 4)}', change,
                            field.path, before=True, after=False, flags=lost))
        return out

    def _policy(self, change: Change, field: FieldChange) -> list[Finding]:
        def open_to_all(value: Any) -> list:
            return [g for g in grants(value, field.path, self.policy).items
                    if g.effect == 'allow' and is_everyone(g.principal, self.policy)
                    and not limited(g.condition, self.policy, self.words.everyone_ranges)]
        new = added(open_to_all(field.before), open_to_all(field.after))
        if not new:
            return []
        acts, res = {g.action for g in new}, {g.resource for g in new}
        return [fact(NAME, 'policy_allows_everyone', f'a policy now lets everyone {short(acts)} on {short(res)}',
                     change, field.path, after={'actions': sorted(acts), 'resources': sorted(res)})]

    def _ranges(self, value: Any, path: str) -> set[tuple]:
        return {('range', n.shape, n.value, self._context(n)) for n in leaves(value, path)
                if n.value in self.words.everyone_ranges and not self._outbound_or_deny(n)}

    def _context(self, node: Node) -> tuple:
        """What the address opens: the ports and protocol beside it (nearest two mappings)."""
        return tuple(sorted((k, str(v)) for parent in node.parents[:2] for k, v in parent.items()
                            if self.words.context_keys.search(k) and not isinstance(v, (dict, list))))

    def _outbound_or_deny(self, node: Node) -> bool:
        if self.words.outbound.search(node.path):
            return True
        near = node.parents[:2]
        return any((self.words.outbound.search(k) and v is True) or (isinstance(v, str) and v.lower() in self.words.deny_values)
                   for parent in near for k, v in parent.items())

    def _flags(self, value: Any, path: str) -> set[tuple]:
        return {('flag', n.shape, n.key) for n in leaves(value, path)
                if self.words.open_flags.search(n.shape) and not self.words.block_flags.search(n.shape)
                and as_switch(n.value, self.words.on, self.words.off) is True}

    def _blocks(self, value: Any, path: str) -> set[tuple]:
        """Blocks that are on. One on before and not on after (off, or removed with its whole setting) is the news."""
        return {('block', n.shape) for n in leaves(value, path) if self.words.block_flags.search(n.shape)
                and as_switch(n.value, self.words.on, self.words.off) is True}

    def _values(self, value: Any, path: str) -> set[tuple]:
        return {('value', n.shape, n.value, rule.why) for n in leaves(value, path) for rule in self.words.values
                if isinstance(n.value, str) and rule.key.search(n.key) and rule.value.search(n.value)}

    def _say(self, change: Change, field: FieldChange, item: tuple) -> Finding:
        kind = item[0]
        if kind == 'range':
            ports = ', '.join(f'{k} {v}' for k, v in item[3]) or 'all ports'
            return fact(NAME, 'address_open', f'{item[2]} (everyone) is now allowed at {item[1]} ({ports})',
                        change, field.path, after=item[2], ports=dict(item[3]))
        if kind == 'flag':
            return fact(NAME, 'flag_on', f'{item[2]} is now on', change, item[1], after=True)
        return fact(NAME, 'grant_to_everyone', f'{item[2]} at {item[1]}: {item[3]}', change, item[1], after=item[2])
