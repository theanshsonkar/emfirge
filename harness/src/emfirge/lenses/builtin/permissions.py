"""The permissions lens: who may now do what, that could not before. And who lost what they had.

Works on any policy document in any setting (see policy.py), on references to separately kept policies, and, where
the state shows no policy at all, on the kind of call that touched the resource.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Iterator

from emfirge.core.model import Change, ChangeType, FieldChange, Finding, Kind, Unknown

from ..api import LensResult, LensView
from . import patterns
from .policy import Grant, Grants, added, grants, matches, principal_class
from .report import fact, status_unknown, unknown, unread_creation
from .state import is_status, leaves, short
from .vocabulary import PolicyWords

NAME = 'permissions'


@dataclass(frozen=True)
class PermissionsLens:
    """kind_of  the kind of a call by its name ('iam.PutRolePolicy' -> Kind.PERMISSION), from the cloud's catalog;
                without it a permission change the state does not show goes unreported by this part"""
    words: PolicyWords = patterns.POLICY
    kind_of: Callable[[str], Kind] | None = None
    name: str = NAME

    def look(self, view: LensView) -> LensResult:
        findings: list[Finding] = []
        unknowns: list[Unknown] = []
        for change in view.changes:
            f, u = self._one(change)
            findings += _once(f)
            unknowns += u
        return LensResult(tuple(findings), tuple(unknowns))

    def _one(self, change: Change) -> tuple[list[Finding], list[Unknown]]:
        blind = unread_creation(NAME, change, 'what it lets anyone do')
        if blind:
            return [], [blind]
        findings: list[Finding] = []
        unknowns: list[Unknown] = []
        seen_policy = False
        for field in change.fields:
            if is_status(field):
                u = status_unknown(NAME, field, change, self.words.status_words)
                unknowns += [u] if u else []
                continue
            before, after = grants(field.before, field.path, self.words), grants(field.after, field.path, self.words)
            seen_policy = seen_policy or bool(before.statements or after.statements)
            if not (before.complete and after.complete):
                unknowns.append(unknown(NAME, f'a policy at {field.path} is too large to compare', change))
                continue
            findings += self._statements(change, field, before, after)
            findings += self._attached(change, field)
        if not seen_policy and change.type is not ChangeType.DELETED:
            findings += self._calls(change)
        return findings, unknowns

    def _statements(self, change: Change, field: FieldChange, before: Grants, after: Grants) -> list[Finding]:
        allow_b = [g for g in before.items if g.effect == 'allow']
        allow_a = [g for g in after.items if g.effect == 'allow']
        deny_b = [g for g in before.items if g.effect == 'deny']
        deny_a = [g for g in after.items if g.effect == 'deny']
        out = [self._new_grant(change, field, code, gs) for code, gs in _grouped(self._classify(added(allow_b, allow_a), allow_b))]
        out += self._new_principals(change, field, allow_b, allow_a)
        out += [_lost(change, field, 'allow_removed', gs, 'may no longer', '(what relied on it may break)')
                for _, gs in _grouped(('allow_removed', g) for g in added(allow_a, allow_b))]
        out += [_lost(change, field, 'deny_removed', gs, 'is no longer refused', '(a Deny was removed)')
                for _, gs in _grouped(('deny_removed', g) for g in added(deny_a, deny_b))]
        return out

    def _classify(self, new: list[Grant], old: list[Grant]) -> Iterator[tuple[str, Grant]]:
        for g in new:
            if self._trust(g):
                yield 'trust_widened', g
            elif any(b.condition and not g.condition and (b.principal, b.action, b.resource) == (g.principal, g.action, g.resource)
                     for b in old):
                yield 'condition_removed', g
            else:
                yield ('allow_widened' if g.wide else 'allow_added'), g

    def _trust(self, g: Grant) -> bool:
        return any(matches(t.lower(), g.action.lower()) for t in self.words.trust_actions)

    def _new_grant(self, change: Change, field: FieldChange, code: str, gs: list[Grant]) -> Finding:
        who = _who(gs[0].principal)
        acts, res = {g.action for g in gs}, {g.resource for g in gs}
        verb = {'trust_widened': 'may now take on this identity with',
                'condition_removed': 'is no longer limited by a condition for',
                'allow_widened': 'may now (wildcard)',
                'allow_added': 'may now'}[code]
        return fact(NAME, code, f'{who} {verb} {short(acts)} on {short(res)}', change, field.path,
                    after={'principal': gs[0].principal, 'actions': sorted(acts), 'resources': sorted(res)},
                    principal_class=principal_class(gs[0].principal, self.words))

    def _new_principals(self, change: Change, field: FieldChange, old: list[Grant], new: list[Grant]) -> list[Finding]:
        known = {g.principal for g in old}
        fresh = sorted({g.principal for g in new if g.principal and g.principal not in known
                        and not any(matches(k, g.principal) for k in known if k)})
        return [fact(NAME, 'principal_added', f'the policy now names {p} ({principal_class(p, self.words)})',
                     change, field.path, after=p, principal_class=principal_class(p, self.words)) for p in fresh]

    def _attached(self, change: Change, field: FieldChange) -> list[Finding]:
        def refs(value: object) -> set[str]:
            return {str(n.value) for n in leaves(value, field.path) if n.value and self.words.attached_keys.search(n.shape)}
        before, after = refs(field.before), refs(field.after)
        return ([fact(NAME, 'policy_attached', f'policy {a} is now attached', change, field.path, after=a) for a in sorted(after - before)]
                + [fact(NAME, 'policy_detached', f'policy {b} is no longer attached (what relied on it may break)',
                        change, field.path, before=b) for b in sorted(before - after)])

    def _calls(self, change: Change) -> list[Finding]:
        """A call of the permission kind with no policy in the state to compare: the call itself is the fact."""
        if self.kind_of is None:
            return []
        calls = [c for c in change.calls if self.kind_of(c) is Kind.PERMISSION]
        if not calls:
            return []
        return [fact(NAME, 'permission_call_unseen', f'{short(calls)} changed who may do what, and the branch state '
                                                     'does not show the policy', change, calls=list(calls))]


def _grouped(items: Iterator[tuple[str, Grant]] | list[tuple[str, Grant]]) -> list[tuple[str, list[Grant]]]:
    """One finding per (code, principal, condition): a statement of ten actions is one fact, not ten."""
    groups: dict[tuple[str, str, str], list[Grant]] = defaultdict(list)
    for code, g in items:
        groups[(code, g.principal, g.condition)].append(g)
    return [(key[0], groups[key]) for key in sorted(groups)]


def _once(findings: list[Finding]) -> list[Finding]:
    """One finding per fact: the same policy shows in several reads of one resource (a role's trust policy in its
    own read and in the list of roles), and says the same thing in each."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        seen.setdefault((f.code, f.message, f.refs), f)
    return list(seen.values())


def _lost(change: Change, field: FieldChange, code: str, gs: list[Grant], verb: str, why: str) -> Finding:
    acts, res = {g.action for g in gs}, {g.resource for g in gs if g.resource}
    on = f' on {short(res)}' if res else ''    # a trust policy names no resource: the role itself is it
    return fact(NAME, code, f'{_who(gs[0].principal)} {verb} {short(acts)}{on} {why}', change, field.path,
                before={'principal': gs[0].principal, 'actions': sorted(acts), 'resources': sorted(res)})


def _who(principal: str) -> str:
    return principal or 'whoever holds this policy'
