"""Policy statements anywhere in a setting, as grants that can be compared.

Any mapping with an effect key is a statement, whatever service holds it (a role, a bucket, a queue, a key). A
statement is expanded into grants: one (effect, principal, action, resource, condition) each. A grant of `after` is
new only when no grant of `before` already covers it (same effect and condition or none, and a pattern of before
matches it), so a narrower rule is never news and a wider one always is.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .state import nodes
from .vocabulary import PolicyWords

NOT = 'NOT:'   # marks a part written with NotAction / NotResource / NotPrincipal: "everything except"


@dataclass(frozen=True, order=True)
class Grant:
    effect: str          # 'allow' | 'deny'
    principal: str       # '' for the holder of the policy; 'Type:value' or '*' otherwise
    action: str
    resource: str
    condition: str = ''  # the condition as canonical JSON, '' when there is none

    @property
    def wide(self) -> bool:
        """The action or resource is a pattern or an 'everything except'."""
        return any(ch in part for part in (self.action, self.resource) for ch in '*?') or \
            self.action.startswith(NOT) or self.resource.startswith(NOT)


@dataclass(frozen=True)
class Grants:
    """The grants found in one value. complete is False when a statement was too large to expand."""
    items: frozenset[Grant] = frozenset()
    statements: int = 0
    complete: bool = True


def grants(value: Any, path: str, words: PolicyWords) -> Grants:
    found: set[Grant] = set()
    count, complete = 0, True
    for node in nodes(value, path):
        if isinstance(node.value, dict) and words.effect_key in node.value:
            count += 1
            expanded = _expand(node.value, words)
            if expanded is None:
                complete = False
            else:
                found |= expanded
    return Grants(frozenset(found), count, complete)


def _expand(statement: dict, words: PolicyWords) -> set[Grant] | None:
    effect = str(statement.get(words.effect_key, '')).lower()
    if effect not in (words.allow.lower(), words.deny.lower()):
        return set()
    principals = _principals(statement, words)
    actions = _parts(statement, words.action, words.not_action)
    resources = _parts(statement, words.resource, words.not_resource)
    if len(principals) * len(actions) * len(resources) > words.max_grants:
        return None
    condition = _canonical(statement.get(words.condition))
    return {Grant(effect, p, a, r, condition) for p in principals for a in actions for r in resources}


def _principals(statement: dict, words: PolicyWords) -> list[str]:
    if words.not_principal in statement:
        return [NOT + _canonical(statement[words.not_principal])]
    value = statement.get(words.principal)
    if value is None:
        return ['']
    if isinstance(value, dict):
        return [f'{kind}:{v}' for kind, vs in sorted(value.items()) for v in _as_list(vs)] or ['']
    return [str(v) for v in _as_list(value)]


def _parts(statement: dict, key: str, not_key: str) -> list[str]:
    if not_key in statement:
        return [NOT + str(v) for v in _as_list(statement[not_key])]
    return [str(v) for v in _as_list(statement.get(key, ''))]


def _as_list(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _canonical(value: Any) -> str:
    return '' if value in (None, {}, []) else json.dumps(value, sort_keys=True, default=str)


def covers(wide: Grant, narrow: Grant) -> bool:
    """`wide` already allows (or refuses) everything `narrow` does."""
    return (wide.effect == narrow.effect
            and (not wide.condition or wide.condition == narrow.condition)
            and matches(wide.principal, narrow.principal)
            and matches(wide.action.lower(), narrow.action.lower())
            and matches(wide.resource, narrow.resource))


def matches(pattern: str, value: str) -> bool:
    if pattern == value:
        return True
    if pattern.startswith(NOT) or value.startswith(NOT):
        return False
    return re.fullmatch(_wildcard(pattern), value) is not None


def _wildcard(pattern: str) -> str:
    return ''.join('.*' if ch == '*' else '.' if ch == '?' else re.escape(ch) for ch in pattern)


def added(before: Iterable[Grant], after: Iterable[Grant]) -> list[Grant]:
    """Grants of `after` that nothing in `before` covers."""
    old = list(before)
    return sorted(g for g in set(after) if not any(covers(b, g) for b in old))


def is_everyone(principal: str, words: PolicyWords) -> bool:
    return principal in words.everyone or principal.startswith(NOT)


def principal_class(principal: str, words: PolicyWords) -> str:
    if not principal:
        return 'holder'
    if principal.startswith(NOT):
        return 'everyone'
    return next((name for name, rx in words.principal_classes if rx.search(principal)), 'other')


def limited(condition: str, words: PolicyWords, everyone_ranges: frozenset[str]) -> bool:
    """The condition narrows who can call to a fixed set (a source address, an account, an organisation)."""
    if not condition:
        return False
    data = json.loads(condition)
    if not isinstance(data, dict):
        return False
    return any(_block_limits(op, block, words, everyone_ranges) for op, block in data.items())


def _block_limits(operator: str, block: Any, words: PolicyWords, everyone_ranges: frozenset[str]) -> bool:
    name = str(operator).lower()
    if any(name.startswith(p) for p in words.ignored_operator_prefixes) or not isinstance(block, dict):
        return False
    name = name.removeprefix(words.any_value_prefix)
    if name not in words.limiting_operators:
        return False
    for key, values in block.items():
        fixed = [v for v in _as_list(values) if isinstance(v, str) and v and not any(c in v for c in '*?$')
                 and v not in everyone_ranges]
        if str(key).lower() in words.limiting_keys and fixed and len(fixed) == len(_as_list(values)):
            return True
    return False
