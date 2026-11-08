"""Permission facts: which ACTIONS an identity may call on which resources.

CORE module, cloud-neutral (L56 entry ``set()``): no provider library, no adapter
import. An adapter injects the two provider-specific parts:

  * ``catalog(service)``      the provider's own action names of a service (or None)
  * ``matches(pattern, rid)`` whether a statement's resource pattern covers a target

Everything else is neutral and deterministic: one ``decide`` function evaluates
Allow/Deny statements for one (action, target) pair, and ``role_permissions`` and
``diff_permissions`` are built on it, so the context answer and the check answer
can never disagree.

What is never claimed:
  * which actions application code calls (not visible; the caller states that)
  * the result of a NotAction / NotResource statement: never evaluated; an Allow of that kind makes a pair
    "unknown", a Deny of that kind makes a plain allow "conditional"
  * a conditional statement as a plain allow: state "conditional"

States of one (action, target) pair: allow | conditional | unknown | none.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Collection, Iterable, Mapping, NamedTuple, Optional, Sequence

ALLOW, CONDITIONAL, UNKNOWN, NONE = "allow", "conditional", "unknown", "none"

Catalog = Callable[[str], Optional[Collection[str]]]
Matches = Callable[[str, str], bool]

MAX_UNCERTAIN_LISTED = 20


class Target(NamedTuple):
    """A resource an identity can reach: its id and the service whose actions address it."""
    id: str
    service: str


@dataclass(frozen=True)
class Statement:
    effect: str  # "allow" | "deny"
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_action: bool = False
    not_resource: bool = False
    conditional: bool = False


@dataclass(frozen=True)
class PermissionLine:
    """One action allowed (or conditionally allowed) on the listed targets."""
    action: str
    effect: str  # "allow" | "conditional"
    resource_ids: tuple[str, ...]


@dataclass(frozen=True)
class Permissions:
    allows: tuple[PermissionLine, ...]
    notes: tuple[tuple[str, str], ...]  # (topic, reason), sorted, no customer identifiers


@dataclass(frozen=True)
class PermissionDiff:
    removed: Mapping[str, tuple[str, ...]]   # action -> targets that were allowed and no longer are
    added: Mapping[str, tuple[str, ...]]     # action -> targets that were not allowed and now are
    uncertain: tuple[str, ...]               # actions whose state changed to/from conditional or unknown
    notes: tuple[tuple[str, str], ...]


def _get(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, Mapping) else getattr(item, key, default)


def normalize(statements: Optional[Iterable[Any]]) -> tuple[Statement, ...]:
    """Statements (models or mappings) as neutral values. Anything that is not Allow/Deny is dropped."""
    result = []
    for item in statements or ():
        effect = str(_get(item, "effect", "") or "").lower()
        if effect not in {"allow", "deny"}:
            continue
        result.append(Statement(
            effect=effect,
            actions=tuple(str(a) for a in (_get(item, "actions", []) or [])),
            resources=tuple(str(r) for r in (_get(item, "resources", []) or [])),
            not_action=bool(_get(item, "is_not_action", False)),
            not_resource=bool(_get(item, "is_not_resource", False)),
            conditional=bool(_get(item, "has_condition", False)),
        ))
    return tuple(result)


@lru_cache(maxsize=4096)
def _pattern(pattern: str) -> "re.Pattern[str]":
    """IAM wildcard (* and ?) as a case-insensitive full match."""
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(body, re.IGNORECASE | re.DOTALL)


def action_matches(pattern: str, action: str) -> bool:
    return _pattern(pattern).fullmatch(action) is not None


def _service(action: str) -> str:
    return action.split(":", 1)[0].lower() if ":" in action else ""


def _has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


# ── one pair ──────────────────────────────────────────────────────

def _action_applies(statement: Statement, action: str) -> bool:
    hit = any(action_matches(p, action) for p in statement.actions)
    return not hit if statement.not_action else hit


def _resource_applies(statement: Statement, target: str, matches: Matches) -> bool:
    hit = any(matches(p, target) for p in statement.resources)
    return not hit if statement.not_resource else hit


def _decide(statements: Sequence[Statement], applies: Sequence[bool], action: str) -> str:
    """The state of one action given which statements already cover the target."""
    plain_deny = uncertain_deny = False
    plain_allow = conditional_allow = unknown_allow = False
    for statement, covers in zip(statements, applies):
        unexpanded = statement.not_action or statement.not_resource
        # A negated statement is never evaluated: the complement of an approximate match is not trustworthy,
        # so it is treated as possibly applying to every pair.
        if not unexpanded and not (covers and _action_applies(statement, action)):
            continue
        if statement.effect == "deny":
            if unexpanded or statement.conditional:
                uncertain_deny = True
            else:
                plain_deny = True
        elif unexpanded:
            unknown_allow = True
        elif statement.conditional:
            conditional_allow = True
        else:
            plain_allow = True
    if plain_deny:
        return NONE
    if plain_allow:
        return CONDITIONAL if uncertain_deny else ALLOW
    if unknown_allow:
        return UNKNOWN
    if conditional_allow:
        return CONDITIONAL
    return NONE


def decide(statements: Sequence[Statement], action: str, target: str, matches: Matches) -> str:
    """allow | conditional | unknown | none for one action on one target. A plain Deny always wins."""
    applies = [_resource_applies(s, target, matches) for s in statements]
    return _decide(statements, applies, action)


# ── the action universe ───────────────────────────────────────────

class _Universe:
    """Concrete actions named by the Allow statements, per service, expanded from the catalog."""

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self.by_service: dict[str, dict[str, str]] = {}   # service -> lower name -> canonical name
        self.notes: set[tuple[str, str]] = set()
        self._canon: dict[str, dict[str, str]] = {}

    def _canonical(self, service: str) -> dict[str, str]:
        if service not in self._canon:
            names = self.catalog(service)
            self._canon[service] = {n.lower(): n for n in names} if names else {}
        return self._canon[service]

    def add(self, statements: Sequence[Statement]) -> None:
        for statement in statements:
            if statement.effect != "allow":
                continue
            if statement.not_action or statement.not_resource:
                self.notes.add(("not_action_not_expanded",
                                "a statement with NotAction or NotResource is not expanded into actions; "
                                "what it allows is unknown"))
            if statement.not_action:
                continue
            for pattern in statement.actions:
                self._add_pattern(pattern)

    def _add_pattern(self, pattern: str) -> None:
        service = _service(pattern)
        if not service or _has_wildcard(service):
            self.notes.add(("action_wildcard_not_expanded",
                            "an action pattern with a wildcard service (such as '*') is not expanded into actions; "
                            "it addresses every service"))
            return
        canon = self._canonical(service)
        bucket = self.by_service.setdefault(service, {})
        if not _has_wildcard(pattern):
            name = pattern.split(":", 1)[1] if ":" in pattern else ""
            bucket.setdefault(pattern.lower(), canon.get(pattern.lower(), f"{service}:{name}"))
            return
        if not canon:
            self.notes.add(("action_list_unavailable",
                            f"no action list is available for service '{service}'; its wildcard actions are not expanded"))
            return
        for lower, name in canon.items():
            if action_matches(pattern, name):
                bucket.setdefault(lower, name)

    def actions_for(self, service: str) -> list[str]:
        return sorted(self.by_service.get(service.lower(), {}).values())


def _expanded_targets(statements: Sequence[Statement], targets: Sequence[Target], matches: Matches
                      ) -> dict[str, list[bool]]:
    return {t.id: [_resource_applies(s, t.id, matches) for s in statements] for t in targets}


def _sorted_notes(notes: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(set(notes)))


# ── public: one identity, one snapshot ────────────────────────────

def role_permissions(statements: Sequence[Statement], targets: Sequence[Target], catalog: Catalog,
                     matches: Matches) -> Permissions:
    """The effective (action, targets) allow list: sorted, deterministic, plain allows and conditional ones apart."""
    universe = _Universe(catalog)
    universe.add(statements)
    covers = _expanded_targets(statements, targets, matches)
    found: dict[tuple[str, str], list[str]] = {}
    for target in sorted(targets, key=lambda t: t.id):
        for action in universe.actions_for(target.service):
            state = _decide(statements, covers[target.id], action)
            if state in (ALLOW, CONDITIONAL):
                found.setdefault((action, state), []).append(target.id)
    lines = tuple(PermissionLine(action, state, tuple(sorted(ids)))
                  for (action, state), ids in sorted(found.items()))
    notes = set(universe.notes)
    if any(s.conditional for s in statements):
        notes.add(("conditional_statements", "statements with a condition are listed as conditional, never as a plain allow"))
    return Permissions(allows=lines, notes=_sorted_notes(notes))


def diff_permissions(before: Sequence[Statement], after: Sequence[Statement], targets: Sequence[Target],
                     catalog: Catalog, matches: Matches) -> PermissionDiff:
    """Per action: targets that went from allowed to not allowed (and back); anything uncertain is set apart."""
    universe = _Universe(catalog)
    universe.add(before)
    universe.add(after)
    covers_before = _expanded_targets(before, targets, matches)
    covers_after = _expanded_targets(after, targets, matches)
    removed: dict[str, list[str]] = {}
    added: dict[str, list[str]] = {}
    uncertain: set[str] = set()
    for target in sorted(targets, key=lambda t: t.id):
        for action in universe.actions_for(target.service):
            was = _decide(before, covers_before[target.id], action)
            now = _decide(after, covers_after[target.id], action)
            if was == now:
                continue
            if was == ALLOW and now == NONE:
                removed.setdefault(action, []).append(target.id)
            elif was == NONE and now == ALLOW:
                added.setdefault(action, []).append(target.id)
            else:
                uncertain.add(action)
    notes = set(universe.notes)
    if uncertain:
        listed = sorted(uncertain)
        shown = ", ".join(listed[:MAX_UNCERTAIN_LISTED])
        more = f" and {len(listed) - MAX_UNCERTAIN_LISTED} more" if len(listed) > MAX_UNCERTAIN_LISTED else ""
        notes.add(("permission_uncertain",
                   f"{len(listed)} actions became or stopped being conditional or unexpanded, so whether the role "
                   f"may call them is not decided: {shown}{more}"))
    return PermissionDiff(
        removed={a: tuple(sorted(ids)) for a, ids in sorted(removed.items())},
        added={a: tuple(sorted(ids)) for a, ids in sorted(added.items())},
        uncertain=tuple(sorted(uncertain)),
        notes=_sorted_notes(notes),
    )
