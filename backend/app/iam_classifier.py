"""Offline IAM action classification backed by policy-sentry's bundled data.

This module deliberately keeps privilege-escalation detection separate from
policy-sentry access-level metadata: the latter describes API semantics, while
the former is a small permissive security-review heuristic.
"""

from contextvars import ContextVar
from functools import lru_cache
from typing import Any

from app.iam_escalation import _action_matches, paths_for_classifier


_access_levels_unavailable: ContextVar[bool] = ContextVar(
    "iam_access_levels_unavailable", default=False
)
_failed_cache_keys: ContextVar[frozenset[str]] = ContextVar(
    "iam_failed_cache_keys", default=frozenset()
)


def begin_build() -> None:
    """Reset policy-sentry availability diagnostics for one graph build."""
    failed = _failed_cache_keys.get()
    if failed:
        _classify_cached.cache_clear()
        _failed_cache_keys.set(frozenset())
    _access_levels_unavailable.set(False)


def access_levels_unavailable() -> bool:
    return _access_levels_unavailable.get()

_ACCESS_LEVELS = frozenset({
    "Permissions management", "Write", "Tagging", "List", "Read",
})

_PRIVILEGE_ESCALATION_ACTIONS = paths_for_classifier()


def _normalise(action: Any) -> str:
    if not isinstance(action, str):
        return ""
    return action.strip().lower()


@lru_cache(maxsize=256)
def _policy_sentry_service_map(service: str) -> tuple[dict[str, frozenset[str]], bool]:
    """Return (lowercase action -> levels, known service) from policy-sentry."""
    from policy_sentry.querying.actions import get_action_data, get_actions_for_service

    action_names = get_actions_for_service(service)
    known = bool(action_names)
    result: dict[str, set[str]] = {}
    for qualified_name in action_names:
        if not isinstance(qualified_name, str) or ":" not in qualified_name:
            continue
        _, action_name = qualified_name.split(":", 1)
        rows = get_action_data(service, action_name).get(service, [])
        levels = {
            row.get("access_level") for row in rows
            if row.get("access_level") in _ACCESS_LEVELS
        }
        if levels:
            result.setdefault(action_name.lower(), set()).update(levels)
    return {name: frozenset(levels) for name, levels in result.items()}, known


def _policy_sentry_levels(action: str) -> set[str]:
    """Return levels for an exact action or local IAM wildcard pattern."""
    if action == "*":
        return set(_ACCESS_LEVELS)
    if ":" not in action:
        return set()
    service, action_pattern = action.split(":", 1)
    if not service or not action_pattern or service != service.lower():
        # Service prefixes are case-insensitive, but normalize them below;
        # a service wildcard is only meaningful for the whole action wildcard.
        service = service.lower()
    if service == "*":
        return set(_ACCESS_LEVELS) if action_pattern == "*" else set()
    service = service.lower()
    if "*" not in action_pattern and "?" not in action_pattern:
        from policy_sentry.querying.actions import get_action_data
        rows = get_action_data(service, action_pattern).get(service, [])
        direct_levels = {
            row.get("access_level") for row in rows
            if row.get("access_level") in _ACCESS_LEVELS
        }
        if direct_levels:
            return direct_levels
    action_map, known = _policy_sentry_service_map(service)
    if not known:
        return set()
    levels = set()
    for action_name, action_levels in action_map.items():
        if _action_matches(action_pattern, action_name):
            levels.update(action_levels)
    return levels


@lru_cache(maxsize=4096)
def _classify_cached(action: str) -> frozenset[str]:
    try:
        levels = _policy_sentry_levels(action)
        return frozenset(levels or {"Unknown"})
    except Exception:
        # Import, datastore, and API failures are intentionally fail-closed for
        # classification and must never make graph construction fail.
        _access_levels_unavailable.set(True)
        _failed_cache_keys.set(_failed_cache_keys.get() | {action})
        return frozenset({"Unknown"})


def classify_action(action: Any) -> set[str]:
    """Classify one IAM action into policy-sentry access levels.

    The returned set is always a fresh mutable set, while cached values remain
    immutable and deterministic.
    """
    return set(_classify_cached(_normalise(action)))


@lru_cache(maxsize=4096)
def _escalation_cached(action: str) -> bool:
    if action in {"*", "iam:*"}:
        return True
    if ":" not in action:
        return False
    service, action_name = action.split(":", 1)
    if service == "iam" and "*" in action_name:
        return True
    # Match the curated set case-insensitively after normalization.
    return f"{service}:{action_name}" in {
        item.lower() for item in _PRIVILEGE_ESCALATION_ACTIONS
    }


def is_privilege_escalation(action: Any) -> bool:
    """Return whether an action is in the permissive escalation review set."""
    try:
        return _escalation_cached(_normalise(action))
    except Exception:
        return False
