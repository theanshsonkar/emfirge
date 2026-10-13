"""Pathfinding.cloud-backed IAM privilege escalation matching."""
from __future__ import annotations
import fnmatch
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATHS = json.loads((Path(__file__).parent / "data" / "pathfinding_paths.json").read_text())["paths"]


def _value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _action_matches(pattern: Any, permission: str) -> bool:
    return isinstance(pattern, str) and fnmatch.fnmatchcase(permission.lower(), pattern.lower())


@lru_cache(maxsize=4096)
def _action_resource_services(permission: str) -> tuple[bool, tuple[str, ...]]:
    """Return whether policy-sentry knows an action and its ARN services."""
    if ":" not in permission:
        return False, ()
    service, action = permission.split(":", 1)
    if not service or not action:
        return False, ()
    try:
        from policy_sentry.querying.actions import get_action_data

        rows = get_action_data(service, action).get(service, [])
    except Exception:
        return False, ()
    if not rows:
        return False, ()
    services = set()
    for row in rows:
        arn_format = row.get("resource_arn_format")
        if not isinstance(arn_format, str) or arn_format == "*":
            continue
        parts = arn_format.split(":", 5)
        if len(parts) >= 3:
            service_segment = re.sub(r"\\$\\{[^}]+\\}", "*", parts[2])
            services.add(service_segment.lower())
    return True, tuple(sorted(services))


def _resource_covers(resource: Any, permission: str) -> tuple[bool, bool]:
    """Return (covered, resource_unverified) for a resource/action pair."""
    if not isinstance(resource, str):
        return False, False
    if resource == "*":
        return True, False
    if not resource.lower().startswith("arn:"):
        return False, False
    parts = resource.split(":", 5)
    if len(parts) < 3:
        return False, False
    known, services = _action_resource_services(permission)
    if not known:
        return True, True
    if not services:
        return False, False
    return any(fnmatch.fnmatchcase(parts[2].lower(), service) for service in services), False


def _statement_actions(statement: Any) -> list[Any]:
    return list(_value(statement, "actions", []) or [])


def _statement_applies(statement: Any, permission: str) -> bool:
    actions = _statement_actions(statement)
    if _value(statement, "is_not_action", False):
        return not any(_action_matches(action, permission) for action in actions)
    return any(_action_matches(action, permission) for action in actions)


def _allowed_evidence(permission: str, statements: list[Any]) -> dict[str, Any] | None:
    allows = []
    resource_unverified = False
    for statement in statements:
        if str(_value(statement, "effect", "")).lower() != "allow" or not _statement_applies(statement, permission):
            continue
        if _value(statement, "is_not_resource", False):
            covered = True
        else:
            covered_resources = [
                _resource_covers(resource, permission)
                for resource in (_value(statement, "resources", []) or [])
            ]
            covered = any(item[0] for item in covered_resources)
            resource_unverified = resource_unverified or any(item[1] for item in covered_resources if item[0])
        if covered:
            allows.append(statement)
    if not allows:
        return None
    for statement in statements:
        if str(_value(statement, "effect", "")).lower() != "deny" or _value(statement, "has_condition", False):
            continue
        resources = list(_value(statement, "resources", []) or [])
        if "*" in resources and _statement_applies(statement, permission):
            return None
    evidence = {"permission": permission, "conditional": any(bool(_value(s, "has_condition", False)) for s in allows)}
    if resource_unverified:
        evidence["resource_unverified"] = True
    return evidence


def matching_paths(statements: list[Any]) -> list[dict[str, Any]]:
    """Return pathfinding paths whose every required permission is allowed."""
    result = []
    for path in _PATHS:
        evidence = []
        for permission in path.get("required", []):
            item = _allowed_evidence(permission, statements)
            if item is None:
                break
            evidence.append(item)
        else:
            match = dict(path)
            match["evidence"] = evidence
            result.append(match)
    return result


def paths_for_classifier() -> frozenset[str]:
    return frozenset(path["required"][0].lower() for path in _PATHS if len(path.get("required", [])) == 1)
