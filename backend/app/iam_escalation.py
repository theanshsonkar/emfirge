"""Pathfinding.cloud-backed IAM privilege escalation matching."""
from __future__ import annotations
import fnmatch
import json
from pathlib import Path
from typing import Any

_PATHS = json.loads((Path(__file__).parent / "data" / "pathfinding_paths.json").read_text())["paths"]


def _value(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _action_matches(pattern: Any, permission: str) -> bool:
    return isinstance(pattern, str) and fnmatch.fnmatchcase(permission.lower(), pattern.lower())


def _resource_covers(resource: Any, permission: str) -> bool:
    if not isinstance(resource, str):
        return False
    if resource == "*":
        return True
    if not resource.lower().startswith("arn:"):
        return False
    parts = resource.split(":", 5)
    if len(parts) < 3:
        return False
    service = permission.split(":", 1)[0]
    return fnmatch.fnmatchcase(service.lower(), parts[2].lower())


def _statement_actions(statement: Any) -> list[Any]:
    return list(_value(statement, "actions", []) or [])


def _statement_applies(statement: Any, permission: str) -> bool:
    actions = _statement_actions(statement)
    if _value(statement, "is_not_action", False):
        return not any(_action_matches(action, permission) for action in actions)
    return any(_action_matches(action, permission) for action in actions)


def _allowed_evidence(permission: str, statements: list[Any]) -> dict[str, Any] | None:
    allows = []
    for statement in statements:
        if str(_value(statement, "effect", "")).lower() != "allow" or not _statement_applies(statement, permission):
            continue
        if _value(statement, "is_not_resource", False):
            covered = True
        else:
            covered = any(_resource_covers(resource, permission) for resource in (_value(statement, "resources", []) or []))
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
    return {"permission": permission, "conditional": any(bool(_value(s, "has_condition", False)) for s in allows)}


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
