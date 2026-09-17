"""Offline IAM action classification backed by policy-sentry's bundled data.

This module deliberately keeps privilege-escalation detection separate from
policy-sentry access-level metadata: the latter describes API semantics, while
the former is a small permissive security-review heuristic.
"""

from functools import lru_cache
from typing import Any

_ACCESS_LEVELS = frozenset({
    "Permissions management", "Write", "Tagging", "List", "Read",
})

# Curated, intentionally permissive review set.  This is not a replacement for
# policy-sentry's IAM datastore and errs toward flagging possible escalation.
_PRIVILEGE_ESCALATION_ACTIONS = frozenset({
    "iam:PassRole", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
    "iam:PutRolePolicy", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
    "iam:CreateRole", "iam:DeleteRolePermissionsBoundary",
    "iam:PutRolePermissionsBoundary", "iam:AttachGroupPolicy",
    "iam:DetachUserPolicy", "iam:DetachRolePolicy", "iam:UpdateRole",
    "iam:UpdateUser", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:CreateServiceLinkedRole", "sts:AssumeRole",
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
    "lambda:AddPermission", "cloudformation:CreateStack",
    "cloudformation:UpdateStack", "ec2:RunInstances",
})


def _normalise(action: Any) -> str:
    if not isinstance(action, str):
        return ""
    return action.strip().lower()


def _policy_sentry_levels(action: str) -> set[str]:
    """Return levels from the installed policy-sentry bundle, without I/O."""
    from policy_sentry.querying.actions import get_action_data

    if action == "*":
        # policy-sentry can enumerate this, but the explicit result avoids a
        # potentially expensive all-services expansion and is semantically exact.
        return set(_ACCESS_LEVELS)
    if ":" not in action:
        return set()
    service, action_name = action.split(":", 1)
    if not service or not action_name:
        return set()
    rows = get_action_data(service, action_name)
    levels = set()
    for row in rows.get(service, []):
        level = row.get("access_level")
        if level in _ACCESS_LEVELS:
            levels.add(level)
    return levels


@lru_cache(maxsize=4096)
def _classify_cached(action: str) -> frozenset[str]:
    try:
        levels = _policy_sentry_levels(action)
        return frozenset(levels or {"Unknown"})
    except Exception:
        # Import, datastore, and API failures are intentionally fail-closed for
        # classification and must never make graph construction fail.
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
