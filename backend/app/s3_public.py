"""S3 public-access evaluation following AWS's "meaning of public".

Source: S3 Block Public Access docs ("The meaning of public"). A bucket policy
is assumed public; an Allow statement is non-public only when its principal is
a fixed, non-wildcard value or a fixed-value condition limits it to one of the
keys below. Anything we cannot prove limited counts as public (fail closed).
"""

from __future__ import annotations

import json
import re
from ipaddress import ip_network
from typing import Any, Optional

# Condition keys AWS accepts as limiting a public principal, when the value is fixed.
LIMITING_KEYS = frozenset({
    "aws:sourceip", "aws:sourcearn", "aws:sourcevpc", "aws:sourcevpce",
    "aws:sourceowner", "aws:sourceaccount", "aws:userid",
    "s3:dataaccesspointarn", "s3:dataaccesspointaccount",
    # "An AWS principal, user, role, or service principal (e.g. aws:PrincipalOrgID)"
    "aws:principalorgid", "aws:principalaccount", "aws:principalarn",
})

# Positive operators only. Negated operators, Null, Bool and ...IfExists do not
# limit who can call (a missing key passes them), so they leave a statement public.
_LIMITING_OPERATORS = frozenset({
    "stringequals", "stringequalsignorecase", "stringlike",
    "arnequals", "arnlike", "ipaddress",
})

PUBLIC_ACL_GROUPS = ("AllUsers", "AuthenticatedUsers")

_ACCESS_POINT_ARN = re.compile(r"^arn:aws[\w-]*:s3:[a-z0-9-]+:\d{12}:accesspoint/.*$")


def _list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _not_fixed(value: str) -> bool:
    return "*" in value or "?" in value or "${" in value


def _principal_is_public(statement: dict) -> bool:
    if "NotPrincipal" in statement:
        return True
    principal = statement.get("Principal")
    if principal is None:
        return True
    if isinstance(principal, str):
        return principal == "*" or _not_fixed(principal)
    if not isinstance(principal, dict):
        return True
    for values in principal.values():
        for value in _list(values):
            if not isinstance(value, str) or _not_fixed(value):
                return True
    return False


def _fixed_value(key: str, value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if key == "aws:sourceip":
        if _not_fixed(value):
            return False
        try:
            network = ip_network(value, strict=False)
        except ValueError:
            return False
        return network.prefixlen >= (8 if network.version == 4 else 32)
    if key == "s3:dataaccesspointarn" and _ACCESS_POINT_ARN.match(value):
        # A wildcard access point name is allowed when the account is fixed.
        head = value.split(":accesspoint/", 1)[0]
        return not _not_fixed(head)
    return not _not_fixed(value)


def _condition_limits(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        name = operator.lower()
        if name.startswith("foranyvalue:"):
            name = name.split(":", 1)[1]
        elif name.startswith("forallvalues:"):
            # ForAllValues is true when the key is absent, so it never limits.
            continue
        if name not in _LIMITING_OPERATORS:
            continue
        for key, values in block.items():
            key = str(key).lower()
            if key not in LIMITING_KEYS:
                continue
            values = _list(values)
            if values and all(_fixed_value(key, value) for value in values):
                return True
    return False


def statement_is_public(statement: Any) -> bool:
    if not isinstance(statement, dict):
        return True
    if statement.get("Effect") == "Deny":
        return False
    if not _principal_is_public(statement):
        return False
    return not _condition_limits(statement.get("Condition"))


def policy_is_public(policy: Any) -> bool:
    """True when a bucket policy grants public access. Invalid JSON raises ValueError."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except (TypeError, ValueError) as exc:
            raise ValueError("bucket policy must be valid JSON") from exc
    if not isinstance(policy, dict):
        raise ValueError("bucket policy must be a JSON object")
    statements = policy.get("Statement", [])
    return any(statement_is_public(item) for item in _list(statements))


def acl_grants_are_public(grants: list) -> bool:
    for grant in grants or []:
        uri = (grant.get("Grantee") or {}).get("URI", "")
        if any(uri.endswith("/" + group) for group in PUBLIC_ACL_GROUPS):
            return True
    return False


def effective_is_public(
    acl_public: Optional[bool],
    policy_public: Optional[bool],
    ignore_public_acls: Optional[bool],
    restrict_public_buckets: Optional[bool],
) -> bool:
    """Unknown parts are treated as public evidence absent and blocks absent."""
    return bool(
        (acl_public and not ignore_public_acls)
        or (policy_public and not restrict_public_buckets)
    )
