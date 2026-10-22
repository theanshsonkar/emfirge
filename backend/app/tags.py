"""Resource tags: AWS tag limits and the reserved aws: prefix.

Branch changes replace the complete user tag set. Tags whose key starts with
"aws:" are created by AWS (CloudFormation, Service Catalog, ...); users cannot
add, edit or remove them, and they do not count toward the 50-tag limit, so a
branch keeps them as they are.
"""

from __future__ import annotations

from typing import Any, Optional

MAX_USER_TAGS = 50
MAX_KEY_LENGTH = 128
MAX_VALUE_LENGTH = 256

# Resource types whose model carries tags.
TAGGED_TYPES = frozenset({
    "ec2_instance", "security_group", "rds_instance", "s3_bucket",
    "lambda_function", "ebs_volume", "nat_gateway", "route_table",
})


def is_aws_tag(key: str) -> bool:
    return key.lower().startswith("aws:")


def tag_map(items: Any) -> dict[str, str]:
    """AWS [{Key, Value}] lists (any casing of the field names) as a dict."""
    result: dict[str, str] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = item.get("Key", item.get("key"))
        if isinstance(key, str):
            value = item.get("Value", item.get("value", ""))
            result[key] = "" if value is None else str(value)
    return result


def apply_tag_replacement(before: Optional[dict[str, str]], after: Any) -> dict[str, str]:
    """Validate a complete user tag set and return it with the kept aws: tags."""
    if not isinstance(after, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in after.items()):
        raise ValueError("tags: expected an object of string keys to string values")
    kept = {key: value for key, value in (before or {}).items() if is_aws_tag(key)}
    for key, value in after.items():
        if is_aws_tag(key) and kept.get(key) != value:
            raise ValueError(f"tags: '{key}' uses the reserved aws: prefix; AWS does not let users add, edit or remove it")
        if not 1 <= len(key) <= MAX_KEY_LENGTH:
            raise ValueError(f"tags: key length must be 1 to {MAX_KEY_LENGTH} characters")
        if len(value) > MAX_VALUE_LENGTH:
            raise ValueError(f"tags: value for '{key}' is longer than {MAX_VALUE_LENGTH} characters")
    user = {key: value for key, value in after.items() if not is_aws_tag(key)}
    if len(user) > MAX_USER_TAGS:
        raise ValueError(f"tags: AWS allows at most {MAX_USER_TAGS} user tags per resource")
    return {**user, **kept}


def user_tags(tags: Optional[dict[str, str]]) -> dict[str, str]:
    return {key: value for key, value in (tags or {}).items() if not is_aws_tag(key)}


def _tagged_collections(infra: Any) -> dict[str, list]:
    return {
        "ec2_instance": infra.ec2.instances,
        "security_group": infra.ec2.security_groups,
        "ebs_volume": infra.ec2.ebs_volumes,
        "rds_instance": infra.rds.rds_instances,
        "s3_bucket": infra.s3.buckets,
        "lambda_function": infra.lambda_data.functions,
        "nat_gateway": infra.vpc.nat_gateway_details,
        "route_table": infra.vpc.route_tables,
    }


def _ident(item: Any) -> str:
    return getattr(item, "id", None) or getattr(item, "name", "")


def retagged_resources(base: Any, branch: Any) -> list[str]:
    """Existing resources whose user tags differ between base and branch."""
    changed = []
    branch_collections = _tagged_collections(branch)
    for resource_type, items in _tagged_collections(base).items():
        after = {_ident(item): item for item in branch_collections[resource_type]}
        for item in items:
            other = after.get(_ident(item))
            if other is not None and user_tags(item.tags) != user_tags(other.tags):
                changed.append(_ident(item))
    return sorted(changed)


def has_conditional_iam_statement(infra: Any) -> bool:
    """True when any role statement has a Condition; it may test resource tags (ABAC)."""
    for role in infra.iam.role_policies:
        statements = list(role.access_statements)
        for document in role.policy_documents or []:
            statements.extend(document.statements)
        if any(statement.has_condition for statement in statements):
            return True
    return False
