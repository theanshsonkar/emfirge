"""Terraform Lambda and EC2 settings -> LambdaFunction / EC2Instance fields (AWS adapter).

Unknown stays unknown: a Lambda role or environment, an instance's metadata options or user data
that Terraform cannot show at plan time is reported in unknown_fields and left None / omitted.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from app.plan_ingest_iam import ConfigIndex, IamModel, _is_unknown, _unknown_map

_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[\w.-]*
    \s*[=:]\s*['"]?([^\s'"`$\\{][^\s'"`]{5,})""")
_PLACEHOLDER = re.compile(r"(?i)^(?:changeme|change-me|example|your[_-].*|<.*>|xxx+|\*+|none|null|true|false|undefined)$")


def text_has_secrets(text: str) -> bool:
    """True when the text carries a literal secret: a key id, a private key block, or name=value
    where the name says secret and the value is a literal (not a variable or placeholder)."""
    if _AWS_KEY_ID.search(text) or _PRIVATE_KEY.search(text):
        return True
    return any(not _PLACEHOLDER.match(match.group(1)) for match in _ASSIGNMENT.finditer(text))


def user_data_has_secrets(item: dict, config: ConfigIndex, unknown: list[dict]) -> bool | None:
    """Whether the instance's user data holds a literal secret; None when its text is not in the plan.

    The provider keeps only a hash of user_data in the plan, so the text comes from user_data_base64
    (stored as is) or from a constant in plan.configuration."""
    change = item.get("change") or {}
    after, au = change.get("after") or {}, _unknown_map(change)
    address = item.get("address", "")
    encoded = after.get("user_data_base64")
    if isinstance(encoded, str) and encoded and not _is_unknown(au, "user_data_base64"):
        try:
            return text_has_secrets(base64.b64decode(encoded).decode("utf-8", "replace"))
        except ValueError:
            pass
    constant = config.expression(item, "user_data").get("constant_value")
    if isinstance(constant, str) and constant:
        return text_has_secrets(constant)
    if _is_unknown(au, "user_data") or after.get("user_data") or _is_unknown(au, "user_data_base64"):
        unknown.append({"address": address, "field": "user_data", "reason": "text not available at plan time"})
        return None
    return False if "user_data" in after or "user_data_base64" in after else None


def instance_fields(item: dict, config: ConfigIndex, unknown: list[dict]) -> dict[str, Any]:
    """imdsv2_required (None when metadata_options or http_tokens is unknown) and user data secrets."""
    change = item.get("change") or {}
    after, au = change.get("after") or {}, _unknown_map(change)
    address = item.get("address", "")
    fields: dict[str, Any] = {}
    options = after.get("metadata_options")
    tokens = None
    if not _is_unknown(au, "metadata_options") and isinstance(options, list) and options and isinstance(options[0], dict):
        inner_unknown = au.get("metadata_options")
        inner_unknown = inner_unknown[0] if isinstance(inner_unknown, list) and inner_unknown and isinstance(inner_unknown[0], dict) else {}
        if not inner_unknown.get("http_tokens"):
            tokens = options[0].get("http_tokens")
    if isinstance(tokens, str) and tokens:
        fields["imdsv2_required"] = tokens == "required"
    else:
        fields["imdsv2_required"] = None
        unknown.append({"address": address, "field": "metadata_options", "reason": "http_tokens unknown at plan time"})
    secrets = user_data_has_secrets(item, config, unknown)
    if secrets is not None:
        fields["user_data_has_secrets"] = secrets
    return fields


def lambda_fields(item: dict, iam: IamModel, unknown: list[dict]) -> dict[str, Any]:
    from app.aws_collector import lambda_secret_refs
    change = item.get("change") or {}
    after, au = change.get("after") or {}, _unknown_map(change)
    address = item.get("address", "")
    fields: dict[str, Any] = {}

    value = after.get("role")
    if isinstance(value, str) and value.startswith("arn:") and not _is_unknown(au, "role"):
        fields["role_arn"] = value
    else:
        arn = iam.role_arn(item, "role")
        if arn:
            fields["role_arn"] = arn
        else:
            unknown.append({"address": address, "field": "role", "reason": "unknown Terraform value"})

    environment = after.get("environment")
    env_unknown = au.get("environment")
    if env_unknown is True:
        unknown.append({"address": address, "field": "environment", "reason": "unknown Terraform value"})
    else:
        variables: dict[str, Any] = {}
        unknown_values = False
        if isinstance(environment, list) and environment and isinstance(environment[0], dict):
            variables = dict(environment[0].get("variables") or {})
            inner = env_unknown[0] if isinstance(env_unknown, list) and env_unknown and isinstance(env_unknown[0], dict) else {}
            if inner.get("variables") is True:
                unknown.append({"address": address, "field": "environment", "reason": "unknown Terraform value"})
                variables = None
            elif isinstance(inner.get("variables"), dict):
                for key in inner["variables"]:
                    variables.setdefault(key, None)
                unknown_values = True
        if variables is not None:
            fields["secret_refs"] = lambda_secret_refs(variables)
            if unknown_values:
                unknown.append({"address": address, "field": "environment",
                                "reason": "some variable values are unknown at plan time; only their names were checked"})

    vpc = after.get("vpc_config")
    if isinstance(vpc, list) and vpc and isinstance(vpc[0], dict):
        inner = au.get("vpc_config")
        inner = inner[0] if isinstance(inner, list) and inner and isinstance(inner[0], dict) else {}
        for source, target in (("subnet_ids", "subnet_ids"), ("security_group_ids", "sg_ids")):
            values = vpc[0].get(source)
            if inner.get(source) or (isinstance(values, list) and any(not isinstance(v, str) for v in values)):
                unknown.append({"address": address, "field": f"vpc_config.{source}", "reason": "unknown Terraform value"})
            elif isinstance(values, list):
                fields[target] = list(values)
    elif _is_unknown(au, "vpc_config"):
        unknown.append({"address": address, "field": "vpc_config", "reason": "unknown Terraform value"})
    return fields
