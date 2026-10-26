"""Terraform S3 bucket settings -> S3Bucket fields (AWS adapter).

Settings arrive two ways: inline on aws_s3_bucket (provider 4.x blocks) and as separate resources
(aws_s3_bucket_acl, _versioning, _server_side_encryption_configuration, _public_access_block,
_policy, _logging). A value Terraform marks "known after apply" stays None and is reported in
unknown_fields; an unconfigured setting is never read as "off".
"""
from __future__ import annotations

import json
from typing import Any

from app.mutations import Change
from app.plan_ingest_iam import ConfigIndex, _is_unknown, _module_key, _unknown_map

S3_SEPARATE_TYPES = frozenset({
    "aws_s3_bucket_acl", "aws_s3_bucket_versioning", "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_public_access_block", "aws_s3_bucket_policy", "aws_s3_bucket_logging",
})
PUBLIC_CANNED_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})
_PUBLIC_GROUPS = ("/AllUsers", "/AuthenticatedUsers")
_BPA_FIELDS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")


def _note(unknown: list[dict], address: str, field: str, reason: str = "unknown Terraform value") -> None:
    entry = {"address": address, "field": field, "reason": reason}
    if entry not in unknown:
        unknown.append(entry)


def _canned_acl_public(acl: Any) -> bool | None:
    return acl in PUBLIC_CANNED_ACLS if isinstance(acl, str) and acl else None


def _grants_public(grants: Any) -> bool | None:
    """True when a known grant list gives the public groups access; None when it says nothing either way."""
    for grant in grants or []:
        if isinstance(grant, dict):
            grantee = grant.get("grantee") if isinstance(grant.get("grantee"), list) else [grant]
            for entry in grantee:
                uri = entry.get("uri") if isinstance(entry, dict) else None
                if isinstance(uri, str) and uri.endswith(_PUBLIC_GROUPS):
                    return True
    return None


def _policy_field(value: Any, address: str, unknown: list[dict]) -> str | None:
    if isinstance(value, dict):
        value = json.dumps(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        json.loads(value)
    except ValueError:
        _note(unknown, address, "policy", "invalid JSON")
        return None
    return value


def inline_fields(item: dict, unknown: list[dict]) -> dict[str, Any]:
    """Settings read from the aws_s3_bucket resource itself (provider 4.x inline blocks)."""
    change = item.get("change") or {}
    after, au = change.get("after") or {}, _unknown_map(change)
    address = item.get("address", "")
    fields: dict[str, Any] = {}

    if _is_unknown(au, "acl"):
        _note(unknown, address, "acl")
    else:
        acl_public = _canned_acl_public(after.get("acl"))
        if _is_unknown(au, "grant"):
            _note(unknown, address, "grant")
        elif _grants_public(after.get("grant")):
            acl_public = True
        if acl_public is not None:
            fields["acl_public"] = acl_public

    versioning = after.get("versioning")
    if isinstance(versioning, list) and versioning and isinstance(versioning[0], dict) and isinstance(versioning[0].get("enabled"), bool):
        fields["versioning_enabled"] = versioning[0]["enabled"]
    elif _is_unknown(au, "versioning") or versioning:
        _note(unknown, address, "versioning")

    encryption = after.get("server_side_encryption_configuration")
    if isinstance(encryption, list) and encryption:
        fields["encrypted"] = True
    elif _is_unknown(au, "server_side_encryption_configuration"):
        _note(unknown, address, "server_side_encryption_configuration")

    logging = after.get("logging")
    if isinstance(logging, list) and logging:
        fields["logging_enabled"] = True
    elif _is_unknown(au, "logging"):
        _note(unknown, address, "logging")

    if _is_unknown(au, "policy"):
        _note(unknown, address, "policy")
    else:
        policy = _policy_field(after.get("policy"), address, unknown)
        if policy is not None:
            fields["policy"] = policy
    return fields


class S3Model:
    """Which bucket each separate S3 settings resource belongs to."""

    def __init__(self, plan: dict):
        self.config = ConfigIndex(plan)
        self.buckets: dict[tuple[str, str], list[str | None]] = {}
        for item in plan.get("resource_changes") or []:
            if isinstance(item, dict) and item.get("type") == "aws_s3_bucket" and item.get("mode", "managed") == "managed":
                change = item.get("change") or {}
                if change.get("actions") == ["delete"]:
                    continue
                name = (change.get("after") or {}).get("bucket")
                known = isinstance(name, str) and name and not _is_unknown(_unknown_map(change), "bucket")
                key = (_module_key(item.get("module_address")), f"aws_s3_bucket.{item.get('name')}")
                self.buckets.setdefault(key, []).append(name if known else None)

    def bucket_name(self, item: dict) -> str | None:
        change = item.get("change") or {}
        value = (change.get("after") or change.get("before") or {}).get("bucket")
        if isinstance(value, str) and value and not _is_unknown(_unknown_map(change), "bucket"):
            return value
        found: list[str | None] = []
        for base in self.config.bases(item, "bucket"):
            for key, names in self.buckets.items():
                if key == base:
                    found.extend(names)
        return found[0] if len(found) == 1 and found[0] else None

    def separate(self, item: dict, unknown: list[dict]) -> tuple[list[Change], dict | None]:
        typ = item.get("type", "")
        address = item.get("address", "")
        change = item.get("change") or {}
        actions = change.get("actions") or []
        provider = item.get("provider_name")
        name = self.bucket_name(item)
        if name is None:
            return [], {"address": address, "type": typ, "actions": actions,
                        "provider_name": provider if isinstance(provider, str) else None,
                        "outside_view": False, "unseen": True,
                        "detail": "the bucket this setting belongs to is unknown at plan time"}
        after, au = change.get("after") or {}, _unknown_map(change)
        fields: dict[str, Any] = {}
        if actions == ["delete"]:
            if typ == "aws_s3_bucket_policy":
                fields["policy"] = None
            elif typ == "aws_s3_bucket_public_access_block":
                fields.update({flag: False for flag in _BPA_FIELDS})
            else:
                _note(unknown, address, typ.removeprefix("aws_s3_bucket_"), "removal_not_modeled")
        elif typ == "aws_s3_bucket_acl":
            if _is_unknown(au, "acl") or _is_unknown(au, "access_control_policy"):
                _note(unknown, address, "acl")
            else:
                public = _canned_acl_public(after.get("acl"))
                if _grants_public([g for policy in after.get("access_control_policy") or [] for g in (policy.get("grant") or [])]):
                    public = True
                if public is None and after.get("access_control_policy"):
                    public = False
                if public is not None:
                    fields["acl_public"] = public
        elif typ == "aws_s3_bucket_versioning":
            configuration = after.get("versioning_configuration")
            status = configuration[0].get("status") if isinstance(configuration, list) and configuration and isinstance(configuration[0], dict) else None
            if isinstance(status, str) and not _is_unknown(au, "versioning_configuration"):
                fields["versioning_enabled"] = status == "Enabled"
            else:
                _note(unknown, address, "versioning_configuration")
        elif typ == "aws_s3_bucket_server_side_encryption_configuration":
            if _is_unknown(au, "rule") or not isinstance(after.get("rule"), list):
                _note(unknown, address, "rule")
            elif after["rule"]:
                fields["encrypted"] = True
        elif typ == "aws_s3_bucket_public_access_block":
            for flag in _BPA_FIELDS:
                if _is_unknown(au, flag):
                    _note(unknown, address, flag)
                elif isinstance(after.get(flag), bool):
                    fields[flag] = after[flag]
        elif typ == "aws_s3_bucket_policy":
            if _is_unknown(au, "policy"):
                _note(unknown, address, "policy")
            else:
                policy = _policy_field(after.get("policy"), address, unknown)
                if policy is not None:
                    fields["policy"] = policy
        elif typ == "aws_s3_bucket_logging":
            fields["logging_enabled"] = True  # the resource exists; where the logs go does not change that
        if not fields:
            return [], None
        return [Change(op="modify", resource_type="s3_bucket", resource_id=name, fields=fields)], None


def order_key(change: Change) -> int:
    """Block Public Access first: AWS rejects a public policy on a bucket that blocks it."""
    return 0 if set(change.fields) & set(_BPA_FIELDS) else 1
