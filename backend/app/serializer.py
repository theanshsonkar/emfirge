"""Deterministic Terraform JSON serialization for collected AWS infrastructure."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from app.models import AWSInfrastructure


_NON_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]")
_RULE_FIELDS = ("from_port", "to_port", "protocol")


def _sanitize_name(source: Any) -> str:
    """Convert a source identifier to a valid, deterministic Terraform name."""
    name = _NON_ALPHANUMERIC.sub("_", str(source))
    if not name:
        name = "resource"
    if name[0].isdigit():
        name = f"resource_{name}"
    return name


def _unique_name(source: Any, used: set[str], index: int) -> str:
    base = _sanitize_name(source)
    candidate = base
    if candidate in used:
        candidate = f"{base}_{index}"
        suffix = 2
        while candidate in used:
            candidate = f"{base}_{index}_{suffix}"
            suffix += 1
    used.add(candidate)
    return candidate


def _value(rule: Any, key: str) -> tuple[bool, Any]:
    if isinstance(rule, dict):
        return key in rule, rule.get(key)
    return hasattr(rule, key), getattr(rule, key, None)


def _serialize_rules(rules: Iterable[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for rule in rules:
        item: dict[str, Any] = {}
        for field in _RULE_FIELDS:
            present, value = _value(rule, field)
            if present and value is not None:
                item[field] = value
        present, value = _value(rule, "ip_ranges")
        if present and value is not None:
            item["cidr_blocks"] = value
        serialized.append(item)
    return sorted(
        serialized,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), default=str),
    )


def _optional_model_value(obj: Any, field: str) -> Any:
    """Return a non-None field only when it is an actual model attribute."""
    if not hasattr(obj, field):
        return None
    return getattr(obj, field)


def serialize_to_terraform(infra: AWSInfrastructure) -> dict:
    """Serialize supported infrastructure relationships to Terraform JSON config."""
    resources: dict[str, dict[str, dict[str, Any]]] = {}
    used_names: dict[str, set[str]] = {}

    def add(tf_type: str, source: Any, args: dict[str, Any], index: int) -> None:
        by_type = resources.setdefault(tf_type, {})
        names = used_names.setdefault(tf_type, set())
        by_type[_unique_name(source, names, index)] = args

    for index, instance in enumerate(infra.ec2.instances):
        args: dict[str, Any] = {"instance_type": instance.type}
        if instance.subnet_id is not None:
            args["subnet_id"] = instance.subnet_id
        if instance.sg_ids:
            args["vpc_security_group_ids"] = list(instance.sg_ids)
        if instance.imdsv2_required:
            args["metadata_options"] = [{"http_tokens": "required"}]
        if instance.has_public_ip is not None:
            args["associate_public_ip_address"] = instance.has_public_ip
        add("aws_instance", instance.id, args, index)

    for index, group in enumerate(infra.ec2.security_groups):
        args: dict[str, Any] = {"name": group.name}
        ingress = _serialize_rules(group.rules)
        egress = _serialize_rules(group.egress_rules)
        if ingress:
            args["ingress"] = ingress
        if egress:
            args["egress"] = egress
        add("aws_security_group", group.id, args, index)

    for index, bucket in enumerate(infra.s3.buckets):
        add("aws_s3_bucket", bucket.name, {"bucket": bucket.name}, index)
        public = bool(bucket.is_public)
        add(
            "aws_s3_bucket_public_access_block",
            bucket.name,
            {
                "bucket": bucket.name,
                "block_public_acls": not public,
                "block_public_policy": not public,
                "ignore_public_acls": not public,
                "restrict_public_buckets": not public,
            },
            index,
        )
        if bucket.encrypted is True:
            add(
                "aws_s3_bucket_server_side_encryption_configuration",
                bucket.name,
                {
                    "bucket": bucket.name,
                    "rule": [
                        {
                            "apply_server_side_encryption_by_default": [
                                {"sse_algorithm": "AES256"}
                            ]
                        }
                    ],
                },
                index,
            )
        if bucket.versioning_enabled is True:
            add(
                "aws_s3_bucket_versioning",
                bucket.name,
                {
                    "bucket": bucket.name,
                    "versioning_configuration": [{"status": "Enabled"}],
                },
                index,
            )

    for index, database in enumerate(infra.rds.rds_instances):
        args: dict[str, Any] = {
            "publicly_accessible": database.publicly_accessible,
            "storage_encrypted": database.encrypted,
        }
        for field in ("multi_az", "deletion_protection", "engine"):
            value = _optional_model_value(database, field)
            if value is not None:
                args[field] = value
        add("aws_db_instance", database.id, args, index)

    return {"resource": resources}


def to_terraform_json_string(infra: AWSInfrastructure) -> str:
    """Return deterministic, valid Terraform JSON for infrastructure."""
    return json.dumps(serialize_to_terraform(infra), sort_keys=True, separators=(",", ":"))
