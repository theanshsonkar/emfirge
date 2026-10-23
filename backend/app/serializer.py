"""Deterministic Terraform JSON serialization for collected AWS infrastructure.

The output feeds Checkov/Trivy (app/scanners.py). Three properties matter for
scanner fidelity and are enforced by tests/laws/test_serializer_fidelity_laws.py:

* Cross-resource links are Terraform references (``${aws_s3_bucket.x.id}``),
  because Checkov's graph checks (CKV2_AWS_6, CKV_AWS_21, ...) only follow
  references, never literal names.
* Terraform names are derived only from (resource type, resource id), so the
  same resource has the same name in base and branch, and a result can be
  mapped back to the Emfirge resource (``names``).
* Everything the model knows but the output does not carry is listed in a loss
  report, so a scanner pass is never read as full coverage.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from pydantic import BaseModel

from app.models import AWSInfrastructure


_NON_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]")
_RULE_FIELDS = ("from_port", "to_port", "protocol")
_RULE_KEYS_EMITTED = frozenset(_RULE_FIELDS) | {"ip_ranges"}
_BPA_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")

# Emfirge resource types the serializer emits.
EC2_INSTANCE = "ec2_instance"
SECURITY_GROUP = "security_group"
S3_BUCKET = "s3_bucket"
RDS_INSTANCE = "rds_instance"

# (section attribute, list attribute) -> emfirge resource type
EMITTED_COLLECTIONS: dict[tuple[str, str], str] = {
    ("ec2", "instances"): EC2_INSTANCE,
    ("ec2", "security_groups"): SECURITY_GROUP,
    ("s3", "buckets"): S3_BUCKET,
    ("rds", "rds_instances"): RDS_INSTANCE,
}

_NAME_PREFIX = {
    "aws_instance": "ec2",
    "aws_security_group": "sg",
    "aws_s3_bucket": "s3",
    "aws_s3_bucket_public_access_block": "s3pab",
    "aws_s3_bucket_server_side_encryption_configuration": "s3sse",
    "aws_s3_bucket_versioning": "s3ver",
    "aws_s3_bucket_policy": "s3pol",
    "aws_db_instance": "rds",
}

# Per emitted resource type, every model field and what happens to it:
#   ("emit", tf_arg, report_none)  carried into Terraform; if report_none and
#                                  the value is None it is reported as unknown
#   ("identity",)                  carried by the Terraform name / mapping
#   ("loss", reason)               never emitted; always reported
# A model field missing here is reported as unhandled, and the fidelity law
# fails until it is added.
FIELD_MAP: dict[str, dict[str, tuple]] = {
    EC2_INSTANCE: {
        "id": ("identity",),
        "type": ("emit", "instance_type", False),
        "sg_ids": ("emit", "vpc_security_group_ids", False),
        "subnet_id": ("emit", "subnet_id", False),
        "state": ("loss", "instance state has no Terraform equivalent"),
        "imdsv2_required": ("emit", "metadata_options", False),
        "has_public_ip": ("emit", "associate_public_ip_address", True),
        "instance_profile_arn": ("loss", "an ARN cannot be expressed as iam_instance_profile (needs a profile name)"),
        "block_devices": ("loss", "block devices are not serialized"),
        "tags": ("emit", "tags", True),
    },
    SECURITY_GROUP: {
        "id": ("identity",),
        "name": ("emit", "name", False),
        "rules": ("emit", "ingress", False),
        "egress_rules": ("emit", "egress", False),
        "attached_to": ("loss", "attachment is expressed by instance/db security group references"),
        "tags": ("emit", "tags", True),
    },
    S3_BUCKET: {
        "name": ("identity",),
        "is_public": ("loss", "derived from ACL/policy and the public access block; not emitted"),
        "has_cloudfront": ("loss", "CloudFront association has no Terraform bucket argument"),
        "policy": ("emit", "aws_s3_bucket_policy", False),
        "is_empty": ("loss", "object emptiness has no Terraform equivalent"),
        "encrypted": ("emit", "aws_s3_bucket_server_side_encryption_configuration", True),
        "versioning_enabled": ("emit", "aws_s3_bucket_versioning", True),
        "acl_public": ("loss", "derived ACL exposure is not emitted"),
        "policy_public": ("loss", "derived policy exposure is not emitted"),
        "block_public_acls": ("emit", "aws_s3_bucket_public_access_block", True),
        "ignore_public_acls": ("emit", "aws_s3_bucket_public_access_block", True),
        "block_public_policy": ("emit", "aws_s3_bucket_public_access_block", True),
        "restrict_public_buckets": ("emit", "aws_s3_bucket_public_access_block", True),
        "tags": ("emit", "tags", True),
    },
    RDS_INSTANCE: {
        "id": ("identity",),
        "sg_ids": ("emit", "vpc_security_group_ids", False),
        "subnet_id": ("loss", "aws_db_instance needs a DB subnet group name, not a subnet id"),
        "publicly_accessible": ("emit", "publicly_accessible", False),
        "encrypted": ("emit", "storage_encrypted", False),
        "engine": ("emit", "engine", True),
        "port": ("emit", "port", True),
        "backup_retention_days": ("emit", "backup_retention_period", True),
        "deletion_protection": ("emit", "deletion_protection", True),
        "tags": ("emit", "tags", True),
    },
}


@dataclass
class TerraformOutput:
    tf: dict
    # terraform name -> (emfirge resource_type, emfirge id)
    names: dict[str, tuple[str, str]] = field(default_factory=dict)
    loss: list[dict[str, Any]] = field(default_factory=list)


def _sanitize_name(source: Any) -> str:
    """Convert a source identifier to a valid, deterministic Terraform name."""
    name = _NON_ALPHANUMERIC.sub("_", str(source))
    return name or "resource"


def terraform_name(tf_type: str, resource_type: str, resource_id: Any) -> str:
    """Stable name from (type, id) only; never depends on sibling resources."""
    digest = hashlib.sha1(f"{resource_type}\0{resource_id}".encode("utf-8")).hexdigest()[:8]
    return f"{_NAME_PREFIX[tf_type]}_{_sanitize_name(resource_id)[:40]}_{digest}"


def _value(rule: Any, key: str) -> tuple[bool, Any]:
    if isinstance(rule, dict):
        return key in rule, rule.get(key)
    return hasattr(rule, key), getattr(rule, key, None)


def _serialize_rules(rules: Iterable[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for rule in rules:
        item: dict[str, Any] = {}
        for key in _RULE_FIELDS:
            present, value = _value(rule, key)
            if present and value is not None:
                item[key] = value
        present, value = _value(rule, "ip_ranges")
        if present and value is not None:
            item["cidr_blocks"] = value
        serialized.append(item)
    return sorted(
        serialized,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), default=str),
    )


def _extra_rule_keys(rules: Iterable[Any]) -> list[str]:
    keys: set[str] = set()
    for rule in rules:
        if isinstance(rule, dict):
            keys.update(str(k) for k in rule if k not in _RULE_KEYS_EMITTED)
    return sorted(keys)


def _ref(tf_type: str, name: str) -> str:
    return f"${{{tf_type}.{name}.id}}"


def _model_fields(model: Any) -> list[str]:
    return list(type(model).model_fields)


def _item_id(item: Any, index: int) -> str:
    for key in ("id", "name", "arn", "role_arn", "allocation_id", "username", "key_id", "key"):
        value = getattr(item, key, None)
        if value not in (None, ""):
            return str(value)
    return f"#{index}"


def build_terraform(infra: AWSInfrastructure) -> TerraformOutput:
    """Serialize to Terraform JSON plus the name mapping and the loss report."""
    resources: dict[str, dict[str, dict[str, Any]]] = {}
    names: dict[str, tuple[str, str]] = {}
    loss: list[dict[str, Any]] = []

    def add(tf_type: str, resource_type: str, rid: Any, args: dict[str, Any]) -> str:
        name = terraform_name(tf_type, resource_type, rid)
        resources.setdefault(tf_type, {})[name] = args
        names[name] = (resource_type, str(rid))
        return name

    def lose(resource_type: str, rid: Any, reason: str, field_name: str | None = None, **extra: Any) -> None:
        entry: dict[str, Any] = {"resource_type": resource_type, "id": str(rid), "reason": reason}
        if field_name is not None:
            entry["field"] = field_name
        entry.update(extra)
        loss.append(entry)

    def omitted_field(resource_type: str, rid: Any, field_name: str, reason: str) -> None:
        lose(resource_type, rid, reason, field_name, kind="omitted_field")

    def synthesized(resource_type: str, rid: Any, field_name: str, value: Any, reason: str) -> None:
        lose(resource_type, rid, reason, field_name, kind="synthesized", value=value)

    def report_fields(resource_type: str, rid: Any, model: Any, emitted: set[str]) -> None:
        spec_map = FIELD_MAP[resource_type]
        for field_name in _model_fields(model):
            spec = spec_map.get(field_name)
            if spec is None:
                omitted_field(resource_type, rid, field_name, "field is not handled by the serializer")
            elif spec[0] == "loss":
                omitted_field(resource_type, rid, field_name, spec[1])
            elif spec[0] == "emit" and field_name not in emitted and spec[2] and getattr(model, field_name) is None:
                omitted_field(resource_type, rid, field_name, "value not collected (unknown); omitted rather than guessed")

    sg_names = {
        str(group.id): terraform_name("aws_security_group", SECURITY_GROUP, group.id)
        for group in infra.ec2.security_groups
    }

    def sg_links(sg_ids: Iterable[str]) -> list[str]:
        return [
            _ref("aws_security_group", sg_names[str(sg)]) if str(sg) in sg_names else sg
            for sg in sg_ids
        ]

    seen: set[tuple[str, str]] = set()

    def duplicate(resource_type: str, rid: Any) -> bool:
        key = (resource_type, str(rid))
        if key in seen:
            lose(resource_type, rid, "duplicate id in input; later copy omitted", kind="omitted_resource")
            return True
        seen.add(key)
        return False

    for instance in infra.ec2.instances:
        if duplicate(EC2_INSTANCE, instance.id):
            continue
        args: dict[str, Any] = {"instance_type": instance.type}
        emitted = {"type", "id"}
        if instance.subnet_id is not None:
            args["subnet_id"] = instance.subnet_id
            emitted.add("subnet_id")
        if instance.sg_ids:
            args["vpc_security_group_ids"] = sg_links(instance.sg_ids)
            emitted.add("sg_ids")
        if instance.imdsv2_required:
            args["metadata_options"] = [{"http_tokens": "required"}]
        emitted.add("imdsv2_required")
        if instance.has_public_ip is not None:
            args["associate_public_ip_address"] = instance.has_public_ip
            emitted.add("has_public_ip")
        if instance.tags is not None:
            args["tags"] = dict(instance.tags)
            emitted.add("tags")
        add("aws_instance", EC2_INSTANCE, instance.id, args)
        report_fields(EC2_INSTANCE, instance.id, instance, emitted)

    for group in infra.ec2.security_groups:
        if duplicate(SECURITY_GROUP, group.id):
            continue
        args = {"name": group.name}
        ingress = _serialize_rules(group.rules)
        egress = _serialize_rules(group.egress_rules)
        if ingress:
            args["ingress"] = ingress
        if egress:
            args["egress"] = egress
        emitted = {"id", "name", "rules", "egress_rules"}
        if group.tags is not None:
            args["tags"] = dict(group.tags)
            emitted.add("tags")
        add("aws_security_group", SECURITY_GROUP, group.id, args)
        report_fields(SECURITY_GROUP, group.id, group, emitted)
        for label, rules in (("rules", group.rules), ("egress_rules", group.egress_rules)):
            extra = _extra_rule_keys(rules)
            if extra:
                omitted_field(SECURITY_GROUP, group.id, label, f"rule keys not emitted: {', '.join(extra)}")

    for bucket in infra.s3.buckets:
        if duplicate(S3_BUCKET, bucket.name):
            continue
        bucket_args: dict[str, Any] = {"bucket": bucket.name}
        emitted = {"name"}
        if bucket.tags is not None:
            bucket_args["tags"] = dict(bucket.tags)
            emitted.add("tags")
        bname = add("aws_s3_bucket", S3_BUCKET, bucket.name, bucket_args)
        link = _ref("aws_s3_bucket", bname)

        known = {flag: getattr(bucket, flag) for flag in _BPA_FLAGS if getattr(bucket, flag) is not None}
        if known:
            add("aws_s3_bucket_public_access_block", S3_BUCKET, bucket.name, {"bucket": link, **known})
            emitted.update(known)
        if bucket.encrypted is True:
            add(
                "aws_s3_bucket_server_side_encryption_configuration",
                S3_BUCKET,
                bucket.name,
                {
                    "bucket": link,
                    "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
                },
            )
            synthesized(
                S3_BUCKET, bucket.name, "encrypted", "AES256",
                "model records encrypted=True without the algorithm; AES256 assumed",
            )
        if bucket.encrypted is not None:
            emitted.add("encrypted")
        if bucket.versioning_enabled is True:
            add(
                "aws_s3_bucket_versioning", S3_BUCKET, bucket.name,
                {"bucket": link, "versioning_configuration": [{"status": "Enabled"}]},
            )
        if bucket.versioning_enabled is not None:
            emitted.add("versioning_enabled")
        if bucket.policy:
            add("aws_s3_bucket_policy", S3_BUCKET, bucket.name, {"bucket": link, "policy": bucket.policy})
        emitted.add("policy")
        report_fields(S3_BUCKET, bucket.name, bucket, emitted)

    for database in infra.rds.rds_instances:
        if duplicate(RDS_INSTANCE, database.id):
            continue
        args = {
            "publicly_accessible": database.publicly_accessible,
            "storage_encrypted": database.encrypted,
        }
        emitted = {"id", "publicly_accessible", "encrypted"}
        if database.sg_ids:
            args["vpc_security_group_ids"] = sg_links(database.sg_ids)
            emitted.add("sg_ids")
        for model_field, tf_arg in (
            ("deletion_protection", "deletion_protection"),
            ("engine", "engine"),
            ("port", "port"),
            ("backup_retention_days", "backup_retention_period"),
        ):
            value = getattr(database, model_field)
            if value is not None:
                args[tf_arg] = value
                emitted.add(model_field)
        if database.tags is not None:
            args["tags"] = dict(database.tags)
            emitted.add("tags")
        add("aws_db_instance", RDS_INSTANCE, database.id, args)
        report_fields(RDS_INSTANCE, database.id, database, emitted)

    _report_unemitted_collections(infra, lose)
    loss.sort(key=lambda e: (e["resource_type"], e["id"], e.get("field", ""), e["reason"]))
    return TerraformOutput(tf={"resource": resources}, names=names, loss=loss)


def collections(infra: AWSInfrastructure) -> Iterable[tuple[str, str, list[BaseModel]]]:
    """Yield (section, field, items) for every list of model objects in the input."""
    for section_name in type(infra).model_fields:
        section = getattr(infra, section_name)
        if isinstance(section, list):
            if section and isinstance(section[0], BaseModel):
                yield "", section_name, section
        elif isinstance(section, BaseModel):
            for list_name in type(section).model_fields:
                items = getattr(section, list_name)
                if isinstance(items, list) and items and isinstance(items[0], BaseModel):
                    yield section_name, list_name, items


def _report_unemitted_collections(infra: AWSInfrastructure, lose) -> None:
    for section, list_name, items in collections(infra):
        if (section, list_name) in EMITTED_COLLECTIONS:
            continue
        resource_type = f"{section}.{list_name}" if section else list_name
        for index, item in enumerate(items):
            lose(
                resource_type, _item_id(item, index),
                "resource type is not serialized to Terraform; scanners do not see it",
                kind="omitted_resource",
            )


def loss_summary(loss: list[dict[str, Any]]) -> str | None:
    resources = sum(1 for e in loss if e.get("kind") == "omitted_resource")
    fields = sum(1 for e in loss if e.get("kind") == "omitted_field")
    synth = sum(1 for e in loss if e.get("kind") == "synthesized")
    if not (resources or fields or synth):
        return None
    text = f"scanner input omits {resources} resources and {fields} fields"
    if synth:
        text += f" and synthesizes {synth} values"
    return text + "; see scanner_loss"


def serialize_to_terraform(infra: AWSInfrastructure) -> dict:
    """Serialize supported infrastructure relationships to Terraform JSON config."""
    return build_terraform(infra).tf


def to_terraform_json_string(infra: AWSInfrastructure) -> str:
    """Return deterministic, valid Terraform JSON for infrastructure."""
    return json.dumps(serialize_to_terraform(infra), sort_keys=True, separators=(",", ":"))
