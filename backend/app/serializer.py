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
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel

from app.models import AWSInfrastructure


_NON_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]")
_RULE_FIELDS = ("from_port", "to_port", "protocol")
_BPA_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")

# Emfirge resource types the serializer emits.
EC2_INSTANCE = "ec2_instance"
SECURITY_GROUP = "security_group"
S3_BUCKET = "s3_bucket"
RDS_INSTANCE = "rds_instance"
ROLE_POLICY = "role_policy"
LAMBDA_FUNCTION = "lambda_function"
VPC_SUBNET = "vpc_subnet"
# Types without a list of model objects of their own: a VPC exists as an id
# on subnets/route tables/NACLs, KMS keys as ids in a list, the trail as a flat section.
VPC = "vpc"
KMS_KEY = "kms_key"
CLOUDTRAIL = "cloudtrail"

# (section attribute, list attribute) -> emfirge resource type
EMITTED_COLLECTIONS: dict[tuple[str, str], str] = {
    ("ec2", "instances"): EC2_INSTANCE,
    ("ec2", "security_groups"): SECURITY_GROUP,
    ("s3", "buckets"): S3_BUCKET,
    ("rds", "rds_instances"): RDS_INSTANCE,
    ("iam", "role_policies"): ROLE_POLICY,
    ("lambda_data", "functions"): LAMBDA_FUNCTION,
    ("vpc", "subnets"): VPC_SUBNET,
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
    "aws_iam_role": "iamrole",
    "aws_iam_role_policy": "iamrp",
    "aws_kms_key": "kms",
    "aws_cloudtrail": "trail",
    "aws_lambda_function": "fn",
    "aws_vpc": "vpc",
    "aws_subnet": "subnet",
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
        # None means no profile attached or not collected (the collector cannot tell them apart), so it is not reported.
        "instance_profile_arn": ("emit", "iam_instance_profile", False),
        "detailed_monitoring": ("emit", "monitoring", True),
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
        "multi_az": ("emit", "multi_az", True),
        "log_exports": ("emit", "enabled_cloudwatch_logs_exports", True),
        "iam_auth_enabled": ("emit", "iam_database_authentication_enabled", True),
        "monitoring_interval": ("emit", "monitoring_interval", True),
        "auto_minor_version_upgrade": ("emit", "auto_minor_version_upgrade", True),
        "tags": ("emit", "tags", True),
    },
}

_TRUST_LOSS = "trust policy: only parsed flags are kept, not the raw document, so assume_role_policy cannot be emitted"

FIELD_MAP.update({
    ROLE_POLICY: {
        "role_name": ("emit", "name", False),
        "role_arn": ("identity",),
        "accessible_resources": ("loss", "derived from access_statements; not emitted"),
        "has_admin": ("loss", "derived from access_statements and attached policy names; not emitted"),
        # Effective permissions: managed and inline statements merged into one aws_iam_role_policy.
        # An incomplete record (a Condition, a missing policy) is reported against access_statements.
        "access_statements": ("emit", "policy", False),
        "policy_documents": ("emit", "policy", False),
        "last_used_at": ("loss", "last-used time has no Terraform equivalent"),
        "policy_names": ("loss", "policy names are display data; statements are emitted merged"),
        "trusted_role_arns": ("loss", _TRUST_LOSS),
        "trusted_services": ("loss", _TRUST_LOSS),
        "trust_allows_external": ("loss", _TRUST_LOSS),
        "trust_has_conditions": ("loss", _TRUST_LOSS),
        "trust_external_unrestricted": ("loss", _TRUST_LOSS),
    },
    LAMBDA_FUNCTION: {
        "name": ("emit", "function_name", False),
        "role_arn": ("emit", "role", True),
        "vpc_id": ("emit", "vpc_config", False),
        "subnet_ids": ("emit", "vpc_config", False),
        "sg_ids": ("emit", "vpc_config", False),
        "secret_refs": ("loss", "environment variable names are not serialized"),
        "tags": ("emit", "tags", True),
    },
    VPC_SUBNET: {
        "id": ("identity",),
        "vpc_id": ("emit", "vpc_id", False),
        "cidr": ("emit", "cidr_block", True),
        "resources": ("loss", "resources in the subnet have no Terraform subnet argument"),
        "availability_zone": ("emit", "availability_zone", False),
        "is_public": ("loss", "route-derived; map_public_ip_on_launch is not collected"),
    },
    # No model object: the pseudo-model is the id plus what is known about it.
    VPC: {
        "id": ("identity",),
        "flow_logs": ("emit", "aws_flow_log", False),
    },
    KMS_KEY: {
        "id": ("identity",),
        "enable_key_rotation": ("emit", "enable_key_rotation", False),
    },
    CLOUDTRAIL: {
        "trail_arn": ("identity",),
        "is_enabled": ("emit", "enable_logging", False),
        "is_multi_region": ("emit", "is_multi_region_trail", False),
        "has_log_file_validation": ("emit", "enable_log_file_validation", False),
    },
})

# Terraform arguments of an emitted resource that the model has no field for at
# all: reported on every such resource so the output is never read as complete.
UNMODELED: dict[str, dict[str, str]] = {
    "aws_iam_role": {"assume_role_policy": _TRUST_LOSS},
    "aws_lambda_function": {
        name: "not collected into the model"
        for name in ("runtime", "handler", "timeout", "environment", "tracing_config", "dead_letter_config",
                     "kms_key_arn", "reserved_concurrent_executions", "code_signing_config_arn")
    },
    "aws_cloudtrail": {
        name: "not collected into the model"
        for name in ("s3_bucket_name", "kms_key_id", "sns_topic_name", "cloud_watch_logs_group_arn")
    },
    "aws_kms_key": {name: "not collected into the model" for name in ("customer_master_key_spec", "policy")},
    "aws_subnet": {"map_public_ip_on_launch": "not collected into the model"},
    "aws_vpc": {"cidr_block": "not collected into the model"},
}

# Terraform resource type -> Emfirge resource type (the main resource a check reports on).
TF_TO_EMFIRGE: dict[str, str] = {
    "aws_instance": EC2_INSTANCE,
    "aws_security_group": SECURITY_GROUP,
    "aws_s3_bucket": S3_BUCKET,
    "aws_db_instance": RDS_INSTANCE,
    "aws_iam_role": ROLE_POLICY,
    "aws_iam_role_policy": ROLE_POLICY,
    "aws_lambda_function": LAMBDA_FUNCTION,
    "aws_subnet": VPC_SUBNET,
    "aws_vpc": VPC,
    "aws_kms_key": KMS_KEY,
    "aws_cloudtrail": CLOUDTRAIL,
}


_READS_PATH = Path(__file__).resolve().parent / "data" / "scanner_check_reads.json"


@lru_cache(maxsize=1)
def check_read_rows() -> tuple[dict[str, Any], ...]:
    """Rows {check_id, tf_type, reads, source} of Checkov checks that read attributes, from the check source."""
    try:
        rows = json.loads(_READS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    return tuple(
        row for row in rows if isinstance(row, dict) and row.get("check_id") and row.get("tf_type")
        and isinstance(row.get("reads"), list)
    ) if isinstance(rows, list) else ()


def unmodeled_attributes(tf_type: str) -> dict[str, str]:
    """Terraform attributes of an emitted type that the model has no field for, with the reason.

    Those listed in UNMODELED, plus every attribute a known check reads (scanner_check_reads.json)
    that the serializer does not emit.
    """
    out = dict(UNMODELED.get(tf_type, {}))
    emitted = attribute_fields(tf_type)
    for row in check_read_rows():
        if row["tf_type"] == tf_type:
            for attribute in row["reads"]:
                if attribute not in emitted and attribute not in out:
                    out[attribute] = "not modeled"
    return out


def attribute_fields(tf_type: str) -> dict[str, list[str]]:
    """Terraform attribute (or sub-resource) -> the model fields it carries, for a Terraform type."""
    out: dict[str, list[str]] = {}
    for model_field, spec in FIELD_MAP.get(TF_TO_EMFIRGE.get(tf_type, ""), {}).items():
        if spec[0] == "emit":
            out.setdefault(spec[1], []).append(model_field)
    return out


def _profile_name(arn: str) -> str | None:
    """Terraform's iam_instance_profile takes the profile name: the last segment of an instance-profile ARN."""
    match = re.fullmatch(r"arn:[^:]*:iam::[^:]*:instance-profile/(?:[^/]+/)*([^/]+)", arn)
    return match.group(1) if match else None


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


def _serialize_rules(rules: Iterable[Any], group_key: str, own_id: str, link) -> list[dict[str, Any]]:
    """Rules as Terraform ingress/egress blocks.

    ``group_key`` is the model key holding peer security group ids
    (``source_sg_ids`` for ingress, ``dest_sg_ids`` for egress).  A peer in the
    input becomes a reference, the group itself becomes ``self``, anything else
    stays the literal id.  IPv6 ranges go to ``ipv6_cidr_blocks``.  Peers sit in
    their own block when the rule also has address ranges: AWS keeps one
    permission per source, and Checkov skips a block's CIDRs when it also
    carries ``self``.  Protocol ``-1`` takes ports 0/0, which Terraform requires
    for it and AWS ignores.
    """
    serialized: list[dict[str, Any]] = []
    for rule in rules:
        item: dict[str, Any] = {}
        for key in _RULE_FIELDS:
            present, value = _value(rule, key)
            if present and value is not None:
                item[key] = value
        if str(item.get("protocol")) == "-1":
            item.setdefault("from_port", 0)
            item.setdefault("to_port", 0)
        base = dict(item)
        has_ranges = False
        present, value = _value(rule, "ip_ranges")
        if present and value is not None:
            v6 = [r for r in value if ":" in str(r)]
            v4 = [r for r in value if ":" not in str(r)]
            item["cidr_blocks"] = v4
            if v6:
                item["ipv6_cidr_blocks"] = v6
            has_ranges = bool(value)
        present, peers = _value(rule, group_key)
        peer_item: dict[str, Any] | None = None
        if present and peers:
            peers = [str(peer) for peer in peers if peer]
            target = dict(base) if has_ranges else item
            if own_id in peers:
                target["self"] = True
            others = sorted(set(peers) - {own_id})
            if others:
                target["security_groups"] = link(others)
            if has_ranges and len(target) > len(base):
                peer_item = target
        serialized.append(item)
        if peer_item is not None:
            serialized.append(peer_item)
    return sorted(
        serialized,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), default=str),
    )


def _extra_rule_keys(rules: Iterable[Any], group_key: str) -> list[str]:
    keys: set[str] = set()
    emitted = set(_RULE_FIELDS) | {"ip_ranges", group_key}
    for rule in rules:
        if isinstance(rule, dict):
            for key, value in rule.items():
                if key in emitted:
                    continue
                if key in ("source_sg_ids", "dest_sg_ids") and not value:
                    continue  # the other direction's peer list is empty by default
                keys.add(str(key))
    return sorted(keys)


def _ref(tf_type: str, name: str, attribute: str = "id") -> str:
    return f"${{{tf_type}.{name}.{attribute}}}"


def _model_fields(model: Any) -> list[str]:
    return list(type(model).model_fields)


def _item_id(item: Any, index: int) -> str:
    for key in ("id", "name", "arn", "role_arn", "allocation_id", "username", "key_id", "key"):
        value = getattr(item, key, None)
        if value not in (None, ""):
            return str(value)
    return f"#{index}"


_TRAIL_ARN = re.compile(r"arn:[^:]*:cloudtrail:[^:]*:[^:]*:trail/(.+)")


def _role_policy_document(role: Any) -> tuple[dict | None, list[str]]:
    """The role's effective permissions as one policy document, plus why it may be incomplete.

    Built only from the statements the model kept (effect, actions, resources,
    NotAction/NotResource).  Conditions are not kept, so a statement that had one
    is emitted without it and reported; a policy the model does not record is
    reported too.  The raw trust document is not kept at all.
    """
    problems: list[str] = []
    statements: list[dict[str, Any]] = []
    conditioned: list[int] = []
    malformed: list[int] = []
    for index, st in enumerate(role.access_statements):
        effect = {"allow": "Allow", "deny": "Deny"}.get(str(st.effect).lower())
        if effect is None or not st.actions or not st.resources:
            malformed.append(index)
            continue
        statements.append({
            "Effect": effect,
            ("NotAction" if st.is_not_action else "Action"): list(st.actions),
            ("NotResource" if st.is_not_resource else "Resource"): list(st.resources),
        })
        if st.has_condition:
            conditioned.append(index)
    if conditioned:
        problems.append(
            f"statement(s) {conditioned} have a Condition that is not kept; emitted without it, "
            "so the document is broader than the real policy"
        )
    if malformed:
        problems.append(f"statement(s) {malformed} have no usable effect/action/resource and were dropped")
    if role.policy_documents is None:
        if role.policy_names:
            problems.append("policy breakdown not recorded; cannot confirm every attached or inline policy contributed")
    else:
        missing = sorted(set(role.policy_names) - {doc.name for doc in role.policy_documents})
        if missing:
            problems.append(f"policy document(s) not recorded: {', '.join(missing)}")
    if role.has_admin and not any(
        str(st.effect).lower() == "allow" and "*" in st.actions and "*" in st.resources
        for st in role.access_statements
    ):
        problems.append("role is recorded as administrator but no matching statement was kept")
    document = {"Statement": statements} if statements else None
    return document, problems


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

    def unmodeled(tf_type: str, resource_type: str, rid: Any) -> None:
        for attribute, reason in unmodeled_attributes(tf_type).items():
            omitted_field(resource_type, rid, attribute, reason)

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
        if instance.detailed_monitoring is not None:
            args["monitoring"] = instance.detailed_monitoring
            emitted.add("detailed_monitoring")
        if instance.instance_profile_arn is not None:
            profile = _profile_name(instance.instance_profile_arn)
            if profile is not None:
                args["iam_instance_profile"] = profile
                emitted.add("instance_profile_arn")
            else:
                omitted_field(EC2_INSTANCE, instance.id, "instance_profile_arn",
                              "ARN is not an instance-profile ARN, so no profile name can be derived")
        else:
            emitted.add("instance_profile_arn")
        if instance.tags is not None:
            args["tags"] = dict(instance.tags)
            emitted.add("tags")
        add("aws_instance", EC2_INSTANCE, instance.id, args)
        unmodeled("aws_instance", EC2_INSTANCE, instance.id)
        report_fields(EC2_INSTANCE, instance.id, instance, emitted)

    for group in infra.ec2.security_groups:
        if duplicate(SECURITY_GROUP, group.id):
            continue
        args = {"name": group.name}
        ingress = _serialize_rules(group.rules, "source_sg_ids", str(group.id), sg_links)
        egress = _serialize_rules(group.egress_rules, "dest_sg_ids", str(group.id), sg_links)
        if ingress:
            args["ingress"] = ingress
        if egress:
            args["egress"] = egress
        emitted = {"id", "name", "rules", "egress_rules"}
        if group.tags is not None:
            args["tags"] = dict(group.tags)
            emitted.add("tags")
        add("aws_security_group", SECURITY_GROUP, group.id, args)
        unmodeled("aws_security_group", SECURITY_GROUP, group.id)
        report_fields(SECURITY_GROUP, group.id, group, emitted)
        for label, rules, group_key in (
            ("rules", group.rules, "source_sg_ids"), ("egress_rules", group.egress_rules, "dest_sg_ids"),
        ):
            extra = _extra_rule_keys(rules, group_key)
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
        unmodeled("aws_s3_bucket", S3_BUCKET, bucket.name)
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
            ("multi_az", "multi_az"),
            ("log_exports", "enabled_cloudwatch_logs_exports"),
            ("iam_auth_enabled", "iam_database_authentication_enabled"),
            ("monitoring_interval", "monitoring_interval"),
            ("auto_minor_version_upgrade", "auto_minor_version_upgrade"),
        ):
            value = getattr(database, model_field)
            if value is not None:
                args[tf_arg] = list(value) if isinstance(value, list) else value
                emitted.add(model_field)
        if database.tags is not None:
            args["tags"] = dict(database.tags)
            emitted.add("tags")
        add("aws_db_instance", RDS_INSTANCE, database.id, args)
        unmodeled("aws_db_instance", RDS_INSTANCE, database.id)
        report_fields(RDS_INSTANCE, database.id, database, emitted)

    role_names: dict[str, str] = {}  # role ARN -> Terraform name of its aws_iam_role
    for role in infra.iam.role_policies:
        if duplicate(ROLE_POLICY, role.role_name):
            continue
        rname = add("aws_iam_role", ROLE_POLICY, role.role_name, {"name": role.role_name})
        if role.role_arn:
            role_names.setdefault(role.role_arn, rname)
        document, problems = _role_policy_document(role)
        if document is not None:
            add("aws_iam_role_policy", ROLE_POLICY, role.role_name, {
                "role": _ref("aws_iam_role", rname),
                "policy": json.dumps(document, sort_keys=True, separators=(",", ":")),
            })
        for problem in problems:
            omitted_field(ROLE_POLICY, role.role_name, "access_statements", problem)
        unmodeled("aws_iam_role", ROLE_POLICY, role.role_name)
        report_fields(ROLE_POLICY, role.role_name, role, {"role_name", "role_arn", "access_statements", "policy_documents"})

    vpc_ids = {
        str(vpc_id) for vpc_id in (
            list(infra.vpc.vpcs_without_flow_logs)
            + [subnet.vpc_id for subnet in infra.vpc.subnets]
            + [table.vpc_id for table in infra.vpc.route_tables]
            + [acl.vpc_id for acl in infra.vpc.nacls]
            + [infra.vpc.default_vpc_id]
        ) if vpc_id
    }
    vpc_names = {vpc_id: terraform_name("aws_vpc", VPC, vpc_id) for vpc_id in vpc_ids}
    subnet_names = {str(subnet.id): terraform_name("aws_subnet", VPC_SUBNET, subnet.id) for subnet in infra.vpc.subnets}
    no_flow_logs = set(infra.vpc.vpcs_without_flow_logs)

    for vpc_id in sorted(vpc_ids):
        add("aws_vpc", VPC, vpc_id, {})
        # Only a VPC listed as having no flow log is known to have none; for any
        # other VPC the collector cannot tell "has one" from "check failed".
        if vpc_id not in no_flow_logs:
            omitted_field(VPC, vpc_id, "flow_logs", "flow log state unknown: not listed as lacking flow logs, "
                          "which does not show that one exists; no aws_flow_log is emitted")
        unmodeled("aws_vpc", VPC, vpc_id)
    unlisted_vpcs = infra.vpc.total_vpcs - len(vpc_ids)
    if unlisted_vpcs > 0:
        lose(VPC, "unlisted", f"{unlisted_vpcs} VPC(s) are known only as a count; not serialized", kind="omitted_resource")

    for subnet in infra.vpc.subnets:
        if duplicate(VPC_SUBNET, subnet.id):
            continue
        args = {"vpc_id": _ref("aws_vpc", vpc_names[str(subnet.vpc_id)])}
        emitted = {"id", "vpc_id", "availability_zone"}
        if subnet.cidr is not None:
            args["cidr_block"] = subnet.cidr
            emitted.add("cidr")
        if subnet.availability_zone:
            args["availability_zone"] = subnet.availability_zone
        else:
            omitted_field(VPC_SUBNET, subnet.id, "availability_zone", "value not collected (unknown); omitted rather than guessed")
        add("aws_subnet", VPC_SUBNET, subnet.id, args)
        unmodeled("aws_subnet", VPC_SUBNET, subnet.id)
        report_fields(VPC_SUBNET, subnet.id, subnet, emitted)

    for function in infra.lambda_data.functions:
        if duplicate(LAMBDA_FUNCTION, function.name):
            continue
        args = {"function_name": function.name}
        emitted = {"name", "vpc_id", "subnet_ids", "sg_ids"}
        if function.role_arn:
            args["role"] = (
                _ref("aws_iam_role", role_names[function.role_arn], "arn")
                if function.role_arn in role_names else function.role_arn
            )
            emitted.add("role_arn")
        else:
            omitted_field(LAMBDA_FUNCTION, function.name, "role_arn", "value not collected (unknown); omitted rather than guessed")
            emitted.add("role_arn")
        if function.subnet_ids or function.sg_ids:
            config: dict[str, Any] = {}
            if function.subnet_ids:
                config["subnet_ids"] = [
                    _ref("aws_subnet", subnet_names[str(s)]) if str(s) in subnet_names else s
                    for s in function.subnet_ids
                ]
            if function.sg_ids:
                config["security_group_ids"] = sg_links(function.sg_ids)
            args["vpc_config"] = [config]
        if function.tags is not None:
            args["tags"] = dict(function.tags)
            emitted.add("tags")
        add("aws_lambda_function", LAMBDA_FUNCTION, function.name, args)
        unmodeled("aws_lambda_function", LAMBDA_FUNCTION, function.name)
        report_fields(LAMBDA_FUNCTION, function.name, function, emitted)

    # KMS: the model lists only enabled keys WITHOUT rotation and keys pending
    # deletion; there is no full key list, so a key absent from both lists has
    # an unknown rotation state and is never emitted as "rotation on".
    without_rotation = list(dict.fromkeys(str(k) for k in infra.kms.cmks_without_rotation))
    for key_id in without_rotation:
        if duplicate(KMS_KEY, key_id):
            continue
        add("aws_kms_key", KMS_KEY, key_id, {"enable_key_rotation": False})
        unmodeled("aws_kms_key", KMS_KEY, key_id)
    for key_id in dict.fromkeys(str(k) for k in infra.kms.cmks_pending_deletion):
        if (KMS_KEY, key_id) not in seen:
            lose(KMS_KEY, key_id, "key is pending deletion; rotation state unknown, not serialized", kind="omitted_resource")
    other_keys = infra.kms.total_cmks - len(set(without_rotation) | set(map(str, infra.kms.cmks_pending_deletion)))
    if other_keys > 0:
        lose(KMS_KEY, "unlisted", f"{other_keys} customer-managed key(s) are known only as a count; "
             "rotation state unknown, not serialized", kind="omitted_resource")

    trail = infra.cloudtrail
    if trail.trail_arn:
        trail_args: dict[str, Any] = {"enable_logging": trail.is_enabled}
        match = _TRAIL_ARN.fullmatch(trail.trail_arn)
        if match:
            trail_args["name"] = match.group(1)
        # The model's flags are "any trail" aggregates while trail_arn is one trail:
        # False holds for every trail; True cannot be attributed to this one.
        aggregate = (
            ("is_multi_region", "is_multi_region_trail", trail.is_multi_region),
            ("has_log_file_validation", "enable_log_file_validation", trail.has_log_file_validation),
        )
        for model_field, tf_arg, value in aggregate:
            if value:
                omitted_field(CLOUDTRAIL, trail.trail_arn, model_field,
                              "recorded true for any trail, not for this one; omitted rather than attributed")
            else:
                trail_args[tf_arg] = False
        add("aws_cloudtrail", CLOUDTRAIL, trail.trail_arn, trail_args)
        unmodeled("aws_cloudtrail", CLOUDTRAIL, trail.trail_arn)
        report_fields(CLOUDTRAIL, trail.trail_arn, trail, {"trail_arn", "is_enabled", "is_multi_region", "has_log_file_validation"})
    elif trail.is_enabled or trail.is_multi_region or trail.has_log_file_validation:
        lose(CLOUDTRAIL, "none", "CloudTrail state is recorded without a logging trail ARN; not serialized", kind="omitted_resource")

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
