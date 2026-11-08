"""AWS adapter: which changed settings the check reads, declared by name.

``JUDGED_FIELDS`` is a statement about OUR OWN checks, nothing about AWS behaviour: for a resource type, the settings
that some code of the check reads when that setting changed, whatever it then found. ``readers`` names the module(s)
whose source reads the setting; law L87h greps each reader for the field, so a declaration cannot name code that does
not use it. A setting not listed here is still reported in ``changed_settings``, as not judged.

Declared only where the read is about a MODIFIED resource (a field that a check reads only when the resource is
deleted, such as an emptiness flag on the delete path, is not declared). Adding a reader to a check means adding its
field here; a setting no check reads stays visible, never silent.

``derived_fields`` are settings computed from other settings (the catalog's Derived fields, graph keys that restate a
model field, counts). The core drops them from a resource's list when something else changed on it.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.field_catalog import CATALOG, Derived


@dataclass(frozen=True)
class Judges:
    damages: tuple[str, ...]
    readers: tuple[str, ...]


def _j(damages: str, readers: str) -> Judges:
    return Judges(tuple(damages.split()), tuple(readers.split()))


_SCHEDULE = _j("availability outside_world", "aws_check")
_REACH = _j("availability exposure", "egraph")

# resource type -> setting -> the damages whose checks read it, and the modules that read it
JUDGED_FIELDS: dict[str, dict[str, Judges]] = {
    "ec2_instance": {
        "type": _j("money", "cost"),                       # the price lookup
        "sg_ids": _j("exposure", "exposure"),              # security group consumers
        "subnet_id": _j("exposure", "exposure"),
        "has_public_ip": _j("exposure", "egraph"),         # internet reachability
        "instance_profile_arn": _j("availability", "egraph"),  # uses_iam_role edge
    },
    "security_group": {
        "rules": _j("exposure", "exposure"),
        "egress_rules": _j("exposure", "exposure"),
    },
    "rds_instance": {
        "sg_ids": _j("exposure", "exposure"),
        "subnet_id": _j("exposure", "exposure"),
        "publicly_accessible": _j("exposure", "egraph"),
        "engine": _j("exposure", "rds_ports"),             # default listener port
        "backup_retention_days": _j("data", "verdict"),    # recovery points removed
    },
    "s3_bucket": {
        "is_public": _j("exposure", "aws_check"),
        "logging_enabled": _j("control", "aws_check"),
        "versioning_enabled": _j("data", "verdict"),
    },
    "lambda_function": {
        "role_arn": _j("availability", "egraph"),          # uses_iam_role edge
        "secret_refs": _j("availability", "egraph"),       # REFERENCES_SECRET edge
        "sg_ids": _j("exposure", "egraph"),
        "subnet_ids": _j("exposure", "exposure"),
    },
    "ebs_volume": {
        "state": _j("money", "cost"),
        "size_gb": _j("money", "cost"),
        "volume_type": _j("money", "cost"),
    },
    "dynamodb_table": {
        "pitr_enabled": _j("data", "verdict"),
    },
    "scheduler_schedule": {
        "state": _SCHEDULE,
        "schedule_expression": _SCHEDULE,
        "schedule_expression_timezone": _SCHEDULE,
        "target_arn": _SCHEDULE,
        "target_role_arn": _SCHEDULE,
        "has_input": _SCHEDULE,
        "flexible_time_window_mode": _SCHEDULE,
        "flexible_time_window_minutes": _SCHEDULE,
        "start_date": _SCHEDULE,
        "end_date": _SCHEDULE,
    },
    "cloudfront_distribution": {
        "origins": _j("availability", "cloudfront_check"),
        "cache_behaviors": _j("availability", "cloudfront_check"),
        "default_cache_behavior": _j("availability", "cloudfront_check"),
    },
    "iam_role": {
        "access_statements": _j("availability control", "aws_permissions"),
        "has_admin": _j("control", "aws_check"),
        "trust_allows_external": _j("exposure", "aws_check"),
        "trust_external_unrestricted": _j("exposure", "aws_check"),
    },
    "network_acl": {
        "entries": _REACH,
        "associated_subnet_ids": _REACH,
        "vpc_id": _REACH,
    },
    "route_table": {
        "routes": _REACH,
        "associated_subnet_ids": _REACH,
        "vpc_id": _REACH,
    },
}

# Graph keys that restate a model field under another name, or are computed from other resources, per resource type.
_GRAPH_COMPUTED = {
    "ec2_instance": {"instance_type"},
    "security_group": {"rules_count", "attached_instances"},
    "s3_bucket": {"has_policy"},
    "lambda_function": {"subnet_count"},
    "cloudfront_distribution": {"behaviors"},
    "iam_role": {"accessible_resources"},
}


def judged_map() -> dict[str, dict[str, tuple[str, ...]]]:
    """The neutral form the core reads: type -> setting -> damage names."""
    return {rtype: {name: tuple(sorted(j.damages)) for name, j in fields.items()} for rtype, fields in JUDGED_FIELDS.items()}


def derived_map() -> dict[str, frozenset[str]]:
    """Per resource type, the settings that are computed (catalog Derived fields plus the restated graph keys)."""
    out: dict[str, set[str]] = {
        rtype: {name for name, source in fields.items() if isinstance(source, Derived)} for rtype, fields in CATALOG.items()
    }
    for rtype, names in _GRAPH_COMPUTED.items():
        out.setdefault(rtype, set()).update(names)
    return {rtype: frozenset(names) for rtype, names in out.items()}
