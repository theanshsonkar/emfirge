"""Pure infrastructure mutation helpers for remediation simulations."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, Iterable, Type

from pydantic import BaseModel, Field

from app.models import (
    AWSInfrastructure,
    EC2Instance,
    LambdaFunction,
    RDSInstance,
    S3Bucket,
    SecurityGroup,
)


SUPPORTED_RESOURCE_TYPES = frozenset(
    {"ec2_instance", "security_group", "rds_instance", "s3_bucket", "lambda_function"}
)
SUPPORTED_OPERATIONS = frozenset({"add", "modify", "delete"})


class Change(BaseModel):
    op: str
    resource_type: str
    resource_id: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)


def _fresh(infra: AWSInfrastructure) -> AWSInfrastructure:
    """Reconstruct the model so neither it nor any nested value is shared."""
    return AWSInfrastructure.model_validate(copy.deepcopy(infra.model_dump()))


def _validate_change(change: Change) -> None:
    if change.op not in SUPPORTED_OPERATIONS:
        raise ValueError(f"Unsupported operation: {change.op}")
    if change.resource_type not in SUPPORTED_RESOURCE_TYPES:
        raise ValueError(f"Unsupported resource type: {change.resource_type}")
    if not isinstance(change.fields, dict):
        raise ValueError("Change fields must be a dictionary")


def _model_for(resource_type: str) -> Type[BaseModel]:
    return {
        "ec2_instance": EC2Instance,
        "security_group": SecurityGroup,
        "rds_instance": RDSInstance,
        "s3_bucket": S3Bucket,
        "lambda_function": LambdaFunction,
    }[resource_type]


def _collection(infra: AWSInfrastructure, resource_type: str) -> list:
    if resource_type in {"ec2_instance", "security_group"}:
        return infra.ec2.instances if resource_type == "ec2_instance" else infra.ec2.security_groups
    if resource_type == "rds_instance":
        return infra.rds.rds_instances
    if resource_type == "s3_bucket":
        return infra.s3.buckets
    return infra.lambda_data.functions


def _identity(resource_type: str, resource: BaseModel) -> str:
    return resource.name if resource_type in {"s3_bucket", "lambda_function"} else resource.id


def _field_check(model_type: Type[BaseModel], fields: Dict[str, Any]) -> None:
    unknown = set(fields) - set(model_type.model_fields)
    if unknown:
        raise ValueError(f"Unknown field(s) for {model_type.__name__}: {sorted(unknown)}")


def _auto_id(infra: AWSInfrastructure, change: Change) -> str:
    state = json.dumps(infra.model_dump(), sort_keys=True, separators=(",", ":"), default=str)
    fields = json.dumps(change.fields, sort_keys=True, separators=(",", ":"), default=str)
    for attempt in range(10000):
        digest = hashlib.sha256(f"{state}|{change.resource_type}|{fields}|{attempt}".encode()).hexdigest()[:6]
        candidate = f"new-{change.resource_type}-{digest}"
        if not any(_identity(change.resource_type, item) == candidate for item in _collection(infra, change.resource_type)):
            return candidate
    raise ValueError(f"Could not generate a unique ID for {change.resource_type}")


def _resource_data(infra: AWSInfrastructure, change: Change) -> Dict[str, Any]:
    data = dict(change.fields)
    key = "name" if change.resource_type in {"s3_bucket", "lambda_function"} else "id"
    if key in data:
        raise ValueError(f"Cannot set identity field: {key}")
    identity = change.resource_id or _auto_id(infra, change)
    data[key] = identity
    _field_check(_model_for(change.resource_type), data)
    return data


def _sync_counts(infra: AWSInfrastructure) -> None:
    infra.ec2.instance_count = len(infra.ec2.instances)
    infra.ec2.instance_ids = [instance.id for instance in infra.ec2.instances]
    infra.rds.instances = sorted(instance.id for instance in infra.rds.rds_instances)
    infra.s3.total_buckets = len(infra.s3.buckets)
    infra.lambda_data.function_count = len(infra.lambda_data.functions)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _update_add_summaries(infra: AWSInfrastructure, resource_type: str, resource: BaseModel) -> None:
    if resource_type == "ec2_instance":
        infra.ec2.instance_types.append(resource.type)
    elif resource_type == "s3_bucket" and resource.is_public:
        _append_unique(infra.s3.public_buckets, resource.name)
    elif resource_type == "rds_instance":
        _append_unique(infra.rds.instances, resource.id)
        if resource.publicly_accessible:
            _append_unique(infra.rds.publicly_accessible, resource.id)
        if not resource.encrypted:
            _append_unique(infra.rds.unencrypted_instances, resource.id)


def _remove_value(values: list[str], value: str) -> None:
    values[:] = [item for item in values if item != value]


def _remove_one(values: list[str], value: str) -> None:
    try:
        values.remove(value)
    except ValueError:
        pass


def _delete(infra: AWSInfrastructure, resource_type: str, resource_id: str) -> None:
    collection = _collection(infra, resource_type)
    index = next((i for i, item in enumerate(collection) if _identity(resource_type, item) == resource_id), None)
    if index is None:
        raise ValueError(f"Target not found: {resource_type}/{resource_id}")
    target = collection[index]
    collection.pop(index)

    if resource_type == "ec2_instance":
        _remove_one(infra.ec2.instance_types, target.type)
        for subnet in infra.vpc.subnets:
            _remove_value(subnet.resources, resource_id)
        for group in infra.ec2.security_groups:
            _remove_value(group.attached_to, resource_id)
        _remove_value(infra.ec2.stopped_instances, resource_id)
    elif resource_type == "security_group":
        for instance in infra.ec2.instances:
            _remove_value(instance.sg_ids, resource_id)
        for instance in infra.rds.rds_instances:
            _remove_value(instance.sg_ids, resource_id)
        _remove_value(infra.ec2.open_security_groups, resource_id)
        if infra.ec2.ssh_security_group_id == resource_id:
            infra.ec2.ssh_security_group_id = None
        if infra.ec2.rdp_security_group_id == resource_id:
            infra.ec2.rdp_security_group_id = None
    elif resource_type == "rds_instance":
        _remove_value(infra.rds.instances, resource_id)
        for subnet in infra.vpc.subnets:
            _remove_value(subnet.resources, resource_id)
        for values in (
            infra.rds.publicly_accessible,
            infra.rds.unencrypted_instances,
            infra.rds.instances_without_deletion_protection,
            infra.rds.instances_without_log_exports,
        ):
            _remove_value(values, resource_id)
    elif resource_type == "s3_bucket":
        for values in (
            infra.s3.public_buckets,
            infra.s3.unencrypted_buckets,
            infra.s3.buckets_without_versioning,
            infra.s3.buckets_without_logging,
        ):
            _remove_value(values, resource_id)
    elif resource_type == "lambda_function":
        for subnet in infra.vpc.subnets:
            _remove_value(subnet.resources, resource_id)
        for values in (
            infra.lambda_data.functions_with_admin_role,
            infra.lambda_data.functions_with_outdated_runtime,
            infra.lambda_data.functions_with_no_timeout,
        ):
            _remove_value(values, resource_id)


def recompute_derived_state(infra: AWSInfrastructure) -> AWSInfrastructure:
    """Recompute EC2 internet-exposure summaries from authoritative resources."""
    attached_sg_ids = {
        sg_id
        for instance in infra.ec2.instances
        for sg_id in instance.sg_ids
    }
    ssh_matches: list[str] = []
    rdp_matches: list[str] = []

    def covers_port(rule: dict, port: int) -> bool:
        try:
            start = int(rule.get("from_port", 0))
            end_value = rule.get("to_port")
            end = start if end_value is None else int(end_value)
        except (TypeError, ValueError):
            return False
        if start < 0 or end < 0:
            return False
        if start > end:
            start, end = end, start
        return start <= port <= end

    for group in sorted(infra.ec2.security_groups, key=lambda item: item.id):
        if group.id not in attached_sg_ids:
            continue
        for rule in group.rules:
            cidrs = rule.get("ip_ranges") or []
            if not {"0.0.0.0/0", "::/0"}.intersection(cidrs):
                continue
            if covers_port(rule, 22):
                ssh_matches.append(group.id)
            if covers_port(rule, 3389):
                rdp_matches.append(group.id)

    infra.ec2.ssh_open_to_internet = bool(ssh_matches)
    infra.ec2.ssh_security_group_id = ssh_matches[0] if ssh_matches else None
    infra.ec2.rdp_open_to_internet = bool(rdp_matches)
    infra.ec2.rdp_security_group_id = rdp_matches[0] if rdp_matches else None
    return infra


def apply_change(infra: AWSInfrastructure, change: Change) -> AWSInfrastructure:
    """Apply one change without mutating ``infra``."""
    _validate_change(change)
    result = _fresh(infra)
    resource_type = change.resource_type
    model_type = _model_for(resource_type)

    if change.op == "add":
        data = _resource_data(result, change)
        resource = model_type.model_validate(data)
        if any(_identity(resource_type, item) == _identity(resource_type, resource) for item in _collection(result, resource_type)):
            raise ValueError(f"Target already exists: {resource_type}/{_identity(resource_type, resource)}")
        _collection(result, resource_type).append(resource)
        _update_add_summaries(result, resource_type, resource)
    elif change.op == "modify":
        _field_check(model_type, change.fields)
        identity_field = "name" if resource_type in {"s3_bucket", "lambda_function"} else "id"
        if identity_field in change.fields:
            raise ValueError(f"Cannot modify identity field: {identity_field}")
        collection = _collection(result, resource_type)
        index = next(
            (i for i, item in enumerate(collection) if _identity(resource_type, item) == change.resource_id),
            None,
        )
        if index is None:
            raise ValueError(f"Target not found: {resource_type}/{change.resource_id}")
        target = collection[index]
        updated_data = target.model_dump()
        updated_data.update(change.fields)
        collection[index] = model_type.model_validate(updated_data)
    else:
        _delete(result, resource_type, change.resource_id)

    _sync_counts(result)
    return recompute_derived_state(result)


def apply_changes(infra: AWSInfrastructure, changes: Iterable[Change]) -> AWSInfrastructure:
    """Apply changes in order, returning a fresh model for every step."""
    result = _fresh(infra)
    for change in changes:
        result = apply_change(result, change)
    return result
