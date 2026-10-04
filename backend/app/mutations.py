"""Pure infrastructure mutation helpers for remediation simulations."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, Iterable, Type

from pydantic import BaseModel, Field

from app.models import (
    AccessStatement,
    AWSInfrastructure,
    EC2Instance,
    LambdaFunction,
    RDSInstance,
    S3Bucket,
    SecurityGroup,
)


_CRUD_OPERATIONS = frozenset({"add", "modify", "delete"})

# Authoritative branch mutation contract. Runtime validation, model lookup, the
# capabilities endpoint, and its schema-drift tests all derive from this table.
_MUTATION_CAPABILITIES = {
    "ec2_instance": {"model": EC2Instance, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "security_group": {
        "model": SecurityGroup,
        "operations": _CRUD_OPERATIONS,
        "constraints": ({
            "operations": sorted(_CRUD_OPERATIONS),
            "kind": "derived_field",
            "fields": ["attached_to"],
            "required_fields": [],
            "allowed_fields": [],
            "message": "SecurityGroup.attached_to is derived from EC2 sg_ids; change EC2 sg_ids instead",
        },),
    },
    "rds_instance": {"model": RDSInstance, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "s3_bucket": {"model": S3Bucket, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "lambda_function": {"model": LambdaFunction, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "iam_role_policy": {
        "model": None,
        "operations": frozenset({"modify"}),
        "constraints": ({
            "operations": ["modify"],
            "kind": "complete_field_replacement",
            "fields": [],
            "required_fields": ["access_statements"],
            "allowed_fields": ["access_statements"],
            "message": "Replace the complete normalized statement list for one existing collected role identified by role ARN",
        },),
    },
}
SUPPORTED_RESOURCE_TYPES = frozenset(_MUTATION_CAPABILITIES)
SUPPORTED_OPERATIONS = frozenset().union(
    *(capability["operations"] for capability in _MUTATION_CAPABILITIES.values())
)


class MutationConstraint(BaseModel):
    operations: list[str]
    kind: str
    fields: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    allowed_fields: list[str] = Field(default_factory=list)
    message: str


class ResourceMutationCapability(BaseModel):
    resource_type: str
    operations: list[str]
    constraints: list[MutationConstraint] = Field(default_factory=list)


class MutationCapabilities(BaseModel):
    operations: list[str]
    resources: list[ResourceMutationCapability]


def mutation_capabilities() -> MutationCapabilities:
    """Return the public branch mutation contract from the runtime registry."""
    return MutationCapabilities(
        operations=sorted(SUPPORTED_OPERATIONS),
        resources=[
            ResourceMutationCapability(
                resource_type=resource_type,
                operations=sorted(capability["operations"]),
                constraints=capability["constraints"],
            )
            for resource_type, capability in sorted(_MUTATION_CAPABILITIES.items())
        ],
    )


class Change(BaseModel):
    op: str
    resource_type: str
    resource_id: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)
    expected_change_count: int | None = Field(default=None, ge=0)


def _fresh(infra: AWSInfrastructure) -> AWSInfrastructure:
    """Reconstruct the model so neither it nor any nested value is shared."""
    return AWSInfrastructure.model_validate(copy.deepcopy(infra.model_dump()))


def _validate_change(change: Change) -> None:
    capability = _MUTATION_CAPABILITIES.get(change.resource_type)
    if change.op not in SUPPORTED_OPERATIONS:
        raise ValueError(f"Unsupported operation: {change.op}")
    if capability is None:
        raise ValueError(f"Unsupported resource type: {change.resource_type}")
    if change.op not in capability["operations"]:
        raise ValueError(f"{change.resource_type} supports {', '.join(sorted(capability['operations']))} only")
    if not isinstance(change.fields, dict):
        raise ValueError("Change fields must be a dictionary")
    for constraint in capability["constraints"]:
        if constraint["kind"] == "derived_field" and change.op in constraint["operations"]:
            if set(change.fields).intersection(constraint["fields"]):
                raise ValueError(constraint["message"])


def _model_for(resource_type: str) -> Type[BaseModel]:
    model_type = _MUTATION_CAPABILITIES[resource_type]["model"]
    if model_type is None:
        raise ValueError(f"{resource_type} does not have a resource model")
    return model_type


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


def _sync_security_group_attachments(infra: AWSInfrastructure) -> None:
    """Rebuild the EC2-only SG back-reference from authoritative instance sg_ids.

    RDS, Lambda, and other consumers keep their own sg_ids; their graph
    relationships are emitted from those forward references. ``attached_to``
    feeds the EC2-specific attached-instance edges and security rules.
    """
    attachments = {group.id: [] for group in infra.ec2.security_groups}
    for instance in infra.ec2.instances:
        for sg_id in dict.fromkeys(instance.sg_ids):
            attached = attachments.get(sg_id)
            if attached is not None:
                attached.append(instance.id)
    for group in infra.ec2.security_groups:
        group.attached_to = attachments[group.id]


def _delete(infra: AWSInfrastructure, resource_type: str, resource_id: str) -> None:
    collection = _collection(infra, resource_type)
    index = next((i for i, item in enumerate(collection) if _identity(resource_type, item) == resource_id), None)
    if index is None:
        raise ValueError(f"Target not found: {resource_type}/{resource_id}")
    if resource_type == "security_group":
        users = sorted({
            item.id for item in infra.ec2.instances if resource_id in item.sg_ids
        } | {
            item.id for item in infra.rds.rds_instances if resource_id in item.sg_ids
        } | {
            item.name for item in infra.lambda_data.functions if resource_id in item.sg_ids
        } | {
            item.id for item in infra.elasticache.clusters if resource_id in item.sg_ids
        } | {
            group.id for group in infra.ec2.security_groups if group.id != resource_id
            and any(
                resource_id in (rule.get("source_sg_ids") or [])
                or resource_id in (rule.get("dest_sg_ids") or [])
                for rule in group.rules + group.egress_rules
            )
        })
        if users:
            raise ValueError(
                f"Security group {resource_id} is still in use by {', '.join(users)}; "
                "model detaching or replacing it before deletion"
            )
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


def _replace_iam_role_policy_statements(
    infra: AWSInfrastructure, change: Change
) -> None:
    """Replace the normalized identity-policy statement view for one collected role.

    This deliberately does not accept raw IAM policy documents or create/delete
    roles. Replacing statements clears collector-derived shortcuts so graph
    derivation uses only the supplied normalized statements on this branch.
    """
    constraint = next(
        item for item in _MUTATION_CAPABILITIES["iam_role_policy"]["constraints"]
        if change.op in item["operations"] and item["kind"] == "complete_field_replacement"
    )
    required_fields = set(constraint["required_fields"])
    allowed_fields = set(constraint["allowed_fields"])
    if set(change.fields) != required_fields or required_fields != allowed_fields:
        raise ValueError(
            f"iam_role_policy modify requires only {', '.join(sorted(required_fields))}"
        )
    replacement_field = next(iter(required_fields))
    statements = change.fields[replacement_field]
    if not isinstance(statements, list):
        raise ValueError("access_statements must be a list replacing the complete normalized statement set")

    matches = [policy for policy in infra.iam.role_policies if policy.role_arn == change.resource_id]
    if not matches:
        raise ValueError(f"Target not found: iam_role_policy/{change.resource_id}")
    if len(matches) != 1:
        raise ValueError("IAM role policy target is ambiguous; role ARN must identify exactly one collected role")

    policy = matches[0]
    policy.access_statements = [AccessStatement.model_validate(statement) for statement in statements]
    # Do not let stale collector summaries override an empty/replaced statement
    # set in egraph.build_graph's legacy fallback path.
    policy.has_admin = False
    policy.accessible_resources = []
    policy.policy_names = []


def recompute_derived_state(
    infra: AWSInfrastructure, *, reconcile_security_group_attachments: bool = False,
) -> AWSInfrastructure:
    """Recompute EC2 internet-exposure summaries from authoritative resources."""
    if reconcile_security_group_attachments:
        _sync_security_group_attachments(infra)
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
    if resource_type == "iam_role_policy":
        _replace_iam_role_policy_statements(result, change)
        return result

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
    return recompute_derived_state(
        result,
        reconcile_security_group_attachments=resource_type in {"ec2_instance", "security_group"}
        or (resource_type in {"rds_instance", "lambda_function"} and "sg_ids" in change.fields),
    )


def apply_changes(infra: AWSInfrastructure, changes: Iterable[Change]) -> AWSInfrastructure:
    """Apply changes in order, returning a fresh model for every step."""
    result = _fresh(infra)
    for change in changes:
        result = apply_change(result, change)
    return result
