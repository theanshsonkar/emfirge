"""Pure infrastructure mutation helpers for remediation simulations."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Literal, Type, get_args
from ipaddress import ip_network

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, TypeAdapter, ValidationError, field_validator, model_validator
from app.cidr import is_internet_cidr, rule_opens_port_to_internet
from app.s3_public import effective_is_public, policy_is_public
from app.tags import TAGGED_TYPES, apply_tag_replacement
from app.field_catalog import validate_fields as validate_catalog_fields

from app.models import (
    AccessStatement,
    PolicyDocumentRecord,
    merge_policy_statements,
    AWSInfrastructure,
    EBSSnapshot,
    EBSVolume,
    EC2Instance,
    LambdaFunction,
    RDSInstance,
    RDSSnapshot,
    Route,
    RouteTable,
    S3Bucket,
    SecurityGroup,
    NetworkACL,
    NACLEntry,
    IAMUser,
    NATGateway,
    RolePolicy,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SecurityGroupRuleChange(_StrictModel):
    from_port: int | None = None
    to_port: int | None = None
    protocol: str
    ip_ranges: list[str] = Field(default_factory=list)
    source_sg_ids: list[str] = Field(default_factory=list)
    dest_sg_ids: list[str] = Field(default_factory=list)

    @field_validator("protocol")
    @classmethod
    def valid_protocol(cls, value: str) -> str:
        if value not in {"-1", "tcp", "udp", "icmp", "icmpv6"}:
            try:
                if not 0 <= int(value) <= 255:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("must be an AWS protocol name or numeric protocol") from exc
        return value

    @field_validator("from_port", "to_port")
    @classmethod
    def valid_ports(cls, value: int | None) -> int | None:
        if value is not None and not -1 <= value <= 65535:
            raise ValueError("must be between -1 and 65535")
        return value

    @field_validator("ip_ranges", mode="after")
    @classmethod
    def valid_cidrs(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError("must contain valid CIDR strings") from exc
        return values
    @model_validator(mode="after")
    def validate_rule(self) -> "SecurityGroupRuleChange":
        if (self.protocol in {"tcp", "udp", "6", "17"}
                and self.from_port is not None and self.to_port is not None
                and self.from_port > self.to_port):
            raise ValueError("from_port must be less than or equal to to_port")
        return self


class AccessStatementChange(_StrictModel):
    effect: str
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    is_not_action: bool = False
    is_not_resource: bool = False
    has_condition: bool = False

    @field_validator("effect", mode="before")
    @classmethod
    def normalize_effect(cls, value: str) -> str:
        if value not in {"Allow", "Deny", "allow", "deny"}:
            raise ValueError("must be exactly Allow, Deny, allow, or deny")
        return value.lower()


class RouteChange(_StrictModel):
    destination_cidr: str
    target_type: str
    target_id: str

    @field_validator("destination_cidr")
    @classmethod
    def valid_destination_cidr(cls, value: str) -> str:
        try:
            ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("must be a valid CIDR string") from exc
        return value


class NACLEntryChange(_StrictModel):
    rule_number: int
    protocol: str
    rule_action: str
    egress: bool
    cidr_block: str | None = None
    ipv6_cidr_block: str | None = None
    port_from: int | None = None
    port_to: int | None = None


_MUTATION_NESTED_TYPES = {
    ("security_group", "rules"): list[SecurityGroupRuleChange],
    ("security_group", "egress_rules"): list[SecurityGroupRuleChange],
    ("iam_role_policy", "access_statements"): list[AccessStatementChange],
    ("iam_role_policy", "policy_documents"): list[PolicyDocumentRecord],
    ("route_table", "routes"): list[RouteChange],
    ("network_acl", "entries"): list[NACLEntryChange],
}

def _trust_document(value: Any) -> dict:
    if isinstance(value, str):
        try: value = json.loads(value)
        except Exception as exc: raise ValueError('iam_role.trust_policy must be a JSON object') from exc
    if not isinstance(value, dict) or 'Statement' not in value:
        raise ValueError('iam_role.trust_policy must be an object with Statement')
    return value

def _role_arn(infra: AWSInfrastructure, resource_id: str) -> str:
    if resource_id.startswith('arn:aws:iam::'):
        if not re.fullmatch(r'arn:aws:iam::\d{12}:role/[\w+=,.@/-]+', resource_id): raise ValueError('malformed role ARN')
        return resource_id
    accounts = {p.role_arn.split(':')[4] for p in infra.iam.role_policies if p.role_arn.startswith('arn:') and len(p.role_arn.split(':')) > 4}
    if len(accounts) != 1: raise ValueError('pass the full role ARN')
    return f'arn:aws:iam::{next(iter(accounts))}:role/{resource_id}'


def _loc_text(loc: tuple[Any, ...]) -> str:
    result = ""
    for part in loc:
        result += f"[{part}]" if isinstance(part, int) else ("." if result else "") + str(part)
    return result


def _validation_message(resource_type: str, field: str, error: dict[str, Any], annotation: Any) -> str:
    loc = tuple(error.get("loc", ()))
    path = f"{resource_type}.{field}{_loc_text(loc[1:] if loc and loc[0] == field else loc)}"
    error_type = error.get("type", "")
    if error_type == "extra_forbidden":
        unknown = str(loc[-1]) if loc else field
        item_type = next((arg for arg in get_args(annotation) if hasattr(arg, "model_fields")), annotation)
        allowed = ", ".join(sorted(getattr(item_type, "model_fields", {}).keys()))
        prefix = path.rsplit(".", 1)[0] if loc else path
        return f"{prefix}: unknown field '{unknown}' (allowed: {allowed})"
    if error_type in {"value_error", "assertion_error"}:
        problem = str(error.get("msg", "validation failed"))
        if problem.lower().startswith("value error, "):
            problem = problem[13:]
        return f"{path}: {problem}"
    expected = {
        "int_type": "an integer", "str_type": "a string", "bool_type": "a boolean",
        "list_type": "a list", "dict_type": "an object", "none_required": "null",
    }.get(error_type, "the expected type")
    return f"{path}: expected {expected}"


def _strict_validate_field(resource_type: str, field: str, value: Any, annotation: Any) -> None:
    try:
        TypeAdapter(annotation).validate_json(json.dumps(value), strict=True)
    except (ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, ValidationError) and exc.errors():
            raise ValueError(_validation_message(resource_type, field, exc.errors()[0], annotation)) from exc
        raise ValueError(f"{resource_type}.{field}: expected the field's declared JSON type") from exc


def _validate_change_fields(change: Change) -> None:
    if change.op not in {"add", "modify"}:
        return
    if change.resource_type == "nat_gateway" and change.op == "add":
        unknown = set(change.fields) - {"subnet_id", "connectivity_type", "allocation_id", "tags"}
        if unknown:
            raise ValueError("nat_gateway add fields: subnet_id, connectivity_type, allocation_id and tags only")
        for field in ("subnet_id", "allocation_id"):
            if field in change.fields:
                _strict_validate_field("nat_gateway", field, change.fields[field], str)
        connectivity = change.fields.get("connectivity_type", "public")
        if connectivity not in {"public", "private"}:
            raise ValueError("connectivity_type must be public or private")
        if connectivity == "private" and "allocation_id" in change.fields:
            raise ValueError("A private NAT gateway cannot have an Elastic IP allocation_id")
        return
    if change.resource_type == "ebs_volume" and change.op == "add":
        unknown = set(change.fields) - {"availability_zone", "size_gb", "volume_type", "tags"}
        if unknown:
            raise ValueError("ebs_volume add fields: availability_zone, size_gb, volume_type and tags only")
        if "availability_zone" in change.fields:
            _strict_validate_field("ebs_volume", "availability_zone", change.fields["availability_zone"], str)
        if "size_gb" not in change.fields:
            raise ValueError("ebs_volume.size_gb: required (AWS needs Size when no snapshot is given; restoring from a snapshot is not modeled)")
        _strict_validate_field("ebs_volume", "size_gb", change.fields["size_gb"], int)
        # The type itself is checked against AWS's VolumeType enum by the field catalog.
        volume_type = change.fields.get("volume_type", "gp2")
        if volume_type in _EBS_SIZE_LIMITS_GIB:
            low, high = _EBS_SIZE_LIMITS_GIB[volume_type]
            if not low <= change.fields["size_gb"] <= high:
                raise ValueError(f"ebs_volume.size_gb: {volume_type} volumes are {low} to {high} GiB")
        return
    if change.resource_type == "rds_snapshot" and change.op == "add":
        unknown = set(change.fields) - {"db_instance_id"}
        if unknown:
            raise ValueError("rds_snapshot add fields: unknown schema field")
        if "db_instance_id" in change.fields:
            _strict_validate_field("rds_snapshot", "db_instance_id", change.fields["db_instance_id"], str)
        return
    if change.resource_type == 'iam_role':
        allowed = {'trust_policy'}
        if set(change.fields) - allowed: raise ValueError('iam_role fields: unknown schema field')
        if 'trust_policy' in change.fields: _trust_document(change.fields['trust_policy'])
        if change.op == 'modify' and set(change.fields) != allowed: raise ValueError('iam_role modify requires exactly trust_policy')
        return
    if change.resource_type == 'iam_user':
        if set(change.fields) - {'has_console_access'}: raise ValueError('iam_user fields: unknown schema field')
        if 'has_console_access' in change.fields: _strict_validate_field('iam_user', 'has_console_access', change.fields['has_console_access'], bool)
        return
    if change.resource_type in {"iam_role_policy", "route_table"}:
        annotations = {field: type_ for (resource, field), type_ in _MUTATION_NESTED_TYPES.items() if resource == change.resource_type}
    else:
        model_type = _MUTATION_CAPABILITIES[change.resource_type]["model"]
        annotations = {field: info.annotation for field, info in model_type.model_fields.items()}
        annotations.update({field: type_ for (resource, field), type_ in _MUTATION_NESTED_TYPES.items() if resource == change.resource_type})
    for field, value in change.fields.items():
        if field in annotations:
            # The special complete-replacement handlers provide the established
            # field-level message for a non-list replacement; nested contents
            # are still validated strictly here whenever the outer value is a list.
            if (change.resource_type, field) in _MUTATION_NESTED_TYPES and not isinstance(value, list):
                continue
            _strict_validate_field(change.resource_type, field, value, annotations[field])


_CRUD_OPERATIONS = frozenset({"add", "modify", "delete"})
# CreateVolume size range per volume type (AWS EBS volume types docs).
_EBS_SIZE_LIMITS_GIB = {
    "gp2": (1, 16384), "gp3": (1, 16384), "io1": (4, 16384), "io2": (4, 65536),
    "st1": (125, 16384), "sc1": (125, 16384), "standard": (1, 1024),
}
_DELETE_ONLY = frozenset({"delete"})
_RDS_DELETE_FIELDS = {
    "skip_final_snapshot": bool,
    "final_db_snapshot_identifier": str,
    "delete_automated_backups": bool,
}

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
    "s3_bucket": {
        "model": S3Bucket,
        "operations": _CRUD_OPERATIONS,
        "constraints": ({
            "operations": ["add", "modify"],
            "kind": "derived_field",
            "fields": ["policy_public"],
            "required_fields": [],
            "allowed_fields": [],
            "message": "S3Bucket.policy_public is derived from policy; change policy instead",
        },),
    },
    "lambda_function": {"model": LambdaFunction, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "ebs_volume": {"model": EBSVolume, "operations": frozenset({"add", "delete"}), "constraints": ()},
    "ebs_snapshot": {"model": EBSSnapshot, "operations": _DELETE_ONLY, "constraints": ()},
    "rds_snapshot": {"model": RDSSnapshot, "operations": frozenset({"add", "delete"}), "constraints": ()},
    "iam_role": {"model": None, "operations": _CRUD_OPERATIONS, "constraints": ()},
    "iam_user": {"model": IAMUser, "operations": frozenset({"add"}), "constraints": ()},
    "nat_gateway": {"model": NATGateway, "operations": frozenset({"add"}), "constraints": ()},
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
    "network_acl": {
        "model": NetworkACL,
        "operations": _CRUD_OPERATIONS,
        "constraints": ({
            "operations": ["modify"], "kind": "complete_field_replacement",
            "fields": [], "required_fields": [],
            "allowed_fields": ["entries", "associated_subnet_ids"],
            "message": "Replace complete NACL entries and/or subnet associations",
        },),
    },
    "route_table": {
        "model": RouteTable,
        "operations": frozenset({"add", "modify"}),
        "constraints": ({
            "operations": ["modify"],
            "kind": "complete_field_replacement",
            "fields": [],
            "required_fields": ["routes"],
            "allowed_fields": ["routes"],
            "message": "Replace the complete normalized route list for one existing collected route table; associations are derived, and new IGW routes require complete same-VPC available-attachment evidence",
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


class TargetNotFound(ValueError):
    def __init__(self, resource_type: str, resource_id: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(f"Target not found: {resource_type}")


class Change(BaseModel):
    op: str
    resource_type: str
    resource_id: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)
    expected_change_count: int | None = Field(default=None, ge=0)
    branch_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def _fresh(infra: AWSInfrastructure) -> AWSInfrastructure:
    """Reconstruct the model so neither it nor any nested value is shared."""
    result = AWSInfrastructure.model_validate(copy.deepcopy(infra.model_dump()))
    result._deletions = copy.deepcopy(infra._deletions)
    return result


def deletion_ledger(infra: AWSInfrastructure) -> list[dict]:
    """Return a copy of the ordered delete ledger for one branch view."""
    return copy.deepcopy(infra._deletions)


def _validate_delete_fields(change: Change) -> None:
    if change.resource_type == "rds_instance":
        unknown = set(change.fields) - set(_RDS_DELETE_FIELDS)
        if unknown:
            raise ValueError("rds_instance delete fields: unknown schema field")
        for field, annotation in _RDS_DELETE_FIELDS.items():
            if field in change.fields:
                _strict_validate_field("rds_instance", field, change.fields[field], annotation)
        skip = change.fields.get("skip_final_snapshot")
        identifier = change.fields.get("final_db_snapshot_identifier")
        if skip is False and not identifier:
            raise ValueError("rds_instance.final_db_snapshot_identifier: required when skip_final_snapshot is false")
        if skip is True and identifier is not None:
            raise ValueError("rds_instance.final_db_snapshot_identifier: must be absent when skip_final_snapshot is true")
    elif change.fields:
        raise ValueError(f"{change.resource_type} delete fields: no schema fields are allowed")


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
    if change.resource_type == "ec2_instance" and change.op in {"add", "modify"}:
        state = change.fields.get("state")
        if state is not None and state not in {"pending", "running", "shutting-down", "terminated", "stopping", "stopped"}:
            raise ValueError("state must be one of pending, running, shutting-down, terminated, stopping, stopped")
    _validate_change_fields(change)
    for constraint in capability["constraints"]:
        if constraint["kind"] == "derived_field" and change.op in constraint["operations"]:
            if set(change.fields).intersection(constraint["fields"]):
                raise ValueError(constraint["message"])
    if change.op in {"add", "modify"}:
        validate_catalog_fields(change.resource_type, change.fields)
    if change.op == "delete":
        _validate_delete_fields(change)


def _model_for(resource_type: str) -> Type[BaseModel]:
    model_type = _MUTATION_CAPABILITIES[resource_type]["model"]
    if model_type is None:
        raise ValueError(f"{resource_type} does not have a resource model")
    return model_type


def _collection(infra: AWSInfrastructure, resource_type: str) -> list:
    if resource_type in {"ec2_instance", "security_group", "ebs_volume", "ebs_snapshot"}:
        return {
            "ec2_instance": infra.ec2.instances,
            "security_group": infra.ec2.security_groups,
            "ebs_volume": infra.ec2.ebs_volumes,
            "ebs_snapshot": infra.ec2.ebs_snapshots,
        }[resource_type]
    if resource_type in {"rds_instance", "rds_snapshot"}:
        return infra.rds.rds_instances if resource_type == "rds_instance" else infra.rds.rds_snapshots
    if resource_type == "s3_bucket":
        return infra.s3.buckets
    if resource_type == "network_acl":
        return infra.vpc.nacls
    if resource_type == "iam_role":
        return infra.iam.role_policies
    if resource_type == "iam_user":
        return infra.iam.iam_users
    if resource_type == "nat_gateway":
        return infra.vpc.nat_gateway_details
    if resource_type == "route_table":
        return infra.vpc.route_tables
    return infra.lambda_data.functions


def _identity(resource_type: str, resource: BaseModel) -> str:
    if resource_type in {"s3_bucket", "lambda_function"}:
        return resource.name
    if resource_type == "iam_role":
        return resource.role_arn
    if resource_type == "iam_user":
        return resource.username
    return resource.id


def _field_check(model_type: Type[BaseModel], fields: Dict[str, Any]) -> None:
    unknown = set(fields) - set(model_type.model_fields)
    if unknown:
        allowed = ', '.join(sorted(model_type.model_fields))
        raise ValueError(f"Unknown field(s) for {model_type.__name__}; allowed fields: {allowed}")


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


def _sync_s3_public_buckets(infra: AWSInfrastructure) -> None:
    """Keep the collector's public-bucket summary aligned with bucket models."""
    infra.s3.public_buckets = [bucket.name for bucket in infra.s3.buckets if bucket.is_public]


_S3_PUBLIC_INPUTS = frozenset({"policy", "acl_public", "ignore_public_acls", "restrict_public_buckets", "block_public_policy"})


def _recompute_s3_public(before: S3Bucket | None, bucket: S3Bucket, change: Change) -> None:
    """Recompute is_public from its parts after a change to policy, ACL or BPA.

    Legacy snapshots (acl_public None) only had ACL-derived is_public, so the
    ACL part is taken from the old is_public (fail closed) and kept for later steps.
    """
    if not _S3_PUBLIC_INPUTS.intersection(change.fields):
        return
    try:
        policy_public = policy_is_public(bucket.policy) if bucket.policy else False
    except ValueError as exc:
        raise ValueError(f"s3_bucket.policy: {exc}") from exc
    if "policy" in change.fields and policy_public and bucket.block_public_policy:
        raise ValueError("s3_bucket.policy: BlockPublicPolicy is on for this bucket, so AWS rejects a public bucket policy")
    if bucket.acl_public is None and "acl_public" not in change.fields:
        bucket.acl_public = bool(before.is_public) if before is not None else False
    bucket.policy_public = policy_public
    computed = effective_is_public(bucket.acl_public, policy_public, bucket.ignore_public_acls, bucket.restrict_public_buckets)
    if "is_public" in change.fields and change.fields["is_public"] != computed:
        raise ValueError(f"s3_bucket.is_public: contradicts the policy, ACL and Block Public Access settings (they give {str(computed).lower()})")
    bucket.is_public = computed


def _effective_route_table_associations(infra: AWSInfrastructure) -> dict[str, list[str]]:
    """Resolve explicit subnet associations and main-table inheritance."""
    tables = infra.vpc.route_tables
    result = {
        str(table.id if isinstance(table, RouteTable) else table["id"]): set(
            table.associated_subnet_ids if isinstance(table, RouteTable)
            else table.get("associated_subnet_ids", [])
        )
        for table in tables
    }
    explicitly_associated = set().union(*result.values()) if result else set()
    main_by_vpc: dict[str, list[str]] = {}
    for table in tables:
        get = (lambda key, default=None: getattr(table, key, default)) if isinstance(table, RouteTable) else table.get
        if get("is_main", False):
            main_by_vpc.setdefault(str(get("vpc_id", "")), []).append(str(get("id", "")))
    for subnet in infra.vpc.subnets:
        get = (lambda key, default=None: getattr(subnet, key, default)) if isinstance(subnet, BaseModel) else subnet.get
        subnet_id, vpc_id = str(get("id", "")), str(get("vpc_id", ""))
        main_tables = main_by_vpc.get(vpc_id, [])
        if subnet_id not in explicitly_associated and len(main_tables) == 1:
            result[main_tables[0]].add(subnet_id)
    return {table_id: sorted(subnet_ids) for table_id, subnet_ids in result.items()}


def _sync_route_table_public_subnets(infra: AWSInfrastructure) -> None:
    """Refresh public-subnet summaries after replacing normalized routes."""
    associations = _effective_route_table_associations(infra)
    public_subnets = set()
    for table in infra.vpc.route_tables:
        get = (lambda key, default=None: getattr(table, key, default)) if isinstance(table, RouteTable) else table.get
        routes = get("routes", []) or []
        if any(
            is_internet_cidr(str(route.destination_cidr if isinstance(route, Route) else route.get("destination_cidr", "")))
            and str(route.target_type if isinstance(route, Route) else route.get("target_type", "")).lower() == "internet_gateway"
            for route in routes
        ):
            public_subnets.update(associations.get(str(get("id", "")), []))
    for subnet in infra.vpc.subnets:
        subnet_id = str(subnet.id if isinstance(subnet, BaseModel) else subnet.get("id", ""))
        if isinstance(subnet, BaseModel):
            subnet.is_public = subnet_id in public_subnets
        else:
            subnet["is_public"] = subnet_id in public_subnets
    infra.vpc.public_subnet_ids = sorted(public_subnets)


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


def _delete(
    infra: AWSInfrastructure, resource_type: str, resource_id: str,
    options: dict[str, Any] | None = None, *, implicit: bool = False, via: str | None = None,
) -> None:
    options = options or {}
    collection = _collection(infra, resource_type)
    index = next((i for i, item in enumerate(collection) if _identity(resource_type, item) == resource_id), None)
    if index is None:
        raise TargetNotFound(resource_type, resource_id)
    target = collection[index]
    if resource_type == "network_acl":
        if target.associated_subnet_ids:
            raise ValueError("Network ACL still has associated subnets")
        if target.is_default:
            raise ValueError("Cannot delete the default network ACL")
    if resource_type == "security_group":
        users = sorted({item.id for item in infra.ec2.instances if resource_id in item.sg_ids} | {
            item.id for item in infra.rds.rds_instances if resource_id in item.sg_ids
        } | {item.name for item in infra.lambda_data.functions if resource_id in item.sg_ids} | {
            item.id for item in infra.elasticache.clusters if resource_id in item.sg_ids
        } | {group.id for group in infra.ec2.security_groups if group.id != resource_id and any(
            resource_id in (rule.get("source_sg_ids") or []) or resource_id in (rule.get("dest_sg_ids") or [])
            for rule in group.rules + group.egress_rules
        )})
        if users:
            raise ValueError("Security group is still in use; model detaching or replacing it before deletion")
        if resource_type == "ebs_volume" and target.attached_to is not None and not implicit:
            raise ValueError("ebs_volume.attached_to: volume is in use")
    if resource_type == "rds_instance":
        if target.deletion_protection is True:
            raise ValueError("rds_instance.deletion_protection: deletion is protected")
        identifier = options.get("final_db_snapshot_identifier")
        if identifier and any(snapshot.id == identifier for snapshot in infra.rds.rds_snapshots):
            raise ValueError("rds_instance.final_db_snapshot_identifier: snapshot already exists")
    state_before = target.model_dump()
    collection.pop(index)
    ledger_options = {
        "skip_final_snapshot": options.get("skip_final_snapshot"),
        "delete_automated_backups": options.get("delete_automated_backups", True),
        "final_db_snapshot_identifier": options.get("final_db_snapshot_identifier"),
    }
    infra._deletions.append({"step": len(infra._deletions) + 1, "resource_type": resource_type,
        "resource_id": resource_id, "implicit": implicit, "via": via, "options": ledger_options,
        "state_before": state_before})
    if resource_type == "ec2_instance":
        _remove_one(infra.ec2.instance_types, target.type)
        for subnet in infra.vpc.subnets:
            _remove_value(subnet.resources, resource_id)
        for group in infra.ec2.security_groups:
            _remove_value(group.attached_to, resource_id)
        _remove_value(infra.ec2.stopped_instances, resource_id)
        for device in target.block_devices:
            volume = next((item for item in infra.ec2.ebs_volumes if item.id == device.volume_id), None)
            if volume is None:
                continue
            if device.delete_on_termination is True:
                _delete(infra, "ebs_volume", volume.id, options, implicit=True, via=resource_id)
            else:
                volume.state = "available"
                volume.attached_to = None
        if infra.network_interfaces is not None:
            infra.network_interfaces[:] = [item for item in infra.network_interfaces if item.attached_resource != resource_id]
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
        for values in (infra.rds.publicly_accessible, infra.rds.unencrypted_instances,
                       infra.rds.instances_without_deletion_protection, infra.rds.instances_without_log_exports):
            _remove_value(values, resource_id)
        identifier = options.get("final_db_snapshot_identifier")
        if identifier:
            infra.rds.rds_snapshots.append(RDSSnapshot(id=identifier, db_instance_id=resource_id,
                snapshot_type="manual", status="available"))
        if infra.network_interfaces is not None:
            infra.network_interfaces[:] = [item for item in infra.network_interfaces if item.attached_resource != resource_id]
    elif resource_type == "iam_role":
        pass
    elif resource_type == "s3_bucket":
        for values in (infra.s3.public_buckets, infra.s3.unencrypted_buckets,
                       infra.s3.buckets_without_versioning, infra.s3.buckets_without_logging):
            _remove_value(values, resource_id)
    elif resource_type == "lambda_function":
        for subnet in infra.vpc.subnets:
            _remove_value(subnet.resources, resource_id)
        for values in (infra.lambda_data.functions_with_admin_role, infra.lambda_data.functions_with_outdated_runtime,
                       infra.lambda_data.functions_with_no_timeout):
            _remove_value(values, resource_id)


def _normalized_sg_rule(rule: Any) -> tuple:
    """Return the modeled identity of a security-group rule."""
    if isinstance(rule, BaseModel):
        rule = rule.model_dump()
    rule = rule or {}
    return (
        str(rule.get("protocol", "")),
        rule.get("from_port"),
        rule.get("to_port"),
        tuple(sorted(set(rule.get("ip_ranges") or []))),
        tuple(sorted(set(rule.get("source_sg_ids") or []))),
        tuple(sorted(set(rule.get("dest_sg_ids") or []))),
    )


def _validate_security_group_rules(result: AWSInfrastructure, change: Change) -> None:
    """Permit an unmodeled source-less rule only when replaying one already present."""
    if change.resource_type != "security_group" or change.op not in {"add", "modify"}:
        return
    target = next(
        (group for group in result.ec2.security_groups if group.id == change.resource_id),
        None,
    ) if change.op == "modify" else None
    for field in ("rules", "egress_rules"):
        supplied = change.fields.get(field)
        if not isinstance(supplied, list):
            continue
        existing = (getattr(target, field, []) if target is not None else []) or []
        existing_keys = {_normalized_sg_rule(rule) for rule in existing}
        for index, rule in enumerate(supplied):
            if not isinstance(rule, dict):
                continue
            if rule.get("ip_ranges") or rule.get("source_sg_ids") or rule.get("dest_sg_ids"):
                continue
            if _normalized_sg_rule(rule) not in existing_keys:
                raise ValueError(
                    f"security_group.{field}[{index}]: a new rule needs a source "
                    "(ip_ranges, source_sg_ids or dest_sg_ids) (source is required)"
                )


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
    if set(change.fields) - {"access_statements", "policy_documents"} or ("access_statements" not in change.fields and "policy_documents" not in change.fields):
        raise ValueError("iam_role_policy modify requires only access_statements and/or policy_documents")
    if "policy_documents" in change.fields:
        if not isinstance(change.fields["policy_documents"], list):
            raise ValueError("policy_documents must be a list")
        records = [PolicyDocumentRecord.model_validate(item) for item in change.fields["policy_documents"]]
        derived = merge_policy_statements(records)
        if "access_statements" in change.fields:
            supplied = [AccessStatementChange.model_validate(item) for item in change.fields["access_statements"]]
            if [item.model_dump() for item in supplied] != [item.model_dump() for item in derived]:
                raise ValueError("access_statements must equal merge_policy_statements(policy_documents)")
        statements = derived
    else:
        if not isinstance(change.fields["access_statements"], list):
            raise ValueError("access_statements must be a list")
        statements = [AccessStatementChange.model_validate(item) for item in change.fields["access_statements"]]
        records = None

    matches = [policy for policy in infra.iam.role_policies if policy.role_arn == change.resource_id]
    if not matches:
        raise TargetNotFound("iam_role_policy", change.resource_id)
    if len(matches) != 1:
        raise ValueError("IAM role policy target is ambiguous; role ARN must identify exactly one collected role")

    policy = matches[0]
    policy.access_statements = [
        AccessStatement.model_validate(statement.model_dump() if hasattr(statement, "model_dump") else statement)
        for statement in statements
    ]
    policy.policy_documents = records
    # Do not let stale collector summaries override an empty/replaced statement
    # set in egraph.build_graph's legacy fallback path.
    policy.has_admin = False
    policy.accessible_resources = []
    policy.policy_names = []


def _validated_routes(infra: AWSInfrastructure, table_vpc_id: str, existing: list[Route], routes: Any) -> list[Route]:
    """Normalize a complete route list; new IGW routes need same-VPC attachment evidence."""
    if not isinstance(routes, list):
        raise ValueError("routes must be a list replacing the complete normalized route set")
    normalized = [Route.model_validate(route) for route in routes]
    destinations = [route.destination_cidr for route in normalized]
    if len(destinations) != len(set(destinations)):
        raise ValueError("routes cannot contain duplicate destination_cidr values")
    existing_igw_routes = {
        (route.destination_cidr, route.target_id)
        for route in existing
        if route.target_type.lower() == "internet_gateway"
    }
    for route in normalized:
        if route.target_type.lower() != "internet_gateway":
            continue
        preexisting = (route.destination_cidr, route.target_id) in existing_igw_routes
        if not infra.vpc.internet_gateway_attachments_complete:
            if preexisting:
                # Preserve legacy routes when attachment enumeration was not
                # available; absence of mapping is not same-VPC evidence.
                continue
            raise ValueError(
                "Cannot add an internet_gateway route without complete IGW attachment evidence; "
                "recollect the VPC snapshot"
            )
        same_vpc_attachment = any(
            attachment.internet_gateway_id == route.target_id
            and bool(table_vpc_id)
            and attachment.vpc_id == table_vpc_id
            and attachment.state == "available"
            for attachment in infra.vpc.internet_gateway_attachments
        )
        if not same_vpc_attachment:
            raise ValueError(
                "Internet gateway target is not attached to the route table VPC; "
                "verify the route table and gateway belong to the same VPC"
            )
    return normalized


def _replace_route_table_routes(infra: AWSInfrastructure, change: Change) -> None:
    """Replace only the normalized routes on one collected route table."""
    required_fields = {"routes"}
    if set(change.fields) != required_fields:
        raise ValueError("route_table modify requires only routes as the complete replacement list")
    if not isinstance(change.fields["routes"], list):
        raise ValueError("routes must be a list replacing the complete normalized route set")
    matches = [table for table in infra.vpc.route_tables if table.id == change.resource_id]
    if not matches:
        raise TargetNotFound("route_table", change.resource_id)
    if len(matches) != 1:
        raise ValueError("Route table target is ambiguous; ID must identify exactly one collected route table")
    matches[0].routes = _validated_routes(infra, matches[0].vpc_id, matches[0].routes, change.fields["routes"])
    _sync_route_table_public_subnets(infra)


def _add_route_table(infra: AWSInfrastructure, change: Change) -> AWSInfrastructure:
    """Add a non-main route table: the VPC's local routes, given routes, explicit associations."""
    unknown = set(change.fields) - {"vpc_id", "routes", "associated_subnet_ids", "tags"}
    if unknown:
        raise ValueError("route_table add fields: vpc_id, routes, associated_subnet_ids and tags only")
    vpc_id = change.fields.get("vpc_id")
    if not isinstance(vpc_id, str) or not vpc_id:
        raise ValueError("route_table.vpc_id: required (CreateRouteTable needs the VPC)")
    siblings = [table for table in infra.vpc.route_tables if table.vpc_id == vpc_id]
    if not siblings:
        raise TargetNotFound("vpc", vpc_id)
    # Every table in a VPC has the same local routes (one per VPC CIDR block).
    local = {route.destination_cidr: route for table in siblings for route in table.routes if route.target_type == "local"}
    routes = _validated_routes(infra, vpc_id, [], change.fields.get("routes", []))
    for route in routes:
        if route.target_type == "local" and route.destination_cidr not in local:
            raise ValueError(f"route_table.routes: {route.destination_cidr} is not a local route of {vpc_id}")
        if route.target_type != "local" and route.destination_cidr in local:
            raise ValueError(f"route_table.routes: {route.destination_cidr} is the VPC local route and cannot point elsewhere")
    given = {route.destination_cidr for route in routes}
    routes = [local[cidr] for cidr in sorted(local) if cidr not in given] + routes
    subnet_ids = change.fields.get("associated_subnet_ids", [])
    if not isinstance(subnet_ids, list) or not all(isinstance(item, str) for item in subnet_ids) or len(subnet_ids) != len(set(subnet_ids)):
        raise ValueError("route_table.associated_subnet_ids: expected a list of distinct subnet ids")
    subnet_vpcs = {
        str(item.get("id") if isinstance(item, dict) else item.id): str(item.get("vpc_id") if isinstance(item, dict) else item.vpc_id)
        for item in infra.vpc.subnets
    }
    for subnet_id in subnet_ids:
        if subnet_id not in subnet_vpcs:
            raise TargetNotFound("subnet", subnet_id)
        if subnet_vpcs[subnet_id] != vpc_id:
            raise ValueError(f"route_table.associated_subnet_ids: {subnet_id} is not in {vpc_id}")
    identity = change.resource_id or _auto_id(infra, change)
    if any(table.id == identity for table in infra.vpc.route_tables):
        raise ValueError("Target already exists: route_table")
    # A subnet has one explicit association; associating it here moves it.
    for table in infra.vpc.route_tables:
        table.associated_subnet_ids = [item for item in table.associated_subnet_ids if item not in subnet_ids]
    infra.vpc.route_tables.append(RouteTable(
        id=identity, vpc_id=vpc_id, is_main=False,
        associated_subnet_ids=list(subnet_ids), routes=routes, tags=change.fields.get("tags"),
    ))
    _sync_route_table_public_subnets(infra)
    return recompute_derived_state(infra)


def _replace_network_acl(infra: AWSInfrastructure, change: Change) -> None:
    matches = [acl for acl in infra.vpc.nacls if acl.id == change.resource_id]
    if not matches:
        raise TargetNotFound("network_acl", change.resource_id)
    if set(change.fields) - {"entries", "associated_subnet_ids"}:
        raise ValueError("network_acl modify allows only entries and associated_subnet_ids")
    acl = matches[0]
    if "entries" in change.fields:
        entries = [NACLEntry.model_validate(item) for item in change.fields["entries"]]
        keys = [(entry.egress, entry.rule_number) for entry in entries]
        if len(keys) != len(set(keys)):
            raise ValueError("Network ACL rule_number must be unique per egress direction")
        acl.entries = entries
    if "associated_subnet_ids" in change.fields:
        requested = list(dict.fromkeys(change.fields["associated_subnet_ids"]))
        for subnet_id in requested:
            for other in infra.vpc.nacls:
                if other.id == acl.id:
                    continue
                if subnet_id in other.associated_subnet_ids:
                    other.associated_subnet_ids.remove(subnet_id)
                    other.association_ids = {k: v for k, v in other.association_ids.items() if v != subnet_id}
        acl.associated_subnet_ids = requested
        acl.association_ids = {k: v for k, v in acl.association_ids.items() if v in requested}


def _default_network_acl_entries() -> list[NACLEntry]:
    result = []
    for egress in (False, True):
        result.extend([
            NACLEntry(rule_number=32767, protocol="-1", rule_action="deny", egress=egress, cidr_block="0.0.0.0/0"),
            NACLEntry(rule_number=32767, protocol="-1", rule_action="deny", egress=egress, ipv6_cidr_block="::/0"),
        ])
    return result


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

    for group in sorted(infra.ec2.security_groups, key=lambda item: item.id):
        if group.id not in attached_sg_ids:
            continue
        for rule in group.rules:
            if rule_opens_port_to_internet(rule, 22):
                ssh_matches.append(group.id)
            if rule_opens_port_to_internet(rule, 3389):
                rdp_matches.append(group.id)

    infra.ec2.ssh_open_to_internet = bool(ssh_matches)
    infra.ec2.ssh_security_group_id = ssh_matches[0] if ssh_matches else None
    infra.ec2.rdp_open_to_internet = bool(rdp_matches)
    infra.ec2.rdp_security_group_id = rdp_matches[0] if rdp_matches else None
    return infra


def _add_nat_gateway(result: AWSInfrastructure, change: Change) -> AWSInfrastructure:
    """Add a NAT gateway; AWS defaults connectivity to public, unknown placement stays unset."""
    subnet_id = change.fields.get("subnet_id")
    vpc_id = None
    if subnet_id is not None:
        subnet = next((
            item for item in result.vpc.subnets
            if (item.get("id") if isinstance(item, dict) else item.id) == subnet_id
        ), None)
        if subnet is None:
            raise TargetNotFound("subnet", str(subnet_id))
        vpc_id = subnet.get("vpc_id") if isinstance(subnet, dict) else subnet.vpc_id
    identity = change.resource_id or _auto_id(result, change)
    if identity in result.vpc.nat_gateways or any(item.id == identity for item in result.vpc.nat_gateway_details):
        raise ValueError("Target already exists: nat_gateway")
    result.vpc.nat_gateway_details.append(NATGateway(
        id=identity,
        subnet_id=subnet_id,
        vpc_id=vpc_id,
        connectivity_type=change.fields.get("connectivity_type", "public"),
        allocation_id=change.fields.get("allocation_id"),
        state="available",
        tags=change.fields.get("tags"),
    ))
    result.vpc.nat_gateways.append(identity)
    return result


def _add_ebs_volume(result: AWSInfrastructure, change: Change) -> AWSInfrastructure:
    """Add an unattached volume; AWS defaults the type to gp2, an unknown AZ stays unset."""
    zone = change.fields.get("availability_zone")
    if zone is not None and result.region and not re.fullmatch(re.escape(result.region) + r"[a-z]", zone):
        raise ValueError(f"ebs_volume.availability_zone: {zone} is not an availability zone in {result.region}")
    identity = change.resource_id or _auto_id(result, change)
    if any(item.id == identity for item in result.ec2.ebs_volumes):
        raise ValueError("Target already exists: ebs_volume")
    result.ec2.ebs_volumes.append(EBSVolume(
        id=identity,
        size_gb=change.fields["size_gb"],
        volume_type=change.fields.get("volume_type", "gp2"),
        availability_zone=zone,
        state="available",
        tags=change.fields.get("tags"),
    ))
    return result


def apply_change(infra: AWSInfrastructure, change: Change) -> AWSInfrastructure:
    """Apply one change without mutating ``infra``."""
    _validate_change(change)
    result = _fresh(infra)
    resource_type = change.resource_type
    if resource_type in TAGGED_TYPES and change.op == "add" and change.fields.get("tags") is None:
        # AWS creates a resource with no tags unless they are given.
        change = change.model_copy(update={"fields": {**change.fields, "tags": {}}})
    if resource_type in TAGGED_TYPES and change.op in {"add", "modify"} and "tags" in change.fields:
        current = next((item for item in _collection(result, resource_type)
                        if _identity(resource_type, item) == change.resource_id), None) if change.op == "modify" else None
        tags = apply_tag_replacement(current.tags if current is not None else None, change.fields["tags"])
        change = change.model_copy(update={"fields": {**change.fields, "tags": tags}})
    _validate_security_group_rules(result, change)
    if resource_type == "ec2_instance" and change.op in {"add", "modify"}:
        sg_ids = change.fields.get("sg_ids", [])
        if sg_ids and result.ec2.security_groups:
            known_sg_ids = {group.id for group in result.ec2.security_groups}
            missing = next((sg_id for sg_id in sg_ids if sg_id not in known_sg_ids), None)
            if missing is not None:
                raise TargetNotFound("security_group", str(missing))
        subnet_id = change.fields.get("subnet_id")
        if subnet_id and result.vpc.subnets:
            known_subnet_ids = {
                str(subnet.get("id", "")) if isinstance(subnet, dict) else str(subnet.id)
                for subnet in result.vpc.subnets
            }
            if subnet_id not in known_subnet_ids:
                raise TargetNotFound("subnet", str(subnet_id))
    if resource_type == "rds_snapshot" and change.op == "add":
        db_instance_id = change.fields.get("db_instance_id")
        if db_instance_id is not None and not any(item.id == db_instance_id for item in result.rds.rds_instances):
            raise TargetNotFound("rds_instance", str(db_instance_id))
        if change.resource_id and any(item.id == change.resource_id for item in result.rds.rds_snapshots):
            raise ValueError("Target already exists: rds_snapshot")
    if resource_type == 'iam_role' and change.op in {'add', 'modify'}:
        from app.aws_collector import _parse_role_trust_policy
        from app.trust_policy import external_trust
        target_id = _role_arn(result, change.resource_id) if change.op == 'add' else change.resource_id
        if change.op == 'modify':
            target = next((p for p in result.iam.role_policies if p.role_arn == target_id or p.role_name == target_id), None)
            if target is None: raise TargetNotFound('iam_role', change.resource_id)
            target_id = target.role_arn
            document = _trust_document(change.fields['trust_policy'])
            target.trusted_role_arns, target.trusted_services, target.trust_allows_external, target.trust_has_conditions = _parse_role_trust_policy(document, target_id)
            target.trust_external_unrestricted = external_trust(document, target_id)[1]
            return result
        if any(p.role_arn == target_id for p in result.iam.role_policies): raise ValueError('Target already exists: iam_role')
        document = _trust_document(change.fields['trust_policy']) if 'trust_policy' in change.fields else None
        trusted_roles, services, allows, conditions = _parse_role_trust_policy(document or {}, target_id)
        name = target_id.split(':role/', 1)[-1].rsplit('/', 1)[-1]
        result.iam.role_policies.append(RolePolicy(role_name=name, role_arn=target_id, trusted_role_arns=trusted_roles, trusted_services=services, trust_allows_external=allows, trust_has_conditions=conditions, trust_external_unrestricted=external_trust(document or {}, target_id)[1] if document else False))
        return result
    if resource_type == 'iam_user' and change.op == 'add':
        username = change.resource_id
        if not username: raise ValueError('iam_user resource_id must not be empty')
        if any(u.username == username for u in result.iam.iam_users): raise ValueError('Target already exists: iam_user')
        console = change.fields.get('has_console_access', False)
        result.iam.iam_users.append(IAMUser(username=username, has_console_access=console))
        if console: _append_unique(result.iam.users_without_mfa, username)
        return result
    if resource_type == "nat_gateway" and change.op == "add":
        return _add_nat_gateway(result, change)
    if resource_type == "ebs_volume" and change.op == "add":
        return _add_ebs_volume(result, change)
    if resource_type == "route_table" and change.op == "add":
        return _add_route_table(result, change)
    if resource_type == "iam_role_policy":
        _replace_iam_role_policy_statements(result, change)
        return result
    if resource_type == "route_table":
        _replace_route_table_routes(result, change)
        return recompute_derived_state(result)
    if change.op == "delete":
        _delete(result, resource_type, change.resource_id, change.fields)
        _sync_counts(result)
        return recompute_derived_state(result)
    if resource_type == "network_acl":
        if change.op == "add":
            if "association_ids" in change.fields:
                raise ValueError("association_ids is collector-derived and cannot be supplied")
            entries = change.fields.get("entries", [])
            keys = [(item.get("egress"), item.get("rule_number")) for item in entries]
            if len(keys) != len(set(keys)):
                raise ValueError("Network ACL rule_number must be unique per egress direction")
        elif change.op == "modify":
            _replace_network_acl(result, change)
            return recompute_derived_state(result)
        if change.op == "add" and "entries" not in change.fields:
            change = change.model_copy(update={"fields": {**change.fields, "entries": [entry.model_dump() for entry in _default_network_acl_entries()]}})
        if change.op == "delete":
            _delete(result, resource_type, change.resource_id, change.fields)
            _sync_counts(result)
            return recompute_derived_state(result)

    model_type = _model_for(resource_type)

    if change.op == "add":
        if resource_type == "rds_snapshot":
            data = dict(change.fields)
            data.update({"snapshot_type": "manual", "status": "available"})
            identity = change.resource_id or _auto_id(result, change)
            data["id"] = identity
            resource = model_type.model_validate(data)
        else:
            data = _resource_data(result, change)
            resource = model_type.model_validate(data)
        if any(_identity(resource_type, item) == _identity(resource_type, resource) for item in _collection(result, resource_type)):
            raise ValueError(f"Target already exists: {resource_type}")
        if resource_type == "s3_bucket":
            _recompute_s3_public(None, resource, change)
        _collection(result, resource_type).append(resource)
        if resource_type == "network_acl":
            for subnet_id in resource.associated_subnet_ids:
                for other in result.vpc.nacls:
                    if other.id != resource.id and subnet_id in other.associated_subnet_ids:
                        other.associated_subnet_ids.remove(subnet_id)
                        other.association_ids = {k: v for k, v in other.association_ids.items() if v != subnet_id}
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
            raise TargetNotFound(resource_type, change.resource_id)
        if not change.fields:
            raise ValueError("modify needs at least one field")
        target = collection[index]
        updated_data = target.model_dump()
        updated_data.update(change.fields)
        collection[index] = model_type.model_validate(updated_data)
        if resource_type == "s3_bucket":
            _recompute_s3_public(target, collection[index], change)
    else:
        _delete(result, resource_type, change.resource_id)

    _sync_counts(result)
    if resource_type == "s3_bucket":
        _sync_s3_public_buckets(result)
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
