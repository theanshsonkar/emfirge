"""Pure infrastructure mutation helpers for remediation simulations."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, Iterable, Literal, Type, get_args
from ipaddress import ip_network

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator

from app.models import (
    AccessStatement,
    AWSInfrastructure,
    EC2Instance,
    LambdaFunction,
    RDSInstance,
    Route,
    RouteTable,
    S3Bucket,
    SecurityGroup,
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


_MUTATION_NESTED_TYPES = {
    ("security_group", "rules"): list[SecurityGroupRuleChange],
    ("security_group", "egress_rules"): list[SecurityGroupRuleChange],
    ("iam_role_policy", "access_statements"): list[AccessStatementChange],
    ("route_table", "routes"): list[RouteChange],
}


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
    "route_table": {
        "model": RouteTable,
        "operations": frozenset({"modify"}),
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


class Change(BaseModel):
    op: str
    resource_type: str
    resource_id: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)
    expected_change_count: int | None = Field(default=None, ge=0)
    branch_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


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
    _validate_change_fields(change)
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


def _sync_s3_public_buckets(infra: AWSInfrastructure) -> None:
    """Keep the collector's public-bucket summary aligned with bucket models."""
    infra.s3.public_buckets = [bucket.name for bucket in infra.s3.buckets if bucket.is_public]


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
            str(route.destination_cidr if isinstance(route, Route) else route.get("destination_cidr", "")) == "0.0.0.0/0"
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


def _delete(infra: AWSInfrastructure, resource_type: str, resource_id: str) -> None:
    collection = _collection(infra, resource_type)
    index = next((i for i, item in enumerate(collection) if _identity(resource_type, item) == resource_id), None)
    if index is None:
        raise ValueError(f"Target not found: {resource_type}")
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
                "Security group is still in use; model detaching or replacing it before deletion"
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
        raise ValueError("Target not found: iam_role_policy")
    if len(matches) != 1:
        raise ValueError("IAM role policy target is ambiguous; role ARN must identify exactly one collected role")

    policy = matches[0]
    policy.access_statements = [
        AccessStatement.model_validate(AccessStatementChange.model_validate(statement).model_dump())
        for statement in statements
    ]
    # Do not let stale collector summaries override an empty/replaced statement
    # set in egraph.build_graph's legacy fallback path.
    policy.has_admin = False
    policy.accessible_resources = []
    policy.policy_names = []


def _replace_route_table_routes(infra: AWSInfrastructure, change: Change) -> None:
    """Replace only the normalized routes on one collected route table."""
    required_fields = {"routes"}
    if set(change.fields) != required_fields:
        raise ValueError("route_table modify requires only routes as the complete replacement list")
    routes = change.fields["routes"]
    if not isinstance(routes, list):
        raise ValueError("routes must be a list replacing the complete normalized route set")
    matches = [table for table in infra.vpc.route_tables if table.id == change.resource_id]
    if not matches:
        raise ValueError("Target not found: route_table")
    if len(matches) != 1:
        raise ValueError("Route table target is ambiguous; ID must identify exactly one collected route table")
    normalized = [Route.model_validate(route) for route in routes]
    destinations = [route.destination_cidr for route in normalized]
    if len(destinations) != len(set(destinations)):
        raise ValueError("routes cannot contain duplicate destination_cidr values")
    existing_igw_routes = {
        (route.destination_cidr, route.target_id)
        for route in matches[0].routes
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
            and bool(matches[0].vpc_id)
            and attachment.vpc_id == matches[0].vpc_id
            and attachment.state == "available"
            for attachment in infra.vpc.internet_gateway_attachments
        )
        if not same_vpc_attachment:
            raise ValueError(
                "Internet gateway target is not attached to the route table VPC; "
                "verify the route table and gateway belong to the same VPC"
            )
    matches[0].routes = normalized
    _sync_route_table_public_subnets(infra)


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
    if resource_type == "route_table":
        _replace_route_table_routes(result, change)
        return recompute_derived_state(result)

    model_type = _model_for(resource_type)

    if change.op == "add":
        data = _resource_data(result, change)
        resource = model_type.model_validate(data)
        if any(_identity(resource_type, item) == _identity(resource_type, resource) for item in _collection(result, resource_type)):
            raise ValueError(f"Target already exists: {resource_type}")
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
            raise ValueError(f"Target not found: {resource_type}")
        target = collection[index]
        updated_data = target.model_dump()
        updated_data.update(change.fields)
        collection[index] = model_type.model_validate(updated_data)
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
