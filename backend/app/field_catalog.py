"""Branch field catalog: every settable field traced to AWS's own API model.

Field types, enums, patterns and length/range limits come from the botocore
service models that ship with the SDK (AWS's published API definitions), not
from a hand-written table. What is hand-defined here is only the meaning:
which AWS API member a branch field corresponds to.

Each field of a branch-mutable resource is exactly one of:
- Aws: the value is an AWS API member; botocore constraints are enforced.
- Normalized: Emfirge's normalized view of one or more AWS calls (rule lists,
  tags, public-access parts, ...); validated by its own handler, with the AWS
  calls named so the meaning is traceable.
- Derived: computed by Emfirge or AWS; a change may not set it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional, Union

import botocore
import botocore.session


@dataclass(frozen=True)
class Aws:
    service: str
    operation: str
    member: str  # dotted path into the operation input; list members are stepped through
    shape: Optional[str] = None  # a named shape instead of an operation member


@dataclass(frozen=True)
class Normalized:
    aws_calls: str
    note: str = ""


@dataclass(frozen=True)
class Derived:
    reason: str


Source = Union[Aws, Normalized, Derived]

_TAGS = Normalized("CreateTags / PutBucketTagging / TagResource",
                   "complete user tag set; AWS tag limits and the aws: prefix are enforced in app.tags")

CATALOG: dict[str, dict[str, Source]] = {
    "ec2_instance": {
        "type": Aws("ec2", "RunInstances", "InstanceType"),
        "subnet_id": Aws("ec2", "RunInstances", "SubnetId"),
        "sg_ids": Aws("ec2", "RunInstances", "SecurityGroupIds"),
        "state": Aws("ec2", "", "", shape="InstanceStateName"),
        "imdsv2_required": Normalized("RunInstances / ModifyInstanceMetadataOptions MetadataOptions.HttpTokens", "true when HttpTokens is required"),
        "user_data_has_secrets": Normalized("RunInstances UserData", "true when the user data holds a literal secret; the user data itself is never stored"),
        "has_public_ip": Normalized("RunInstances NetworkInterfaces[].AssociatePublicIpAddress"),
        "instance_profile_arn": Aws("ec2", "RunInstances", "IamInstanceProfile.Arn"),
        "detailed_monitoring": Aws("ec2", "RunInstances", "Monitoring.Enabled"),
        "block_devices": Normalized("RunInstances BlockDeviceMappings / AttachVolume"),
        "tags": _TAGS,
    },
    "security_group": {
        "name": Aws("ec2", "CreateSecurityGroup", "GroupName"),
        "rules": Normalized("AuthorizeSecurityGroupIngress / RevokeSecurityGroupIngress", "complete normalized ingress rule list"),
        "egress_rules": Normalized("AuthorizeSecurityGroupEgress / RevokeSecurityGroupEgress", "complete normalized egress rule list"),
        "attached_to": Derived("derived from EC2 instance sg_ids"),
        "tags": _TAGS,
    },
    "rds_instance": {
        "sg_ids": Aws("rds", "CreateDBInstance", "VpcSecurityGroupIds"),
        "subnet_id": Normalized("CreateDBInstance DBSubnetGroupName", "the subnet the instance runs in"),
        "publicly_accessible": Aws("rds", "CreateDBInstance", "PubliclyAccessible"),
        "encrypted": Aws("rds", "CreateDBInstance", "StorageEncrypted"),
        "engine": Aws("rds", "CreateDBInstance", "Engine"),
        "port": Aws("rds", "CreateDBInstance", "Port"),
        "backup_retention_days": Aws("rds", "CreateDBInstance", "BackupRetentionPeriod"),
        "deletion_protection": Aws("rds", "CreateDBInstance", "DeletionProtection"),
        "multi_az": Aws("rds", "CreateDBInstance", "MultiAZ"),
        "log_exports": Aws("rds", "CreateDBInstance", "EnableCloudwatchLogsExports"),
        "iam_auth_enabled": Aws("rds", "CreateDBInstance", "EnableIAMDatabaseAuthentication"),
        "monitoring_interval": Aws("rds", "CreateDBInstance", "MonitoringInterval"),
        "auto_minor_version_upgrade": Aws("rds", "CreateDBInstance", "AutoMinorVersionUpgrade"),
        "tags": _TAGS,
    },
    "s3_bucket": {
        "is_public": Normalized("PutBucketAcl / PutBucketPolicy / PutPublicAccessBlock", "computed from its parts when they change (app.s3_public)"),
        "has_cloudfront": Normalized("CloudFront CreateDistribution origin", "a distribution serves from this bucket"),
        "policy": Aws("s3", "PutBucketPolicy", "Policy"),
        "is_empty": Normalized("PutObject / DeleteObject", "no objects"),
        "encrypted": Normalized("PutBucketEncryption"),
        "versioning_enabled": Normalized("PutBucketVersioning VersioningConfiguration.Status"),
        "acl_public": Normalized("PutBucketAcl", "grants to AllUsers or AuthenticatedUsers"),
        "policy_public": Derived("derived from policy (app.s3_public)"),
        "block_public_acls": Aws("s3", "PutPublicAccessBlock", "PublicAccessBlockConfiguration.BlockPublicAcls"),
        "ignore_public_acls": Aws("s3", "PutPublicAccessBlock", "PublicAccessBlockConfiguration.IgnorePublicAcls"),
        "block_public_policy": Aws("s3", "PutPublicAccessBlock", "PublicAccessBlockConfiguration.BlockPublicPolicy"),
        "restrict_public_buckets": Aws("s3", "PutPublicAccessBlock", "PublicAccessBlockConfiguration.RestrictPublicBuckets"),
        "logging_enabled": Normalized("PutBucketLogging", "true when server access logging is configured"),
        "tags": _TAGS,
    },
    "lambda_function": {
        "role_arn": Aws("lambda", "CreateFunction", "Role"),
        "vpc_id": Normalized("CreateFunction VpcConfig", "the VPC of the configured subnets"),
        "subnet_ids": Aws("lambda", "CreateFunction", "VpcConfig.SubnetIds"),
        "sg_ids": Aws("lambda", "CreateFunction", "VpcConfig.SecurityGroupIds"),
        "secret_refs": Normalized("CreateFunction Environment.Variables", "secret-looking variables and Secrets Manager ARNs"),
        "tags": _TAGS,
    },
    "ebs_volume": {
        "availability_zone": Aws("ec2", "CreateVolume", "AvailabilityZone"),
        "size_gb": Aws("ec2", "CreateVolume", "Size"),
        "volume_type": Aws("ec2", "CreateVolume", "VolumeType"),
        "create_time": Derived("set by AWS"),
        "state": Derived("set by AWS"),
        "attached_to": Derived("set by AttachVolume, not modeled"),
        "tags": _TAGS,
    },
    "nat_gateway": {
        "subnet_id": Aws("ec2", "CreateNatGateway", "SubnetId"),
        "connectivity_type": Aws("ec2", "CreateNatGateway", "ConnectivityType"),
        "allocation_id": Aws("ec2", "CreateNatGateway", "AllocationId"),
        "vpc_id": Derived("the subnet's VPC"),
        "state": Derived("set by AWS"),
        "tags": _TAGS,
    },
    "route_table": {
        "vpc_id": Aws("ec2", "CreateRouteTable", "VpcId"),
        "routes": Normalized("CreateRoute / ReplaceRoute / DeleteRoute", "complete normalized route list"),
        "associated_subnet_ids": Normalized("AssociateRouteTable SubnetId", "explicit subnet associations"),
        "is_main": Derived("set by AWS for the VPC's main table"),
        "tags": _TAGS,
    },
    "network_acl": {
        "vpc_id": Aws("ec2", "CreateNetworkAcl", "VpcId"),
        "is_default": Derived("set by AWS for the VPC's default ACL"),
        "associated_subnet_ids": Normalized("ReplaceNetworkAclAssociation", "subnet associations"),
        "association_ids": Derived("set by AWS"),
        "entries": Normalized("CreateNetworkAclEntry / ReplaceNetworkAclEntry / DeleteNetworkAclEntry", "complete normalized entry list"),
    },
    "rds_snapshot": {
        "db_instance_id": Aws("rds", "CreateDBSnapshot", "DBInstanceIdentifier"),
        "snapshot_type": Derived("manual for a branch-created snapshot"),
        "status": Derived("set by AWS"),
    },
    "iam_role": {
        "trust_policy": Aws("iam", "CreateRole", "AssumeRolePolicyDocument"),
    },
    "iam_user": {
        "has_console_access": Normalized("CreateLoginProfile / DeleteLoginProfile"),
        "access_statements": Normalized("PutUserPolicy / AttachUserPolicy", "complete normalized statement list"),
        "policy_documents": Normalized("PutUserPolicy / AttachUserPolicy", "normalized policy documents"),
        "has_access_keys": Normalized("CreateAccessKey / DeleteAccessKey", "true when the user has programmatic credentials"),
    },
    "iam_instance_profile": {
        "role_arn": Normalized("CreateInstanceProfile / AddRoleToInstanceProfile", "the one role the profile carries; the profile ARN is the change's resource_id"),
    },
    "iam_role_policy": {
        "access_statements": Normalized("PutRolePolicy / AttachRolePolicy", "complete normalized statement list"),
        "policy_documents": Normalized("PutRolePolicy / AttachRolePolicy", "normalized policy documents"),
    },
}

# Identity fields are the change's resource_id, never a field.
IDENTITY_FIELDS = {"s3_bucket": "name", "lambda_function": "name", "iam_user": "username"}


@lru_cache(maxsize=None)
def _service(name: str):
    return botocore.session.get_session().get_service_model(name)


@lru_cache(maxsize=None)
def resolve(source: Aws):
    """The botocore shape behind an Aws source (KeyError if AWS's model lacks it)."""
    model = _service(source.service)
    if source.shape:
        return model.shape_for(source.shape)
    shape = model.operation_model(source.operation).input_shape
    for part in source.member.split("."):
        while shape.type_name == "list":
            shape = shape.member
        shape = shape.members[part]
    return shape


def _describe(source: Aws) -> str:
    if source.shape:
        return f"{source.service} shape {source.shape}"
    return f"{source.service} {source.operation} {source.member}"


def _check(path: str, source: Aws, shape, value: Any) -> None:
    kind = shape.type_name
    if value is None:
        return  # optional fields may be cleared; required-ness is the handlers' job
    if kind == "list":
        if not isinstance(value, list):
            raise ValueError(f"{path}: expected a list ({_describe(source)})")
        for index, item in enumerate(value):
            _check(f"{path}[{index}]", source, shape.member, item)
        return
    if kind == "string":
        if isinstance(value, (dict, list)) and source.member.endswith("PolicyDocument"):
            value = json.dumps(value)
        if not isinstance(value, str):
            raise ValueError(f"{path}: expected a string ({_describe(source)})")
        enum = shape.enum
        if enum and value not in enum:
            raise ValueError(f"{path}: '{value}' is not a value AWS accepts for {_describe(source)}")
        meta = shape.metadata
        if "min" in meta and len(value) < meta["min"] or "max" in meta and len(value) > meta["max"]:
            raise ValueError(f"{path}: length must be {meta.get('min', 0)} to {meta.get('max', 'any')} ({_describe(source)})")
        if "pattern" in meta and not re.fullmatch(meta["pattern"], value):
            raise ValueError(f"{path}: does not match the AWS pattern for {_describe(source)}")
        return
    if kind in {"integer", "long"}:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{path}: expected an integer ({_describe(source)})")
        meta = shape.metadata
        if "min" in meta and value < meta["min"] or "max" in meta and value > meta["max"]:
            raise ValueError(f"{path}: must be {meta.get('min', '-')} to {meta.get('max', '-')} ({_describe(source)})")
        return
    if kind == "boolean" and not isinstance(value, bool):
        raise ValueError(f"{path}: expected a boolean ({_describe(source)})")


def validate_fields(resource_type: str, fields: dict[str, Any]) -> None:
    """Reject derived fields and values AWS's own API model would reject."""
    catalog = CATALOG.get(resource_type)
    if catalog is None:
        return
    for field, value in fields.items():
        source = catalog.get(field)
        if isinstance(source, Derived):
            raise ValueError(f"{resource_type}.{field} is derived ({source.reason}) and cannot be set")
        if isinstance(source, Aws):
            _check(f"{resource_type}.{field}", source, resolve(source), value)


def catalog_document() -> dict[str, Any]:
    """The catalog as served to agents, with AWS's constraints filled in."""
    resources = {}
    for resource_type, fields in sorted(CATALOG.items()):
        entries = {}
        for field, source in sorted(fields.items()):
            if isinstance(source, Aws):
                shape = resolve(source)
                leaf = shape.member if shape.type_name == "list" else shape
                entry = {"kind": "aws", "aws": _describe(source), "type": shape.type_name}
                if getattr(leaf, "enum", None):
                    entry["enum"] = list(leaf.enum)
                for key in ("min", "max", "pattern"):
                    if key in leaf.metadata:
                        entry[key] = leaf.metadata[key]
            elif isinstance(source, Normalized):
                entry = {"kind": "normalized", "aws": source.aws_calls}
                if source.note:
                    entry["note"] = source.note
            else:
                entry = {"kind": "derived", "reason": source.reason}
            entries[field] = entry
        resources[resource_type] = entries
    return {"source": "botocore service models", "botocore_version": botocore.__version__, "resources": resources}
