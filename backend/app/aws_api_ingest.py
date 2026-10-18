from __future__ import annotations

from typing import Any, Callable

from app.mutations import Change
from app.aws_collector import build_security_group_rule
import copy
import re


_DELETE_PREFIXES = ("Delete", "Terminate", "Purge", "Deregister", "Release", "Remove")
_RISKY_PREFIXES = ("Detach", "Disassociate", "Revoke", "Stop", "Disable")
_RISKY_PUT = re.compile(r"^Put[A-Za-z0-9]*(Policy|Acl)$")
_READ_ONLY_PREFIXES = ("Describe", "List", "Get", "Head")
_INVALID_MESSAGE = "Invalid AWS API calls document"
_GLOBAL_SERVICES = frozenset({"iam", "route53", "cloudfront", "s3"})


def validate_change_regions(
    calls: list[dict[str, Any]], snapshot_region: str,
    document_region: str | None = None,
) -> None:
    """Reject regional changes that cannot be judged against this snapshot."""
    if document_region is not None and not isinstance(document_region, str):
        raise _invalid()
    for call in calls:
        service = str(call.get("service", "")).lower()
        explicit = call.get("region", document_region)
        if explicit is None or service in _GLOBAL_SERVICES:
            continue
        if not isinstance(explicit, str):
            raise _invalid()
        if explicit != snapshot_region:
            raise ValueError(
                f"region_mismatch: change region '{explicit}' does not match "
                f"snapshot region '{snapshot_region}'"
            )

# service, operation -> (resource type, identifier parameter, allowed parameters)
_MAPPED = {
    ("ec2", "TerminateInstances"): ("ec2_instance", "InstanceIds", {"InstanceIds", "DryRun"}),
    ("ec2", "DeleteVolume"): ("ebs_volume", "VolumeId", {"VolumeId", "DryRun"}),
    ("ec2", "DeleteSnapshot"): ("ebs_snapshot", "SnapshotId", {"SnapshotId", "DryRun"}),
    ("ec2", "DeleteSecurityGroup"): ("security_group", "GroupId", {"GroupId", "GroupName", "DryRun"}),
    ("rds", "DeleteDBInstance"): ("rds_instance", "DBInstanceIdentifier", {
        "DBInstanceIdentifier", "SkipFinalSnapshot", "DeleteAutomatedBackups",
        "FinalDBSnapshotIdentifier", "DryRun",
    }),
    ("rds", "DeleteDBSnapshot"): ("rds_snapshot", "DBSnapshotIdentifier", {"DBSnapshotIdentifier", "DryRun"}),
    ("s3", "DeleteBucket"): ("s3_bucket", "Bucket", {"Bucket", "DryRun"}),
    ("lambda", "DeleteFunction"): ("lambda_function", "FunctionName", {"FunctionName", "Qualifier", "DryRun"}),
    ("iam", "DeleteRole"): ("iam_role", "RoleName", {"RoleName", "DryRun"}),
}


def _invalid() -> ValueError:
    return ValueError(_INVALID_MESSAGE)


def _valid_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _validate_identifier(operation: str, parameters: dict[str, Any], identifier: str) -> None:
    value = parameters.get(identifier)
    if operation == "TerminateInstances":
        if not isinstance(value, list) or not value or not all(_valid_string(item) for item in value):
            raise _invalid()
    elif not _valid_string(value):
        raise _invalid()


_UNSEEN_EC2_OPERATIONS = frozenset({
    "CreateNetworkAcl", "DeleteNetworkAcl", "CreateNetworkAclEntry",
    "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry", "ReplaceNetworkAclAssociation",
})


def _sharing_unseen(service: str, operation: str, parameters: dict[str, Any]) -> bool:
    if service == "ec2" and operation == "ModifySnapshotAttribute":
        return parameters.get("Attribute") == "createVolumePermission" or any(
            key in parameters for key in ("CreateVolumePermission", "UserIds", "GroupNames")
        )
    if service == "ec2" and operation == "ModifyImageAttribute":
        return parameters.get("Attribute") == "launchPermission" or any(
            key in parameters for key in ("LaunchPermission", "UserIds", "UserGroups", "OrganizationArns", "OrganizationalUnitArns")
        )
    if service == "ec2" and operation in {"DisableSnapshotBlockPublicAccess", "DisableImageBlockPublicAccess"}:
        return True
    return service == "rds" and operation in {"ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"} and str(parameters.get("AttributeName", "")).lower() == "restore"


def _unmodeled(address: str, service: str, operation: str, detail: str | None = None) -> dict[str, Any]:
    if operation.startswith(_DELETE_PREFIXES):
        actions = ["delete"]
        risk = None
    elif operation.startswith(_RISKY_PREFIXES) or _RISKY_PUT.fullmatch(operation):
        actions = ["update"]
        risk = "risky"
    else:
        actions = ["update"]
        risk = None
    result = {"address": address, "type": f"{service}.{operation}", "actions": actions,
              "provider_name": "aws", "outside_view": False, "source": "aws_api"}
    if risk is not None:
        result["risk"] = risk
    if operation in _UNSEEN_EC2_OPERATIONS:
        result["unseen"] = True
    if detail is not None:
        result["detail"] = detail
    return result

def _permission_list(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    if "IpPermissions" in parameters:
        permissions = parameters["IpPermissions"]
        if not isinstance(permissions, list) or not all(isinstance(item, dict) for item in permissions):
            raise _invalid()
        return permissions
    legacy = {key: parameters[key] for key in ("IpProtocol", "FromPort", "ToPort", "CidrIp") if key in parameters}
    if "IpProtocol" in legacy:
        if "CidrIp" in legacy:
            legacy["IpRanges"] = [{"CidrIp": legacy.pop("CidrIp")}]
        return [legacy]
    raise _invalid()


def _validate_permission(permission: dict[str, Any]) -> None:
    for field in ("FromPort", "ToPort"):
        if field in permission and (not isinstance(permission[field], int) or isinstance(permission[field], bool)):
            raise _invalid()
    for field, cidr_key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
        values = permission.get(field, [])
        if not isinstance(values, list) or any(not isinstance(item, dict) or not isinstance(item.get(cidr_key), str) for item in values):
            raise _invalid()
    for field in ("UserIdGroupPairs", "PrefixListIds"):
        if field in permission and not isinstance(permission[field], list):
            raise _invalid()


def remove_security_group_rule(current: list[dict], target: dict) -> bool:
    """Revoke one permission's ranges/groups without removing sibling entries."""
    key = (target["protocol"], target["from_port"], target["to_port"])
    remove_ips = set(target.get("ip_ranges", []))
    remove_groups = set(target.get("source_sg_ids", [])) | set(target.get("dest_sg_ids", []))
    matched = False
    for existing in current:
        if (existing.get("protocol"), existing.get("from_port"), existing.get("to_port")) != key:
            continue
        matched = True
        existing["ip_ranges"] = [item for item in existing.get("ip_ranges", []) if item not in remove_ips]
        existing["source_sg_ids"] = [item for item in existing.get("source_sg_ids", []) if item not in remove_groups]
        existing["dest_sg_ids"] = [item for item in existing.get("dest_sg_ids", []) if item not in remove_groups]
    current[:] = [item for item in current if item.get("ip_ranges") or item.get("source_sg_ids") or item.get("dest_sg_ids")]
    return matched


def _security_group_change(address, operation, parameters, working, sg_rules, unknown_fields):
    group_id = parameters.get("GroupId")
    if not _valid_string(group_id):
        return None
    permissions = _permission_list(parameters)
    egress = operation.endswith("Egress")
    base = copy.deepcopy(sg_rules(group_id) if sg_rules else None) or []
    if isinstance(base, dict):
        current = working.setdefault(group_id, base).setdefault("egress_rules" if egress else "rules", [])
    else:
        current = working.setdefault(group_id, base)
    emitted = False
    for permission in permissions:
        _validate_permission(permission)
        if permission.get("PrefixListIds"):
            unknown_fields.append({"address": address, "field": "PrefixListIds", "reason": "unsupported_attribute"})
        rule = build_security_group_rule(permission, egress=egress, include_ipv6=True)
        if operation.startswith("Authorize"):
            if rule not in current:
                current.append(copy.deepcopy(rule))
                emitted = True
        else:
            matched = remove_security_group_rule(current, rule)
            emitted = emitted or matched
            if not matched:
                unknown_fields.append({"address": address, "field": "IpPermissions", "reason": "no_matching_rule"})
    if not emitted:
        return None
    field = "egress_rules" if egress else "rules"
    return Change(op="modify", resource_type="security_group", resource_id=group_id,
                  fields={field: copy.deepcopy(current)})


def translate_api_calls(
    doc: Any, resolve_role_arn: Callable[[str], str | None] | None = None,
    sg_rules: Callable[[str], list[dict] | None] | None = None,
    nacls: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("format") != "aws-api-calls/1":
        raise _invalid()
    calls = doc.get("calls")
    if not isinstance(calls, list) or not calls:
        raise _invalid()
    changes: list[Change] = []
    addresses: list[str] = []
    unmodeled: list[dict[str, Any]] = []
    unknown_fields: list[dict[str, Any]] = []
    working: dict[str, list[dict]] = {}
    working_nacls: dict[str, Any] = {}
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            raise _invalid()
        service, operation = call.get("service"), call.get("operation")
        if not _valid_string(service) or not _valid_string(operation):
            raise _invalid()
        parameters = call.get("parameters", {})
        if not isinstance(parameters, dict) or ("region" in call and not isinstance(call["region"], str)):
            raise _invalid()
        address = f"calls[{index}] {service}.{operation}"
        if parameters.get("DryRun") is True or operation.startswith(_READ_ONLY_PREFIXES):
            continue
        lower_service = service.lower()
        if _sharing_unseen(lower_service, operation, parameters):
            item = _unmodeled(address, lower_service, operation)
            item["unseen"] = True
            item["detail"] = f"{operation} can share a snapshot or image with other AWS accounts or the public, and Emfirge does not read sharing yet"
            unmodeled.append(item)
            continue
        if lower_service == "ec2" and operation in {"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress"}:
            if "GroupId" not in parameters:
                unmodeled.append(_unmodeled(address, lower_service, operation)); continue
            if not _valid_string(parameters.get("GroupId")):
                raise _invalid()
            change = _security_group_change(address, operation, parameters, working, sg_rules, unknown_fields)
            if change:
                changes.append(change); addresses.append(address)
            continue
        if lower_service == "ec2" and operation in {"CreateNetworkAcl", "DeleteNetworkAcl", "CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry", "ReplaceNetworkAclAssociation"}:
            acl_id = parameters.get("NetworkAclId")
            if operation == "CreateNetworkAcl":
                vpc_id = parameters.get("VpcId")
                if not _valid_string(vpc_id):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing VpcId")); continue
                acl_id = f"acl-new-{sum(1 for key in working_nacls if key.startswith('acl-new-')) + 1}"
                working_nacls[acl_id] = {"id": acl_id, "vpc_id": vpc_id, "entries": [], "associated_subnet_ids": [], "association_ids": {}}
                changes.append(Change(op="add", resource_type="network_acl", resource_id=acl_id, fields={"vpc_id": vpc_id}))
                addresses.append(address); continue
            if operation == "ReplaceNetworkAclAssociation":
                association_id = parameters.get("AssociationId")
                target_id = parameters.get("NetworkAclId")
                if not _valid_string(association_id) or not _valid_string(target_id):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing association parameters")); continue
                subnet_id = None
                for cached in working_nacls.values():
                    subnet_id = cached.get("association_ids", {}).get(association_id)
                    if subnet_id: break
                if subnet_id is None and nacls is not None:
                    source = nacls(f"association:{association_id}")
                    if source is not None:
                        subnet_id = getattr(source, "association_ids", {}).get(association_id) if not isinstance(source, dict) else source.get("association_ids", {}).get(association_id)
                if subnet_id is None:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "association id not in snapshot")); continue
                target = working_nacls.setdefault(target_id, copy.deepcopy(nacls(target_id)) if nacls and nacls(target_id) is not None else {})
                if not target:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "network ACL id not in snapshot")); continue
                assoc = list(target.get("associated_subnet_ids", []) if isinstance(target, dict) else target.associated_subnet_ids)
                if subnet_id not in assoc: assoc.append(subnet_id)
                changes.append(Change(op="modify", resource_type="network_acl", resource_id=target_id, fields={"associated_subnet_ids": assoc}))
                addresses.append(address); continue
            if not _valid_string(acl_id):
                unmodeled.append(_unmodeled(address, lower_service, operation, "missing NetworkAclId")); continue
            if acl_id not in working_nacls:
                source = nacls(acl_id) if nacls else None
                if source is None:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "network ACL id not in snapshot")); continue
                working_nacls[acl_id] = copy.deepcopy(source.model_dump() if hasattr(source, "model_dump") else source)
            current = working_nacls[acl_id]
            if operation == "DeleteNetworkAcl":
                changes.append(Change(op="delete", resource_type="network_acl", resource_id=acl_id)); addresses.append(address); continue
            entry = {"rule_number": parameters.get("RuleNumber"), "protocol": parameters.get("Protocol"), "rule_action": parameters.get("RuleAction"), "egress": parameters.get("Egress", False), "cidr_block": parameters.get("CidrBlock"), "ipv6_cidr_block": parameters.get("Ipv6CidrBlock"), "port_from": (parameters.get("PortRange") or {}).get("From"), "port_to": (parameters.get("PortRange") or {}).get("To")}
            if (not isinstance(entry["rule_number"], int) or isinstance(entry["rule_number"], bool)
                    or not 1 <= entry["rule_number"] <= 32766
                    or (operation != "DeleteNetworkAclEntry" and (not _valid_string(entry["protocol"])
                        or entry["rule_action"] not in {"allow", "deny"}))):
                unmodeled.append(_unmodeled(address, lower_service, operation, "invalid network ACL entry")); continue
            entries = current.setdefault("entries", [])
            match = next((i for i, item in enumerate(entries) if item.get("rule_number") == entry["rule_number"] and item.get("egress") == entry["egress"]), None)
            if operation == "CreateNetworkAclEntry":
                if match is not None:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "rule number already exists")); continue
                entries.append(entry)
            elif operation == "ReplaceNetworkAclEntry":
                if match is None:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "entry not in snapshot")); continue
                entries[match] = entry
            else:
                if match is None:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "entry not in snapshot")); continue
                entries.pop(match)
            changes.append(Change(op="modify", resource_type="network_acl", resource_id=acl_id, fields={"entries": copy.deepcopy(entries)})); addresses.append(address); continue
        if lower_service == "rds" and operation == "ModifyDBInstance":
            _validate_identifier(operation, parameters, "DBInstanceIdentifier")
            mapped_fields = {"BackupRetentionPeriod": ("backup_retention_days", int), "DeletionProtection": ("deletion_protection", bool),
                             "PubliclyAccessible": ("publicly_accessible", bool), "VpcSecurityGroupIds": ("sg_ids", list)}
            fields = {}
            for field, value in parameters.items():
                if field in {"DBInstanceIdentifier", "ApplyImmediately", "DryRun"}:
                    continue
                if field not in mapped_fields:
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
                    continue
                target, expected = mapped_fields[field]
                valid = isinstance(value, expected) and (expected is not int or not isinstance(value, bool))
                if field == "VpcSecurityGroupIds":
                    valid = isinstance(value, list) and all(_valid_string(item) for item in value)
                if not valid:
                    raise _invalid()
                fields[target] = value
            if fields:
                changes.append(Change(op="modify", resource_type="rds_instance", resource_id=parameters["DBInstanceIdentifier"], fields=fields))
                addresses.append(address)
            continue
        mapped = _MAPPED.get((lower_service, operation))
        if mapped is None:
            unmodeled.append(_unmodeled(address, lower_service, operation))
            continue
        resource_type, identifier, known = mapped
        if operation == "DeleteSecurityGroup" and "GroupId" not in parameters:
            unmodeled.append(_unmodeled(address, lower_service, operation))
            continue
        _validate_identifier(operation, parameters, identifier)
        if operation == "DeleteDBInstance":
            for field in ("SkipFinalSnapshot", "DeleteAutomatedBackups"):
                if field in parameters and not isinstance(parameters[field], bool): raise _invalid()
            if "FinalDBSnapshotIdentifier" in parameters and not _valid_string(parameters["FinalDBSnapshotIdentifier"]): raise _invalid()
        for field in parameters:
            if field not in known: unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
        fields = {}
        if operation == "DeleteDBInstance":
            fields = {"skip_final_snapshot": parameters.get("SkipFinalSnapshot", False), "delete_automated_backups": parameters.get("DeleteAutomatedBackups", True)}
            if "FinalDBSnapshotIdentifier" in parameters: fields["final_db_snapshot_identifier"] = parameters["FinalDBSnapshotIdentifier"]
        if operation == "DeleteFunction" and "Qualifier" in parameters:
            unmodeled.append(_unmodeled(address, lower_service, operation)); continue
        resource_id_values = parameters[identifier] if operation == "TerminateInstances" else [parameters[identifier]]
        for resource_id in resource_id_values:
            if operation == "DeleteFunction" and isinstance(resource_id, str) and resource_id.startswith("arn:") and ":function:" in resource_id:
                resource_id = resource_id.split(":function:", 1)[1].split(":", 1)[0]
            if operation == "DeleteRole" and resolve_role_arn is not None:
                resource_id = resolve_role_arn(resource_id) or resource_id
            changes.append(Change(op="delete", resource_type=resource_type, resource_id=resource_id, fields=fields.copy()))
            addresses.append(address)
    return {"changes": changes, "addresses": addresses, "unmodeled": unmodeled, "unknown_fields": unknown_fields}
