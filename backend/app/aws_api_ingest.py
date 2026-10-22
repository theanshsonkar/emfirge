from __future__ import annotations

from typing import Any, Callable
import json

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


def _policy_statements(document: Any) -> list:
    if isinstance(document, str):
        import urllib.parse
        document = json.loads(urllib.parse.unquote(document))
    if not isinstance(document, dict):
        raise _invalid()
    rows = document.get("Statement", [])
    if isinstance(rows, dict): rows = [rows]
    if not isinstance(rows, list): raise _invalid()
    from app.models import AccessStatement
    result = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Effect"), str): continue
        ak = "NotAction" if "NotAction" in row else "Action"
        rk = "NotResource" if "NotResource" in row else "Resource"
        actions, resources = row.get(ak, []), row.get(rk, [])
        if isinstance(actions, str): actions = [actions]
        if isinstance(resources, str): resources = [resources]
        if not isinstance(actions, list) or not isinstance(resources, list): continue
        actions = list(dict.fromkeys(x for x in actions if isinstance(x, str)))
        resources = list(dict.fromkeys(x for x in resources if isinstance(x, str)))
        if actions or resources:
            result.append(AccessStatement(effect=row["Effect"].lower(), actions=actions, resources=resources,
                is_not_action=ak == "NotAction", is_not_resource=rk == "NotResource",
                has_condition=bool(row.get("Condition"))))
    return result


def _role_value(role: Any, field: str, default=None):
    return role.get(field, default) if isinstance(role, dict) else getattr(role, field, default)


def _statement_dicts(statements: list) -> list[dict]:
    return [item.model_dump(mode="json") if hasattr(item, "model_dump") else copy.deepcopy(item) for item in statements]


def _role_change(role: Any, records: list, address: str):
    from app.models import PolicyDocumentRecord, merge_policy_statements
    normalized = [item.model_dump(mode="json") if hasattr(item, "model_dump") else copy.deepcopy(item) for item in records]
    statements = merge_policy_statements([
        item if isinstance(item, PolicyDocumentRecord) else PolicyDocumentRecord.model_validate(item)
        for item in records
    ])
    role["policy_documents"] = copy.deepcopy(normalized)
    role["access_statements"] = statements
    return Change(op="modify", resource_type="iam_role_policy", resource_id=role["role_arn"],
                  fields={"policy_documents": [item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in records],
                          "access_statements": _statement_dicts(statements)})


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
    role_policies: list[Any] | None = None,
    ec2_instances: list[Any] | None = None,
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
    working_roles = {
        _role_value(role, "role_name"): {"role_arn": _role_value(role, "role_arn"),
            "policy_names": list(_role_value(role, "policy_names", []) or []),
            "policy_documents": copy.deepcopy([item.model_dump() if hasattr(item, "model_dump") else item for item in (_role_value(role, "policy_documents") or [])]) if _role_value(role, "policy_documents") is not None else None,
            "access_statements": copy.deepcopy(_role_value(role, "access_statements", []) or [])}
        for role in (role_policies or [])
    }
    working_instances = {(_role_value(item, "id")): item for item in (ec2_instances or [])}
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
        if lower_service == "iam" and operation in {"CreateRole", "UpdateAssumeRolePolicy", "CreateUser"}:
            if operation == "CreateRole":
                role_name = parameters.get("RoleName")
                if not _valid_string(role_name):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing RoleName")); continue
                document = parameters.get("AssumeRolePolicyDocument")
                try:
                    if isinstance(document, str): document = json.loads(document)
                    if not isinstance(document, dict): raise ValueError
                except Exception as exc: raise _invalid() from exc
                for field in parameters:
                    if field not in {"RoleName", "AssumeRolePolicyDocument", "Tags"}:
                        unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
                changes.append(Change(op="add", resource_type="iam_role", resource_id=role_name, fields={"trust_policy": document})); addresses.append(address); continue
            if operation == "UpdateAssumeRolePolicy":
                role_name, document = parameters.get("RoleName"), parameters.get("PolicyDocument")
                if not _valid_string(role_name):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing RoleName")); continue
                try:
                    if isinstance(document, str): document = json.loads(document)
                    if not isinstance(document, dict): raise ValueError
                except Exception as exc: raise _invalid() from exc
                for field in parameters:
                    if field not in {"RoleName", "PolicyDocument"}:
                        unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
                changes.append(Change(op="modify", resource_type="iam_role", resource_id=role_name, fields={"trust_policy": document})); addresses.append(address); continue
            user_name = parameters.get("UserName")
            if not _valid_string(user_name):
                unmodeled.append(_unmodeled(address, lower_service, operation, "missing UserName")); continue
            for field in parameters:
                if field not in {"UserName", "Tags"}:
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
            changes.append(Change(op="add", resource_type="iam_user", resource_id=user_name, fields={})); addresses.append(address); continue
        if lower_service == "iam" and operation in {"PutRolePolicy", "DeleteRolePolicy", "AttachRolePolicy", "DetachRolePolicy"}:
            if role_policies is None:
                item = _unmodeled(address, lower_service, operation, "IAM role policy state is unavailable")
                item["unseen"] = True
                unmodeled.append(item)
                continue
            role_name = parameters.get("RoleName")
            role = working_roles.get(role_name)
            if role is None:
                unmodeled.append(_unmodeled(address, lower_service, operation, "role target not in snapshot")); continue
            if operation == "PutRolePolicy":
                name, doc = parameters.get("PolicyName"), parameters.get("PolicyDocument")
                if not _valid_string(name) or doc is None: raise _invalid()
                from app.models import PolicyDocumentRecord, merge_policy_statements
                statements = _policy_statements(doc)
                if role["policy_documents"] is None:
                    if name in role["policy_names"]:
                        unmodeled.append(_unmodeled(address, lower_service, operation, "PutRolePolicy replaces an inline policy whose current statements Emfirge did not record")); unmodeled[-1]["unseen"] = True
                    else:
                        role["access_statements"] = merge_policy_statements([PolicyDocumentRecord(name="existing", kind="inline", statements=role["access_statements"]), PolicyDocumentRecord(name=name, kind="inline", statements=statements)])
                        changes.append(Change(op="modify", resource_type="iam_role_policy", resource_id=role["role_arn"], fields={"access_statements": _statement_dicts(role["access_statements"])})); addresses.append(address)
                else:
                    records = [PolicyDocumentRecord.model_validate(item) for item in role["policy_documents"] if not (item.get("kind") == "inline" and item.get("name") == name)]
                    records.append(PolicyDocumentRecord(name=name, kind="inline", statements=statements)); records.sort(key=lambda item: (item.kind, item.name, item.arn or ""))
                    changes.append(_role_change(role, records, address)); addresses.append(address)
                continue
            if role["policy_documents"] is None:
                detail = f"{operation} removes an inline policy whose statements Emfirge did not record" if operation == "DeleteRolePolicy" else f"{operation} removes a managed policy whose document Emfirge did not record"
                item = _unmodeled(address, lower_service, operation, detail); item["unseen"] = True; unmodeled.append(item); continue
            from app.models import PolicyDocumentRecord
            name = parameters.get("PolicyName")
            if operation in {"DeleteRolePolicy", "DetachRolePolicy"}:
                arn = parameters.get("PolicyArn")
                kind = "inline" if operation == "DeleteRolePolicy" else "managed"
                matches = [item for item in role["policy_documents"] if item.get("kind") == kind and ((name and item.get("name") == name) or (arn and item.get("arn") == arn))]
                if not matches:
                    unmodeled.append(_unmodeled(address, lower_service, operation, "policy is not attached")); continue
                records = [PolicyDocumentRecord.model_validate(item) for item in role["policy_documents"] if item not in matches]
                changes.append(_role_change(role, records, address)); addresses.append(address)
            else:
                arn = parameters.get("PolicyArn")
                source = next((r for other in working_roles.values() for r in (other["policy_documents"] or []) if r.get("kind") == "managed" and r.get("arn") == arn), None)
                if source is None:
                    item = _unmodeled(address, lower_service, operation, "AttachRolePolicy attaches a managed policy whose document Emfirge did not record"); item["unseen"] = True; unmodeled.append(item); continue
                if any(r.get("arn") == arn for r in role["policy_documents"]): continue
                records = [PolicyDocumentRecord.model_validate(item) for item in role["policy_documents"]] + [PolicyDocumentRecord.model_validate(source)]
                records.sort(key=lambda item: (item.kind, item.name, item.arn or ""))
                changes.append(_role_change(role, records, address)); addresses.append(address)
            continue
        if lower_service == "ec2" and operation == "ModifyInstanceMetadataOptions":
            if ec2_instances is None:
                item = _unmodeled(address, lower_service, operation, "EC2 instance metadata state is unavailable")
                item["unseen"] = True
                unmodeled.append(item)
                continue
            instance_id = parameters.get("InstanceId")
            instance = working_instances.get(instance_id)
            if instance is None:
                unmodeled.append(_unmodeled(address, lower_service, operation, "instance target not in snapshot")); continue
            for field in ("HttpEndpoint", "HttpPutResponseHopLimit", "HttpProtocolIpv6", "InstanceMetadataTags"):
                if field in parameters: unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
            if "HttpTokens" not in parameters: continue
            if parameters["HttpTokens"] not in {"required", "optional"}: raise _invalid()
            value = parameters["HttpTokens"] == "required"
            current = _role_value(instance, "imdsv2_required")
            if current == value: continue
            changes.append(Change(op="modify", resource_type="ec2_instance", resource_id=instance_id, fields={"imdsv2_required": value})); addresses.append(address)
            if isinstance(instance, dict): instance["imdsv2_required"] = value
            else: instance.imdsv2_required = value
            continue
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
        if lower_service == "ec2" and operation == "CreateNatGateway":
            if not _valid_string(parameters.get("SubnetId")):
                raise _invalid()
            fields = {"subnet_id": parameters["SubnetId"]}
            for source, target in (("ConnectivityType", "connectivity_type"), ("AllocationId", "allocation_id")):
                if source in parameters:
                    if not _valid_string(parameters[source]):
                        raise _invalid()
                    fields[target] = parameters[source]
            for field in parameters:
                if field not in {"SubnetId", "ConnectivityType", "AllocationId", "TagSpecifications", "ClientToken"}:
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
            # AWS assigns the NAT id; an empty id lets the branch generate a stable placeholder.
            changes.append(Change(op="add", resource_type="nat_gateway", resource_id="", fields=fields))
            addresses.append(address)
            continue
        if lower_service == "rds" and operation == "CreateDBSnapshot":
            if not _valid_string(parameters.get("DBSnapshotIdentifier")):
                unmodeled.append(_unmodeled(address, lower_service, operation))
                continue
            if not _valid_string(parameters.get("DBInstanceIdentifier")):
                raise _invalid()
            for field in parameters:
                if field not in {"DBSnapshotIdentifier", "DBInstanceIdentifier", "Tags"}:
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
            changes.append(Change(op="add", resource_type="rds_snapshot", resource_id=parameters["DBSnapshotIdentifier"], fields={"db_instance_id": parameters["DBInstanceIdentifier"]}))
            addresses.append(address)
            continue
        if lower_service == "s3" and operation in {"PutBucketPolicy", "DeleteBucketPolicy", "PutPublicAccessBlock", "PutBucketTagging", "DeleteBucketTagging"}:
            bucket = parameters.get("Bucket")
            if not _valid_string(bucket):
                unmodeled.append(_unmodeled(address, lower_service, operation, "missing Bucket")); continue
            known = {"Bucket", "ExpectedBucketOwner", "ChecksumAlgorithm", "ContentMD5"}
            if operation == "PutBucketPolicy":
                policy = parameters.get("Policy")
                if isinstance(policy, dict):
                    policy = json.dumps(policy)
                if not _valid_string(policy):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing Policy")); continue
                known |= {"Policy", "ConfirmRemoveSelfBucketAccess"}
                fields = {"policy": policy}
            elif operation == "DeleteBucketPolicy":
                fields = {"policy": None}
            elif operation == "DeleteBucketTagging":
                fields = {"tags": {}}
            elif operation == "PutBucketTagging":
                tag_set = (parameters.get("Tagging") or {}).get("TagSet") if isinstance(parameters.get("Tagging"), dict) else None
                if not isinstance(tag_set, list) or not all(isinstance(item, dict) and _valid_string(item.get("Key")) and isinstance(item.get("Value"), str) for item in tag_set):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing or malformed Tagging.TagSet")); continue
                known.add("Tagging")
                # PutBucketTagging replaces the whole tag set.
                fields = {"tags": {item["Key"]: item["Value"] for item in tag_set}}
            else:
                config = parameters.get("PublicAccessBlockConfiguration")
                if not isinstance(config, dict) or not all(isinstance(value, bool) for value in config.values()):
                    unmodeled.append(_unmodeled(address, lower_service, operation, "missing or malformed PublicAccessBlockConfiguration")); continue
                known.add("PublicAccessBlockConfiguration")
                # The call replaces the whole configuration; an omitted setting is false.
                fields = {field: config.get(key, False) for field, key in (
                    ("block_public_acls", "BlockPublicAcls"), ("ignore_public_acls", "IgnorePublicAcls"),
                    ("block_public_policy", "BlockPublicPolicy"), ("restrict_public_buckets", "RestrictPublicBuckets"))}
                for key in sorted(set(config) - {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}):
                    unknown_fields.append({"address": address, "field": f"PublicAccessBlockConfiguration.{key}", "reason": "unsupported_attribute"})
            for field in parameters:
                if field not in known:
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
            changes.append(Change(op="modify", resource_type="s3_bucket", resource_id=bucket, fields=fields))
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
