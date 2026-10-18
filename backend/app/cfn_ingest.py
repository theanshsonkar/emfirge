from __future__ import annotations

import json
from typing import Any

from app.aws_api_ingest import _unmodeled


_MAX_CHANGES = 2000


def _invalid() -> ValueError:
    return ValueError("Invalid CloudFormation change set document")


def _resource(change: dict[str, Any]) -> dict[str, Any]:
    if change.get("Type") != "Resource" or not isinstance(change.get("ResourceChange"), dict):
        raise _invalid()
    resource = change["ResourceChange"]
    if not all(isinstance(resource.get(key), str) for key in ("Action", "ResourceType")):
        raise _invalid()
    return resource


def _context(resource: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = resource.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid()
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError, RecursionError) as exc:
        raise _invalid() from exc
    if not isinstance(parsed, dict):
        raise _invalid()
    return parsed


def _parts(resource_type: str) -> tuple[str, str]:
    bits = resource_type.split("::")
    if len(bits) == 3 and bits[0] == "AWS":
        return bits[1].lower(), bits[2]
    if len(bits) == 2 and bits[0] == "Custom":
        return "custom", bits[1]
    return resource_type.split("::", 1)[0].lower(), bits[-1]


_UNSEEN_CFN_TYPES = frozenset({
    "AWS::EC2::NetworkAcl", "AWS::EC2::NetworkAclEntry",
    "AWS::EC2::SubnetNetworkAclAssociation", "AWS::EC2::SecurityGroupEgress",
})


def _extra(address: str, resource_type: str, operation: str) -> dict[str, Any]:
    service, _ = _parts(resource_type)
    if operation in {"RetainResource", "ConditionalReplacement", "MissingPropertyValues"} or resource_type == "AWS::CloudFormation::Stack":
        service = "cloudformation"
    result = _unmodeled(address, service, operation)
    if resource_type in _UNSEEN_CFN_TYPES:
        result["unseen"] = True
    return result


def _properties(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if doc is None:
        return None
    properties = doc.get("Properties")
    return properties if isinstance(properties, dict) else None


def _normalize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    protocol = rule.get("IpProtocol", rule.get("Protocol"))
    if protocol is not None:
        result["IpProtocol"] = str(protocol)
    for source, target in (("FromPort", "FromPort"), ("ToPort", "ToPort")):
        if source in rule and rule[source] is not None:
            try:
                result[target] = int(rule[source])
            except (TypeError, ValueError) as exc:
                raise _invalid() from exc
    if "CidrIp" in rule:
        result["IpRanges"] = [{"CidrIp": rule["CidrIp"]}]
    elif "CidrIpv6" in rule:
        result["Ipv6Ranges"] = [{"CidrIpv6": rule["CidrIpv6"]}]
    elif "SourceSecurityGroupId" in rule:
        result["UserIdGroupPairs"] = [{"GroupId": rule["SourceSecurityGroupId"]}]
    return result


def _sg_calls(resource: dict[str, Any], before: dict[str, Any] | None, after: dict[str, Any] | None, address: str) -> list[dict[str, Any]]:
    old = (_properties(before) or {}).get("SecurityGroupIngress")
    new = (_properties(after) or {}).get("SecurityGroupIngress")
    if not isinstance(old, list) or not isinstance(new, list):
        raise _invalid()
    old_rules = {_rule_key(rule): rule for rule in old if isinstance(rule, dict)}
    new_rules = {_rule_key(rule): rule for rule in new if isinstance(rule, dict)}
    calls = []
    for key, rule in new_rules.items():
        if key not in old_rules:
            calls.append({"service": "ec2", "operation": "AuthorizeSecurityGroupIngress",
                          "parameters": {"GroupId": resource.get("PhysicalResourceId"), "IpPermissions": [_normalize_rule(rule)]}})
    for key, rule in old_rules.items():
        if key not in new_rules:
            calls.append({"service": "ec2", "operation": "RevokeSecurityGroupIngress",
                          "parameters": {"GroupId": resource.get("PhysicalResourceId"), "IpPermissions": [_normalize_rule(rule)]}})
    return calls


def _rule_key(rule: dict[str, Any]) -> str:
    return json.dumps(_normalize_rule(rule), sort_keys=True, separators=(",", ":"))


def _removal(resource: dict[str, Any], address: str, policy_action: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    typ = resource["ResourceType"]
    service, suffix = _parts(typ)
    physical = resource.get("PhysicalResourceId")
    if policy_action in {"Retain", "ReplaceAndRetain"}:
        return [], [_extra(address, typ, "RetainResource")]
    if typ == "AWS::EC2::SecurityGroupIngress":
        before = _context(resource, "BeforeContext")
        rule = _properties(before) if before else None
        if isinstance(rule, dict):
            return [{"service": "ec2", "operation": "RevokeSecurityGroupIngress",
                     "parameters": {"GroupId": rule.get("GroupId") or physical,
                                    "IpPermissions": [_normalize_rule(rule)]}}], []
        return [], [_extra(address, typ, "Delete" + suffix)]
    if typ == "AWS::RDS::DBInstance":
        if not isinstance(physical, str) or not physical:
            return [], [_extra(address, typ, "DeleteDBInstance")]
        snapshot = policy_action in {"Snapshot", "ReplaceAndSnapshot"}
        params = {"DBInstanceIdentifier": physical, "SkipFinalSnapshot": not snapshot}
        if snapshot:
            params["FinalDBSnapshotIdentifier"] = f"{physical}-final"
        return [{"service": "rds", "operation": "DeleteDBInstance", "parameters": params}], []
    operations = {("ec2", "Instance"): ("ec2", "TerminateInstances", "InstanceIds", True),
                  ("ec2", "Volume"): ("ec2", "DeleteVolume", "VolumeId", False),
                  ("ec2", "SecurityGroup"): ("ec2", "DeleteSecurityGroup", "GroupId", False),
                  ("s3", "Bucket"): ("s3", "DeleteBucket", "Bucket", False),
                  ("lambda", "Function"): ("lambda", "DeleteFunction", "FunctionName", False),
                  ("iam", "Role"): ("iam", "DeleteRole", "RoleName", False)}
    mapped = operations.get((service, suffix))
    if mapped and isinstance(physical, str) and physical:
        svc, operation, key, many = mapped
        value = [physical] if many else physical
        return [{"service": svc, "operation": operation, "parameters": {key: value}}], []
    return [], [_extra(address, typ, "Delete" + suffix)]


def _resolved(value: Any) -> Any:
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return None


def _nacl_entry_call(resource: dict[str, Any], properties: dict[str, Any], operation: str) -> dict[str, Any] | None:
    acl_id = _resolved(properties.get("NetworkAclId")); number = _resolved(properties.get("RuleNumber"))
    protocol = _resolved(properties.get("Protocol", properties.get("IpProtocol")))
    action = _resolved(properties.get("RuleAction")); egress = _resolved(properties.get("Egress", False))
    if not isinstance(acl_id, str) or not isinstance(number, int) or isinstance(number, bool) or not isinstance(protocol, (str, int)) or not isinstance(action, str) or not isinstance(egress, bool):
        return None
    params: dict[str, Any] = {"NetworkAclId": acl_id, "RuleNumber": number, "Protocol": str(protocol), "RuleAction": action, "Egress": egress}
    if isinstance(properties.get("CidrBlock"), str): params["CidrBlock"] = properties["CidrBlock"]
    if isinstance(properties.get("Ipv6CidrBlock"), str): params["Ipv6CidrBlock"] = properties["Ipv6CidrBlock"]
    port = properties.get("PortRange")
    if isinstance(port, dict):
        lo, hi = _resolved(port.get("From")), _resolved(port.get("To"))
        if isinstance(lo, int) and isinstance(hi, int): params["PortRange"] = {"From": lo, "To": hi}
    return {"service": "ec2", "operation": operation, "parameters": params}


def _nacl_snapshot_lookup(snapshot: Any, acl_id: str) -> Any:
    if snapshot is None: return None
    if callable(snapshot): return snapshot(acl_id)
    if acl_id in snapshot: return snapshot.get(acl_id)
    if acl_id.startswith("association:"):
        association_id = acl_id.split(":", 1)[1]
        return next((acl for acl in snapshot.values() if association_id in getattr(acl, "association_ids", {})), None)
    return None


def _nacl_association_id(snapshot: Any, subnet_id: str) -> str | None:
    if snapshot is None: return None
    values = snapshot.values() if isinstance(snapshot, dict) else []
    for acl in values:
        associated = getattr(acl, "associated_subnet_ids", []) if not isinstance(acl, dict) else acl.get("associated_subnet_ids", [])
        if subnet_id not in associated: continue
        ids = getattr(acl, "association_ids", {}) if not isinstance(acl, dict) else acl.get("association_ids", {})
        for association_id, subnet in ids.items():
            if subnet == subnet_id: return association_id
    return None


def convert_change_set(doc: Any, nacls: Any = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(doc, dict) or not isinstance(doc.get("Changes"), list) or len(doc["Changes"]) > _MAX_CHANGES:
        raise _invalid()
    calls: list[dict[str, Any]] = []
    extras: list[dict[str, Any]] = []
    for index, item in enumerate(doc["Changes"]):
        if not isinstance(item, dict):
            raise _invalid()
        if item.get("Type") != "Resource":
            continue
        resource = _resource(item)
        action = resource["Action"]
        typ = resource["ResourceType"]
        address = f"Changes[{index}] {typ}/{resource.get('LogicalResourceId', '')}"
        service, suffix = _parts(typ)
        physical = resource.get("PhysicalResourceId")
        policy = resource.get("PolicyAction")
        if typ == "AWS::EC2::NetworkAclEntry":
            context = _context(resource, "AfterContext") or _context(resource, "BeforeContext")
            props = _properties(context) if context else None
            operation = {"Add": "CreateNetworkAclEntry", "Modify": "ReplaceNetworkAclEntry", "Remove": "DeleteNetworkAclEntry"}.get(action)
            call = _nacl_entry_call(resource, props, operation) if operation and isinstance(props, dict) else None
            if call: calls.append(call)
            else: extras.append(_extra(address, typ, operation or action + suffix));
            continue
        if typ == "AWS::EC2::NetworkAcl":
            context = _context(resource, "AfterContext") or _context(resource, "BeforeContext")
            props = _properties(context) if context else {}
            vpc_id = _resolved(props.get("VpcId")) if isinstance(props, dict) else None
            if action == "Add" and isinstance(vpc_id, str): calls.append({"service": "ec2", "operation": "CreateNetworkAcl", "parameters": {"VpcId": vpc_id}})
            elif action == "Remove" and isinstance(physical, str) and physical: calls.append({"service": "ec2", "operation": "DeleteNetworkAcl", "parameters": {"NetworkAclId": physical}})
            else: extras.append(_extra(address, typ, "CreateNetworkAcl" if action == "Add" else "DeleteNetworkAcl"))
            continue
        if typ == "AWS::EC2::SubnetNetworkAclAssociation":
            context = _context(resource, "AfterContext") or _context(resource, "BeforeContext")
            props = _properties(context) if context else {}
            subnet_id = _resolved(props.get("SubnetId")) if isinstance(props, dict) else None
            target_id = _resolved(props.get("NetworkAclId")) if isinstance(props, dict) else None
            association_id = _nacl_association_id(nacls, subnet_id) if isinstance(subnet_id, str) else None
            if action in {"Add", "Modify"} and isinstance(subnet_id, str) and isinstance(target_id, str) and association_id:
                calls.append({"service": "ec2", "operation": "ReplaceNetworkAclAssociation", "parameters": {"AssociationId": association_id, "NetworkAclId": target_id}})
            elif action == "Remove" and isinstance(subnet_id, str) and association_id:
                snapshot_acl = _nacl_snapshot_lookup(nacls, "association:" + association_id)
                vpc_id = getattr(snapshot_acl, "vpc_id", None) if snapshot_acl is not None else None
                default_id = next((str(k) for k, a in (nacls or {}).items() if getattr(a, "vpc_id", None) == vpc_id and getattr(a, "is_default", False)), None) if isinstance(nacls, dict) else None
                if default_id: calls.append({"service": "ec2", "operation": "ReplaceNetworkAclAssociation", "parameters": {"AssociationId": association_id, "NetworkAclId": default_id}})
                else: extras.append(_extra(address, typ, "ReplaceNetworkAclAssociation"))
            else: extras.append(_extra(address, typ, "ReplaceNetworkAclAssociation"))
            continue
        if action == "Remove":
            removal_calls, removal_extras = _removal(resource, address, policy)
            calls.extend(removal_calls)
            extras.extend(removal_extras)
        elif action == "Modify":
            replacement = resource.get("Replacement")
            if replacement in {"True", "Conditional"}:
                if policy == "ReplaceAndRetain":
                    removal_calls, removal_extras = [], [_extra(address, typ, "RetainResource")]
                else:
                    removal_calls, removal_extras = _removal(resource, address, policy)
                calls.extend(removal_calls)
                extras.extend(removal_extras)
                if replacement == "Conditional":
                    extras.append(_extra(address, typ, "ConditionalReplacement"))
                continue
            before, after = _context(resource, "BeforeContext"), _context(resource, "AfterContext")
            if typ == "AWS::EC2::SecurityGroup":
                if before is None or after is None:
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                else:
                    calls.extend(_sg_calls(resource, before, after, address))
            elif typ == "AWS::RDS::DBInstance":
                if before is None or after is None or _properties(before) is None or _properties(after) is None:
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                else:
                    bp, ap = _properties(before), _properties(after)
                    params = {"DBInstanceIdentifier": physical}
                    for key in ("DeletionProtection", "BackupRetentionPeriod", "PubliclyAccessible", "VPCSecurityGroups"):
                        if bp.get(key) != ap.get(key) and key in ap:
                            if key == "DeletionProtection" and isinstance(ap[key], str):
                                params[key] = ap[key].strip().lower() == "true"
                            else:
                                params[key] = ap[key]
                    mapped = {"DeletionProtection": "DeletionProtection", "BackupRetentionPeriod": "BackupRetentionPeriod", "PubliclyAccessible": "PubliclyAccessible", "VPCSecurityGroups": "VpcSecurityGroupIds"}
                    params = {"DBInstanceIdentifier": params["DBInstanceIdentifier"], **{mapped[k]: v for k, v in params.items() if k != "DBInstanceIdentifier"}}
                    if len(params) > 1:
                        calls.append({"service": "rds", "operation": "ModifyDBInstance", "parameters": params})
            else:
                before, after = _context(resource, "BeforeContext"), _context(resource, "AfterContext")
                if typ == "AWS::EC2::SecurityGroupIngress" and isinstance(_properties(before), dict):
                    rule = _properties(before)
                    calls.append({"service": "ec2", "operation": "RevokeSecurityGroupIngress", "parameters": {"GroupId": rule.get("GroupId") or physical, "IpPermissions": [_normalize_rule(rule)]}})
                else:
                    extras.append(_extra(address, typ, "UpdateNestedStack" if typ == "AWS::CloudFormation::Stack" else "Update" + suffix))
        elif action == "Add":
            if typ == "AWS::EC2::SecurityGroupIngress":
                after = _context(resource, "AfterContext")
                rule = _properties(after) if after else None
                if not isinstance(rule, dict):
                    extras.append(_extra(address, typ, "CreateSecurityGroupIngress"))
                else:
                    calls.append({"service": "ec2", "operation": "AuthorizeSecurityGroupIngress", "parameters": {"GroupId": rule.get("GroupId") or physical, "IpPermissions": [_normalize_rule(rule)]}})
            else:
                extras.append(_extra(address, typ, "Create" + suffix))
        elif action == "Import":
            extras.append(_extra(address, typ, "Import"))
        elif action == "Dynamic":
            extras.append(_extra(address, typ, "DynamicChange"))
        else:
            extras.append(_extra(address, typ, action + suffix))
    return {"format": "aws-api-calls/1", "calls": calls}, extras
