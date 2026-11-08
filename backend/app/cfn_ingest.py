from __future__ import annotations

import json
from typing import Any

from app.aws_api_ingest import _unmodeled
from app.cloudfront_distribution import cfn_config_to_api, cfn_unmodeled
from app.dynamodb_table import cfn_calls as dynamodb_cfn_calls


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


def _normalize_rule(rule: dict[str, Any], egress: bool = False) -> dict[str, Any]:
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
    elif egress and "DestinationSecurityGroupId" in rule:
        result["UserIdGroupPairs"] = [{"GroupId": rule["DestinationSecurityGroupId"]}]
    elif egress and "DestinationPrefixListId" in rule:
        result["PrefixListIds"] = [{"PrefixListId": rule["DestinationPrefixListId"]}]
    elif "SourceSecurityGroupId" in rule:
        result["UserIdGroupPairs"] = [{"GroupId": rule["SourceSecurityGroupId"]}]
    return result


_SG_RULE_PROPERTIES = {"SecurityGroupIngress": ("Ingress", False), "SecurityGroupEgress": ("Egress", True)}


def _sg_rule_calls(resource: dict[str, Any], old: list, new: list, kind: str, egress: bool) -> list[dict[str, Any]]:
    old_rules = {_rule_key(rule, egress): rule for rule in old if isinstance(rule, dict)}
    new_rules = {_rule_key(rule, egress): rule for rule in new if isinstance(rule, dict)}
    calls = []
    for key, rule in new_rules.items():
        if key not in old_rules:
            calls.append({"service": "ec2", "operation": f"AuthorizeSecurityGroup{kind}",
                          "parameters": {"GroupId": resource.get("PhysicalResourceId"), "IpPermissions": [_normalize_rule(rule, egress)]}})
    for key, rule in old_rules.items():
        if key not in new_rules:
            calls.append({"service": "ec2", "operation": f"RevokeSecurityGroup{kind}",
                          "parameters": {"GroupId": resource.get("PhysicalResourceId"), "IpPermissions": [_normalize_rule(rule, egress)]}})
    return calls


def _sg_calls(resource: dict[str, Any], before: dict[str, Any] | None, after: dict[str, Any] | None, address: str
              ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(calls, unknowns) for a modified security group: ingress and egress rules are diffed; every other changed property is a named unknown.

    A group with no SecurityGroupEgress property keeps a default egress rule the change set does not state, so adding or
    removing the whole property is unknown, never an empty or allow-all list.
    """
    old_props, new_props = _properties(before) or {}, _properties(after) or {}
    calls: list[dict[str, Any]] = []
    extras: list[dict[str, Any]] = []
    for prop, (kind, egress) in _SG_RULE_PROPERTIES.items():
        old, new = old_props.get(prop), new_props.get(prop)
        if prop not in old_props and prop not in new_props:
            continue
        if isinstance(old, list) and isinstance(new, list):
            calls.extend(_sg_rule_calls(resource, old, new, kind, egress))
        elif egress and (old is None) != (new is None) and isinstance(old if new is None else new, list):
            result = _extra(address, "AWS::EC2::SecurityGroup", "UpdateSecurityGroup")
            result["field"] = prop
            result["detail"] = (f"{prop} was {'removed' if new is None else 'added'}; without it the group keeps a default egress rule "
                                "that the change set does not state, so the resulting egress is unknown")
            extras.append(result)
        else:
            raise _invalid()
    for prop in sorted((set(old_props) | set(new_props)) - set(_SG_RULE_PROPERTIES)):
        if old_props.get(prop) != new_props.get(prop):
            result = _extra(address, "AWS::EC2::SecurityGroup", "UpdateSecurityGroup")
            result["field"] = prop
            result["detail"] = f"{prop} changed; Emfirge does not model this security group property, so its effect is unknown"
            extras.append(result)
    return calls, extras


def _rule_key(rule: dict[str, Any], egress: bool = False) -> str:
    return json.dumps(_normalize_rule(rule, egress), sort_keys=True, separators=(",", ":"))


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
                  ("iam", "Role"): ("iam", "DeleteRole", "RoleName", False),
                  ("dynamodb", "Table"): ("dynamodb", "DeleteTable", "TableName", False)}
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


_SCHEDULER_OPERATIONS = {"Add": "CreateSchedule", "Modify": "UpdateSchedule", "Remove": "DeleteSchedule"}


def _scheduler_call(resource: dict[str, Any], action: str, physical: Any) -> dict[str, Any] | None:
    """AWS::Scheduler::Schedule add / update / remove as the API call it stands for (properties are the API's members)."""
    before = _properties(_context(resource, "BeforeContext")) or {}
    after = _properties(_context(resource, "AfterContext")) or {}
    source = before if action == "Remove" else after
    name = source.get("Name", physical if action != "Add" else None)
    group = source.get("GroupName")
    if not isinstance(name, str) or not name or (group is not None and not isinstance(group, str)):
        return None
    params: dict[str, Any] = {"Name": name}
    if group:
        params["GroupName"] = group
    if action == "Remove":
        return {"service": "scheduler", "operation": "DeleteSchedule", "parameters": params}
    params.update({key: value for key, value in after.items() if key not in {"Name", "GroupName"}})
    window, target = params.get("FlexibleTimeWindow"), params.get("Target")
    if (not isinstance(params.get("ScheduleExpression"), str) or not isinstance(window, dict) or not isinstance(window.get("Mode"), str)
            or not isinstance(target, dict) or not isinstance(target.get("Arn"), str) or not isinstance(target.get("RoleArn"), str)
            or not all(isinstance(params.get(key), str) for key in ("State", "StartDate", "EndDate", "ScheduleExpressionTimezone", "ActionAfterCompletion") if key in params)):
        return None
    minutes = window.get("MaximumWindowInMinutes")
    if isinstance(minutes, str) and minutes.isdigit():
        params["FlexibleTimeWindow"] = {**window, "MaximumWindowInMinutes": int(minutes)}
    return {"service": "scheduler", "operation": _SCHEDULER_OPERATIONS[action], "parameters": params}


def _cloudfront_call(resource: dict[str, Any], physical: Any) -> dict[str, Any] | None:
    """AWS::CloudFront::Distribution update as a partial UpdateDistribution call (only the modeled members, converted to the API's shape)."""
    before = (_properties(_context(resource, "BeforeContext")) or {}).get("DistributionConfig")
    after = (_properties(_context(resource, "AfterContext")) or {}).get("DistributionConfig")
    if not isinstance(physical, str) or not physical or not isinstance(after, dict) or not isinstance(before, dict):
        return None
    return {"service": "cloudfront", "operation": "UpdateDistribution", "partial": True,
            "unmodeled": cfn_unmodeled(before, after),
            "parameters": {"Id": physical, "DistributionConfig": cfn_config_to_api(after)}}


def _removed_extra(address: str, resource_type: str, operation: str, prop: str) -> dict[str, Any]:
    """An unknown for a property the change set removed: CloudFormation resets it to a default Emfirge does not state."""
    result = _extra(address, resource_type, operation)
    result["detail"] = f"{prop} was removed; CloudFormation resets it to its default, which is not known here, so the resulting setting is unknown"
    result["field"] = prop
    return result


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
        if (typ == "AWS::Scheduler::Schedule" and action in _SCHEDULER_OPERATIONS and policy not in {"Retain", "ReplaceAndRetain"}
                and not (action == "Modify" and resource.get("Replacement") in {"True", "Conditional"})):
            call = _scheduler_call(resource, action, physical)
            if call is None:
                extras.append(_extra(address, typ, "MissingPropertyValues"))
            else:
                calls.append(call)
            continue
        if (typ == "AWS::DynamoDB::Table" and action == "Modify" and policy not in {"Retain", "ReplaceAndRetain"}
                and resource.get("Replacement") not in {"True", "Conditional"}):
            before_props, after_props = _properties(_context(resource, "BeforeContext")), _properties(_context(resource, "AfterContext"))
            if not isinstance(before_props, dict) or not isinstance(after_props, dict):
                extras.append(_extra(address, typ, "MissingPropertyValues"))
                continue
            table_calls, resolved, removed_unknown = dynamodb_cfn_calls(action, physical, before_props, after_props)
            if not resolved:
                extras.append(_extra(address, typ, "MissingPropertyValues"))
                continue
            calls.extend(table_calls)
            extras.extend(_removed_extra(address, typ, "UpdateTable", name) for name in removed_unknown)
            # every other property that differs is a change Emfirge does not model
            others = {key for key in set(before_props) | set(after_props)
                      if key not in {"PointInTimeRecoverySpecification", "DeletionProtectionEnabled"} and before_props.get(key) != after_props.get(key)}
            if others:
                extras.append(_extra(address, typ, "UpdateTable"))
            continue
        if (typ == "AWS::CloudFront::Distribution" and action == "Modify" and policy not in {"Retain", "ReplaceAndRetain"}
                and resource.get("Replacement") not in {"True", "Conditional"}):
            call = _cloudfront_call(resource, physical)
            if call is None:
                extras.append(_extra(address, typ, "MissingPropertyValues"))
            else:
                calls.append(call)
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
                    sg_calls, sg_extras = _sg_calls(resource, before, after, address)
                    calls.extend(sg_calls)
                    extras.extend(sg_extras)
            elif typ == "AWS::RDS::DBInstance":
                if before is None or after is None or _properties(before) is None or _properties(after) is None:
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                else:
                    bp, ap = _properties(before), _properties(after)
                    params = {"DBInstanceIdentifier": physical}
                    # A removed property is reset by CloudFormation to a default the resource page does not
                    # state for these four (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbinstance.html), so it is unknown.
                    for key in ("DeletionProtection", "BackupRetentionPeriod", "PubliclyAccessible", "VPCSecurityGroups"):
                        if key in bp and key not in ap:
                            extras.append(_removed_extra(address, typ, "ModifyDBInstance", key))
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
            if typ == "AWS::EC2::NatGateway":
                after = _context(resource, "AfterContext")
                properties = _properties(after) if after else None
                subnet_id = _resolved((properties or {}).get("SubnetId"))
                if not isinstance(subnet_id, str) or not subnet_id:
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                    continue
                params = {"SubnetId": subnet_id}
                for key, value in properties.items():
                    if key in {"SubnetId", "Tags"}:
                        continue
                    params[key] = _resolved(value) if key in {"AllocationId", "ConnectivityType"} else value
                    if params[key] is None:
                        extras.append(_extra(address, typ, "MissingPropertyValues"))
                        break
                else:
                    calls.append({"service": "ec2", "operation": "CreateNatGateway", "parameters": params})
            elif typ == "AWS::EC2::RouteTable":
                properties = _properties(_context(resource, "AfterContext")) or {}
                vpc_id = _resolved(properties.get("VpcId"))
                if not isinstance(vpc_id, str) or not vpc_id:
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                    continue
                params = {"VpcId": vpc_id}
                if properties.get("Tags"):
                    params["TagSpecifications"] = [{"ResourceType": "route-table", "Tags": properties["Tags"]}]
                calls.append({"service": "ec2", "operation": "CreateRouteTable", "parameters": params})
            elif typ == "AWS::EC2::Volume":
                properties = _properties(_context(resource, "AfterContext")) or {}
                params = {}
                for key, value in properties.items():
                    if key == "Tags":
                        params["TagSpecifications"] = [{"ResourceType": "volume", "Tags": value}]
                        continue
                    params[key] = _resolved(value) if key in {"AvailabilityZone", "VolumeType", "SnapshotId"} else value
                    if key == "Size" and isinstance(value, str) and value.isdigit():
                        params[key] = int(value)
                if any(value is None for value in params.values()):
                    extras.append(_extra(address, typ, "MissingPropertyValues"))
                else:
                    calls.append({"service": "ec2", "operation": "CreateVolume", "parameters": params})
            elif typ == "AWS::EC2::SecurityGroupIngress":
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
