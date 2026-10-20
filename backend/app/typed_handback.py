from __future__ import annotations

import hashlib
import json
from typing import Any

import botocore.session
from botocore.validate import ParamValidator

from app.models import AWSInfrastructure
from app.mutations import Change, apply_changes

_SESSION = botocore.session.get_session()


class UnmappableChanges(ValueError):
    def __init__(self, changes: list[dict]):
        self.changes = changes
        super().__init__("Changes cannot be represented as AWS API calls")


def canonical_sha256(calls: list[dict]) -> str:
    return hashlib.sha256(json.dumps(calls, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _resource(state: AWSInfrastructure, typ: str, ident: str):
    collections = {
        "security_group": state.ec2.security_groups,
        "ec2_instance": state.ec2.instances,
        "rds_instance": state.rds.rds_instances,
        "s3_bucket": state.s3.buckets,
        "lambda_function": state.lambda_data.functions,
        "ebs_volume": state.ec2.ebs_volumes,
        "ebs_snapshot": state.ec2.ebs_snapshots,
        "rds_snapshot": state.rds.rds_snapshots,
        "route_table": state.vpc.route_tables,
        "network_acl": state.vpc.nacls,
    }
    items = collections.get(typ, [])
    key = "name" if typ in {"s3_bucket", "lambda_function"} else "id"
    return next((x for x in items if getattr(x, key, None) == ident), None)


def _perm(rule: Any, egress: bool) -> dict:
    get = lambda k: rule.get(k) if isinstance(rule, dict) else getattr(rule, k, None)
    result: dict[str, Any] = {"IpProtocol": get("protocol")}
    if get("from_port") is not None:
        result["FromPort"] = get("from_port")
    if get("to_port") is not None:
        result["ToPort"] = get("to_port")
    cidrs = get("ip_ranges") or []
    if any(":" not in cidr for cidr in cidrs):
        result["IpRanges"] = [{"CidrIp": c} for c in cidrs if ":" not in c]
    if any(":" in cidr for cidr in cidrs):
        result["Ipv6Ranges"] = [{"CidrIpv6": c} for c in cidrs if ":" in c]
    ids = get("dest_sg_ids" if egress else "source_sg_ids") or []
    if ids:
        result["UserIdGroupPairs"] = [{"GroupId": x} for x in ids]
    return result


def _rule_key(rule: Any) -> str:
    return json.dumps(rule.model_dump(mode="json") if hasattr(rule, "model_dump") else rule, sort_keys=True, separators=(",", ":"))


def _target(route: Any) -> tuple[str, str] | None:
    typ, ident = route.target_type, route.target_id
    keys = {
        "gateway": "GatewayId", "igw": "GatewayId", "internet_gateway": "GatewayId",
        "nat": "NatGatewayId", "nat_gateway": "NatGatewayId",
        "instance": "InstanceId", "vpc peering": "VpcPeeringConnectionId", "vpc_peering": "VpcPeeringConnectionId",
        "transit gateway": "TransitGatewayId", "transit_gateway": "TransitGatewayId",
        "network interface": "NetworkInterfaceId", "network_interface": "NetworkInterfaceId",
    }
    key = keys.get(typ.lower())
    return (key, ident) if key else None


def _calls_for(before, change: Change, after, index: int) -> tuple[list[dict], list[dict]]:
    typ, op, ident, fields = change.resource_type, change.op, change.resource_id, change.fields
    errors: list[dict] = []
    def err(reason):
        errors.append({"change_index": index, "op": op, "resource_type": typ, "reason": reason})
    def call(service, operation, params):
        return {"change_index": index, "service": service, "operation": operation, "params": params}
    if op == "add":
        if typ == "rds_snapshot":
            db_instance_id = fields.get("db_instance_id")
            if not isinstance(db_instance_id, str) or not db_instance_id:
                err("error")
                return [], errors
            return [call("rds", "CreateDBSnapshot", {"DBSnapshotIdentifier": ident, "DBInstanceIdentifier": db_instance_id})], errors
        err("operation_not_mapped")
        return [], errors
    # All mapped operations are based on an existing resource.  Check this
    # before the individual handlers so their lookups cannot leak StopIteration
    # or attribute errors for a missing resource.
    if typ in {"security_group", "ec2_instance", "rds_instance", "s3_bucket", "lambda_function", "ebs_volume", "ebs_snapshot", "rds_snapshot", "route_table", "network_acl"}:
        try:
            existing = _resource(before, typ, ident)
        except Exception:
            existing = None
        if existing is None:
            err("resource_not_found")
            return [], errors
    if op == "modify":
        for field, value in fields.items():
            if value is None:
                err(f"null_value:{field}")
        if errors:
            return [], errors
    if typ == "security_group" and op == "delete":
        return [call("ec2", "DeleteSecurityGroup", {"GroupId": ident})], errors
    if typ == "security_group" and op == "modify":
        if "name" in fields: err("field_not_mapped: name")
        authorizes, revokes = [], []
        for field, egress, auth, revoke in (("rules", False, "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"), ("egress_rules", True, "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress")):
            if field not in fields: continue
            old_group = _resource(before, "security_group", ident)
            new_group = _resource(after, "security_group", ident)
            old_rules = {_rule_key(x): x for x in (getattr(old_group, field) if old_group else [])}
            new_rules = {_rule_key(x): x for x in (getattr(new_group, field) if new_group else [])}
            for key in sorted(new_rules.keys() - old_rules.keys()): authorizes.append(call("ec2", auth, {"GroupId": ident, "IpPermissions": [_perm(new_rules[key], egress)]}))
            for key in sorted(old_rules.keys() - new_rules.keys()): revokes.append(call("ec2", revoke, {"GroupId": ident, "IpPermissions": [_perm(old_rules[key], egress)]}))
        result = authorizes + revokes
        unknown = set(fields) - {"name", "rules", "egress_rules"}
        for field in sorted(unknown): err(f"field_not_mapped: {field}")
        return result, errors
    if typ == "ec2_instance":
        if op == "delete": return [call("ec2", "TerminateInstances", {"InstanceIds": [ident]})], errors
        result = []
        for field in fields:
            value = getattr(after.ec2.instances[next(i for i,x in enumerate(after.ec2.instances) if x.id == ident)], field, None)
            if field == "state" and value in {"stopped", "running"}: result.append(call("ec2", "StopInstances" if value == "stopped" else "StartInstances", {"InstanceIds": [ident]}))
            elif field == "sg_ids": result.append(call("ec2", "ModifyInstanceAttribute", {"InstanceId": ident, "Groups": value}))
            elif field == "type": result.append(call("ec2", "ModifyInstanceAttribute", {"InstanceId": ident, "InstanceType": {"Value": value}}))
            elif field == "imdsv2_required": result.append(call("ec2", "ModifyInstanceMetadataOptions", {"InstanceId": ident, "HttpTokens": "required" if value else "optional"}))
            else: err(f"field_not_mapped: {field}")
        return result, errors
    deletes = {"ebs_volume": ("ec2", "DeleteVolume", "VolumeId"), "ebs_snapshot": ("ec2", "DeleteSnapshot", "SnapshotId"), "rds_snapshot": ("rds", "DeleteDBSnapshot", "DBSnapshotIdentifier")}
    if op == "delete" and typ in deletes:
        service, operation, key = deletes[typ]; return [call(service, operation, {key: ident})], errors
    if typ == "rds_instance" and op == "delete":
        params = {"DBInstanceIdentifier": ident, "SkipFinalSnapshot": fields.get("skip_final_snapshot", False)}
        for field, key in (("final_db_snapshot_identifier", "FinalDBSnapshotIdentifier"), ("delete_automated_backups", "DeleteAutomatedBackups")):
            if field in fields: params[key] = fields[field]
        return [call("rds", "DeleteDBInstance", params)], errors
    if typ == "rds_instance" and op == "modify":
        params = {"DBInstanceIdentifier": ident, "ApplyImmediately": True}; mapping = {"publicly_accessible":"PubliclyAccessible", "backup_retention_days":"BackupRetentionPeriod", "deletion_protection":"DeletionProtection", "sg_ids":"VpcSecurityGroupIds"}
        for field in fields:
            value = getattr(after.rds.rds_instances[next(i for i,x in enumerate(after.rds.rds_instances) if x.id == ident)], field)
            if value is None:
                err(f"field_not_mapped: {field} (null values are not supported)")
            elif field in mapping: params[mapping[field]] = value
            else: err(f"field_not_mapped: {field}")
        return [call("rds", "ModifyDBInstance", params)] if not errors else [], errors
    if typ == "s3_bucket" and op == "delete": return [call("s3", "DeleteBucket", {"Bucket": ident})], errors
    if typ == "s3_bucket" and op == "modify":
        result=[]
        for field in fields:
            value = getattr(after.s3.buckets[next(i for i,x in enumerate(after.s3.buckets) if x.name == ident)], field)
            if field == "versioning_enabled" and isinstance(value, bool): result.append(call("s3", "PutBucketVersioning", {"Bucket": ident, "VersioningConfiguration": {"Status": "Enabled" if value else "Suspended"}}))
            elif field == "policy" and isinstance(value, str): result.append(call("s3", "PutBucketPolicy", {"Bucket": ident, "Policy": value}))
            elif field in {"versioning_enabled", "policy"}: err(f"field_not_mapped: {field}")
            else: err(f"field_not_mapped: {field}")
        return result, errors
    if typ == "lambda_function" and op == "delete": return [call("lambda", "DeleteFunction", {"FunctionName": ident})], errors
    if typ == "lambda_function" and op == "modify":
        target = next(x for x in after.lambda_data.functions if x.name == ident); params={"FunctionName":ident}
        for field in fields:
            if field == "role_arn": params["Role"] = target.role_arn
            elif field in {"subnet_ids", "sg_ids"}: params["VpcConfig"] = {"SubnetIds": target.subnet_ids, "SecurityGroupIds": target.sg_ids}
            else: err(f"field_not_mapped: {field}")
        return [call("lambda", "UpdateFunctionConfiguration", params)] if not errors else [], errors
    if typ == "network_acl" and op == "modify":
        old = _resource(before, typ, ident); new = _resource(after, typ, ident); result = []
        if "entries" in fields:
            old_entries = {(x.rule_number, x.egress): x for x in old.entries}; new_entries = {(x.rule_number, x.egress): x for x in new.entries}
            def entry_params(entry):
                p = {"NetworkAclId": ident, "RuleNumber": entry.rule_number, "Protocol": entry.protocol, "RuleAction": entry.rule_action, "Egress": entry.egress}
                if entry.cidr_block: p["CidrBlock"] = entry.cidr_block
                if entry.ipv6_cidr_block: p["Ipv6CidrBlock"] = entry.ipv6_cidr_block
                if entry.port_from is not None: p["PortRange"] = {"From": entry.port_from, "To": entry.port_to}
                return p
            def check_default(entry):
                if entry.rule_number == 32767:
                    err("default_rule_not_modifiable")
                    return True
                return False
            for key in sorted(new_entries.keys() - old_entries.keys()):
                if not check_default(new_entries[key]): result.append(call("ec2", "CreateNetworkAclEntry", entry_params(new_entries[key])))
            for key in sorted(old_entries.keys() - new_entries.keys()):
                if key[0] != 32767: result.append(call("ec2", "DeleteNetworkAclEntry", {"NetworkAclId": ident, "RuleNumber": key[0], "Egress": key[1]}))
                else: err("default_rule_not_modifiable")
            for key in sorted(old_entries.keys() & new_entries.keys()):
                if _rule_key(old_entries[key]) != _rule_key(new_entries[key]) and not check_default(new_entries[key]):
                    result.append(call("ec2", "ReplaceNetworkAclEntry", entry_params(new_entries[key])))
        if "associated_subnet_ids" in fields:
            removed = set(old.associated_subnet_ids) - set(new.associated_subnet_ids)
            added = set(new.associated_subnet_ids) - set(old.associated_subnet_ids)
            for subnet in added:
                association_id = next((association_id for acl in before.vpc.nacls for association_id, associated_subnet in acl.association_ids.items() if associated_subnet == subnet), None)
                if association_id is None: err("association_id_unknown")
                else: result.append(call("ec2", "ReplaceNetworkAclAssociation", {"AssociationId": association_id, "NetworkAclId": ident}))
            after_subnets = {subnet for acl in after.vpc.nacls for subnet in acl.associated_subnet_ids}
            for subnet in removed:
                if subnet not in after_subnets: err("subnet_without_network_acl")
        unknown = set(fields) - {"entries", "associated_subnet_ids"}
        for field in sorted(unknown): err(f"field_not_mapped: {field}")
        return result, errors
    if typ == "network_acl" and op == "delete":
        return [call("ec2", "DeleteNetworkAcl", {"NetworkAclId": ident})], errors
    if typ == "route_table" and op == "modify" and set(fields) == {"routes"}:
        old = {x.destination_cidr:x for x in _resource(before, typ, ident).routes}; new={x.destination_cidr:x for x in _resource(after, typ, ident).routes}; result=[]
        def base(route): return {"RouteTableId":ident, ("DestinationIpv6CidrBlock" if ":" in route.destination_cidr else "DestinationCidrBlock"):route.destination_cidr}
        for destination in sorted(set(old)|set(new)):
            if destination not in new: result.append(call("ec2", "DeleteRoute", base(old[destination])))
            elif destination not in old:
                target=_target(new[destination]);
                if target is None: err(f"unmappable route target_type: {new[destination].target_type}")
                else: p=base(new[destination]); p[target[0]]=target[1]; result.append(call("ec2", "CreateRoute", p))
            elif old[destination].target_type != new[destination].target_type or old[destination].target_id != new[destination].target_id:
                target=_target(new[destination]);
                if target is None: err(f"unmappable route target_type: {new[destination].target_type}")
                else: p=base(new[destination]); p[target[0]]=target[1]; result.append(call("ec2", "ReplaceRoute", p))
        return result, errors
    err("operation_or_resource_not_mapped")
    return [], errors


def build_api_calls(base: AWSInfrastructure, changes: list[Change]) -> list[dict]:
    state = base
    calls: list[dict] = []
    errors: list[dict] = []
    for index, change in enumerate(changes):
        try:
            if change.op != "add" and change.resource_type in {"security_group", "ec2_instance", "rds_instance", "s3_bucket", "lambda_function", "ebs_volume", "ebs_snapshot", "rds_snapshot", "route_table", "network_acl"}:
                try:
                    found = _resource(state, change.resource_type, change.resource_id)
                except Exception:
                    found = None
                if found is None:
                    errors.append({"change_index": index, "op": change.op, "resource_type": change.resource_type, "reason": "resource_not_found"})
                    continue
            after = apply_changes(state, [change])
            generated, item_errors = _calls_for(state, change, after, index)
        except Exception as exc:
            errors.append({"change_index": index, "op": change.op, "resource_type": change.resource_type, "reason": f"build_failed:{type(exc).__name__}"})
            continue
        calls.extend(generated); errors.extend(item_errors); state = after
    for item in calls:
        model = _SESSION.get_service_model(item["service"]).operation_model(item["operation"])
        report = ParamValidator().validate(item["params"], model.input_shape)
        if report.has_errors():
            errors.append({"change_index": item["change_index"], "op": changes[item["change_index"]].op, "resource_type": changes[item["change_index"]].resource_type, "reason": f"botocore_validation_failed: {report}"})
    if errors: raise UnmappableChanges(errors)
    return calls
