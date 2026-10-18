"""Translate Terraform show -json plans into normalized branch mutations."""
from __future__ import annotations

from typing import Any
import copy

from app.mutations import Change
from app.aws_api_ingest import remove_security_group_rule

_AWS_PROVIDER_TYPES = {"aws", "awscc"}


def is_aws_provider(provider_name: Any) -> bool:
    """AWS = provider type (last path segment of provider_name) is aws or awscc.
    A missing/blank/non-string provider_name counts as AWS (fail closed).
    """
    if not isinstance(provider_name, str) or not provider_name.strip():
        return True
    return provider_name.strip().rstrip("/").rsplit("/", 1)[-1].lower() in _AWS_PROVIDER_TYPES


_UNSEEN_TERRAFORM_TYPES = frozenset({"aws_default_security_group"})
_TERRAFORM_RULE_TYPES = frozenset({
    "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
    "aws_security_group_rule",
})

_RESOURCE_MAP = {
    "aws_instance": ("ec2_instance", "id"),
    "aws_db_instance": ("rds_instance", "identifier"),
    "aws_security_group": ("security_group", "id"),
    "aws_s3_bucket": ("s3_bucket", "bucket"),
    "aws_lambda_function": ("lambda_function", "function_name"),
    "aws_ebs_volume": ("ebs_volume", "id"),
    "aws_ebs_snapshot": ("ebs_snapshot", "id"),
    "aws_db_snapshot": ("rds_snapshot", "db_snapshot_identifier"),
    "aws_iam_role": ("iam_role", "arn"),
}
_DELETE_ORDER = ["ec2_instance", "lambda_function", "rds_instance", "ebs_volume",
                 "ebs_snapshot", "rds_snapshot", "s3_bucket", "security_group", "iam_role"]


def _unknown(change: dict, address: str, field: str, unknown: list[dict], reason: str | None = None) -> bool:
    if field in (change.get("after_unknown") or {}):
        item = {"address": address, "field": field}
        if reason:
            item["reason"] = reason
        unknown.append(item)
        return True
    return False


def _rules(value: Any) -> list[dict]:
    result = []
    for item in value or []:
        if not isinstance(item, dict):
            continue
        result.append({
            "from_port": item.get("from_port"), "to_port": item.get("to_port"),
            "protocol": str(item.get("protocol", "-1")),
            "ip_ranges": item.get("cidr_blocks", item.get("ip_ranges", [])) or [],
            "source_sg_ids": item.get("security_groups", item.get("source_sg_ids", [])) or [],
            "dest_sg_ids": item.get("dest_sg_ids", []) or [],
        })
    return result


def _rules(value: Any) -> list[dict]:
    result = []
    for item in value or []:
        if not isinstance(item, dict):
            continue
        ranges = item.get("cidr_blocks", item.get("ip_ranges", [])) or []
        ranges = list(ranges) + list(item.get("ipv6_cidr_blocks", []) or [])
        result.append({
            "from_port": item.get("from_port"), "to_port": item.get("to_port"),
            "protocol": str(item.get("protocol", "-1")),
            "ip_ranges": ranges,
            "source_sg_ids": item.get("security_groups", item.get("source_sg_ids", [])) or [],
            "dest_sg_ids": item.get("dest_sg_ids", []) or [],
        })
    return result


def _terraform_rule(typ: str, value: dict, parent_id: str) -> tuple[str, dict]:
    ingress = typ.endswith("ingress_rule") or (typ == "aws_security_group_rule" and value.get("type", "ingress") == "ingress")
    ranges = []
    groups = []
    if typ == "aws_security_group_rule":
        ranges = list(value.get("cidr_blocks", []) or []) + list(value.get("ipv6_cidr_blocks", []) or [])
        groups = list(value.get("security_groups", []) or [])
        if value.get("source_security_group_id"):
            groups.append(value["source_security_group_id"])
        if value.get("self"):
            groups.append(parent_id)
        protocol = value.get("protocol", "-1")
    else:
        if value.get("cidr_ipv4"):
            ranges.append(value["cidr_ipv4"])
        if value.get("cidr_ipv6"):
            ranges.append(value["cidr_ipv6"])
        if value.get("referenced_security_group_id"):
            groups.append(value["referenced_security_group_id"])
        protocol = value.get("ip_protocol", "-1")
    protocol = str(protocol)
    if protocol == "-1":
        from_port = to_port = None
    else:
        from_port = value.get("from_port")
        to_port = value.get("to_port")
    rule = {"from_port": from_port, "to_port": to_port,
            "protocol": str(protocol), "ip_ranges": ranges,
            "source_sg_ids": groups if ingress else [],
            "dest_sg_ids": groups if not ingress else []}
    return ("rules" if ingress else "egress_rules"), rule


def _rule_parent(item: dict, config_resources: dict[str, dict], created_ids: dict[str, str]) -> str | None:
    change = item.get("change") or {}
    before, after = change.get("before") or {}, change.get("after") or {}
    value = before if change.get("actions") == ["delete"] else after
    parent = value.get("security_group_id")
    if parent and "security_group_id" not in (change.get("after_unknown") or {}):
        return str(parent)
    expression = (config_resources.get(item.get("address"), {}).get("expressions") or {}).get("security_group_id", {})
    for reference in expression.get("references", []) or []:
        if reference in created_ids:
            return created_ids[reference]
        if reference.split(".")[0:2] == reference.split(".")[:2] and reference in created_ids:
            return created_ids[reference]
    return None


def _rule_change(item: dict, sg_rules: dict[str, list[dict]], config_resources: dict[str, dict], created_ids: dict[str, str], unknown_fields: list[dict]) -> tuple[list[Change], dict | None]:
    typ = item.get("type", "")
    parent = _rule_parent(item, config_resources, created_ids)
    actions = (item.get("change") or {}).get("actions", [])
    if not parent or parent not in sg_rules and parent not in created_ids.values():
        return [], {"address": item.get("address", ""), "type": typ, "actions": actions,
                     "provider_name": item.get("provider_name") if isinstance(item.get("provider_name"), str) else None,
                     "outside_view": False, "unseen": True, "unresolvable_parent": not bool(parent)}
    before, after = (item.get("change") or {}).get("before") or {}, (item.get("change") or {}).get("after") or {}
    field, after_rule = _terraform_rule(typ, after, parent)
    _, before_rule = _terraform_rule(typ, before, parent)
    current = {"rules": list(sg_rules.get(parent, [])), "egress_rules": []}
    if parent in sg_rules:
        current["egress_rules"] = []
    # Existing branch egress rules are supplied under a tagged mapping.
    existing = sg_rules.get(parent, [])
    if isinstance(existing, dict):
        current = {"rules": list(existing.get("rules", [])), "egress_rules": list(existing.get("egress_rules", []))}
    if field not in current:
        current[field] = []
    if actions == ["delete"]:
        target = before_rule
        remove_security_group_rule(current[field], target)
    elif actions == ["update"] or set(actions) == {"delete", "create"}:
        remove_security_group_rule(current[field], before_rule)
        current[field].append(after_rule)
    elif actions == ["create"]:
        if after_rule not in current[field]:
            current[field].append(after_rule)
    else:
        return [], None
    if current[field] == (existing.get(field, []) if isinstance(existing, dict) else existing) and actions == ["delete"]:
        return [], None
    sg_rules[parent] = current
    return [Change(op="modify", resource_type="security_group", resource_id=parent, fields=current)], None


def _fields(resource: str, change: dict, address: str, unknown: list[dict], *, update: bool = False) -> dict:
    after = change.get("after") or {}
    fields: dict[str, Any] = {}
    mappings = {
        "aws_instance": {"instance_type": "type", "subnet_id": "subnet_id",
            "vpc_security_group_ids": "sg_ids", "associate_public_ip_address": "has_public_ip"},
        "aws_db_instance": {"vpc_security_group_ids": "sg_ids", "publicly_accessible": "publicly_accessible",
            "storage_encrypted": "encrypted", "backup_retention_period": "backup_retention_days",
            "deletion_protection": "deletion_protection", "engine": "engine"},
    }
    supported = mappings.get(resource, {})
    if update:
        allowed = {"aws_security_group": {"ingress"}, "aws_db_instance": {"backup_retention_period", "deletion_protection"}}
        supported = {key: value for key, value in supported.items() if key in allowed.get(resource, set())}
    if resource == "aws_security_group":
        if "name" in after:
            fields["name"] = after["name"]
        if "ingress" in after and not _unknown(change, address, "ingress", unknown):
            fields["rules"] = _rules(after.get("ingress"))
    for source, target in supported.items():
        if update and (change.get("before") or {}).get(source) == after.get(source):
            continue
        if source in (change.get("after_unknown") or {}):
            _unknown(change, address, source, unknown)
            continue
        if source in after:
            fields[target] = after[source]
    if resource == "aws_instance":
        if "metadata_options" in after and not update and not _unknown(change, address, "metadata_options", unknown):
            metadata = after.get("metadata_options") or {}
            if "http_tokens" in metadata and not _unknown(change, address, "metadata_options.http_tokens", unknown):
                fields["imdsv2_required"] = metadata.get("http_tokens") == "required"
        if not update:
            fields.setdefault("state", "running")
    return fields


def _nacl_defaults() -> list[dict]:
    return [{"rule_number": 32767, "protocol": "-1", "rule_action": "deny", "egress": egress,
             "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": None, "port_from": None, "port_to": None}
            for egress in (False, True)]


def _nacl_entry(value: dict, egress: bool) -> dict:
    return {"rule_number": value.get("rule_number", value.get("rule_no")),
            "protocol": str(value.get("protocol", "-1")),
            "rule_action": value.get("rule_action", value.get("action", "deny")),
            "egress": egress, "cidr_block": value.get("cidr_block"),
            "ipv6_cidr_block": value.get("ipv6_cidr_block"),
            "port_from": value.get("from_port"), "port_to": value.get("to_port")}


def _nacl_inline(after: dict, *, authoritative: bool = False) -> list[dict]:
    entries = []
    for name, egress in (("ingress", False), ("egress", True)):
        for value in after.get(name, []) or []:
            if isinstance(value, dict):
                entries.append(_nacl_entry(value, egress))
    if not entries and not authoritative:
        return _nacl_defaults()
    if authoritative:
        entries.extend(_nacl_defaults())
    return entries


def _nacl_value(item: dict, field: str, unknown: list[dict], value: dict) -> Any:
    change = item.get("change") or {}
    if field in (change.get("after_unknown") or {}):
        unknown.append({"address": item.get("address", ""), "field": field,
                        "reason": "unknown Terraform value"})
        return None
    return value.get(field)


def _nacl_changes(item: dict, nacls: dict[str, Any], config_resources: dict[str, dict],
                  created_ids: dict[str, str], unknown: list[dict], acl_counter: list[int]) -> tuple[list[Change], dict | None]:
    change = item.get("change") or {}; actions = change.get("actions", []); address = item.get("address", "")
    typ = item.get("type", ""); before = change.get("before") or {}; after = change.get("after") or {}
    value = before if actions == ["delete"] else after
    if typ == "aws_network_acl_rule":
        acl_id = _nacl_value(item, "network_acl_id", unknown, value)
        if acl_id is None:
            for reference in ((config_resources.get(address, {}).get("expressions") or {}).get("network_acl_id", {}).get("references", []) or []):
                if reference in created_ids:
                    acl_id = created_ids[reference]
                    unknown[:] = [entry for entry in unknown if not (entry.get("address") == address and entry.get("field") == "network_acl_id")]
                    break
        if not acl_id or str(acl_id) not in nacls:
            return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws",
                         "outside_view": False, "unseen": True, "detail": "network ACL id not in snapshot"}
        acl_id = str(acl_id); current = copy.deepcopy(nacls[acl_id].get("entries", []))
        def key(entry): return (entry.get("rule_number"), entry.get("egress"))
        old = _nacl_entry(before, bool(before.get("egress", False)))
        new = _nacl_entry(after, bool(after.get("egress", False)))
        if actions == ["delete"]:
            current = [entry for entry in current if key(entry) != key(old)]
        else:
            current = [entry for entry in current if key(entry) != key(old if actions != ["create"] else new)]
            current.append(new)
        nacls[acl_id]["entries"] = current
        return [Change(op="modify", resource_type="network_acl", resource_id=acl_id, fields={"entries": current})], None
    if typ == "aws_network_acl_association":
        subnet = _nacl_value(item, "subnet_id", unknown, value)
        target = _nacl_value(item, "network_acl_id", unknown, value)
        if target is None:
            for reference in ((config_resources.get(address, {}).get("expressions") or {}).get("network_acl_id", {}).get("references", []) or []):
                if reference in created_ids:
                    target = created_ids[reference]
                    unknown[:] = [entry for entry in unknown if not (entry.get("address") == address and entry.get("field") == "network_acl_id")]
                    break
        if not subnet or not target:
            return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws", "outside_view": False, "unseen": True, "detail": "association value unknown"}
        subnet, target = str(subnet), str(target)
        if actions == ["delete"]:
            vpc_id = next((a.get("vpc_id") for a in nacls.values() if subnet in a.get("associated_subnet_ids", [])), None)
            target = next((aid for aid, a in nacls.items() if a.get("vpc_id") == vpc_id and a.get("is_default")), None)
        if not target or target not in nacls:
            return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws", "outside_view": False, "unseen": True, "detail": "network ACL association target not in snapshot"}
        associated = list(nacls[target].get("associated_subnet_ids", []));
        if subnet not in associated: associated.append(subnet)
        nacls[target]["associated_subnet_ids"] = associated
        return [Change(op="modify", resource_type="network_acl", resource_id=target, fields={"associated_subnet_ids": associated})], None
    if typ == "aws_network_acl":
        if actions == ["delete"]:
            acl_id = before.get("id") or before.get("network_acl_id")
            if not acl_id or str(acl_id) not in nacls:
                return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws", "outside_view": False, "unseen": True, "detail": "network ACL id not in snapshot"}
            return [Change(op="delete", resource_type="network_acl", resource_id=str(acl_id))], None
        acl_id = after.get("id")
        if not acl_id:
            acl_counter[0] += 1; acl_id = f"acl-new-{acl_counter[0]}"; created_ids[address] = acl_id; created_ids[address + ".id"] = acl_id
        acl_id = str(acl_id)
        vpc_id = after.get("vpc_id")
        if not vpc_id or "vpc_id" in (change.get("after_unknown") or {}):
            return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws", "outside_view": False, "unseen": True, "detail": "VPC id unknown"}
        fields = {"vpc_id": vpc_id}
        if actions == ["create"] or "ingress" in after or "egress" in after:
            fields["entries"] = _nacl_inline(after)
        if "subnet_ids" in after: fields["associated_subnet_ids"] = after.get("subnet_ids") or []
        nacls[acl_id] = {"id": acl_id, "vpc_id": vpc_id, "entries": fields.get("entries", _nacl_defaults()), "associated_subnet_ids": fields.get("associated_subnet_ids", [])}
        return [Change(op="add" if actions == ["create"] else "modify", resource_type="network_acl", resource_id=acl_id, fields=fields if actions == ["create"] else {k: v for k, v in fields.items() if k != "vpc_id"})], None
    if typ == "aws_default_network_acl":
        acl_id = after.get("default_network_acl_id") or before.get("default_network_acl_id")
        if not acl_id or str(acl_id) not in nacls:
            return [], {"address": address, "type": typ, "actions": actions, "provider_name": "aws", "outside_view": False, "unseen": True, "detail": "default network ACL id not in snapshot"}
        fields = {}
        if "ingress" in after or "egress" in after: fields["entries"] = _nacl_inline(after, authoritative=True)
        if "subnet_ids" in after: fields["associated_subnet_ids"] = after.get("subnet_ids") or []
        if not fields: return [], None
        return [Change(op="modify", resource_type="network_acl", resource_id=str(acl_id), fields=fields)], None
    return [], None


def _translate_item(item: dict, unknown_fields: list[dict], *, sg_rules: dict[str, Any] | None = None, config_resources: dict[str, dict] | None = None, created_ids: dict[str, str] | None = None, nacls: dict[str, Any] | None = None, acl_counter: list[int] | None = None) -> tuple[list[Change], dict | None]:
    if item.get("mode", "managed") != "managed":
        return [], None
    address = item.get("address", "")
    typ = item.get("type", "")
    actions = item.get("change", {}).get("actions", [])
    if actions in (["no-op"], ["read"]):
        return [], None
    provider_name = item.get("provider_name")
    if not is_aws_provider(provider_name):
        return [], {"address": address, "type": typ, "actions": actions,
                     "provider_name": provider_name, "outside_view": True}
    if typ in {"aws_network_acl", "aws_network_acl_rule", "aws_network_acl_association", "aws_default_network_acl"}:
        return _nacl_changes(item, nacls or {}, config_resources or {}, created_ids or {}, unknown_fields, acl_counter or [0])
    if typ in _UNSEEN_TERRAFORM_TYPES:
        return [], {"address": address, "type": typ, "actions": actions,
                     "provider_name": provider_name if isinstance(provider_name, str) else None,
                     "outside_view": False, "unseen": True}
    if typ in _TERRAFORM_RULE_TYPES:
        return _rule_change(item, sg_rules or {}, config_resources or {}, created_ids or {}, unknown_fields)
    if typ not in _RESOURCE_MAP:
        return [], {"address": address, "type": typ, "actions": actions,
                     "provider_name": provider_name if isinstance(provider_name, str) else None,
                     "outside_view": False}
    resource, id_key = _RESOURCE_MAP[typ]
    change = item.get("change") or {}
    before, after = change.get("before") or {}, change.get("after") or {}
    resource_id = (before if actions == ["delete"] or actions in (["delete", "create"], ["create", "delete"]) else after).get(id_key)
    if resource_id is None:
        resource_id = (before or after).get("id", "")
    result: list[Change] = []
    if actions == ["delete"] or actions in (["delete", "create"], ["create", "delete"]):
        options = {}
        if typ == "aws_db_instance":
            for source, target in (("skip_final_snapshot", "skip_final_snapshot"),
                                   ("final_snapshot_identifier", "final_db_snapshot_identifier"),
                                   ("delete_automated_backups", "delete_automated_backups")):
                if source in before and before[source] is not None:
                    options[target] = before[source]
        result.append(Change(op="delete", resource_type=resource, resource_id=str(resource_id or ""), fields=options))
    if actions == ["create"] or actions in (["delete", "create"], ["create", "delete"]):
        fields = _fields(typ, change, address, unknown_fields)
        if resource in {"lambda_function", "s3_bucket", "ebs_volume", "ebs_snapshot", "rds_snapshot", "iam_role"}:
            fields = {}
        result.append(Change(op="add", resource_type=resource, resource_id=str((after or {}).get(id_key, resource_id) or ""), fields=fields))
    elif actions == ["update"]:
        fields = _fields(typ, change, address, unknown_fields, update=True)
        supported = {"aws_security_group": {"ingress"}, "aws_db_instance": {"backup_retention_period", "deletion_protection"}}
        for field in (change.get("before", {}) or {}):
            if (change.get("before") or {}).get(field) != (after or {}).get(field) and field not in supported.get(typ, set()):
                if field not in (change.get("after_unknown") or {}):
                    unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})
        if fields:
            result.append(Change(op="modify", resource_type=resource, resource_id=str(resource_id or ""), fields=fields))
    return result, None


def translate_plan(plan: Any, sg_rules: dict[str, Any] | None = None, nacls: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ValueError("Terraform plan must be a JSON object")
    if not isinstance(plan.get("format_version"), str) or not plan["format_version"].startswith("1."):
        raise ValueError("Terraform plan format_version must start with '1.'")
    if not isinstance(plan.get("resource_changes"), list):
        raise ValueError("Terraform plan resource_changes must be a list")
    unknown_fields: list[dict] = []
    unmodeled: list[dict] = []
    sg_rules = sg_rules if sg_rules is not None else {}
    nacls = nacls if nacls is not None else {}
    nacls = {key: (value.model_dump() if hasattr(value, "model_dump") else copy.deepcopy(value)) for key, value in nacls.items()}
    config_resources = {
        resource.get("address"): resource for resource in ((plan.get("configuration") or {}).get("root_module") or {}).get("resources", [])
        if isinstance(resource, dict) and isinstance(resource.get("address"), str)
    }
    created_ids = {}
    acl_counter = [0]
    for resource in plan["resource_changes"]:
        if isinstance(resource, dict) and resource.get("type") == "aws_security_group":
            after = (resource.get("change") or {}).get("after") or {}
            if after.get("id"):
                created_ids[resource.get("address")] = str(after["id"])
                created_ids[resource.get("address") + ".id"] = str(after["id"])
    deletes: list[tuple[Change, str, dict]] = []
    modifies: list[tuple[Change, str, dict]] = []
    adds: list[tuple[Change, str, dict]] = []
    for item in plan["resource_changes"]:
        if not isinstance(item, dict):
            raise ValueError("Terraform plan resource_changes entries must be objects")
        change = item.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if (not isinstance(change, dict) or not isinstance(actions, list)
                or not actions or not all(isinstance(action, str) for action in actions)):
            raise ValueError("Terraform plan change actions must be a non-empty list of strings")
        changes, unsupported = _translate_item(item, unknown_fields, sg_rules=sg_rules,
                                                 config_resources=config_resources, created_ids=created_ids,
                                                 nacls=nacls, acl_counter=acl_counter)
        if unsupported:
            unmodeled.append(unsupported)
        for change in changes:
            target = deletes if change.op == "delete" else modifies if change.op == "modify" else adds
            target.append((change, item.get("address", ""), item))
    sg_delete = {c.resource_id: (c, a, i) for c, a, i in deletes if c.resource_type == "security_group"}
    ordered_sg: list[tuple[Change, str, dict]] = []
    remaining = dict(sg_delete)
    while remaining:
        ready = sorted(k for k, (_, _, item) in remaining.items()
                       if not any(ref in remaining for rule in ((item.get("change") or {}).get("before") or {}).get("ingress", []) or []
                                  for ref in (rule.get("security_groups", []) if isinstance(rule, dict) else [])))
        if not ready:
            ready = [sorted(remaining)[0]]
        for key in ready:
            ordered_sg.append(remaining.pop(key))
    deletes = [x for x in deletes if x[0].resource_type != "security_group"]
    deletes.sort(key=lambda x: (_DELETE_ORDER.index(x[0].resource_type), x[1]))
    deletes.extend(ordered_sg)
    ordered = deletes + sorted(
        modifies + adds,
        key=lambda item: (
            0 if item[0].op == "add" and item[0].resource_type == "security_group" else
            1 if item[0].op == "modify" else 2,
            item[1],
        ),
    )
    return {"changes": [c for c, _, _ in ordered], "addresses": [a for _, a, _ in ordered],
            "unmodeled": unmodeled, "unknown_fields": unknown_fields}
