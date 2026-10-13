"""Translate Terraform show -json plans into normalized branch mutations."""
from __future__ import annotations

from typing import Any

from app.mutations import Change

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


def _translate_item(item: dict, unknown_fields: list[dict]) -> tuple[list[Change], dict | None]:
    if item.get("mode", "managed") != "managed":
        return [], None
    address = item.get("address", "")
    typ = item.get("type", "")
    actions = item.get("change", {}).get("actions", [])
    if actions in (["no-op"], ["read"]):
        return [], None
    if typ not in _RESOURCE_MAP:
        return [], {"address": address, "type": typ, "actions": actions}
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


def translate_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ValueError("Terraform plan must be a JSON object")
    if not isinstance(plan.get("format_version"), str) or not plan["format_version"].startswith("1."):
        raise ValueError("Terraform plan format_version must start with '1.'")
    if not isinstance(plan.get("resource_changes"), list):
        raise ValueError("Terraform plan resource_changes must be a list")
    unknown_fields: list[dict] = []
    unmodeled: list[dict] = []
    deletes: list[tuple[Change, str, dict]] = []
    modifies: list[tuple[Change, str, dict]] = []
    adds: list[tuple[Change, str, dict]] = []
    for item in plan["resource_changes"]:
        if not isinstance(item, dict):
            raise ValueError("Terraform plan resource_changes entries must be objects")
        changes, unsupported = _translate_item(item, unknown_fields)
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
    ordered = deletes + modifies + adds
    return {"changes": [c for c, _, _ in ordered], "addresses": [a for _, a, _ in ordered],
            "unmodeled": unmodeled, "unknown_fields": unknown_fields}
