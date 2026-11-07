"""DynamoDB table parsing shared by the collector, mutations and the ingest formats.

Adapter module (AWS specific). What a branch can change on a table is exactly what AWS lets one
call change: point-in-time recovery (UpdateContinuousBackups) and deletion protection (UpdateTable).
Deleting a table is DeleteTable. Adding a table is not modeled.

Provider facts the judgment of a delete relies on live in the neutral core (``delete_lens``) with
their documentation URLs; this module only translates calls and templates into branch fields.
"""
from __future__ import annotations

from typing import Any

# Reads the collector makes (and the IAM role must cover, pinned by a law).
COLLECTOR_OPERATIONS = ("ListTables", "DescribeTable", "DescribeContinuousBackups", "ListBackups")

# Branch field <- API member
SETTABLE_FIELDS = ("pitr_enabled", "deletion_protection_enabled")

# Members each API call accepts that the model carries; anything else is an unsupported attribute.
UPDATE_TABLE_MEMBERS = {"TableName", "DeletionProtectionEnabled"}
UPDATE_CONTINUOUS_BACKUPS_MEMBERS = {"TableName", "PointInTimeRecoverySpecification"}


def table_name(value: Any) -> str | None:
    """The table name from a TableName parameter, which AWS accepts as a name or a table ARN."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("arn:"):
        marker = ":table/"
        if marker not in value:
            return None
        name = value.split(marker, 1)[1].split("/", 1)[0]
        return name or None
    return value


def boolean(value: Any) -> bool | None:
    """A boolean from an API value or a CloudFormation / Terraform spelling; None when it is not a literal boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def api_fields(operation: str, parameters: dict[str, Any]) -> tuple[dict[str, Any], list[str], bool]:
    """Branch fields, unsupported member names and validity of one UpdateTable / UpdateContinuousBackups call.

    Validity is False when a member the model reads is present with a value that is not a boolean.
    """
    fields: dict[str, Any] = {}
    valid = True
    if operation == "UpdateTable":
        if "DeletionProtectionEnabled" in parameters:
            if isinstance(parameters["DeletionProtectionEnabled"], bool):
                fields["deletion_protection_enabled"] = parameters["DeletionProtectionEnabled"]
            else:
                valid = False
        unsupported = sorted(set(parameters) - UPDATE_TABLE_MEMBERS)
    else:
        spec = parameters.get("PointInTimeRecoverySpecification")
        if not isinstance(spec, dict) or not isinstance(spec.get("PointInTimeRecoveryEnabled"), bool):
            valid = False
        else:
            fields["pitr_enabled"] = spec["PointInTimeRecoveryEnabled"]
        unsupported = sorted(set(parameters) - UPDATE_CONTINUOUS_BACKUPS_MEMBERS)
        if isinstance(spec, dict):
            unsupported += sorted(f"PointInTimeRecoverySpecification.{key}" for key in set(spec) - {"PointInTimeRecoveryEnabled"})
    return fields, unsupported, valid


def cfn_calls(action: str, physical: Any, before: dict[str, Any], after: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """AWS::DynamoDB::Table Modify as the API calls it stands for; (calls, resolved).

    ``resolved`` is False when a property the model reads changed to a value that is not a literal.
    """
    name = after.get("TableName", before.get("TableName", physical))
    if not isinstance(name, str) or not name:
        return [], False
    calls: list[dict[str, Any]] = []
    old_spec, new_spec = before.get("PointInTimeRecoverySpecification"), after.get("PointInTimeRecoverySpecification")
    if "PointInTimeRecoverySpecification" in after and new_spec != old_spec:
        enabled = boolean(new_spec.get("PointInTimeRecoveryEnabled")) if isinstance(new_spec, dict) else None
        if enabled is None:
            return [], False
        calls.append({"service": "dynamodb", "operation": "UpdateContinuousBackups", "parameters": {
            "TableName": name, "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": enabled}}})
    if "DeletionProtectionEnabled" in after and after["DeletionProtectionEnabled"] != before.get("DeletionProtectionEnabled"):
        protected = boolean(after["DeletionProtectionEnabled"])
        if protected is None:
            return [], False
        calls.append({"service": "dynamodb", "operation": "UpdateTable", "parameters": {"TableName": name, "DeletionProtectionEnabled": protected}})
    return calls, True


def plan_fields(before: dict[str, Any], after: dict[str, Any], unknown: set[str]) -> tuple[dict[str, Any], list[str]]:
    """aws_dynamodb_table attributes that changed, as branch fields; plus the modeled paths unknown at plan time."""
    fields: dict[str, Any] = {}
    unknown_paths: list[str] = []

    def pitr(value: dict[str, Any]) -> bool | None:
        block = value.get("point_in_time_recovery")
        if isinstance(block, list) and block and isinstance(block[0], dict):
            return boolean(block[0].get("enabled"))
        return None

    if any(path == "point_in_time_recovery" or path.startswith("point_in_time_recovery.") for path in unknown):
        unknown_paths.append("point_in_time_recovery")
    else:
        new, old = pitr(after), pitr(before)
        if new is not None and new != old:
            fields["pitr_enabled"] = new
    if "deletion_protection_enabled" in unknown:
        unknown_paths.append("deletion_protection_enabled")
    else:
        new, old = boolean(after.get("deletion_protection_enabled")), boolean(before.get("deletion_protection_enabled"))
        if new is not None and new != old:
            fields["deletion_protection_enabled"] = new
    return fields, unknown_paths
