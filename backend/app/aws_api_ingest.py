from __future__ import annotations

from typing import Any, Callable

from app.mutations import Change


_DELETE_PREFIXES = ("Delete", "Terminate", "Purge", "Deregister", "Release", "Remove")
_READ_ONLY_PREFIXES = ("Describe", "List", "Get", "Head")
_INVALID_MESSAGE = "Invalid AWS API calls document"

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


def _unmodeled(address: str, service: str, operation: str) -> dict[str, Any]:
    actions = ["delete"] if operation.startswith(_DELETE_PREFIXES) else ["update"]
    return {"address": address, "type": f"{service}.{operation}", "actions": actions,
            "provider_name": "aws", "outside_view": False, "source": "aws_api"}


def translate_api_calls(
    doc: Any, resolve_role_arn: Callable[[str], str | None] | None = None,
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
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            raise _invalid()
        service = call.get("service")
        operation = call.get("operation")
        if not _valid_string(service) or not _valid_string(operation):
            raise _invalid()
        parameters = call.get("parameters", {})
        if not isinstance(parameters, dict):
            raise _invalid()
        if "region" in call and not isinstance(call["region"], str):
            raise _invalid()
        address = f"calls[{index}] {service}.{operation}"
        if parameters.get("DryRun") is True or operation.startswith(_READ_ONLY_PREFIXES):
            continue

        mapped = _MAPPED.get((service.lower(), operation))
        if mapped is None:
            unmodeled.append(_unmodeled(address, service.lower(), operation))
            continue
        resource_type, identifier, known = mapped
        # DeleteSecurityGroup with only GroupName cannot be modeled, but is a valid AWS call.
        if operation == "DeleteSecurityGroup" and "GroupId" not in parameters:
            unmodeled.append(_unmodeled(address, service.lower(), operation))
            continue
        _validate_identifier(operation, parameters, identifier)
        if operation == "DeleteDBInstance":
            for field in ("SkipFinalSnapshot", "DeleteAutomatedBackups"):
                if field in parameters and not isinstance(parameters[field], bool):
                    raise _invalid()
            if "FinalDBSnapshotIdentifier" in parameters and not _valid_string(parameters["FinalDBSnapshotIdentifier"]):
                raise _invalid()
        for field in parameters:
            if field not in known:
                unknown_fields.append({"address": address, "field": field, "reason": "unsupported_attribute"})

        if operation == "DeleteDBInstance":
            fields = {
                "skip_final_snapshot": parameters.get("SkipFinalSnapshot", False),
                "delete_automated_backups": parameters.get("DeleteAutomatedBackups", True),
            }
            if "FinalDBSnapshotIdentifier" in parameters:
                fields["final_db_snapshot_identifier"] = parameters["FinalDBSnapshotIdentifier"]
        else:
            fields = {}
        if operation == "DeleteFunction" and "Qualifier" in parameters:
            unmodeled.append(_unmodeled(address, service.lower(), operation))
            continue

        resource_id_values = parameters[identifier] if operation == "TerminateInstances" else [parameters[identifier]]
        for resource_id in resource_id_values:
            if operation == "DeleteFunction" and isinstance(resource_id, str) and resource_id.startswith("arn:"):
                marker = ":function:"
                if marker in resource_id:
                    resource_id = resource_id.split(marker, 1)[1].split(":", 1)[0]
            if operation == "DeleteRole" and resolve_role_arn is not None:
                resolved = resolve_role_arn(resource_id)
                if resolved:
                    resource_id = resolved
            changes.append(Change(op="delete", resource_type=resource_type,
                                  resource_id=resource_id, fields=fields.copy()))
            addresses.append(address)

    return {"changes": changes, "addresses": addresses, "unmodeled": unmodeled,
            "unknown_fields": unknown_fields}
