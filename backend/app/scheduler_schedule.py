"""AWS adapter helpers for EventBridge Scheduler schedules.

One place for the parts every input shares: the ``group/name`` identity, AWS's
documented defaults, timestamps, the settings Emfirge does not store, and the
translation of CreateSchedule / UpdateSchedule parameters into branch fields.

Collector, mutations, API / CLI / CloudFormation / Terraform ingest and hand-back
all use these, so the four input formats cannot drift apart.

Never stored: the Target.Input payload (it can hold secrets). Only whether one is
set (``has_input``) and the names of other unmodeled members are kept.
"""
from __future__ import annotations

from datetime import timezone
from typing import Any, Optional

from botocore.utils import parse_to_aware_datetime

from app.field_catalog import Aws, _check, resolve

DEFAULT_GROUP = "default"

# CreateSchedule documents these defaults for omitted members; UpdateSchedule is a
# full replace, so an omitted member goes back to them (State to ENABLED).
AWS_DEFAULTS = {
    "state": "ENABLED",
    "schedule_expression_timezone": "UTC",
    "action_after_completion": "NONE",
}
# AWS always reports a retry policy; the default is the same as leaving it out.
DEFAULT_RETRY_POLICY = {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185}

# Branch fields a change may set (the schedule's identity and ARN are never fields).
SETTABLE_FIELDS = (
    "state", "schedule_expression", "schedule_expression_timezone", "flexible_time_window_mode",
    "flexible_time_window_minutes", "target_arn", "target_role_arn", "start_date", "end_date",
    "action_after_completion", "has_input", "unmodeled_settings",
)
# Members every CreateSchedule / UpdateSchedule call must carry: (API path, branch field).
REQUIRED_MEMBERS = (
    ("ScheduleExpression", "schedule_expression"),
    ("FlexibleTimeWindow", "flexible_time_window_mode"),
    ("Target.Arn", "target_arn"),
    ("Target.RoleArn", "target_role_arn"),
)
_TOP_LEVEL = {
    "State": "state", "ScheduleExpression": "schedule_expression",
    "ScheduleExpressionTimezone": "schedule_expression_timezone", "StartDate": "start_date",
    "EndDate": "end_date", "ActionAfterCompletion": "action_after_completion",
}
_CALL_ONLY = {"Name", "GroupName", "ClientToken", "FlexibleTimeWindow", "Target", "DryRun"}
_UNMODELED_TOP = ("Description", "KmsKeyArn")
_UNMODELED_TARGET = ("DeadLetterConfig", "EcsParameters", "EventBridgeParameters", "KinesisParameters",
                     "RetryPolicy", "SageMakerPipelineParameters", "SqsParameters")
_NAME = Aws("scheduler", "CreateSchedule", "Name")
_GROUP = Aws("scheduler", "CreateSchedule", "GroupName")


def identity(group: str, name: str) -> str:
    return f"{group or DEFAULT_GROUP}/{name}"


def split_identity(resource_id: Any) -> tuple[str, str]:
    """``group/name`` (or a bare name in the default group), checked against AWS's own limits."""
    if not isinstance(resource_id, str) or not resource_id:
        raise ValueError("scheduler_schedule resource_id: expected <group>/<name> or a name in the default group")
    parts = resource_id.split("/")
    if len(parts) > 2:
        raise ValueError("scheduler_schedule resource_id: expected <group>/<name>")
    group, name = (DEFAULT_GROUP, parts[0]) if len(parts) == 1 else parts
    _check("scheduler_schedule.name", _NAME, resolve(_NAME), name)
    _check("scheduler_schedule.group_name", _GROUP, resolve(_GROUP), group)
    return group, name


def normalize_timestamp(value: Any) -> str:
    """One text form (UTC, second precision) for a timestamp from any input."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)) and not hasattr(value, "isoformat"):
        raise ValueError("expected a timestamp")
    try:
        moment = parse_to_aware_datetime(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("expected a timestamp") from exc
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _set(value: Any) -> bool:
    return value not in (None, "", [], {})


def unmodeled_settings(schedule: dict[str, Any]) -> list[str]:
    """Names of members set on a schedule (CreateSchedule/GetSchedule shape) that Emfirge does not store."""
    names = [key for key in _UNMODELED_TOP if _set(schedule.get(key))]
    target = schedule.get("Target") if isinstance(schedule.get("Target"), dict) else {}
    for key in _UNMODELED_TARGET:
        value = target.get(key)
        if key == "RetryPolicy" and value == DEFAULT_RETRY_POLICY:
            continue
        if _set(value):
            names.append(f"Target.{key}")
    return names


def api_fields(parameters: dict[str, Any], *, replace: bool) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Branch fields for CreateSchedule (``replace=False``) or UpdateSchedule (``replace=True``) parameters.

    Returns (fields, problems); a problem is (API member, reason). Required members a call
    leaves out are problems and are not defaulted. UpdateSchedule replaces everything, so
    the members it leaves out are set to AWS's documented default or cleared.
    """
    fields: dict[str, Any] = {}
    problems: list[tuple[str, str]] = []
    for member, field in _TOP_LEVEL.items():
        if member in parameters and parameters[member] is not None:
            value = parameters[member]
            if field in {"start_date", "end_date"}:
                try:
                    value = normalize_timestamp(value)
                except ValueError:
                    problems.append((member, "invalid_value"))
                    continue
            fields[field] = value
        elif replace and field != "schedule_expression":
            fields[field] = AWS_DEFAULTS.get(field)
    window = parameters.get("FlexibleTimeWindow")
    window = window if isinstance(window, dict) else {}
    target = parameters.get("Target")
    target = target if isinstance(target, dict) else {}
    if window.get("Mode") is not None:
        fields["flexible_time_window_mode"] = window["Mode"]
    if window.get("MaximumWindowInMinutes") is not None:
        fields["flexible_time_window_minutes"] = window["MaximumWindowInMinutes"]
    elif replace:
        fields["flexible_time_window_minutes"] = None
    if target.get("Arn") is not None:
        fields["target_arn"] = target["Arn"]
    if target.get("RoleArn") is not None:
        fields["target_role_arn"] = target["RoleArn"]
    for path, field in REQUIRED_MEMBERS:
        if field not in fields:
            problems.append((path, "required_member_missing"))
    fields["has_input"] = _set(target.get("Input"))
    fields["unmodeled_settings"] = unmodeled_settings(parameters)
    return fields, problems


def unsupported_members(parameters: dict[str, Any]) -> list[str]:
    """Members present in the call that Emfirge does not model (reported as unknown fields)."""
    names = [key for key in _UNMODELED_TOP if _set(parameters.get(key))]
    target = parameters.get("Target") if isinstance(parameters.get("Target"), dict) else {}
    names += [f"Target.{key}" for key in _UNMODELED_TARGET if _set(target.get(key)) and not (key == "RetryPolicy" and target[key] == DEFAULT_RETRY_POLICY)]
    known_top = set(_TOP_LEVEL) | _CALL_ONLY | set(_UNMODELED_TOP)
    names += [key for key in parameters if key not in known_top]
    known_target = {"Arn", "RoleArn", "Input"} | set(_UNMODELED_TARGET)
    names += [f"Target.{key}" for key in target if key not in known_target]
    return names


def aws_schedule_fields(schedule: dict[str, Any]) -> dict[str, Any]:
    """SchedulerSchedule keyword values from a GetSchedule (or ListSchedules summary) response.

    The Target.Input payload is read only to say whether one exists.
    """
    window = schedule.get("FlexibleTimeWindow") or {}
    target = schedule.get("Target") or {}
    values: dict[str, Any] = {
        "name": schedule.get("Name"),
        "group_name": schedule.get("GroupName") or DEFAULT_GROUP,
        "arn": schedule.get("Arn"),
        "state": schedule.get("State"),
        "schedule_expression": schedule.get("ScheduleExpression"),
        "schedule_expression_timezone": schedule.get("ScheduleExpressionTimezone"),
        "flexible_time_window_mode": window.get("Mode"),
        "flexible_time_window_minutes": window.get("MaximumWindowInMinutes"),
        "target_arn": target.get("Arn"),
        "target_role_arn": target.get("RoleArn"),
        "action_after_completion": schedule.get("ActionAfterCompletion"),
        "has_input": _set(target.get("Input")) if "Target" in schedule and "Arn" in target and "RoleArn" in target else None,
        "unmodeled_settings": unmodeled_settings(schedule),
    }
    for member, field in (("StartDate", "start_date"), ("EndDate", "end_date")):
        value = schedule.get(member)
        values[field] = normalize_timestamp(value) if value is not None else None
    return values


def lambda_function_name(arn: Optional[str]) -> Optional[str]:
    """Function name from a Lambda function ARN (qualifier dropped); None for anything else."""
    if not isinstance(arn, str) or ":lambda:" not in arn or ":function:" not in arn:
        return None
    return arn.split(":function:", 1)[1].split(":", 1)[0] or None
