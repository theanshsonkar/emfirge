"""L75 EventBridge Scheduler schedules: collected, branchable, diffable, hand-back exact.

The incident behind this law: a deploy script ran `update-schedule --state ENABLED`
and a deliberately paused job ran again. The harness must see a schedule, its state
and its target, so a state flip on a branch is a visible fact.

L75a  collector reads state, expression and target; never stores the Input payload
L75b  denied / error collection is recorded and shows up as unknown in /context
L75c  add / modify / delete on a branch (typed, pure, AWS defaults, no guessing)
L75d  a state change is a modified resource with before/after values in the diff
L75e  UpdateSchedule is a full replace: omitted State means ENABLED, and a call that
      misses required members is an unknown field, never a silent default
L75f  API, CLI, Terraform and CloudFormation give the same branch
L75g  hand-back builds exact scheduler calls from botocore shapes, and refuses to
      rebuild a schedule whose settings Emfirge does not store
L75h  graph: invokes / uses_iam_role edges, dependency direction, delete lens
L75i  cost is usage based (unknown with a reason), schedules carry no tags
L75j  field catalog comes from botocore; the IAM read policy lists the scheduler reads
L75k  old snapshots still load; the scheduler code lives in adapter modules
"""
import json
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.exceptions import ClientError
from moto import mock_aws

from app.aws_api_ingest import translate_api_calls
from app.aws_cli_ingest import parse_cli_commands
from app.aws_collector import collect_scheduler
from app.aws_context import answer_for_infra
from app.cfn_ingest import convert_change_set
from app.cost import estimate_monthly_cost, unknown_reason
from app.delete_lens import analyze_deletions
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.field_catalog import CATALOG, resolve
from app.graph_schema import validate_graph
from app.models import AWSInfrastructure, SchedulerData, SchedulerSchedule
from app.mutations import Change, TargetNotFound, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from tests.incidents.synthetic_base import load_synthetic_base

REGION = "ap-south-1"
ACCOUNT = "000000000000"
LAMBDA_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:dl-worker"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/DlWorkerRole"
SQS_ARN = f"arn:aws:sqs:{REGION}:{ACCOUNT}:some-queue"
SECRET_INPUT = '{"api_key": "sk-live-planted-secret-zq7"}'
NIGHTLY = "default/nightly-report"
APP_DIR = Path(__file__).resolve().parents[2] / "app"


def schedule(name="nightly-report", group="default", state="DISABLED", target=LAMBDA_ARN, **extra):
    values = dict(
        name=name, group_name=group, arn=f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/{group}/{name}",
        state=state, schedule_expression="cron(0 2 * * ? *)", schedule_expression_timezone="UTC",
        flexible_time_window_mode="OFF", target_arn=target, target_role_arn=ROLE_ARN,
        action_after_completion="NONE", has_input=False)
    values.update(extra)
    return SchedulerSchedule(**values)


def base_with(*schedules):
    base = load_synthetic_base("delete")
    return base.model_copy(update={"scheduler": SchedulerData(schedules=list(schedules or [schedule()]))})


def find(infra, identity=NIGHTLY):
    return next(s for s in infra.scheduler.schedules if f"{s.group_name}/{s.name}" == identity)


# ── L75a collector ────────────────────────────────────────────────────────────

@pytest.fixture
def fake_aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        yield boto3.client("scheduler", region_name=REGION)


def _collect():
    warnings = []
    return collect_scheduler("testing", "testing", "testing", REGION, warnings), warnings


def test_L75a_collector_reads_state_and_target_but_never_the_input_payload(fake_aws):
    fake_aws.create_schedule(
        Name="nightly-report", ScheduleExpression="rate(5 minutes)", FlexibleTimeWindow={"Mode": "OFF"}, State="DISABLED",
        Target={"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN, "Input": SECRET_INPUT})
    fake_aws.create_schedule_group(Name="batch")
    fake_aws.create_schedule(
        Name="weekly", GroupName="batch", ScheduleExpression="cron(0 1 ? * MON *)", ScheduleExpressionTimezone="Asia/Kolkata",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 15}, ActionAfterCompletion="DELETE",
        StartDate="2030-01-01T00:00:00Z", Target={"Arn": SQS_ARN, "RoleArn": ROLE_ARN})
    data, warnings = _collect()
    assert data.collection_status == {"scheduler": "ok"} and warnings == []
    by_identity = {f"{s.group_name}/{s.name}": s for s in data.schedules}
    assert set(by_identity) == {NIGHTLY, "batch/weekly"}
    nightly = by_identity[NIGHTLY]
    assert (nightly.state, nightly.schedule_expression, nightly.target_arn, nightly.target_role_arn) == (
        "DISABLED", "rate(5 minutes)", LAMBDA_ARN, ROLE_ARN)
    assert nightly.arn == f"arn:aws:scheduler:{REGION}:123456789012:schedule/default/nightly-report"
    assert nightly.has_input is True
    weekly = by_identity["batch/weekly"]
    assert (weekly.state, weekly.schedule_expression_timezone, weekly.flexible_time_window_mode,
            weekly.flexible_time_window_minutes, weekly.action_after_completion, weekly.start_date) == (
        "ENABLED", "Asia/Kolkata", "FLEXIBLE", 15, "DELETE", "2030-01-01T00:00:00Z")
    assert weekly.has_input is False
    # AWS always reports its default retry policy; only a non-default one is an unmodeled setting.
    assert nightly.unmodeled_settings == [] and weekly.unmodeled_settings == []
    assert "planted-secret" not in data.model_dump_json()
    assert "sk-live" not in AWSInfrastructure(scheduler=data).model_dump_json()


def test_L75a_collector_lists_settings_it_does_not_store_by_name_only(fake_aws):
    fake_aws.create_schedule(
        Name="retry", ScheduleExpression="rate(1 hour)", FlexibleTimeWindow={"Mode": "OFF"}, Description="tells a story",
        Target={"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN, "RetryPolicy": {"MaximumRetryAttempts": 3}})
    data, _ = _collect()
    assert data.schedules[0].unmodeled_settings == ["Description", "Target.RetryPolicy"]
    assert "tells a story" not in data.model_dump_json()


def test_L75a_collector_is_paginated(fake_aws):
    for number in range(120):
        fake_aws.create_schedule(Name=f"s{number:03d}", ScheduleExpression="rate(1 day)", FlexibleTimeWindow={"Mode": "OFF"},
                                 Target={"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN})
    data, _ = _collect()
    assert len(data.schedules) == 120 and data.collection_status == {"scheduler": "ok"}


def test_L75a_collector_only_makes_read_calls(fake_aws, monkeypatch):
    from botocore.client import BaseClient

    fake_aws.create_schedule(Name="x", ScheduleExpression="rate(1 day)", FlexibleTimeWindow={"Mode": "OFF"},
                             Target={"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN})
    seen = []
    original = BaseClient._make_api_call
    monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (seen.append(op), original(self, op, params))[1])
    _collect()
    assert seen and set(seen) <= {"ListSchedules", "GetSchedule", "ListScheduleGroups"}


# ── L75b denied / error ────────────────────────────────────────────────────────

def _fail_scheduler(monkeypatch, code, operations=("ListSchedules",)):
    from botocore.client import BaseClient

    original = BaseClient._make_api_call

    def patched(self, operation_name, params):
        if operation_name in operations:
            raise ClientError({"Error": {"Code": code, "Message": f"arn:aws:scheduler:{REGION}:123456789012:schedule/default/x"}}, operation_name)
        return original(self, operation_name, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)


@pytest.mark.parametrize("code, status", [("AccessDeniedException", "denied"), ("InternalServerException", "error")])
def test_L75b_failed_collection_is_recorded_not_empty(fake_aws, monkeypatch, code, status):
    _fail_scheduler(monkeypatch, code)
    data, warnings = _collect()
    assert data.schedules == [] and data.collection_status == {"scheduler": status}
    assert warnings and "arn:aws" not in " ".join(warnings)


def test_L75b_a_denied_get_schedule_keeps_what_the_list_gave_and_marks_it_denied(fake_aws, monkeypatch):
    fake_aws.create_schedule(Name="x", ScheduleExpression="rate(1 day)", FlexibleTimeWindow={"Mode": "OFF"}, State="DISABLED",
                             Target={"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN})
    _fail_scheduler(monkeypatch, "AccessDeniedException", ("GetSchedule",))
    data, _ = _collect()
    only = data.schedules[0]
    assert (only.state, only.target_arn) == ("DISABLED", LAMBDA_ARN)
    assert only.schedule_expression is None and only.has_input is None
    assert data.collection_status == {"scheduler": "denied"}


def test_L75b_denied_collection_is_unknown_in_context_and_ok_is_known():
    for status in ("denied", "error"):
        infra = base_with()
        infra.collection = {**infra.collection, "scheduler": status}
        for question in ("inventory", "resource", "depends_on", "dependents", "baseline"):
            body = answer_for_infra(question, infra, analysis_id="a", resource_id=NIGHTLY if question in {"resource", "depends_on", "dependents"} else None).model_dump(mode="json")
            reasons = {u["topic"]: u["reason"] for u in body["unknown"]}
            assert status in reasons.get("scheduler", ""), (question, reasons)
            assert "scheduler" not in {k["topic"] for k in body["known"]}
    ok = base_with()
    ok.collection = {**ok.collection, "scheduler": "ok"}
    body = answer_for_infra("inventory", ok, analysis_id="a").model_dump(mode="json")
    assert "scheduler" in {k["topic"] for k in body["known"]}
    assert "scheduler" not in {u["topic"] for u in body["unknown"]}
    assert any(f["resource_id"] == NIGHTLY and f["resource_type"] == "scheduler_schedule" for f in body["facts"])


# ── L75c branch add / modify / delete ──────────────────────────────────────────

def test_L75c_modify_state_is_pure_and_changes_only_the_state():
    base = base_with()
    before = base.model_dump(mode="json")
    branch = apply_change(base, Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"state": "ENABLED"}))
    assert base.model_dump(mode="json") == before
    assert find(branch).state == "ENABLED" and find(base).state == "DISABLED"
    assert find(branch).model_dump(exclude={"state"}) == find(base).model_dump(exclude={"state"})
    # a bare name means the default group
    again = apply_change(base, Change(op="modify", resource_type="scheduler_schedule", resource_id="nightly-report", fields={"state": "ENABLED"}))
    assert find(again).state == "ENABLED"


@pytest.mark.parametrize("fields", [
    {"state": "enabled"}, {"state": "PAUSED"}, {"state": True}, {"target_role_arn": "not-an-arn"},
    {"action_after_completion": "KEEP"}, {"flexible_time_window_mode": "ON"}, {"name": "renamed"}, {"group_name": "other"},
    {"arn": "arn:aws:scheduler:x"}, {"unknown_field": 1}, {"has_input": "yes"}, {"flexible_time_window_minutes": 5},
    {"start_date": "tomorrow"}, {"target_arn": "lambda"},
])
def test_L75c_values_aws_would_reject_are_rejected(fields):
    with pytest.raises(ValueError):
        apply_change(base_with(), Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields=fields))


def test_L75c_modify_of_a_missing_schedule_names_no_resource():
    with pytest.raises(TargetNotFound) as exc:
        apply_change(base_with(), Change(op="modify", resource_type="scheduler_schedule", resource_id="default/nope", fields={"state": "ENABLED"}))
    assert "nope" not in str(exc.value)
    with pytest.raises(ValueError):
        apply_change(base_with(), Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={}))


def test_L75c_add_uses_documented_aws_defaults_and_never_invents_required_values():
    base = base_with()
    full = {"schedule_expression": "rate(1 hour)", "flexible_time_window_mode": "OFF", "target_arn": LAMBDA_ARN, "target_role_arn": ROLE_ARN}
    added = find(apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id="batch/hourly", fields=full)), "batch/hourly")
    # CreateSchedule documents State=ENABLED, timezone UTC and ActionAfterCompletion=NONE as defaults.
    assert (added.group_name, added.name, added.state, added.schedule_expression_timezone, added.action_after_completion,
            added.has_input, added.unmodeled_settings, added.arn) == ("batch", "hourly", "ENABLED", "UTC", "NONE", False, [], None)
    bare = find(apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id="bare", fields={})), "default/bare")
    assert (bare.schedule_expression, bare.flexible_time_window_mode, bare.target_arn, bare.target_role_arn) == (None, None, None, None)
    with pytest.raises(ValueError):
        apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields=full))
    for bad_id in ("", "a/b/c", "bad name", "x" * 65, "/x"):
        with pytest.raises(ValueError):
            apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id=bad_id, fields=full))
    caps = {entry.resource_type: entry for entry in mutation_capabilities().resources}
    assert caps["scheduler_schedule"].operations == ["add", "delete", "modify"]


def test_L75c_delete_removes_the_schedule_and_is_ledgered():
    from app.mutations import deletion_ledger

    base = base_with(schedule(), schedule("other"))
    branch = apply_change(base, Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={}))
    assert [f"{s.group_name}/{s.name}" for s in branch.scheduler.schedules] == ["default/other"]
    assert [item["resource_id"] for item in deletion_ledger(branch)] == [NIGHTLY]
    with pytest.raises(ValueError):
        apply_change(base, Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"force": True}))
    with pytest.raises(TargetNotFound):
        apply_change(branch, Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={}))


# ── L75d the diff ──────────────────────────────────────────────────────────────

def test_L75d_state_change_is_a_modified_resource_with_before_and_after():
    base = base_with()
    branch = apply_change(base, Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"state": "ENABLED"}))
    diff = diff_infrastructure(base, branch)
    entries = [item for item in diff.resources_modified if item["resource_type"] == "scheduler_schedule"]
    assert entries == [{"id": NIGHTLY, "resource_type": "scheduler_schedule", "changed": ["base.state"],
                        "values": {"base.state": {"before": "DISABLED", "after": "ENABLED"}}}]
    assert diff.resources_added == [] and diff.resources_removed == []
    assert diff.modeled_state_unchanged is False
    reverse = diff_infrastructure(branch, base)
    assert next(i for i in reverse.resources_modified if i["resource_type"] == "scheduler_schedule")["values"] == {
        "base.state": {"before": "ENABLED", "after": "DISABLED"}}


def test_L75d_values_are_only_reported_for_declared_fields_and_never_for_other_types():
    base = base_with()
    retarget = apply_change(base, Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY,
                                         fields={"schedule_expression": "rate(1 minute)", "target_arn": SQS_ARN}))
    entry = next(i for i in diff_infrastructure(base, retarget).resources_modified if i["resource_type"] == "scheduler_schedule")
    assert entry["changed"] == ["base.schedule_expression", "base.target_arn"]
    assert entry["values"]["base.schedule_expression"] == {"before": "cron(0 2 * * ? *)", "after": "rate(1 minute)"}
    other = apply_change(base, Change(op="modify", resource_type="lambda_function", resource_id="dl-worker", fields={"role_arn": f"arn:aws:iam::{ACCOUNT}:role/Other"}))
    assert all("values" not in item for item in diff_infrastructure(base, other).resources_modified)


def test_L75d_add_and_delete_show_in_the_diff():
    base = base_with()
    added = apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id="batch/new", fields={}))
    assert {"id": "batch/new", "resource_type": "scheduler_schedule"} in diff_infrastructure(base, added).resources_added
    removed = apply_change(base, Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={}))
    diff = diff_infrastructure(base, removed)
    assert {"id": NIGHTLY, "resource_type": "scheduler_schedule"} in diff.resources_removed
    assert any(impact["removed_resource"]["id"] == NIGHTLY for impact in diff.deletion_impacts)


# ── L75e full replace ──────────────────────────────────────────────────────────

def _update(parameters):
    return translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "scheduler", "operation": "UpdateSchedule", "parameters": parameters}]})


UPDATE = {"Name": "nightly-report", "ScheduleExpression": "cron(0 2 * * ? *)", "FlexibleTimeWindow": {"Mode": "OFF"},
          "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}}


def test_L75e_update_without_state_resets_it_to_enabled_the_incident():
    base = base_with()
    result = _update(dict(UPDATE))
    assert result["unknown_fields"] == []
    assert [(c.op, c.resource_type, c.resource_id) for c in result["changes"]] == [("modify", "scheduler_schedule", NIGHTLY)]
    assert result["changes"][0].fields["state"] == "ENABLED"
    branch = apply_changes(base, result["changes"])
    assert find(branch).state == "ENABLED"
    diff = diff_infrastructure(base, branch)
    assert next(i for i in diff.resources_modified if i["resource_type"] == "scheduler_schedule")["values"]["base.state"] == {
        "before": "DISABLED", "after": "ENABLED"}
    kept = _update({**UPDATE, "State": "DISABLED"})
    assert apply_changes(base, kept["changes"]).scheduler == base.scheduler


def test_L75e_update_clears_what_the_call_leaves_out():
    base = base_with(schedule(start_date="2030-01-01T00:00:00Z", end_date="2031-01-01T00:00:00Z", schedule_expression_timezone="Asia/Kolkata",
                              action_after_completion="DELETE", has_input=True))
    branch = apply_changes(base, _update({**UPDATE, "State": "DISABLED"})["changes"])
    updated = find(branch)
    assert (updated.start_date, updated.end_date, updated.schedule_expression_timezone, updated.action_after_completion, updated.has_input) == (
        None, None, "UTC", "NONE", False)


@pytest.mark.parametrize("missing", ["ScheduleExpression", "FlexibleTimeWindow", "Target.Arn", "Target.RoleArn"])
def test_L75e_missing_required_members_are_unknown_fields_never_defaults(missing):
    parameters = json.loads(json.dumps(UPDATE))
    if "." in missing:
        parameters["Target"].pop(missing.split(".")[1])
    else:
        parameters.pop(missing)
    result = _update(parameters)
    assert [item["field"] for item in result["unknown_fields"]] == [missing]
    assert result["unknown_fields"][0]["reason"] == "required_member_missing"
    fields = result["changes"][0].fields
    assert {"ScheduleExpression": "schedule_expression", "FlexibleTimeWindow": "flexible_time_window_mode",
            "Target.Arn": "target_arn", "Target.RoleArn": "target_role_arn"}[missing] not in fields


def test_L75e_settings_emfirge_does_not_store_are_flagged_and_noted():
    result = _update({**UPDATE, "State": "DISABLED", "Description": "x", "Target": {**UPDATE["Target"], "Input": SECRET_INPUT,
                      "DeadLetterConfig": {"Arn": f"arn:aws:sqs:{REGION}:{ACCOUNT}:dlq"}}})
    assert {item["field"] for item in result["unknown_fields"]} == {"Description", "Target.DeadLetterConfig"}
    assert all(item["reason"] == "unsupported_attribute" for item in result["unknown_fields"])
    fields = result["changes"][0].fields
    assert fields["has_input"] is True and fields["unmodeled_settings"] == ["Description", "Target.DeadLetterConfig"]
    assert "planted-secret" not in json.dumps([c.model_dump() for c in result["changes"]]) + json.dumps(result["unknown_fields"])


def test_L75e_delete_call_maps_to_a_delete_change():
    result = translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "scheduler", "operation": "DeleteSchedule", "parameters": {"Name": "weekly", "GroupName": "batch"}}]})
    assert [(c.op, c.resource_id, c.fields) for c in result["changes"]] == [("delete", "batch/weekly", {})]
    assert result["unmodeled"] == []


# ── L75f four formats ──────────────────────────────────────────────────────────

def _cli(command):
    return translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [command]}))


def _tf(actions, before, after, unknown=None):
    return translate_plan({"format_version": "1.2", "resource_changes": [{
        "address": "aws_scheduler_schedule.nightly", "type": "aws_scheduler_schedule", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}}}]})


def _tf_object(state="ENABLED", **overrides):
    value = {"name": "nightly-report", "group_name": "default", "state": state, "schedule_expression": "cron(0 2 * * ? *)",
             "schedule_expression_timezone": "UTC", "description": "", "kms_key_arn": "", "start_date": None, "end_date": None,
             "action_after_completion": "NONE",
             "flexible_time_window": [{"mode": "OFF", "maximum_window_in_minutes": None}],
             "target": [{"arn": LAMBDA_ARN, "role_arn": ROLE_ARN, "input": "", "dead_letter_config": [],
                         "retry_policy": [{"maximum_event_age_in_seconds": 86400, "maximum_retry_attempts": 185}],
                         "ecs_parameters": [], "eventbridge_parameters": [], "kinesis_parameters": [],
                         "sagemaker_pipeline_parameters": [], "sqs_parameters": []}]}
    value.update(overrides)
    return value


def _cfn(action, properties, before=None, replacement="False"):
    change = {"Action": action, "LogicalResourceId": "Nightly", "ResourceType": "AWS::Scheduler::Schedule",
              "PhysicalResourceId": "nightly-report", "Replacement": replacement}
    if properties is not None:
        change["AfterContext"] = json.dumps({"Properties": properties})
    if before is not None:
        change["BeforeContext"] = json.dumps({"Properties": before})
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": change}]})
    assert extras == []
    return translate_api_calls(doc)


def _snapshot_of(result, base):
    assert result["unknown_fields"] == [] and result["unmodeled"] == []
    return apply_changes(base, result["changes"]).scheduler.model_dump(mode="json")


def test_L75f_the_incident_update_gives_the_same_branch_in_all_four_formats():
    base = base_with()
    props = {"Name": "nightly-report", "ScheduleExpression": "cron(0 2 * * ? *)", "FlexibleTimeWindow": {"Mode": "OFF"},
             "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}, "State": "ENABLED"}
    cli = _cli("aws scheduler update-schedule --name nightly-report --state ENABLED --schedule-expression 'cron(0 2 * * ? *)' "
               f"--flexible-time-window '{{\"Mode\":\"OFF\"}}' --target '{{\"Arn\":\"{LAMBDA_ARN}\",\"RoleArn\":\"{ROLE_ARN}\"}}'")
    results = {
        "api": _update({**UPDATE, "State": "ENABLED"}),
        "cli": cli,
        "cfn": _cfn("Modify", props, before={**props, "State": "DISABLED"}),
        "terraform": _tf(["update"], _tf_object("DISABLED"), _tf_object("ENABLED")),
    }
    states = {name: _snapshot_of(result, base) for name, result in results.items()}
    assert len({json.dumps(value, sort_keys=True) for value in states.values()}) == 1, states
    for name, result in results.items():
        assert [(c.op, c.resource_type, c.resource_id) for c in result["changes"]] == [("modify", "scheduler_schedule", NIGHTLY)], name
        branch = apply_changes(base, result["changes"])
        entry = next(i for i in diff_infrastructure(base, branch).resources_modified if i["resource_type"] == "scheduler_schedule")
        assert entry["values"] == {"base.state": {"before": "DISABLED", "after": "ENABLED"}}, name
        # every format hands back the same exact call
        assert [c["operation"] for c in build_api_calls(base, result["changes"])] == ["UpdateSchedule"], name


def test_L75f_create_gives_the_same_branch_in_all_four_formats():
    base = base_with()
    params = {"Name": "hourly", "GroupName": "batch", "ScheduleExpression": "rate(1 hour)", "FlexibleTimeWindow": {"Mode": "OFF"},
              "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}, "State": "DISABLED"}
    create = lambda p: translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "scheduler", "operation": "CreateSchedule", "parameters": p}]})
    tf_after = _tf_object("DISABLED", name="hourly", group_name="batch", schedule_expression="rate(1 hour)")
    results = {
        "api": create(params),
        "cli": _cli("aws scheduler create-schedule --name hourly --group-name batch --state DISABLED --schedule-expression 'rate(1 hour)' "
                    f"--flexible-time-window '{{\"Mode\":\"OFF\"}}' --target '{{\"Arn\":\"{LAMBDA_ARN}\",\"RoleArn\":\"{ROLE_ARN}\"}}'"),
        "cfn": _cfn("Add", params),
        "terraform": _tf(["create"], None, tf_after, {"arn": True, "id": True}),
    }
    states = {name: _snapshot_of(result, base) for name, result in results.items()}
    assert len({json.dumps(value, sort_keys=True) for value in states.values()}) == 1, states
    created = next(s for s in apply_changes(base, results["api"]["changes"]).scheduler.schedules if s.name == "hourly")
    assert (created.group_name, created.state, created.target_arn) == ("batch", "DISABLED", LAMBDA_ARN)
    for name, result in results.items():
        assert [c.op for c in result["changes"]] == ["add"], name
        assert [c["params"] for c in build_api_calls(base, result["changes"])] == [{
            "Name": "hourly", "GroupName": "batch", "ScheduleExpression": "rate(1 hour)", "FlexibleTimeWindow": {"Mode": "OFF"},
            "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}, "State": "DISABLED", "ScheduleExpressionTimezone": "UTC",
            "ActionAfterCompletion": "NONE"}], name


def test_L75f_delete_gives_the_same_branch_in_all_four_formats():
    base = base_with()
    results = {
        "api": translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "scheduler", "operation": "DeleteSchedule", "parameters": {"Name": "nightly-report"}}]}),
        "cli": _cli("aws scheduler delete-schedule --name nightly-report"),
        "cfn": _cfn("Remove", None, before={"Name": "nightly-report"}),
        "terraform": _tf(["delete"], _tf_object(), None),
    }
    for name, result in results.items():
        assert [(c.op, c.resource_id) for c in result["changes"]] == [("delete", NIGHTLY)], name
        assert apply_changes(base, result["changes"]).scheduler.schedules == [], name
        assert build_api_calls(base, result["changes"])[0]["params"] == {"Name": "nightly-report", "GroupName": "default"}, name


def test_L75f_terraform_unknown_and_unsupported_values_stay_visible():
    unknown = _tf(["update"], _tf_object("DISABLED"), _tf_object("ENABLED", schedule_expression=None), {"schedule_expression": True})
    assert {item["field"] for item in unknown["unknown_fields"]} == {"schedule_expression"}
    after = _tf_object("ENABLED", description="why", target=[{**_tf_object()["target"][0], "input": SECRET_INPUT,
                       "dead_letter_config": [{"arn": f"arn:aws:sqs:{REGION}:{ACCOUNT}:dlq"}]}])
    result = _tf(["update"], _tf_object("DISABLED"), after)
    assert {item["field"] for item in result["unknown_fields"]} == {"description", "target.dead_letter_config"}
    assert result["changes"][0].fields["has_input"] is True
    assert "planted-secret" not in json.dumps([c.model_dump() for c in result["changes"]])
    rename = _tf(["delete", "create"], _tf_object(), _tf_object(name="renamed"))
    assert [(c.op, c.resource_id) for c in rename["changes"]] == [("delete", NIGHTLY), ("add", "default/renamed")]


def test_L75f_cloudformation_with_unresolved_values_is_an_extra_not_a_guess():
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Add", "LogicalResourceId": "S", "ResourceType": "AWS::Scheduler::Schedule",
        "AfterContext": json.dumps({"Properties": {"Name": "x", "ScheduleExpression": "rate(1 day)", "FlexibleTimeWindow": {"Mode": "OFF"},
                                                   "Target": {"Arn": {"Fn::GetAtt": ["Fn", "Arn"]}, "RoleArn": ROLE_ARN}}})}}]})
    assert doc["calls"] == [] and len(extras) == 1


# ── L75g hand-back ─────────────────────────────────────────────────────────────

def test_L75g_modify_state_hands_back_one_exact_update_schedule():
    base = base_with(schedule(start_date="2030-01-01T00:00:00Z"))
    calls = build_api_calls(base, [Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"state": "ENABLED"})])
    assert calls == [{"change_index": 0, "service": "scheduler", "operation": "UpdateSchedule", "params": {
        "Name": "nightly-report", "GroupName": "default", "ScheduleExpression": "cron(0 2 * * ? *)",
        "FlexibleTimeWindow": {"Mode": "OFF"}, "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}, "State": "ENABLED",
        "ScheduleExpressionTimezone": "UTC", "ActionAfterCompletion": "NONE", "StartDate": "2030-01-01T00:00:00Z"}}]


def test_L75g_flexible_window_and_delete():
    base = base_with(schedule(flexible_time_window_mode="FLEXIBLE", flexible_time_window_minutes=10))
    update = build_api_calls(base, [Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"state": "ENABLED"})])
    assert update[0]["params"]["FlexibleTimeWindow"] == {"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 10}
    assert build_api_calls(base, [Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={})]) == [
        {"change_index": 0, "service": "scheduler", "operation": "DeleteSchedule", "params": {"Name": "nightly-report", "GroupName": "default"}}]


@pytest.mark.parametrize("current", [
    {"has_input": True}, {"has_input": None}, {"unmodeled_settings": ["Target.DeadLetterConfig"]},
    {"schedule_expression": None}, {"state": None}, {"target_role_arn": None},
])
def test_L75g_update_is_refused_when_it_would_wipe_or_guess_settings(current):
    base = base_with(schedule(**current))
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"target_arn": SQS_ARN})])
    assert exc.value.changes[0]["resource_type"] == "scheduler_schedule"
    assert exc.value.changes[0]["reason"].startswith(("unspecified_values", "field_not_mapped"))


def test_L75g_add_with_missing_required_values_is_refused():
    base = base_with()
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [Change(op="add", resource_type="scheduler_schedule", resource_id="bare", fields={})])
    assert exc.value.changes[0]["reason"].startswith("unspecified_values")


def test_L75g_every_call_is_valid_against_the_botocore_model():
    from botocore.validate import ParamValidator
    import botocore.session

    model = botocore.session.get_session().get_service_model("scheduler")
    base = base_with()
    for change in (Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={"state": "ENABLED"}),
                   Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={})):
        for call in build_api_calls(base, [change]):
            assert not ParamValidator().validate(call["params"], model.operation_model(call["operation"]).input_shape).has_errors()


# ── L75h graph ─────────────────────────────────────────────────────────────────

def _edges(graph, source):
    return {(edge.dst, edge.relationship.value) for edge in graph.edges if edge.src == source}


def test_L75h_node_edges_and_schema():
    base = base_with(schedule(), schedule("to-queue", target=SQS_ARN))
    graph = build_graph(base)
    assert validate_graph(graph) == []
    node = next(n for n in graph.nodes if n.id == NIGHTLY)
    assert node.resource_type == "scheduler_schedule" and node.category.value == "other"
    assert node.base["state"] == "DISABLED" and node.base["target_arn"] == LAMBDA_ARN
    assert "input" not in json.dumps(node.base).lower() or node.base.get("has_input") is False
    assert _edges(graph, NIGHTLY) == {("dl-worker", "invokes"), ("iam-role-DlWorkerRole", "uses_iam_role")}
    # a target Emfirge does not model is unknown: the node keeps the arn, no edge is guessed
    assert _edges(graph, "default/to-queue") == {("iam-role-DlWorkerRole", "uses_iam_role")}
    assert next(n for n in graph.nodes if n.id == "default/to-queue").base["target_arn"] == SQS_ARN


def test_L75h_a_target_in_another_region_or_missing_function_gets_no_edge():
    other_region = base_with(schedule(target=LAMBDA_ARN.replace(REGION, "us-east-1")), schedule("ghost", target=LAMBDA_ARN.replace("dl-worker", "ghost")))
    graph = build_graph(other_region)
    assert not any(edge.relationship.value == "invokes" for edge in graph.edges)


def test_L75h_an_alias_arn_targets_the_function():
    graph = build_graph(base_with(schedule(target=LAMBDA_ARN + ":live")))
    assert ("dl-worker", "invokes") in _edges(graph, NIGHTLY)


def test_L75h_deleting_the_target_lambda_lists_the_schedule_as_an_impact():
    base = base_with()
    branch = apply_change(base, Change(op="delete", resource_type="lambda_function", resource_id="dl-worker", fields={}))
    lens = analyze_deletions(base, branch)
    impact = next(item for item in lens.impacts if item.resource_id == NIGHTLY)
    assert (impact.resource_type, impact.relation, impact.depth) == ("scheduler_schedule", "invokes", 1)
    # the other direction: deleting the schedule impacts neither the lambda nor the role
    gone = apply_change(base, Change(op="delete", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields={}))
    assert [item.resource_id for item in analyze_deletions(base, gone).impacts] == []


def test_L75h_the_schedule_is_a_dependent_of_the_lambda_in_context():
    infra = base_with()
    infra.collection = {**infra.collection, "scheduler": "ok"}
    body = answer_for_infra("dependents", infra, analysis_id="a", resource_id="dl-worker").model_dump(mode="json")
    assert any(f["resource_id"] == NIGHTLY and f["relationship"] == "invokes" for f in body["facts"])
    body = answer_for_infra("depends_on", infra, analysis_id="a", resource_id=NIGHTLY).model_dump(mode="json")
    assert {f["resource_id"] for f in body["facts"]} >= {"dl-worker", "iam-role-DlWorkerRole"}


# ── L75i cost and tags ─────────────────────────────────────────────────────────

def test_L75i_schedules_are_usage_priced_so_cost_is_unknown_with_a_reason_never_a_number():
    estimate = estimate_monthly_cost(base_with())
    record = next(item for item in estimate.resources if item.resource_type == "scheduler_schedule")
    assert (record.resource_id, record.monthly_usd, record.basis) == (NIGHTLY, None, "usage-based-unknown")
    assert unknown_reason(record) == "usage-based pricing is not embedded"
    base = base_with()
    diff = diff_infrastructure(base, apply_change(base, Change(op="add", resource_type="scheduler_schedule", resource_id="batch/new", fields={})))
    assert diff.cost_delta["status"] == "unknown" and diff.cost_delta_monthly_usd is None


def test_L75i_eventbridge_scheduler_has_no_schedule_tags_in_aws():
    # CreateSchedule has no Tags member and ListTagsForResource accepts schedule-group ARNs only.
    import botocore.session

    model = botocore.session.get_session().get_service_model("scheduler")
    assert "Tags" not in model.operation_model("CreateSchedule").input_shape.members
    assert "schedule-group" in model.operation_model("ListTagsForResource").input_shape.members["ResourceArn"].metadata["pattern"]
    assert "tags" not in SchedulerSchedule.model_fields and "tags" not in CATALOG["scheduler_schedule"]
    from app.tags import TAGGED_TYPES

    assert "scheduler_schedule" not in TAGGED_TYPES


# ── L75j catalog and IAM ───────────────────────────────────────────────────────

def test_L75j_catalog_fields_trace_to_botocore_scheduler_members():
    catalog = CATALOG["scheduler_schedule"]
    assert resolve(catalog["state"]).enum == ["ENABLED", "DISABLED"]
    assert resolve(catalog["flexible_time_window_mode"]).enum == ["OFF", "FLEXIBLE"]
    assert resolve(catalog["action_after_completion"]).enum == ["NONE", "DELETE"]
    assert resolve(catalog["target_role_arn"]).metadata["pattern"].startswith("^arn:aws")
    assert {source.service for source in catalog.values() if hasattr(source, "service")} == {"scheduler"}
    # every settable CreateSchedule member Emfirge models is an Aws source, none of Input is stored
    assert "Input" not in " ".join(getattr(source, "member", "") for source in catalog.values())


@pytest.mark.parametrize("path", ["iam-role.yaml", "backend/cloudformation/iam-role.yaml"])
def test_L75j_iam_read_policy_lists_the_scheduler_reads_and_no_scheduler_writes(path):
    root = Path(__file__).resolve().parents[3]
    text = (root / path).read_text()
    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    document = yaml.load(text, Loader=Loader)
    actions = [a for statement in document["Resources"]["EmfirgeReadOnlyRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
               for a in statement["Action"]]
    scheduler = {a for a in actions if a.startswith("scheduler:")}
    assert scheduler == {"scheduler:ListSchedules", "scheduler:GetSchedule", "scheduler:ListScheduleGroups", "scheduler:ListTagsForResource"}


# ── L75k compatibility and boundary ────────────────────────────────────────────

def test_L75k_old_snapshots_without_scheduler_data_still_load():
    legacy = load_synthetic_base("delete").model_dump(mode="json")
    legacy.pop("scheduler", None)
    old = AWSInfrastructure.model_validate(legacy)
    assert old.scheduler.schedules == [] and old.collection.get("scheduler") is None
    assert not any(n.resource_type == "scheduler_schedule" for n in build_graph(old).nodes)
    restored = AWSInfrastructure.model_validate(json.loads(base_with().model_dump_json()))
    assert find(restored) == find(base_with())


def test_L75k_scheduler_logic_lives_in_adapter_modules_only():
    from tests.laws.test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, CORE_MODULES, _imported_names

    assert "scheduler_schedule" in ADAPTER_MODULES and "scheduler_schedule" not in CORE_MODULES
    for core in CORE_MODULES:
        assert "scheduler_schedule" not in _imported_names(core), core
    assert ALLOWED["egraph"] == {"models", "iam_classifier", "iam_escalation", "rds_ports"}


def test_L75l_api_branch_flow_shows_the_state_flip_in_the_diff(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = base_with()
    main._branch_request_log.clear()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l75-api", "name": "l75-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    capabilities = client.get("/branches/capabilities").json()
    assert {"resource_type": "scheduler_schedule", "operations": ["add", "delete", "modify"], "constraints": []} in capabilities["resources"]
    rejected = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "scheduler_schedule", "resource_id": NIGHTLY, "fields": {"state": "enabled"}})
    assert rejected.status_code == 422, rejected.text
    ok = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "scheduler_schedule", "resource_id": NIGHTLY, "fields": {"state": "ENABLED"}})
    assert ok.status_code == 200, ok.text
    diff = client.get(f"/branches/{branch_id}/diff").json()
    assert [item for item in diff["resources_modified"] if item["resource_type"] == "scheduler_schedule"] == [
        {"id": NIGHTLY, "resource_type": "scheduler_schedule", "changed": ["base.state"],
         "values": {"base.state": {"before": "DISABLED", "after": "ENABLED"}}}]
    assert client.get(f"/branches/{branch_id}/verdict").status_code == 200
    handback = client.get(f"/branches/{branch_id}/handback")
    assert handback.status_code == 200, handback.text
    assert [call["operation"] for call in handback.json()["calls"]] == ["UpdateSchedule"]
    main._branch_request_log.clear()  # leave the shared per-minute limiter as found
