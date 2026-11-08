"""L77: a schedule that starts running on the branch is an outside_world fact.

The incident: a deploy reset a paused EventBridge Scheduler schedule to ENABLED and the
Lambda it triggers (it publishes podcast episodes) ran again. Emfirge cannot see what the
target does, so the answer says only what is true: this schedule now runs target X on
expression E, and what X does outside the cloud is not visible.

L77a  the incident (DISABLED -> ENABLED) gives the same outside_world fact in all input formats
L77b  DISABLED stays DISABLED: no fact; an added DISABLED schedule: no fact
L77c  ENABLED -> DISABLED is an availability fact naming the target
L77d  unknown state is unknown, never a fact; a target that is not collected is unknown
L77e  closed schema, determinism, no ids in free text still hold on these branches
L77f  source_url is AWS documentation
"""
from __future__ import annotations

import json
import re

import pytest

from app.check_facts import CheckResult
from app.mutations import Change, apply_change, apply_changes

from .test_check_facts_laws import (
    FORBIDDEN_NAME_PARTS, ID_KEYS, _answers, _check, _dump, _json_keys, _json_values, _leaks, _reason_codes,
)
from .test_scheduler_schedule_laws import (
    ACCOUNT, LAMBDA_ARN, NIGHTLY, REGION, ROLE_ARN, SQS_ARN, UPDATE, _cfn, _cli, _tf, _tf_object, _update,
    base_with, schedule,
)

DOCS = "https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-state.html"
TARGET_ID = "dl-worker"
EXPECTED_FACT = {
    "resource_id": NIGHTLY, "resource_type": "scheduler_schedule", "change": "schedule_enabled",
    "schedule_expression": "cron(0 2 * * ? *)", "resource_ids": [TARGET_ID], "action": None, "service": "scheduler",
    "reason": "Runs its target on a timer without anyone starting it.", "source_url": DOCS,
}
EFFECTS_UNKNOWN = "what the target does outside the cloud is not visible to Emfirge"


def _outside(result):
    return _dump(result)["answers"][5]


def _mod(**fields):
    return Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields=fields)


def _add(identity, state):
    return Change(op="add", resource_type="scheduler_schedule", resource_id=identity, fields={
        "state": state, "schedule_expression": "rate(1 hour)", "flexible_time_window_mode": "OFF",
        "target_arn": LAMBDA_ARN, "target_role_arn": ROLE_ARN})


def _incident_results():
    props = {"Name": "nightly-report", "ScheduleExpression": "cron(0 2 * * ? *)", "FlexibleTimeWindow": {"Mode": "OFF"},
             "Target": {"Arn": LAMBDA_ARN, "RoleArn": ROLE_ARN}, "State": "ENABLED"}
    return {
        "api_without_state": _update(dict(UPDATE)),
        "api": _update({**UPDATE, "State": "ENABLED"}),
        "cli": _cli("aws scheduler update-schedule --name nightly-report --state ENABLED --schedule-expression 'cron(0 2 * * ? *)' "
                    f"--flexible-time-window '{{\"Mode\":\"OFF\"}}' --target '{{\"Arn\":\"{LAMBDA_ARN}\",\"RoleArn\":\"{ROLE_ARN}\"}}'"),
        "cfn": _cfn("Modify", props, before={**props, "State": "DISABLED"}),
        "terraform": _tf(["update"], _tf_object("DISABLED"), _tf_object("ENABLED")),
    }


def _schedule_facts(answer):
    return [f for f in answer["facts"] if f.get("resource_type") == "scheduler_schedule"]


def _disabled_facts(body):
    return [f for f in _answers(body)["availability"]["facts"] if f["change"] == "schedule_disabled"]


# ── L77a ──────────────────────────────────────────────────────────

def test_L77a_the_incident_gives_the_same_outside_world_fact_in_every_input_format():
    base = base_with()
    branches = {"typed": apply_change(base, _mod(state="ENABLED"))}
    branches.update({name: apply_changes(base, result["changes"]) for name, result in _incident_results().items()})
    answers = {}
    for name, branch in branches.items():
        answer = _outside(_check(base, branch))
        assert _schedule_facts(answer) == [EXPECTED_FACT], name
        unknown = [u for u in answer["unknown"] if u["resource_id"] == TARGET_ID]
        assert [(u["topic"], u["reason"]) for u in unknown] == [("target_effects", EFFECTS_UNKNOWN)], name
        answers[name] = json.dumps(answer, sort_keys=True)
    assert len(set(answers.values())) == 1, "the input formats produced different outside_world answers"


def test_L77a_a_schedule_added_enabled_is_a_fact_with_its_own_change():
    base = base_with()
    facts = _schedule_facts(_outside(_check(base, apply_change(base, _add("batch/new", "ENABLED")))))
    assert facts == [{**EXPECTED_FACT, "resource_id": "batch/new", "change": "schedule_added_enabled",
                      "schedule_expression": "rate(1 hour)"}]


def test_L77a_an_enabled_schedule_whose_expression_changes_is_a_schedule_changed_fact():
    base = base_with(schedule(state="ENABLED"))
    branch = apply_change(base, _mod(schedule_expression="rate(1 minute)"))
    assert _schedule_facts(_outside(_check(base, branch))) == [
        {**EXPECTED_FACT, "change": "schedule_changed", "schedule_expression": "rate(1 minute)"}]
    # a timezone change moves when it runs (L85a); a state-preserving no-op is no fact
    assert _schedule_facts(_outside(_check(base, base.model_copy(deep=True)))) == []


# ── L77b ──────────────────────────────────────────────────────────

def test_L77b_disabled_stays_disabled_gives_no_fact_and_no_unknown():
    base = base_with()
    kept = apply_changes(base, _update({**UPDATE, "State": "DISABLED"})["changes"])
    retimed = apply_change(base, _mod(schedule_expression="rate(1 minute)"))
    added = apply_change(base, _add("batch/off", "DISABLED"))
    for branch in (kept, retimed, added):
        body = _dump(_check(base, branch))
        outside = _answers(body)["outside_world"]
        assert _schedule_facts(outside) == [] and _disabled_facts(body) == []
        assert not [u for u in outside["unknown"]
                    if u["topic"] in {"target_effects", "schedule_state_unknown", "schedule_target_not_modeled"}]


# ── L77c ──────────────────────────────────────────────────────────

def test_L77c_enabled_to_disabled_is_an_availability_fact_naming_the_target():
    base = base_with(schedule(state="ENABLED"))
    body = _dump(_check(base, apply_change(base, _mod(state="DISABLED"))))
    assert _disabled_facts(body) == [{"resource_id": NIGHTLY, "resource_type": "scheduler_schedule", "change": "schedule_disabled",
                                      "path": [NIGHTLY, TARGET_ID], "depth": 1, "recently_used": None}]
    assert _schedule_facts(_answers(body)["outside_world"]) == []


# ── L77d ──────────────────────────────────────────────────────────

def test_L77d_unknown_state_is_unknown_and_never_a_fact():
    base = base_with(schedule(state=None))
    for change in (_mod(schedule_expression="rate(1 minute)"), _mod(state="ENABLED")):
        body = _dump(_check(base, apply_change(base, change)))
        outside = _answers(body)["outside_world"]
        assert _schedule_facts(outside) == [] and _disabled_facts(body) == []
        assert [(u["topic"], u["resource_id"]) for u in outside["unknown"] if u["topic"] == "schedule_state_unknown"] == [
            ("schedule_state_unknown", NIGHTLY)]


def test_L77d_a_target_that_is_not_a_collected_resource_is_unknown_on_the_schedule():
    base = base_with(schedule(target=SQS_ARN))
    answer = _outside(_check(base, apply_change(base, _mod(state="ENABLED"))))
    assert _schedule_facts(answer) == [{**EXPECTED_FACT, "resource_ids": []}]
    topics = {(u["topic"], u["resource_id"]) for u in answer["unknown"]}
    assert ("schedule_target_not_modeled", NIGHTLY) in topics
    assert not any(topic == "target_effects" for topic, _ in topics)


# ── L77e ──────────────────────────────────────────────────────────

def _scenarios():
    base = base_with()
    enabled_base = base_with(schedule(state="ENABLED"))
    unknown_base = base_with(schedule(state=None))
    return [(base, apply_change(base, _mod(state="ENABLED"))),
            (enabled_base, apply_change(enabled_base, _mod(state="DISABLED"))),
            (enabled_base, apply_change(enabled_base, _mod(schedule_expression="rate(1 minute)"))),
            (unknown_base, apply_change(unknown_base, _mod(state="ENABLED"))),
            (base, apply_change(base, _add("batch/new", "ENABLED")))]


def test_L77e_closed_schema_no_verdict_words_no_reason_codes():
    codes = _reason_codes()
    for base, branch in _scenarios():
        body = _dump(_check(base, branch))
        CheckResult.model_validate(body)
        for key in set(_json_keys(body)):
            assert not any(part in key.lower() for part in FORBIDDEN_NAME_PARTS), key
        assert not codes & {v for v in _json_values(body) if isinstance(v, str)}
        for index, answer in enumerate(body["answers"]):
            for fact in answer["facts"]:
                bad = json.loads(json.dumps(body))
                bad["answers"][index]["facts"][answer["facts"].index(fact)]["recommendation"] = "x"
                with pytest.raises(Exception):
                    CheckResult.model_validate(bad)


def test_L77e_deterministic():
    for base, branch in _scenarios():
        first = _check(base, branch).model_dump_json()
        assert first == _check(base, branch).model_dump_json()


def test_L77e_no_customer_identifier_in_free_text():
    name, group = "zz-planted-sched-7731", "zz-planted-group-7731"
    base = base_with(schedule(name=name, group=group), schedule(name="other", group=group, target=SQS_ARN, state="ENABLED"))
    identity = f"{group}/{name}"
    branch = apply_changes(base, [
        Change(op="modify", resource_type="scheduler_schedule", resource_id=identity, fields={"state": "ENABLED"}),
        Change(op="modify", resource_type="scheduler_schedule", resource_id=f"{group}/other", fields={"state": "DISABLED"})])
    body = _dump(_check(base, branch))
    assert name in json.dumps(body)  # positive control
    known = {identity, f"{group}/other", TARGET_ID}
    assert not _leaks(body, [name, group], known), _leaks(body, [name, group], known)
    assert {"resource_id", "resource_ids", "path"} <= ID_KEYS


# ── L77f ──────────────────────────────────────────────────────────

def test_L77f_source_url_is_aws_documentation():
    base = base_with()
    fact = _schedule_facts(_outside(_check(base, apply_change(base, _mod(state="ENABLED")))))[0]
    assert re.fullmatch(r"https://docs\.aws\.amazon\.com/scheduler/[A-Za-z0-9_./-]+\.html", fact["source_url"])
    assert fact["source_url"] == DOCS
