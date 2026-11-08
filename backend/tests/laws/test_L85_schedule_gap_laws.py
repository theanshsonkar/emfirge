"""L85: the schedule facts and gaps an auditor found missing.

L85a  an ENABLED schedule whose timezone, start/end date, role, input flag or flexible window changes is a
      schedule_changed fact (the timing or the way it runs changed); an unchanged one is not
L85b  deleting an ENABLED schedule is an availability fact naming the target; deleting a DISABLED one is none;
      a schedule whose state was not collected is unknown, never a fact
L85c  no resource id in the free text of these facts (ids live in resource_id fields only)
L85d  outside_world carries plan gaps (rejected, unmodeled, unknown values) as unknowns
L85e  a denied or failed scheduler scan is an unknown in outside_world; an ok scan is known
L85f  Terraform: an unknown (computed) group_name is one explicit unknown, never the default group
L85g  the schedule -> Lambda invokes edge needs the same account; an account that cannot be told is no edge
"""
from __future__ import annotations

import json

import pytest

from app.egraph import build_graph
from app.mutations import Change, apply_change

from .test_check_facts_laws import _answers, _check, _dump, _leaks
from .test_schedule_check_laws import TARGET_ID, _disabled_facts, _outside, _schedule_facts
from .test_scheduler_schedule_laws import (
    ACCOUNT, LAMBDA_ARN, NIGHTLY, ROLE_ARN, _tf, _tf_object, base_with, schedule,
)


def _mod(**fields):
    return Change(op="modify", resource_type="scheduler_schedule", resource_id=NIGHTLY, fields=fields)


def _delete(identity=NIGHTLY):
    return Change(op="delete", resource_type="scheduler_schedule", resource_id=identity)


# ── L85a ──────────────────────────────────────────────────────────

CHANGES = [
    {"schedule_expression_timezone": "Asia/Kolkata"},
    {"start_date": "2030-01-01T00:00:00Z"},
    {"end_date": "2030-01-01T00:00:00Z"},
    {"target_role_arn": f"arn:aws:iam::{ACCOUNT}:role/OtherRole"},
    {"has_input": True},
    {"flexible_time_window_mode": "FLEXIBLE", "flexible_time_window_minutes": 15},
]


@pytest.mark.parametrize("fields", CHANGES, ids=lambda f: next(iter(f)))
def test_L85a_a_change_to_how_an_enabled_schedule_runs_is_a_fact(fields):
    base = base_with(schedule(state="ENABLED"))
    facts = _schedule_facts(_outside(_check(base, apply_change(base, _mod(**fields)))))
    assert [(f["resource_id"], f["change"], f["resource_ids"]) for f in facts] == [(NIGHTLY, "schedule_changed", [TARGET_ID])]


def test_L85a_unchanged_or_disabled_gives_no_fact():
    enabled = base_with(schedule(state="ENABLED"))
    assert _schedule_facts(_outside(_check(enabled, enabled.model_copy(deep=True)))) == []
    disabled = base_with(schedule(state="DISABLED"))
    for fields in CHANGES:
        assert _schedule_facts(_outside(_check(disabled, apply_change(disabled, _mod(**fields))))) == []


# ── L85b ──────────────────────────────────────────────────────────

def test_L85b_deleting_an_enabled_schedule_is_an_availability_fact_naming_the_target():
    base = base_with(schedule(state="ENABLED"))
    body = _dump(_check(base, apply_change(base, _delete())))
    facts = [f for f in _answers(body)["availability"]["facts"] if f["change"] == "schedule_deleted"]
    assert facts == [{"resource_id": NIGHTLY, "resource_type": "scheduler_schedule", "change": "schedule_deleted",
                      "path": [NIGHTLY, TARGET_ID], "depth": 1, "recently_used": None}]
    assert _disabled_facts(body) == []


def test_L85b_deleting_a_disabled_schedule_is_no_fact():
    base = base_with(schedule(state="DISABLED"))
    body = _dump(_check(base, apply_change(base, _delete())))
    assert not [f for f in _answers(body)["availability"]["facts"] if f["change"] == "schedule_deleted"]


def test_L85b_deleting_a_schedule_whose_state_is_unknown_is_unknown_not_a_fact():
    base = base_with(schedule(state=None))
    body = _dump(_check(base, apply_change(base, _delete())))
    assert not [f for f in _answers(body)["availability"]["facts"] if f["change"] == "schedule_deleted"]
    unknown = _answers(body)["availability"]["unknown"] + _answers(body)["outside_world"]["unknown"]
    assert (("schedule_state_unknown", NIGHTLY)) in {(u["topic"], u["resource_id"]) for u in unknown}


# ── L85c ──────────────────────────────────────────────────────────

def test_L85c_no_resource_id_in_the_free_text_of_the_new_facts():
    name, group = "zz-planted-sched-8851", "zz-planted-group-8851"
    identity = f"{group}/{name}"
    base = base_with(schedule(name=name, group=group, state="ENABLED"))
    for branch in (apply_change(base, Change(op="modify", resource_type="scheduler_schedule", resource_id=identity,
                                             fields={"schedule_expression_timezone": "Asia/Kolkata"})),
                   apply_change(base, _delete(identity))):
        body = _dump(_check(base, branch))
        assert name in json.dumps(body)
        assert not _leaks(body, [name, group], {identity, TARGET_ID}), _leaks(body, [name, group], {identity, TARGET_ID})


# ── L85d / L85e ───────────────────────────────────────────────────

def _gap_plans():
    return [{"plan_id": "p1", "input_sha256": "a" * 64, "rejected": [{"address": "calls[0]", "reason": "x"}],
             "unmodeled": [{"address": "calls[1]", "type": "scheduler_schedule", "actions": ["update"], "outside_view": False}],
             "unknown_fields": [{"address": "calls[2]", "field": "group_name", "reason": "unknown Terraform value"}]}]


def test_L85d_outside_world_carries_plan_gaps_as_unknowns():
    unknown = _outside(_check(base_with(), plans=_gap_plans()))["unknown"]
    topics = {(u["topic"], u["resource_id"]) for u in unknown}
    assert ("plan_change_not_applied", "calls[0]") in topics
    assert ("unmodeled_item", "calls[1]") in topics
    assert ("plan_values_unknown", "calls[2]") in topics


def test_L85d_no_plan_gaps_adds_no_plan_unknowns():
    unknown = _outside(_check(base_with()))["unknown"]
    assert not {u["topic"] for u in unknown} & {"plan_change_not_applied", "unmodeled_item", "plan_values_unknown"}


@pytest.mark.parametrize("status", ["denied", "error"])
def test_L85e_a_failed_scheduler_scan_is_unknown_in_outside_world(status):
    base = base_with()
    base.collection = {**base.collection, "scheduler": status}
    answer = _outside(_check(base))
    assert [u for u in answer["unknown"] if u["topic"] == "scheduler"], answer["unknown"]
    assert not [k for k in answer["checked"] if k["topic"] == "scheduler"]


def test_L85e_an_ok_scheduler_scan_is_known_and_a_missing_status_is_unknown():
    base = base_with()
    base.collection = {**base.collection, "scheduler": "ok"}
    answer = _outside(_check(base))
    assert [k for k in answer["checked"] if k["topic"] == "scheduler"]
    assert not [u for u in answer["unknown"] if u["topic"] == "scheduler"]
    base.collection = {k: v for k, v in base.collection.items() if k != "scheduler"}
    assert [u for u in _outside(_check(base))["unknown"] if u["topic"] == "scheduler"]


# ── L85f ──────────────────────────────────────────────────────────

def test_L85f_an_unknown_group_name_is_one_explicit_unknown_never_the_default_group():
    after = _tf_object("ENABLED", group_name=None)
    result = _tf(["create"], None, after, {"group_name": True})
    assert result["changes"] == []
    assert [i["field"] for i in result["unknown_fields"]].count("group_name") == 1
    assert [u for u in result["unmodeled"] if u["address"] == "aws_scheduler_schedule.nightly"]


def test_L85f_an_unknown_group_on_update_does_not_modify_the_default_group_schedule():
    result = _tf(["update"], _tf_object("DISABLED"), _tf_object("ENABLED", group_name=None), {"group_name": True})
    assert not [c for c in result["changes"] if c.op in ("add", "modify")]
    assert [i["field"] for i in result["unknown_fields"]].count("group_name") == 1


def test_L85f_a_known_group_is_unchanged():
    result = _tf(["create"], None, _tf_object("ENABLED", group_name="batch"))
    assert [(c.op, c.resource_id) for c in result["changes"]] == [("add", "batch/nightly-report")]
    assert result["unknown_fields"] == []


# ── L85g ──────────────────────────────────────────────────────────

def _invokes(base):
    return {(e.src, e.dst) for e in build_graph(base).edges if e.relationship.value == "invokes"}


def test_L85g_same_account_target_links_and_other_account_does_not():
    assert _invokes(base_with()) == {(NIGHTLY, TARGET_ID)}
    other = LAMBDA_ARN.replace(ACCOUNT, "111111111111")
    assert _invokes(base_with(schedule(target=other))) == set()


def test_L85g_the_account_comes_from_the_role_when_the_schedule_has_no_arn_and_is_unknown_without_either():
    assert _invokes(base_with(schedule(arn=None))) == {(NIGHTLY, TARGET_ID)}
    other_role = ROLE_ARN.replace(ACCOUNT, "111111111111")
    assert _invokes(base_with(schedule(arn=None, target_role_arn=other_role))) == set()
    assert _invokes(base_with(schedule(arn=None, target_role_arn=None))) == set()


def test_L85g_a_cross_account_target_is_not_modeled_in_the_check():
    other = LAMBDA_ARN.replace(ACCOUNT, "111111111111")
    base = base_with(schedule(target=other))
    answer = _outside(_check(base, apply_change(base, _mod(state="ENABLED"))))
    assert ("schedule_target_not_modeled", NIGHTLY) in {(u["topic"], u["resource_id"]) for u in answer["unknown"]}
    assert _schedule_facts(answer)[0]["resource_ids"] == []
