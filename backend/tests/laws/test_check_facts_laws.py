"""L74: check returns FACTS about consequences, not rule ids.

``GET /branches/{id}/check`` answers six damage questions (data, exposure, money,
availability, control, outside_world) with typed facts, what was checked and what
is unknown. No pass/warn/block, no score, no severity, no rule or reason ids, no
advice. Emfirge has no AI inside, so the same branch gives byte-identical output.

L74a  six answers always, in order; checked + unknown on each; an unmodeled plan
      item is unknown in the five diff answers
L74b  closed schema, no verdict-like names, no reason-code strings in any value
L74c  deterministic (repeat and shuffled independent changes)
L74d  one truth: facts equal what the delete lens / verdict / cost already compute
L74e  every locked incident scenario yields a fact in the damage it is about
L74f  outside_world is decided per service from the action (Jarvis-shaped plans)
L74g  zero changes: baseline + six empty answers with checked entries
L74h  tenant isolation and read-only
L74i  no customer identifier in free text
L56   check_facts is a core module with zero AWS imports
"""
from __future__ import annotations

import ast
import copy
import json
import random
import re
import typing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from app import auth, database
from app.database import AnalysisLog
from app.mutations import Change, apply_change
from tests.incidents.base import build_incident_base
from tests.incidents.synthetic_base import load_synthetic_base

from .test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, AWS_LIBS, CORE_MODULES
from .test_isolation_branches import _assert_hidden, _create_a_branch, _headers
from .test_tenant_isolation import tenant_client  # noqa: F401  (fixture)
from tests.incidents.test_phase_d_scenarios import phase_d_branch_db  # noqa: F401  (fixture)
from tests.test_plan_ingest import plan_client  # noqa: F401  (fixture)

APP_DIR = Path(__file__).resolve().parents[2] / "app"
DAMAGES = ("data", "exposure", "money", "availability", "control", "outside_world")
DIFF_DAMAGES = DAMAGES[:5]
REVISION = "r" * 64


# ── helpers ───────────────────────────────────────────────────────

def _delete_base():
    return load_synthetic_base("delete")


def _apply(base, *changes):
    branch = base
    for change in changes:
        branch = apply_change(branch, change)
    return branch


def _del(rtype, rid, **fields):
    return Change(op="delete", resource_type=rtype, resource_id=rid, fields=fields)


def _mod(rtype, rid, **fields):
    return Change(op="modify", resource_type=rtype, resource_id=rid, fields=fields)


def _add(rtype, rid, **fields):
    return Change(op="add", resource_type=rtype, resource_id=rid, fields=fields)


def _check(base, branch=None, **kw):
    from app.aws_check import check_for_branch
    branch = base.model_copy(deep=True) if branch is None else branch
    kw.setdefault("branch_id", "law-branch")
    kw.setdefault("base_analysis_id", "law-base")
    kw.setdefault("branch_revision", REVISION)
    return check_for_branch(base, branch, **kw)


def _dump(result) -> dict:
    return result.model_dump(mode="json")


def _answers(body) -> dict:
    return {a["damage"]: a for a in body["answers"]}


def _unmodeled_item(action="foo.DoThing", address="calls[0]", **extra):
    from app.aws_api_ingest import _unmodeled
    service, operation = action.split(".", 1)
    return {**_unmodeled(address, service, operation), **extra}


def _plan(*items, plan_id="p1"):
    return {"plan_id": plan_id, "input_sha256": "a" * 64, "rejected": [], "unmodeled": list(items), "unknown_fields": []}


def _rich():
    """A branch that touches all five diff damages at once."""
    base = _delete_base()
    branch = _apply(
        base,
        _del("s3_bucket", "dl-data-bucket"),
        _del("rds_instance", "db-dl-reports", skip_final_snapshot=True),
        _mod("rds_instance", "db-dl-prod", backup_retention_days=0),
        _del("iam_role", "arn:aws:iam::000000000000:role/DlWorkerRole"),
        _mod("security_group", "sg-dl-unused", rules=[
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]),
    )
    return base, branch


def _walk_models(model, seen=None):
    seen = set() if seen is None else seen
    if model in seen:
        return seen
    seen.add(model)
    for field in model.model_fields.values():
        _walk_annotation(field.annotation, seen)
    return seen


def _walk_annotation(annotation, seen):
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        _walk_models(annotation, seen)
    for arg in typing.get_args(annotation):
        _walk_annotation(arg, seen)


def _json_values(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _json_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _json_values(value)
    else:
        yield node


def _json_keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _json_keys(value)
    elif isinstance(node, list):
        for value in node:
            yield from _json_keys(value)


# ── L74a: six answers, checked + unknown, unmodeled items are unknown ─

def test_L74a_six_answers_always_in_fixed_order_each_with_checked_and_unknown():
    """L74a: every check has the six damage answers in order, each with checked and unknown lists."""
    base, branch = _rich()
    for body in (_dump(_check(base)), _dump(_check(base, branch))):
        assert [a["damage"] for a in body["answers"]] == list(DAMAGES)
        for answer in body["answers"]:
            assert set(answer) == {"damage", "facts", "checked", "unknown"}
            assert answer["checked"], answer["damage"]
            assert answer["unknown"], answer["damage"]
            assert all(set(c) == {"topic", "detail", "resource_id"} for c in answer["checked"])
            assert all(set(u) == {"topic", "reason", "resource_id"} for u in answer["unknown"])


def test_L74a_an_empty_facts_list_always_says_what_was_looked_at():
    """L74a: an empty facts list is never alone: at least one checked entry says what was looked at."""
    base = _delete_base()
    harmless = _apply(base, _del("security_group", "sg-dl-unused"))
    for branch in (base.model_copy(deep=True), harmless):
        body = _dump(_check(base, branch))
        empties = [a for a in body["answers"] if not a["facts"]]
        assert empties
        for answer in empties:
            assert answer["checked"] and all(c["detail"].strip() for c in answer["checked"]), answer["damage"]


@pytest.mark.parametrize("action", ["foo.DoThing", "ses.SendEmail", "aws_ses_email_identity", "ec2.ModifyVolume"])
def test_L74a_an_unmodeled_plan_item_is_unknown_in_the_five_diff_answers(action):
    """L74a: every unmodeled plan item (any format) is unknown in data, exposure, money, availability and control."""
    base = _delete_base()
    address = "aws_ses_email_identity.mail" if action.startswith("aws_") else "calls[0]"
    item = ({"address": address, "type": action, "actions": ["create"], "provider_name": "registry.terraform.io/hashicorp/aws", "outside_view": False}
            if action.startswith("aws_") else _unmodeled_item(action, address))
    body = _dump(_check(base, plans=[_plan(item)]))
    answers = _answers(body)
    for damage in DIFF_DAMAGES:
        hits = [u for u in answers[damage]["unknown"] if f"not modeled on the branch: {action}" in u["reason"]]
        assert hits, (damage, action)
        assert all(u["resource_id"] in (None, address) for u in hits)
    # the same item is never silently fine in outside_world
    outside = answers["outside_world"]
    assert outside["facts"] or any(u["topic"] == "unclassified_action" for u in outside["unknown"])


def test_L74a_every_unmodeled_item_of_every_plan_shows_up():
    """L74a: two plans with three items -> each action is unknown in each diff answer."""
    base = _delete_base()
    plans = [_plan(_unmodeled_item("foo.One", "calls[0]"), _unmodeled_item("bar.Two", "calls[1]"), plan_id="p1"),
             _plan(_unmodeled_item("baz.Three", "calls[0]"), plan_id="p2")]
    answers = _answers(_dump(_check(base, plans=plans)))
    for damage in DIFF_DAMAGES:
        text = " ".join(u["reason"] for u in answers[damage]["unknown"])
        for action in ("foo.One", "bar.Two", "baz.Three"):
            assert action in text, (damage, action)


def test_L74a_denied_collection_sources_are_unknown_where_relevant():
    """L74a: a degraded source is never a silent 'nothing found'; ok sources are checked."""
    base = _delete_base()
    base.collection = {"network_interfaces": "denied", "ebs_snapshots": "error", "rds_snapshots": "denied",
                       "ebs_volumes": "denied", "iam_role_last_used": "error"}
    branch = _apply(base, _del("rds_instance", "db-dl-reports", skip_final_snapshot=True))
    answers = _answers(_dump(_check(base, branch)))
    assert {"ebs_snapshots", "rds_snapshots"} <= {u["topic"] for u in answers["data"]["unknown"]}
    assert "network_interfaces" in {u["topic"] for u in answers["exposure"]["unknown"]}
    assert "ebs_volumes" in {u["topic"] for u in answers["money"]["unknown"]}
    assert "iam_role_last_used" in {u["topic"] for u in answers["availability"]["unknown"]}
    ok = _delete_base()
    ok_answers = _answers(_dump(_check(ok, _apply(ok, _del("rds_instance", "db-dl-reports", skip_final_snapshot=True)))))
    assert {"ebs_snapshots", "rds_snapshots"} <= {c["topic"] for c in ok_answers["data"]["checked"]}
    assert not {"ebs_snapshots", "rds_snapshots"} & {u["topic"] for u in ok_answers["data"]["unknown"]}


def test_L74a_collector_warnings_are_unknown():
    """L74a: services the collector skipped are unknown in the diff answers (exception text withheld)."""
    base = _delete_base()
    base.warnings = ["EC2 scan skipped: insufficient permissions",
                     "S3 scan skipped: unexpected error — User: arn:aws:iam::1:user/zz-secret-user is not authorized"]
    body = _dump(_check(base, _apply(base, _del("security_group", "sg-dl-unused"))))
    for damage in DIFF_DAMAGES:
        reasons = " ".join(u["reason"] for u in _answers(body)[damage]["unknown"] if u["topic"] == "collector_skipped")
        assert "EC2 scan skipped" in reasons, damage
    assert "zz-secret-user" not in json.dumps(body)


def test_L74a_recent_use_not_checked_is_unknown_for_deleted_and_modified_resources():
    """L74a: no evidence gathered for a removed or modified resource -> unknown 'recent use not checked'."""
    base = _delete_base()
    branch = _apply(base, _del("security_group", "sg-dl-unused"), _mod("security_group", "sg-dl-web", rules=[
        {"protocol": "tcp", "from_port": 80, "to_port": 80, "ip_ranges": ["10.0.0.0/8"]}]))
    body = _dump(_check(base, branch))
    assert "sg-dl-web" in [e for e in body["changes"] if e["change"] == "modified"][0]["resource_ids"]
    unknown = {u["resource_id"] for u in _answers(body)["availability"]["unknown"] if u["topic"] == "recent_use"}
    assert {"sg-dl-unused", "sg-dl-web"} <= unknown


# ── L74b: closed schema, no verdicts, no reason codes ──────────────

FORBIDDEN_NAME_PARTS = ("verdict", "level", "severity", "score", "rule", "code", "check_id", "fix",
                        "recommend", "advice", "remediation", "safe", "risk")


def test_L74b_every_response_model_forbids_extra_fields():
    """L74b: every model in the CheckResult schema is extra='forbid'."""
    from app.check_facts import CheckResult
    models = _walk_models(CheckResult)
    assert len(models) >= 10
    for model in models:
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_L74b_no_verdict_like_field_names_in_schema():
    """L74b: no field in the schema is named/contains verdict, level, severity, score, rule, code, check_id, fix, advice, risk, safe."""
    from app.check_facts import CheckResult
    for model in _walk_models(CheckResult):
        for name in model.model_fields:
            assert not any(part in name.lower() for part in FORBIDDEN_NAME_PARTS), (model.__name__, name)


def test_L74b_no_verdict_like_key_in_any_real_response():
    """L74b: no key anywhere in a real response contains a verdict-like word."""
    base, branch = _rich()
    body = _dump(_check(base, branch, plans=[_plan(_unmodeled_item("support.CreateCase"))]))
    keys = set(_json_keys(body))
    assert keys
    for key in keys:
        assert not any(part in key.lower() for part in FORBIDDEN_NAME_PARTS), key
    assert not {"pass", "warn", "block"} & {v for v in _json_values(body) if isinstance(v, str)}


def _reason_codes() -> set[str]:
    text = (APP_DIR / "verdict.py").read_text()
    codes = set(re.findall(r"_reason\(\s*['\"](?:warn|block)['\"],\s*['\"]([a-z_]+)['\"]", text))
    codes |= set(re.findall(r"_reason\(\s*level,\s*['\"]([a-z_]+)['\"]", text))
    codes |= {"stateless_replace", "unseen_change", "outside_view", "unmodeled_delete", "unmodeled_risky_change",
              "unmodeled_change", "plan_delete_rejected", "plan_change_rejected", "unknown_plan_values",
              "internet_to_broad_data_access", "unspecified_values", "tag_change_access_unmodeled"}
    return codes


def test_L74b_no_value_in_the_response_is_a_reason_code_string():
    """L74b: no reason code from verdict.py appears as a value (or inside a value) of any response."""
    codes = _reason_codes()
    assert len(codes) >= 25 and {"lost_dependency", "newly_internet_reachable", "recently_used"} <= codes
    base, branch = _rich()
    docs = [_dump(_check(base, branch, plans=[_plan(_unmodeled_item("support.CreateCase"), _unmodeled_item("foo.DoThing"))])),
            _dump(_check(base)),
            _dump(_check(build_incident_base(), _apply(build_incident_base(), _mod("s3_bucket", "inc-data-bucket", is_public=True))))]
    for body in docs:
        values = [v for v in _json_values(body) if isinstance(v, str)]
        assert values
        assert not codes & set(values), sorted(codes & set(values))
        for value in values:
            assert not re.search(r"EMFIRGE-[A-Z0-9]+-\d+", value), value


def test_L74b_an_advice_field_cannot_be_smuggled_in():
    """L74b: adding any extra field anywhere in a response is rejected on validation."""
    from app.check_facts import CheckResult
    base, branch = _rich()
    body = _dump(_check(base, branch))
    CheckResult.model_validate(body)
    paths = [[], ["changes", 0], ["answers", 0], ["answers", 0, "checked", 0], ["answers", 0, "unknown", 0]]
    for index, answer in enumerate(body["answers"]):
        if answer["facts"]:
            paths.append(["answers", index, "facts", 0])
    assert len(paths) >= 8
    for path in paths:
        bad = copy.deepcopy(body)
        node = bad
        for step in path:
            node = node[step]
        node["recommendation"] = "do something"
        with pytest.raises(ValidationError):
            CheckResult.model_validate(bad)


# ── L74c: deterministic ───────────────────────────────────────────

def test_L74c_same_branch_checked_twice_is_byte_identical():
    """L74c: repeat -> identical JSON."""
    base, branch = _rich()
    plans = [_plan(_unmodeled_item("support.CreateCase"), _unmodeled_item("foo.DoThing"))]
    one = _check(base, branch, plans=plans).model_dump_json()
    two = _check(base, branch, plans=plans).model_dump_json()
    assert one == two


def test_L74c_independent_changes_in_any_order_give_identical_output():
    """L74c: shuffling independent changes (and plan items) changes nothing."""
    base = _delete_base()
    changes = [
        _del("s3_bucket", "dl-data-bucket"),
        _del("rds_instance", "db-dl-reports", skip_final_snapshot=True),
        _del("rds_snapshot", "dlsnap-reports"),
        _mod("security_group", "sg-dl-unused", rules=[{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]),
        _del("ebs_volume", "vol-dl-data"),
    ]
    items = [_unmodeled_item("support.CreateCase", "calls[0]"), _unmodeled_item("foo.DoThing", "calls[1]"),
             _unmodeled_item("servicequotas.RequestServiceQuotaIncrease", "calls[2]")]
    reference = None
    for seed in range(6):
        rng = random.Random(seed)
        order = changes[:]
        rng.shuffle(order)
        shuffled_items = items[:]
        rng.shuffle(shuffled_items)
        try:
            branch = _apply(base, *order)
        except Exception:  # an order that cannot apply is not independent
            continue
        out = _check(base, branch, plans=[_plan(*shuffled_items)]).model_dump_json()
        reference = reference or out
        assert out == reference, seed
    assert reference is not None


def test_L74c_lists_are_sorted_not_in_discovery_order():
    """L74c: changes ids and fact lists come back sorted."""
    base, branch = _rich()
    body = _dump(_check(base, branch))
    for entry in body["changes"]:
        assert entry["resource_ids"] == sorted(entry["resource_ids"])
    for answer in body["answers"]:
        keys = [(c["topic"], c["detail"], c["resource_id"] or "") for c in answer["checked"]]
        assert keys == sorted(keys)
        keys = [(u["topic"], u["reason"], u["resource_id"] or "") for u in answer["unknown"]]
        assert keys == sorted(keys)


# ── L74d: one truth ───────────────────────────────────────────────

def _verdict(base, branch, **kw):
    from app.verdict import combined_verdict
    return combined_verdict(base, branch, run_scanners=False, **kw)


def test_L74d_changes_equal_the_diff_minus_the_virtual_internet_node():
    """L74d: changes.added/removed/modified are the verdict's resource lists (ids only)."""
    base, branch = _rich()
    verdict = _verdict(base, branch)
    body = _dump(_check(base, branch))
    got = {e["change"]: e["resource_ids"] for e in body["changes"]}
    assert [e["change"] for e in body["changes"]] == ["added", "removed", "modified"]
    assert got["removed"] == sorted(i["id"] for i in verdict.resources_removed if i["id"] != "INTERNET")
    assert got["modified"] == sorted(i["id"] for i in verdict.resources_modified)
    assert got["added"] == sorted(i["id"] for i in verdict.resources_added)
    assert got["removed"] and got["modified"]


def test_L74d_data_facts_equal_delete_lens_and_recovery_removed():
    """L74d: data facts == delete lens data_lost + recovery_points (+ the extracted recovery_removed logic)."""
    from app.verdict import recovery_removals
    base, branch = _rich()
    verdict = _verdict(base, branch)
    facts = _answers(_dump(_check(base, branch)))["data"]["facts"]
    deleted = {f["resource_id"]: f for f in facts if f["change"] == "deleted"}
    lost = {x.resource_id for x in verdict.deletion.data_lost}
    points = {x.resource_id: x for x in verdict.deletion.recovery_points}
    assert set(deleted) == lost | set(points)
    assert lost and points
    for rid in lost:
        assert deleted[rid]["has_recovery_point"] is False and deleted[rid]["recovery_resource_ids"] == []
    for rid, point in points.items():
        assert deleted[rid]["has_recovery_point"] is True
        assert deleted[rid]["recovery_resource_ids"] == ([point.source_id] if point.source_id != rid else [])
    removed = {(f["resource_id"], f["resource_type"]) for f in facts if f["change"] == "recovery_removed"}
    expected = {(rid, rtype) for rid, rtype in recovery_removals(base, branch)}
    assert removed == expected and ("db-dl-prod", "rds_instance") in removed
    gone = _apply(base, _del("rds_snapshot", "dlsnap-reports"))
    facts = _answers(_dump(_check(base, gone)))["data"]["facts"]
    assert {(f["resource_id"], f["resource_type"]) for f in facts if f["change"] == "recovery_removed"} == {("dlsnap-reports", "rds_snapshot")}


def test_L74d_recovery_removed_logic_is_extracted_not_copied():
    """L74d: verdict.py's inline recovery_removed block now calls the extracted function."""
    from app.verdict import recovery_removals
    text = (APP_DIR / "verdict.py").read_text()
    assert "recovery_removals(" in text
    assert "recovery_removed = any(" not in text  # the inline copy is gone
    assert text.count("backup_retention_days") == 2  # old and new side, both inside the extracted function
    base = _delete_base()
    assert recovery_removals(base, base.model_copy(deep=True)) == []
    off = _apply(base, _mod("rds_instance", "db-dl-prod", backup_retention_days=0))
    assert ("db-dl-prod", "rds_instance") in recovery_removals(base, off)
    unversioned = _apply(base, _mod("s3_bucket", "dl-data-bucket", versioning_enabled=False))
    assert ("dl-data-bucket", "s3_bucket") in recovery_removals(base, unversioned)


def test_L74d_exposure_facts_equal_verdict_exposure_fields():
    """L74d: exposure facts == verdict newly_exposed / no_longer_exposed / newly_internet_reachable."""
    base = build_incident_base()
    branch = _apply(base, _mod("security_group", "sg-inc-web", rules=[
        {"protocol": "tcp", "from_port": 80, "to_port": 80, "ip_ranges": ["0.0.0.0/0"]},
        {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "ip_ranges": ["0.0.0.0/0"]}]),
        _add("ec2_instance", "i-inc-new", type="t3.micro", state="running", subnet_id="subnet-inc-pub", sg_ids=["sg-inc-web"], has_public_ip=True))
    verdict = _verdict(base, branch)
    facts = _answers(_dump(_check(base, branch)))["exposure"]["facts"]
    got = {(f["resource_id"], f["protocol"], tuple(f["ports"]), f["source"], tuple(f["resource_ids"]), f["state"])
           for f in facts if f["change"] == "newly_exposed"}
    want = {(e["resource_id"], e["protocol"], (e["from_port"], e["to_port"]), e["source"], (e["via_sg"],), e["state"])
            for e in verdict.newly_exposed}
    assert got == want and want
    gone = {(f["resource_id"], tuple(f["ports"])) for f in facts if f["change"] == "no_longer_exposed"}
    assert gone == {(e["resource_id"], (e["from_port"], e["to_port"])) for e in verdict.no_longer_exposed}
    reachable = {f["resource_id"] for f in facts if f["change"] == "became_internet_reachable"}
    assert reachable == set(verdict.newly_internet_reachable) and reachable
    unreachable = {f["resource_id"] for f in facts if f["change"] == "no_longer_internet_reachable"}
    assert unreachable == set(verdict.no_longer_internet_reachable)
    assert all(f["resource_type"] for f in facts)


def test_L74d_money_facts_equal_cost_changes_and_totals_equal_cost_sides():
    """L74d: per-resource money == verdict.cost_changes; one total fact == cost_before / cost_after known totals."""
    base, branch = _rich()
    verdict = _verdict(base, branch)
    money = _answers(_dump(_check(base, branch)))["money"]
    per = {f["resource_id"]: f for f in money["facts"] if f["resource_id"] is not None}
    assert {c["resource_id"] for c in verdict.cost_changes} == set(per) and per
    for change in verdict.cost_changes:
        fact = per[change["resource_id"]]
        assert fact["resource_type"] == change["resource_type"]
        assert fact["before_monthly_usd"] == change["before_monthly_usd"]
        assert fact["after_monthly_usd"] == change["after_monthly_usd"]
    totals = [f for f in money["facts"] if f["resource_id"] is None]
    assert len(totals) == 1
    assert totals[0]["before_monthly_usd"] == verdict.cost_before["known_monthly_usd"]
    assert totals[0]["after_monthly_usd"] == verdict.cost_after["known_monthly_usd"]
    from app.cost import ResourceCost, unknown_reason
    unpriced = [c for c in verdict.cost_changes
                if (c["before_basis"] and c["before_monthly_usd"] is None) or (c["after_basis"] and c["after_monthly_usd"] is None)]
    assert unpriced
    topic_reasons = {(u["resource_id"], u["reason"]) for u in money["unknown"] if u["resource_id"]}
    for c in unpriced:
        basis = c["before_basis"] if c["before_monthly_usd"] is None and c["before_basis"] else c["after_basis"]
        reason = unknown_reason(ResourceCost(resource_id=c["resource_id"], resource_type=c["resource_type"], monthly_usd=None, basis=basis))
        assert (c["resource_id"], reason) in topic_reasons, c


def test_L74d_availability_facts_equal_lost_dependencies_connectivity_and_impacts():
    """L74d: availability facts == verdict lost_dependencies / lost_connectivity / deletion impacts / lost ingress."""
    base, branch = _rich()
    branch = _apply(branch, _del("iam_role", "arn:aws:iam::000000000000:role/DlBatchRole"))
    verdict = _verdict(base, branch)
    facts = _answers(_dump(_check(base, branch)))["availability"]["facts"]
    deps = {(f["resource_id"], tuple(f["path"])) for f in facts if f["change"] == "dependency_removed"}
    assert deps == {(e["from"], (e["from"], e["to"])) for e in verdict.lost_dependencies} and deps
    conn = {(f["resource_id"], tuple(f["path"])) for f in facts if f["change"] == "internal_path_removed"}
    assert conn == {(e["from"], (e["from"], e["to"])) for e in verdict.lost_connectivity}
    impacts = {(f["resource_id"], f["depth"]) for f in facts if f["change"] in ("dependent_of_deleted", "deleted_along_with")}
    assert impacts == {(i.resource_id, i.depth) for i in verdict.deletion.impacts} and impacts
    along = {f["resource_id"] for f in facts if f["change"] == "deleted_along_with"}
    assert along == {i.resource_id for i in verdict.deletion.impacts if i.relation.startswith("deleted_with")}
    for f in facts:
        if f["change"] in ("dependent_of_deleted", "deleted_along_with"):
            assert f["path"][-1] == f["resource_id"] and len(f["path"]) == f["depth"] + 1
    ingress = {f["resource_id"] for f in facts if f["change"] == "internet_path_removed"}
    assert ingress == set(verdict.no_longer_internet_reachable)


def test_L74d_recently_used_comes_from_evidence_and_role_last_used():
    """L74d: recently_used is True/False/None from the same last-used truth as the delete lens; None = unknown."""
    from app.delete_lens import recently_used_deleted
    base = _delete_base()
    worked = {}
    for role in ("DlBatchRole", "DlWorkerRole"):
        arn = f"arn:aws:iam::000000000000:role/{role}"
        branch = _apply(base, _del("iam_role", arn))
        facts = _answers(_dump(_check(base, branch)))["availability"]["facts"]
        deps = [f for f in facts if f["change"] in ("dependent_of_deleted", "dependency_removed")]
        assert deps, role
        worked[role] = {f["recently_used"] for f in deps}
        assert worked[role] == {recently_used_deleted(base, branch)}, role
    assert worked["DlBatchRole"] == {True} and worked["DlWorkerRole"] == {False}
    # no role last-used collected -> null, never false
    blind = _delete_base()
    blind.collection = {**blind.collection, "iam_role_last_used": "denied"}
    branch = _apply(blind, _del("iam_role", "arn:aws:iam::000000000000:role/DlWorkerRole"))
    facts = _answers(_dump(_check(blind, branch)))["availability"]["facts"]
    assert {f["recently_used"] for f in facts if f["change"] == "dependent_of_deleted"} == {None}


def test_L74d_control_facts_cover_admin_logging_and_trust():
    """L74d: control/exposure facts from modeled fields: admin lost, logging disabled, escalation added, external trust."""
    base = _delete_base()
    base.iam.role_policies[0].has_admin = True
    base.s3.buckets[0].logging_enabled = True
    role_arn = base.iam.role_policies[0].role_arn
    bucket = base.s3.buckets[0].name
    branch = _apply(base, _del("iam_role", role_arn), _mod("s3_bucket", bucket, logging_enabled=False))
    control = {(f["resource_id"], f["change"]) for f in _answers(_dump(_check(base, branch)))["control"]["facts"]}
    assert any(change == "admin_access_removed" for _, change in control), control
    assert (bucket, "logging_disabled") in control
    clean = _delete_base()
    assert not _answers(_dump(_check(clean, clean.model_copy(deep=True))))["control"]["facts"]


def test_L74d_control_facts_include_introduced_privilege_escalation():
    """L74d: a role that gains escalation paths is a control fact (same truth as the verdict)."""
    from app.verdict import introduced_privilege_escalation_ids
    base = build_incident_base()
    arn = "arn:aws:iam::000000000000:role/EmfirgeDemoAppRole"
    branch = _apply(base, _mod("iam_role_policy", arn, access_statements=[
        {"effect": "Allow", "actions": ["iam:*"], "resources": ["*"]}]))
    expected = introduced_privilege_escalation_ids(base, branch)
    assert expected
    facts = _answers(_dump(_check(base, branch)))["control"]["facts"]
    assert {f["resource_id"] for f in facts if f["change"] == "privilege_escalation_path_added"} == expected


def test_L74d_s3_becoming_public_is_an_exposure_fact():
    """L74d: a bucket going public is exposure to the world; going private is the reverse."""
    base = build_incident_base()
    public = _apply(base, _mod("s3_bucket", "inc-data-bucket", is_public=True))
    facts = _answers(_dump(_check(base, public)))["exposure"]["facts"]
    assert {(f["resource_id"], f["change"]) for f in facts} >= {("inc-data-bucket", "became_public")}
    back = _answers(_dump(_check(public, base)))["exposure"]["facts"]
    assert ("inc-data-bucket", "no_longer_public") in {(f["resource_id"], f["change"]) for f in back}


def test_L74d_role_trust_in_an_external_account_is_an_exposure_fact():
    """L74d: trust_allows_external false->true on a role is newly_trusts_external_account."""
    base = _delete_base()
    arn = base.iam.role_policies[0].role_arn
    branch = base.model_copy(deep=True)
    branch.iam.role_policies[0].trust_allows_external = True
    facts = _answers(_dump(_check(base, branch)))["exposure"]["facts"]
    role_name = base.iam.role_policies[0].role_name
    assert {(f["resource_id"], f["change"]) for f in facts if f["change"] == "newly_trusts_external_account"} == {
        (f"iam-role-{role_name}", "newly_trusts_external_account")}, arn


# ── L74e: locked incident scenarios ────────────────────────────────

INCIDENTS = json.loads((Path(__file__).resolve().parents[1] / "incidents" / "scenarios.json").read_text())
INCIDENT_DAMAGE = {  # scenario -> damages it is about (None: harmless, no data/exposure facts)
    "R02": {"exposure"}, "R03": {"exposure"}, "R04": None, "R05": {"exposure"}, "R06b": {"exposure"},
    "R07": {"exposure"}, "R08": {"data"}, "R10": {"data", "control"}, "R11": {"control"}, "R12": {"availability"},
}
CODE_DAMAGE = {
    "data_store_deleted_no_recovery_point": "data", "data_store_deleted_with_recovery_point": "data",
    "recovery_point_removed": "data",
    "introduced_critical_exposure": "exposure", "new_exposure": "exposure", "latent_exposure": "exposure",
    "newly_internet_reachable": "exposure",
    "lost_dependency": "availability", "lost_connectivity": "availability", "deletion_impact": "availability",
    "lost_ingress": "availability",
    "privilege_escalation": "control",
}


def _post_changes(client, branch_id, changes):
    for count, change in enumerate(changes):
        response = client.post(f"/branches/{branch_id}/changes", json={**change, "expected_change_count": count})
        assert response.status_code == 200, response.text


def _fact_damages(body):
    """Damages with a fact. A fact that only shrinks exposure (no_longer_*) is not damage, so it does not count."""
    return {a["damage"] for a in body["answers"]
            if any(not str(f.get("change", "")).startswith("no_longer") for f in a["facts"])}


def test_L74e_every_locked_incident_scenario_yields_a_fact_in_its_damage(incident_branch_db, monkeypatch):
    """L74e: R02..R12 each produce >=1 fact in the damage the scenario is about; the harmless one produces no data/exposure fact."""
    from app import branches, main
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    client = TestClient(main.app)
    seen = 0
    for scenario in INCIDENTS:
        if scenario["id"] not in INCIDENT_DAMAGE:
            continue  # http_status scenarios never reach a branch state
        main._branch_request_log.clear()
        branch_id = client.post("/branches", json={"base_analysis_id": "incident", "name": scenario["id"]}).json()["branch_id"]
        _post_changes(client, branch_id, scenario["changes"])
        response = client.get(f"/branches/{branch_id}/check")
        assert response.status_code == 200, (scenario["id"], response.text)
        body = response.json()
        want = INCIDENT_DAMAGE[scenario["id"]]
        if want is None:
            assert not {"data", "exposure"} & _fact_damages(body), scenario["id"]
        else:
            assert want <= _fact_damages(body), (scenario["id"], _fact_damages(body))
        seen += 1
    assert seen == len(INCIDENT_DAMAGE)


def _phase_d_scenarios():
    return [json.loads(p.read_text()) for p in sorted((Path(__file__).resolve().parents[1] / "incidents" / "phase_d").glob("*.json"))]


def test_L74e_every_phase_d_scenario_yields_facts_for_the_damage_its_verdict_reasons_name(phase_d_branch_db, monkeypatch):
    """L74e: for the PocketOS / Kiro / DataTalks / open-SSH ... scenarios, each damage a verdict reason names has a fact."""
    from app import branches, main
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    client = TestClient(main.app)
    plain = 0
    for scenario in _phase_d_scenarios():
        base = load_synthetic_base(scenario["base"], scenario.get("base_patch"))
        monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id, base=base: copy.deepcopy(base))
        main._branch_request_log.clear()
        branch_id = client.post("/branches", json={"base_analysis_id": "phase-d", "name": scenario["id"]}).json()["branch_id"]
        _post_changes(client, branch_id, scenario.get("changes", []))
        if "terraform_plan" in scenario:
            plan = json.loads((Path(__file__).resolve().parents[1] / "incidents" / scenario["terraform_plan"]).read_text())
            assert client.post(f"/branches/{branch_id}/plans/terraform", json=plan).status_code == 200
        reasons = {r["code"] for r in client.get(f"/branches/{branch_id}/verdict").json()["reasons"]}
        body = client.get(f"/branches/{branch_id}/check").json()
        damages = _fact_damages(body)
        named = {CODE_DAMAGE[c] for c in reasons if c in CODE_DAMAGE}
        assert named <= damages, (scenario["id"], named, damages)
        if not named:
            plain += 1
            assert not {"data", "exposure"} & damages, scenario["id"]
        for expected in scenario["expect"].get("data_lost_includes", []):
            data_ids = {f["resource_id"] for f in _answers(body)["data"]["facts"]}
            assert expected in data_ids, (scenario["id"], expected)
    assert plain >= 1  # the harmless SG delete (D09)


# ── L74f: outside_world is per service, from the action ────────────

def _branch_with_calls(client, calls):
    branch_id = client.post("/branches", json={"base_analysis_id": "delete", "name": "outside"}).json()["branch_id"]
    response = client.post(f"/branches/{branch_id}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": calls})
    assert response.status_code == 200, response.text
    return branch_id


def _outside(client, branch_id):
    response = client.get(f"/branches/{branch_id}/check")
    assert response.status_code == 200, response.text
    return _answers(response.json())["outside_world"]


def test_L74f_service_quota_increase_is_an_outside_world_fact(plan_client):
    """L74f: servicequotas.RequestServiceQuotaIncrease leaves the cloud: fact with the provider's doc URL."""
    branch = _branch_with_calls(plan_client, [{"service": "servicequotas", "operation": "RequestServiceQuotaIncrease",
                                               "parameters": {"ServiceCode": "ec2", "QuotaCode": "L-1216C47A", "DesiredValue": 1000}}])
    outside = _outside(plan_client, branch)
    facts = [f for f in outside["facts"] if f["action"] == "servicequotas.RequestServiceQuotaIncrease"]
    assert len(facts) == 1
    assert set(facts[0]) == {"action", "service", "reason", "source_url", "resource_id"}
    assert facts[0]["source_url"].startswith("https://docs.aws.amazon.com/") and facts[0]["reason"]
    assert not [u for u in outside["unknown"] if u["topic"] == "unclassified_action"]


def test_L74f_support_create_case_is_an_outside_world_fact(plan_client):
    """L74f: support.CreateCase is classified too."""
    branch = _branch_with_calls(plan_client, [{"service": "support", "operation": "CreateCase", "parameters": {"subject": "x"}}])
    facts = _outside(plan_client, branch)["facts"]
    assert [f["action"] for f in facts] == ["support.CreateCase"]
    assert facts[0]["service"] == "support" and facts[0]["source_url"].startswith("https://")


def test_L74f_an_unknown_service_is_unclassified_never_silently_fine(plan_client):
    """L74f: foo.DoThing is not in the table -> unknown 'unclassified_action', no fact, and not a silent empty answer."""
    branch = _branch_with_calls(plan_client, [{"service": "foo", "operation": "DoThing", "parameters": {}}])
    outside = _outside(plan_client, branch)
    assert outside["facts"] == []
    hits = [u for u in outside["unknown"] if u["topic"] == "unclassified_action"]
    assert len(hits) == 1 and "foo.DoThing" in hits[0]["reason"]


def test_L74f_a_mixed_plan_classifies_each_call_on_its_own(plan_client):
    """L74f: known outside-world calls and an unknown one in one plan; the typed change stays inside the cloud."""
    branch = _branch_with_calls(plan_client, [
        {"service": "support", "operation": "CreateCase", "parameters": {}},
        {"service": "foo", "operation": "DoThing", "parameters": {}},
        {"service": "s3", "operation": "DeleteBucket", "parameters": {"Bucket": "dl-data-bucket"}},
    ])
    outside = _outside(plan_client, branch)
    assert [f["action"] for f in outside["facts"]] == ["support.CreateCase"]
    assert [u["topic"] for u in outside["unknown"] if u["topic"] == "unclassified_action"] == ["unclassified_action"]
    assert any("stay inside" in c["detail"] or "inside the account" in c["detail"] for c in outside["checked"])


def test_L74f_terraform_resource_types_are_classified_by_prefix(plan_client):
    """L74f: an unmodeled terraform aws_ses_* resource is an outside_world fact; aws_foo_bar is unclassified."""
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "tf-out"}).json()["branch_id"]
    plan = {"format_version": "1.2", "resource_changes": [
        {"address": "aws_ses_email_identity.mail", "type": "aws_ses_email_identity", "provider_name": "registry.terraform.io/hashicorp/aws",
         "change": {"actions": ["create"], "before": None, "after": {"email": "x@example.com"}}},
        {"address": "aws_foo_bar.x", "type": "aws_foo_bar", "provider_name": "registry.terraform.io/hashicorp/aws",
         "change": {"actions": ["create"], "before": None, "after": {}}}]}
    assert plan_client.post(f"/branches/{branch_id}/plans/terraform", json=plan).status_code == 200
    outside = _outside(plan_client, branch_id)
    assert [f["action"] for f in outside["facts"]] == ["aws_ses_email_identity"]
    assert outside["facts"][0]["service"] == "ses" and outside["facts"][0]["resource_id"] == "aws_ses_email_identity.mail"
    assert [u for u in outside["unknown"] if u["topic"] == "unclassified_action" and "aws_foo_bar" in u["reason"]]


def test_L74f_every_table_entry_cites_the_providers_own_documentation():
    """L74f: each outside-world table entry has a service id, a reason and an AWS documentation URL."""
    from app.aws_outside_world import OUTSIDE_WORLD_SERVICES, classify_action
    assert {"support", "servicequotas", "ses", "sesv2", "route53domains", "savingsplans"} <= {
        s for e in OUTSIDE_WORLD_SERVICES for s in e.services}
    seen = set()
    for entry in OUTSIDE_WORLD_SERVICES:
        assert entry.services and entry.reason.strip()
        assert re.fullmatch(r"https://(docs\.aws\.amazon\.com|aws\.amazon\.com)/\S+", entry.source_url), entry
        for service in entry.services:
            assert service not in seen, service
            seen.add(service)
            hit = classify_action(f"{service}.SomeOperation")
            assert hit is not None and hit.service == service and hit.source_url == entry.source_url
        for prefix in entry.terraform_prefixes:
            assert prefix.startswith("aws_") and prefix.endswith("_")
            assert classify_action(f"{prefix}thing") is not None
    assert classify_action("foo.DoThing") is None and classify_action("ec2.DeleteVolume") is None
    assert classify_action("aws_instance") is None


def test_L74f_the_outside_world_table_is_an_adapter_module_and_check_facts_never_names_a_service():
    """L74f/L56: the table lives in the AWS adapter; the core holds no service name."""
    assert "aws_outside_world" in ADAPTER_MODULES and "aws_check" in ADAPTER_MODULES
    core = (APP_DIR / "check_facts.py").read_text().lower()
    for word in ("servicequotas", "support.", "route53", "savingsplans", "sesv2", "marketplace", "boto"):
        assert word not in core, word


# ── L74g: zero changes ─────────────────────────────────────────────

def test_L74g_an_empty_branch_returns_the_baseline_and_six_empty_answers(plan_client):
    """L74g: no changes -> baseline == context baseline on the base; six answers, no facts, checked entries."""
    from app.aws_context import answer_for_infra
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "empty"}).json()["branch_id"]
    response = plan_client.get(f"/branches/{branch_id}/check")
    assert response.status_code == 200, response.text
    body = response.json()
    expected = answer_for_infra("baseline", _delete_base(), analysis_id="delete").model_dump(mode="json")
    assert body["baseline"] == expected and body["baseline"]["facts"]
    assert [a["damage"] for a in body["answers"]] == list(DAMAGES)
    for answer in body["answers"]:
        assert answer["facts"] == [] and answer["checked"], answer["damage"]
    assert [e["resource_ids"] for e in body["changes"]] == [[], [], []]
    assert body["base_analysis_id"] == "delete" and body["branch_id"] == branch_id


def test_L74g_a_branch_with_changes_has_no_baseline(plan_client):
    """L74g: baseline is only for the zero-change case."""
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "one"}).json()["branch_id"]
    assert plan_client.post(f"/branches/{branch_id}/changes", json={
        "op": "delete", "resource_type": "security_group", "resource_id": "sg-dl-unused", "fields": {},
        "expected_change_count": 0}).status_code == 200
    body = plan_client.get(f"/branches/{branch_id}/check").json()
    assert body["baseline"] is None
    assert "sg-dl-unused" in [e for e in body["changes"] if e["change"] == "removed"][0]["resource_ids"]


def test_L74g_function_level_zero_change_matches_the_baseline_too():
    """L74g: the same agreement without HTTP."""
    from app.aws_context import answer_for_infra
    base = _delete_base()
    result = _dump(_check(base, base_analysis_id="x"))
    assert result["baseline"] == answer_for_infra("baseline", base, analysis_id="x").model_dump(mode="json")


# ── L74h: tenant isolation and read-only ───────────────────────────

def test_L74h_check_is_scoped_to_the_callers_tenant(tenant_client):
    """L74h: B gets the same 404 for A's branch as for a branch that does not exist; A reads its own."""
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    hidden = _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/check")
    assert hidden.status_code == 404
    from app import main
    main._branch_request_log.clear()
    own = client.get(f"/branches/{branch_id}/check", headers=_headers(key_a))
    assert own.status_code == 200, own.text
    assert own.json()["branch_id"] == branch_id
    assert "i-demo-web-001" not in hidden.text


def _row_counts():
    db = database.SessionLocal()
    try:
        import sqlalchemy
        return {t.name: db.execute(t.select().with_only_columns(sqlalchemy.func.count())).scalar()
                for t in database.Base.metadata.sorted_tables}
    finally:
        db.close()


def test_L74h_check_never_touches_aws_or_writes_rows(shared_test_db, monkeypatch):
    """L74h: no boto3 client/session is created and no table's row count changes."""
    import boto3
    import botocore.client
    import botocore.session
    from app import in_use_evidence, main
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    client = TestClient(main.app)
    db = database.SessionLocal()
    try:
        db.add(AnalysisLog(aws_account_id="000000000000", findings_json=json.dumps({
            "analysis_id": "ro-scan", "infrastructure": _delete_base().model_dump(mode="json")})))
        db.commit()
    finally:
        db.close()
    main._branch_request_log.clear()
    branch_id = client.post("/branches", json={"base_analysis_id": "ro-scan", "name": "ro"}).json()["branch_id"]
    for count, change in enumerate([_del("s3_bucket", "dl-data-bucket"), _del("security_group", "sg-dl-unused")]):
        main._branch_request_log.clear()
        assert client.post(f"/branches/{branch_id}/changes", json={**change.model_dump(), "expected_change_count": count}).status_code == 200
    main._branch_request_log.clear()
    assert client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{"service": "support", "operation": "CreateCase", "parameters": {}}]}).status_code == 200

    def boom(*_a, **_k):
        raise AssertionError("AWS client/session created during /check")

    monkeypatch.setattr(boto3, "client", boom)
    monkeypatch.setattr(boto3, "resource", boom)
    monkeypatch.setattr(boto3.session.Session, "__init__", boom)
    monkeypatch.setattr(botocore.session.Session, "create_client", boom)
    monkeypatch.setattr(botocore.client.ClientCreator, "create_client", boom)
    monkeypatch.setattr(in_use_evidence, "read_evidence", boom)
    monkeypatch.setattr(main, "read_evidence", boom)
    before = _row_counts()
    for _ in range(2):
        main._branch_request_log.clear()
        response = client.get(f"/branches/{branch_id}/check")
        assert response.status_code == 200, response.text
    assert _row_counts() == before


def test_L74h_unknown_branch_is_404_without_echo(plan_client):
    """L74h: a branch id that does not exist is 404."""
    assert plan_client.get("/branches/00000000-0000-0000-0000-000000000000/check").status_code == 404


# ── L74i: no customer identifier in free text ──────────────────────

TOKENIZE_TS = Path(__file__).resolve().parents[3] / "mcp" / "src" / "tokenize.ts"
ID_KEYS = {"resource_id", "resource_ids", "path", "source", "recovery_resource_ids"}
PLANTED = {
    "dl-data-bucket": "zz-planted-bucket-7731",
    "DlWorkerRole": "zzPlantedRoleWorker7731",
    "DlBatchRole": "zzPlantedRoleBatch7731",
    "dl-worker": "zz-planted-lambda-worker-7731",
    "dl-batch": "zz-planted-lambda-batch-7731",
    "i-dl-web": "zz-planted-instance-7731",
    "db-dl-prod": "zz-planted-db-prod-7731",
    "db-dl-reports": "zz-planted-db-reports-7731",
    "dlsnap-reports": "zz-planted-snap-7731",
    "sg-dl-unused": "zz-planted-sg-7731",
}
PLANTED_USER = "zz-planted-user-7731"
PLANTED_ADDRESS = "aws_ses_email_identity.zz-planted-addr-7731"


def _planted_infra():
    from app.models import AWSInfrastructure
    text = _delete_base().model_dump_json()
    for old, new in PLANTED.items():
        text = text.replace(old, new)
    infra = AWSInfrastructure.model_validate_json(text)
    infra.warnings = [
        "IAM scan skipped: insufficient permissions",
        f"S3 scan skipped: unexpected error — User: arn:aws:iam::123456789012:user/{PLANTED_USER} "
        f"is not authorized to perform s3:ListBucket on resource: {PLANTED['dl-data-bucket']}",
    ]
    return infra


def _leaks(node, names, known_ids, key="", path="$"):
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if any(n in k for n in names):
                found.append(f"{path}: dict key {k!r}")
            found += _leaks(v, names, known_ids, k, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found += _leaks(v, names, known_ids, key, f"{path}[{i}]")
    elif isinstance(node, str) and any(n in node for n in names):
        whole_id = node in known_ids or re.fullmatch(r"arn:aws:\S+", node)
        if key not in ID_KEYS or not whole_id:
            found.append(f"{path}: {node!r}")
    return found


def test_L74i_identifier_keys_are_masked_by_the_mcp_tokenizer():
    """L74i: every key allowed to carry an id is in the MCP tokenizer's masked key sets."""
    src = TOKENIZE_TS.read_text()
    masked = set()
    for name in ("SENSITIVE_KEYS", "IDENTIFIER_KEYS"):
        body = re.search(rf"const {name} = new Set\(\[(.*?)\]\)", src, re.S).group(1)
        masked |= set(re.findall(r'"([^"]+)"', body))
    assert ID_KEYS <= masked, sorted(ID_KEYS - masked)
    from app.check_facts import CheckResult
    # every field of the schema that can hold an identifier is one of the masked keys
    for model in _walk_models(CheckResult):
        for name, field in model.model_fields.items():
            if name in {"resource_id", "resource_ids", "path", "recovery_resource_ids", "branch_id", "base_analysis_id"}:
                assert name in masked or name in {"branch_id", "base_analysis_id"}, name


def test_L74i_planted_names_only_appear_as_whole_values_of_identifier_keys():
    """L74i: no resource id/name inside a topic, detail, reason; evidence, warnings and plan addresses included."""
    from app.evidence_models import EvidenceRecord
    base = _planted_infra()
    branch = _apply(
        base,
        _del("s3_bucket", PLANTED["dl-data-bucket"]),
        _del("rds_instance", PLANTED["db-dl-reports"], skip_final_snapshot=True),
        _del("rds_snapshot", PLANTED["dlsnap-reports"]),
        _del("iam_role", f"arn:aws:iam::000000000000:role/{PLANTED['DlWorkerRole']}"),
        _mod("security_group", PLANTED["sg-dl-unused"], rules=[{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]),
    )
    evidence = [EvidenceRecord(resource_id=PLANTED["dl-data-bucket"], resource_type="s3_bucket", source="cloudwatch_metrics",
                               status="denied", used=None, window_days=14, observed_at="2026-10-02T00:00:00Z"),
                EvidenceRecord(resource_id=PLANTED["db-dl-reports"], resource_type="rds_instance", source="cloudtrail_events",
                               status="ok", used=True, window_days=90, observed_at="2026-10-02T00:00:00Z",
                               last_event_at="2026-10-01T00:00:00Z")]
    plans = [_plan(_unmodeled_item("support.CreateCase", PLANTED_ADDRESS), _unmodeled_item("foo.DoThing", "calls[1]"))]
    body = _dump(_check(base, branch, plans=plans, evidence=evidence))
    names = list(PLANTED.values()) + [PLANTED_USER, "zz-planted-addr-7731"]
    from app.egraph import build_graph
    known_ids = set(names) | {PLANTED_ADDRESS} | {n.id for n in build_graph(base).nodes}
    known_ids |= {i for e in body["changes"] for i in e["resource_ids"]}
    assert not _leaks(body, names, known_ids), _leaks(body, names, known_ids)
    blob = json.dumps(body)
    for name in (PLANTED["dl-data-bucket"], PLANTED["db-dl-reports"], PLANTED["sg-dl-unused"], "zz-planted-addr-7731"):
        assert name in blob  # positive control: the names really are in the answer
    assert PLANTED_USER not in blob  # an exception text may name a user: withheld entirely


# ── L56: core / adapter boundary ───────────────────────────────────

def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] if not a.name.startswith("app.") else a.name.split(".")[1] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")
            if node.level == 0 and mod[0] == "app" and len(mod) > 1:
                found.add(mod[1])
            elif node.level == 0 and mod[0] == "app":
                found.update(a.name for a in node.names)
            elif node.level == 0:
                found.add(mod[0])
    return found


def test_L56_check_facts_is_a_core_module_with_zero_aws_imports():
    """L56: check_facts is core with ALLOWED == set(); aws_check and aws_outside_world are the adapters."""
    assert "check_facts" in CORE_MODULES and ALLOWED.get("check_facts") == set()
    assert {"aws_check", "aws_outside_world"} <= ADAPTER_MODULES
    imported = _imports(APP_DIR / "check_facts.py")
    assert not imported & (ADAPTER_MODULES | AWS_LIBS), sorted(imported & (ADAPTER_MODULES | AWS_LIBS))
    assert not imported & {"aws_check", "aws_outside_world", "aws_context"}
