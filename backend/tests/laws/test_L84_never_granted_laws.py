"""L84: Emfirge cannot see application code, so it cannot know a permission was NEVER granted.

The real incident: a Lambda role was never granted dynamodb:DeleteItem; the code called it and failed. There is no
base permission to remove, so no ``permission_removed`` fact can exist. The honest answer is an unknown that
points the agent to the context ``access`` question for the role.

L84a  never granted in base or branch: no permission_removed fact, and one never-granted unknown per touched role
L84b  the unknown is one per role (not per action, not per compute user), deterministic, in the unknown shape
L84c  a compute resource the branch changes, whose role is visible, raises it for that role too
L84d  an unrelated branch does not raise it
L84e  a permission that WAS granted and is removed is still a fact (a different case), and carries the layers caveat
L84f  /context access lists the allowed actions per role and says it is the identity-policy view only
L84g  without a permission_removed fact, availability carries no layers caveat
"""
from __future__ import annotations

import copy

import pytest

from app.mutations import Change, apply_change

from tests.incidents.jarvis.build import BUCKET, LAMBDAS, ROLES
from .test_jarvis_rehearsal_laws import (  # noqa: F401  (fixtures)
    answers, jarvis_infra, put_role_policy_call, rig, unknown_of,
)
from .test_check_facts_laws import _check, _dump

TOPIC = "permission_never_granted"


def never_granted_infra(infra):
    """The same account, but every role was NEVER granted dynamodb:DeleteItem (in the base)."""
    out = copy.deepcopy(infra)
    for role in out.iam.role_policies:
        for statement in role.access_statements:
            statement.actions = [a for a in statement.actions if a != "dynamodb:DeleteItem"]
        for record in role.policy_documents or []:
            for statement in record.statements:
                statement.actions = [a for a in statement.actions if a != "dynamodb:DeleteItem"]
    return out


def _role_id(kind):
    return f"iam-role-{ROLES[kind]}"


@pytest.fixture
def never_rig(rig, jarvis_infra, monkeypatch):
    from app import main
    stripped = never_granted_infra(jarvis_infra)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: copy.deepcopy(stripped))
    return rig


def _with_scan(kind):
    return put_role_policy_call(kind, ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan"])


# ── L84a ──────────────────────────────────────────────────────────

def test_L84a_never_granted_is_no_fact_but_an_unknown_for_the_role(never_rig):
    branch = never_rig.branch()
    never_rig.api(branch, _with_scan("publisher"))
    body = never_rig.check(branch)
    assert [f for f in answers(body)["availability"]["facts"] if f["change"] == "permission_removed"] == []
    notes = unknown_of(body, "availability", TOPIC)
    assert [n["resource_id"] for n in notes] == [_role_id("publisher")]
    reason = notes[0]["reason"]
    assert "application code" in reason and "never granted" in reason and "access" in reason
    assert LAMBDAS["publisher"] not in reason and ROLES["publisher"] not in reason  # ids live in resource_id only


def test_L84a_the_unknown_is_only_in_availability(never_rig):
    branch = never_rig.branch()
    never_rig.api(branch, _with_scan("publisher"))
    body = never_rig.check(branch)
    for damage in ("data", "exposure", "money", "control", "outside_world"):
        assert unknown_of(body, damage, TOPIC) == [], damage


# ── L84b ──────────────────────────────────────────────────────────

def test_L84b_one_unknown_per_role_and_deterministic(never_rig):
    branch = never_rig.branch()
    never_rig.api(branch, _with_scan("publisher"), _with_scan("door"))
    first, second = never_rig.check(branch), never_rig.check(branch)
    ids = [n["resource_id"] for n in unknown_of(first, "availability", TOPIC)]
    assert ids == sorted([_role_id("publisher"), _role_id("door")]) and len(ids) == 2
    assert unknown_of(first, "availability", TOPIC) == unknown_of(second, "availability", TOPIC)
    for note in unknown_of(first, "availability", TOPIC):
        assert set(note) == {"topic", "reason", "resource_id"}


# ── L84c ──────────────────────────────────────────────────────────

def test_L84c_a_changed_function_with_a_visible_role_raises_it_for_that_role(jarvis_infra):
    base = never_granted_infra(jarvis_infra)
    branch = apply_change(base, Change(op="modify", resource_type="lambda_function", resource_id=LAMBDAS["door"],
                                       fields={"tags": {"touched": "yes"}}))
    body = _dump(_check(base, branch))
    notes = unknown_of(body, "availability", TOPIC)
    assert [n["resource_id"] for n in notes] == [_role_id("door")], notes


# ── L84d ──────────────────────────────────────────────────────────

def test_L84d_an_unrelated_branch_does_not_raise_it(never_rig):
    branch = never_rig.branch()
    never_rig.api(branch, {"service": "s3", "operation": "PutBucketTagging", "parameters": {
        "Bucket": BUCKET, "Tagging": {"TagSet": [{"Key": "a", "Value": "b"}]}}})
    assert unknown_of(never_rig.check(branch), "availability", TOPIC) == []
    assert unknown_of(never_rig.check(never_rig.branch("empty")), "availability", TOPIC) == []


# ── L84e / L84g ───────────────────────────────────────────────────

def test_L84e_a_granted_then_removed_permission_is_still_a_fact_with_the_layers_caveat(rig):
    """A DIFFERENT case from the incident: the base HAD dynamodb:DeleteItem and the branch removes it."""
    branch = rig.branch()
    rig.api(branch, put_role_policy_call("publisher", ["dynamodb:GetItem", "dynamodb:PutItem"]))
    body = rig.check(branch)
    facts = [f for f in answers(body)["availability"]["facts"] if f["change"] == "permission_removed"]
    assert [f["action"] for f in facts] == ["dynamodb:DeleteItem"]
    layers = unknown_of(body, "availability", "other_policy_layers")
    assert [n["resource_id"] for n in layers] == [_role_id("publisher")]
    assert "session policies" in layers[0]["reason"]


def test_L84g_without_a_removed_fact_availability_has_no_layers_caveat(never_rig):
    branch = never_rig.branch()
    never_rig.api(branch, _with_scan("publisher"))
    assert unknown_of(never_rig.check(branch), "availability", "other_policy_layers") == []


# ── L84f ──────────────────────────────────────────────────────────

def test_L84f_context_access_lists_actions_and_says_identity_policy_view_only(never_rig):
    branch = never_rig.branch()
    body = never_rig.context(branch, "access")
    fact = {f["resource_id"]: f for f in body["facts"]}[_role_id("publisher")]
    allows = {(p["action"], p["effect"]) for p in fact["permissions"]}
    assert ("dynamodb:GetItem", "allow") in allows and ("dynamodb:DeleteItem", "allow") not in allows
    notes = [u for u in body["unknown"] if u["topic"] == "other_policy_layers"]
    assert len(notes) == 1
    text = notes[0]["reason"]
    for word in ("identity", "service control", "permission boundaries", "resource policies", "session policies"):
        assert word in text, word
