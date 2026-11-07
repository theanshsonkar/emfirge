"""L76: permission-level facts (which ACTIONS a role may call on which resources).

Incident: an agent deployed a Lambda whose execution role policy lacked
``dynamodb:DeleteItem`` on the table the code uses; the feature broke at runtime.
The graph only had coarse ``can_access`` edges, so a change that removed one action
but kept others was invisible. Emfirge cannot see application code, so it never says
which actions the code calls: that is stated as unknown.

L76a  removing one action from a role used by a lambda -> availability fact
      ``permission_removed`` (action, table, lambda user); unchanged actions: no fact
L76b  wildcard ``dynamodb:*`` -> explicit list expands from the provider's action list
L76c  an added Deny removes the action
L76d  conditions / NotAction are conditional or unknown, never a plain allow or removal
L76e  deterministic, closed schema, no customer ids in free text
L76f  /context ``access`` lists action-level allows equal to the same expansion function
L76g  core/adapter boundary: expansion is a core module; the botocore catalog is an adapter
L76h  aws-api ``iam.PutRolePolicy`` flows into the same facts
L76i  unknown is honest: app code actions, action catalog gap, unchanged roles are silent
"""
from __future__ import annotations

import ast
import json
import random
import re
from pathlib import Path

import pytest

from app.models import AccessStatement, AWSInfrastructure, DynamoDBTable, LambdaFunction, RolePolicy
from app.mutations import Change, apply_change
from tests.incidents.synthetic_base import load_synthetic_base

from .test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, AWS_LIBS, CORE_MODULES

APP_DIR = Path(__file__).resolve().parents[2] / "app"
ACCOUNT = "000000000000"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/OrdersRole"
ROLE_ID = "iam-role-OrdersRole"
TABLE = "orders"
TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{TABLE}"
LAMBDA = "orders-fn"
REVISION = "r" * 64


# ── helpers ───────────────────────────────────────────────────────

def _stmt(actions, *, effect="Allow", resources=None, not_action=False, not_resource=False, condition=False):
    return {"effect": effect, "actions": list(actions), "resources": list(resources or [TABLE_ARN]),
            "is_not_action": not_action, "is_not_resource": not_resource, "has_condition": condition}


def _infra(statements, *, with_lambda=True) -> AWSInfrastructure:
    base = load_synthetic_base("delete").model_copy(deep=True)
    base.dynamodb.tables.append(DynamoDBTable(name=TABLE, arn=TABLE_ARN))
    if with_lambda:
        base.lambda_data.functions.append(LambdaFunction(name=LAMBDA, role_arn=ROLE_ARN))
    base.iam.role_policies.append(RolePolicy(
        role_name="OrdersRole", role_arn=ROLE_ARN,
        access_statements=[AccessStatement.model_validate(s) for s in statements]))
    return base


def _branch(base, statements):
    return apply_change(base, Change(op="modify", resource_type="iam_role_policy", resource_id=ROLE_ARN,
                                     fields={"access_statements": list(statements)}))


def _check(base, branch=None, **kw):
    from app.aws_check import check_for_branch
    branch = base.model_copy(deep=True) if branch is None else branch
    return check_for_branch(base, branch, branch_id="law-branch", base_analysis_id="law-base",
                            branch_revision=REVISION, **kw)


def _body(result) -> dict:
    return result.model_dump(mode="json")


def _answers(body) -> dict:
    return {a["damage"]: a for a in body["answers"]}


def _permission_facts(body, damage="availability", change=None):
    return [f for f in _answers(body)[damage]["facts"]
            if f["change"] in {"permission_removed", "permission_added"} and (change is None or f["change"] == change)]


def _removed(statements_before, statements_after, **kw):
    base = _infra(statements_before)
    body = _body(_check(base, _branch(base, statements_after), **kw))
    return body, {f["action"]: f for f in _permission_facts(body, "availability", "permission_removed")}


def _unknown(body, topic, damage="availability"):
    return [u for u in _answers(body)[damage]["unknown"] if u["topic"] == topic]


def _catalog(service):
    from app.aws_actions import actions_for_service
    return actions_for_service(service)


def _json_keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _json_keys(value)
    elif isinstance(node, list):
        for value in node:
            yield from _json_keys(value)


# ── L76a: one action removed, the others kept ──────────────────────

def test_L76a_removing_delete_item_from_a_lambda_role_is_a_permission_removed_fact():
    """L76a: Get/Put/Delete -> Get/Put on the table: one fact for DeleteItem naming the table and the lambda."""
    body, removed = _removed([_stmt(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"])],
                             [_stmt(["dynamodb:GetItem", "dynamodb:PutItem"])])
    assert set(removed) == {"dynamodb:DeleteItem"}
    fact = removed["dynamodb:DeleteItem"]
    assert fact == {"resource_id": ROLE_ID, "resource_type": "iam_role", "change": "permission_removed",
                    "action": "dynamodb:DeleteItem", "resource_ids": [TABLE], "affected_node_ids": [LAMBDA]}
    assert _permission_facts(body, "control") == []


def test_L76a_unchanged_actions_produce_no_fact_and_an_unchanged_role_is_silent():
    """L76a: Get and Put stay allowed -> no fact for them; a branch that changes nothing says nothing."""
    body, removed = _removed([_stmt(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"])],
                             [_stmt(["dynamodb:GetItem", "dynamodb:PutItem"])])
    assert "dynamodb:GetItem" not in removed and "dynamodb:PutItem" not in removed
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])
    quiet = _body(_check(base))
    assert _permission_facts(quiet, "availability") == [] and _permission_facts(quiet, "control") == []
    assert _unknown(quiet, "app_code_actions") == []


def test_L76a_adding_an_action_is_a_permission_added_fact_in_control():
    """L76a: the reverse change is permission_added, in control, with the same shape."""
    base = _infra([_stmt(["dynamodb:GetItem"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])))
    added = _permission_facts(body, "control", "permission_added")
    assert added == [{"resource_id": ROLE_ID, "resource_type": "iam_role", "change": "permission_added",
                      "action": "dynamodb:DeleteItem", "resource_ids": [TABLE], "affected_node_ids": [LAMBDA]}]
    assert _permission_facts(body, "availability") == []


def test_L76a_removing_all_access_to_a_table_removes_every_action_on_it():
    """L76a: the can_access edge disappears on the branch; the actions are still reported as removed."""
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"],
                                                   resources=["arn:aws:dynamodb:us-east-1:000000000000:table/other"])])))
    removed = {f["action"]: f for f in _permission_facts(body, "availability", "permission_removed")}
    assert set(removed) == {"dynamodb:DeleteItem", "dynamodb:GetItem"}
    assert removed["dynamodb:GetItem"]["resource_ids"] == [TABLE]


def test_L76a_a_role_without_compute_still_gets_the_fact_with_no_users():
    """L76a: the lambda is not a precondition of the fact; affected_node_ids is just empty."""
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])], with_lambda=False)
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"])])))
    (fact,) = _permission_facts(body, "availability", "permission_removed")
    assert fact["affected_node_ids"] == [] and fact["action"] == "dynamodb:DeleteItem"


# ── L76b: wildcard expansion from the provider's action list ────────

KEPT = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
        "dynamodb:DescribeTable"]


def test_L76b_dynamodb_star_to_an_explicit_list_removes_exactly_the_rest_of_the_catalog():
    """L76b: dynamodb:* -> six actions: removed == catalog minus kept, DeleteItem among them."""
    _, removed = _removed([_stmt(["dynamodb:*"])], [_stmt(KEPT)])
    catalog = _catalog("dynamodb")
    assert "dynamodb:DeleteItem" in catalog and "dynamodb:DeleteTable" in catalog
    assert set(removed) == set(catalog) - set(KEPT)
    assert all(f["resource_ids"] == [TABLE] for f in removed.values())


def test_L76b_botocore_operations_missing_from_the_iam_list_are_the_documented_gap_not_a_silent_one():
    """L76b: most operations are IAM actions; the few that are not (PartiQL, Transact*) are the stated catalog gap."""
    import botocore.session
    from app.aws_actions import ACTION_CATALOG_GAP
    ops = {f"dynamodb:{op}" for op in botocore.session.get_session().get_service_model("dynamodb").operation_names}
    catalog = set(_catalog("dynamodb"))
    assert {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem", "dynamodb:Query",
            "dynamodb:Scan", "dynamodb:CreateTable", "dynamodb:DeleteTable"} <= ops & catalog
    missing = ops - catalog
    assert missing and len(missing) < len(ops) // 4  # a handful of operations that IAM authorizes through other actions
    assert "operation" in ACTION_CATALOG_GAP and "IAM action" in ACTION_CATALOG_GAP


def test_L76b_the_catalog_falls_back_to_botocore_operations_when_the_iam_catalog_lacks_the_service(monkeypatch):
    """L76b: botocore operation names are the action list when the IAM catalog has no such service."""
    import app.aws_actions as aws_actions
    monkeypatch.setattr(aws_actions, "_iam_catalog", lambda service: None)
    aws_actions.actions_for_service.cache_clear()
    try:
        names = aws_actions.actions_for_service("dynamodb")
        assert "dynamodb:DeleteItem" in names and "dynamodb:CreateTable" in names
    finally:
        aws_actions.actions_for_service.cache_clear()


def test_L76b_action_wildcard_patterns_expand_within_the_service():
    """L76b: dynamodb:Delete* granted -> narrowed to Get* gives every Delete* action as removed, none else."""
    _, removed = _removed([_stmt(["dynamodb:Delete*", "dynamodb:Get*"])], [_stmt(["dynamodb:Get*"])])
    deletes = {a for a in _catalog("dynamodb") if a.startswith("dynamodb:Delete")}
    assert "dynamodb:DeleteItem" in deletes
    assert set(removed) == deletes


def test_L76b_an_unknown_service_wildcard_is_unknown_not_an_empty_expansion():
    """L76b: a wildcard of a service with no action list is stated as unknown (and never guessed)."""
    base = _infra([_stmt(["dynamodb:GetItem", "nosuchsvc:*"], resources=["*"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"], resources=["*"])])))
    topics = {u["topic"] for u in _answers(body)["availability"]["unknown"]}
    assert "action_list_unavailable" in topics


def test_L76b_a_service_wildcard_is_not_expanded_and_says_so():
    """L76b: an action pattern with a wildcard service (such as *) is not expanded; it is unknown."""
    base = _infra([_stmt(["*"], resources=["*"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"], resources=["*"])])))
    assert _unknown(body, "action_wildcard_not_expanded")


# ── L76c: a Deny removes the action ────────────────────────────────

def test_L76c_a_deny_added_for_one_action_removes_only_that_action():
    """L76c: Allow Get/Put/Delete + new Deny DeleteItem -> permission_removed for DeleteItem only."""
    allow = _stmt(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"])
    _, removed = _removed([allow], [allow, _stmt(["dynamodb:DeleteItem"], effect="Deny")])
    assert set(removed) == {"dynamodb:DeleteItem"}


def test_L76c_a_wildcard_deny_removes_every_matching_action():
    """L76c: Deny dynamodb:Delete* over an allowed dynamodb:* removes each Delete action."""
    allow = _stmt(["dynamodb:*"])
    _, removed = _removed([allow], [allow, _stmt(["dynamodb:Delete*"], effect="Deny")])
    assert set(removed) == {a for a in _catalog("dynamodb") if a.startswith("dynamodb:Delete")}


def test_L76c_a_deny_on_another_resource_removes_nothing():
    """L76c: a Deny that does not match the table is not a removal."""
    allow = _stmt(["dynamodb:DeleteItem"])
    deny = _stmt(["dynamodb:DeleteItem"], effect="Deny", resources=[f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/other"])
    body, removed = _removed([allow], [allow, deny])
    assert removed == {}


def test_L76c_removing_a_deny_is_permission_added():
    """L76c: the Deny is lifted -> the action is allowed again (permission_added)."""
    allow = _stmt(["dynamodb:DeleteItem", "dynamodb:GetItem"])
    deny = _stmt(["dynamodb:DeleteItem"], effect="Deny")
    base = _infra([allow, deny])
    body = _body(_check(base, _branch(base, [allow])))
    assert [f["action"] for f in _permission_facts(body, "control", "permission_added")] == ["dynamodb:DeleteItem"]


# ── L76d: conditions and NotAction are never a plain allow or removal ──

def test_L76d_a_condition_added_to_the_allow_is_uncertain_not_a_removal():
    """L76d: Allow DeleteItem -> Allow DeleteItem with a Condition: no removal fact, an uncertain note."""
    body, removed = _removed([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])],
                             [_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:DeleteItem"], condition=True)])
    assert removed == {}
    (note,) = _unknown(body, "permission_uncertain")
    assert note["resource_id"] == ROLE_ID and "dynamodb:DeleteItem" in note["reason"]
    assert "dynamodb:GetItem" not in note["reason"]


def test_L76d_a_conditional_allow_that_is_dropped_is_not_reported_as_a_plain_removal():
    """L76d: it was never a plain allow, so losing it is not 'permission_removed'."""
    body, removed = _removed([_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:DeleteItem"], condition=True)],
                             [_stmt(["dynamodb:GetItem"])])
    assert removed == {}
    assert _unknown(body, "permission_uncertain")


def test_L76d_a_conditional_deny_does_not_remove_the_action():
    """L76d: Deny with a Condition may or may not apply: not a removal, an uncertain note."""
    allow = _stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])
    body, removed = _removed([allow], [allow, _stmt(["dynamodb:DeleteItem"], effect="Deny", condition=True)])
    assert removed == {}
    assert _unknown(body, "permission_uncertain")


def test_L76d_not_action_statements_are_unknown_never_a_plain_allow_or_removal():
    """L76d: Allow NotAction is not expanded; moving to or from one is uncertain, not removed/added."""
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:Scan"], not_action=True)])))
    removed_actions = {f["action"] for f in _permission_facts(body, "availability", "permission_removed")}
    assert "dynamodb:DeleteItem" not in removed_actions and "dynamodb:GetItem" not in removed_actions
    assert _unknown(body, "not_action_not_expanded")
    assert _unknown(body, "permission_uncertain")


def test_L76d_not_resource_statements_are_unknown():
    """L76d: Allow with NotResource is unknown for the actions it names."""
    base = _infra([_stmt(["dynamodb:DeleteItem"])])
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:DeleteItem"], not_resource=True)])))
    assert _permission_facts(body, "availability") == []
    assert _unknown(body, "not_action_not_expanded")


def test_L76d_the_context_answer_lists_conditional_allows_as_conditional():
    """L76d: /context access lists a conditional allow with effect 'conditional', never 'allow'."""
    infra = _infra([_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:DeleteItem"], condition=True)])
    perms = {(p["action"], p["effect"]): p["resource_ids"] for p in _access_facts(infra)[ROLE_ID]["permissions"]}
    assert perms == {("dynamodb:GetItem", "allow"): [TABLE], ("dynamodb:DeleteItem", "conditional"): [TABLE]}


# ── L76e: deterministic, closed, no customer ids in free text ─────

def test_L76e_the_check_is_byte_identical_across_repeats_and_statement_order():
    """L76e: same branch twice, and reversed statement order, give identical JSON."""
    allow_a = _stmt(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Scan"])
    allow_b = _stmt(["dynamodb:Query"])
    base = _infra([allow_a, allow_b])
    branch = _branch(base, [_stmt(["dynamodb:GetItem"])])
    first = _check(base, branch).model_dump_json()
    assert first == _check(base, branch).model_dump_json()
    base2 = _infra([allow_b, allow_a])
    branch2 = _branch(base2, [_stmt(["dynamodb:GetItem"])])
    assert _check(base2, branch2).model_dump_json() == first


def test_L76e_the_schema_stays_closed_and_the_fact_has_exactly_the_documented_fields():
    """L76e: PermissionFact forbids extra fields and is part of the Fact union (L74b walks it)."""
    from pydantic import ValidationError
    from app.check_facts import CheckResult, PermissionFact
    assert set(PermissionFact.model_fields) == {"resource_id", "resource_type", "change", "action", "resource_ids",
                                                "affected_node_ids"}
    with pytest.raises(ValidationError):
        PermissionFact(resource_id="r", resource_type="iam_role", change="permission_removed", action="a:B",
                       resource_ids=[], affected_node_ids=[], advice="x")
    assert PermissionFact in set(_walk(CheckResult))


def _walk(model, seen=None):
    import typing
    from pydantic import BaseModel
    seen = set() if seen is None else seen
    if model in seen:
        return seen
    seen.add(model)

    def visit(annotation):
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            _walk(annotation, seen)
        for arg in typing.get_args(annotation):
            visit(arg)
    for field in model.model_fields.values():
        visit(field.annotation)
    return seen


def test_L76e_no_verdict_word_as_a_key_or_reason_code_as_a_value():
    """L76e: the L74b rules hold for responses that carry permission facts."""
    from tests.laws.test_check_facts_laws import _reason_codes
    base = _infra([_stmt(["dynamodb:*"])])
    body = _body(_check(base, _branch(base, [_stmt(KEPT), _stmt(["dynamodb:Delete*"], effect="Deny", condition=True)])))
    assert _permission_facts(body)
    forbidden = ("verdict", "level", "severity", "score", "rule", "code", "check_id", "fix", "advice", "risk", "safe")
    for key in _json_keys(body):
        assert not any(word in key.lower() for word in forbidden), key
    codes = _reason_codes()
    values = {v for v in _all_strings(body)}
    assert not codes & values


def _all_strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _all_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _all_strings(value)
    elif isinstance(node, str):
        yield node


def test_L76e_customer_names_only_appear_as_whole_values_of_identifier_keys():
    """L76e: role, table and lambda names are never inside a topic, reason or detail (L74i), and the keys are masked."""
    names = {"OrdersRole": "zzPlantedRoleAcme7731", TABLE: "zz-planted-table-7731", LAMBDA: "zz-planted-lambda-fn-7731"}
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"]), _stmt(["dynamodb:Scan"], condition=True)])
    text = base.model_dump_json()
    for old, new in sorted(names.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(old, new)
    planted = AWSInfrastructure.model_validate_json(text)
    arn = ROLE_ARN.replace("OrdersRole", names["OrdersRole"])
    table_arn = TABLE_ARN.replace(TABLE, names[TABLE])
    statements = [_stmt(["dynamodb:GetItem"], resources=[table_arn])]
    branch = apply_change(planted, Change(op="modify", resource_type="iam_role_policy", resource_id=arn,
                                          fields={"access_statements": statements}))
    body = _body(_check(planted, branch))
    assert _permission_facts(body)
    id_keys = {"resource_id", "resource_ids", "affected_node_ids"}

    def walk(node, key=""):
        if isinstance(node, dict):
            for k, v in node.items():
                assert not any(n in k for n in names.values()), k
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif isinstance(node, str) and any(n in node for n in names.values()):
            assert key in id_keys and (node in names.values() or node.startswith("iam-role-")), (key, node)
    walk(body)
    assert any(n in json.dumps(body) for n in names.values())  # positive control
    src = (Path(__file__).resolve().parents[3] / "mcp" / "src" / "tokenize.ts").read_text()
    masked = set()
    for const in ("SENSITIVE_KEYS", "IDENTIFIER_KEYS"):
        masked |= set(re.findall(r'"([^"]+)"', re.search(rf"const {const} = new Set\(\[(.*?)\]\)", src, re.S).group(1)))
    assert id_keys <= masked


# ── L76f: /context access lists the same expansion ─────────────────

def _access(infra, **kw):
    from app.aws_context import answer_for_infra
    return answer_for_infra("access", infra, analysis_id="law-scan", **kw)


def _access_facts(infra, **kw):
    return {f["resource_id"]: f for f in _access(infra, **kw).model_dump(mode="json")["facts"]}


def test_L76f_context_access_lists_sorted_action_level_allows():
    """L76f: 'can role X DeleteItem on table T' is answerable: sorted (action, effect) entries with the tables."""
    infra = _infra([_stmt(["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem"])])
    fact = _access_facts(infra)[ROLE_ID]
    assert fact["permissions"] == [
        {"action": "dynamodb:DeleteItem", "effect": "allow", "resource_ids": [TABLE]},
        {"action": "dynamodb:GetItem", "effect": "allow", "resource_ids": [TABLE]},
        {"action": "dynamodb:PutItem", "effect": "allow", "resource_ids": [TABLE]},
    ]
    assert fact["resource_ids"] == [TABLE]  # the coarse edge list is unchanged


def test_L76f_wildcards_and_denies_are_applied_in_the_context_answer():
    """L76f: dynamodb:* minus a Deny on Delete* lists the catalog without the Delete actions."""
    infra = _infra([_stmt(["dynamodb:*"]), _stmt(["dynamodb:Delete*"], effect="Deny")])
    listed = {p["action"] for p in _access_facts(infra)[ROLE_ID]["permissions"]}
    assert listed == {a for a in _catalog("dynamodb") if not a.startswith("dynamodb:Delete")}


def test_L76f_context_and_check_use_one_truth():
    """L76f: what the check reports removed is exactly base-context minus branch-context, per role and table."""
    base = _infra([_stmt(["dynamodb:*"])])
    branch = _branch(base, [_stmt(KEPT)])
    before = {p["action"] for p in _access_facts(base)[ROLE_ID]["permissions"] if p["effect"] == "allow"}
    after = {p["action"] for p in _access_facts(branch)[ROLE_ID]["permissions"] if p["effect"] == "allow"}
    body = _body(_check(base, branch))
    removed = {f["action"] for f in _permission_facts(body, "availability", "permission_removed")}
    assert removed == before - after and removed


def test_L76f_the_context_list_equals_the_core_expansion_function():
    """L76f: the answer is the neutral expansion function's output, not a second implementation."""
    from app.aws_permissions import role_permission_lines
    from app.egraph import build_graph
    infra = _infra([_stmt(["dynamodb:Get*", "dynamodb:DeleteItem"]), _stmt(["dynamodb:GetRecords"], effect="Deny")])
    graph = build_graph(infra)
    role = next(r for r in infra.iam.role_policies if r.role_arn == ROLE_ARN)
    lines = role_permission_lines(role, graph)
    got = [(l.action, l.effect, tuple(l.resource_ids)) for l in lines.allows]
    shown = [(p["action"], p["effect"], tuple(p["resource_ids"])) for p in _access_facts(infra)[ROLE_ID]["permissions"]]
    assert got == shown and got == sorted(got)


def test_L76f_identities_without_statements_have_no_permissions_and_unknown_is_stated():
    """L76f: a role with no collected statements lists nothing; the context carries unknown notes for gaps."""
    infra = _infra([_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:Scan"], not_action=True)])
    body = _access(infra).model_dump(mode="json")
    topics = {u["topic"] for u in body["unknown"]}
    assert {"not_action_not_expanded", "action_catalog"} <= topics
    assert all(u["resource_id"] is None or u["resource_id"].startswith("iam-role-") for u in body["unknown"])
    other = _access_facts(infra)["iam-role-DlAppRole"]
    assert all(p["action"].startswith("s3:") for p in other["permissions"])


def test_L76f_context_text_carries_no_customer_ids():
    """L76f: unknown/known text never embeds the role or table name; the role is in resource_id."""
    infra = _infra([_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:Scan"], not_action=True)])
    body = _access(infra).model_dump(mode="json")
    texts = [u["reason"] for u in body["unknown"]] + [u["detail"] for u in body["known"]] + [u["topic"] for u in body["unknown"]]
    assert texts
    for text in texts:
        assert "OrdersRole" not in text and TABLE not in text.split()


# ── L76g: core/adapter boundary ────────────────────────────────────

def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            parts = (node.module or "").split(".")
            if node.level == 0 and parts[0] == "app" and len(parts) > 1:
                found.add(parts[1])
            elif node.level == 0 and parts[0]:
                found.add(parts[0])
    return found


def test_L76g_the_expansion_is_a_core_module_with_no_adapter_or_aws_imports():
    """L76g: permission_facts is a registered core module that imports no AWS library or adapter module."""
    assert "permission_facts" in CORE_MODULES and ALLOWED["permission_facts"] == set()
    imported = _imports(APP_DIR / "permission_facts.py")
    assert not imported & (ADAPTER_MODULES | AWS_LIBS | {"policy_sentry"}), imported


def test_L76g_the_action_catalog_is_an_adapter_and_the_only_botocore_user_of_the_feature():
    """L76g: botocore and the IAM catalog are imported only by adapter modules of this feature."""
    assert {"aws_actions", "aws_permissions"} <= ADAPTER_MODULES
    assert "botocore" in _imports(APP_DIR / "aws_actions.py")
    for core in ("permission_facts", "check_facts", "context_query"):
        assert not _imports(APP_DIR / f"{core}.py") & (AWS_LIBS | {"policy_sentry", "aws_actions", "aws_permissions"})


def test_L76g_the_core_expansion_runs_with_a_fake_catalog_and_matcher():
    """L76g: the neutral core works from injected catalog/matcher alone (no AWS adapter needed)."""
    from app.permission_facts import Target, diff_permissions, normalize
    catalog = {"svc": frozenset({"svc:Read", "svc:Write", "svc:Delete"})}.get
    matches = lambda pattern, target: pattern in {"*", target}
    before = normalize([_stmt(["svc:*"], resources=["t1"])])
    after = normalize([_stmt(["svc:Read", "svc:Write"], resources=["t1"])])
    diff = diff_permissions(before, after, [Target("t1", "svc")], catalog, matches)
    assert diff.removed == {"svc:Delete": ("t1",)} and diff.added == {} and diff.uncertain == ()


# ── L76h: the aws-api mutation path reaches the same facts ─────────

def test_L76h_aws_api_put_role_policy_flows_into_permission_facts():
    """L76h: iam.PutRolePolicy replacing an inline policy -> typed iam_role_policy change -> permission_removed."""
    from app.aws_api_ingest import translate_api_calls
    from app.models import PolicyDocumentRecord
    record = PolicyDocumentRecord(name="inline", kind="inline", statements=[
        AccessStatement.model_validate(_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"]))])
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])
    role = next(r for r in base.iam.role_policies if r.role_arn == ROLE_ARN)
    role.policy_documents, role.policy_names = [record], ["inline"]
    doc = {"format": "aws-api-calls/1", "calls": [{"service": "iam", "operation": "PutRolePolicy", "parameters": {
        "RoleName": "OrdersRole", "PolicyName": "inline",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN}]}}}]}
    result = translate_api_calls(doc, role_policies=[role])
    assert [c.resource_type for c in result["changes"]] == ["iam_role_policy"]
    branch = base
    for change in result["changes"]:
        branch = apply_change(branch, change)
    body = _body(_check(base, branch))
    assert [f["action"] for f in _permission_facts(body, "availability", "permission_removed")] == ["dynamodb:DeleteItem"]


def test_L76h_the_typed_and_api_paths_give_identical_permission_facts():
    """L76h: the typed modify and the aws-api call that produces the same statements give the same check facts."""
    from app.aws_api_ingest import translate_api_calls
    from app.models import PolicyDocumentRecord
    statements = [_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])]
    base = _infra(statements)
    role = next(r for r in base.iam.role_policies if r.role_arn == ROLE_ARN)
    role.policy_documents = [PolicyDocumentRecord(name="inline", kind="inline",
                                                  statements=[AccessStatement.model_validate(s) for s in statements])]
    role.policy_names = ["inline"]
    typed = _branch(base, [_stmt(["dynamodb:GetItem"])])
    doc = {"format": "aws-api-calls/1", "calls": [{"service": "iam", "operation": "PutRolePolicy", "parameters": {
        "RoleName": "OrdersRole", "PolicyName": "inline",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN}]}}}]}
    via_api = base
    for change in translate_api_calls(doc, role_policies=[role])["changes"]:
        via_api = apply_change(via_api, change)
    assert (_permission_facts(_body(_check(base, typed))) == _permission_facts(_body(_check(base, via_api)))
            and _permission_facts(_body(_check(base, typed))))


# ── L76i: honest unknowns ──────────────────────────────────────────

def test_L76i_app_code_actions_are_unknown_whenever_a_compute_role_changed():
    """L76i: Emfirge cannot see which actions the code calls: stated on the role, in availability."""
    body, _ = _removed([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])], [_stmt(["dynamodb:GetItem"])])
    (note,) = _unknown(body, "app_code_actions")
    assert note["resource_id"] == ROLE_ID
    assert "application code" in note["reason"] and "not visible" in note["reason"]
    # even a change that produces no fact (action added elsewhere, condition added) still carries it
    base = _infra([_stmt(["dynamodb:GetItem"])])
    other = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"], resources=["*"])])))
    assert _unknown(other, "app_code_actions")


def test_L76i_a_changed_role_without_compute_has_no_app_code_note():
    """L76i: the note is for roles that compute uses; an unused role's change does not carry it."""
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])], with_lambda=False)
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"])])))
    assert _unknown(body, "app_code_actions") == []


def test_L76i_the_action_catalog_gap_is_stated_when_actions_were_compared():
    """L76i: IAM action names differ from API operations in a few services; the check says so honestly."""
    body, _ = _removed([_stmt(["dynamodb:*"])], [_stmt(KEPT)])
    (note,) = _unknown(body, "action_catalog")
    assert "operation" in note["reason"] and "s3:ListBucket" in note["reason"]
    quiet = _body(_check(_infra([_stmt(["dynamodb:GetItem"])])))
    assert _unknown(quiet, "action_catalog") == []


def test_L76i_unrecorded_policy_breakdown_is_unknown_on_the_base_role():
    """L76i: a base role whose managed/inline breakdown was not recorded may have unseen managed policies."""
    base = _infra([_stmt(["dynamodb:GetItem", "dynamodb:DeleteItem"])])
    role = next(r for r in base.iam.role_policies if r.role_arn == ROLE_ARN)
    assert role.policy_documents is None
    body = _body(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"])])))
    (note,) = _unknown(body, "managed_policies_not_recorded")
    assert note["resource_id"] == ROLE_ID


def test_L76i_other_policy_layers_stay_unknown_in_the_context_answer():
    """L76i: boundaries, SCPs and resource policies are not collected; the access answer says so."""
    body = _access(_infra([_stmt(["dynamodb:GetItem"])])).model_dump(mode="json")
    assert "other_policy_layers" in {u["topic"] for u in body["unknown"]}


def test_L76i_shuffled_statement_lists_never_change_the_facts():
    """L76i: any order of the same statements yields the same facts (property check)."""
    rng = random.Random(7)
    pool = [_stmt(["dynamodb:GetItem"]), _stmt(["dynamodb:PutItem"]), _stmt(["dynamodb:DeleteItem"]),
            _stmt(["dynamodb:Delete*"], effect="Deny"), _stmt(["dynamodb:Scan"], condition=True)]
    outputs = set()
    for _ in range(4):
        order = pool[:]
        rng.shuffle(order)
        base = _infra(order)
        outputs.add(_check(base, _branch(base, [_stmt(["dynamodb:GetItem"])])).model_dump_json())
    assert len(outputs) == 1
