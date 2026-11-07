"""L73: the read-only context query ("what is true in my cloud?").

An agent asks a question and gets FACTS back: never a verdict, advice or a fix.
Every answer says what was checked (known) and what was not and why (unknown).
Emfirge has no AI inside, so the same input gives byte-identical output.

L73a  every answer has known + unknown; a degraded source is never a silent
      "nothing found"
L73b  facts never fix: every response model forbids extra fields and no field
      name carries advice / verdict / score / severity
L73c  deterministic: same snapshot (and shuffled input order) -> identical JSON
L73d  one truth: dependents == delete_lens impacts, reachable == exposures,
      recovery points and role usage == the delete lens helpers
L73e  tenant isolation: hosted caller A never reads B's scan or branch
L73f  read-only: no boto3 client/session, no DB row count changes
L73g  the core module has zero AWS imports (L56 entry set())
L73h  bad input -> 422, unknown resource -> 404 without echo
"""
from __future__ import annotations

import ast
import copy
import json
import random
import typing
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from app import auth, database
from app.database import AnalysisLog
from app.demo_seed import build_demo_infrastructure
from tests.incidents.synthetic_base import load_synthetic_base

from .test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, AWS_LIBS, CORE_MODULES
from .test_tenant_isolation import tenant_client  # noqa: F401  (fixture)

APP_DIR = Path(__file__).resolve().parents[2] / "app"

QUESTIONS = ("inventory", "resource", "depends_on", "dependents", "reachable",
             "access", "data", "cost", "live", "marks", "baseline")
NEEDS_ID = ("resource", "depends_on", "dependents")

SHAPES = {
    "inventory": {"resource_id", "resource_type", "category", "region"},
    "resource": {"resource_id", "resource_type", "category", "tags", "edges"},
    "depends_on": {"resource_id", "resource_type", "relationship", "depth", "path"},
    "dependents": {"resource_id", "resource_type", "relationship", "depth", "path"},
    "reachable": {"resource_id", "resource_type", "protocol", "ports", "source", "resource_ids", "state"},
    "access": {"resource_id", "resource_ids", "escalation"},
    "data": {"resource_id", "resource_type", "has_recovery_point", "recovery_resource_ids", "recovery_kinds"},
    "cost": {"resource_id", "resource_type", "monthly_usd", "basis"},
    "live": {"resource_id", "used", "last_used_at", "window_days", "basis"},
    "marks": {"resource_id", "tags"},
    "baseline": {"topic", "count"},
}


# ── helpers ───────────────────────────────────────────────────────

def _ask(question, infra, resource_id=None, **kw):
    from app.aws_context import answer_for_infra
    return answer_for_infra(question, infra, analysis_id="law-scan", resource_id=resource_id, **kw)


def _json(resp) -> str:
    return resp.model_dump_json()


def _dump(resp) -> dict:
    return resp.model_dump(mode="json")


def _ids(infra) -> list[str]:
    return [f["resource_id"] for f in _dump(_ask("inventory", infra))["facts"]]


def _delete_base():
    return load_synthetic_base("delete")


@pytest.fixture(params=["clean", "nightmare", "empty", "partial", "delete_base", "demo"])
def infra_case(request):
    name = request.param
    if name == "delete_base":
        return name, _delete_base()
    if name == "demo":
        return name, build_demo_infrastructure()
    return name, request.getfixturevalue({
        "clean": "clean_infra", "nightmare": "nightmare_infra",
        "empty": "empty_infra", "partial": "partial_permissions_infra",
    }[name])


def _pick_id(infra) -> str | None:
    ids = _ids(infra)
    return sorted(ids)[len(ids) // 2] if ids else None


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


def _shuffled(infra, seed):
    """Same snapshot, every top-level resource collection in a different order."""
    rng = random.Random(seed)
    clone = infra.model_copy(deep=True)
    for owner_name in type(clone).model_fields:
        owner = getattr(clone, owner_name)
        if isinstance(owner, list):
            rng.shuffle(owner)
        elif isinstance(owner, BaseModel):
            for name in type(owner).model_fields:
                value = getattr(owner, name)
                if isinstance(value, list) and value and isinstance(value[0], BaseModel):
                    rng.shuffle(value)
    return clone


def _json_values(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _json_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _json_values(value)
    else:
        yield node


# ── L73a: known/unknown on every answer; no silent "nothing found" ─

def test_L73a_every_answer_has_known_and_unknown(infra_case):
    """L73a: every question on every fixture returns non-empty known and unknown lists."""
    name, infra = infra_case
    rid = _pick_id(infra)
    for question in QUESTIONS:
        if question in NEEDS_ID and rid is None:
            continue  # an empty account has no resource to ask about
        body = _dump(_ask(question, infra, resource_id=rid if question in NEEDS_ID else None))
        assert body["question"] == question
        assert set(body) == {"question", "source", "facts", "known", "unknown"}
        assert body["known"], (name, question)
        assert body["unknown"], (name, question)
        assert all(set(k) == {"topic", "detail"} for k in body["known"])
        assert all(set(u) == {"topic", "reason"} for u in body["unknown"])


def test_L73a_degraded_collection_sources_are_unknown():
    """L73a: a source marked denied/error in infra.collection appears in unknown for the questions that depend on it."""
    infra = _delete_base()
    infra.collection = {
        "network_interfaces": "denied", "ebs_volumes": "denied", "ebs_snapshots": "error",
        "rds_snapshots": "denied", "iam_role_last_used": "error",
    }
    expected = {
        "inventory": {"ebs_volumes"}, "cost": {"ebs_volumes"},
        "reachable": {"network_interfaces"}, "live": {"iam_role_last_used"},
        "data": {"ebs_volumes", "ebs_snapshots", "rds_snapshots"},
    }
    for question, sources in expected.items():
        body = _dump(_ask(question, infra))
        topics = {u["topic"]: u["reason"] for u in body["unknown"]}
        for source in sources:
            assert source in topics, (question, source)
            assert infra.collection[source] in topics[source], (question, source, topics[source])
            assert source not in {k["topic"] for k in body["known"]}


def test_L73a_ok_sources_are_known_not_unknown():
    """L73a: positive control: a source collected ok is known and not listed unknown."""
    infra = _delete_base()
    body = _dump(_ask("data", infra))
    assert {"ebs_snapshots", "rds_snapshots"} <= {k["topic"] for k in body["known"]}
    assert not {"ebs_snapshots", "rds_snapshots", "ebs_volumes"} & {u["topic"] for u in body["unknown"]}


def test_L73a_unrecorded_collection_status_is_unknown(clean_infra):
    """L73a: an old snapshot with no collection status cannot claim it checked the source."""
    assert clean_infra.collection == {}
    body = _dump(_ask("data", clean_infra))
    topics = {u["topic"] for u in body["unknown"]}
    assert {"ebs_snapshots", "rds_snapshots"} <= topics


def test_L73a_denied_snapshots_never_become_no_recovery_point():
    """L73a: no silent 'nothing found': a denied snapshot source yields null, never false."""
    infra = _delete_base()
    infra.collection = {**infra.collection, "ebs_snapshots": "denied", "rds_snapshots": "error"}
    infra.ec2.ebs_snapshots = []
    infra.rds.rds_snapshots = []
    facts = {f["resource_id"]: f for f in _dump(_ask("data", infra))["facts"]}
    assert facts["vol-dl-data"]["has_recovery_point"] is None
    assert facts["db-dl-reports"]["has_recovery_point"] is None
    # positive control: with the sources readable, absence IS a false
    ok = _delete_base()
    ok.ec2.ebs_snapshots = []
    ok.rds.rds_snapshots = []
    facts = {f["resource_id"]: f for f in _dump(_ask("data", ok))["facts"]}
    assert facts["vol-dl-data"]["has_recovery_point"] is False
    assert facts["db-dl-reports"]["has_recovery_point"] is False


def test_L73a_empty_facts_always_carry_a_matching_unknown(empty_infra):
    """L73a: an empty facts list is never alone: every empty answer says why it may be empty."""
    empty_infra.collection = {"ebs_volumes": "denied", "network_interfaces": "error",
                              "ebs_snapshots": "denied", "rds_snapshots": "denied",
                              "iam_role_last_used": "denied"}
    for question in ("inventory", "reachable", "access", "data", "cost", "live", "marks"):
        body = _dump(_ask(question, empty_infra))
        assert body["facts"] == [], question
        assert body["unknown"], question
    live = _dump(_ask("live", empty_infra))
    assert any(u["topic"] == "iam_role_last_used" for u in live["unknown"])
    assert any(u["topic"] == "recent_use" for u in live["unknown"])


def test_L73a_skipped_services_are_unknown(partial_permissions_infra):
    """L73a: collector warnings (services skipped for permissions) are unknown on every question."""
    for question in ("inventory", "cost", "reachable", "baseline"):
        body = _dump(_ask(question, partial_permissions_infra))
        skipped = [u for u in body["unknown"] if u["topic"] == "collector_skipped"]
        reasons = " ".join(u["reason"] for u in skipped)
        assert "EC2 scan skipped" in reasons and "RDS scan skipped" in reasons, question


def test_L73a_untagged_types_are_unknown_in_marks():
    """L73a: tags=None (not collected) is unknown for that resource type, never 'no tags'."""
    infra = _delete_base()
    body = _dump(_ask("marks", infra))
    assert all(f["resource_id"] != "i-dl-web" for f in body["facts"])
    assert any(u["topic"] == "tags:ec2_instance" for u in body["unknown"])
    infra.ec2.instances[0].tags = {}
    body = _dump(_ask("marks", infra))
    assert {"resource_id": "i-dl-web", "tags": {}} in body["facts"]
    assert not any(u["topic"] == "tags:ec2_instance" for u in body["unknown"])


def test_L73a_marks_always_say_owner_intent_is_unknown(infra_case):
    """L73a: marks always carries the owner_intent unknown (emfirge.md is not built yet)."""
    _, infra = infra_case
    body = _dump(_ask("marks", infra))
    assert {"topic": "owner_intent",
            "reason": "emfirge.md is not built yet; only resource tags are shown"} in body["unknown"]


def test_L73a_marks_show_user_tags_only():
    """L73a: aws: tags are AWS's own and are not shown as marks."""
    infra = _delete_base()
    infra.ec2.instances[0].tags = {"aws:cloudformation:stack-name": "s", "team": "web", "env": "prod"}
    facts = _dump(_ask("marks", infra, resource_id="i-dl-web"))["facts"]
    assert facts == [{"resource_id": "i-dl-web", "tags": {"env": "prod", "team": "web"}}]


# ── L73b: facts never fix ─────────────────────────────────────────

FORBIDDEN_WORDS = ("fix", "recommend", "advice", "advis", "remediat", "suggest", "verdict",
                   "score", "severity", "risk", "safe", "should", "priority", "critical")


def test_L73b_every_response_model_forbids_extra_fields():
    """L73b: every pydantic model in the request and response schema has extra='forbid'."""
    from app.context_query import ContextRequest, ContextResponse
    models = _walk_models(ContextResponse) | _walk_models(ContextRequest)
    assert len(models) >= 10
    for model in models:
        assert model.model_config.get("extra") == "forbid", model.__name__


def test_L73b_no_advice_field_names_in_schema():
    """L73b: no field name anywhere in the schema carries fix/advice/verdict/score/severity words."""
    from app.context_query import ContextResponse
    for model in _walk_models(ContextResponse):
        for name in model.model_fields:
            assert not any(word in name.lower() for word in FORBIDDEN_WORDS), (model.__name__, name)


def test_L73b_an_advice_field_cannot_be_smuggled_in():
    """L73b: constructing a response with an extra field is rejected."""
    from app.context_query import ContextResponse
    body = _dump(_ask("baseline", _delete_base()))
    ContextResponse.model_validate(body)
    for path in ([], ["facts", 0], ["source"], ["known", 0], ["unknown", 0]):
        bad = copy.deepcopy(body)
        node = bad
        for step in path:
            node = node[step]
        node["recommendation"] = "do something"
        with pytest.raises(ValidationError):
            ContextResponse.model_validate(bad)


def test_L73b_exposure_severity_is_not_passed_through(nightmare_infra):
    """L73b: the exposure severity ratings never reach a context answer."""
    from app.egraph import build_graph
    from app.exposure import compute_exposures
    ratings = {e.severity for e in compute_exposures(nightmare_infra, build_graph(nightmare_infra))}
    assert ratings, "fixture must have exposures for this law to bite"
    body = _dump(_ask("reachable", nightmare_infra))
    assert body["facts"]
    assert not ratings & {v for v in _json_values(body) if isinstance(v, str)}
    assert "severity" not in json.dumps(body).lower()


def test_L73b_baseline_has_no_verdict_words(infra_case):
    """L73b: baseline is counts only: no score, no verdict, no risky/safe words."""
    _, infra = infra_case
    text = json.dumps(_dump(_ask("baseline", infra))).lower()
    for word in ("risky", "safe", "severity", "score", "verdict", "recommend", "should"):
        assert word not in text, word


@pytest.mark.parametrize("question", [q for q in QUESTIONS if q not in NEEDS_ID])
def test_L73b_fact_record_shapes_are_pinned(question):
    """L73b: each question's fact records have exactly the documented field names."""
    infra = _delete_base()
    infra.ec2.instances[0].tags = {"team": "web"}
    body = _dump(_ask(question, infra))
    assert body["facts"], question
    for fact in body["facts"]:
        assert set(fact) == SHAPES[question], (question, fact)


@pytest.mark.parametrize("question", NEEDS_ID)
def test_L73b_id_question_record_shapes_are_pinned(question):
    """L73b: resource/depends_on/dependents records have exactly the documented field names."""
    body = _dump(_ask(question, _delete_base(), resource_id="sg-dl-web"))
    assert body["facts"], question
    for fact in body["facts"]:
        assert set(fact) == SHAPES[question]
    if question == "resource":
        assert len(body["facts"]) == 1
        edge = body["facts"][0]["edges"][0]
        assert set(edge) == {"relationship", "source", "target"}


# ── L73c: deterministic ───────────────────────────────────────────

def test_L73c_same_snapshot_answered_twice_is_byte_identical(infra_case):
    """L73c: same snapshot, same question -> identical JSON."""
    name, infra = infra_case
    rid = _pick_id(infra)
    for question in QUESTIONS:
        if question in NEEDS_ID and rid is None:
            continue
        a = _json(_ask(question, infra, resource_id=rid if question in NEEDS_ID else None))
        b = _json(_ask(question, infra, resource_id=rid if question in NEEDS_ID else None))
        assert a == b, (name, question)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_L73c_shuffled_input_order_is_byte_identical(infra_case, seed):
    """L73c: the same snapshot with its resource lists shuffled -> identical JSON."""
    name, infra = infra_case
    rid = _pick_id(infra)
    shuffled = _shuffled(infra, seed)
    for question in QUESTIONS:
        if question in NEEDS_ID and rid is None:
            continue
        arg = rid if question in NEEDS_ID else None
        assert _json(_ask(question, infra, resource_id=arg)) == _json(_ask(question, shuffled, resource_id=arg)), (name, question, seed)


def test_L73c_tag_and_collection_key_order_does_not_matter():
    """L73c: dict key order in tags and collection never leaks into the answer."""
    one, two = _delete_base(), _delete_base()
    one.ec2.instances[0].tags = {"b": "2", "a": "1", "c": "3"}
    two.ec2.instances[0].tags = {"c": "3", "a": "1", "b": "2"}
    two.collection = dict(reversed(list(two.collection.items())))
    for question in ("marks", "resource", "baseline", "data", "live"):
        arg = "i-dl-web" if question == "resource" else None
        assert _json(_ask(question, one, resource_id=arg)) == _json(_ask(question, two, resource_id=arg)), question


def test_L73c_lists_are_sorted():
    """L73c: known/unknown and fact lists come back sorted, not in discovery order."""
    infra = _delete_base()
    body = _dump(_ask("inventory", infra))
    keys = [(f["resource_type"], f["resource_id"]) for f in body["facts"]]
    assert keys == sorted(keys)
    assert body["unknown"] == sorted(body["unknown"], key=lambda u: (u["topic"], u["reason"]))
    assert body["known"] == sorted(body["known"], key=lambda k: (k["topic"], k["detail"]))


# ── L73d: one truth ───────────────────────────────────────────────

def _crafted_delete_lens(base, node):
    """delete_lens impacts for deleting one graph node, with a hand-written ledger entry."""
    from app.delete_lens import analyze_deletions
    branch = base.model_copy(deep=True)
    branch._deletions.append({
        "step": 1, "resource_type": node.resource_type, "resource_id": node.id,
        "implicit": False, "via": None, "state_before": {},
        "options": {"skip_final_snapshot": None, "delete_automated_backups": True,
                    "final_db_snapshot_identifier": None},
    })
    return analyze_deletions(base, branch)


@pytest.mark.parametrize("which", ["delete_base", "demo", "nightmare"])
def test_L73d_dependents_equal_delete_lens_impacts_for_every_node(which, nightmare_infra):
    """L73d: dependents(x) == delete_lens impacts for deleting x (ids, depth, relationship)."""
    from app.egraph import build_graph
    infra = {"delete_base": _delete_base(), "demo": build_demo_infrastructure(), "nightmare": nightmare_infra}[which]
    graph = build_graph(infra)
    checked_nonempty = 0
    for node in graph.nodes:
        if node.id == "INTERNET":
            continue
        lens = _crafted_delete_lens(infra, node)
        expected = sorted((i.resource_id, i.depth, i.relation) for i in lens.impacts)
        got = sorted((f["resource_id"], f["depth"], f["relationship"])
                     for f in _dump(_ask("dependents", infra, resource_id=node.id))["facts"])
        assert got == expected, (which, node.id)
        checked_nonempty += bool(expected)
    assert checked_nonempty >= 2, "the law must bite on real dependency chains"


def test_L73d_dependents_equal_delete_lens_for_a_real_delete():
    """L73d: same agreement when the delete goes through the real mutation path."""
    from app.delete_lens import analyze_deletions
    from app.mutations import Change, apply_change
    base = _delete_base()
    for rtype, rid, node_id, fields in (
            ("s3_bucket", "dl-data-bucket", "dl-data-bucket", {}),
            ("iam_role", "arn:aws:iam::000000000000:role/DlWorkerRole", "iam-role-DlWorkerRole", {}),
            ("rds_instance", "db-dl-reports", "db-dl-reports", {"skip_final_snapshot": True}),
            ("security_group", "sg-dl-unused", "sg-dl-unused", {})):
        branch = apply_change(base, Change(op="delete", resource_type=rtype, resource_id=rid, fields=fields))
        lens = analyze_deletions(base, branch)
        expected = sorted((i.resource_id, i.depth) for i in lens.impacts if not i.relation.startswith("deleted_with"))
        got = sorted((f["resource_id"], f["depth"])
                     for f in _dump(_ask("dependents", base, resource_id=node_id))["facts"])
        assert got == expected, rid


def test_L73d_depends_on_is_the_mirror_of_dependents(infra_case):
    """L73d: y in dependents(x) at depth d  <=>  x in depends_on(y) at depth d."""
    name, infra = infra_case
    ids = [i for i in _ids(infra) if i != "INTERNET"][:25]
    for x in ids:
        for fact in _dump(_ask("dependents", infra, resource_id=x))["facts"]:
            back = {f["resource_id"]: f["depth"]
                    for f in _dump(_ask("depends_on", infra, resource_id=fact["resource_id"]))["facts"]}
            assert back.get(x) == fact["depth"], (name, x, fact["resource_id"])


def test_L73d_dependency_paths_start_at_the_asked_resource_and_end_at_the_fact():
    """L73d: path = ids from the asked resource to the fact; length == depth + 1."""
    infra = _delete_base()
    for question in ("dependents", "depends_on"):
        facts = _dump(_ask(question, infra, resource_id="sg-dl-web"))["facts"]
        assert facts, question
        for f in facts:
            assert f["path"][0] == "sg-dl-web" and f["path"][-1] == f["resource_id"]
            assert len(f["path"]) == f["depth"] + 1


def test_L73d_reachable_equals_exposures_and_internet_reachable_set(infra_case):
    """L73d: reachable facts == compute_exposures records; every internet-reachable node is present."""
    from app.egraph import build_graph, get_internet_reachable_set
    from app.exposure import compute_exposures
    name, infra = infra_case
    graph = build_graph(infra)
    exposures = compute_exposures(infra, graph)
    facts = _dump(_ask("reachable", infra))["facts"]
    got = {(f["resource_id"], f["protocol"], tuple(f["ports"]), f["source"], tuple(f["resource_ids"]), f["state"])
           for f in facts if f["state"] != "reachable"}
    want = {(e.resource_id, e.protocol, (e.from_port, e.to_port), e.source, (e.via_sg,), e.state) for e in exposures}
    assert got == want, name
    assert get_internet_reachable_set(graph) <= {f["resource_id"] for f in facts}, name


def test_L73d_reachable_has_real_content_on_nightmare(nightmare_infra):
    """L73d: guard against vacuous agreement: nightmare really has exposures and a reachable set."""
    facts = _dump(_ask("reachable", nightmare_infra))["facts"]
    assert any(f["state"] == "active" and 22 in range(f["ports"][0], f["ports"][1] + 1) for f in facts)


def test_L73d_recovery_points_equal_delete_lens():
    """L73d: has_recovery_point agrees with delete_lens data_lost / recovery_points for the same resource."""
    from app.egraph import build_graph
    infra = _delete_base()
    graph = build_graph(infra)
    facts = {f["resource_id"]: f for f in _dump(_ask("data", infra))["facts"]}
    assert {"dl-data-bucket", "db-dl-prod", "db-dl-reports", "vol-dl-root", "vol-dl-data"} <= set(facts)
    for node in graph.nodes:
        if node.resource_type not in {"s3_bucket", "rds_instance", "ebs_volume"}:
            continue
        before = {"s3_bucket": infra.s3.buckets, "rds_instance": infra.rds.rds_instances,
                  "ebs_volume": infra.ec2.ebs_volumes}[node.resource_type]
        item = next(x for x in before if getattr(x, "id", getattr(x, "name", None)) == node.id)
        from app.delete_lens import analyze_deletions
        branch = infra.model_copy(deep=True)
        branch._deletions.append({
            "step": 1, "resource_type": node.resource_type, "resource_id": node.id, "implicit": False,
            "via": None, "state_before": item.model_dump(),
            "options": {"skip_final_snapshot": None, "delete_automated_backups": True,
                        "final_db_snapshot_identifier": None}})
        lens = analyze_deletions(infra, branch)
        lost = {x.resource_id for x in lens.data_lost}
        points = {x.source_id for x in lens.recovery_points if x.resource_id == node.id and x.source_id != node.id}
        kinds = {x.kind for x in lens.recovery_points if x.resource_id == node.id}
        fact = facts[node.id]
        assert fact["has_recovery_point"] is (node.id not in lost), node.id
        assert set(fact["recovery_resource_ids"]) == points, node.id
        assert set(fact["recovery_kinds"]) == kinds, node.id
    assert facts["vol-dl-root"]["has_recovery_point"] is True
    assert facts["vol-dl-root"]["recovery_resource_ids"] == ["snap-dl-root"]
    assert facts["vol-dl-data"]["has_recovery_point"] is False


def test_L73d_role_usage_equals_delete_lens_helpers():
    """L73d: live.used for a role agrees with delete_lens recently_used / usage_unknown."""
    from app.delete_lens import deleted_role_usage_unknown, recently_used_deleted
    for status in ("ok", "denied"):
        infra = _delete_base()
        infra.collection = {**infra.collection, "iam_role_last_used": status}
        facts = {f["resource_id"]: f for f in _dump(_ask("live", infra))["facts"]}
        for role in infra.iam.role_policies:
            branch = infra.model_copy(deep=True)
            branch._deletions.append({"step": 1, "resource_type": "iam_role", "resource_id": role.role_arn,
                                      "implicit": False, "via": None, "state_before": {}, "options": {}})
            node_id = f"iam-role-{role.role_name}"
            used = facts[node_id]["used"]
            assert (used is True) == recently_used_deleted(infra, branch), (status, node_id)
            assert (used is None) == deleted_role_usage_unknown(infra, branch), (status, node_id)
            assert facts[node_id]["basis"] == "scan:last_used"
            assert facts[node_id]["window_days"] == 90
    infra = _delete_base()
    facts = {f["resource_id"]: f for f in _dump(_ask("live", infra))["facts"]}
    assert facts["iam-role-DlBatchRole"]["used"] is True
    assert facts["iam-role-DlWorkerRole"]["used"] is False
    assert facts["iam-role-DlWorkerRole"]["last_used_at"] == "2026-06-01T00:00:00Z"
    assert facts["iam-role-DlAppRole"]["used"] is False and facts["iam-role-DlAppRole"]["last_used_at"] is None


def test_L73d_cost_equals_cost_estimate():
    """L73d: cost facts are the cost.py estimate; null prices also appear as unknown with a reason."""
    from app.cost import estimate_monthly_cost
    infra = _delete_base()
    estimate = {r.resource_id: r for r in estimate_monthly_cost(infra).resources}
    body = _dump(_ask("cost", infra))
    facts = {f["resource_id"]: f for f in body["facts"]}
    priced = {rid: r for rid, r in estimate.items() if r.monthly_usd is not None}
    assert priced
    for rid, record in priced.items():
        assert facts[rid]["monthly_usd"] == record.monthly_usd, rid
        assert facts[rid]["basis"] == record.basis
    unknown_topics = {u["topic"]: u["reason"] for u in body["unknown"]}
    nulls = [f for f in body["facts"] if f["monthly_usd"] is None]
    assert nulls, "fixture must have an unpriced resource (rds / s3)"
    for f in nulls:
        assert f"cost:{f['resource_id']}" in unknown_topics, f
        assert unknown_topics[f"cost:{f['resource_id']}"]


def test_L73d_access_escalation_equals_iam_escalation():
    """L73d: escalation path ids are exactly iam_escalation.matching_paths for that role."""
    from app.iam_escalation import matching_paths
    from app.models import AccessStatement
    infra = _delete_base()
    statements = [AccessStatement(effect="Allow", actions=["iam:*"], resources=["*"])]
    infra.iam.role_policies[0].access_statements = statements
    expected = sorted(p["id"] for p in matching_paths(statements))
    assert expected, "iam:* on * must match pathfinding paths"
    facts = {f["resource_id"]: f for f in _dump(_ask("access", infra))["facts"]}
    role_id = f"iam-role-{infra.iam.role_policies[0].role_name}"
    assert facts[role_id]["escalation"] == expected
    other = f"iam-role-{infra.iam.role_policies[1].role_name}"
    assert facts[other]["escalation"] == []
    assert "dl-data-bucket" in facts[other]["resource_ids"]


# ── L73e: tenant isolation (hosted) ───────────────────────────────

def _seed_two_tenants(ids):
    """A gets the delete-base snapshot (older), B gets the demo snapshot (newer)."""
    def store(account, analysis_id, infra, when):
        db = database.SessionLocal()
        try:
            row = db.query(AnalysisLog).filter(AnalysisLog.id == ids[account]).one()
            row.findings_json = json.dumps({"analysis_id": analysis_id,
                                            "infrastructure": infra.model_dump(mode="json")})
            row.timestamp = when
            db.commit()
        finally:
            db.close()
    now = datetime(2026, 10, 1, 12, 0, 0)
    store("111111111111", "a-uuid", _delete_base(), now - timedelta(days=1))
    store("222222222222", "b-uuid", build_demo_infrastructure(), now)


def _hdr(key):
    return {"X-API-Key": key}


def _post(client, key, **body):
    from app import main
    main._branch_request_log.clear()
    return client.post("/context", headers=_hdr(key), json=body)


def test_L73e_scan_by_id_is_scoped_to_the_callers_accounts(tenant_client):
    """L73e: A reads A's scan; B's scan id and a missing id give A the same 404."""
    client, key_a, key_b, ids = tenant_client
    _seed_two_tenants(ids)
    own = _post(client, key_a, question="inventory", analysis_id="a-uuid")
    assert own.status_code == 200, own.text
    assert own.json()["source"]["analysis_id"] == "a-uuid"
    hidden = _post(client, key_a, question="inventory", analysis_id="b-uuid")
    missing = _post(client, key_a, question="inventory", analysis_id="nonexistent-analysis")
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()
    back = _post(client, key_b, question="inventory", analysis_id="a-uuid")
    assert back.status_code == 404
    assert "i-dl-web" not in back.text


def test_L73e_null_analysis_id_picks_only_the_callers_latest(tenant_client):
    """L73e: with analysis_id null, A gets A's latest scan even though B's is newer."""
    client, key_a, key_b, ids = tenant_client
    _seed_two_tenants(ids)
    a = _post(client, key_a, question="inventory")
    b = _post(client, key_b, question="inventory")
    assert a.status_code == b.status_code == 200
    assert a.json()["source"]["analysis_id"] == "a-uuid"
    assert a.json()["source"]["region"] == "ap-south-1"
    assert b.json()["source"]["analysis_id"] == "b-uuid"
    a_ids = {f["resource_id"] for f in a.json()["facts"]}
    b_ids = {f["resource_id"] for f in b.json()["facts"]}
    assert "i-dl-web" in a_ids and "i-dl-web" not in b_ids
    assert a_ids.isdisjoint({"i-demo-web-001"}) and "i-demo-web-001" in b_ids


def test_L73e_caller_without_accounts_sees_nothing(tenant_client):
    """L73e: a project with no bound accounts gets 404 for latest and for a named scan."""
    client, key_a, _, ids = tenant_client
    _seed_two_tenants(ids)
    empty_key = auth.create_api_key("tenant-law-context-empty")
    client.get("/project", headers=_hdr(empty_key))
    assert _post(client, empty_key, question="inventory").status_code == 404
    assert _post(client, empty_key, question="inventory", analysis_id="a-uuid").status_code == 404


def test_L73e_branch_is_scoped_to_the_callers_tenant(tenant_client):
    """L73e: B cannot read A's branch; same 404 as a branch that does not exist."""
    from app import main
    client, key_a, key_b, ids = tenant_client
    _seed_two_tenants(ids)
    main._branch_request_log.clear()
    created = client.post("/branches", headers=_hdr(key_a), json={"base_analysis_id": "a-uuid", "name": "ctx-law"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    own = _post(client, key_a, question="inventory", branch_id=branch_id)
    assert own.status_code == 200, own.text
    assert own.json()["source"]["kind"] == "branch"
    assert own.json()["source"]["branch_id"] == branch_id
    assert own.json()["source"]["analysis_id"] == "a-uuid"
    random_id = "00000000-0000-0000-0000-000000000000"
    hidden = _post(client, key_b, question="inventory", branch_id=branch_id)
    missing = _post(client, key_b, question="inventory", branch_id=random_id)
    assert hidden.status_code == missing.status_code == 404
    assert json.dumps(hidden.json()).replace(branch_id, "<ID>") == json.dumps(missing.json()).replace(random_id, "<ID>")
    assert "i-dl-web" not in hidden.text


def test_L73e_unknown_resource_does_not_echo_other_tenants_data(tenant_client):
    """L73e: asking A's scan for B's resource id is a 404 that does not echo the id or B's data."""
    client, key_a, _, ids = tenant_client
    _seed_two_tenants(ids)
    for question in ("resource", "depends_on", "dependents"):
        resp = _post(client, key_a, question=question, analysis_id="a-uuid", resource_id="i-demo-web-001")
        assert resp.status_code == 404, question
        assert "i-demo-web-001" not in resp.text and "demo" not in resp.text.lower()


# ── L73f: read-only ───────────────────────────────────────────────

def _row_counts():
    db = database.SessionLocal()
    try:
        return {t.name: db.execute(t.select().with_only_columns(__import__("sqlalchemy").func.count())).scalar()
                for t in database.Base.metadata.sorted_tables}
    finally:
        db.close()


def test_L73f_context_never_touches_aws_or_writes_rows(shared_test_db, monkeypatch):
    """L73f: no boto3 client/session is created and no table's row count changes."""
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
    created = client.post("/branches", json={"base_analysis_id": "ro-scan", "name": "ro"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]

    def boom(*_a, **_k):
        raise AssertionError("AWS client/session created during /context")

    monkeypatch.setattr(boto3, "client", boom)
    monkeypatch.setattr(boto3, "resource", boom)
    monkeypatch.setattr(boto3.session.Session, "__init__", boom)
    monkeypatch.setattr(botocore.session.Session, "create_client", boom)
    monkeypatch.setattr(botocore.client.ClientCreator, "create_client", boom)
    monkeypatch.setattr(in_use_evidence, "read_evidence", boom)
    monkeypatch.setattr(main, "read_evidence", boom)

    before = _row_counts()
    assert before["analysis_logs"] == 1
    for source in ({"analysis_id": "ro-scan"}, {"branch_id": branch_id}, {}):
        for question in QUESTIONS:
            body = {"question": question, **source}
            if question in NEEDS_ID:
                body["resource_id"] = "sg-dl-web"
            main._branch_request_log.clear()
            resp = client.post("/context", json=body)
            assert resp.status_code == 200, (question, source, resp.text)
    assert _row_counts() == before


# ── L73g: the core has zero AWS imports ───────────────────────────

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
            elif node.level == 1:
                found.add(mod[0] if mod[0] else node.names[0].name)
    return found


def test_L73g_context_query_is_a_core_module_with_no_aws_imports():
    """L73g: context_query is core with ALLOWED == set(); aws_context is the adapter."""
    assert "context_query" in CORE_MODULES
    assert ALLOWED.get("context_query") == set()
    assert "aws_context" in ADAPTER_MODULES
    imported = _imports(APP_DIR / "context_query.py")
    assert not imported & (ADAPTER_MODULES | AWS_LIBS), sorted(imported & (ADAPTER_MODULES | AWS_LIBS))
    assert "aws_context" not in imported


def test_L73g_adapter_is_the_only_place_the_neutral_facts_meet_aws_models():
    """L73g: the adapter imports the AWS-specific truths (tags, cost, models) the core must not."""
    imported = _imports(APP_DIR / "aws_context.py")
    assert {"tags", "cost", "models"} <= imported


# ── L73h: bad input ───────────────────────────────────────────────

@pytest.fixture
def selfhost_client(shared_test_db, monkeypatch):
    from app import main
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    db = database.SessionLocal()
    try:
        db.add(AnalysisLog(aws_account_id="000000000000", findings_json=json.dumps({
            "analysis_id": "bad-scan", "infrastructure": _delete_base().model_dump(mode="json")})))
        db.commit()
    finally:
        db.close()
    main._branch_request_log.clear()
    return TestClient(main.app)


@pytest.mark.parametrize("body", [
    {"question": "advise"},
    {"question": "fix_it", "analysis_id": "bad-scan"},
    {},
    {"question": "resource"},
    {"question": "depends_on"},
    {"question": "dependents", "resource_id": ""},
    {"question": "dependents", "resource_id": "   "},
    {"question": "inventory", "analysis_id": "bad-scan", "branch_id": "11111111-1111-1111-1111-111111111111"},
    {"question": "baseline", "resource_id": "sg-dl-web"},
    {"question": "inventory", "recommendation": "x"},
    {"question": "inventory", "analysis_id": 5},
    {"question": ["inventory"]},
])
def test_L73h_bad_input_is_422(selfhost_client, body):
    """L73h: unknown question, missing resource_id, both ids, extra fields -> 422."""
    resp = selfhost_client.post("/context", json=body)
    assert resp.status_code == 422, (body, resp.status_code, resp.text)


def test_L73h_malformed_json_is_422_not_500(selfhost_client):
    """L73h: a body that is not JSON is a client error."""
    resp = selfhost_client.post("/context", content="not json", headers={"content-type": "application/json"})
    assert resp.status_code == 422


@pytest.mark.parametrize("question", ["resource", "depends_on", "dependents", "data", "cost", "live", "marks", "access", "reachable", "inventory"])
def test_L73h_unknown_resource_id_is_404_without_echo(selfhost_client, question):
    """L73h: a resource id that is not in the snapshot is 404; the id is not echoed."""
    secret = "i-0123456789abcdef0"
    resp = selfhost_client.post("/context", json={"question": question, "analysis_id": "bad-scan", "resource_id": secret})
    assert resp.status_code == 404, (question, resp.text)
    assert secret not in resp.text


def test_L73h_unknown_scan_and_branch_are_404(selfhost_client):
    """L73h: unknown analysis_id / branch_id -> 404."""
    assert selfhost_client.post("/context", json={"question": "inventory", "analysis_id": "nope"}).status_code == 404
    assert selfhost_client.post("/context", json={"question": "inventory", "branch_id": "nope"}).status_code == 404


def test_L73h_scan_without_a_stored_snapshot_is_404_not_an_empty_answer(selfhost_client):
    """L73h: a scan that has no infrastructure snapshot must not answer as an empty account."""
    db = database.SessionLocal()
    try:
        db.add(AnalysisLog(aws_account_id="000000000000", findings_json=json.dumps({"analysis_id": "old-scan"})))
        db.commit()
    finally:
        db.close()
    resp = selfhost_client.post("/context", json={"question": "inventory", "analysis_id": "old-scan"})
    assert resp.status_code == 404


def test_L73h_valid_resource_questions_answer_200(selfhost_client):
    """L73h: positive control: the same endpoint answers a valid resource question."""
    resp = selfhost_client.post("/context", json={"question": "dependents", "analysis_id": "bad-scan", "resource_id": "sg-dl-web"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["facts"]
    assert resp.json()["source"] == {"kind": "scan", "analysis_id": "bad-scan", "branch_id": None,
                                     "collected_at": "2026-10-01T00:00:00Z", "region": "ap-south-1"}


def test_L73h_branch_live_uses_stored_evidence_rows(selfhost_client):
    """L73h: for a branch source, live answers from stored evidence rows (basis branch:evidence), never AWS."""
    from app import branches
    from app.evidence_models import EvidenceRecord
    created = selfhost_client.post("/branches", json={"base_analysis_id": "bad-scan", "name": "ev"})
    branch_id = created.json()["branch_id"]
    branches.save_evidence(branch_id, "e" * 64, [
        EvidenceRecord(resource_id="i-dl-web", resource_type="ec2_instance", source="cloudwatch_metrics",
                       status="ok", used=True, window_days=14, observed_at="2026-10-02T00:00:00Z",
                       last_event_at="2026-10-01T10:00:00Z"),
        EvidenceRecord(resource_id="db-dl-prod", resource_type="rds_instance", source="cloudwatch_metrics",
                       status="denied", used=None, window_days=14, observed_at="2026-10-02T00:00:00Z"),
    ])
    body = selfhost_client.post("/context", json={"question": "live", "branch_id": branch_id}).json()
    by_id = {(f["resource_id"], f["basis"]): f for f in body["facts"]}
    assert by_id[("i-dl-web", "branch:evidence")]["used"] is True
    assert by_id[("i-dl-web", "branch:evidence")]["window_days"] == 14
    assert by_id[("i-dl-web", "branch:evidence")]["last_used_at"] == "2026-10-01T10:00:00Z"
    assert by_id[("db-dl-prod", "branch:evidence")]["used"] is None
    assert any(u["topic"] == "evidence:db-dl-prod" and "denied" in u["reason"] for u in body["unknown"])
    scan = selfhost_client.post("/context", json={"question": "live", "analysis_id": "bad-scan"}).json()
    assert all(f["basis"] == "scan:last_used" for f in scan["facts"])
