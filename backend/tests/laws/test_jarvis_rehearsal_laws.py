"""L79: offline rehearsal of Harness v1 step 5 (the real test on the Jarvis account).

An agent redoes the real field-notes work through the harness; each real incident must come back as a
true signal (ROADMAP section 6). The account here is invented (111122223333, acme-demo-* names) and is
produced by the REAL collectors under moto (CloudFront policies and the OAC on the origin are canned
provider-shaped responses, as in L78). Every flow goes through the real HTTP endpoints, with the same
requests the CLI sends: create a branch from the stored scan, POST a plan in the format an agent uses,
GET /branches/{id}/check.

L79a  CloudFront: aws-cli update-distribution moves feed.xml to a Host-forwarding managed policy
      -> availability fact origin_receives_host_header
L79b  re-enabled schedule: aws-cli update-schedule without --state (AWS default ENABLED)
      -> outside_world fact schedule_enabled + target_effects unknown
L79c  Lambda quota request: aws-api servicequotas.RequestServiceQuotaIncrease
      -> outside_world fact with the provider's source_url
L79d  missing dynamodb:DeleteItem: aws-api iam.PutRolePolicy -> availability fact permission_removed
      naming the lambdas, and app_code_actions unknown
L79e  harmless change (tag on the bucket): no data / exposure / availability / outside_world fact
L79f  zero-change check: baseline present
L79g  /context: inventory, dependents of the bucket include the distribution, access shows DeleteItem
L79h  no invented account id, name or id in any free-text field of any response
L79i  the rehearsal account really is what the field notes describe (collector output, not hand-built)
"""
from __future__ import annotations

import copy
import json
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from app.cloudfront_check import SOURCE_URL as CLOUDFRONT_DOCS
from tests.incidents.jarvis import build
from tests.incidents.jarvis.build import (
    ACCOUNT, BUCKET, CACHING_OPTIMIZED, ETAG, FEED, LAMBDAS, REGION, ROLES, SCHEDULE_EXPRESSIONS, SCHEDULER_ROLE,
    SCHEDULES, TABLE, TABLE_ARN, USE_ORIGIN_CACHE_CONTROL, distribution_config, lambda_arn, role_arn,
)

from .test_check_facts_laws import ID_KEYS, TOKENIZE_TS

# L74i's keys plus the one L76 added (affected_node_ids); all of them must be masked by the MCP tokenizer.
REDACTED_ID_KEYS = ID_KEYS | {"affected_node_ids"}

SCHEDULE_DOCS = "https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-enable-disable.html"
QUOTA_DOCS = "https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html"
EFFECTS_UNKNOWN = "what the target does outside the cloud is not visible to Emfirge"


# ── the account and the HTTP harness ───────────────────────────────

@pytest.fixture(scope="module")
def jarvis_infra():
    """The collector output, built once (moto + canned CloudFront reads); tests deep-copy it."""
    with pytest.MonkeyPatch.context() as mp:
        infra = build.build_aws(mp)
    return infra


@pytest.fixture
def rig(jarvis_infra, monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'jarvis.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: copy.deepcopy(jarvis_infra))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _key: None)
    for name in ("run_checkov", "run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(verdict, name, lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setenv("EMFIRGE_RUN_SCANNERS", "0")
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    client = TestClient(main.app)
    yield Rig(client, jarvis_infra)
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


class Rig:
    def __init__(self, client, infra):
        self.client, self.infra = client, infra
        self.responses: list[tuple[str, dict]] = []  # every JSON response, for the redaction law

    def _keep(self, label, response):
        assert response.status_code == 200, (label, response.status_code, response.text)
        body = response.json()
        self.responses.append((label, body))
        return body

    @property
    def dist(self):
        return self.infra.cloudfront.distributions[0]

    def branch(self, name="rehearsal"):
        body = self._keep("create_branch", self.client.post("/branches", json={"base_analysis_id": "jarvis-scan", "name": name}))
        return body["branch_id"]

    def plan(self, branch_id, kind, document):
        return self._keep(f"plans/{kind}", self.client.post(f"/branches/{branch_id}/plans/{kind}", json=document))

    def cli(self, branch_id, *commands):
        """What `emfirge try BRANCH --aws-cli "..."` sends."""
        return self.plan(branch_id, "aws-cli", {"format": "aws-cli/1", "commands": list(commands)})

    def api(self, branch_id, *calls):
        return self.plan(branch_id, "aws-api", {"format": "aws-api-calls/1", "calls": list(calls)})

    def typed(self, branch_id, change):
        return self._keep("changes", self.client.post(f"/branches/{branch_id}/changes", json=change))

    def check(self, branch_id):
        return self._keep("check", self.client.get(f"/branches/{branch_id}/check"))

    def context(self, branch_id, question, resource_id=None):
        payload = {"question": question, "branch_id": branch_id}
        if resource_id:
            payload["resource_id"] = resource_id
        return self._keep(f"context/{question}", self.client.post("/context", json=payload))


def answers(body):
    return {a["damage"]: a for a in body["answers"]}


def facts_of(body, damage, **match):
    return [f for f in answers(body)[damage]["facts"] if all(f.get(k) == v for k, v in match.items())]


def unknown_of(body, damage, topic):
    return [u for u in answers(body)[damage]["unknown"] if u["topic"] == topic]


def quote(text):
    return "'" + text.replace("'", "'\\''") + "'"


# ── incident commands as an agent would write them ─────────────────

def cmd_feed_to_host_forwarding_policy(dist):
    config = json.dumps(distribution_config(USE_ORIGIN_CACHE_CONTROL), separators=(",", ":"))
    return f"aws cloudfront update-distribution --id {dist.id} --if-match {dist.etag} --distribution-config {quote(config)}"


def cmd_update_schedule_without_state(kind="publisher"):
    """The deploy script that forgot `--state`: AWS resets an omitted State to ENABLED."""
    return (f"aws scheduler update-schedule --name {SCHEDULES[kind]} --schedule-expression {quote(SCHEDULE_EXPRESSIONS[kind])} "
            f"--flexible-time-window {quote(json.dumps({'Mode': 'OFF'}))} "
            f"--target {quote(json.dumps({'Arn': lambda_arn(kind), 'RoleArn': f'arn:aws:iam::{ACCOUNT}:role/{SCHEDULER_ROLE}'}))}")


QUOTA_CALL = {"service": "servicequotas", "operation": "RequestServiceQuotaIncrease",
              "parameters": {"ServiceCode": "lambda", "QuotaCode": "L-B99A9384", "DesiredValue": 1000}}


def put_role_policy_call(kind, actions):
    return {"service": "iam", "operation": "PutRolePolicy", "parameters": {
        "RoleName": ROLES[kind], "PolicyName": "table-access",
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": TABLE_ARN}]}}}


# ── L79i: the account is collector output ──────────────────────────

def test_L79i_the_rehearsal_account_is_what_the_field_notes_describe(jarvis_infra):
    infra = jarvis_infra
    assert infra.warnings == [] and infra.region == REGION
    assert {b.name for b in infra.s3.buckets} == {BUCKET}
    assert [t.name for t in infra.dynamodb.tables] == [TABLE]
    assert {f.name for f in infra.lambda_data.functions} == set(LAMBDAS.values())
    for kind, name in LAMBDAS.items():
        assert next(f for f in infra.lambda_data.functions if f.name == name).role_arn == role_arn(kind)
        role = next(r for r in infra.iam.role_policies if r.role_arn == role_arn(kind))
        assert {a for s in role.access_statements for a in s.actions} == {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"}
    assert len(infra.scheduler.schedules) == 3 and {s.state for s in infra.scheduler.schedules} == {"DISABLED"}
    assert {s.target_arn for s in infra.scheduler.schedules} == {lambda_arn(k) for k in LAMBDAS}
    assert infra.collection["cloudfront"] == "ok" and infra.collection["scheduler"] == "ok"
    dist = infra.cloudfront.distributions[0]
    assert ACCOUNT in dist.arn and ACCOUNT in infra.dynamodb.tables[0].arn  # moto honoured the invented account id
    feed = next(b for b in dist.cache_behaviors if b.path_pattern == FEED)
    assert feed.cache_policy_id == CACHING_OPTIMIZED and dist.origins[0].origin_access_control_id == build.OAC
    assert dist.origins[0].s3_bucket == BUCKET and dist.etag == ETAG
    by_id = {p.id: p for p in infra.cloudfront.cache_policies}
    assert by_id[CACHING_OPTIMIZED].forwards_host is False and by_id[USE_ORIGIN_CACHE_CONTROL].forwards_host is True
    # the real account id of the field notes is nowhere in the fixture
    assert "282027772803" not in infra.model_dump_json()


# ── L79a: CloudFront 404 on the feed ───────────────────────────────

def test_L79a_cloudfront_host_forwarding_policy_is_an_availability_fact(rig):
    branch = rig.branch()
    plan = rig.cli(branch, cmd_feed_to_host_forwarding_policy(rig.dist))
    assert plan["unmodeled"] == [] and plan["unknown_fields"] == [] and plan["rejected"] == []
    body = rig.check(branch)
    expected = {
        "resource_id": rig.dist.id, "resource_type": "cloudfront_distribution", "change": "origin_receives_host_header",
        "resource_ids": [BUCKET], "path_pattern": FEED, "cache_policy_id": USE_ORIGIN_CACHE_CONTROL,
        "origin_request_policy_id": None, "source_url": CLOUDFRONT_DOCS,
    }
    assert facts_of(body, "availability", change="origin_receives_host_header") == [expected]
    # and nothing else claims damage on this branch
    assert answers(body)["availability"]["facts"] == [expected]
    assert answers(body)["outside_world"]["facts"] == []
    for damage in ("data", "exposure"):
        assert answers(body)[damage]["facts"] == []


def test_L79a_the_fix_caching_optimized_is_no_fact(rig):
    """The corrected change (CachingOptimized does not forward Host) must not be flagged."""
    branch = rig.branch()
    config = json.dumps(distribution_config(CACHING_OPTIMIZED), separators=(",", ":"))
    rig.cli(branch, f"aws cloudfront update-distribution --id {rig.dist.id} --if-match {rig.dist.etag} --distribution-config {quote(config)}")
    assert facts_of(rig.check(branch), "availability", change="origin_receives_host_header") == []


# ── L79b: the re-enabled schedule ──────────────────────────────────

def test_L79b_update_schedule_without_state_is_an_outside_world_fact(rig):
    branch = rig.branch()
    plan = rig.cli(branch, cmd_update_schedule_without_state("publisher"))
    assert plan["unmodeled"] == [] and plan["unknown_fields"] == []
    body = rig.check(branch)
    expected = {
        "resource_id": f"default/{SCHEDULES['publisher']}", "resource_type": "scheduler_schedule", "change": "schedule_enabled",
        "schedule_expression": SCHEDULE_EXPRESSIONS["publisher"], "resource_ids": [LAMBDAS["publisher"]], "action": None,
        "service": "scheduler", "reason": "Runs its target on a timer without anyone starting it.", "source_url": SCHEDULE_DOCS,
    }
    assert facts_of(body, "outside_world", resource_type="scheduler_schedule") == [expected]
    effects = [u for u in unknown_of(body, "outside_world", "target_effects")]
    assert [(u["resource_id"], u["reason"]) for u in effects] == [(LAMBDAS["publisher"], EFFECTS_UNKNOWN)]
    # the other two schedules stay paused and are not mentioned
    assert [f["resource_id"] for f in answers(body)["outside_world"]["facts"]] == [expected["resource_id"]]


def test_L79b_disabled_schedule_restated_as_disabled_is_silent(rig):
    branch = rig.branch()
    rig.cli(branch, cmd_update_schedule_without_state("door") + " --state DISABLED")
    body = rig.check(branch)
    assert answers(body)["outside_world"]["facts"] == []


# ── L79c: the unasked Lambda quota request ─────────────────────────

def test_L79c_quota_increase_is_an_outside_world_fact_with_source_url(rig):
    branch = rig.branch()
    rig.api(branch, QUOTA_CALL)
    body = rig.check(branch)
    facts = facts_of(body, "outside_world", action="servicequotas.RequestServiceQuotaIncrease")
    assert len(facts) == 1
    assert set(facts[0]) == {"action", "service", "reason", "source_url", "resource_id"}
    assert facts[0]["service"] == "servicequotas" and facts[0]["source_url"] == QUOTA_DOCS and facts[0]["reason"]
    assert unknown_of(body, "outside_world", "unclassified_action") == []
    # an account action touches no modeled resource
    for damage in ("data", "exposure", "availability"):
        assert answers(body)[damage]["facts"] == []


CLI_QUOTA = "aws service-quotas request-service-quota-increase --service-code lambda --quota-code L-B99A9384 --desired-value 1000"


def _quota_facts(body):
    return [f for f in answers(body)["outside_world"]["facts"] if f["action"].endswith(".RequestServiceQuotaIncrease")]


def test_L79c_the_same_request_through_the_cli_is_an_outside_world_fact_too(rig):
    """`aws service-quotas request-service-quota-increase` as an agent types it: same source_url, same reason."""
    api_branch, cli_branch = rig.branch("api"), rig.branch("cli")
    rig.api(api_branch, QUOTA_CALL)
    rig.cli(cli_branch, CLI_QUOTA)
    (via_api,), (via_cli,) = _quota_facts(rig.check(api_branch)), _quota_facts(rig.check(cli_branch))
    assert via_cli["source_url"] == via_api["source_url"] == QUOTA_DOCS and via_cli["reason"] == via_api["reason"]


@pytest.mark.xfail(strict=True, reason=(
    "GAP: the CLI spells the service `service-quotas`, the API `servicequotas`; the outside_world fact keeps the "
    "spelling it was given (action/service 'service-quotas.RequestServiceQuotaIncrease' / 'service-quotas' vs "
    "'servicequotas.RequestServiceQuotaIncrease' / 'servicequotas'). The signal is true in both, but one incident "
    "gives different action/service strings per input format."))
def test_L79c_cli_and_api_give_identical_quota_facts_apart_from_the_plan_address(rig):
    api_branch, cli_branch = rig.branch("api"), rig.branch("cli")
    rig.api(api_branch, QUOTA_CALL)
    rig.cli(cli_branch, CLI_QUOTA)
    strip = lambda f: {k: v for k, v in f.items() if k != "resource_id"}
    assert [strip(f) for f in _quota_facts(rig.check(cli_branch))] == [strip(f) for f in _quota_facts(rig.check(api_branch))]


# ── L79d: the missing dynamodb:DeleteItem ──────────────────────────

def test_L79d_removing_delete_item_is_an_availability_fact_naming_the_lambda(rig):
    branch = rig.branch()
    plan = rig.api(branch, put_role_policy_call("publisher", ["dynamodb:GetItem", "dynamodb:PutItem"]))
    assert plan["unmodeled"] == [] and plan["unknown_fields"] == []
    body = rig.check(branch)
    expected = {
        "resource_id": f"iam-role-{ROLES['publisher']}", "resource_type": "iam_role", "change": "permission_removed",
        "action": "dynamodb:DeleteItem", "resource_ids": [TABLE], "affected_node_ids": [LAMBDAS["publisher"]],
    }
    got = facts_of(body, "availability", change="permission_removed")
    assert got == [expected], got
    notes = unknown_of(body, "availability", "app_code_actions")
    assert len(notes) == 1 and notes[0]["resource_id"] == expected["resource_id"]
    assert "application code" in notes[0]["reason"] and "not visible" in notes[0]["reason"]


def test_L79d_keeping_all_three_actions_is_no_fact(rig):
    branch = rig.branch()
    rig.api(branch, put_role_policy_call("door", ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]))
    assert facts_of(rig.check(branch), "availability", change="permission_removed") == []


# ── L79e: a harmless change ────────────────────────────────────────

def test_L79e_a_tag_change_on_the_bucket_claims_no_damage(rig):
    branch = rig.branch()
    rig.api(branch, {"service": "s3", "operation": "PutBucketTagging", "parameters": {
        "Bucket": BUCKET, "Tagging": {"TagSet": [{"Key": "project", "Value": "demo"}, {"Key": "owner", "Value": "someone"}]}}})
    body = rig.check(branch)
    assert [c for c in body["changes"]], "the tag change must be seen, not dropped"
    for damage in ("data", "exposure", "availability", "outside_world"):
        assert answers(body)[damage]["facts"] == [], damage


# ── L79f: zero changes ─────────────────────────────────────────────

def test_L79f_zero_change_check_carries_the_baseline(rig):
    branch = rig.branch()
    body = rig.check(branch)
    # the change summary always lists its three buckets; with no change every one of them is empty
    assert [c["change"] for c in body["changes"]] == ["added", "removed", "modified"]
    assert all(c["resource_ids"] == [] for c in body["changes"])
    for damage in ("data", "exposure", "availability", "outside_world"):
        assert answers(body)[damage]["facts"] == [], damage
    baseline = body["baseline"]
    assert baseline is not None and baseline["question"] == "baseline"
    # a changed branch does not repeat it
    rig.api(branch, QUOTA_CALL)
    assert rig.check(branch)["baseline"] is None


# ── L79g: /context ─────────────────────────────────────────────────

def test_L79g_context_inventory_lists_the_account(rig):
    branch = rig.branch()
    body = rig.context(branch, "inventory")
    ids = {f.get("resource_id") for f in body["facts"]}
    assert {BUCKET, TABLE, rig.dist.id, *LAMBDAS.values()} <= ids
    assert {f"default/{n}" for n in SCHEDULES.values()} <= ids


def test_L79g_context_dependents_of_the_bucket_include_the_distribution(rig):
    branch = rig.branch()
    body = rig.context(branch, "dependents", BUCKET)
    assert any(f["resource_id"] == rig.dist.id and f["relationship"] == "serves_from_bucket" for f in body["facts"]), body["facts"]


def test_L79g_context_access_shows_delete_item_for_each_lambda_role(rig):
    branch = rig.branch()
    body = rig.context(branch, "access")
    by_id = {f["resource_id"]: f for f in body["facts"]}
    for kind in LAMBDAS:
        fact = by_id[f"iam-role-{ROLES[kind]}"]
        allows = {(p["action"], p["effect"]) for p in fact["permissions"]}
        assert ("dynamodb:DeleteItem", "allow") in allows, (kind, fact)
        assert all(p["resource_ids"] == [TABLE] for p in fact["permissions"])


def test_L79g_context_access_on_a_branch_that_removed_delete_item_no_longer_shows_it(rig):
    branch = rig.branch()
    rig.api(branch, put_role_policy_call("publisher", ["dynamodb:GetItem", "dynamodb:PutItem"]))
    by_id = {f["resource_id"]: f for f in rig.context(branch, "access")["facts"]}
    actions = lambda kind: {p["action"] for p in by_id[f"iam-role-{ROLES[kind]}"]["permissions"]}
    assert "dynamodb:DeleteItem" not in actions("publisher") and "dynamodb:DeleteItem" in actions("door")


# ── L79h: redaction expectation on every response ──────────────────

def _every_incident(rig):
    for command in (cmd_feed_to_host_forwarding_policy(rig.dist), cmd_update_schedule_without_state("sentinel")):
        branch = rig.branch()
        rig.cli(branch, command)
        rig.check(branch)
    for call in (QUOTA_CALL, put_role_policy_call("door", ["dynamodb:GetItem", "dynamodb:PutItem"])):
        branch = rig.branch()
        rig.api(branch, call)
        rig.check(branch)
        rig.context(branch, "access")
        rig.context(branch, "inventory")
    rig.context(rig.branch(), "dependents", BUCKET)


def _own_leaks(node, names, known_ids, key="", path="$"):
    """L74i's leak rule with the keys this account produces: a name may only be a whole value of a masked key."""
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if any(n in k for n in names):
                found.append(f"{path}: dict key {k!r}")
            found += _own_leaks(v, names, known_ids, k, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found += _own_leaks(v, names, known_ids, key, f"{path}[{i}]")
    elif isinstance(node, str) and any(n in node for n in names):
        if key not in REDACTED_ID_KEYS or not (node in known_ids or re.fullmatch(r"arn:aws:\S+", node)):
            found.append(f"{path}: {node!r}")
    return found


def test_L79h_every_identifier_key_is_masked_by_the_mcp_tokenizer():
    src = TOKENIZE_TS.read_text()
    masked = set()
    for name in ("SENSITIVE_KEYS", "IDENTIFIER_KEYS"):
        masked |= set(re.findall(r'"([^"]+)"', re.search(rf"const {name} = new Set\(\[(.*?)\]\)", src, re.S).group(1)))
    assert REDACTED_ID_KEYS <= masked, sorted(REDACTED_ID_KEYS - masked)


def test_L79h_no_invented_id_or_name_in_free_text_of_any_response(rig):
    """The MCP tokenizer masks the identifier KEYS; everything else must be free of ids (reuses the L74i helper)."""
    _every_incident(rig)
    names = [ACCOUNT, BUCKET, TABLE, rig.dist.id, build.OAC, SCHEDULER_ROLE, *LAMBDAS.values(), *ROLES.values(), *SCHEDULES.values()]

    def id_values(node, key=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from id_values(v, k)
        elif isinstance(node, list):
            for v in node:
                yield from id_values(v, key)
        elif isinstance(node, str) and key in REDACTED_ID_KEYS:
            yield node

    assert len(rig.responses) > 15
    for label, body in rig.responses:
        known = set(id_values(body))
        problems = _own_leaks(body, names, known)
        assert not problems, (label, problems)
    # positive control: the ids really are in the answers, under the masked keys
    blob = json.dumps([b for _, b in rig.responses])
    for name in (BUCKET, TABLE, LAMBDAS["door"], rig.dist.id):
        assert name in blob
    assert ACCOUNT not in blob  # stronger than the rule: the account id is in no answer at all


def test_L79h_the_fixture_has_no_real_account_identifier(jarvis_infra):
    text = jarvis_infra.model_dump_json()
    for real in ("282027772803", "E35DGPXUEH0T83", "feeds.emfirge.cloud"):
        assert real not in text
