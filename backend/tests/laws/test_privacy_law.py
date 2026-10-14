"""L9 privacy law: customer identifiers never enter free-text API fields."""
import copy
import json
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, event, given, settings, strategies as st
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient

from app import branches, database, main, verdict
from app.rules import run_all_checks
from tests.incidents.base import build_incident_base

FREE_TEXT_KEYS = {
    "issue", "recommendation", "title", "summary", "message", "messages", "reason",
    "notes", "warnings", "coverage_warnings", "caption", "detail", "error",
    "description", "explanation", "note", "label", "text", "hint", "impact",
    "evidence", "statement",
}
HEX = "0123456789abcdef"
MARKER = st.builds(lambda value: "mk" + value, st.text(alphabet=HEX, min_size=10, max_size=10))
ACCOUNT = st.text(alphabet="0123456789", min_size=12, max_size=12)
PORT = st.sampled_from([22, 80, 443, 5432, 3389, 8080])
CIDR = st.sampled_from(["0.0.0.0/0", "10.0.0.0/8", "203.0.113.7/32"])
RULES = st.lists(st.fixed_dictionaries({
    "protocol": st.just("tcp"), "from_port": PORT, "to_port": PORT,
    "ip_ranges": st.lists(CIDR, min_size=1, max_size=1),
}), max_size=2)
OPS = st.lists(st.one_of(
    st.just("sg"), st.just("bucket"), st.just("unknown"), st.just("malformed"),
    st.just("iam"), st.just("simulate"),
), min_size=1, max_size=6)


def _planted_base(sg_id, sg_name, instance_id, bucket_name, role_arn, role_name, lambda_name):
    base = copy.deepcopy(build_incident_base())
    base.ec2.security_groups[0].id = sg_id
    base.ec2.security_groups[0].name = sg_name
    base.ec2.instances[0].id = instance_id
    base.ec2.instances[0].sg_ids = [sg_id]
    base.ec2.instance_ids = [instance_id]
    base.ec2.ssh_security_group_id = sg_id
    base.s3.buckets[0].name = bucket_name
    base.iam.role_policies[0].role_arn = role_arn
    base.iam.role_policies[0].role_name = role_name
    base.iam.role_policies[0].access_statements[0].resources = [role_arn]
    base.lambda_data.functions[0].name = lambda_name
    base.lambda_data.functions[0].role_arn = role_arn
    return base


def _walk(value, key, markers, account):
    if isinstance(value, str):
        if key in FREE_TEXT_KEYS:
            lowered = value.lower()
            assert not any(marker.lower() in lowered for marker in markers), (key, value)
            assert account not in value, (key, value)
    elif isinstance(value, dict):
        for child_key, child in value.items():
            _walk(child, child_key, markers, account)
    elif isinstance(value, list):
        for child in value:
            _walk(child, key, markers, account)


def _assert_safe(response, markers, account):
    body = response.text
    if response.status_code < 200 or response.status_code >= 300:
        assert not any(marker in body for marker in markers), body
        assert account not in body, body
    if "text/event-stream" in response.headers.get("content-type", ""):
        for line in body.splitlines():
            if line.startswith("data:"):
                _walk(json.loads(line[5:].strip()), None, markers, account)
    else:
        _walk(response.json(), None, markers, account)


@settings(max_examples=100, deadline=None, suppress_health_check=[
    HealthCheck.function_scoped_fixture, HealthCheck.too_slow,
])
@given(
    st.lists(MARKER, min_size=8, max_size=8, unique=True), ACCOUNT, RULES, OPS,
)
def test_L9_http_free_text_never_contains_planted_identifiers(
    incident_branch_db, monkeypatch, markers, account, rules, operations,
):
    sg_id, sg_name, instance_id, bucket_marker, role_marker, role_name_marker, lambda_marker, unknown = markers
    bucket_name = f"{bucket_marker}-{account}-data"
    role_arn = f"arn:aws:iam::{account}:role/{role_name_marker}"
    base = _planted_base(sg_id, sg_name, instance_id, bucket_name, role_arn, role_name_marker, lambda_marker)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    monkeypatch.setattr(verdict, "run_checkov", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_trivy", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_cloudsplaining", lambda *_a, **_k: {"available": False, "findings": []})
    findings = jsonable_encoder(run_all_checks(base))
    analysis_id = f"l9-analysis-{abs(hash((account, tuple(markers), tuple(operations))))}"
    database.save_analysis({
        "region_analyzed": base.region, "aws_account_id": account,
        "findings_json": {"analysis_id": analysis_id, "infrastructure": base.model_dump(mode="json"), **findings},
    })
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "get_simulation_count_today", lambda _account: 0)
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    monkeypatch.setitem(main.app.dependency_overrides, main.require_api_key, lambda: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    llm_inputs = []
    llm_prompts = []

    class AdversarialMessages:
        def create(self, **kwargs):
            llm_inputs.append(kwargs)
            llm_prompts.append(kwargs["messages"][0]["content"])
            return SimpleNamespace(content=[SimpleNamespace(text=repr(kwargs))])

    class AdversarialAnthropic:
        def __init__(self, **_kwargs):
            self.messages = AdversarialMessages()

    monkeypatch.setattr("anthropic.Anthropic", AdversarialAnthropic)
    main._branch_request_log.clear()
    main._simulate_request_log.clear()
    client = TestClient(main.app)

    for response in (client.get(f"/logs/by-uuid/{analysis_id}"), client.get(f"/egraph/{analysis_id}"),
                      client.get(f"/compliance/{analysis_id}")):
        _assert_safe(response, markers, account)
    created = client.post("/branches", json={"base_analysis_id": analysis_id, "name": "l9"})
    _assert_safe(created, markers, account)
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    accepted = 0
    bucket_seen = False
    for op in operations:
        event(op)
        if op == "bucket":
            if bucket_seen:
                continue
            bucket_seen = True
            payload = {"op": "delete", "resource_type": "s3_bucket", "resource_id": bucket_name, "fields": {}}
        elif op == "sg":
            payload = {"op": "modify", "resource_type": "security_group", "resource_id": sg_id,
                       "fields": {"rules": rules}}
        elif op == "unknown":
            payload = {"op": "modify", "resource_type": "security_group", "resource_id": unknown,
                       "fields": {"rules": rules}}
        elif op == "malformed":
            payload = {"op": "modify", "resource_type": "security_group", "resource_id": sg_id,
                       "fields": {f"{unknown}-field": unknown}}
        elif op == "iam":
            payload = {"op": "modify", "resource_type": "iam_role_policy", "resource_id": role_arn,
                       "fields": {"access_statements": [{"effect": "Allow", "actions": ["iam:CreatePolicyVersion"],
                       "resources": ["*"]}]}}
        else:
            response = client.post("/simulate", json={"analysis_id": analysis_id,
                "query": f"Explain changes involving {sg_id}, {instance_id}, {bucket_name}, {role_arn}, {lambda_marker}"})
            assert response.status_code == 200, response.text
            assert any(line.startswith("data:") for line in response.text.splitlines()), response.text
            _assert_safe(response, markers, account)
            assert llm_inputs
            assert llm_prompts
            prompt = llm_prompts[0]
            assert not any(marker in prompt or account in prompt for marker in markers)
            assert "[redacted]" not in prompt
            assert "Nodes:" in prompt
            assert not any(marker in repr(llm_inputs[-1]) or account in repr(llm_inputs[-1]) for marker in markers)
            continue
        payload["expected_change_count"] = accepted
        response = client.post(f"/branches/{branch_id}/changes", json=payload)
        _assert_safe(response, markers, account)
        if op in {"unknown", "malformed"}:
            assert response.status_code == 422, response.text
        else:
            assert response.status_code == 200, response.text
            accepted += 1

    plan = {"format_version": "1.0", "resource_changes": [
        {"address": f"aws_security_group.{sg_id}", "type": "aws_security_group", "change": {
            "actions": ["delete"], "before": {"id": sg_id}, "after": None}},
        {"address": f"aws_dynamodb_table.{lambda_marker}", "type": "aws_dynamodb_table", "change": {
            "actions": ["delete"], "before": {"name": lambda_marker}, "after": None}},
    ]}
    plan_raw = json.dumps(plan, separators=(",", ":")).encode()
    plan_response = client.post(f"/branches/{branch_id}/plans/terraform", content=plan_raw)
    _assert_safe(plan_response, markers, account)
    assert plan_response.status_code == 200, plan_response.text
    plan_id = plan_response.json()["plan_id"]
    handback = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback")
    _assert_safe(handback, markers, account)
    assert handback.status_code == 200, handback.text
    handback_payload = handback.json()
    verified = client.post("/handback/verify", json={
        "plan_id": plan_id, "verdict_id": handback_payload["verdict_id"],
        "plan_text": handback_payload["plan_text"],
    })
    _assert_safe(verified, markers, account)
    assert verified.status_code == 200, verified.text

    final_responses = (
        client.get(f"/branches/{branch_id}/verdict"), client.get(f"/branches/{branch_id}/diff"),
        client.get(f"/branches/{branch_id}"), client.post("/branches/compare", json={"branch_ids": [branch_id]}),
        client.get("/branches/unknown-branch"),
    )
    for response in final_responses:
        _assert_safe(response, markers, account)
    for response in final_responses[:-1]:
        assert response.status_code == 200, response.text
    assert final_responses[-1].status_code == 404, final_responses[-1].text


def test_L9_evidence_endpoints_do_not_echo_cloudtrail_customer_markers(incident_branch_db, monkeypatch):
    from datetime import datetime, timezone
    from app.evidence_models import EvidenceRecord
    marker = "CUSTOMER-USERNAME-MARKER"
    base = build_incident_base()
    analysis_id = "privacy-evidence-analysis"
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _: base)
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _: None)
    monkeypatch.setattr(main, "_scanned_account_id", lambda _: "111122223333")
    monkeypatch.setattr(main, "assume_role_credentials", lambda _role_arn, _caller, _db: ({"AccessKeyId": "x", "SecretAccessKey": "y"}, "111122223333"))
    monkeypatch.setattr(main, "read_evidence", lambda *args, **kwargs: [EvidenceRecord(
        resource_id="none", resource_type="rds_instance", source="cloudtrail_events", status="ok", used=None,
        window_days=90, observed_at=datetime.now(timezone.utc).isoformat(), event_name="DeleteDB")])
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    client = TestClient(main.app)
    branch_id = client.post("/branches", json={"base_analysis_id": analysis_id, "name": "privacy"}).json()["branch_id"]
    estimate = client.get(f"/branches/{branch_id}/in-use-evidence/estimate?sources=cloudtrail_events")
    assert estimate.status_code == 200
    payload = {"role_arn": "arn:aws:iam::111122223333:role/Role", "sources": ["cloudtrail_events"],
               "accept_estimate_id": estimate.json()["estimate_id"]}
    response = client.post(f"/branches/{branch_id}/in-use-evidence", json=payload)
    assert response.status_code == 200
    assert marker not in response.text
    main.app.dependency_overrides.pop(main.require_api_key, None)
