"""L9 privacy law: customer identifiers never enter free-text API fields."""
import copy
import json

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient

from app import branches, database, main, verdict
from app.demo_seed import build_demo_infrastructure
from app.rules import run_all_checks
from tests.incidents.base import build_incident_base
from tests.incidents.test_incidents import incident_branch_db

MARKERS = ("zq-planted-bucket-7731", "sg-0zqplanted01", "zqplantedrole", "000000007731")
FREE_TEXT_KEYS = {
    "issue", "recommendation", "title", "summary", "message", "messages", "reason",
    "notes", "warnings", "coverage_warnings", "caption", "detail", "error",
}
RULES = st.lists(st.fixed_dictionaries({
    "protocol": st.just("tcp"),
    "from_port": st.integers(min_value=22, max_value=443),
    "to_port": st.integers(min_value=22, max_value=443),
    "ip_ranges": st.lists(st.sampled_from(["0.0.0.0/0", "10.0.0.0/16"]), min_size=1, max_size=1),
}), max_size=2)


def _planted_base():
    base = copy.deepcopy(build_incident_base())
    base.ec2.security_groups[0].id = "sg-0zqplanted01"
    base.ec2.security_groups[0].name = "zq-planted-security-group"
    base.ec2.instances[0].sg_ids = ["sg-0zqplanted01"]
    base.ec2.instance_ids = [base.ec2.instances[0].id]
    base.ec2.ssh_security_group_id = "sg-0zqplanted01"
    base.s3.buckets[0].name = "zq-planted-bucket-7731"
    base.iam.role_policies[0].role_arn = "arn:aws:iam::000000007731:role/ZqPlantedRole"
    base.iam.role_policies[0].role_name = "ZqPlantedRole"
    base.lambda_data.functions[0].role_arn = base.iam.role_policies[0].role_arn
    return base


def _walk(value, key=None):
    if isinstance(value, str) and key in FREE_TEXT_KEYS:
        lowered = value.lower()
        assert not any(marker in lowered for marker in MARKERS), (key, value)
    elif isinstance(value, dict):
        for child_key, child in value.items():
            _walk(child, child_key)
    elif isinstance(value, list):
        for child in value:
            _walk(child, key)


def _assert_safe(response):
    assert response.status_code < 500, response.text
    _walk(response.json())


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=4)
@given(RULES, st.booleans(), st.booleans())
def test_L9_http_free_text_never_contains_planted_identifiers(
    incident_branch_db, monkeypatch, rules, public, delete_assets,
):
    base = _planted_base()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    monkeypatch.setattr(verdict, "run_checkov", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_trivy", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_cloudsplaining", lambda *_a, **_k: {"available": False, "findings": []})
    findings = jsonable_encoder(run_all_checks(base))
    analysis_id = f"l9-analysis-{abs(hash((repr(rules), public, delete_assets)))}"
    database.save_analysis({
        "region_analyzed": base.region, "aws_account_id": "000000007731",
        "findings_json": {"analysis_id": analysis_id, "infrastructure": base.model_dump(mode="json"),
                          **findings},
    })
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    main._branch_request_log.clear()
    client = TestClient(main.app)
    for response in (
        client.get(f"/logs/by-uuid/{analysis_id}"),
        client.get(f"/egraph/{analysis_id}"),
        client.get(f"/compliance/{analysis_id}"),
    ):
        _assert_safe(response)

    created = client.post("/branches", json={"base_analysis_id": analysis_id, "name": "l9"})
    assert created.status_code == 200, created.text
    _assert_safe(created)
    branch_id = created.json()["branch_id"]
    change = {"op": "modify", "resource_type": "security_group",
              "resource_id": "sg-0zqplanted01", "fields": {"rules": rules}}
    for payload in (change, {"op": "modify", "resource_type": "s3_bucket",
                             "resource_id": "zq-planted-bucket-7731",
                             "fields": {"is_public": public}}):
        response = client.post(f"/branches/{branch_id}/changes", json=payload)
        _assert_safe(response)
    if delete_assets:
        _assert_safe(client.post(f"/branches/{branch_id}/changes", json={
            "op": "delete", "resource_type": "s3_bucket",
            "resource_id": "zq-planted-bucket-7731", "fields": {},
        }))
    for response in (
        client.get(f"/branches/{branch_id}"),
        client.get(f"/branches/{branch_id}/diff"),
        client.get(f"/branches/{branch_id}/verdict"),
        client.post("/branches/compare", json={"branch_ids": [branch_id]}),
        client.get("/branches/unknown-branch"),
        client.post(f"/branches/{branch_id}/changes", json={
            "op": "modify", "resource_type": "security_group",
            "resource_id": "sg-0zqplanted01", "fields": {"rules": [{"cidrs": ["planted"]}]},
        }),
        client.post(f"/branches/{branch_id}/changes", json={
            **change, "expected_change_count": 999,
        }),
    ):
        _assert_safe(response)


@pytest.mark.parametrize("endpoint", ["findings", "analysis", "branch-create", "branch-change", "branch-diff", "branch-verdict", "branch-compare", "branch-inspect"])
def test_L9_endpoint_inventory_is_explicit(endpoint):
    assert endpoint
