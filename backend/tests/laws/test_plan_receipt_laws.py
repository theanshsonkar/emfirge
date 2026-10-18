import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app import branches, database, main, verdict
from tests.incidents.synthetic_base import load_synthetic_base


@pytest.fixture
def plan_client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'law.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: load_synthetic_base("delete"))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    for name in ("run_checkov", "run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(verdict, name, lambda *_a, **_k: {"available": False, "findings": []})
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    client = TestClient(main.app)
    yield client, factory
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def _branch(client, name="law"):
    response = client.post("/branches", json={"base_analysis_id": "delete", "name": name})
    assert response.status_code == 200, response.text
    return response.json()["branch_id"]


def _calls():
    return [{"service": "ec2", "operation": "AuthorizeSecurityGroupIngress",
             "parameters": {"GroupId": "sg-dl-web", "IpPermissions": [{
                 "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                 "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}}
            for port in (8080, 8443)]


def _plan(client, branch_id, calls=None):
    response = client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": calls or _calls()})
    assert response.status_code == 200, response.text
    return response.json()


def _typed(client, branch_id, count=None):
    payload = {"op": "modify", "resource_type": "security_group", "resource_id": "sg-dl-web",
               "fields": {"rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                        "ip_ranges": ["0.0.0.0/0"]}]}}
    if count is not None:
        payload["expected_change_count"] = count
    response = client.post(f"/branches/{branch_id}/changes", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def _verify_plan(client, branch_id, plan_id):
    handback = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback")
    assert handback.status_code == 200, handback.text
    body = handback.json()
    checked = client.post("/handback/verify", json={
        "plan_id": plan_id, "verdict_id": body["verdict_id"], "plan_text": body["plan_text"],
        "base_analysis_id": body["base_analysis_id"], "branch_revision": body["branch_revision"]})
    assert checked.status_code == 200, checked.text
    assert checked.json() == {"ok": True}
    return body


def test_L41_receipt_revision_matches_prefix(plan_client):
    client, _ = plan_client
    branch_id = _branch(client)
    _typed(client, branch_id, 0)
    receipt = _plan(client, branch_id)
    branch = branches.get_branch(branch_id)
    expected = branches.branch_revision(branches.Branch(
        branch_id=branch_id, name=branch.name, base=branch.base, changes=branch.changes[:3], status=branch.status))
    assert receipt["branch_revision"] == expected


def test_L41a_fork_keeps_receipts(plan_client):
    client, _ = plan_client
    parent = _branch(client, "parent")
    receipt = _plan(client, parent)
    fork = client.post(f"/branches/{parent}/fork", json={"name": "child"}).json()
    child = fork["branch_id"]
    child_plan = fork["plan_id_map"][receipt["plan_id"]]
    child_hb = _verify_plan(client, child, child_plan)
    assert child_hb["input_sha256"] == receipt["input_sha256"]
    typed = client.get(f"/branches/{child}/handback")
    assert typed.status_code == 409 and typed.json()["error"] == "branch_has_plan_receipts"
    assert client.get(f"/branches/{parent}/plans/{receipt['plan_id']}/handback").status_code == 200


def test_L41b_rollback_to_count_drops_only_later_receipts(plan_client):
    client, _ = plan_client
    bid = _branch(client)
    _typed(client, bid, 0)
    x = _plan(client, bid)
    _typed(client, bid, 3)
    y = _plan(client, bid)
    assert client.post(f"/branches/{bid}/rollback-to-count", json={"target_change_count": 3}).status_code == 200
    _verify_plan(client, bid, x["plan_id"])
    assert client.get(f"/branches/{bid}/plans/{y['plan_id']}/handback").status_code == 404
    client.post(f"/branches/{bid}/rollback-to-count", json={"target_change_count": 2})
    assert client.get(f"/branches/{bid}/plans/{x['plan_id']}/handback").status_code == 404
    client.post(f"/branches/{bid}/rollback-to-count", json={"target_change_count": 0})
    assert client.get(f"/branches/{bid}/handback").json().get("error") != "branch_has_plan_receipts"


def test_L41c_rollback_last(plan_client):
    client, _ = plan_client
    bid = _branch(client)
    x = _plan(client, bid)
    _typed(client, bid, 2)
    assert client.post(f"/branches/{bid}/rollback").status_code == 200
    assert client.get(f"/branches/{bid}/plans/{x['plan_id']}/handback").status_code == 200
    client.post(f"/branches/{bid}/rollback")
    assert client.get(f"/branches/{bid}/plans/{x['plan_id']}/handback").status_code == 404


def test_L41d_child_rollback_does_not_touch_parent(plan_client):
    client, _ = plan_client
    parent = _branch(client)
    receipt = _plan(client, parent)
    child = client.post(f"/branches/{parent}/fork", json={"name": "child"}).json()["branch_id"]
    child_plan = client.get(f"/branches/{child}/verdict").json()["plans"][0]["plan_id"]
    client.post(f"/branches/{child}/rollback-to-count", json={"target_change_count": 0})
    assert client.get(f"/branches/{child}/plans/{child_plan}/handback").status_code == 404
    assert client.get(f"/branches/{parent}/plans/{receipt['plan_id']}/handback").status_code == 200


def test_L41e_discard_keeps_receipt_rows(plan_client):
    client, factory = plan_client
    bid = _branch(client)
    receipt = _plan(client, bid)
    assert client.post(f"/branches/{bid}/discard", json={}).status_code == 200
    session = factory()
    try:
        assert session.query(database.PlanLog).filter_by(plan_id=receipt["plan_id"]).count() == 1
    finally:
        session.close()
