import hashlib
import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings, strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from tests.incidents.synthetic_base import load_synthetic_base


@pytest.fixture
def handback_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'handback.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(verdict, "run_checkov", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_trivy", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_cloudsplaining", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: load_synthetic_base("delete"))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def posted_plan(handback_db):
    raw = (Path(__file__).parent / "incidents/fixtures/datatalks_destroy_plan.json").read_bytes()
    branch_response = handback_db.post("/branches", json={"base_analysis_id": "delete", "name": "handback"})
    assert branch_response.status_code == 200, branch_response.text
    branch_id = branch_response.json()["branch_id"]
    response = handback_db.post(f"/branches/{branch_id}/plans/terraform", content=raw)
    assert response.status_code == 200, response.text
    return handback_db, branch_id, raw, response.json()["plan_id"]


def test_handback_round_trip_is_original_input(posted_plan):
    client, branch_id, raw, plan_id = posted_plan
    response = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["plan_text"].encode() == raw
    assert hashlib.sha256(payload["plan_text"].encode()).hexdigest() == payload["input_sha256"]
    verified = client.post("/handback/verify", json={
        "plan_id": plan_id, "verdict_id": payload["verdict_id"], "plan_text": payload["plan_text"], "base_analysis_id": payload["base_analysis_id"], "branch_revision": payload["branch_revision"],
    })
    assert verified.status_code == 200
    assert verified.json() == {"ok": True}


def test_handback_conflicts_never_echo_input(posted_plan):
    client, branch_id, raw, plan_id = posted_plan
    handback = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback").json()
    changed = handback["plan_text"][:-1] + ("0" if handback["plan_text"][-1] != "0" else "1")
    response = client.post("/handback/verify", json={
        "plan_id": plan_id, "base_analysis_id": handback["base_analysis_id"], "branch_revision": handback["branch_revision"], "verdict_id": handback["verdict_id"], "plan_text": changed,
    })
    assert response.status_code == 409
    assert response.json() == {"ok": False, "reason_code": "input_hash_mismatch"}
    assert raw.decode() not in response.text

    response = client.post("/handback/verify", json={
        "plan_id": "unknown", "verdict_id": "x", "plan_text": handback["plan_text"], "base_analysis_id": handback["base_analysis_id"], "branch_revision": handback["branch_revision"],
    })
    assert response.status_code == 409
    assert response.json() == {"ok": False, "reason_code": "unknown_plan"}


@settings(max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.integers(min_value=0, max_value=1000))
def test_handback_hash_law(posted_plan, offset):
    client, branch_id, raw, plan_id = posted_plan
    handback = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback").json()
    text = bytearray(raw)
    if text:
        text[offset % len(text)] ^= 1
    candidate = bytes(text).decode("utf-8", errors="replace")
    response = client.post("/handback/verify", json={
        "plan_id": plan_id, "base_analysis_id": handback["base_analysis_id"], "branch_revision": handback["branch_revision"], "verdict_id": handback["verdict_id"], "plan_text": candidate,
    })
    assert (response.status_code == 200) is (bytes(text) == raw)


def test_handback_verdict_and_revision_binding(posted_plan):
    client, branch_id, _raw, plan_id = posted_plan
    handback = client.get(f"/branches/{branch_id}/plans/{plan_id}/handback").json()
    tampered = client.post("/handback/verify", json={
        "plan_id": plan_id, "base_analysis_id": handback["base_analysis_id"], "branch_revision": handback["branch_revision"], "verdict_id": "0" * 64, "plan_text": handback["plan_text"],
    })
    assert tampered.status_code == 409
    assert tampered.json() == {"ok": False, "reason_code": "verdict_changed"}

    changed = client.post(f"/branches/{branch_id}/changes", json={
        "op": "add", "resource_type": "s3_bucket", "resource_id": "handback-extra",
        "fields": {}, "expected_change_count": 2,
    })
    assert changed.status_code == 200, changed.text
    stale = client.post("/handback/verify", json={
        "plan_id": plan_id, "base_analysis_id": handback["base_analysis_id"], "branch_revision": handback["branch_revision"], "verdict_id": handback["verdict_id"], "plan_text": handback["plan_text"],
    })
    assert stale.status_code == 409
    assert stale.json() == {"ok": False, "reason_code": "branch_revision_changed"}
