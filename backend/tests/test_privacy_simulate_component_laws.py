"""L71e /simulate/component in raw (MCP) mode never calls an LLM; the narrative is deterministic."""
import json

import anthropic
import pytest
from fastapi.testclient import TestClient

from app import database, main
from app.models import AWSInfrastructure

ANALYSIS_ID = "cccccccc-0000-4000-8000-000000000003"
BODY = {"analysis_id": ANALYSIS_ID, "config": {"component_type": "s3_bucket"}}


@pytest.fixture
def client(shared_test_db, monkeypatch):
    infra = AWSInfrastructure(region="us-east-1").model_dump(mode="json")
    with database.SessionLocal() as db:
        db.add(database.AnalysisLog(aws_account_id="", findings_json=json.dumps(
            {"analysis_id": ANALYSIS_ID, "infrastructure": infra}), risk_score=1))
        db.commit()
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda *_a, **_k: None, raising=False)
    main._simulate_request_log.clear()
    return TestClient(main.app)


@pytest.fixture
def llm_calls(monkeypatch):
    calls = []

    class Forbidden:
        def __init__(self, *args, **kwargs):
            calls.append("client constructed")
            raise AssertionError("LLM client must not be used in raw mode")

    monkeypatch.setattr(anthropic, "Anthropic", Forbidden)
    return calls


@pytest.mark.parametrize("headers", [{"x-mcp": "1"}, {"x-source": "mcp"}])
def test_L71e_raw_mode_never_calls_an_llm(client, llm_calls, headers):
    response = client.post("/simulate/component", json=BODY, headers=headers)
    assert response.status_code == 200, response.text
    assert llm_calls == []
    narrative = response.json()["narrative"]
    assert narrative["verdict"] and narrative["summary"]


def test_L71e_non_raw_mode_still_uses_the_llm_path(client, llm_calls):
    response = client.post("/simulate/component", json=BODY)
    assert response.status_code == 200, response.text
    assert llm_calls == ["client constructed"]  # failure falls back to the deterministic narrative
