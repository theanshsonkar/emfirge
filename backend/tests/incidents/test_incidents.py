import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from app.diffing import diff_infrastructure
from app.egraph import build_graph, get_internet_reachable_set
from app.rules import run_all_checks
from tests.incidents.base import build_incident_base
from tests.incidents.known_gaps import KNOWN_GAPS

SCENARIOS = json.loads((Path(__file__).with_name("scenarios.json")).read_text())


@pytest.fixture
def incident_branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'incident-branches.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(verdict, "run_checkov", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_trivy", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_cloudsplaining", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: build_incident_base())
    monkeypatch.setenv("EMFIRGE_RUN_SCANNERS", "0")
    main._branch_request_log.clear()
    yield
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def _assert_expectation(expect, diff, verdict_json):
    if "verdict" in expect:
        assert verdict_json["verdict"] == expect["verdict"]
    if "introduced_includes" in expect:
        added = {item["rule_id"] for item in verdict_json["native_added"]}
        assert set(expect["introduced_includes"]).issubset(added)
    if "introduced_count" in expect:
        assert len(verdict_json["native_added"]) == expect["introduced_count"]
    if "score_after_lte_before" in expect:
        assert diff["score_after"] <= diff["score_before"]
    if "no_longer_reachable_includes" in expect:
        assert set(expect["no_longer_reachable_includes"]).issubset(set(diff["no_longer_internet_reachable"]))
    if "introduces_privilege_escalation" in expect:
        assert verdict_json["introduces_privilege_escalation"] is expect["introduces_privilege_escalation"]


@pytest.mark.parametrize(
    "scenario",
    [pytest.param(
        s,
        id=s["id"],
        marks=pytest.mark.xfail(strict=True, reason=KNOWN_GAPS[s["id"]])
        if s["id"] in KNOWN_GAPS else (),
    ) for s in SCENARIOS],
)
def test_incident_scenario(incident_branch_db, scenario):
    client = TestClient(main.app)
    created = client.post("/branches", json={"base_analysis_id": "incident", "name": scenario["id"]})
    assert created.status_code == 200
    branch_id = created.json()["branch_id"]
    count = 0
    for change in scenario["changes"]:
        payload = {**change, "expected_change_count": count}
        response = client.post(f"/branches/{branch_id}/changes", json=payload)
        if "http_status" in scenario["expect"]:
            assert response.status_code == scenario["expect"]["http_status"]
            assert client.get(f"/branches/{branch_id}").json()["num_changes"] == count
            return
        assert response.status_code == 200
        count += 1
    diff = client.get(f"/branches/{branch_id}/diff")
    verdict_response = client.get(f"/branches/{branch_id}/verdict")
    assert diff.status_code == verdict_response.status_code == 200
    _assert_expectation(scenario["expect"], diff.json(), verdict_response.json())


def test_incident_base_is_internet_reachable_and_ssh_critical():
    base = build_incident_base()
    assert "i-inc-web" in get_internet_reachable_set(build_graph(base))
    findings = run_all_checks(base, build_graph(base))
    assert any(f.rule_id == "EMFIRGE-EC2-002" and f.severity == "Critical" for f in findings["critical_risks"])
