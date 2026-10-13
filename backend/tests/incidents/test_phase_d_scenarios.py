import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from tests.incidents.base import build_incident_base
from tests.incidents.known_gaps import KNOWN_GAPS_PHASE_D
from tests.incidents.synthetic_base import load_synthetic_base

SCENARIOS = json.loads((Path(__file__).with_name("scenarios_phase_d.json")).read_text())


@pytest.fixture
def phase_d_branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase-d-branches.sqlite'}")
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


def _assert_expectation(expect, response):
    v = response.json()
    reasons = {r["code"] for r in v["reasons"]}
    allowed = {"verdict", "introduces_privilege_escalation", "reasons_include", "reasons_exclude", "data_lost_includes", "data_lost_excludes", "impact_includes", "coverage_cannot_see_includes", "http_status"}
    unknown = set(expect) - allowed
    if unknown:
        pytest.fail(f"Unknown expectation key(s): {sorted(unknown)}")
    if "verdict" in expect:
        assert v["verdict"] == expect["verdict"]
    if "introduces_privilege_escalation" in expect:
        assert v["introduces_privilege_escalation"] is expect["introduces_privilege_escalation"]
    assert set(expect.get("reasons_include", [])).issubset(reasons)
    assert not set(expect.get("reasons_exclude", [])) & reasons
    lost = {d["resource_id"] for d in v["deletion"]["data_lost"]}
    assert set(expect.get("data_lost_includes", [])).issubset(lost)
    assert not set(expect.get("data_lost_excludes", [])) & lost
    impacts = {i["resource_id"] for i in v["deletion"]["impacts"]}
    assert set(expect.get("impact_includes", [])).issubset(impacts)
    cannot_see = set(v["deletion"]["coverage"]["cannot_see"])
    assert set(expect.get("coverage_cannot_see_includes", [])).issubset(cannot_see)


@pytest.mark.parametrize(
    "scenario",
    [pytest.param(s, id=s["id"], marks=pytest.mark.xfail(strict=True, reason=KNOWN_GAPS_PHASE_D[s["id"]])) for s in SCENARIOS],
)
def test_phase_d_scenario(phase_d_branch_db, scenario):
    base = load_synthetic_base(scenario["base"], scenario.get("base_patch"))
    client = TestClient(main.app)
    created = client.post("/branches", json={"base_analysis_id": "phase-d", "name": scenario["id"]})
    assert created.status_code == 200
    branch_id = created.json()["branch_id"]
    count = 0
    for change in scenario.get("changes", []):
        payload = {**change, "expected_change_count": count}
        response = client.post(f"/branches/{branch_id}/changes", json=payload)
        expected_status = scenario["expect"].get("http_status", 200)
        assert response.status_code == expected_status
        if "http_status" in scenario["expect"]:
            return
        count += 1
    if "terraform_plan" in scenario:
        try:
            from app.plan_ingest import ingest_terraform_plan
        except ImportError as exc:
            raise NotImplementedError("Phase I") from exc
        ingest_terraform_plan(Path(__file__).parent / scenario["terraform_plan"])
    verdict_response = client.get(f"/branches/{branch_id}/verdict")
    assert verdict_response.status_code == 200
    _assert_expectation(scenario["expect"], verdict_response)
