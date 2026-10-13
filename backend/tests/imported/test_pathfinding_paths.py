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

PATHS = json.loads(
    (Path(__file__).parents[2] / "app" / "data" / "pathfinding_paths.json").read_text()
)["paths"]
ROLE_ARN = "arn:aws:iam::000000000000:role/EmfirgeDemoAppRole"

# Keep this explicit and reviewable. It should only contain paths that the branch
# change model or matcher genuinely cannot express or decide.
PATHFINDING_KNOWN_GAPS: dict[str, str] = {}


def _path_param(path):
    marks = ()
    if path["id"] in PATHFINDING_KNOWN_GAPS:
        marks = pytest.mark.xfail(strict=True, reason=PATHFINDING_KNOWN_GAPS[path["id"]])
    return pytest.param(path, id=path["id"], marks=marks)


@pytest.fixture
def pathfinding_branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'pathfinding-branches.sqlite'}")
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


def _verdict_for_actions(client, actions):
    created = client.post("/branches", json={"base_analysis_id": "pathfinding", "name": "pathfinding"})
    assert created.status_code == 200
    branch_id = created.json()["branch_id"]
    change = {
        "op": "modify",
        "resource_type": "iam_role_policy",
        "resource_id": ROLE_ARN,
        "fields": {
            "access_statements": [{"effect": "Allow", "actions": actions, "resources": ["*"]}],
        },
        "expected_change_count": 0,
    }
    response = client.post(f"/branches/{branch_id}/changes", json=change)
    assert response.status_code == 200
    verdict_response = client.get(f"/branches/{branch_id}/verdict")
    assert verdict_response.status_code == 200
    return verdict_response.json()


@pytest.mark.parametrize("path", [_path_param(path) for path in PATHS])
def test_pathfinding_path_is_blocked(pathfinding_branch_db, path):
    result = _verdict_for_actions(TestClient(main.app), path["required"])
    matched_ids = {item["id"] for item in result["escalation_paths"]}
    assert result["verdict"] == "block"
    assert result["introduces_privilege_escalation"] is True
    assert path["id"] in matched_ids


@pytest.mark.parametrize(
    "path,removed_action",
    [
        pytest.param(path, action, id=f"{path['id']}-without-{action.replace(':', '-')}", marks=(
            pytest.mark.xfail(strict=True, reason=PATHFINDING_KNOWN_GAPS[path["id"]])
            if path["id"] in PATHFINDING_KNOWN_GAPS else ()
        ))
        for path in PATHS if len(path["required"]) >= 2
        for action in path["required"]
    ],
)
def test_pathfinding_path_requires_every_action(pathfinding_branch_db, path, removed_action):
    actions = [action for action in path["required"] if action != removed_action]
    result = _verdict_for_actions(TestClient(main.app), actions)
    matched_ids = {item["id"] for item in result["escalation_paths"]}
    assert path["id"] not in matched_ids
