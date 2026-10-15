import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.mutations import Change, apply_change
from tests.incidents.base import build_incident_base
from tests.incidents.test_incidents import incident_branch_db


SCENARIOS = json.loads((Path(__file__).with_name("scenarios.json")).read_text())
INPUT_SCENARIOS = [scenario for scenario in SCENARIOS if "http_status" not in scenario["expect"]]


@pytest.mark.parametrize("scenario", INPUT_SCENARIOS, ids=lambda scenario: scenario["id"])
def test_scenario_changes_are_accepted_over_http(incident_branch_db, scenario):
    client = TestClient(main.app)
    created = client.post(
        "/branches", json={"base_analysis_id": "incident", "name": f"inputs-{scenario['id']}"}
    )
    assert created.status_code == 200
    branch_id = created.json()["branch_id"]

    for count, change in enumerate(scenario["changes"]):
        response = client.post(
            f"/branches/{branch_id}/changes",
            json={**change, "expected_change_count": count},
        )
        assert response.status_code == 200, response.text


def test_iam_effect_casing_produces_identical_branch_state():
    base = build_incident_base()
    fields = {
        "access_statements": [
            {"effect": "allow", "actions": ["iam:CreatePolicyVersion"], "resources": ["*"]}
        ]
    }
    lowercase = apply_change(
        base,
        Change(
            op="modify",
            resource_type="iam_role_policy",
            resource_id="arn:aws:iam::000000000000:role/EmfirgeDemoAppRole",
            fields=fields,
        ),
    )
    canonical = apply_change(
        base,
        Change(
            op="modify",
            resource_type="iam_role_policy",
            resource_id="arn:aws:iam::000000000000:role/EmfirgeDemoAppRole",
            fields={**fields, "access_statements": [{**fields["access_statements"][0], "effect": "Allow"}]},
        ),
    )
    assert canonical.model_dump() == lowercase.model_dump()
