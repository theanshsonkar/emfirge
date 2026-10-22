"""Accuracy loop in Moto: the branch prediction must match the re-scanned account.

Shape accuracy and verdict consistency only; Moto cannot show whether a verdict is
correct (see scripts/moto_accuracy_loop.py and ACCURACY-LOOP-PLAN.md).
"""
import pytest

from scripts import moto_accuracy_loop as loop

SCENARIOS = {item["id"]: item for item in loop._scenarios()}


@pytest.fixture(autouse=True)
def fake_aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": loop.REGION,
                       "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
def test_prediction_matches_rescanned_account(scenario_id):
    result = loop.run_scenario(SCENARIOS[scenario_id])
    assert result["shape_match"], result["shape_problems"]
    assert result["verdict_consistent"], (result["predicted_verdict"], result["actual_verdict"])


def test_open_ssh_and_admin_policy_block_after_real_apply():
    assert loop.run_scenario(SCENARIOS[1])["actual_verdict"]["verdict"] == "block"
    assert "privilege_escalation" in loop.run_scenario(SCENARIOS[3])["actual_verdict"]["reasons"]


@pytest.mark.xfail(strict=True, reason="known_gap: a bucket made public by a bucket policy is not detected; "
                   "only ACL AllUsers grants set is_public")
def test_known_gap_public_bucket_policy_does_not_pass():
    assert loop.run_scenario(SCENARIOS[4])["actual_verdict"]["verdict"] != "pass"
