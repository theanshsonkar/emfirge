"""Tests for the deterministic offline accuracy-loop harness."""
import json

from scripts.accuracy_loop import run_harness, score_prediction


def test_harness_runs_both_scenarios_and_separate_rates(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    report = run_harness()
    assert len(report["records"]) == 2
    assert {record["scenario"] for record in report["records"]} == {
        "s3_public_bucket", "security_group_ssh_exposure"
    }
    assert "shape_rate" in report and "verdict_rate" in report
    assert report["shape_rate"] == 1.0
    assert report["verdict_rate"] == 1.0
    for record in report["records"]:
        assert {"scenario", "predicted_verdict", "predicted_findings", "actual_findings",
                "shape_match", "verdict_checkable", "verdict_correct"} <= set(record)
    with open("accuracy_report.json", encoding="utf-8") as report_file:
        persisted = json.load(report_file)
    assert len(persisted["records"]) == 2


def test_scorer_rejects_missing_finding_and_wrong_shape():
    shape = {"added": [{"type": "s3_bucket", "id": "demo"}], "removed": [], "modified": []}
    wrong_shape = {"added": [], "removed": [], "modified": []}
    expected = [{"source": "native", "rule_id": "EMFIRGE-S3-001",
                 "resource_id": "demo", "status": "confirmed"}]
    result = score_prediction(
        wrong_shape, shape, [], expected, verdict_checkable=True,
        predicted_verdict="pass", actual_verdict="block",
    )
    assert result["shape_match"] is False
    assert result["finding_match"] is False
    assert result["verdict_correct"] is False


def test_unknown_verdict_never_passes():
    result = score_prediction({}, {}, [], [], verdict_checkable=None,
                              predicted_verdict="pass", actual_verdict="pass")
    assert result["verdict_checkable"] is False
    assert result["verdict_correct"] is False
