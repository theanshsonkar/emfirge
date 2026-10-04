"""Tests for the deterministic offline accuracy-loop harness."""
import json

from scripts.accuracy_loop import run_harness, score_prediction


def test_harness_runs_scenarios_and_separate_rates(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    report = run_harness()
    assert len(report["records"]) == 3
    assert {record["scenario"] for record in report["records"]} == {
        "s3_public_bucket", "security_group_ssh_exposure",
        "delete_s3_bucket_with_surviving_iam_role",
    }
    assert "shape_rate" in report and "verdict_rate" in report
    assert report["shape_rate"] == 1.0
    assert report["verdict_rate"] == 1.0
    for record in report["records"]:
        assert {"scenario", "predicted_verdict", "expected_verdict", "predicted_findings",
                "expected_findings", "predicted_shape", "expected_shape",
                "predicted_dependencies", "expected_dependencies",
                "predicted_deletion_impacts", "expected_deletion_impacts",
                "dependency_match", "deletion_match",
                "shape_match", "verdict_checkable", "verdict_correct"} <= set(record)
    with open("accuracy_report.json", encoding="utf-8") as report_file:
        persisted = json.load(report_file)
    assert len(persisted["records"]) == 3


def test_offline_harness_detects_a_perturbed_prediction():
    report = run_harness()
    record = report["records"][0]
    perturbed_shape = json.loads(json.dumps(record["predicted_shape"]))
    perturbed_shape["modified"][0]["id"] = "wrong-bucket"

    rescored = score_prediction(
        perturbed_shape,
        record["expected_shape"],
        record["predicted_findings"],
        record["expected_findings"],
        verdict_checkable=True,
        predicted_verdict=record["predicted_verdict"],
        actual_verdict=record["expected_verdict"],
    )

    assert rescored["shape_match"] is False
    assert rescored["verdict_correct"] is True


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


def test_deletion_scenario_catches_missing_dependency_or_deletion_signal():
    report = run_harness()
    record = next(item for item in report["records"]
                  if item["scenario"] == "delete_s3_bucket_with_surviving_iam_role")
    assert record["shape_match"] is True
    assert record["dependency_match"] is True
    assert record["deletion_match"] is True
    assert record["verdict_correct"] is True

    for signal_field, score_field in (
        ("predicted_dependencies", "dependency_match"),
        ("predicted_deletion_impacts", "deletion_match"),
    ):
        missing_signal = score_prediction(
            record["predicted_shape"], record["expected_shape"],
            record["predicted_findings"], record["expected_findings"],
            verdict_checkable=True,
            predicted_verdict=record["predicted_verdict"],
            actual_verdict=record["expected_verdict"],
            predicted_dependencies=([] if signal_field == "predicted_dependencies"
                                    else record["predicted_dependencies"]),
            actual_dependencies=record["expected_dependencies"],
            predicted_deletion_impacts=([] if signal_field == "predicted_deletion_impacts"
                                        else record["predicted_deletion_impacts"]),
            actual_deletion_impacts=record["expected_deletion_impacts"],
        )
        assert missing_signal[score_field] is False
        assert missing_signal["verdict_correct"] is False
