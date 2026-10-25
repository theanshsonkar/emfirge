"""L63 scanner severities from a published source: a crosswalked Checkov check takes the severity Prowler publishes for the equivalent check, any other scanner finding stays advisory.

Emfirge owns only the "this Checkov check tests the same thing as that Prowler
check" mapping; every severity is read from the vendored Prowler per-check
metadata and is never typed in by hand.
"""
import hashlib
import json
from pathlib import Path

import pytest

from app import scanners
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

DATA = Path(scanners.__file__).resolve().parent / "data"
CHECKS = DATA / "third_party" / "prowler" / "checks"
SEVERITIES = {"critical", "high", "medium", "low"}


def _rows():
    return json.loads((DATA / "scanner_severity_crosswalk.json").read_text(encoding="utf-8"))


def _source():
    return json.loads((CHECKS / "SOURCE.json").read_text(encoding="utf-8"))


def _metadata(prowler_check):
    return json.loads((CHECKS / f"{prowler_check}.metadata.json").read_text(encoding="utf-8"))


def test_L63_crosswalk_is_populated_and_rows_are_unique():
    rows = _rows()
    assert rows
    ids = [row["check_id"] for row in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        assert row["equivalence_note"].strip()
        assert row["source"] == f"prowler {row['prowler_check']} @ {_source()['commit']}"


def test_L63a_every_severity_equals_the_vendored_prowler_severity():
    for row in _rows():
        assert row["severity"] == str(_metadata(row["prowler_check"])["Severity"]).strip().lower(), row["check_id"]


def test_L63b_every_prowler_check_is_vendored_and_listed_with_its_sha256():
    listed = {entry["path"]: entry["sha256"] for entry in _source()["files"]}
    for row in _rows():
        name = f"{row['prowler_check']}.metadata.json"
        assert name in listed, name
        assert hashlib.sha256((CHECKS / name).read_bytes()).hexdigest() == listed[name], name
        assert _metadata(row["prowler_check"])["CheckID"] == row["prowler_check"]
    assert set(listed) == {f.name for f in CHECKS.glob("*.metadata.json")}  # nothing vendored without a record


def test_L63c_license_and_commit_are_recorded():
    source = _source()
    assert source["license"] == "Apache-2.0"
    assert (CHECKS / source["license_file"]).read_text(encoding="utf-8").lstrip().startswith("Apache License")
    assert len(source["commit"]) == 40


def test_L63d_severities_are_in_the_closed_set_and_loaded_by_the_scanner():
    table = scanners.severity_crosswalk()
    assert set(table) == {row["check_id"] for row in _rows()}
    for row in _rows():
        assert row["severity"] in SEVERITIES
        assert table[row["check_id"]]["severity"] == row["severity"]
        assert table[row["check_id"]]["source"] == row["source"]


@pytest.mark.parametrize("severity", ["critical", "high", "low", "unknown", None])
def test_L63e_uncrosswalked_check_never_exceeds_high(severity):
    assert "CKV_AWS_NOT_IN_TABLE" not in scanners.severity_crosswalk()
    out = scanners.govern_scanner_finding({"check_id": "CKV_AWS_NOT_IN_TABLE", "severity": severity})
    assert out["severity"] != "critical"


def test_L63e_crosswalked_check_takes_the_table_severity_whatever_the_scanner_said():
    for row in _rows():
        for reported in ("low", "critical"):
            out = scanners.govern_scanner_finding({"check_id": row["check_id"], "severity": reported})
            assert out["severity"] == row["severity"]


def test_L63f_crosswalked_critical_finding_blocks_through_combined_verdict(monkeypatch):
    critical = [row for row in _rows() if row["severity"] == "critical"]
    assert critical, "expected at least one Prowler-critical equivalence"
    check_id = critical[0]["check_id"]
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", "http://scanner.test:8765")
    for name in ("run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(f"app.verdict.{name}", lambda *_a, **_k: {"available": False, "findings": [], "error": "off"})

    def fake_worker(url, terraform_json, timeout_s):
        if "t3.large" not in terraform_json:
            return []
        name = next(iter(json.loads(terraform_json)["resource"]["aws_instance"]))
        return [scanners.ScannerFinding(
            check_id=check_id, resource=f"aws_instance.{name}", severity="UNKNOWN",
            title="stub", guideline=None,
        )]

    monkeypatch.setattr(scanners, "_scan_via_worker", fake_worker)
    base = load_synthetic_base("delete")
    branch = base.model_copy(deep=True)
    branch.ec2.instances[0].type = "t3.large"
    verdict = combined_verdict(base, branch, run_scanners=True)
    assert verdict.scanner_added[0]["severity"] == "critical"
    assert "introduced_critical_finding" in {r["code"] for r in verdict.reasons}
    assert verdict.verdict == "block"
