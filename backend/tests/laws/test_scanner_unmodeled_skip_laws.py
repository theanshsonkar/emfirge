"""L66 scanner checks on unmodeled input are skipped: a Checkov check that reads an attribute Emfirge never models (a KMS key policy, a Lambda's tracing config, a bucket's lifecycle rules) fires on the missing value, not on the resource, so its finding is skipped and reported, while a check that only tests attributes Emfirge emits still fires."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from app import scanners
from app.models import AWSInfrastructure, RDSData, RDSInstance
from app.serializer import TF_TO_EMFIRGE, attribute_fields, build_terraform, check_read_rows, unmodeled_attributes
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base
from tests.laws.test_serializer_fidelity_laws import _full_infra


def _stub_checkov(monkeypatch, findings_for):
    """Replace the Checkov CLI: findings_for(tf_type) -> check ids reported on every resource of that type."""
    scanners.clear_scan_cache()

    def run(cmd, **_):
        tf = json.loads(next(Path(cmd[cmd.index("-d") + 1]).glob("*.tf.json")).read_text())
        failed = [
            {"check_id": check_id, "resource": f"{tf_type}.{name}", "check_name": "stub"}
            for tf_type, entries in tf["resource"].items() for name in entries for check_id in findings_for(tf_type)
        ]
        return SimpleNamespace(stdout=json.dumps({"results": {"failed_checks": failed}}), returncode=1)

    monkeypatch.setattr("app.scanners.subprocess.run", run)


def _rds(**fields) -> AWSInfrastructure:
    return AWSInfrastructure(region="us-east-1", rds=RDSData(rds_instances=[RDSInstance(id="db-1", **fields)]))


def _codes(verdict):
    return {reason["code"] for reason in verdict.reasons}


def test_L66a_every_row_reads_attributes_the_serializer_emits_or_records_as_omitted():
    rows = check_read_rows()
    assert len(rows) > 40 and len({row["check_id"] for row in rows}) == len(rows)
    assert {"CKV2_AWS_64", "CKV_AWS_252", "CKV_AWS_50", "CKV2_AWS_12"} <= {row["check_id"] for row in rows}
    for row in rows:
        assert row["tf_type"] in TF_TO_EMFIRGE, row["check_id"]
        assert row["reads"] and row["source"].startswith("checkov 3.3.19 "), row["check_id"]
        assert "severity" not in row, row["check_id"]
        known = set(attribute_fields(row["tf_type"])) | set(unmodeled_attributes(row["tf_type"]))
        assert set(row["reads"]) <= known, row["check_id"]
    # Every unmodeled attribute is recorded on each emitted resource of its type.
    out = build_terraform(_full_infra())
    recorded = {(e["resource_type"], e["id"]): set() for e in out.loss}
    for entry in out.loss:
        if entry.get("kind") == "omitted_field":
            recorded[(entry["resource_type"], entry["id"])].add(entry["field"])
    for tf_type, entries in out.tf["resource"].items():
        for name in entries:
            if tf_type in TF_TO_EMFIRGE and tf_type != "aws_iam_role_policy":
                assert set(unmodeled_attributes(tf_type)) <= recorded[out.names[name]], tf_type


def test_L66b_uncrosswalked_check_on_unmodeled_attribute_is_skipped_and_reported(monkeypatch):
    assert "CKV2_AWS_60" not in scanners._crosswalk_rows()
    infra = _rds(engine="postgres", publicly_accessible=True)
    _stub_checkov(monkeypatch, lambda t: ["CKV2_AWS_60"] if t == "aws_db_instance" else [])
    result = scanners.run_checkov(infra)
    assert result.findings == []
    assert result.skipped == [
        {"check_id": "CKV2_AWS_60", "resource_type": "rds_instance", "id": "db-1", "inputs": ["copy_tags_to_snapshot"]}
    ]
    base = load_synthetic_base("delete")
    branch = base.model_copy(deep=True)
    branch.rds.rds_instances.append(infra.rds.rds_instances[0])
    _stub_checkov(monkeypatch, lambda t: ["CKV2_AWS_60"] if t == "aws_db_instance" else [])
    verdict = combined_verdict(base, branch, run_scanners=True)
    assert "new_scanner_finding" not in _codes(verdict) and verdict.scanner_added == []
    assert any(item["check_id"] == "CKV2_AWS_60" and item["id"] == "db-1" for item in verdict.scanner_skipped)


def test_L66c_uncrosswalked_check_on_emitted_known_attribute_is_kept_and_warns(monkeypatch):
    assert "CKV_AWS_17" not in scanners._crosswalk_rows()
    infra = _rds(engine="postgres", publicly_accessible=True)
    _stub_checkov(monkeypatch, lambda t: ["CKV_AWS_17"] if t == "aws_db_instance" else [])
    result = scanners.run_checkov(infra)
    assert [f.check_id for f in result.findings] == ["CKV_AWS_17"] and result.skipped == []
    base = load_synthetic_base("delete")
    branch = base.model_copy(deep=True)
    branch.rds.rds_instances.append(infra.rds.rds_instances[0])
    _stub_checkov(monkeypatch, lambda t: ["CKV_AWS_17"] if t == "aws_db_instance" else [])
    verdict = combined_verdict(base, branch, run_scanners=True)
    assert [item["check_id"] for item in verdict.scanner_added] == ["CKV_AWS_17"]
    assert "new_scanner_finding" in _codes(verdict) and verdict.verdict == "warn"


UNMODELED_CHECKS = {
    "aws_kms_key": ["CKV2_AWS_64"], "aws_cloudtrail": ["CKV_AWS_35", "CKV_AWS_252", "CKV2_AWS_10"],
    "aws_lambda_function": ["CKV_AWS_50", "CKV_AWS_115", "CKV_AWS_116", "CKV_AWS_272", "CKV_AWS_173"],
    "aws_vpc": ["CKV2_AWS_12"], "aws_s3_bucket": ["CKV_AWS_18", "CKV2_AWS_61", "CKV2_AWS_62", "CKV_AWS_144"],
    "aws_db_instance": ["CKV2_AWS_60"], "aws_instance": ["CKV_AWS_135", "CKV_AWS_8"], "aws_security_group": ["CKV_AWS_23"],
}


def test_L66d_new_resources_on_a_branch_add_no_findings_from_unmodeled_attribute_checks(monkeypatch):
    base = load_synthetic_base("delete")
    branch = _full_infra()  # every emitted type, none of it in the base
    ssh_open = {"CKV_AWS_24"}
    _stub_checkov(
        monkeypatch,
        lambda t: UNMODELED_CHECKS.get(t, []) + (sorted(ssh_open) if t == "aws_security_group" else []),
    )
    verdict = combined_verdict(base, branch, run_scanners=True)
    added = {item["check_id"] for item in verdict.scanner_added}
    assert added == ssh_open  # the check on an emitted attribute still fires
    unmodeled_ids = {c for ids in UNMODELED_CHECKS.values() for c in ids}
    assert not added & unmodeled_ids
    skipped_ids = {item["check_id"] for item in verdict.scanner_skipped}
    assert unmodeled_ids <= skipped_ids
