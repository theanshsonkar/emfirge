"""Deterministic offline accuracy-loop mechanics check for the demo fixture."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, scanners, verdict
from app.demo_seed import build_demo_infrastructure
from app.mutations import Change
from app.verdict import combined_verdict

REPORT_PATH = Path(__file__).resolve().parents[1] / "accuracy_report.json"


def _unavailable(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {"available": False, "findings": [], "error": "offline harness"}


def _finding_identity(finding: Any) -> tuple[str, str, str]:
    if isinstance(finding, dict):
        get = finding.get
    else:
        get = lambda key, default=None: getattr(finding, key, default)
    return (str(get("rule_id", get("check_id", "")) or ""),
            str(get("resource_id", get("resource", "")) or ""),
            str(get("source", "native") or "native"))


def _normal_finding(finding: Any, source: str = "native") -> dict[str, Any]:
    if hasattr(finding, "model_dump"):
        finding = finding.model_dump(mode="json")
    finding = dict(finding)
    return {
        "source": str(finding.get("source", source)),
        "rule_id": str(finding.get("rule_id", finding.get("check_id", "")) or ""),
        "resource_id": str(finding.get("resource_id", finding.get("resource", "")) or ""),
        "severity": str(finding.get("severity", "unknown") or "unknown"),
        "status": str(finding.get("status", "confirmed") or "confirmed"),
        **({"scanner": str(finding["scanner"])} if "scanner" in finding else {}),
    }


def _finding_identities(findings: Iterable[Any]) -> set[tuple[str, str, str]]:
    return {
        _finding_identity(item)
        for item in findings
        if str(item.get("status", "confirmed") if isinstance(item, dict) else "confirmed")
        not in {"unavailable", "unknown"}
    }


def _resource_inventory(infra: Any) -> dict[tuple[str, str], dict[str, str]]:
    collections = (
        ("ec2_instance", infra.ec2.instances),
        ("security_group", infra.ec2.security_groups),
        ("rds_instance", infra.rds.rds_instances),
        ("s3_bucket", infra.s3.buckets),
        ("lambda_function", infra.lambda_data.functions),
    )
    result: dict[tuple[str, str], dict[str, str]] = {}
    for resource_type, resources in collections:
        for resource in resources:
            identity = resource.name if resource_type in {"s3_bucket", "lambda_function"} else resource.id
            result[(resource_type, str(identity))] = {"type": resource_type, "id": str(identity)}
    return result


def _shape(base: Any, branch: Any) -> dict[str, list[dict[str, str]]]:
    base_ids, branch_ids = _resource_inventory(base), _resource_inventory(branch)
    base_models = {(item_type, item_id): resource for item_type, resources in (
        ("ec2_instance", base.ec2.instances), ("security_group", base.ec2.security_groups),
        ("rds_instance", base.rds.rds_instances), ("s3_bucket", base.s3.buckets),
        ("lambda_function", base.lambda_data.functions),
    ) for resource in resources for item_id in [resource.name if item_type in {"s3_bucket", "lambda_function"} else resource.id]
                   for item_type, item_id in [(item_type, str(item_id))]}
    branch_models = {(item_type, item_id): resource for item_type, resources in (
        ("ec2_instance", branch.ec2.instances), ("security_group", branch.ec2.security_groups),
        ("rds_instance", branch.rds.rds_instances), ("s3_bucket", branch.s3.buckets),
        ("lambda_function", branch.lambda_data.functions),
    ) for resource in resources for item_id in [resource.name if item_type in {"s3_bucket", "lambda_function"} else resource.id]
                     for item_type, item_id in [(item_type, str(item_id))]}
    return {
        "added": [branch_ids[key] for key in sorted(set(branch_ids) - set(base_ids))],
        "removed": [base_ids[key] for key in sorted(set(base_ids) - set(branch_ids))],
        "modified": [branch_ids[key] for key in sorted(set(base_ids) & set(branch_ids))
                     if base_models[key].model_dump(mode="json") != branch_models[key].model_dump(mode="json")],
    }


def _shape_keys(shape: Any, field: str) -> set[tuple[str, str]]:
    values = shape.get(field, []) if isinstance(shape, dict) else []
    return {(str(item.get("type", "")), str(item.get("id", item.get("resource_id", ""))))
            for item in values}


def score_prediction(
    predicted_shape: dict[str, Any], actual_shape: dict[str, Any],
    predicted_findings: Iterable[Any], actual_findings: Iterable[Any],
    verdict_checkable: bool | None = True, *,
    predicted_verdict: str | None = None, actual_verdict: str | None = None,
) -> dict[str, Any]:
    """Score resource shape, finding identities, and verdict independently."""
    shape_match = all(_shape_keys(predicted_shape, field) == _shape_keys(actual_shape, field)
                      for field in ("added", "removed", "modified"))
    finding_match = _finding_identities(predicted_findings) == _finding_identities(actual_findings)
    checkable = verdict_checkable is True
    verdict_correct = bool(checkable and predicted_verdict is not None
                           and actual_verdict is not None
                           and predicted_verdict == actual_verdict
                           and finding_match)
    return {
        "shape_match": shape_match,
        "finding_match": finding_match,
        "verdict_checkable": checkable,
        "verdict_correct": verdict_correct,
    }


def _scenario_prediction(name: str, base: Any, branch: Any, actual: Any, target: str,
                         resource_type: str, expected_rule: str) -> dict[str, Any]:
    predicted_findings = [{"source": "native", "rule_id": expected_rule,
                           "resource_id": target, "severity": "unknown", "status": "confirmed"}]
    actual_findings = [_normal_finding(item) for item in actual.native_added]
    for scanner_name, status in actual.scanner_status.items():
        if status != "ok":
            actual_findings.append({"source": "scanner", "scanner": scanner_name,
                                    "status": "unavailable", "rule_id": "", "resource_id": "",
                                    "severity": "unknown"})
    predicted_verdict = "warn" if name == "s3_public_bucket" else "block"
    predicted_shape = {"added": [], "removed": [],
                       "modified": [{"type": resource_type, "id": target}]}
    scores = score_prediction(predicted_shape, _shape(base, branch), predicted_findings,
                              actual_findings, verdict_checkable=True,
                              predicted_verdict=predicted_verdict, actual_verdict=actual.verdict)
    return {"scenario": name, "predicted_verdict": predicted_verdict,
            "predicted_findings": predicted_findings,
            "actual_findings": actual_findings, **scores}


def run_harness() -> dict[str, Any]:
    """Run both fixture scenarios with isolated SQLite persistence."""
    engine = None
    branch_ids: list[str] = []
    with tempfile.TemporaryDirectory(prefix="emfirge-accuracy-") as temp_dir:
        try:
            engine = create_engine(f"sqlite:///{Path(temp_dir) / 'branches.sqlite'}")
            database.Base.metadata.create_all(engine)
            factory = sessionmaker(bind=engine)
            old_db, old_branches = database.SessionLocal, branches.SessionLocal
            old_scanners = (scanners.run_checkov, scanners.run_trivy, scanners.run_cloudsplaining)
            old_verdict = (verdict.run_checkov, verdict.run_trivy, verdict.run_cloudsplaining)
            database.SessionLocal = factory
            branches.SessionLocal = factory
            scanners.run_checkov = scanners.run_trivy = scanners.run_cloudsplaining = _unavailable
            verdict.run_checkov = verdict.run_trivy = verdict.run_cloudsplaining = _unavailable
            try:
                base = build_demo_infrastructure()
                bucket = "emfirge-demo-artifacts-000000000000"
                scenarios = [
                    ("s3_public_bucket", Change(op="modify", resource_type="s3_bucket",
                        resource_id=bucket, fields={"is_public": True}), bucket, "EMFIRGE-S3-001"),
                    ("security_group_ssh_exposure", Change(op="modify", resource_type="security_group",
                        resource_id="sg-demo-public", fields={"rules": [{"protocol": "tcp",
                        "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]}),
                     "sg-demo-public", "EMFIRGE-EC2-002"),
                ]
                records = []
                for name, change, target, rule_id in scenarios:
                    branch_id = branches.create_branch(base, name, base_analysis_id="accuracy-demo")
                    branch_ids.append(branch_id)
                    branches.apply_change_to_branch(branch_id, change)
                    reality = branches.rebuild_branch_infra(branch_id)
                    # S3's public_buckets is a derived collector summary; derive it from
                    # the rebuilt authoritative bucket before native rules evaluate reality.
                    reality.s3.public_buckets = [b.name for b in reality.s3.buckets if b.is_public]
                    actual = combined_verdict(base, reality, run_scanners=False)
                    record = _scenario_prediction(name, base, reality, actual, target,
                                                   change.resource_type, rule_id)
                    records.append(record)
                report = {"mode": "offline demo mechanics check (not true AWS accuracy)",
                          "records": records,
                          "shape_rate": sum(r["shape_match"] for r in records) / len(records),
                          "verdict_rate": sum(r["verdict_correct"] for r in records) / len(records)}
                REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return report
            finally:
                for branch_id in branch_ids:
                    try:
                        branches.discard_branch(branch_id)
                    except Exception:
                        pass
                database.SessionLocal, branches.SessionLocal = old_db, old_branches
                (scanners.run_checkov, scanners.run_trivy, scanners.run_cloudsplaining) = old_scanners
                (verdict.run_checkov, verdict.run_trivy, verdict.run_cloudsplaining) = old_verdict
        finally:
            if engine is not None:
                engine.dispose()


def main() -> None:
    report = run_harness()
    print("Offline demo mechanics check — not true AWS accuracy")
    print(f"Scenarios: {len(report['records'])}; shape rate: {report['shape_rate']:.0%}; "
          f"verdict rate: {report['verdict_rate']:.0%}")


if __name__ == "__main__":
    main()
