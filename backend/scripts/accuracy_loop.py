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
    predicted_dependencies: Iterable[Any] = (), actual_dependencies: Iterable[Any] = (),
    predicted_deletion_impacts: Iterable[Any] = (), actual_deletion_impacts: Iterable[Any] = (),
) -> dict[str, Any]:
    """Score shape, findings, modeled deletion signals, and verdict independently."""
    shape_match = all(_shape_keys(predicted_shape, field) == _shape_keys(actual_shape, field)
                      for field in ("added", "removed", "modified"))
    finding_match = _finding_identities(predicted_findings) == _finding_identities(actual_findings)
    dependency_match = sorted(predicted_dependencies, key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        actual_dependencies, key=lambda item: json.dumps(item, sort_keys=True))
    deletion_match = sorted(predicted_deletion_impacts, key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        actual_deletion_impacts, key=lambda item: json.dumps(item, sort_keys=True))
    checkable = verdict_checkable is True
    verdict_correct = bool(checkable and predicted_verdict is not None
                           and actual_verdict is not None
                           and predicted_verdict == actual_verdict
                           and finding_match and dependency_match and deletion_match)
    return {
        "shape_match": shape_match,
        "finding_match": finding_match,
        "dependency_match": dependency_match,
        "deletion_match": deletion_match,
        "verdict_checkable": checkable,
        "verdict_correct": verdict_correct,
    }


def _scenario_prediction(name: str, base: Any, branch: Any, prediction: Any,
                         expected: dict[str, Any]) -> dict[str, Any]:
    """Compare engine output to a separately specified synthetic observation."""
    predicted_findings = [_normal_finding(item) for item in prediction.native_added]
    for scanner_name, status in prediction.scanner_status.items():
        if status != "ok":
            predicted_findings.append({"source": "scanner", "scanner": scanner_name,
                                    "status": "unavailable", "rule_id": "", "resource_id": "",
                                    "severity": "unknown"})
    predicted_shape = _shape(base, branch)
    scores = score_prediction(
        predicted_shape, expected["shape"], predicted_findings, expected["findings"],
        verdict_checkable=True, predicted_verdict=prediction.verdict,
        actual_verdict=expected["verdict"],
        predicted_dependencies=prediction.lost_dependencies,
        actual_dependencies=expected.get("lost_dependencies", []),
        predicted_deletion_impacts=prediction.deletion_impacts,
        actual_deletion_impacts=expected.get("deletion_impacts", []),
    )
    return {"scenario": name, "predicted_verdict": prediction.verdict,
            "expected_verdict": expected["verdict"],
            "predicted_shape": predicted_shape,
            "expected_shape": expected["shape"],
            "predicted_findings": predicted_findings,
            "expected_findings": expected["findings"],
            "predicted_dependencies": prediction.lost_dependencies,
            "expected_dependencies": expected.get("lost_dependencies", []),
            "predicted_deletion_impacts": prediction.deletion_impacts,
            "expected_deletion_impacts": expected.get("deletion_impacts", []), **scores}


def run_harness() -> dict[str, Any]:
    """Run the fixture scenarios with isolated SQLite persistence."""
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
                # Expected observations are explicit scenario facts from the
                # synthetic fixture. The engine's Change/rebuild/graph/verdict
                # path never produces this oracle.
                scenarios = [
                    ("s3_public_bucket", Change(op="modify", resource_type="s3_bucket",
                        resource_id=bucket, fields={"is_public": True}), {
                            "shape": {"added": [], "removed": [],
                                      "modified": [{"type": "s3_bucket", "id": bucket}]},
                            "findings": [{"source": "native", "rule_id": "EMFIRGE-S3-001",
                                          "resource_id": bucket, "severity": "unknown",
                                          "status": "confirmed"}],
                            "verdict": "warn",
                        }),
                    ("security_group_ssh_exposure", Change(op="modify", resource_type="security_group",
                        resource_id="sg-demo-public", fields={"rules": [{"protocol": "tcp",
                        "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]}), {
                            "shape": {"added": [], "removed": [],
                                      "modified": [{"type": "security_group", "id": "sg-demo-public"}]},
                            "findings": [{"source": "native", "rule_id": "EMFIRGE-EC2-002",
                                          "resource_id": "sg-demo-public", "severity": "unknown",
                                          "status": "confirmed"}],
                            "verdict": "block",
                        }),
                    ("delete_s3_bucket_with_surviving_iam_role", Change(
                        op="delete", resource_type="s3_bucket", resource_id=bucket,
                    ), {
                        "shape": {"added": [],
                                  "removed": [{"type": "s3_bucket", "id": bucket}],
                                  "modified": []},
                        "findings": [
                            {"source": "scanner", "scanner": scanner_name,
                             "status": "unavailable", "rule_id": "", "resource_id": "",
                             "severity": "unknown"}
                            for scanner_name in ("checkov", "trivy", "cloudsplaining")
                        ],
                        "lost_dependencies": [{
                            "from": "iam-role-EmfirgeDemoAppRole",
                            "to": bucket,
                            "relationship": "can_access",
                        }],
                        "deletion_impacts": [{
                            "removed_resource": {"id": bucket, "resource_type": "s3_bucket"},
                            "surviving_related_resources": [],
                            "possible_consequence": (
                                "This concrete resource was removed from the modeled branch. "
                                "The snapshot cannot determine whether removal disrupts service operation or affects stored data."
                            ),
                        }],
                        "verdict": "block",
                    }),
                ]
                records = []
                for name, change, expected in scenarios:
                    branch_id = branches.create_branch(base, name, base_analysis_id="accuracy-demo")
                    branch_ids.append(branch_id)
                    branches.apply_change_to_branch(branch_id, change)
                    predicted_state = branches.rebuild_branch_infra(branch_id)
                    prediction = combined_verdict(base, predicted_state, run_scanners=False)
                    record = _scenario_prediction(name, base, predicted_state, prediction, expected)
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
