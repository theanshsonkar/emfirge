"""Deterministic, offline walkthrough of the demo branch service layer.

Run from ``aws-risk-agent`` with ``python -m scripts.demo_branch_flow``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, verdict
from app.demo_seed import build_demo_infrastructure
from app.mutations import Change


def _unavailable(*_args, **_kwargs):
    return {"available": False, "findings": []}


def main() -> None:
    # Keep the service-layer persistence isolated from the user's configured DB.
    with tempfile.TemporaryDirectory(prefix="emfirge-demo-") as temp_dir:
        engine = create_engine(f"sqlite:///{Path(temp_dir) / 'branches.sqlite'}")
        database.Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        original_database_session_local = database.SessionLocal
        original_branches_session_local = branches.SessionLocal
        original_run_checkov = verdict.run_checkov
        original_run_trivy = verdict.run_trivy
        original_run_cloudsplaining = verdict.run_cloudsplaining
        try:
            database.SessionLocal = factory
            branches.SessionLocal = factory
            verdict.run_checkov = _unavailable
            verdict.run_trivy = _unavailable
            verdict.run_cloudsplaining = _unavailable

            base = build_demo_infrastructure()
            dangerous = branches.create_branch(base, "dangerous-ssh", base_analysis_id="demo-base")
            dangerous_change = Change(
                op="modify", resource_type="security_group", resource_id="sg-demo-public",
                fields={"rules": [{"protocol": "tcp", "from_port": 22,
                                    "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]},
            )
            branches.apply_change_to_branch(dangerous, dangerous_change)
            dangerous_infra = branches.rebuild_branch_infra(dangerous)
            dangerous_verdict = verdict.combined_verdict(base, dangerous_infra)
            print("Emfirge demo branch walkthrough (offline)")
            print(f"Dangerous branch verdict: {dangerous_verdict.verdict}")
            print(f"  newly_internet_reachable: {dangerous_verdict.newly_internet_reachable}")
            print(f"  added findings: {len(dangerous_verdict.native_added) + len(dangerous_verdict.scanner_added)}")
            print(f"  cost delta: ${dangerous_verdict.cost_delta_monthly_usd:.2f}/month")
            print(f"  limits introduced: {dangerous_verdict.limits_introduced}")

            rolled_back = branches.rollback_last(dangerous)
            print(f"Rollback: {len(rolled_back.changes)} changes remain on dangerous branch")
            branches.apply_change_to_branch(dangerous, dangerous_change)

            safe = branches.create_branch(base, "safe-encryption", base_analysis_id="demo-base")
            branches.apply_change_to_branch(safe, Change(
                op="modify", resource_type="s3_bucket",
                resource_id="emfirge-demo-artifacts-000000000000",
                fields={"encrypted": True},
            ))
            safe_verdict = verdict.combined_verdict(base, branches.rebuild_branch_infra(safe))
            print(f"Safe branch verdict: {safe_verdict.verdict}")
            comparison = branches.compare_branches([dangerous, safe])
            ranking_names = [next(summary.name for summary in comparison.branches
                                  if summary.branch_id == branch_id)
                             for branch_id in comparison.ranking]
            print(f"Safest-first ranking: {ranking_names}")
            print(f"  branch names: {[summary.name for summary in comparison.branches]}")
            assert dangerous_verdict.verdict in {"warn", "block"}
            assert "i-demo-web-001" in dangerous_verdict.newly_internet_reachable
            assert safe_verdict.verdict == "pass"
            assert comparison.ranking[0] == safe
        finally:
            database.SessionLocal = original_database_session_local
            branches.SessionLocal = original_branches_session_local
            verdict.run_checkov = original_run_checkov
            verdict.run_trivy = original_run_trivy
            verdict.run_cloudsplaining = original_run_cloudsplaining
            engine.dispose()


if __name__ == "__main__":
    main()
