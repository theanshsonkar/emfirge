import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, verdict
from app.demo_seed import build_demo_infrastructure
from app.egraph import build_graph
from app.mutations import Change
from app.verdict import combined_verdict


@pytest.fixture
def demo_branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'demo-branches.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    unavailable = lambda *_args, **_kwargs: {"available": False, "findings": []}
    monkeypatch.setattr(verdict, "run_checkov", unavailable)
    monkeypatch.setattr(verdict, "run_trivy", unavailable)
    monkeypatch.setattr(verdict, "run_cloudsplaining", unavailable)
    yield
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def dangerous_change():
    return Change(
        op="modify", resource_type="security_group", resource_id="sg-demo-public",
        fields={"rules": [{"protocol": "tcp", "from_port": 22,
                            "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]},
    )


def safe_change():
    return Change(
        op="modify", resource_type="s3_bucket",
        resource_id="emfirge-demo-artifacts-000000000000",
        fields={"encrypted": True},
    )


def delete_artifacts_change():
    return Change(
        op="delete", resource_type="s3_bucket",
        resource_id="emfirge-demo-artifacts-000000000000",
    )


def test_demo_builder_graph_and_snapshot_are_deterministic():
    first = build_demo_infrastructure()
    second = build_demo_infrastructure()
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    graph_types = {node.resource_type for node in build_graph(first).nodes}
    assert {"vpc", "vpc_subnet", "ec2_instance", "security_group",
            "rds_instance", "s3_bucket", "iam_role"} <= graph_types
    with open("app/demo_account.json", encoding="utf-8") as snapshot_file:
        snapshot = json.load(snapshot_file)
    assert snapshot == first.model_dump(mode="json")


def test_dangerous_change_is_reachable_and_safe_change_passes(demo_branch_db):
    base = build_demo_infrastructure()
    dangerous = branches.create_branch(base, "dangerous-ssh", base_analysis_id="demo")
    branches.apply_change_to_branch(dangerous, dangerous_change())
    dangerous_result = combined_verdict(base, branches.rebuild_branch_infra(dangerous))
    assert dangerous_result.verdict == "block"
    assert any(
        finding.get("rule_id") == "EMFIRGE-EC2-002"
        for finding in dangerous_result.native_added
    )
    assert "i-demo-web-001" in dangerous_result.newly_internet_reachable

    safe = branches.create_branch(base, "safe-encryption", base_analysis_id="demo")
    branches.apply_change_to_branch(safe, safe_change())
    safe_result = combined_verdict(base, branches.rebuild_branch_infra(safe))
    assert safe_result.verdict == "pass"

    first = dangerous_result.model_dump()
    second = combined_verdict(base, branches.rebuild_branch_infra(dangerous)).model_dump()
    assert first == second


def test_redundant_demo_change_is_explicitly_unchanged(demo_branch_db):
    base = build_demo_infrastructure()
    branch_id = branches.create_branch(base, "already-versioned", base_analysis_id="demo")
    unchanged_value = Change(
        op="modify", resource_type="s3_bucket",
        resource_id="emfirge-demo-artifacts-000000000000",
        fields={"versioning_enabled": True},
    )
    branches.apply_change_to_branch(branch_id, unchanged_value)

    diff = branches.get_branch_diff(branch_id)
    result = combined_verdict(base, branches.rebuild_branch_infra(branch_id), run_scanners=False)

    assert diff.modeled_state_unchanged is True
    assert result.verdict == "pass"
    assert result.modeled_state_unchanged is True


def test_compare_branches_ranks_safe_first_and_rollback_is_deterministic(demo_branch_db):
    base = build_demo_infrastructure()
    dangerous = branches.create_branch(base, "dangerous-ssh", base_analysis_id="demo")
    safe = branches.create_branch(base, "safe-encryption", base_analysis_id="demo")
    branches.apply_change_to_branch(dangerous, dangerous_change())
    branches.apply_change_to_branch(safe, safe_change())
    rolled_back = branches.rollback_last(safe)
    assert rolled_back.changes == []
    branches.apply_change_to_branch(safe, safe_change())

    result = branches.compare_branches([dangerous, safe])
    assert result.ranking[0] == safe
    assert result.ranking[1] == dangerous
    assert result.model_dump() == branches.compare_branches([dangerous, safe]).model_dump()


def test_agent_sees_lost_capability_before_and_after_rollback(demo_branch_db):
    base = build_demo_infrastructure()
    branch_id = branches.create_branch(base, "remove-artifacts", base_analysis_id="demo")
    branches.apply_change_to_branch(branch_id, delete_artifacts_change())

    diff = branches.get_branch_diff(branch_id)
    assert diff.lost_dependencies == [{
        "from": "iam-role-EmfirgeDemoAppRole",
        "to": "emfirge-demo-artifacts-000000000000",
        "relationship": "can_access",
    }]
    result = combined_verdict(base, branches.rebuild_branch_infra(branch_id), run_scanners=False)
    assert result.verdict == "warn"
    assert result.lost_dependencies == diff.lost_dependencies
    assert result.scanner_status == {
        "checkov": "disabled", "trivy": "disabled", "cloudsplaining": "disabled",
    }
    assert result.coverage_warnings

    branches.rollback_last(branch_id)
    restored = combined_verdict(base, branches.rebuild_branch_infra(branch_id), run_scanners=False)
    assert restored.verdict == "pass"
    assert restored.lost_dependencies == []


def test_agent_compare_does_not_rank_dependency_loss_above_safe_fix(demo_branch_db):
    base = build_demo_infrastructure()
    delete_id = branches.create_branch(base, "remove-artifacts", base_analysis_id="demo")
    safe_id = branches.create_branch(base, "encrypt-artifacts", base_analysis_id="demo")
    branches.apply_change_to_branch(delete_id, delete_artifacts_change())
    branches.apply_change_to_branch(safe_id, safe_change())

    comparison = branches.compare_branches([delete_id, safe_id])
    assert comparison.ranking == [safe_id, delete_id]
    assert comparison.branches[0].lost_dependencies == 1
    assert comparison.branches[1].lost_dependencies == 0
