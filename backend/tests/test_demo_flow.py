import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, verdict
from app import main
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
    recorded = branches.apply_change_to_branch(branch_id, unchanged_value)
    assert recorded.last_change_modeled_state_unchanged is True

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


def test_demo_resource_deletion_warns_without_iam_dependency_and_rollback_clears_it(demo_branch_db):
    base = build_demo_infrastructure()
    rds = base.rds.rds_instances[0]
    rds.publicly_accessible = True
    rds.encrypted = False
    base.rds.publicly_accessible = [rds.id]
    base.rds.unencrypted_instances = [rds.id]

    deletion = branches.create_branch(base, "remove-demo-database", base_analysis_id="demo")
    branches.apply_change_to_branch(deletion, Change(
        op="delete", resource_type="rds_instance", resource_id=rds.id,
    ))
    diff = branches.get_branch_diff(deletion)
    result = combined_verdict(base, branches.rebuild_branch_infra(deletion), run_scanners=False)

    assert diff.lost_dependencies == []
    assert any(item["rule_id"] == "EMFIRGE-RDS-002" for item in diff.removed_findings)
    assert len(diff.deletion_impacts) == 1
    impact = diff.deletion_impacts[0]
    assert impact["removed_resource"] == {"id": rds.id, "resource_type": "rds_instance"}
    assert {item["id"] for item in impact["surviving_related_resources"]} >= {
        "sg-demo-db", "subnet-demo-private",
    }
    assert "cannot determine whether removal disrupts" in impact["possible_consequence"]
    assert result.verdict == "warn"
    assert result.deletion_impacts == diff.deletion_impacts
    assert "modeled_resources_removed=1" in result.summary

    safe = branches.create_branch(base, "leave-demo-database", base_analysis_id="demo")
    branches.apply_change_to_branch(safe, safe_change())
    comparison = branches.compare_branches([deletion, safe])
    deletion_summary = next(item for item in comparison.branches if item.branch_id == deletion)
    assert deletion_summary.deletion_impacts == 1
    assert comparison.ranking == [safe, deletion]

    branches.rollback_last(deletion)
    restored_diff = branches.get_branch_diff(deletion)
    restored_verdict = combined_verdict(
        base, branches.rebuild_branch_infra(deletion), run_scanners=False,
    )
    assert restored_diff.deletion_impacts == []
    assert restored_verdict.verdict == "pass"
    assert restored_verdict.deletion_impacts == []


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


def test_demo_agent_http_branch_sequence(demo_branch_db, monkeypatch):
    main._branch_request_log.clear()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis",
                        lambda _analysis_id: build_demo_infrastructure())
    monkeypatch.setenv("EMFIRGE_RUN_SCANNERS", "0")
    client = TestClient(main.app)

    created = client.post("/branches", json={"base_analysis_id": "demo", "name": "restrict-web"})
    assert created.status_code == 200
    branch_id = created.json()["branch_id"]
    changed = client.post(f"/branches/{branch_id}/changes", json={
        **dangerous_change().model_dump(), "expected_change_count": 0,
    })
    assert changed.status_code == 200
    assert changed.json()["num_changes"] == 1
    assert changed.json()["modeled_state_unchanged"] is False

    diff = client.get(f"/branches/{branch_id}/diff")
    verdict_response = client.get(f"/branches/{branch_id}/verdict")
    assert diff.status_code == verdict_response.status_code == 200
    assert "i-demo-web-001" in diff.json()["newly_internet_reachable"]
    assert verdict_response.json()["verdict"] == "block"
    assert verdict_response.json()["coverage_warnings"]

    stale = client.post(f"/branches/{branch_id}/changes", json={
        **safe_change().model_dump(), "expected_change_count": 0,
    })
    assert stale.status_code == 409
    safe_created = client.post("/branches", json={
        "base_analysis_id": "demo", "name": "encrypt-artifacts",
    })
    safe_id = safe_created.json()["branch_id"]
    assert client.post(f"/branches/{safe_id}/changes", json=safe_change().model_dump()).status_code == 200
    comparison = client.post("/branches/compare", json={"branch_ids": [branch_id, safe_id]})
    assert comparison.status_code == 200
    assert comparison.json()["ranking"][0] == safe_id

    rolled_back = client.post(f"/branches/{branch_id}/rollback", json={"expected_change_count": 1})
    assert rolled_back.status_code == 200
    assert rolled_back.json()["num_changes"] == 0
    assert client.get(f"/branches/{branch_id}/diff").json()["modeled_state_unchanged"] is True
