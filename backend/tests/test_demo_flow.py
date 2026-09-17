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
