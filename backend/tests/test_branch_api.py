"""Hermetic HTTP tests for the simulation branch API."""
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.models import AWSInfrastructure, EC2Data, EC2Instance, S3Bucket, S3Data
from app.verdict import CombinedVerdict


client = TestClient(app)


def branch(branch_id="b-1", name="fix", status="open", base_analysis_id="a-1", changes=None, base=None):
    return SimpleNamespace(
        branch_id=branch_id,
        name=name,
        status=status,
        base_analysis_id=base_analysis_id,
        changes=changes or [],
        base=base or AWSInfrastructure.model_validate({"region": "us-east-1"}),
    )


def reset_limiter():
    from app import main
    main._branch_request_log.clear()


def test_create_branch_uses_analysis_loader_and_returns_id():
    reset_limiter()
    with patch("app.main.get_infrastructure_for_analysis", return_value=branch().base) as loader, \
         patch("app.main.branches.create_branch", return_value="b-123") as create:
        response = client.post("/branches", json={"base_analysis_id": "a-1", "name": "harden"})
    assert response.status_code == 200
    assert response.json() == {"branch_id": "b-123"}
    loader.assert_called_once_with("a-1")
    create.assert_called_once_with(loader.return_value, "harden", "a-1")


def test_add_change_and_diff():
    reset_limiter()
    changed = branch(changes=[{"op": "modify", "resource_type": "s3_bucket"}])
    diff = {"added_nodes": [], "removed_nodes": [], "modified_nodes": [], "added_edges": [],
            "removed_edges": [], "added_findings": [], "removed_findings": [], "score_before": 1,
            "score_after": 2, "score_delta": 1, "newly_internet_reachable": [],
            "no_longer_internet_reachable": []}
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=AWSInfrastructure(
             region="us-east-1", s3=S3Data(buckets=[S3Bucket(name="bucket")])
         )), \
         patch("app.main.branches.apply_change_to_branch", return_value=changed), \
         patch("app.main.branches.get_branch_diff", return_value=diff):
        response = client.post("/branches/b-1/changes", json={
            "op": "modify", "resource_type": "s3_bucket", "resource_id": "bucket", "fields": {}
        })
        diff_response = client.get("/branches/b-1/diff")
    assert response.status_code == 200
    assert response.json()["branch_id"] == "b-1"
    assert response.json()["num_changes"] == 1
    assert diff_response.status_code == 200
    assert diff_response.json()["score_delta"] == 1


def test_invalid_change_returns_422_without_persistence():
    reset_limiter()
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=branch().base), \
         patch("app.main.branches.apply_change_to_branch") as persist:
        response = client.post("/branches/b-1/changes", json={
            "op": "replace", "resource_type": "unsupported", "resource_id": "x", "fields": {}
        })
    assert response.status_code == 422
    assert "Unsupported operation" in response.json()["detail"]
    persist.assert_not_called()


def test_stacked_add_then_modify_validates_against_rebuilt_state():
    reset_limiter()
    base = AWSInfrastructure(region="us-east-1")
    rebuilt_with_added_ec2 = AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(instances=[EC2Instance(id="i-new", type="t3.micro", state="running")]),
    )
    first = branch(changes=[{"op": "add", "resource_type": "ec2_instance", "resource_id": "i-new", "fields": {}}])
    second = branch(changes=[
        {"op": "add", "resource_type": "ec2_instance", "resource_id": "i-new", "fields": {}},
        {"op": "modify", "resource_type": "ec2_instance", "resource_id": "i-new", "fields": {"imdsv2_required": True}},
    ])
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", side_effect=[base, rebuilt_with_added_ec2]) as rebuild, \
         patch("app.main.branches.apply_change_to_branch", side_effect=[first, second]):
        add_response = client.post("/branches/b-1/changes", json={
            "op": "add", "resource_type": "ec2_instance", "resource_id": "i-new",
            "fields": {"type": "t3.micro", "state": "running"},
        })
        modify_response = client.post("/branches/b-1/changes", json={
            "op": "modify", "resource_type": "ec2_instance", "resource_id": "i-new",
            "fields": {"imdsv2_required": True},
        })

    assert add_response.status_code == 200
    assert modify_response.status_code == 200
    assert modify_response.json()["num_changes"] == 2
    assert rebuild.call_count == 2
    assert rebuild.call_args_list[1].args == ("b-1",)


def test_invalid_change_target_returns_422_without_persistence():
    reset_limiter()
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=branch().base), \
         patch("app.main.branches.apply_change_to_branch") as persist:
        response = client.post("/branches/b-1/changes", json={
            "op": "modify", "resource_type": "s3_bucket", "resource_id": "missing", "fields": {}
        })
    assert response.status_code == 422
    assert "Target not found" in response.json()["detail"]
    persist.assert_not_called()


def test_verdict_shape():
    reset_limiter()
    verdict = CombinedVerdict(verdict="pass", summary="ok")
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=branch().base), \
         patch("app.main.combined_verdict", return_value=verdict):
        response = client.get("/branches/b-1/verdict")
    assert response.status_code == 200
    assert response.json()["verdict"] == "pass"
    assert response.json()["summary"] == "ok"


def test_rollback_discard_and_closed_change_conflict():
    reset_limiter()
    rolled = branch(changes=[])
    with patch("app.main.branches.rollback_last", return_value=rolled), \
         patch("app.main.branches.discard_branch", return_value=branch(status="discarded")), \
         patch("app.main.branches.get_branch", return_value=branch(status="discarded")), \
         patch("app.main.branches.apply_change_to_branch", side_effect=ValueError("Branch is not open")):
        rollback = client.post("/branches/b-1/rollback")
        discard = client.post("/branches/b-1/discard")
        conflict = client.post("/branches/b-1/changes", json={"op": "delete", "resource_type": "s3_bucket", "resource_id": "x"})
    assert rollback.status_code == 200
    assert rollback.json()["num_changes"] == 0
    assert discard.json() == {"branch_id": "b-1", "status": "discarded"}
    assert conflict.status_code == 409


def test_compare_returns_ranking():
    reset_limiter()
    result = {"base_analysis_id": "a-1", "branches": [], "ranking": ["b-2", "b-1"],
              "has_mixed_bases": False, "base_analysis_ids": ["a-1", "a-1"]}
    with patch("app.main.branches.compare_branches", return_value=result) as compare:
        response = client.post("/branches/compare", json={"branch_ids": ["b-1", "b-2"]})
    assert response.status_code == 200
    assert response.json()["ranking"] == ["b-2", "b-1"]
    compare.assert_called_once_with(["b-1", "b-2"])


def test_unknown_branch_is_404():
    reset_limiter()
    from app import branches
    with patch("app.main.branches.get_branch_diff", side_effect=branches.BranchNotFoundError("missing")):
        response = client.get("/branches/missing/diff")
    assert response.status_code == 404


def test_branch_rate_cap_is_429(monkeypatch):
    reset_limiter()
    import app.main as main
    monkeypatch.setattr(main, "_BRANCH_LIMIT", 1)
    with patch("app.main.branches.list_branches", return_value=[]):
        assert client.get("/branches").status_code == 200
        response = client.get("/branches")
    assert response.status_code == 429
