"""Hermetic HTTP tests for the simulation branch API."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import branches
from app.main import app
from app.demo_seed import build_demo_infrastructure
from app.models import (
    AccessStatement, AWSInfrastructure, EC2Data, EC2Instance, IAMData,
    RolePolicy, S3Bucket, S3Data,
)
from app.mutations import Change, apply_changes
from app.verdict import CombinedVerdict


client = TestClient(app)


def branch(branch_id="b-1", name="fix", status="open", base_analysis_id="a-1", changes=None, base=None,
           last_change_modeled_state_unchanged=False):
    return SimpleNamespace(
        branch_id=branch_id,
        name=name,
        status=status,
        base_analysis_id=base_analysis_id,
        changes=changes or [],
        base=base or AWSInfrastructure.model_validate({"region": "us-east-1"}),
        last_change_modeled_state_unchanged=last_change_modeled_state_unchanged,
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


def test_capabilities_endpoint_returns_runtime_mutation_contract():
    from app.mutations import mutation_capabilities

    reset_limiter()
    response = client.get("/branches/capabilities")

    assert response.status_code == 200
    assert response.json() == mutation_capabilities().model_dump(mode="json")
    resources = {item["resource_type"]: item for item in response.json()["resources"]}
    assert resources["iam_role_policy"]["operations"] == ["modify"]
    constraint = resources["iam_role_policy"]["constraints"][0]
    assert constraint["required_fields"] == ["access_statements"]
    assert constraint["allowed_fields"] == ["access_statements"]


def test_get_branch_endpoint_returns_ordered_changes_without_base():
    reset_limiter()
    detail = branches.BranchDetail(
        branch_id="b-1", name="inspect", status="open", base_analysis_id="a-1",
        branch_revision="a" * 64,
        num_changes=2, changes=[
            {"op": "add", "resource_type": "s3_bucket", "resource_id": "one", "fields": {}},
            {"op": "delete", "resource_type": "s3_bucket", "resource_id": "two", "fields": {}},
        ],
    )
    with patch("app.main.branches.read_branch", return_value=detail) as read:
        response = client.get("/branches/b-1")

    assert response.status_code == 200
    assert response.json() == detail.model_dump(mode="json")
    assert "base" not in response.json()
    assert [change["resource_id"] for change in response.json()["changes"]] == ["one", "two"]
    read.assert_called_once_with("b-1")


def test_get_branch_endpoint_returns_404_for_missing_id():
    reset_limiter()
    with patch("app.main.branches.read_branch",
               side_effect=branches.BranchNotFoundError("Branch not found: missing")):
        response = client.get("/branches/missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "Branch not found: missing"


def test_fork_endpoint_returns_child_id_and_change_count():
    reset_limiter()
    with patch("app.main.branches.fork_branch", return_value=("child-1", 3)) as fork:
        response = client.post("/branches/parent-1/fork", json={"name": "candidate"})

    assert response.status_code == 200
    assert response.json() == {"branch_id": "child-1", "num_changes": 3}
    fork.assert_called_once_with("parent-1", "candidate")


@pytest.mark.parametrize("payload", [{}, {"name": "  "}, {"name": "x", "other": True}])
def test_fork_endpoint_validates_required_name(payload):
    reset_limiter()
    response = client.post("/branches/parent-1/fork", json=payload)
    assert response.status_code == 422


def test_fork_endpoint_maps_missing_quota_and_conflict_errors():
    reset_limiter()
    with patch("app.main.branches.fork_branch", side_effect=branches.BranchNotFoundError("Branch not found")):
        assert client.post("/branches/missing/fork", json={"name": "child"}).status_code == 404
    with patch("app.main.branches.fork_branch", side_effect=branches.BranchLimitError("limit")):
        assert client.post("/branches/full/fork", json={"name": "child"}).status_code == 429
    with patch("app.main.branches.fork_branch", side_effect=branches.BranchConflictError("changed")):
        assert client.post("/branches/raced/fork", json={"name": "child"}).status_code == 409


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


def test_no_op_change_is_reported_in_change_diff_and_verdict_responses():
    reset_limiter()
    base = AWSInfrastructure(region="us-east-1", s3=S3Data(total_buckets=1,
        buckets=[S3Bucket(name="bucket", encrypted=True)],
    ))
    changed = branch(changes=[{
        "op": "modify", "resource_type": "s3_bucket", "resource_id": "bucket",
        "fields": {"encrypted": True},
    }], base=base, last_change_modeled_state_unchanged=True)
    diff = {
        "added_nodes": [], "removed_nodes": [], "modified_nodes": [], "added_edges": [],
        "removed_edges": [], "lost_dependencies": [], "coverage_warnings": [],
        "added_findings": [], "removed_findings": [], "score_before": 1,
        "score_after": 1, "score_delta": 0, "newly_internet_reachable": [],
        "no_longer_internet_reachable": [], "modeled_state_unchanged": True,
    }
    with patch("app.main.branches.get_branch", return_value=branch(base=base)), \
         patch("app.main.branches.rebuild_branch_infra", return_value=base), \
         patch("app.main.branches.apply_change_to_branch", return_value=changed), \
         patch("app.main.branches.get_branch_diff", return_value=diff), \
         patch("app.main.combined_verdict", return_value=CombinedVerdict(
             verdict="pass", summary="no modeled change", modeled_state_unchanged=True,
         )):
        apply_response = client.post("/branches/b-1/changes", json={
            "op": "modify", "resource_type": "s3_bucket", "resource_id": "bucket",
            "fields": {"encrypted": True},
        })
        diff_response = client.get("/branches/b-1/diff")
        verdict_response = client.get("/branches/b-1/verdict")

    assert apply_response.status_code == 200
    assert apply_response.json() == {
        "branch_id": "b-1", "num_changes": 1, "modeled_state_unchanged": True,
    }
    assert diff_response.status_code == 200
    assert diff_response.json()["modeled_state_unchanged"] is True
    assert verdict_response.status_code == 200
    assert verdict_response.json()["verdict"] == "pass"
    assert verdict_response.json()["modeled_state_unchanged"] is True


def test_inspect_diff_and_verdict_share_the_loaded_branch_revision():
    reset_limiter()
    loaded = branches.Branch(
        branch_id="b-revision", name="snapshot", base=AWSInfrastructure(region="us-east-1"),
        status="open", changes=[Change(
            op="add", resource_type="s3_bucket", resource_id="revision-bucket",
        )],
    )
    expected_revision = branches.branch_revision(loaded)
    with patch("app.main.branches.get_branch", return_value=loaded), \
         patch("app.branches.diff_infrastructure", return_value=branches.DiffResult()), \
         patch("app.main.combined_verdict", return_value=CombinedVerdict(
             verdict="pass", summary="ok",
         )):
        inspect_response = client.get("/branches/b-revision")
        diff_response = client.get("/branches/b-revision/diff")
        verdict_response = client.get("/branches/b-revision/verdict")

    assert inspect_response.status_code == diff_response.status_code == verdict_response.status_code == 200
    assert inspect_response.json()["branch_revision"] == expected_revision
    assert diff_response.json()["branch_revision"] == expected_revision
    assert verdict_response.json()["branch_revision"] == expected_revision


def test_agent_can_replace_collected_role_statements_on_branch():
    reset_limiter()
    role_arn = "arn:aws:iam::000000000000:role/AppRole"
    base = AWSInfrastructure(iam=IAMData(role_policies=[RolePolicy(
        role_name="AppRole",
        role_arn=role_arn,
        access_statements=[AccessStatement(
            effect="allow", actions=["s3:GetObject"], resources=["*"],
        )],
    )]))
    changed = branch(changes=[{"op": "modify", "resource_type": "iam_role_policy"}])
    with patch("app.main.branches.get_branch", return_value=branch(base=base)), \
         patch("app.main.branches.rebuild_branch_infra", return_value=base), \
         patch("app.main.branches.apply_change_to_branch", return_value=changed) as persist:
        response = client.post("/branches/b-1/changes", json={
            "op": "modify",
            "resource_type": "iam_role_policy",
            "resource_id": role_arn,
            "fields": {"access_statements": []},
        })

    assert response.status_code == 200
    assert response.json()["num_changes"] == 1
    persisted_change = persist.call_args.args[1]
    assert persisted_change.resource_type == "iam_role_policy"
    assert persisted_change.fields == {"access_statements": []}


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


def test_agent_cannot_persist_in_use_security_group_delete():
    reset_limiter()
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=build_demo_infrastructure()), \
         patch("app.main.branches.apply_change_to_branch") as persist:
        response = client.post("/branches/b-1/changes", json={
            "op": "delete", "resource_type": "security_group",
            "resource_id": "sg-demo-public", "fields": {},
        })
    assert response.status_code == 422
    assert "still in use by i-demo-web-001" in response.json()["detail"]
    persist.assert_not_called()


def test_stale_agent_append_returns_conflict():
    reset_limiter()
    with patch("app.main.branches.get_branch", return_value=branch()), \
         patch("app.main.branches.rebuild_branch_infra", return_value=AWSInfrastructure(region="us-east-1")), \
         patch("app.main.branches.apply_change_to_branch",
               side_effect=branches.BranchConflictError("Branch changed")):
        response = client.post("/branches/b-1/changes", json={
            "op": "add", "resource_type": "s3_bucket", "resource_id": "new-bucket",
            "fields": {}, "expected_change_count": 0,
        })
    assert response.status_code == 409
    assert response.json()["detail"] == "Branch changed"


def test_stale_agent_rollback_returns_conflict():
    reset_limiter()
    with patch("app.main.branches.rollback_last",
               side_effect=branches.BranchConflictError("Branch changed")) as rollback:
        response = client.post("/branches/b-1/rollback", json={"expected_change_count": 1})
    assert response.status_code == 409
    rollback.assert_called_once_with("b-1", expected_change_count=1)


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
         patch("app.main.branches.rebuild_branch_state", return_value=branch().base), \
         patch("app.main.combined_verdict", return_value=verdict):
        response = client.get("/branches/b-1/verdict")
    assert response.status_code == 200
    assert response.json()["verdict"] == "pass"
    assert response.json()["summary"] == "ok"


def test_verdict_uses_one_loaded_branch_view_for_rebuild(monkeypatch):
    reset_limiter()
    monkeypatch.setenv("EMFIRGE_RUN_SCANNERS", "0")
    first_change = Change(op="add", resource_type="s3_bucket", resource_id="first")
    first_view = branch(
        base=AWSInfrastructure(region="us-east-1"), changes=[first_change],
    )
    later_view = branch(
        base=AWSInfrastructure(region="us-west-2"),
        changes=[Change(op="add", resource_type="s3_bucket", resource_id="later")],
    )
    verdict = CombinedVerdict(verdict="pass", summary="ok")

    with patch("app.main.branches.get_branch", side_effect=[first_view, later_view]) as load, \
         patch("app.main.branches.rebuild_branch_state", wraps=branches.rebuild_branch_state) as rebuild, \
         patch("app.main.combined_verdict", return_value=verdict) as combine:
        response = client.get("/branches/b-1/verdict")

    rebuilt = apply_changes(first_view.base, first_view.changes)
    assert response.status_code == 200
    load.assert_called_once_with("b-1")
    rebuild.assert_called_once_with(first_view)
    combine.assert_called_once_with(first_view.base, rebuilt, run_scanners=False)


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


def test_discard_maps_stale_change_count_to_conflict():
    reset_limiter()
    with patch("app.main.branches.discard_branch",
               side_effect=branches.BranchConflictError("Branch changed: expected 1 change(s), found 2")) as discard:
        response = client.post("/branches/b-1/discard", json={"expected_change_count": 1})

    assert response.status_code == 409
    assert response.json()["detail"] == "Branch changed: expected 1 change(s), found 2"
    discard.assert_called_once_with("b-1", expected_change_count=1)


@pytest.mark.parametrize("payload", [
    {"expected_change_count": -1},
    {"expected_change_count": True},
    {"unexpected": 1},
    ["expected_change_count"],
])
def test_discard_rejects_invalid_guard_payload(payload):
    reset_limiter()
    with patch("app.main.branches.discard_branch") as discard:
        response = client.post("/branches/b-1/discard", json=payload)

    assert response.status_code == 422
    discard.assert_not_called()


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
