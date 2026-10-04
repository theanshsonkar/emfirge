from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database
from app.models import AWSInfrastructure
from app.mutations import Change


@pytest.fixture
def branch_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'branches.db'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    yield
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def test_branch_round_trip_mutations_rebuild_diff_rollback_and_discard(branch_db):
    base = AWSInfrastructure(region="us-east-1")
    branch_id = branches.create_branch(base, "experiment", base_analysis_id="analysis-1")

    created = branches.get_branch(branch_id)
    assert created.name == "experiment"
    assert created.base_analysis_id == "analysis-1"
    assert created.status == "open"
    assert created.changes == []

    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="ec2_instance", resource_id="i-new",
        fields={"type": "t3.micro", "state": "running"},
    ))
    branches.apply_change_to_branch(branch_id, Change(
        op="modify", resource_type="ec2_instance", resource_id="i-new",
        fields={"imdsv2_required": True},
    ))
    current = branches.get_branch(branch_id)
    assert [change.op for change in current.changes] == ["add", "modify"]
    assert current.base.ec2.instances == []  # the base remains immutable

    rebuilt = branches.rebuild_branch_infra(branch_id)
    assert rebuilt.ec2.instances[0].id == "i-new"
    assert rebuilt.ec2.instances[0].imdsv2_required is True
    assert rebuilt.model_dump() == branches.rebuild_branch_infra(branch_id).model_dump()

    first_diff = branches.get_branch_diff(branch_id)
    second_diff = branches.get_branch_diff(branch_id)
    assert first_diff.model_dump() == second_diff.model_dump()
    assert first_diff.added_nodes == ["i-new"]

    rolled_back = branches.rollback_last(branch_id)
    assert [change.op for change in rolled_back.changes] == ["add"]
    assert branches.rollback_last(branch_id).changes == []
    assert branches.rollback_last(branch_id).changes == []  # no-op safe

    branches.apply_change_to_branch(branch_id, {"op": "add", "resource_type": "ec2_instance",
                                                "resource_id": "i-other",
                                                "fields": {"type": "t3.nano", "state": "running"}})
    discarded = branches.discard_branch(branch_id)
    assert discarded.status == "discarded"


def test_read_branch_returns_only_ordered_normalized_change_log(branch_db):
    branch_id = branches.create_branch(
        AWSInfrastructure(region="us-east-1"), "inspect", base_analysis_id="analysis",
    )
    for bucket_name in ("first", "second"):
        branches.apply_change_to_branch(branch_id, Change(
            op="add", resource_type="s3_bucket", resource_id=bucket_name,
            fields={"encrypted": True}, expected_change_count=len(branches.get_branch(branch_id).changes),
        ))

    detail = branches.read_branch(branch_id)

    assert detail.model_dump(mode="json") == {
        "branch_id": branch_id,
        "name": "inspect",
        "status": "open",
        "base_analysis_id": "analysis",
        "num_changes": 2,
        "changes": [
            {"op": "add", "resource_type": "s3_bucket", "resource_id": "first",
             "fields": {"encrypted": True}},
            {"op": "add", "resource_type": "s3_bucket", "resource_id": "second",
             "fields": {"encrypted": True}},
        ],
    }
    assert not hasattr(detail, "base")

    branches.discard_branch(branch_id)
    assert branches.read_branch(branch_id).status == "discarded"


def test_list_branches_filters_by_base_analysis(branch_db):
    base = AWSInfrastructure()
    branches.create_branch(base, "one", base_analysis_id="a")
    branches.create_branch(base, "two", base_analysis_id="b")
    branches.create_branch(base, "three", base_analysis_id="a")

    assert [item.name for item in branches.list_branches("a")] == ["one", "three"]
    assert len(branches.list_branches()) == 3


def test_missing_branch_has_explicit_error(branch_db):
    with pytest.raises(branches.BranchNotFoundError, match="Branch not found"):
        branches.get_branch("missing")


def test_direct_branch_append_rejects_invalid_change_without_corrupting_log(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "safe")
    with pytest.raises(ValueError, match="Target not found"):
        branches.apply_change_to_branch(branch_id, Change(
            op="modify", resource_type="security_group", resource_id="sg-missing",
            fields={"rules": []},
        ))
    assert branches.get_branch(branch_id).changes == []
    assert branches.rebuild_branch_infra(branch_id).region == "us-east-1"


def test_stale_agent_change_count_rejects_append_and_preserves_history(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "shared")
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="first-bucket",
        expected_change_count=0,
    ))
    with pytest.raises(branches.BranchConflictError, match="expected 0 change"):
        branches.apply_change_to_branch(branch_id, Change(
            op="add", resource_type="s3_bucket", resource_id="second-bucket",
            expected_change_count=0,
        ))
    assert len(branches.get_branch(branch_id).changes) == 1
    assert branches.get_branch(branch_id).changes[0].expected_change_count is None
    assert [bucket.name for bucket in branches.rebuild_branch_infra(branch_id).s3.buckets] == ["first-bucket"]


def test_stale_agent_cannot_rollback_another_agents_change(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "shared")
    for name in ("first-bucket", "second-bucket"):
        branches.apply_change_to_branch(branch_id, Change(
            op="add", resource_type="s3_bucket", resource_id=name,
        ))
    with pytest.raises(branches.BranchConflictError, match="expected 1 change"):
        branches.rollback_last(branch_id, expected_change_count=1)
    assert len(branches.get_branch(branch_id).changes) == 2
    assert len(branches.rollback_last(branch_id, expected_change_count=2).changes) == 1


def test_stale_agent_cannot_discard_after_another_append(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "shared")
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="first-bucket",
        expected_change_count=0,
    ))
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="second-bucket",
        expected_change_count=1,
    ))

    with pytest.raises(branches.BranchConflictError, match="expected 1 change.*found 2"):
        branches.discard_branch(branch_id, expected_change_count=1)
    still_open = branches.get_branch(branch_id)
    assert still_open.status == "open"
    assert len(still_open.changes) == 2

    discarded = branches.discard_branch(branch_id, expected_change_count=2)
    assert discarded.status == "discarded"
    # The legacy no-body request stays idempotent.
    assert branches.discard_branch(branch_id).status == "discarded"



def test_branch_limit_is_per_base_and_discard_frees_slot(branch_db, monkeypatch):
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 2)
    base = AWSInfrastructure(region="us-east-1")
    other_base = AWSInfrastructure(region="us-west-2")

    first = branches.create_branch(base, "first", base_analysis_id="same")
    second = branches.create_branch(base, "second", base_analysis_id="same")
    with pytest.raises(branches.BranchLimitError, match=r"Open branch limit \(2\) reached"):
        branches.create_branch(base, "blocked", base_analysis_id="same")

    # A different base-analysis ID has an independent open-branch quota.
    different_base_branch = branches.create_branch(other_base, "other", base_analysis_id="other")
    assert branches.get_branch(different_base_branch).base.region == "us-west-2"

    branches.discard_branch(first)
    replacement = branches.create_branch(base, "replacement", base_analysis_id="same")
    assert branches.get_branch(replacement).status == "open"
    assert branches.get_branch(second).status == "open"


def test_same_base_branches_are_isolated(branch_db):
    base = AWSInfrastructure(region="us-east-1")
    left = branches.create_branch(base, "left", base_analysis_id="same")
    right = branches.create_branch(base, "right", base_analysis_id="same")

    branches.apply_change_to_branch(left, Change(
        op="add", resource_type="ec2_instance", resource_id="i-left",
        fields={"type": "t3.micro", "state": "running"},
    ))
    branches.apply_change_to_branch(right, Change(
        op="add", resource_type="ec2_instance", resource_id="i-right",
        fields={"type": "t3.small", "state": "running"},
    ))

    assert [instance.id for instance in branches.rebuild_branch_infra(left).ec2.instances] == ["i-left"]
    assert [instance.id for instance in branches.rebuild_branch_infra(right).ec2.instances] == ["i-right"]
    assert branches.get_branch(left).base.ec2.instances == []
    assert branches.get_branch(right).base.ec2.instances == []


def test_compare_summary_has_exact_values_and_safer_first_ranking(branch_db):
    base = AWSInfrastructure(region="us-east-1")
    safer = branches.create_branch(base, "safer", base_analysis_id="analysis")
    riskier = branches.create_branch(base, "riskier", base_analysis_id="analysis")
    branches.apply_change_to_branch(safer, Change(
        op="add", resource_type="ec2_instance", resource_id="i-safe",
        fields={"type": "t3.micro", "state": "running", "imdsv2_required": True},
    ))
    branches.apply_change_to_branch(riskier, Change(
        op="add", resource_type="ec2_instance", resource_id="i-risk",
        fields={"type": "t3.micro", "state": "running", "has_public_ip": True},
    ))

    result = branches.compare_branches([riskier, safer])
    assert result.base_analysis_id == "analysis"
    assert result.base_analysis_ids == ["analysis", "analysis"]
    assert result.has_mixed_bases is False
    assert [summary.branch_id for summary in result.branches] == [riskier, safer]
    assert result.branches[0].model_dump() == {
        "branch_id": riskier,
        "name": "riskier",
        "score_after": 89,
        "score_delta": -5,
        "added_nodes": 1,
        "removed_nodes": 0,
        "newly_internet_reachable": 0,
        "no_longer_internet_reachable": 0,
        "added_findings": 4,
        "removed_findings": 0,
        "lost_dependencies": 0,
        "lost_connectivity": 0,
        "deletion_impacts": 0,
        "has_privilege_escalation": False,
    }
    assert result.branches[1].model_dump() == {
        "branch_id": safer,
        "name": "safer",
        "score_after": 93,
        "score_delta": -1,
        "added_nodes": 1,
        "removed_nodes": 0,
        "newly_internet_reachable": 0,
        "no_longer_internet_reachable": 0,
        "added_findings": 3,
        "removed_findings": 0,
        "lost_dependencies": 0,
        "lost_connectivity": 0,
        "deletion_impacts": 0,
        "has_privilege_escalation": False,
    }
    assert result.ranking == [safer, riskier]


def test_compare_detects_privilege_escalation_from_iam_graph(branch_db):
    from app.models import AccessStatement, IAMData, RolePolicy, S3Bucket, S3Data

    # Change currently supports no IAM resource type, so use the actual IAMData /
    # RolePolicy / AccessStatement infrastructure construction pattern as the
    # already-escalated base state for this comparison test.
    base = AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(name="bucket")]), iam=IAMData(role_policies=[RolePolicy(
        role_name="EscalatedRole",
        role_arn="arn:aws:iam::123456789012:role/EscalatedRole",
        access_statements=[AccessStatement(
            effect="allow", actions=["*"], resources=["arn:aws:s3:::bucket"],
        )],
    )]))
    branch_id = branches.create_branch(base, "escalated", base_analysis_id="iam")

    summary = branches.compare_branches([branch_id]).branches[0]
    assert summary.has_privilege_escalation is True


def test_compare_uses_one_loaded_branch_view_for_diff_and_rebuild():
    first_change = Change(op="add", resource_type="s3_bucket", resource_id="first")
    second_changes = [
        Change(op="add", resource_type="s3_bucket", resource_id="second-a"),
        Change(op="add", resource_type="s3_bucket", resource_id="second-b"),
    ]
    first_view = branches.Branch(
        branch_id="b-1", name="snapshot", base=AWSInfrastructure(region="us-east-1"),
        changes=[first_change], status="open",
    )
    later_view = branches.Branch(
        branch_id="b-1", name="snapshot", base=AWSInfrastructure(region="us-west-2"),
        changes=second_changes, status="open",
    )

    with patch.object(branches, "get_branch", side_effect=[first_view, later_view]) as load:
        result = branches.compare_branches(["b-1"])

    load.assert_called_once_with("b-1")
    summary = result.branches[0]
    assert summary.added_nodes == 1
    assert summary.name == first_view.name


def test_compare_is_deterministic_and_reports_mixed_base_metadata(branch_db):
    base_a = AWSInfrastructure(region="us-east-1")
    base_b = AWSInfrastructure(region="us-west-2")
    first = branches.create_branch(base_a, "same-name", base_analysis_id="a")
    second = branches.create_branch(base_b, "same-name", base_analysis_id="b")

    first_result = branches.compare_branches([first, second])
    second_result = branches.compare_branches([first, second])
    assert first_result.model_dump() == second_result.model_dump()
    assert first_result.base_analysis_id == "a"
    assert first_result.base_analysis_ids == ["a", "b"]
    assert first_result.has_mixed_bases is True
    assert first_result.ranking == []
    assert first_result.comparison_warnings


def test_compare_refuses_ranking_for_same_analysis_id_with_different_snapshots(branch_db):
    first = branches.create_branch(AWSInfrastructure(region="us-east-1"), "first", base_analysis_id="a")
    second = branches.create_branch(AWSInfrastructure(region="us-west-2"), "second", base_analysis_id="a")
    result = branches.compare_branches([first, second])
    assert result.has_mixed_bases is True
    assert result.ranking == []


def test_compare_empty_and_unknown_behavior(branch_db):
    assert branches.compare_branches([]).model_dump() == {
        "base_analysis_id": None,
        "branches": [],
        "ranking": [],
        "has_mixed_bases": False,
        "base_analysis_ids": [],
        "comparison_warnings": [],
    }
    with pytest.raises(branches.BranchNotFoundError, match="Branch not found"):
        branches.compare_branches(["missing"])
