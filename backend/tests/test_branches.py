from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
import json

import pytest
from sqlalchemy import create_engine, event, text
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
    yield engine
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
        "branch_revision": branches.branch_revision(branches.get_branch(branch_id)),
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


def test_branch_revision_is_stable_and_tracks_persisted_state_changes(branch_db):
    parent_id = branches.create_branch(
        AWSInfrastructure(region="us-east-1"), "parent", base_analysis_id="revision",
    )
    initial = branches.read_branch(parent_id).branch_revision
    assert branches.read_branch(parent_id).branch_revision == initial

    branches.apply_change_to_branch(parent_id, Change(
        op="add", resource_type="s3_bucket", resource_id="revision-bucket",
        expected_change_count=0,
    ))
    appended = branches.read_branch(parent_id).branch_revision
    assert appended != initial
    assert branches.read_branch(parent_id).branch_revision == appended

    child_id, _ = branches.fork_branch(parent_id, "child")
    assert branches.read_branch(child_id).branch_revision == appended
    branches.apply_change_to_branch(child_id, Change(
        op="add", resource_type="s3_bucket", resource_id="child-only",
    ))
    assert branches.read_branch(child_id).branch_revision != appended
    assert branches.rollback_last(child_id).changes[0].resource_id == "revision-bucket"
    assert branches.read_branch(child_id).branch_revision == appended

    branches.rollback_last(parent_id)
    assert branches.read_branch(parent_id).branch_revision == initial


def test_branch_revision_excludes_request_only_expected_count():
    base = AWSInfrastructure(region="us-east-1")
    first = branches.Branch(
        branch_id="one", name="same", base=base,
        changes=[Change(op="add", resource_type="s3_bucket", resource_id="bucket",
                        expected_change_count=0, branch_revision="a" * 64)], status="open",
    )
    second = first.model_copy(update={
        "changes": [Change(op="add", resource_type="s3_bucket", resource_id="bucket",
                           expected_change_count=42, branch_revision="b" * 64)],
    })
    assert branches.branch_revision(first) == branches.branch_revision(second)


def test_fork_copies_snapshot_and_ordered_log_without_parent_coupling(branch_db):
    base = AWSInfrastructure(region="us-west-2")
    parent_id = branches.create_branch(base, "parent", base_analysis_id="analysis-fork")
    for bucket in ("one", "two"):
        branches.apply_change_to_branch(parent_id, Change(
            op="add", resource_type="s3_bucket", resource_id=bucket,
            fields={"encrypted": True},
        ))

    child_id, count = branches.fork_branch(parent_id, "child")
    parent = branches.get_branch(parent_id)
    child = branches.get_branch(child_id)

    assert child_id != parent_id
    assert count == 2
    assert child.status == "open"
    assert child.name == "child"
    assert child.base_analysis_id == parent.base_analysis_id == "analysis-fork"
    assert child.base.model_dump(mode="json") == parent.base.model_dump(mode="json") == base.model_dump(mode="json")
    assert [change.model_dump(mode="json") for change in child.changes] == [
        change.model_dump(mode="json") for change in parent.changes
    ]

    branches.apply_change_to_branch(child_id, Change(
        op="add", resource_type="s3_bucket", resource_id="child-only",
    ))
    assert len(branches.get_branch(child_id).changes) == 3
    assert len(branches.get_branch(parent_id).changes) == 2
    comparison = branches.compare_branches([parent_id, child_id])
    assert {item.branch_id for item in comparison.branches} == {parent_id, child_id}


def test_fork_requires_open_parent_and_enforces_open_quota(branch_db, monkeypatch):
    parent_id = branches.create_branch(
        AWSInfrastructure(), "parent", base_analysis_id="limited-fork",
    )
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 1)
    with pytest.raises(branches.BranchLimitError):
        branches.fork_branch(parent_id, "over quota")
    assert len(branches.list_branches("limited-fork")) == 1

    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 2)
    branches.discard_branch(parent_id)
    with pytest.raises(ValueError, match="not open"):
        branches.fork_branch(parent_id, "discarded parent")


def test_fork_rejects_parent_append_between_snapshot_and_conditional_lock(branch_db):
    # No base_analysis_id means this fork does not take the quota lock, letting
    # the injected append exercise the parent-log compare-and-swap directly.
    parent_id = branches.create_branch(AWSInfrastructure(), "parent")
    branches.apply_change_to_branch(parent_id, Change(
        op="add", resource_type="s3_bucket", resource_id="before-fork",
    ))
    injected = False

    def append_during_fork(connection, cursor, statement, parameters, context, executemany):
        nonlocal injected
        if injected or not statement.lstrip().lower().startswith("update branch_logs"):
            return
        injected = True
        latest = json.dumps([
            {"op": "add", "resource_type": "s3_bucket", "resource_id": "before-fork", "fields": {}},
            {"op": "add", "resource_type": "s3_bucket", "resource_id": "concurrent", "fields": {}},
        ], sort_keys=True, separators=(",", ":"))
        with connection.engine.begin() as race_connection:
            race_connection.execute(
                text("UPDATE branch_logs SET changes_json = :changes WHERE branch_id = :id"),
                {"changes": latest, "id": parent_id},
            )

    event.listen(branch_db, "before_cursor_execute", append_during_fork)
    try:
        with pytest.raises(branches.BranchConflictError, match="changed during fork"):
            branches.fork_branch(parent_id, "must-not-be-partial")
    finally:
        event.remove(branch_db, "before_cursor_execute", append_during_fork)

    assert len(branches.list_branches()) == 1
    assert [change.resource_id for change in branches.get_branch(parent_id).changes] == [
        "before-fork", "concurrent",
    ]


@pytest.mark.parametrize("creator", ["create", "fork"])
def test_concurrent_creators_cannot_exceed_open_branch_quota(branch_db, monkeypatch, creator):
    base_analysis_id = f"concurrent-{creator}"
    if creator == "create":
        monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 1)
        create = lambda name: branches.create_branch(
            AWSInfrastructure(), name, base_analysis_id=base_analysis_id,
        )
    else:
        parent_id = branches.create_branch(
            AWSInfrastructure(), "parent", base_analysis_id=base_analysis_id,
        )
        monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 2)
        create = lambda name: branches.fork_branch(parent_id, name)

    barrier = Barrier(3)

    def contender(name):
        barrier.wait(timeout=5)
        try:
            return create(name)
        except branches.BranchLimitError:
            return "quota-rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(contender, "first")
        second = pool.submit(contender, "second")
        barrier.wait(timeout=5)
        results = [first.result(timeout=10), second.result(timeout=10)]

    assert results.count("quota-rejected") == 1
    assert len(branches.list_branches(base_analysis_id)) == branches.MAX_OPEN_BRANCHES_PER_BASE


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


def test_stale_branch_revision_rejects_same_count_different_history(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "revision-guard")
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="first-bucket",
    ))
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="second-bucket",
    ))
    observed = branches.read_branch(branch_id).branch_revision

    branches.rollback_last(branch_id, expected_change_count=2)
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="replacement-bucket",
        expected_change_count=1,
    ))
    assert len(branches.get_branch(branch_id).changes) == 2
    assert branches.read_branch(branch_id).branch_revision != observed

    with pytest.raises(branches.BranchConflictError, match="revision is stale"):
        branches.apply_change_to_branch(branch_id, Change(
            op="add", resource_type="s3_bucket", resource_id="must-not-appear",
            expected_change_count=2, branch_revision=observed,
        ))

    current = branches.get_branch(branch_id)
    assert [change.resource_id for change in current.changes] == [
        "first-bucket", "replacement-bucket",
    ]


def test_append_stores_neither_request_only_concurrency_token(branch_db):
    branch_id = branches.create_branch(AWSInfrastructure(region="us-east-1"), "clean-log")
    observed = branches.read_branch(branch_id).branch_revision
    branches.apply_change_to_branch(branch_id, Change(
        op="add", resource_type="s3_bucket", resource_id="bucket",
        expected_change_count=0, branch_revision=observed,
    ))

    session = branches.SessionLocal()
    try:
        row = branches._load_branch(session, branch_id)
        assert "expected_change_count" not in row.changes_json
        assert "branch_revision" not in row.changes_json
    finally:
        session.close()


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
        "branch_revision": branches.branch_revision(branches.get_branch(riskier)),
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
        "branch_revision": branches.branch_revision(branches.get_branch(safer)),
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
