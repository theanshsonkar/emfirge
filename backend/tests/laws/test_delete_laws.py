import copy

import hypothesis
import pytest
from hypothesis import given, strategies as st

from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.mutations import Change, apply_change
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base


RESOURCE_TYPES = (
    "ec2_instance", "rds_instance", "s3_bucket", "ebs_volume",
    "ebs_snapshot", "rds_snapshot", "iam_role", "security_group",
)


def _resource_id(resource_type, item):
    if resource_type in {"s3_bucket", "iam_role"}:
        return item.name if resource_type == "s3_bucket" else item.role_arn
    return item.id


def _deletable(base):
    result = []
    for resource_type, items in (
        ("ec2_instance", base.ec2.instances), ("rds_instance", base.rds.rds_instances),
        ("s3_bucket", base.s3.buckets), ("ebs_volume", base.ec2.ebs_volumes),
        ("ebs_snapshot", base.ec2.ebs_snapshots), ("rds_snapshot", base.rds.rds_snapshots),
        ("iam_role", base.iam.role_policies), ("security_group", base.ec2.security_groups),
    ):
        result.extend((resource_type, _resource_id(resource_type, item)) for item in items)
    return result


def _delete_options(resource_type, resource_id, suffix=0):
    if resource_type != "rds_instance":
        return {}
    if suffix % 2:
        return {"skip_final_snapshot": True}
    return {"skip_final_snapshot": False, "final_db_snapshot_identifier": f"law-final-{resource_id}-{suffix}"}


def _change_strategy():
    base = load_synthetic_base("delete")
    targets = _deletable(base)
    return st.permutations(targets).map(list).flatmap(
        lambda ordered: st.tuples(
            st.just(ordered), st.integers(min_value=0, max_value=max(0, len(ordered)))
        ).map(lambda pair: pair[0][:pair[1]])
    )


@st.composite
def delete_sequences(draw):
    base = load_synthetic_base("delete")
    targets = draw(st.permutations(_deletable(base)))
    count = draw(st.integers(min_value=0, max_value=len(targets)))
    return list(targets[:count])


def _apply(base, resource_type, resource_id, fields=None):
    try:
        return apply_change(base, Change(op="delete", resource_type=resource_type,
                                         resource_id=resource_id, fields=fields or {}))
    except (ValueError, TypeError) as exc:
        hypothesis.event("422 skipped: " + resource_type)
        return None


def _run(base, sequence):
    branch = base
    applied_count = 0
    for index, (resource_type, resource_id) in enumerate(sequence):
        next_branch = _apply(branch, resource_type, resource_id,
                             _delete_options(resource_type, resource_id, index))
        if next_branch is not None:
            branch = next_branch
            applied_count += 1
    hypothesis.event(f"applied mutations: {applied_count}")
    hypothesis.assume(applied_count > 0)
    return branch


def _lens(base, branch):
    return combined_verdict(base, branch, run_scanners=False).deletion


@given(delete_sequences())
def test_data_lost_requires_block(sequence):
    base = load_synthetic_base("delete")
    branch = _run(base, sequence)
    result = combined_verdict(base, branch, run_scanners=False)
    if result.deletion.data_lost:
        assert result.verdict == "block"


@given(delete_sequences())
def test_appending_snapshot_delete_never_shrinks_data_lost(sequence):
    base = load_synthetic_base("delete")
    before = _run(base, sequence)
    old = {item.resource_id for item in _lens(base, before).data_lost}
    for snapshot_type, snapshot_id in (("ebs_snapshot", "snap-dl-root"), ("rds_snapshot", "dlsnap-reports")):
        after = _apply(before, snapshot_type, snapshot_id)
        if after is not None:
            new = {item.resource_id for item in _lens(base, after).data_lost}
            assert old <= new


@given(delete_sequences(), st.sampled_from([("ec2_instance", "i-dl-web"), ("rds_instance", "db-dl-prod")]))
def test_delete_then_readd_never_shrinks_data_lost(sequence, readd):
    base = load_synthetic_base("delete")
    deleted = _run(base, sequence)
    alone = _lens(base, deleted)
    removed = _apply(deleted, readd[0], readd[1], _delete_options(readd[0], readd[1], 1))
    if removed is None:
        return
    deleted = removed
    if readd[0] == "ec2_instance":
        source = next(item for item in base.ec2.instances if item.id == readd[1])
        fields = source.model_dump(exclude={"id"})
    else:
        source = next(item for item in base.rds.rds_instances if item.id == readd[1])
        fields = source.model_dump(exclude={"id"})
    try:
        readded = apply_change(deleted, Change(op="add", resource_type=readd[0], resource_id=readd[1], fields=fields))
    except (ValueError, TypeError):
        hypothesis.event("422 skipped: re-add " + readd[0])
        return
    assert {item.resource_id for item in _lens(base, readded).data_lost} >= {
        item.resource_id for item in alone.data_lost
    }


@given(delete_sequences())
def test_delete_coverage_has_unmodeled_categories(sequence):
    base = load_synthetic_base("delete")
    branch = _run(base, sequence)
    if sequence:
        cannot = set(_lens(base, branch).coverage.cannot_see)
        assert {"app_code_references", "dns_records", "other_accounts", "data_contents"} <= cannot


@given(delete_sequences())
def test_impacts_reference_base_nodes_and_not_data_lost(sequence):
    base = load_synthetic_base("delete")
    lens = _lens(base, _run(base, sequence))
    base_ids = {str(node.id) for node in build_graph(base).nodes}
    lost = {item.resource_id for item in lens.data_lost}
    assert all(item.resource_id in base_ids for item in lens.impacts)
    assert not lost.intersection({item.resource_id for item in lens.impacts})


@given(delete_sequences())
def test_delete_score_never_raises(sequence):
    base = load_synthetic_base("delete")
    diff = diff_infrastructure(base, _run(base, sequence))
    assert diff.score_after <= diff.score_before


@given(st.sampled_from(["arn:aws:iam::000000000000:role/DlAppRole", "arn:aws:iam::000000000000:role/DlBatchRole"]))
def test_denied_role_usage_blocks_with_unknown_reason(role_arn):
    base = load_synthetic_base("delete", {"collection": {"iam_role_last_used": "denied"}})
    branch = _apply(base, "iam_role", role_arn)
    if branch is None:
        pytest.fail("IAM role delete should be valid")
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "block"
    assert any(reason["code"] == "usage_unknown" for reason in result.reasons)


@given(st.sampled_from(["ebs_snapshot", "rds_snapshot"]))
def test_unusable_snapshot_is_not_recovery_point(snapshot_type):
    patch = {"ebs_snapshots": [{"id": "snap-dl-root", "volume_id": "vol-dl-root", "state": "creating"}]} if snapshot_type == "ebs_snapshot" else {"rds_snapshots": [{"id": "dlsnap-reports", "db_instance_id": "db-dl-reports", "snapshot_type": "manual", "status": "creating"}]}
    base = load_synthetic_base("delete", patch)
    resource_type, resource_id = (("ec2_instance", "i-dl-web") if snapshot_type == "ebs_snapshot" else ("rds_instance", "db-dl-reports"))
    options = {} if snapshot_type == "ebs_snapshot" else _delete_options(resource_type, resource_id, 1)
    branch = _apply(base, resource_type, resource_id, options)
    assert branch is not None
    assert all(item.source_id not in {"snap-dl-root", "dlsnap-reports"} for item in _lens(base, branch).recovery_points)
