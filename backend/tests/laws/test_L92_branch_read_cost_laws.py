"""L92: reading a branch costs one small query, not a full account snapshot per step.

The incident (2026-11-08, after the L90 deploy): check and diff still ended in a 504 and
`branch list` took 52s, while the engine computes the same check in under a second. On the live
server one database round trip costs about 0.6s, and every branch request:
  - ran the tenant guard, which downloaded and parsed the WHOLE base snapshot only to read
    base_analysis_id, then searched every stored scan's JSON text for the owner;
  - then loaded the same snapshot again (diff loaded it twice more);
  - `branch list` did all of that once per branch.

L92a  The base snapshot of a branch never changes, so it is parsed once per process and served
      from memory; each caller gets its own copy (mutating it never changes the cache).
L92b  `branch list` never reads a base snapshot.
L92c  Branch visibility reads only branch metadata and is remembered per caller for a short time.
"""
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import branches, main
from app.database import BranchLog, SessionLocal
from app.models import AWSInfrastructure, S3Bucket, S3Data


def _infra():
    return AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(name="law92-bucket")]))


CREATED: list[str] = []


def _new(name, analysis):
    bid = branches.create_branch(_infra(), name, analysis)
    CREATED.append(bid)
    return bid


@pytest.fixture(autouse=True)
def _clean():
    branches._clear_branch_caches()
    main._clear_visibility_cache()
    yield
    session = SessionLocal()
    try:
        session.query(BranchLog).filter(BranchLog.branch_id.in_(CREATED)).delete(synchronize_session=False)
        session.commit()
    finally:
        session.close()
    CREATED.clear()
    branches._clear_branch_caches()
    main._clear_visibility_cache()


def test_L92a_base_is_parsed_once_and_copies_are_independent():
    bid = _new("law92a", f"analysis-92a-{uuid.uuid4()}")
    with patch.object(branches.AWSInfrastructure, "model_validate", wraps=AWSInfrastructure.model_validate) as parse:
        first = branches.get_branch(bid)
        second = branches.get_branch(bid)
        assert parse.call_count <= 1, f"base parsed {parse.call_count} times for two reads"
    first.base.s3.buckets[0].name = "changed-by-caller"
    assert branches.get_branch(bid).base.s3.buckets[0].name == "law92-bucket"
    assert second.base.s3.buckets[0].name == "law92-bucket"


def test_L92b_list_never_reads_a_base_snapshot():
    analysis = f"analysis-92b-{uuid.uuid4()}"
    for i in range(3):
        _new(f"law92b-{i}", analysis)
    branches._clear_branch_caches()
    with patch.object(branches.AWSInfrastructure, "model_validate", side_effect=AssertionError("snapshot parsed")):
        rows = branches.list_branch_summaries(analysis)
    assert {r["name"] for r in rows} >= {"law92b-0", "law92b-1", "law92b-2"}
    assert all(set(r) >= {"branch_id", "name", "status", "base_analysis_id", "num_changes"} for r in rows)


def test_L92c_visibility_reads_metadata_only_and_is_remembered():
    bid = _new("law92c", None)

    class Caller:
        mode = "hosted"
        project_id = "p-92"

    session = SessionLocal()
    try:
        with patch.object(branches.AWSInfrastructure, "model_validate", side_effect=AssertionError("snapshot parsed")):
            assert main._branch_is_visible(bid, Caller(), session) is False  # ownerless: hidden
        with patch.object(branches, "get_branch_meta", side_effect=AssertionError("not remembered")):
            assert main._branch_is_visible(bid, Caller(), session) is False
    finally:
        session.close()
