"""L86 data honesty and mutation-testing survivors.

L86a  DynamoDB ItemCount 0 is unknown emptiness: "DynamoDB updates this value approximately every six hours.
      Recent changes might not be reflected in this value."
      https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html
      (fetched 2026-11-08). So 0 is never a recovery point and never proof of no data loss.
"""
from __future__ import annotations

from pathlib import Path

from app.delete_lens import analyze_deletions
from app.mutations import apply_change
from app.verdict import combined_verdict

from .test_check_facts_laws import _check, _dump
from .test_dynamodb_table_laws import ORDERS, base_with, data_facts, delete, table

APP = Path(__file__).resolve().parents[2] / "app"


def test_L86a_item_count_zero_is_never_a_recovery_point_in_any_answer():
    for extra in (dict(item_count=0), dict(item_count=0, item_count_reported=True)):
        base = base_with(table(**extra))
        branch = apply_change(base, delete())
        lens = analyze_deletions(base, branch)
        assert lens.recovery_points == [] and lens.data_lost == []
        assert [x.resource_id for x in lens.recovery_unknown] == [ORDERS]
        assert data_facts(_dump(_check(base, branch)))[0]["has_recovery_point"] is None
        got = {(r["code"] if isinstance(r, dict) else r.code) for r in combined_verdict(base, branch, run_scanners=False).reasons}
        assert "data_store_deleted_with_recovery_point" not in got and "data_store_deleted_recovery_unknown" in got


def test_L86a_the_reported_empty_kind_no_longer_exists():
    assert "reported_empty_table" not in "".join(p.read_text() for p in APP.glob("*.py"))
