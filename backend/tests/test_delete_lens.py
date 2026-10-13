from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.delete_lens import RECENT_USE_DAYS, recently_used_deleted
from app.mutations import Change, apply_change
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base


def _deleted_role(days_ago):
    base = load_synthetic_base("delete")
    stamp = datetime.fromisoformat(base.collected_at.replace("Z", "+00:00"))
    role = next(role for role in base.iam.role_policies if role.role_name == "DlBatchRole")
    role.last_used_at = (stamp - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    branch = apply_change(base, Change(op="delete", resource_type="iam_role", resource_id=role.role_arn))
    return base, branch


def test_recent_use_window_is_90_days():
    assert RECENT_USE_DAYS == 90


def test_role_used_before_recent_use_window_blocks_at_both_inclusive_boundaries():
    for days_ago in (RECENT_USE_DAYS - 1, RECENT_USE_DAYS):
        base, branch = _deleted_role(days_ago)
        result = combined_verdict(base, branch, run_scanners=False)
        assert result.verdict == "block"
        assert any(item["code"] == "recently_used" for item in result.reasons)


def test_role_used_after_recent_use_window_is_not_recently_used():
    base, branch = _deleted_role(RECENT_USE_DAYS + 1)
    assert not recently_used_deleted(base, branch)
