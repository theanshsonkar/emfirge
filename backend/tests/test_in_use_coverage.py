from datetime import datetime, timezone

from app.delete_lens import analyze_deletions
from app.evidence_models import EvidenceRecord
from app.mutations import Change, apply_change
from tests.incidents.synthetic_base import load_synthetic_base


NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
RESOURCE_ID = "dl-worker"


def _lens(record):
    base = load_synthetic_base("delete")
    branch = apply_change(base, Change(op="delete", resource_type="lambda_function", resource_id=RESOURCE_ID))
    return analyze_deletions(base, branch, evidence=[record])


def _record(status, used):
    return EvidenceRecord(
        resource_id=RESOURCE_ID,
        resource_type="lambda_function",
        source="cloudwatch_metrics",
        status=status,
        used=used,
        window_days=90,
        observed_at=NOW.isoformat(),
    )


def test_in_use_coverage_distinguishes_unreadable_evidence_from_no_data():
    denied = _lens(_record("denied", None))
    error = _lens(_record("error", None))
    no_data = _lens(_record("no_data", False))

    assert any(
        f"recent use of {RESOURCE_ID}: could not check" in entry
        and "access denied" in entry
        for entry in denied.coverage.cannot_see
    )
    assert any(
        f"recent use of {RESOURCE_ID}: could not check" in entry
        and "read error" in entry
        for entry in error.coverage.cannot_see
    )
    assert not any(f"recent use of {RESOURCE_ID}" in entry for entry in no_data.coverage.cannot_see)
    assert denied.model_dump(mode="json") != no_data.model_dump(mode="json")
