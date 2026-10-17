import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from botocore.exceptions import ClientError

from app.evidence_models import EvidenceRecord
from app.in_use_evidence import read_evidence
from app.mutations import Change, apply_change
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base


NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
CREDS = {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"}
START = NOW - timedelta(days=90)


class FakeTrail:
    def __init__(self, pages):
        self.pages = list(pages)

    def lookup_events(self, **kwargs):
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def resource(resource_id="resource-1"):
    return SimpleNamespace(resource_type="lambda_function", resource_id=resource_id, dimension_value=resource_id)


def read(trail):
    return read_evidence(
        CREDS, "ap-south-1", [resource()], ["cloudtrail_events"], now=NOW,
        own_session_name="owner", client_factory=lambda *_: trail, sleep=lambda _: None,
    )[0]


def denied():
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "access denied"}},
        "LookupEvents",
    )


def throttled():
    return ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "throttled"}},
        "LookupEvents",
    )


def test_access_denied_is_unknown_not_unused():
    record = read(FakeTrail([denied()]))
    assert record.status == "unknown"
    assert record.status != "no_data"


def test_throttling_mid_pagination_is_unknown():
    record = read(FakeTrail([{"Events": [], "NextToken": "page-2"}, throttled()]))
    assert record.status == "unknown"


def test_history_starting_after_requested_window_is_unknown():
    record = read(FakeTrail([{
        "TrailStartTime": START + timedelta(days=1),
        "Events": [{"EventName": "UpdateFunctionCode", "EventTime": START + timedelta(days=1)}],
    }]))
    assert record.status == "unknown"


def test_complete_window_with_no_events_is_no_data():
    record = read(FakeTrail([{"Events": []}]))
    assert record.status == "no_data"


def test_complete_window_with_event_is_in_use():
    record = read(FakeTrail([{
        "Events": [{"EventName": "UpdateFunctionCode", "EventTime": NOW - timedelta(days=1)}],
    }]))
    assert record.status == "ok"
    assert record.last_event_at is not None


def test_unknown_cloudtrail_evidence_cannot_pass_delete():
    base = load_synthetic_base("delete")
    branch = apply_change(base, Change(op="delete", resource_type="lambda_function", resource_id="dl-worker"))
    evidence = EvidenceRecord(
        resource_id="dl-worker", resource_type="lambda_function", source="cloudtrail_events",
        status="unknown", used=None, window_days=90, observed_at=NOW.isoformat(),
    )
    result = combined_verdict(base, branch, run_scanners=False, evidence=[evidence])
    assert result.verdict != "pass"
