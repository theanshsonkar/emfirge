import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
from datetime import timedelta
from types import SimpleNamespace

from hypothesis import HealthCheck, given, settings, strategies as st

from app.evidence_models import EvidenceRecord
from app.in_use_evidence import read_evidence
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

NOW = __import__("datetime").datetime(2026, 10, 1, tzinfo=__import__("datetime").timezone.utc)
CREDS = {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"}


def _branch_with_deletes(base, deletes):
    branch = base.model_copy(deep=True)
    branch._deletions = [{"resource_type": typ, "resource_id": rid} for typ, rid in deletes]
    return branch


def _rank(value):
    return {"pass": 0, "warn": 1, "block": 2}[value]


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.booleans(), st.booleans())
def test_L12_evidence_never_lowers_the_verdict(used, holds_data):
    base = load_synthetic_base("delete")
    branch = _branch_with_deletes(base, [("rds_instance", "db-dl-prod")])
    record = EvidenceRecord(resource_id="db-dl-prod", resource_type="rds_instance", source="cloudwatch_metrics",
                            status="ok", used=used, holds_data=holds_data, window_days=90,
                            observed_at=NOW.isoformat())
    without = combined_verdict(base, branch, run_scanners=False, evidence=None)
    with_evidence = combined_verdict(base, branch, run_scanners=False, evidence=[record])
    assert _rank(with_evidence.verdict) >= _rank(without.verdict)
    assert {x["code"] for x in without.reasons} <= {x["code"] for x in with_evidence.reasons}


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(["ec2_instance", "rds_instance", "lambda_function", "ebs_volume"]), st.booleans())
def test_L13_usage_metrics_block_exactly(kind, used):
    ids = {"ec2_instance": "i-dl-web", "rds_instance": "db-dl-prod", "lambda_function": "dl-worker", "ebs_volume": "vol-dl-data"}
    metric = {"ec2_instance": "CPUUtilization", "rds_instance": "DatabaseConnections", "lambda_function": "Invocations", "ebs_volume": "VolumeReadOps"}[kind]
    stat = "Maximum" if kind in {"ec2_instance", "rds_instance"} else "Sum"
    fake = SimpleNamespace(get_metric_statistics=lambda **kwargs: {"Datapoints": [{"Timestamp": NOW, stat: 5 if used else 0}]})
    target = SimpleNamespace(resource_type=kind, resource_id=ids[kind], dimension_value=ids[kind])
    record = read_evidence(CREDS, "r", [target], ["cloudwatch_metrics"], now=NOW, own_session_name="s",
                           client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.used is used
    base = load_synthetic_base("delete")
    branch = _branch_with_deletes(base, [(kind, ids[kind])])
    result = combined_verdict(base, branch, run_scanners=False, evidence=[record])
    assert ("recently_used" in {x["code"] for x in result.reasons}) is used


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.permutations(["cloudtrail_events", "cloudwatch_metrics"]))
def test_L14_cost_is_shown_before_any_read(sources):
    base = load_synthetic_base("delete")
    branch = _branch_with_deletes(base, [("rds_instance", "db-dl-prod")])
    first = __import__("app.in_use_evidence", fromlist=["build_estimate"]).build_estimate(base, branch, "revision", list(sources))
    second = __import__("app.in_use_evidence", fromlist=["build_estimate"]).build_estimate(base, branch, "revision", list(reversed(sources)))
    assert first.estimate_id == second.estimate_id
    changed = _branch_with_deletes(base, [("rds_instance", "db-dl-reports")])
    assert first.estimate_id != __import__("app.in_use_evidence", fromlist=["build_estimate"]).build_estimate(base, changed, "revision", list(sources)).estimate_id
