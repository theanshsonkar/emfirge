import json
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app import branches, database, in_use_evidence, main
from app.delete_lens import analyze_deletions
from app.mutations import Change, apply_change
from app.evidence_models import EvidenceRecord, METRIC_SPECS
from app.in_use_evidence import build_estimate, read_evidence
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
CREDS = {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"}


def resource(kind, rid="resource-1"):
    return SimpleNamespace(resource_type=kind, resource_id=rid, dimension_value=rid)


class FakeMetric:
    def __init__(self, values=None, error=None):
        self.values = values or {}
        self.error = error
        self.calls = []

    def get_metric_statistics(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        metric = kwargs["MetricName"]
        return {"Datapoints": self.values.get(metric, [])}


class FakeTrail:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0) if self.pages else {"Events": []}


def points(stat, values, day=0):
    return [{"Timestamp": NOW - timedelta(days=day + i), stat: value} for i, value in enumerate(values)]


@pytest.mark.parametrize("kind, expected", [
    ("ec2_instance", METRIC_SPECS["ec2_instance"]),
    ("rds_instance", METRIC_SPECS["rds_instance"]),
    ("lambda_function", METRIC_SPECS["lambda_function"]),
    ("ebs_volume", METRIC_SPECS["ebs_volume"]),
    ("s3_bucket", METRIC_SPECS["s3_bucket"]),
])
def test_metric_query_shape(kind, expected):
    fake = FakeMetric()
    read_evidence(CREDS, "ap-south-1", [resource(kind)], ["cloudwatch_metrics"], now=NOW,
                  own_session_name="session", client_factory=lambda service, region, creds: fake, sleep=lambda _: None)
    assert [(c["Namespace"], c["MetricName"], c["Dimensions"][0]["Name"], c["Statistics"][0]) for c in fake.calls] == expected
    for call in fake.calls:
        assert call["Period"] == 86400
        assert call["StartTime"] == NOW - timedelta(days=90)
        assert call["EndTime"] == NOW
    assert fake.calls[-1]["Dimensions"][-1:] == ([{"Name": "StorageType", "Value": "AllStorageTypes"}] if kind == "s3_bucket" else fake.calls[-1]["Dimensions"][-1:])


@pytest.mark.parametrize("kind, metric, stat, value, used", [
    ("ec2_instance", "CPUUtilization", "Maximum", 4.99, False),
    ("ec2_instance", "CPUUtilization", "Maximum", 5.0, True),
    ("rds_instance", "DatabaseConnections", "Maximum", 0, False),
    ("rds_instance", "DatabaseConnections", "Maximum", 1, True),
    ("lambda_function", "Invocations", "Sum", 0, False),
    ("lambda_function", "Invocations", "Sum", 1, True),
])
def test_usage_thresholds(kind, metric, stat, value, used):
    fake = FakeMetric({metric: points(stat, [value])})
    record = read_evidence(CREDS, "r", [resource(kind)], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.used is used


@pytest.mark.parametrize("total, used", [(4_999_999, False), (5_000_000, True)])
def test_ec2_network_same_day_threshold(total, used):
    fake = FakeMetric({"CPUUtilization": [], "NetworkIn": points("Sum", [total // 2]),
                       "NetworkOut": points("Sum", [total - total // 2])})
    record = read_evidence(CREDS, "r", [resource("ec2_instance")], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.used is used


def test_ebs_read_write_ops_and_no_data():
    fake = FakeMetric({"VolumeReadOps": [], "VolumeWriteOps": points("Sum", [1])})
    record = read_evidence(CREDS, "r", [resource("ebs_volume")], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.used is True
    empty = FakeMetric()
    record = read_evidence(CREDS, "r", [resource("ebs_volume")], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: empty, sleep=lambda _: None)[0]
    assert record.status == "no_data" and record.used is False


def test_s3_holds_data_uses_latest():
    fake = FakeMetric({"NumberOfObjects": points("Average", [0, 4])})
    record = read_evidence(CREDS, "r", [resource("s3_bucket", "bucket")], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.holds_data is False
    assert record.status == "ok"


@pytest.mark.parametrize("exc, status", [
    (ClientError({"Error": {"Code": "AccessDenied", "Message": "CUSTOM_MARKER"}}, "GetMetricStatistics"), "denied"),
    (RuntimeError("CUSTOM_MARKER"), "error"),
])
def test_metric_errors_are_safe(exc, status):
    fake = FakeMetric(error=exc)
    record = read_evidence(CREDS, "r", [resource("rds_instance")], ["cloudwatch_metrics"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.status == status and "CUSTOM_MARKER" not in record.model_dump_json()


def test_cloudtrail_filters_pages_and_throttles():
    marker = "CUSTOM_MARKER"
    trail = FakeTrail([
        {"Events": [{"ReadOnly": "true", "Username": "owner"}, {"Username": "session"}], "NextToken": "p2"},
        {"Events": [{"Username": "customer", "EventName": "DeleteBucket", "EventTime": NOW - timedelta(days=1),
                      "SourceIPAddress": marker, "AccessKeyId": marker, "CloudTrailEvent": marker}]},
    ])
    sleeps = []
    records = read_evidence(CREDS, "ap-south-1", [resource("s3_bucket", "b")], ["cloudtrail_events"], now=NOW,
                            own_session_name="session", client_factory=lambda *_: trail, sleep=sleeps.append)
    assert records[0].status == "ok" and records[0].event_name == "DeleteBucket"
    assert len(trail.calls) == 2 and sleeps == [0.5]
    assert marker not in records[0].model_dump_json()


def test_cloudtrail_incomplete_and_invalid_event_names():
    trail = FakeTrail([{"Events": [], "NextToken": "1"}, {"Events": [], "NextToken": "2"}, {"Events": [], "NextToken": "3"}])
    record = read_evidence(CREDS, "r", [resource("iam_role", "arn:role")], ["cloudtrail_events"], now=NOW,
                           own_session_name="s", client_factory=lambda *_: trail, sleep=lambda _: None)[0]
    assert record.status == "unknown"
    for bad in ("Delete Bucket", "Delete/Bucket"):
        trail = FakeTrail([{"Events": [{"EventName": bad}]}])
        record = read_evidence(CREDS, "r", [resource("s3_bucket")], ["cloudtrail_events"], now=NOW,
                               own_session_name="s", client_factory=lambda *_: trail, sleep=lambda _: None)[0]
        assert record.event_name is None


def test_iam_role_uses_global_trail_region_and_shared_throttle():
    calls, sleeps = [], []
    trail = FakeTrail([{"Events": []}])
    def factory(service, region, creds):
        calls.append((service, region))
        return trail
    read_evidence(CREDS, "eu-west-1", [resource("iam_role"), resource("s3_bucket")], ["cloudtrail_events"], now=NOW,
                  own_session_name="s", client_factory=factory, sleep=sleeps.append)
    assert calls == [("cloudtrail", "us-east-1"), ("cloudtrail", "eu-west-1")]
    assert sleeps == [0.5]


def test_estimate_is_deterministic_and_has_no_clients():
    base = load_synthetic_base("delete")
    branch = base.model_copy(deep=True)
    branch._deletions = [{"resource_type": "rds_instance", "resource_id": "db-dl-prod"}]
    estimate = build_estimate(base, branch, "rev", ["cloudwatch_metrics"])
    assert estimate.calls[0].max_requests == 1
    assert [(r.resource_type, r.resource_id) for r in estimate.resources] == [("rds_instance", "db-dl-prod")]
    assert estimate.estimate_id == build_estimate(base, branch, "rev", ["cloudwatch_metrics"]).estimate_id


def test_verdict_evidence_is_monotonic_and_recent_activity():
    base = load_synthetic_base("delete")
    branch = base.model_copy(deep=True)
    branch._deletions = [{"resource_type": "rds_instance", "resource_id": "db-dl-prod"}]
    record = EvidenceRecord(resource_id="db-dl-prod", resource_type="rds_instance", source="cloudwatch_metrics",
                            status="ok", used=True, window_days=90, observed_at=NOW.isoformat())
    result = combined_verdict(base, branch, run_scanners=False, evidence=[record])
    assert result.verdict == "block" and any(r["code"] == "recently_used" for r in result.reasons)


@pytest.fixture
def evidence_client(monkeypatch, tmp_path):
    engine = database.create_engine(f"sqlite:///{tmp_path / 'evidence.sqlite'}") if hasattr(database, "create_engine") else None
    if engine is None:
        from sqlalchemy import create_engine
        engine = create_engine(f"sqlite:///{tmp_path / 'evidence.sqlite'}")
    database.Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _: load_synthetic_base("delete"))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _: None)
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app), factory
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def test_http_estimate_stale_id_and_invalid_payload_have_no_customer_echo(evidence_client, monkeypatch):
    client, factory = evidence_client
    analysis = "analysis-111122223333"
    session = factory()
    session.add(database.AnalysisLog(aws_account_id="111122223333", findings_json=json.dumps({"analysis_id": analysis})))
    session.commit(); session.close()
    branch_id = client.post("/branches", json={"base_analysis_id": analysis, "name": "evidence"}).json()["branch_id"]
    estimate = client.get(f"/branches/{branch_id}/in-use-evidence/estimate?sources=cloudwatch_metrics").json()
    assert estimate["calls"]
    response = client.post(f"/branches/{branch_id}/in-use-evidence", json={"role_arn": "arn:aws:iam::111122223333:role/Role", "sources": ["cloudwatch_metrics"], "accept_estimate_id": "0" * 64})
    assert response.status_code == 409 and estimate["estimate_id"] in response.text
    bad = client.get(f"/branches/{branch_id}/in-use-evidence/estimate?sources=bad,CUSTOM_MARKER")
    assert bad.status_code == 422 and "CUSTOM_MARKER" not in bad.text


def test_http_verdict_without_evidence_matches_explicit_none(evidence_client):
    client, factory = evidence_client
    analysis = "analysis-plain"
    session = factory(); session.add(database.AnalysisLog(aws_account_id="111122223333", findings_json=json.dumps({"analysis_id": analysis}))); session.commit(); session.close()
    branch_id = client.post("/branches", json={"base_analysis_id": analysis, "name": "plain"}).json()["branch_id"]
    response = client.get(f"/branches/{branch_id}/verdict")
    assert response.status_code == 200
    branch = branches.get_branch(branch_id)
    assert response.json() == combined_verdict(branch.base, branches.rebuild_branch_state(branch), run_scanners=False, evidence=None).model_dump(mode="json") | {"branch_revision": branches.branch_revision(branch)}


ROLE = "arn:aws:iam::111122223333:role/EmfirgeRole"
PLANTED = ("PLANTED_USER", "203.0.113.9", "PLANTEDKEYID", "PLANTED_RAW_EVENT")
LAMBDA = "dl-worker"


def _iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _seed(factory, analysis, account="111122223333"):
    session = factory()
    session.add(database.AnalysisLog(aws_account_id=account, findings_json=json.dumps({"analysis_id": analysis})))
    session.commit()
    session.close()


def _branch_deleting(client, analysis, deletes):
    branch_id = client.post("/branches", json={"base_analysis_id": analysis, "name": "ev"}).json()["branch_id"]
    for typ, rid in deletes:
        response = client.post(f"/branches/{branch_id}/changes", json={"op": "delete", "resource_type": typ, "resource_id": rid})
        assert response.status_code == 200, response.text
    return branch_id


class Recorder:
    def __init__(self):
        self.sts, self.clients, self.account = [], [], "111122223333"

    def assume(self, role_arn, _caller, _db):
        self.sts.append(role_arn)
        return CREDS, self.account


@pytest.fixture
def wired(evidence_client, monkeypatch):
    client, factory = evidence_client
    rec = Recorder()
    metric = FakeMetric({"Invocations": points("Sum", [3])})
    trail = FakeTrail([{"Events": [{"ReadOnly": "false", "Username": PLANTED[0], "SourceIPAddress": PLANTED[1],
                                    "AccessKeyId": PLANTED[2], "CloudTrailEvent": PLANTED[3],
                                    "EventName": "UpdateFunctionCode", "EventTime": datetime.now(timezone.utc) - timedelta(days=2)}]}])

    def make(service, region, creds):
        rec.clients.append((service, region))
        return metric if service == "cloudwatch" else trail

    monkeypatch.setattr(main, "assume_role_credentials", rec.assume)
    monkeypatch.setattr(in_use_evidence, "_default_client", make)
    monkeypatch.setattr(in_use_evidence, "_sleep", lambda _: None)
    return client, factory, rec


def _accept(client, branch_id, role=ROLE):
    estimate = client.get(f"/branches/{branch_id}/in-use-evidence/estimate").json()
    return estimate, client.post(f"/branches/{branch_id}/in-use-evidence",
                                 json={"role_arn": role, "sources": estimate["sources"], "accept_estimate_id": estimate["estimate_id"]})


def test_http_accepted_estimate_reads_and_blocks(wired):
    client, factory, rec = wired
    _seed(factory, "an-ok")
    branch_id = _branch_deleting(client, "an-ok", [("lambda_function", LAMBDA)])
    before = client.get(f"/branches/{branch_id}/verdict").json()
    estimate = client.get(f"/branches/{branch_id}/in-use-evidence/estimate").json()
    assert rec.sts == [] and rec.clients == []
    _, response = _accept(client, branch_id)
    assert response.status_code == 200, response.text
    assert rec.sts == [ROLE]
    assert {r["source"] for r in response.json()["records"]} == {"cloudwatch_metrics", "cloudtrail_events"}
    after = client.get(f"/branches/{branch_id}/verdict")
    for text in (response.text, after.text, json.dumps(estimate)):
        assert ROLE not in text
        for planted in PLANTED:
            assert planted not in text
    after = after.json()
    codes = {r["code"] for r in after["reasons"]}
    assert after["verdict"] == "block" and "recently_used" in codes and "recent_activity" in codes
    assert {r["code"] for r in before["reasons"]} <= codes
    assert {"cloudwatch_metrics", "cloudtrail_events"} <= set(after["deletion"]["coverage"]["can_see"])


@pytest.mark.parametrize("seed_account", ["444455556666", None])
def test_http_account_mismatch_makes_no_aws_call(wired, seed_account):
    client, factory, rec = wired
    if seed_account:
        _seed(factory, "an-mm", seed_account)
    branch_id = _branch_deleting(client, "an-mm", [("lambda_function", LAMBDA)])
    _, response = _accept(client, branch_id)
    assert response.status_code == 409
    assert rec.sts == [] and rec.clients == []


def test_http_assumed_account_differs_reads_nothing(wired):
    client, factory, rec = wired
    rec.account = "999988887777"
    _seed(factory, "an-assumed")
    branch_id = _branch_deleting(client, "an-assumed", [("lambda_function", LAMBDA)])
    _, response = _accept(client, branch_id)
    assert response.status_code == 409
    assert rec.sts == [ROLE] and rec.clients == []


def test_http_stale_estimate_after_branch_change_makes_no_call(wired):
    client, factory, rec = wired
    _seed(factory, "an-stale")
    branch_id = _branch_deleting(client, "an-stale", [("lambda_function", LAMBDA)])
    estimate = client.get(f"/branches/{branch_id}/in-use-evidence/estimate").json()
    second = ("ec2_instance", "i-dl-web")
    assert client.post(f"/branches/{branch_id}/changes", json={"op": "delete", "resource_type": second[0], "resource_id": second[1]}).status_code == 200
    response = client.post(f"/branches/{branch_id}/in-use-evidence",
                           json={"role_arn": ROLE, "sources": estimate["sources"], "accept_estimate_id": estimate["estimate_id"]})
    assert response.status_code == 409
    assert response.json()["estimate"]["estimate_id"] != estimate["estimate_id"]
    assert rec.sts == [] and rec.clients == []


def test_http_too_many_resources_is_422_without_calls(wired, monkeypatch):
    client, factory, rec = wired
    monkeypatch.setattr(in_use_evidence, "MAX_EVIDENCE_RESOURCES", 0)
    _seed(factory, "an-many")
    branch_id = _branch_deleting(client, "an-many", [("lambda_function", LAMBDA)])
    _, response = _accept(client, branch_id)
    assert response.status_code == 422
    assert rec.sts == [] and rec.clients == []


@pytest.mark.parametrize("patch", [
    {"role_arn": "arn:aws:iam::111122223333:user/CUSTOM_MARKER"},
    {"sources": ["cloudwatch_metrics", "cloudwatch_metrics"]},
    {"sources": ["CUSTOM_MARKER"]},
    {"accept_estimate_id": "CUSTOM_MARKER"},
    {"extra_field": "CUSTOM_MARKER"},
])
def test_http_invalid_post_is_422_without_echo_or_calls(wired, patch):
    client, factory, rec = wired
    _seed(factory, "an-bad")
    branch_id = _branch_deleting(client, "an-bad", [("lambda_function", LAMBDA)])
    body = {"role_arn": ROLE, "sources": ["cloudwatch_metrics"], "accept_estimate_id": "0" * 64, **patch}
    response = client.post(f"/branches/{branch_id}/in-use-evidence", json=body)
    assert response.status_code == 422
    assert "CUSTOM_MARKER" not in response.text
    assert rec.sts == [] and rec.clients == []


@pytest.mark.parametrize("days, expected", [(89, True), (90, True), (91, False)])
def test_recent_activity_window_uses_observed_at(days, expected):
    base = load_synthetic_base("delete")
    branch = apply_change(base, Change(op="delete", resource_type="lambda_function", resource_id=LAMBDA))
    record = EvidenceRecord(resource_id=LAMBDA, resource_type="lambda_function", source="cloudtrail_events", status="ok",
                            used=None, window_days=90, observed_at=_iso(NOW), last_event_at=_iso(NOW - timedelta(days=days)))
    result = combined_verdict(base, branch, run_scanners=False, evidence=[record])
    assert ("recent_activity" in {r["code"] for r in result.reasons}) is expected


def test_s3_no_data_does_not_claim_cloudwatch_coverage():
    base = load_synthetic_base("delete")
    bucket = "dl-data-bucket"
    branch = apply_change(base, Change(op="delete", resource_type="s3_bucket", resource_id=bucket))
    record = EvidenceRecord(resource_id=bucket, resource_type="s3_bucket", source="cloudwatch_metrics", status="no_data",
                            used=None, window_days=90, observed_at=_iso(NOW))
    lens = analyze_deletions(base, branch, evidence=[record])
    assert "cloudwatch_metrics" in lens.coverage.cannot_see and "cloudwatch_metrics" not in lens.coverage.can_see
