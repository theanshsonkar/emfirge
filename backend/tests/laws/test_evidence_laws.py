import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from hypothesis import HealthCheck, assume, given, settings, strategies as st

from app import database, in_use_evidence, main
from app.evidence_models import METRIC_SPECS, EvidenceRecord
from app.in_use_evidence import read_evidence
from app.mutations import Change, apply_change, deletion_ledger
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base
from tests.test_in_use_evidence import evidence_client  # noqa: F401

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
CREDS = {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"}
ROLE = "arn:aws:iam::111122223333:role/EmfirgeRole"
RANK = {"pass": 0, "warn": 1, "block": 2}
SOURCES = ["cloudtrail_events", "cloudwatch_metrics"]
STATUSES = ["ok", "no_data", "denied", "error", "incomplete", "unknown"]
USAGE_TYPES = {"ec2_instance", "rds_instance", "lambda_function", "ebs_volume"}
SETTINGS = dict(deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])


def _iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _candidates(base):
    """Every (resource_type, resource_id) in the delete base that op=delete can target, using the id format the branch API uses."""
    values = []
    values += [("ec2_instance", item.id) for item in base.ec2.instances]
    values += [("ebs_volume", item.id) for item in base.ec2.ebs_volumes]
    values += [("ebs_snapshot", item.id) for item in base.ec2.ebs_snapshots]
    values += [("rds_instance", item.id) for item in base.rds.rds_instances]
    values += [("rds_snapshot", item.id) for item in base.rds.rds_snapshots]
    values += [("s3_bucket", item.name) for item in base.s3.buckets]
    values += [("iam_role", item.role_arn) for item in base.iam.role_policies]
    values += [("lambda_function", item.name) for item in base.lambda_data.functions]
    return sorted(values)


def _apply(base, picks):
    branch, done = base, []
    for typ, rid in picks:
        try:
            branch = apply_change(branch, Change(op="delete", resource_type=typ, resource_id=rid))
        except Exception:
            continue
        done.append((typ, rid))
    return branch, done


def _codes(result):
    return {reason["code"] for reason in result.reasons}


def _record(draw, typ, rid):
    return EvidenceRecord(
        resource_id=rid, resource_type=typ, source=draw(st.sampled_from(SOURCES)),
        status=draw(st.sampled_from(STATUSES)), used=draw(st.sampled_from([True, False, None])),
        holds_data=draw(st.sampled_from([True, False, None])), window_days=90, observed_at=_iso(NOW),
        last_event_at=draw(st.one_of(st.none(), st.integers(-200, 200).map(lambda d: _iso(NOW - timedelta(days=d))))),
        event_name=draw(st.one_of(st.none(), st.sampled_from(["DeleteBucket", "ModifyDBInstance"]))),
    )


@settings(max_examples=60, **SETTINGS)
@given(data=st.data())
def test_L12_evidence_never_lowers_the_verdict(data):
    base = load_synthetic_base("delete")
    cands = _candidates(base)
    branch, done = _apply(base, data.draw(st.lists(st.sampled_from(cands), min_size=1, max_size=3, unique=True)))
    assume(done)
    ledger_ids = {str(item["resource_id"]) for item in deletion_ledger(branch)}
    records = [_record(data.draw, typ, rid) for typ, rid in data.draw(st.lists(st.sampled_from(cands), min_size=1, max_size=6))]
    without = combined_verdict(base, branch, run_scanners=False)
    with_evidence = combined_verdict(base, branch, run_scanners=False, evidence=records)
    assert RANK[with_evidence.verdict] >= RANK[without.verdict]
    assert _codes(without) <= _codes(with_evidence)
    assert {(d.resource_id, d.why) for d in without.deletion.data_lost} <= {(d.resource_id, d.why) for d in with_evidence.deletion.data_lost}
    outside = [record for record in records if record.resource_id not in ledger_ids]
    only_outside = combined_verdict(base, branch, run_scanners=False, evidence=outside)
    assert only_outside.model_dump(mode="json") == without.model_dump(mode="json")


def _daily(stat, values):
    return [{"Timestamp": NOW - timedelta(days=i), stat: value} for i, value in enumerate(values)]


NEAR = {
    "CPUUtilization": st.sampled_from([0.0, 1.0, 4.99, 5.0, 5.01, 80.0]),
    "NetworkIn": st.sampled_from([0, 1, 2_499_999, 2_500_000, 4_999_999, 5_000_000, 9_000_000]),
    "NetworkOut": st.sampled_from([0, 1, 2_499_999, 2_500_000, 4_999_999, 5_000_000, 9_000_000]),
}


@settings(max_examples=80, **SETTINGS)
@given(data=st.data())
def test_L13_usage_metrics_block_exactly(data):
    base = load_synthetic_base("delete")
    typ, rid = data.draw(st.sampled_from([c for c in _candidates(base) if c[0] in USAGE_TYPES]))
    branch, done = _apply(base, [(typ, rid)])
    assume(done)
    series = {}
    for _namespace, metric, _dimension, stat in METRIC_SPECS[typ]:
        values = data.draw(st.lists(NEAR.get(metric, st.sampled_from([0, 0, 1, 7, 1000])), max_size=5))
        series[metric] = _daily(stat, values)
    if typ == "ec2_instance":
        per_day = {}
        for metric in ("NetworkIn", "NetworkOut"):
            for point in series[metric]:
                per_day[point["Timestamp"]] = per_day.get(point["Timestamp"], 0) + point["Sum"]
        expected = any(p["Maximum"] >= 5.0 for p in series["CPUUtilization"]) or any(v >= 5_000_000 for v in per_day.values())
    else:
        expected = any(point[stat] > 0 for _n, metric, _d, stat in METRIC_SPECS[typ] for point in series[metric])
    fake = SimpleNamespace(get_metric_statistics=lambda **kw: {"Datapoints": series[kw["MetricName"]]})
    target = SimpleNamespace(resource_type=typ, resource_id=rid, dimension_value=rid)
    record = read_evidence(CREDS, "ap-south-1", [target], ["cloudwatch_metrics"], now=NOW, own_session_name="s",
                           client_factory=lambda *_: fake, sleep=lambda _: None)[0]
    assert record.used is expected
    without = combined_verdict(base, branch, run_scanners=False)
    result = combined_verdict(base, branch, run_scanners=False, evidence=[record])
    cloudwatch_block = any(r["code"] == "recently_used" and "CloudWatch" in r["message"] for r in result.reasons)
    assert cloudwatch_block is expected
    if expected:
        assert result.verdict == "block"
    else:
        assert result.model_dump(mode="json")["verdict"] == without.verdict


@settings(max_examples=30, **SETTINGS)
@given(data=st.data())
def test_L14_cost_is_shown_before_any_read(evidence_client, monkeypatch, data):
    client, factory = evidence_client
    calls = []
    monkeypatch.setattr(main, "assume_role_credentials", lambda arn, _caller, _db: calls.append(("sts", arn)) or (CREDS, "111122223333"))
    monkeypatch.setattr(in_use_evidence, "_default_client", lambda *args: calls.append(("client", args[0])))
    analysis = f"an-{uuid.uuid4()}"
    session = factory()
    session.add(database.AnalysisLog(aws_account_id="111122223333", findings_json=json.dumps({"analysis_id": analysis})))
    session.commit()
    session.close()
    branch_id = client.post("/branches", json={"base_analysis_id": analysis, "name": "law14"}).json()["branch_id"]
    cands = _candidates(load_synthetic_base("delete"))
    picks = data.draw(st.lists(st.sampled_from(cands), min_size=1, max_size=2, unique=True))
    applied = [p for p in picks if client.post(f"/branches/{branch_id}/changes", json={"op": "delete", "resource_type": p[0], "resource_id": p[1]}).status_code == 200]
    assume(applied)
    sources = data.draw(st.lists(st.sampled_from(SOURCES), min_size=1, max_size=2, unique=True))
    path = f"/branches/{branch_id}/in-use-evidence"
    first = client.get(f"{path}/estimate?sources={','.join(sources)}").json()
    again = client.get(f"{path}/estimate?sources={','.join(reversed(sources))}").json()
    assert first["estimate_id"] == again["estimate_id"]
    wrong = data.draw(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64).filter(lambda s: s != first["estimate_id"]))
    response = client.post(path, json={"role_arn": ROLE, "sources": sources, "accept_estimate_id": wrong})
    assert response.status_code == 409
    assert response.json()["estimate"]["estimate_id"] == first["estimate_id"]
    other_sources = [s for s in SOURCES if s not in sources] or [sources[0]]
    if sorted(other_sources) != sorted(sources):
        assert client.get(f"{path}/estimate?sources={','.join(other_sources)}").json()["estimate_id"] != first["estimate_id"]
    extra = next((c for c in cands if c not in applied and client.post(f"/branches/{branch_id}/changes", json={"op": "delete", "resource_type": c[0], "resource_id": c[1]}).status_code == 200), None)
    if extra is not None:
        assert client.get(f"{path}/estimate?sources={','.join(sources)}").json()["estimate_id"] != first["estimate_id"]
    assert calls == []
