"""L71a Privacy purge: one registry covers every table; purge removes every account-linked row.

No AWS: the role check is stubbed and S3 is moto.
"""
import json
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app import database, main
from app.main import app

A, B = "111122223333", "444455556666"
UUID_A, UUID_B = "aaaaaaaa-0000-4000-8000-000000000001", "bbbbbbbb-0000-4000-8000-000000000002"
BUCKET = "emfirge-test-reports"


def _privacy():
    from app import privacy
    return privacy


def test_L71a_registry_every_table_is_in_the_purge_plan_and_every_entry_is_a_table():
    plan = _privacy().PURGE_PLAN
    tables = set(database.Base.metadata.tables)
    assert tables - set(plan) == set(), "tables missing from PURGE_PLAN"
    assert set(plan) - tables == set(), "PURGE_PLAN names unknown tables"
    for name, rule in plan.items():
        if rule.kind == "kept":
            assert rule.detail.strip(), f"{name}: kept without a reason"


def _seed(db, account, uuid, project_id):
    D = database
    db.add_all([
        D.AnalysisLog(aws_account_id=account, findings_json=json.dumps({"analysis_id": uuid}), risk_score=1),
        D.DriftEvent(aws_account_id=account, change_type="new_finding"),
        D.SimulationLog(aws_account_id=account, analysis_id=uuid, query="q"),
        D.Feedback(aws_account_id=account, message="m"),
        D.LLMUsage(aws_account_id=account, endpoint_type="insight"),
        D.AccountBinding(aws_account_id=account, project_id=project_id),
        D.AccountBindingEvent(aws_account_id=account, project_id=project_id, action="bind", actor="t"),
    ])
    branch = f"branch-{account}"
    db.add_all([
        D.BranchLog(branch_id=branch, name="n", base_analysis_id=uuid, base_infra_json="{}"),
        D.BranchOwner(branch_id=branch, project_id=project_id),
        D.PlanLog(plan_id=f"plan-{account}", branch_id=branch, input_sha256="0" * 64, raw_input="",
                  branch_revision_after="r"),
        D.BranchEvidenceLog(branch_id=branch, estimate_id="e"),
        D.BranchPolicyCheckLog(branch_id=branch, branch_revision="r", estimate_id="e"),
    ])


def _count_for(db, account, uuid):
    D = database
    branch = f"branch-{account}"
    return {
        "analysis_logs": db.query(D.AnalysisLog).filter_by(aws_account_id=account).count(),
        "drift_events": db.query(D.DriftEvent).filter_by(aws_account_id=account).count(),
        "simulation_logs": db.query(D.SimulationLog).filter_by(aws_account_id=account).count(),
        "feedback": db.query(D.Feedback).filter_by(aws_account_id=account).count(),
        "llm_usage": db.query(D.LLMUsage).filter_by(aws_account_id=account).count(),
        "account_bindings": db.query(D.AccountBinding).filter_by(aws_account_id=account).count(),
        "account_binding_events": db.query(D.AccountBindingEvent).filter_by(aws_account_id=account).count(),
        "branch_logs": db.query(D.BranchLog).filter_by(branch_id=branch).count(),
        "branch_owners": db.query(D.BranchOwner).filter_by(branch_id=branch).count(),
        "plan_logs": db.query(D.PlanLog).filter_by(branch_id=branch).count(),
        "branch_evidence_logs": db.query(D.BranchEvidenceLog).filter_by(branch_id=branch).count(),
        "branch_policy_check_logs": db.query(D.BranchPolicyCheckLog).filter_by(branch_id=branch).count(),
    }


@pytest.fixture
def client(shared_test_db, monkeypatch):
    monkeypatch.setattr(main, "assume_customer_role", lambda *a, **k: ({}, A))
    monkeypatch.delenv("S3_BUCKET_NAME", raising=False)
    return TestClient(app)


def test_L71a_end_to_end_purge_removes_every_account_row_and_leaves_other_accounts(client):
    with database.SessionLocal() as db:
        project = database.Project(name="p", external_id="x")
        db.add(project)
        db.flush()
        _seed(db, A, UUID_A, project.id)
        _seed(db, B, UUID_B, project.id)
        db.commit()
        before_b = _count_for(db, B, UUID_B)
        assert all(v == 1 for v in _count_for(db, A, UUID_A).values())
    response = client.post("/privacy/purge", json={"role_arn": f"arn:aws:iam::{A}:role/R"})
    assert response.status_code == 200, response.text
    body = response.json()
    with database.SessionLocal() as db:
        assert _count_for(db, A, UUID_A) == {k: 0 for k in before_b}
        assert _count_for(db, B, UUID_B) == before_b
        assert db.query(database.Project).count() == 1  # login is not account data
    for table in before_b:
        assert body["deleted"][table] == 1, table
    assert body["deleted"]["s3_objects"] == 0


@mock_aws
def test_L71a_s3_purge_deletes_only_the_accounts_s3_reports(shared_test_db, monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y", "AWS_REGION": "us-east-1",
                 "S3_BUCKET_NAME": BUCKET}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(main, "assume_customer_role", lambda *a, **k: ({}, A))
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    for uuid in (UUID_A, UUID_B):
        s3.put_object(Bucket=BUCKET, Key=f"reports/2026-01-01/analysis-{uuid}.json", Body=b"{}")
    with database.SessionLocal() as db:
        project = database.Project(name="p", external_id="x")
        db.add(project)
        db.flush()
        _seed(db, A, UUID_A, project.id)
        _seed(db, B, UUID_B, project.id)
        db.commit()
    response = TestClient(app).post("/privacy/purge", json={"role_arn": f"arn:aws:iam::{A}:role/R"})
    assert response.status_code == 200, response.text
    assert response.json()["deleted"]["s3_objects"] == 1
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])]
    assert keys == [f"reports/2026-01-01/analysis-{UUID_B}.json"]
