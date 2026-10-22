
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from app.models import EBSVolume, RDSInstance, Route, RouteTable, S3Bucket, SecurityGroup
from tests.incidents.synthetic_base import load_synthetic_base


def synthetic_base():
    base = load_synthetic_base("delete")
    ec2 = base.ec2.model_copy(update={
        "security_groups": [SecurityGroup(id="sg-0aaa", name="synthetic", rules=[{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}])],
        "ebs_volumes": [EBSVolume(id="vol-0bbb", size_gb=8, volume_type="gp3")],
    })
    s3 = base.s3.model_copy(update={"buckets": [S3Bucket(name="synthetic-bucket", is_public=False)]})
    rds = base.rds.model_copy(update={"rds_instances": [RDSInstance(id="synthetic-db")]})
    vpc = base.vpc.model_copy(update={
        "route_tables": [RouteTable(id="rtb-0ccc", vpc_id="vpc-dl0001", routes=[Route(destination_cidr="10.20.0.0/16", target_type="local", target_id="local")])],
        "internet_gateway_attachments": [{"internet_gateway_id": "igw-0ddd", "vpc_id": "vpc-dl0001", "state": "available"}],
    })
    return base.model_copy(update={"ec2": ec2, "s3": s3, "rds": rds, "vpc": vpc})


def branch(client, name="typed"):
    response = client.post("/branches", json={"base_analysis_id": "synthetic", "name": name})
    assert response.status_code == 200, response.text
    return response.json()["branch_id"]


def change(client, branch_id, payload, expected=0):
    response = client.post(f"/branches/{branch_id}/changes", json={**payload, "expected_change_count": expected})
    assert response.status_code == 200, response.text


@pytest.fixture
def typed_client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'typed.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(verdict, "run_checkov", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_trivy", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(verdict, "run_cloudsplaining", lambda *_a, **_k: {"available": False, "findings": []})
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: synthetic_base())
    monkeypatch.setitem(main.app.dependency_overrides, main.require_api_key, lambda: None)
    yield TestClient(main.app)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


PLAN_GUIDANCE = (
    "This branch was built from a submitted plan. Hand back that original plan "
    "(terraform/aws-api/aws-cli) instead, or create a new branch from the base "
    "analysis and apply typed changes only."
)
UNMAPPABLE_GUIDANCE = (
    "These changes have no AWS API equivalent yet, so nothing was handed back. "
    "Roll the branch back to before them (or discard and recreate the branch "
    "without them) and hand back again, or apply them by hand outside Emfirge."
)


def test_plan_receipt_handback_explains_next_step(typed_client):
    bid = branch(typed_client, "plan-guidance")
    raw = (Path(__file__).parent / "incidents/fixtures/datatalks_destroy_plan.json").read_bytes()
    assert typed_client.post(f"/branches/{bid}/plans/terraform", content=raw).status_code == 200

    response = typed_client.get(f"/branches/{bid}/handback")

    assert response.status_code == 409
    assert response.json() == {"error": "branch_has_plan_receipts", "next_step": PLAN_GUIDANCE}


def test_unmappable_handback_explains_next_step_without_resource_id(typed_client):
    bid = branch(typed_client, "unmappable-guidance")
    resource_id = "synthetic-bucket"
    change(typed_client, bid, {"op": "modify", "resource_type": "s3_bucket", "resource_id": resource_id, "fields": {"is_public": True}})
    change(typed_client, bid, {"op": "add", "resource_type": "s3_bucket", "resource_id": "new-bucket", "fields": {}}, expected=1)

    response = typed_client.get(f"/branches/{bid}/handback")

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "unmappable_changes"
    assert [item["change_index"] for item in body["changes"]] == [0, 1]
    assert body["changes"][0]["reason"] == "field_not_mapped: is_public"
    assert body["changes"][1]["reason"] == "operation_not_mapped"
    assert body["next_step"] == UNMAPPABLE_GUIDANCE
    assert resource_id not in body["next_step"]
