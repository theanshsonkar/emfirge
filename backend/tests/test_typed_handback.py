import hashlib
import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import botocore.session
import pytest
from botocore.validate import ParamValidator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from app.models import EBSVolume, RDSInstance, Route, RouteTable, S3Bucket, SecurityGroup
from app.mutations import Change
from app.typed_handback import UnmappableChanges, build_api_calls, canonical_sha256
from tests.incidents.synthetic_base import load_synthetic_base


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
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


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


def assert_valid_calls(calls):
    session = botocore.session.get_session()
    for call in calls:
        model = session.get_service_model(call["service"]).operation_model(call["operation"])
        assert not ParamValidator().validate(call["params"], model.input_shape).has_errors()


def test_security_group_modify_emits_authorize_then_revoke(typed_client):
    bid = branch(typed_client)
    change(typed_client, bid, {"op": "modify", "resource_type": "security_group", "resource_id": "sg-0aaa", "fields": {"rules": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["10.0.0.0/8"]}]}})
    body = typed_client.get(f"/branches/{bid}/handback").json()
    assert body["calls"] == [
        {"change_index": 0, "service": "ec2", "operation": "AuthorizeSecurityGroupIngress", "params": {"GroupId": "sg-0aaa", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}},
        {"change_index": 0, "service": "ec2", "operation": "RevokeSecurityGroupIngress", "params": {"GroupId": "sg-0aaa", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}},
    ]
    assert_valid_calls(body["calls"])


def test_delete_and_route_calls_have_exact_params(typed_client):
    cases = [
        ({"op": "delete", "resource_type": "ebs_volume", "resource_id": "vol-0bbb", "fields": {}}, "DeleteVolume", "ec2", {"VolumeId": "vol-0bbb"}),
        ({"op": "delete", "resource_type": "s3_bucket", "resource_id": "synthetic-bucket", "fields": {}}, "DeleteBucket", "s3", {"Bucket": "synthetic-bucket"}),
        ({"op": "delete", "resource_type": "rds_instance", "resource_id": "synthetic-db", "fields": {"skip_final_snapshot": True}}, "DeleteDBInstance", "rds", {"DBInstanceIdentifier": "synthetic-db", "SkipFinalSnapshot": True}),
        ({"op": "modify", "resource_type": "route_table", "resource_id": "rtb-0ccc", "fields": {"routes": [{"destination_cidr": "10.20.0.0/16", "target_type": "local", "target_id": "local"}, {"destination_cidr": "0.0.0.0/0", "target_type": "igw", "target_id": "igw-0ddd"}]}}, "CreateRoute", "ec2", {"RouteTableId": "rtb-0ccc", "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0ddd"}),
    ]
    for index, (payload, operation, service, params) in enumerate(cases):
        bid = branch(typed_client, f"exact-{index}")
        change(typed_client, bid, payload)
        calls = typed_client.get(f"/branches/{bid}/handback").json()["calls"]
        assert {"change_index": 0, "service": service, "operation": operation, "params": params} in calls
        assert_valid_calls(calls)


def test_unmappable_changes_are_not_echoed(typed_client):
    bid = branch(typed_client)
    change(typed_client, bid, {"op": "modify", "resource_type": "s3_bucket", "resource_id": "synthetic-bucket", "fields": {"is_public": True}})
    change(typed_client, bid, {"op": "add", "resource_type": "s3_bucket", "resource_id": "new-bucket", "fields": {}}, expected=1)
    response = typed_client.get(f"/branches/{bid}/handback")
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "unmappable_changes"
    assert {item["change_index"] for item in body["changes"]} == {0, 1}
    assert "calls" not in body


def test_empty_and_plan_branches_conflict(typed_client):
    empty = typed_client.get(f"/branches/{branch(typed_client, 'empty')}/handback")
    assert empty.status_code == 409 and empty.json() == {"error": "no_changes"}
    bid = branch(typed_client, "plan")
    raw = (Path(__file__).parent / "incidents/fixtures/datatalks_destroy_plan.json").read_bytes()
    assert typed_client.post(f"/branches/{bid}/plans/terraform", content=raw).status_code == 200
    response = typed_client.get(f"/branches/{bid}/handback")
    assert response.status_code == 409 and response.json() == {"error": "branch_has_plan_receipts"}


def test_typed_handback_is_stable_and_verifies_conflicts(typed_client):
    bid = branch(typed_client)
    change(typed_client, bid, {"op": "delete", "resource_type": "ebs_volume", "resource_id": "vol-0bbb", "fields": {}})
    first = typed_client.get(f"/branches/{bid}/handback")
    second = typed_client.get(f"/branches/{bid}/handback")
    assert first.content == second.content
    body = first.json()
    assert typed_client.post(f"/branches/{bid}/handback/verify", json=body).status_code == 200
    tampered = dict(body, calls=[])
    assert typed_client.post(f"/branches/{bid}/handback/verify", json=tampered).json()["reason_code"] == "input_hash_mismatch"
    tampered["input_sha256"] = canonical_sha256([])
    response = typed_client.post(f"/branches/{bid}/handback/verify", json=tampered)
    assert response.status_code == 409 and response.json()["reason_code"] == "input_hash_mismatch"
    for field, value, reason in [("base_analysis_id", "wrong", "base_snapshot_changed"), ("verdict_id", "wrong", "verdict_changed")]:
        candidate = dict(body, **{field: value})
        response = typed_client.post(f"/branches/{bid}/handback/verify", json=candidate)
        assert response.status_code == 409 and response.json()["reason_code"] == reason
    stale = typed_client.post(f"/branches/{bid}/changes", json={"op": "delete", "resource_type": "s3_bucket", "resource_id": "synthetic-bucket", "fields": {}, "expected_change_count": 1})
    assert stale.status_code == 200
    response = typed_client.post(f"/branches/{bid}/handback/verify", json=body)
    assert response.status_code == 409 and response.json()["reason_code"] == "input_hash_mismatch"
    missing = dict(body); missing.pop("calls")
    response = typed_client.post(f"/branches/{bid}/handback/verify", json=missing)
    assert response.status_code == 422 and "calls" not in response.text


def test_plan_verify_validation(typed_client):
    bid = branch(typed_client, "plan-verify")
    raw = (Path(__file__).parent / "incidents/fixtures/datatalks_destroy_plan.json").read_bytes()
    plan = typed_client.post(f"{bid}/plans/terraform", content=raw)
    assert plan.status_code == 404
    # Plan receipts use the established branch-scoped endpoint.
    assert typed_client.post(f"/branches/{bid}/plans/terraform", content=raw).status_code == 200
    plan_id = branches.list_plans(bid)[0]["plan_id"]
    handback = typed_client.get(f"/branches/{bid}/plans/{plan_id}/handback").json()
    missing = dict(handback); missing.pop("base_analysis_id")
    assert typed_client.post("/handback/verify", json=missing).status_code == 422
    assert typed_client.post("/handback/verify", json={**handback, "base_analysis_id": "wrong"}).json()["reason_code"] == "base_snapshot_changed"
    assert typed_client.post("/handback/verify", json={**handback, "branch_revision": "0" * 64}).json()["reason_code"] == "branch_revision_changed"
    assert typed_client.post("/handback/verify", json=handback).status_code == 200


def test_s3_modify_policy_none_is_unmappable(typed_client):
    bid = branch(typed_client, "null-policy")
    change(typed_client, bid, {"op": "modify", "resource_type": "s3_bucket", "resource_id": "synthetic-bucket", "fields": {"policy": None}})
    response = typed_client.get(f"/branches/{bid}/handback")
    assert response.status_code == 422
    assert {item["reason"] for item in response.json()["changes"]} == {"null_value:policy"}


def test_s3_modify_versioning_none_is_unmappable_or_validation_error(typed_client):
    bid = branch(typed_client, "null-versioning")
    response = typed_client.post(f"/branches/{bid}/changes", json={"op": "modify", "resource_type": "s3_bucket", "resource_id": "synthetic-bucket", "fields": {"versioning_enabled": None}, "expected_change_count": 0})
    if response.status_code == 422:
        return
    assert response.status_code == 200, response.text
    response = typed_client.get(f"/branches/{bid}/handback")
    assert response.status_code == 422
    assert {item["reason"] for item in response.json()["changes"]} == {"null_value:versioning_enabled"}


def test_build_api_calls_missing_resource_is_unmappable():
    with pytest.raises(UnmappableChanges) as raised:
        build_api_calls(synthetic_base(), [Change(op="modify", resource_type="s3_bucket", resource_id="missing-bucket", fields={"policy": "{}"})])
    assert raised.value.changes == [{"change_index": 0, "op": "modify", "resource_type": "s3_bucket", "reason": "resource_not_found"}]
