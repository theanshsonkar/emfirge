import hashlib
import json
import os
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, main, verdict
from tests.incidents.synthetic_base import load_synthetic_base


@pytest.fixture
def plan_client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'plans.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: load_synthetic_base("delete"))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    for name in ("run_checkov", "run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(verdict, name, lambda *_a, **_k: {"available": False, "findings": []})
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def _branch(client):
    response = client.post("/branches", json={"base_analysis_id": "delete", "name": "plan"})
    assert response.status_code == 200, response.text
    return response.json()["branch_id"]


def _post(client, payload, *, whitespace=False):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    if whitespace:
        raw += b"\n  "
    branch_id = _branch(client)
    response = client.post(f"/branches/{branch_id}/plans/terraform", content=raw)
    return branch_id, raw, response


def _item(address, typ, actions, before=None, after=None, after_unknown=None, mode="managed"):
    return {"address": address, "mode": mode, "type": typ,
            "change": {"actions": actions, "before": before, "after": after,
                        "after_unknown": after_unknown or {}}}


def test_locked_datatalks_plan_and_raw_hash(plan_client):
    raw = (Path(__file__).parent / "incidents/fixtures/datatalks_destroy_plan.json").read_bytes()
    branch_id = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch_id}/plans/terraform", content=raw)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["input_sha256"] == hashlib.sha256(raw).hexdigest()
    verdict_response = plan_client.get(f"/branches/{branch_id}/verdict")
    assert verdict_response.json()["verdict"] == "block"
    codes = {item["code"] for item in verdict_response.json()["reasons"]}
    assert {"unmodeled_delete", "data_store_deleted_no_recovery_point"} <= codes
    result = verdict_response.json()
    assert any(x["resource_id"] == "db-dl-prod" for x in result["deletion"]["data_lost"])
    assert {"aws_route_table", "aws_internet_gateway", "aws_subnet", "aws_vpc"} <= {x["type"] for x in body["unmodeled"]}


def test_unmodeled_delete_blocks_and_create_warns(plan_client):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        _item("aws_dynamodb_table.x", "aws_dynamodb_table", ["delete"], {"name": "x"}, None)]})
    assert response.status_code == 200
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "block"
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        _item("aws_cloudwatch_log_group.x", "aws_cloudwatch_log_group", ["create"], None, {"name": "x"})]})
    assert response.status_code == 200
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "warn"
    assert any(x["type"] == "aws_cloudwatch_log_group" for x in response.json()["unmodeled"])


def test_replace_unknown_noop_read_and_data_mode(plan_client):
    replace = {"format_version": "1.0", "resource_changes": [
        _item("aws_db_instance.db", "aws_db_instance", ["delete", "create"],
              {"identifier": "db-dl-prod", "skip_final_snapshot": True}, {"identifier": "db-new"})]}
    branch_id, _, response = _post(plan_client, replace)
    assert response.status_code == 200, response.text
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "block"
    payload = {"format_version": "1.0", "resource_changes": [
        _item("aws_instance.i", "aws_instance", ["create"], None,
              {"id": "i-new", "instance_type": "t3.micro", "state": "running"}, {"subnet_id": True}),
        _item("aws_instance.noop", "aws_instance", ["no-op"], None, {}),
        _item("data.aws_instance.read", "aws_instance", ["read"], None, {}, mode="data"),
    ]}
    branch_id, raw, response = _post(plan_client, payload, whitespace=True)
    assert response.status_code == 200, response.text
    body = response.json()
    assert any(item["field"] == "subnet_id" for item in body["unknown_fields"])
    assert "aws_instance.i" in body["applied"]
    branch = branches.get_branch(branch_id)
    added = [x for x in branch.changes if x.op == "add" and x.resource_id == "i-new"]
    assert added and "subnet_id" not in added[0].fields
    assert "data.aws_instance.read" not in body["applied"]
    assert body["input_sha256"] == hashlib.sha256(raw).hexdigest()


def test_bad_format_does_not_echo_input(plan_client):
    branch_id = _branch(plan_client)
    raw = b'{"format_version":"9.9","marker":"SECRET-PLAN"}'
    response = plan_client.post(f"/branches/{branch_id}/plans/terraform", content=raw)
    assert response.status_code == 422
    assert "SECRET-PLAN" not in response.text


def test_db_identifier_is_resource_id(plan_client):
    _, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        _item("aws_db_instance.db", "aws_db_instance", ["create"], None, {"identifier": "db-by-identifier"})]})
    assert response.status_code == 200
    assert "aws_db_instance.db" in response.json()["applied"]


def test_non_aws_unmodeled_resources_are_outside_view_and_warn(plan_client):
    for typ, actions in (("random_password", ["delete"]), ("null_resource", ["create"]),
                         ("local_file", ["update"]), ("tls_private_key", ["delete", "create"])):
        branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
            {**_item(f"{typ}.x", typ, actions, {}, {}),
             "provider_name": f"registry.terraform.io/hashicorp/{typ.split('_')[0]}"}
        ]})
        assert response.status_code == 200
        body = response.json()
        assert body["applied"] == []
        assert body["unmodeled"][0]["outside_view"] is True
        verdict_body = plan_client.get(f"/branches/{branch_id}/verdict").json()
        assert verdict_body["verdict"] == "warn"
        assert {reason["code"] for reason in verdict_body["reasons"]} == {"outside_view"}


@pytest.mark.parametrize("actions", [["create", "delete"], ["delete", "create"]])
def test_unmodeled_aws_replace_blocks(plan_client, actions):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        {**_item("aws_dynamodb_table.x", "aws_dynamodb_table", actions, {}, {}),
         "provider_name": "registry.terraform.io/hashicorp/aws"}
    ]})
    assert response.status_code == 200
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert {reason["code"] for reason in result["reasons"]} == {"unmodeled_delete"}


def test_unmodeled_missing_provider_is_aws_and_blocks(plan_client):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        _item("aws_dynamodb_table.x", "aws_dynamodb_table", ["delete"], {}, {})
    ]})
    assert response.status_code == 200
    assert plan_client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "block"


def test_modeled_type_under_non_aws_provider_is_outside_view(plan_client):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        {**_item("aws_instance.x", "aws_instance", ["delete"], {"id": "i-x"}, {}),
         "provider_name": "registry.terraform.io/acme/foo"}
    ]})
    assert response.status_code == 200
    assert response.json()["applied"] == []
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "warn"
    assert {reason["code"] for reason in result["reasons"]} == {"outside_view"}


def test_plan_reasons_are_fail_closed_for_rejected_deletes_and_old_receipts():
    assert {r["code"] for r in verdict._plan_reasons([{"rejected": [{"op": "add"}]}])} == {"plan_change_rejected"}
    assert {r["code"] for r in verdict._plan_reasons([{"rejected": [{"address": "x", "reason_code": "mutation_rejected"}]}])} == {"plan_delete_rejected"}
    reasons = verdict._plan_reasons([{"unmodeled": [{"type": "aws_x", "actions": ["delete"]}]}])
    assert {r["code"] for r in reasons} == {"unmodeled_delete"}


def test_awscc_unmodeled_delete_blocks(plan_client):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        {**_item("awscc_rds_db_cluster.x", "awscc_rds_db_cluster", ["delete"], {}, {}),
         "provider_name": "registry.terraform.io/hashicorp/awscc"}
    ]})
    assert response.status_code == 200
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert {reason["code"] for reason in result["reasons"]} == {"unmodeled_delete"}


def test_rejected_modeled_delete_records_op_and_blocks(plan_client):
    branch_id, _, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [
        _item("aws_security_group.web", "aws_security_group", ["delete"], {"id": "sg-dl-web"}, {})
    ]})
    assert response.status_code == 200
    body = response.json()
    assert body["rejected"] and body["rejected"][0]["op"] == "delete"
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert "plan_delete_rejected" in {reason["code"] for reason in result["reasons"]}
