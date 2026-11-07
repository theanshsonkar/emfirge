"""L71c Plans: the server keeps a fingerprint (sha256) of an uploaded plan, never its text.

Planted secrets in a Terraform plan must appear in no column of any table; handback
still binds to the plan by hash and verifies against the caller's own original file.
"""
import base64
import hashlib
import json

from sqlalchemy import text

from app import database
from tests.laws.test_plan_receipt_laws import plan_client, _branch  # noqa: F401

LAMBDA_SECRET = "PLANTED-LAMBDA-ENV-SECRET-91f3"
USERDATA_SECRET = "PLANTED-USERDATA-SECRET-77ab"
USERDATA = f"#!/bin/bash\nexport API_TOKEN={USERDATA_SECRET}\n"
USERDATA_B64 = base64.b64encode(USERDATA.encode()).decode()
ACCOUNT = "123456789012"


def _item(typ, name, after, unknown=None):
    return {"address": f"{typ}.{name}", "mode": "managed", "type": typ, "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["create"], "before": None, "after": after, "after_unknown": unknown or {}}}


def _plan_bytes():
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            _item("aws_lambda_function", "f", {
                "function_name": "f", "tags": {}, "tags_all": {},
                "environment": [{"variables": {"DB_PASSWORD": LAMBDA_SECRET, "REGION": "us-east-1"}}]},
                {"role": True, "arn": True}),
            _item("aws_instance", "i", {
                "instance_type": "t3.micro", "tags": {}, "tags_all": {},
                "user_data": USERDATA, "user_data_base64": USERDATA_B64}),
        ],
        "configuration": {"root_module": {"resources": []}},
        "prior_state": {"values": {"root_module": {"resources": [
            {"mode": "data", "type": "aws_caller_identity", "name": "c", "values": {"account_id": ACCOUNT}}]}}},
    }
    return json.dumps(plan).encode()


def _all_strings(factory):
    found = []
    with factory() as db:
        for table in database.Base.metadata.sorted_tables:
            for row in db.execute(table.select()).mappings():
                for column, value in row.items():
                    if isinstance(value, str):
                        found.append((table.name, column, value))
    return found


def _assert_no_plan_text_anywhere(factory):
    needles = (LAMBDA_SECRET, USERDATA_SECRET, USERDATA_B64)
    for table, column, value in _all_strings(factory):
        for needle in needles:
            assert needle not in value, f"{needle} stored in {table}.{column}"


def test_L71c_no_plan_text_in_any_table_and_handback_verifies_by_hash(plan_client):
    client, factory = plan_client
    branch_id = _branch(client)
    raw = _plan_bytes()
    posted = client.post(f"/branches/{branch_id}/plans/terraform", content=raw)
    assert posted.status_code == 200, posted.text
    receipt = posted.json()
    assert receipt["input_sha256"] == hashlib.sha256(raw).hexdigest()
    _assert_no_plan_text_anywhere(factory)
    with factory() as db:
        plans = db.execute(text("select raw_input, input_sha256 from plan_logs")).all()
    assert plans == [("", receipt["input_sha256"])]

    fork = client.post(f"/branches/{branch_id}/fork", json={"name": "child"}).json()
    _assert_no_plan_text_anywhere(factory)
    assert fork["plan_id_map"]

    handback = client.get(f"/branches/{branch_id}/plans/{receipt['plan_id']}/handback")
    assert handback.status_code == 200, handback.text
    body = handback.json()
    assert "plan_text" not in body
    assert body["input_sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["verdict_id"] and body["branch_revision"]
    assert "sha256" in body["instruction"] and "your own" in body["instruction"]
    assert LAMBDA_SECRET not in handback.text and USERDATA_SECRET not in handback.text

    verify = {"plan_id": receipt["plan_id"], "verdict_id": body["verdict_id"],
              "base_analysis_id": body["base_analysis_id"], "branch_revision": body["branch_revision"]}
    ok = client.post("/handback/verify", json={**verify, "plan_text": raw.decode()})
    assert ok.status_code == 200 and ok.json() == {"ok": True}
    bad = client.post("/handback/verify", json={**verify, "plan_text": raw.decode() + " "})
    assert bad.status_code == 409 and bad.json()["reason_code"] == "input_hash_mismatch"


def test_L71c_startup_blanks_plan_text_stored_by_older_versions(shared_test_db):
    with database.SessionLocal() as db:
        db.add(database.PlanLog(plan_id="old", branch_id="b", input_sha256="0" * 64,
                                raw_input=f"legacy {LAMBDA_SECRET}", branch_revision_after="r"))
        db.commit()
    database.create_tables()
    database.create_tables()  # idempotent
    with database.SessionLocal() as db:
        row = db.query(database.PlanLog).one()
        assert (row.raw_input, row.input_sha256) == ("", "0" * 64)
