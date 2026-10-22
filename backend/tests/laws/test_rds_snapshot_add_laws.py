import itertools
import pytest

from app.aws_api_ingest import translate_api_calls
from app.cost import cost_sides
from app.mutations import Change, TargetNotFound, apply_change, apply_changes
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base
from tests.test_plan_ingest import _post, plan_client  # noqa: F401


def add(base, ident="snap-new", db="db-dl-prod", fields=None):
    return apply_change(base, Change(op="add", resource_type="rds_snapshot", resource_id=ident,
                                     fields=({"db_instance_id": db} if fields is None and db else (fields or {}))))


def delete_db(base, db="db-dl-prod"):
    return apply_change(base, Change(op="delete", resource_type="rds_instance", resource_id=db,
                                     fields={"skip_final_snapshot": True, "delete_automated_backups": True}))


def codes(verdict):
    return {reason["code"] for reason in verdict.reasons}


def test_add_snapshot_is_pure_and_server_defaults():
    base = load_synthetic_base("delete")
    before = base.model_dump(mode="json")
    branch = add(base)
    snap = next(item for item in branch.rds.rds_snapshots if item.id == "snap-new")
    assert (snap.snapshot_type, snap.status, snap.db_instance_id) == ("manual", "available", "db-dl-prod")
    assert base.model_dump(mode="json") == before


def test_invalid_source_and_fields_are_rejected():
    base = load_synthetic_base("delete")
    with pytest.raises((ValueError, TargetNotFound)):
        add(base, db="missing-db")
    for fields in ({"status": "available"}, {"snapshot_type": "manual"}, {"wat": 1}):
        with pytest.raises(ValueError):
            add(base, fields=fields)


def test_duplicate_snapshot_is_rejected():
    base = load_synthetic_base("delete")
    existing = base.rds.rds_snapshots[0].id
    with pytest.raises(ValueError):
        add(base, ident=existing)


def test_unspecified_snapshot_is_warned_but_complete_one_is_not():
    base = load_synthetic_base("delete")
    branch = add(base, db=None, fields={})
    result = combined_verdict(base, branch, run_scanners=False)
    reason = next(item for item in result.reasons if item["code"] == "unspecified_values")
    assert "snap-new" in reason["resources"]
    assert "snap-new" not in reason["message"]
    assert "unspecified_change_fields" in result.coverage_warnings
    complete = combined_verdict(base, add(base), run_scanners=False)
    assert not any(item["code"] == "unspecified_values" for item in complete.reasons)


def test_snapshot_before_delete_recovers_db_but_control_does_not():
    base = load_synthetic_base("delete")
    with_snap = delete_db(add(base))
    control = delete_db(base)
    assert "data_store_deleted_with_recovery_point" in codes(combined_verdict(base, with_snap, run_scanners=False))
    assert "data_store_deleted_no_recovery_point" not in codes(combined_verdict(base, with_snap, run_scanners=False))
    assert "data_store_deleted_no_recovery_point" in codes(combined_verdict(base, control, run_scanners=False))


def test_unspecified_and_deleted_snapshot_still_blocks():
    base = load_synthetic_base("delete")
    assert "data_store_deleted_no_recovery_point" in codes(combined_verdict(base, delete_db(add(base, db=None, fields={})), run_scanners=False))


def test_deleted_added_snapshot_does_not_recover():
    base = load_synthetic_base("delete")
    branch = add(base)
    branch = apply_change(branch, Change(op="delete", resource_type="rds_snapshot", resource_id="snap-new"))
    assert "data_store_deleted_no_recovery_point" in codes(combined_verdict(base, delete_db(branch), run_scanners=False))


def test_added_snapshot_cost_is_unknown_usage():
    base = load_synthetic_base("delete")
    branch = add(base)
    _, branch_side, changes, _ = cost_sides(base, branch)
    item = next(x for x in changes if x.resource_type == "rds_snapshot")
    assert item.after_monthly_usd is None and item.after_basis == "usage-based-unknown"
    assert branch_side.status == "partial"


def test_snapshot_change_round_trip_through_typed_handback_and_api_ingest():
    base = load_synthetic_base("delete")
    change = Change(op="add", resource_type="rds_snapshot", resource_id="snap-roundtrip",
                    fields={"db_instance_id": "db-dl-prod"})
    calls = build_api_calls(base, [change])
    payload = {"format": "aws-api-calls/1", "calls": [
        {"service": call["service"], "operation": call["operation"], "parameters": call["params"]}
        for call in calls
    ]}
    assert translate_api_calls(payload)["changes"] == [change]


def test_snapshot_delete_recovery_brute_force():
    base = load_synthetic_base("delete", {"rds_snapshots": []})
    dbs = ["db-dl-prod", "db-dl-reports"]
    adds = [Change(op="add", resource_type="rds_snapshot", resource_id=f"snap-{db}",
                   fields={"db_instance_id": db}) for db in dbs]
    deletes = [Change(op="delete", resource_type="rds_instance", resource_id=db,
                      fields={"skip_final_snapshot": True, "delete_automated_backups": True}) for db in dbs]
    operations = adds + deletes
    for size in range(1, len(operations) + 1):
        for sequence in itertools.permutations(operations, size):
            try:
                branch = apply_changes(base, sequence)
            except (TargetNotFound, ValueError):
                assert any(op.op == "add" and any(previous.op == "delete" and previous.resource_id == op.fields.get("db_instance_id")
                                                   for previous in sequence[:index])
                           for index, op in enumerate(sequence))
                continue
            verdict = combined_verdict(base, branch, run_scanners=False)
            reason_codes = codes(verdict)
            deleted = {op.resource_id for op in sequence if op.op == "delete"}
            safe = {db for db in deleted if any(op.op == "add" and op.fields.get("db_instance_id") == db
                                                 for op in sequence[:next(i for i, op in enumerate(sequence)
                                                                           if op.op == "delete" and op.resource_id == db)])}
            unsafe = deleted - safe
            assert ("data_store_deleted_no_recovery_point" in reason_codes) == bool(unsafe)
            assert ("data_store_deleted_with_recovery_point" in reason_codes) == bool(safe)
            for code, expected in (("data_store_deleted_no_recovery_point", unsafe),
                                   ("data_store_deleted_with_recovery_point", safe)):
                reason = next((item for item in verdict.reasons if item["code"] == code), None)
                if reason:
                    assert expected <= set(reason.get("resources", []))


def test_snapshot_add_http_validation(plan_client):
    def post(payload):
        branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "snapshot"}).json()["branch_id"]
        return plan_client.post(f"/branches/{branch_id}/changes", json=payload)

    missing = post({"op": "add", "resource_type": "rds_snapshot", "resource_id": "snap-http", "fields": {}})
    assert 200 <= missing.status_code < 300
    verdict = plan_client.get(f"/branches/{missing.json()['branch_id']}/verdict").json()
    reason = next(item for item in verdict["reasons"] if item["code"] == "unspecified_values")
    assert "snap-http" in reason["resources"]
    unknown_source = post({"op": "add", "resource_type": "rds_snapshot", "resource_id": "snap-http", "fields": {"db_instance_id": "db-does-not-exist"}})
    assert unknown_source.status_code == 422
    invalid = post({"op": "add", "resource_type": "rds_snapshot", "resource_id": "snap-http", "fields": {"status": "available"}})
    assert invalid.status_code == 422
    duplicate = post({"op": "add", "resource_type": "rds_snapshot", "resource_id": "dlsnap-reports", "fields": {"db_instance_id": "db-dl-reports"}})
    assert duplicate.status_code == 422
    valid = post({"op": "add", "resource_type": "rds_snapshot", "resource_id": "snap-http", "fields": {"db_instance_id": "db-dl-prod"}})
    assert 200 <= valid.status_code < 300


def test_typed_handback_snapshot_and_unmapped_adds():
    base = load_synthetic_base("delete")
    change = Change(op="add", resource_type="rds_snapshot", resource_id="snap-new", fields={"db_instance_id": "db-dl-prod"})
    calls = build_api_calls(base, [change])
    assert len(calls) == 1
    assert {key: calls[0][key] for key in ("service", "operation", "params")} == {"service": "rds", "operation": "CreateDBSnapshot", "params": {"DBSnapshotIdentifier": "snap-new", "DBInstanceIdentifier": "db-dl-prod"}}
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [change.model_copy(update={"fields": {}})])
    assert exc.value.changes[0]["reason"] == "error"
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [Change(op="add", resource_type="ec2_instance", resource_id="i-new", fields={"type": "t3.small", "state": "running", "sg_ids": []})])
    assert exc.value.changes[0]["reason"] == "operation_not_mapped"


def test_api_ingest_and_round_trip():
    base = load_synthetic_base("delete")
    change = Change(op="add", resource_type="rds_snapshot", resource_id="snap-x", fields={"db_instance_id": "db-dl-prod"})
    calls = build_api_calls(base, [change])
    payload = {"format": "aws-api-calls/1", "calls": [
        {"service": call["service"], "operation": call["operation"], "parameters": call["params"]}
        for call in calls
    ]}
    assert translate_api_calls(payload)["changes"] == [change]
    assert not translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "rds", "operation": "CreateDBSnapshot", "parameters": {"DBInstanceIdentifier": "db-dl-prod"}}]})["changes"]


def _plan(snapshot_id="snap-x", db="db-dl-prod", unknown=False, shared=None):
    after = {"id": snapshot_id, "db_snapshot_identifier": snapshot_id, "db_instance_identifier": db}
    if shared:
        after["shared_accounts"] = shared
    change = {"actions": ["create"], "before": None, "after": after}
    if unknown:
        change["after_unknown"] = {"db_instance_identifier": True}
    return {"format_version": "1.0", "resource_changes": [{"address": "aws_db_snapshot.x", "mode": "managed", "type": "aws_db_snapshot", "name": "x", "change": change}], "configuration": {"root_module": {"resources": [{"address": "aws_db_snapshot.x", "type": "aws_db_snapshot", "name": "x", "expressions": {}}]}}}


def test_terraform_snapshot_known_unknown_and_shared(plan_client):
    known = translate_plan(_plan())
    assert known["changes"][0] == Change(op="add", resource_type="rds_snapshot", resource_id="snap-x", fields={"db_instance_id": "db-dl-prod"})
    unknown = translate_plan(_plan(unknown=True))
    assert unknown["changes"][0].fields == {}
    unknown_branch = apply_change(load_synthetic_base("delete"), unknown["changes"][0])
    unknown_verdict = combined_verdict(load_synthetic_base("delete"), unknown_branch, run_scanners=False)
    unknown_reason = next(item for item in unknown_verdict.reasons if item["code"] == "unspecified_values")
    assert "snap-x" in unknown_reason["resources"]
    branch, _, response = _post(plan_client, _plan())
    assert response.status_code != 422
    unseen_branch, _, response = _post(plan_client, _plan(shared=["other-account"]))
    assert response.status_code != 422
    unseen_verdict = plan_client.get(f"/branches/{unseen_branch}/verdict").json()
    assert unseen_verdict["verdict"] == "block"
    assert "unseen_change" in {reason["code"] for reason in unseen_verdict["reasons"]}
