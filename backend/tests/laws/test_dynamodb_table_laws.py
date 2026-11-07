"""L80 DynamoDB tables are first-class in the data damage answer and in delete safety.

The incident class: a table holding data is deleted (DeleteTable, `terraform destroy`, a
CloudFormation resource removal) and the answer to "what data is lost" said nothing,
because only buckets, databases and volumes had a recovery assessment. A table is now
judged from provider facts the collector reads, by the same truth in the delete lens,
the verdict and the check's data answer.

Provider facts relied on (AWS documentation, fetched 2026-11-07):
  * DescribeTable ItemCount: "DynamoDB updates this value approximately every six hours.
    Recent changes might not be reflected in this value."
    https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html
  * "When you delete a table that has point-in-time recovery enabled, DynamoDB automatically
    creates a backup snapshot called a system backup and retains it for 35 days"
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html
    (BackupSummary BackupType SYSTEM: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BackupSummary.html)
  * An on-demand backup restores a table that "no longer exists"
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Restore.Tutorial.html
  * Deletion protection: "When deletion protection is enabled for a table, it cannot be deleted by anyone."
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html

L80a  collector reads item count, PITR, an AVAILABLE on-demand backup, deletion protection; read calls only;
      a refused read is unknown (None), never "no PITR" / "no backup" / "empty"
L80b  delete of a non-empty table with no recovery point: data fact has_recovery_point=false AND a verdict block
L80c  on-demand backup or PITR (system backup on delete) is a recovery point; one truth in lens, verdict, check, /context
L80d  item count unknown or recovery unreadable is unknown (null + note), never a pass and never "lost"
L80e  ItemCount 0 is "reported empty", with the approximation note citing the AWS page
L80f  PITR true -> false on a branch is a recovery_removed data fact and a recovery_point_removed warning
L80g  deleting a table a lambda role can access lists the role and lambda as dependents (can_access)
L80h  mutations: delete, modify pitr_enabled / deletion_protection_enabled; strict values; protection blocks delete
L80i  API, CLI, Terraform and CloudFormation give the same branch and the same answers
L80j  hand-back builds exact DeleteTable / UpdateContinuousBackups / UpdateTable calls; moto round trip lives in
      tests/test_handback_moto_roundtrip.py
L80k  field catalog comes from botocore; the IAM role covers every read the collector makes
L80l  old snapshots load; dynamodb logic lives in adapter modules only; API flow
"""
from __future__ import annotations

import json
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.exceptions import ClientError
from moto import mock_aws

from app.aws_api_ingest import translate_api_calls
from app.aws_cli_ingest import parse_cli_commands
from app.aws_collector import collect_dynamodb
from app.aws_context import answer_for_infra
from app.cfn_ingest import convert_change_set
from app.delete_lens import DATA_STORE_TYPES, analyze_deletions
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.field_catalog import CATALOG, resolve
from app.models import AWSInfrastructure, DynamoDBData, DynamoDBTable
from app.mutations import Change, TargetNotFound, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import DATA_HOLDING_TYPES, combined_verdict, recovery_removals
from tests.incidents.synthetic_base import load_synthetic_base

from .test_check_facts_laws import _answers, _check, _dump, _json_values

REGION = "ap-south-1"
ACCOUNT = "000000000000"
ORDERS = "orders"
WORKER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/DlWorkerRole"
ITEM_COUNT_URL = "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html"
ROOT = Path(__file__).resolve().parents[3]


def arn(name):
    return f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}"


def table(name=ORDERS, **extra):
    values = dict(name=name, arn=arn(name), item_count=1200, pitr_enabled=False, has_backup=False,
                  deletion_protection_enabled=False, billing_mode="PAY_PER_REQUEST")
    values.update(extra)
    return DynamoDBTable(**values)


def base_with(*tables, access=False):
    base = load_synthetic_base("delete")
    tables = list(tables or [table()])
    update = {"dynamodb": DynamoDBData(total_tables=len(tables), tables=tables),
              "collection": {**base.collection, "dynamodb": "ok"}}
    if access:
        roles = []
        for role in base.iam.role_policies:
            if role.role_arn == WORKER_ROLE:
                statement = {"effect": "Allow", "actions": ["dynamodb:GetItem", "dynamodb:PutItem"],
                             "resources": [t.arn for t in tables]}
                role = role.model_copy(update={"access_statements": [*role.access_statements, statement],
                                               "accessible_resources": [*role.accessible_resources, *[t.arn for t in tables]]})
            roles.append(role)
        update["iam"] = base.iam.model_copy(update={"role_policies": roles})
    return base.model_copy(update=update)


def find(infra, name=ORDERS):
    return next(t for t in infra.dynamodb.tables if t.name == name)


def delete(name=ORDERS):
    return Change(op="delete", resource_type="dynamodb_table", resource_id=name, fields={})


def modify(name=ORDERS, **fields):
    return Change(op="modify", resource_type="dynamodb_table", resource_id=name, fields=fields)


def data_facts(body):
    return [f for f in _answers(body)["data"]["facts"] if f["resource_type"] == "dynamodb_table"]


def data_unknown(body):
    return {(u["topic"], u["resource_id"]): u["reason"] for u in _answers(body)["data"]["unknown"]}


def codes(verdict):
    return {r["code"] for r in verdict.reasons} if verdict.reasons and isinstance(verdict.reasons[0], dict) else {r.code for r in verdict.reasons}


# ── L80a collector ────────────────────────────────────────────────────────────

@pytest.fixture
def fake_aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        yield boto3.client("dynamodb", region_name=REGION)


def _make(client, name=ORDERS, items=0):
    client.create_table(TableName=name, KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
                        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
    for number in range(items):
        client.put_item(TableName=name, Item={"k": {"S": f"item-{number}"}})


def _collect():
    warnings = []
    return collect_dynamodb("testing", "testing", "testing", REGION, warnings), warnings


def _fail(monkeypatch, code, operations):
    from botocore.client import BaseClient

    original = BaseClient._make_api_call

    def patched(self, operation_name, params):
        if operation_name in operations:
            raise ClientError({"Error": {"Code": code, "Message": f"arn:aws:dynamodb:{REGION}:123456789012:table/orders"}}, operation_name)
        return original(self, operation_name, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)


def test_L80a_collector_reads_items_pitr_backup_and_deletion_protection(fake_aws):
    _make(fake_aws, items=3)
    _make(fake_aws, "plain")
    fake_aws.update_continuous_backups(TableName=ORDERS, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True})
    fake_aws.update_table(TableName=ORDERS, DeletionProtectionEnabled=True)
    fake_aws.create_backup(TableName=ORDERS, BackupName="manual-1")
    data, warnings = _collect()
    assert warnings == [] and data.collection_status == {"dynamodb": "ok"}
    by_name = {t.name: t for t in data.tables}
    orders, plain = by_name[ORDERS], by_name["plain"]
    assert (orders.item_count, orders.pitr_enabled, orders.has_backup, orders.deletion_protection_enabled) == (3, True, True, True)
    assert (plain.item_count, plain.pitr_enabled, plain.has_backup, plain.deletion_protection_enabled) == (0, False, False, False)
    assert orders.billing_mode == "PAY_PER_REQUEST"


def test_L80a_collector_only_makes_read_calls(fake_aws, monkeypatch):
    from botocore.client import BaseClient

    _make(fake_aws)
    seen = []
    original = BaseClient._make_api_call
    monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (seen.append(op), original(self, op, params))[1])
    _collect()
    assert set(seen) == {"ListTables", "DescribeTable", "DescribeContinuousBackups", "ListBackups"}  # L80k pins the role to these


def test_L80a_a_missing_item_count_is_unknown_not_zero(fake_aws, monkeypatch):
    from botocore.client import BaseClient

    _make(fake_aws)
    original = BaseClient._make_api_call

    def patched(self, operation_name, params):
        result = original(self, operation_name, params)
        if operation_name == "DescribeTable":
            result["Table"].pop("ItemCount", None)
        return result

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)
    data, _ = _collect()
    assert data.tables[0].item_count is None


def test_L80a_a_refused_continuous_backups_read_is_unknown_not_no_pitr(fake_aws, monkeypatch):
    _make(fake_aws, items=1)
    _fail(monkeypatch, "AccessDeniedException", ("DescribeContinuousBackups",))
    data, _ = _collect()
    only = data.tables[0]
    assert only.pitr_enabled is None and only.has_backup is False and only.item_count == 1
    assert data.collection_status == {"dynamodb": "denied"}


def test_L80a_a_refused_list_backups_read_is_unknown_not_no_backup(fake_aws, monkeypatch):
    _make(fake_aws, items=1)
    _fail(monkeypatch, "AccessDeniedException", ("ListBackups",))
    data, _ = _collect()
    assert data.tables[0].has_backup is None and data.tables[0].pitr_enabled is False
    assert data.collection_status == {"dynamodb": "denied"}


@pytest.mark.parametrize("code, status", [("AccessDeniedException", "denied"), ("InternalServerError", "error")])
def test_L80a_failed_listing_is_recorded_not_empty(fake_aws, monkeypatch, code, status):
    _fail(monkeypatch, code, ("ListTables",))
    data, warnings = _collect()
    assert data.tables == [] and data.collection_status == {"dynamodb": status}
    assert warnings and "arn:aws" not in " ".join(warnings)


def test_L80a_only_an_available_backup_counts_and_every_page_is_read(fake_aws, monkeypatch):
    """A CREATING or DELETED backup restores nothing; the available one may be on a later page."""
    from botocore.client import BaseClient

    _make(fake_aws)
    original = BaseClient._make_api_call
    pages = [{"BackupSummaries": [{"BackupArn": "a1", "BackupStatus": "DELETED", "BackupType": "USER", "TableName": ORDERS},
                                  {"BackupArn": "a2", "BackupStatus": "CREATING", "BackupType": "USER", "TableName": ORDERS}],
              "LastEvaluatedBackupArn": "a2"},
             {"BackupSummaries": [{"BackupArn": "a3", "BackupStatus": "AVAILABLE", "BackupType": "USER", "TableName": ORDERS}]}]
    calls = []

    def patched(self, operation_name, params):
        if operation_name == "ListBackups":
            calls.append(params)
            return pages[len(calls) - 1]
        return original(self, operation_name, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)
    data, _ = _collect()
    assert data.tables[0].has_backup is True and len(calls) == 2
    pages[1] = {"BackupSummaries": [{"BackupArn": "a3", "BackupStatus": "DELETED", "BackupType": "USER", "TableName": ORDERS}]}
    calls.clear()
    data, _ = _collect()
    assert data.tables[0].has_backup is False


# ── L80b a table with data and no recovery point ───────────────────────────────

def test_L80b_deleting_a_table_with_data_and_no_recovery_point_blocks_and_is_a_data_fact():
    base = base_with()
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    assert [(x.resource_id, x.resource_type) for x in lens.data_lost] == [(ORDERS, "dynamodb_table")]
    assert lens.recovery_points == [] and lens.recovery_unknown == []
    verdict = combined_verdict(base, branch, run_scanners=False)
    reason = next(r for r in verdict.reasons if _code(r) == "data_store_deleted_no_recovery_point")
    assert _level(reason) == "block" and verdict.verdict == "block"
    assert data_facts(_dump(_check(base, branch))) == [{
        "resource_id": ORDERS, "resource_type": "dynamodb_table", "change": "deleted",
        "has_recovery_point": False, "recovery_resource_ids": []}]


def _code(reason):
    return reason["code"] if isinstance(reason, dict) else reason.code


def _level(reason):
    return reason["level"] if isinstance(reason, dict) else reason.level


def test_L80b_dynamodb_is_in_the_shared_data_store_truth():
    assert "dynamodb_table" in DATA_STORE_TYPES and "dynamodb_table" in DATA_HOLDING_TYPES


def test_L80b_the_data_answer_no_longer_says_tables_have_no_recovery_assessment():
    base = base_with()
    body = _dump(_check(base, apply_change(base, delete())))
    text = " ".join(u["reason"] for u in _answers(body)["data"]["unknown"])
    assert "dynamodb_table" in text and "tables," not in text and "(tables" not in text
    assert "queues" in text  # the other data stores stay unassessed, and the answer says so
    context = answer_for_infra("data", base_with(), analysis_id="a").model_dump(mode="json")
    assert "dynamodb_table" in " ".join(u["reason"] for u in context["unknown"]) and "(tables" not in " ".join(u["reason"] for u in context["unknown"])


# ── L80c recovery points, one truth ────────────────────────────────────────────

@pytest.mark.parametrize("extra, kind", [
    ({"has_backup": True}, "dynamodb_backup"),
    ({"pitr_enabled": True}, "dynamodb_system_backup"),
])
def test_L80c_an_on_demand_backup_or_pitr_is_a_recovery_point_in_every_answer(extra, kind):
    base = base_with(table(**extra))
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    assert lens.data_lost == [] and lens.recovery_unknown == []
    assert [(p.resource_id, p.kind) for p in lens.recovery_points] == [(ORDERS, kind)]
    verdict = combined_verdict(base, branch, run_scanners=False)
    got = {_code(r): _level(r) for r in verdict.reasons}
    assert "data_store_deleted_no_recovery_point" not in got and got["data_store_deleted_with_recovery_point"] == "warn"
    assert data_facts(_dump(_check(base, branch))) == [{
        "resource_id": ORDERS, "resource_type": "dynamodb_table", "change": "deleted",
        "has_recovery_point": True, "recovery_resource_ids": []}]
    # the context question for the existing table says the same thing
    line = next(f for f in answer_for_infra("data", base, analysis_id="a").model_dump(mode="json")["facts"] if f["resource_type"] == "dynamodb_table")
    assert line["has_recovery_point"] is True and kind in json.dumps(line)


def test_L80c_context_says_no_recovery_point_for_an_existing_table_with_data_and_none():
    facts = answer_for_infra("data", base_with(), analysis_id="a").model_dump(mode="json")["facts"]
    assert [f["has_recovery_point"] for f in facts if f["resource_type"] == "dynamodb_table"] == [False]


def test_L80c_pitr_is_a_recovery_point_for_a_delete_only_because_aws_keeps_a_system_backup():
    """The reason is stated in the answer so it can be checked against the AWS page, not taken on trust."""
    base = base_with(table(pitr_enabled=True))
    body = _dump(_check(base, apply_change(base, delete())))
    assert "system backup" in json.dumps(_answers(body)["data"]) and "35 days" in json.dumps(_answers(body)["data"])
    assert "PointInTimeRecovery_Howitworks.html" in json.dumps(_answers(body)["data"])


def test_L80c_other_tables_are_not_recovered_by_this_tables_backup():
    base = base_with(table(), table("audit", has_backup=True))
    branch = apply_change(base, delete())
    assert [x.resource_id for x in analyze_deletions(base, branch).data_lost] == [ORDERS]


def test_L80c_check_lens_and_verdict_agree_for_every_state():
    states = [
        dict(item_count=5), dict(item_count=5, has_backup=True), dict(item_count=5, pitr_enabled=True), dict(item_count=0),
        dict(item_count=None), dict(item_count=5, pitr_enabled=None), dict(item_count=5, has_backup=None),
        dict(item_count=None, pitr_enabled=True),
    ]
    for extra in states:
        base = base_with(table(**extra))
        branch = apply_change(base, delete())
        lens = analyze_deletions(base, branch)
        fact = data_facts(_dump(_check(base, branch)))
        assert len(fact) == 1, extra
        if lens.data_lost:
            assert fact[0]["has_recovery_point"] is False, extra
        elif lens.recovery_unknown:
            assert fact[0]["has_recovery_point"] is None, extra
        else:
            assert fact[0]["has_recovery_point"] is True, extra
        assert len(lens.data_lost) + len(lens.recovery_unknown) + len(lens.recovery_points) == 1, extra


# ── L80d unknown is unknown ────────────────────────────────────────────────────

def test_L80d_unknown_item_count_with_no_recovery_point_is_unknown_never_pass_never_lost():
    base = base_with(table(item_count=None))
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    assert lens.data_lost == [] and lens.recovery_points == []
    assert [(x.resource_id, x.resource_type) for x in lens.recovery_unknown] == [(ORDERS, "dynamodb_table")]
    verdict = combined_verdict(base, branch, run_scanners=False)
    got = {_code(r): _level(r) for r in verdict.reasons}
    assert got.get("data_store_deleted_recovery_unknown") == "warn" and verdict.verdict != "pass"
    assert "data_store_deleted_no_recovery_point" not in got and "data_store_deleted_with_recovery_point" not in got
    body = _dump(_check(base, branch))
    assert data_facts(body) == [{"resource_id": ORDERS, "resource_type": "dynamodb_table", "change": "deleted",
                                 "has_recovery_point": None, "recovery_resource_ids": []}]
    assert "item count" in data_unknown(body)[("recovery_unknown", ORDERS)]


@pytest.mark.parametrize("extra", [dict(pitr_enabled=None), dict(has_backup=None)])
def test_L80d_an_unreadable_recovery_source_with_items_is_unknown(extra):
    base = base_with(table(**extra))
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    assert lens.data_lost == [] and [x.resource_id for x in lens.recovery_unknown] == [ORDERS]
    assert data_facts(_dump(_check(base, branch)))[0]["has_recovery_point"] is None


def test_L80d_a_known_recovery_point_beats_an_unknown_item_count():
    base = base_with(table(item_count=None, pitr_enabled=True))
    lens = analyze_deletions(base, apply_change(base, delete()))
    assert lens.recovery_unknown == [] and [p.kind for p in lens.recovery_points] == ["dynamodb_system_backup"]


def test_L80d_a_denied_dynamodb_collection_is_unknown_in_the_data_answers():
    for status in ("denied", "error"):
        base = base_with()
        base.collection = {**base.collection, "dynamodb": status}
        body = _dump(_check(base, apply_change(base, delete())))
        reasons = {u["topic"]: u["reason"] for u in _answers(body)["data"]["unknown"]}
        assert status in reasons.get("dynamodb", ""), reasons
        context = answer_for_infra("data", base, analysis_id="a").model_dump(mode="json")
        assert any(u["topic"] == "dynamodb" and status in u["reason"] for u in context["unknown"])
    ok = answer_for_infra("data", base_with(), analysis_id="a").model_dump(mode="json")
    assert "dynamodb" in {k["topic"] for k in ok["known"]}


def test_L80d_the_unknown_notes_name_aws_backup_as_not_read():
    base = base_with()
    body = _dump(_check(base, apply_change(base, delete())))
    assert "AWS Backup" in json.dumps(_answers(body)["data"]["unknown"])


# ── L80e reported empty ────────────────────────────────────────────────────────

def test_L80e_a_table_reported_empty_is_not_lost_and_carries_the_approximation_note():
    base = base_with(table(item_count=0))
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    assert lens.data_lost == [] and [(p.resource_id, p.kind) for p in lens.recovery_points] == [(ORDERS, "reported_empty_table")]
    body = _dump(_check(base, branch))
    assert data_facts(body)[0]["has_recovery_point"] is True
    reason = data_unknown(body)[("item_count_approximate", ORDERS)]
    assert ITEM_COUNT_URL in reason and "six hours" in reason


def test_L80e_the_note_is_only_for_tables_reported_empty():
    base = base_with(table(item_count=7, has_backup=True))
    body = _dump(_check(base, apply_change(base, delete())))
    assert ("item_count_approximate", ORDERS) not in data_unknown(body)


# ── L80f recovery removed ──────────────────────────────────────────────────────

def test_L80f_turning_pitr_off_is_a_recovery_removed_fact_and_a_warning():
    base = base_with(table(pitr_enabled=True))
    branch = apply_change(base, modify(pitr_enabled=False))
    assert recovery_removals(base, branch) == [(ORDERS, "dynamodb_table")]
    body = _dump(_check(base, branch))
    assert data_facts(body) == [{"resource_id": ORDERS, "resource_type": "dynamodb_table", "change": "recovery_removed",
                                 "has_recovery_point": None, "recovery_resource_ids": []}]
    verdict = combined_verdict(base, branch, run_scanners=False)
    assert {_code(r): _level(r) for r in verdict.reasons}["recovery_point_removed"] == "warn"


def test_L80f_other_changes_are_not_recovery_removals():
    base = base_with(table(pitr_enabled=False))
    assert recovery_removals(base, apply_change(base, modify(pitr_enabled=True))) == []
    assert recovery_removals(base, apply_change(base, modify(deletion_protection_enabled=True))) == []
    on = base_with(table(pitr_enabled=True))
    assert recovery_removals(on, apply_change(on, modify(deletion_protection_enabled=True))) == []
    assert data_facts(_dump(_check(on, apply_change(on, modify(pitr_enabled=True))))) == []


def test_L80f_the_diff_shows_the_pitr_flip_with_before_and_after():
    base = base_with(table(pitr_enabled=True))
    entry = next(i for i in diff_infrastructure(base, apply_change(base, modify(pitr_enabled=False))).resources_modified
                 if i["resource_type"] == "dynamodb_table")
    assert entry["values"] == {"base.pitr_enabled": {"before": True, "after": False}}
    entry = next(i for i in diff_infrastructure(base, apply_change(base, modify(deletion_protection_enabled=True))).resources_modified
                 if i["resource_type"] == "dynamodb_table")
    assert entry["values"] == {"base.deletion_protection_enabled": {"before": False, "after": True}}


# ── L80g availability dependents ───────────────────────────────────────────────

def test_L80g_deleting_a_table_a_lambda_role_can_access_lists_its_dependents_via_can_access():
    base = base_with(access=True)
    graph = build_graph(base)
    table_id = next(n.id for n in graph.nodes if n.resource_type == "dynamodb_table")
    assert any(e["relationship"] == "can_access" and e["to"] == table_id and e["from"].endswith("DlWorkerRole") for e in graph.edges)
    branch = apply_change(base, delete())
    lens = analyze_deletions(base, branch)
    relations = {(i.resource_id, i.relation) for i in lens.impacts}
    assert any(rid.endswith("DlWorkerRole") and relation == "can_access" for rid, relation in relations), relations
    assert any(rid == "dl-worker" or rid.endswith("dl-worker") for rid, _ in relations), relations
    availability = _answers(_dump(_check(base, branch)))["availability"]["facts"]
    assert any(f["change"] == "dependent_of_deleted" and f["resource_id"].endswith("DlWorkerRole") for f in availability), availability


def test_L80g_a_table_nothing_uses_has_no_dependents():
    base = base_with(access=False)
    assert analyze_deletions(base, apply_change(base, delete())).impacts == []


# ── L80h mutations ─────────────────────────────────────────────────────────────

def test_L80h_capabilities_are_delete_and_modify_only():
    entry = next(r for r in mutation_capabilities().resources if r.resource_type == "dynamodb_table")
    assert entry.operations == ["delete", "modify"]
    with pytest.raises(ValueError, match="supports delete, modify only"):
        apply_change(base_with(), Change(op="add", resource_type="dynamodb_table", resource_id="new", fields={}))


def test_L80h_delete_removes_the_table_ledgers_it_and_keeps_summaries_right():
    base = base_with(table(), table("audit", pitr_enabled=True))
    base.dynamodb.tables_without_pitr = [ORDERS]
    branch = apply_change(base, delete())
    assert [t.name for t in branch.dynamodb.tables] == ["audit"]
    assert branch.dynamodb.total_tables == 1 and branch.dynamodb.tables_without_pitr == []
    assert [t.name for t in base.dynamodb.tables] == [ORDERS, "audit"]  # pure
    from app.mutations import deletion_ledger
    ledger = deletion_ledger(branch)
    assert [(x["resource_type"], x["resource_id"]) for x in ledger] == [("dynamodb_table", ORDERS)]
    assert ledger[0]["state_before"]["item_count"] == 1200


def test_L80h_modify_pitr_and_deletion_protection_are_pure_and_keep_summaries_right():
    base = base_with(table())
    base.dynamodb.tables_without_pitr = [ORDERS]
    branch = apply_change(base, modify(pitr_enabled=True, deletion_protection_enabled=True))
    changed = find(branch)
    assert (changed.pitr_enabled, changed.deletion_protection_enabled) == (True, True)
    assert branch.dynamodb.tables_without_pitr == []
    assert find(base).pitr_enabled is False
    back = apply_change(branch, modify(pitr_enabled=False))
    assert back.dynamodb.tables_without_pitr == [ORDERS]


@pytest.mark.parametrize("fields", [
    {"item_count": 0}, {"has_backup": True}, {"billing_mode": "PROVISIONED"}, {"arn": "x"}, {"name": "other"},
    {"encryption_type": "KMS"}, {"nonsense": True}, {},
])
def test_L80h_only_pitr_and_deletion_protection_can_be_modified(fields):
    with pytest.raises(ValueError):
        apply_change(base_with(), modify(**fields))


@pytest.mark.parametrize("field", ["pitr_enabled", "deletion_protection_enabled"])
@pytest.mark.parametrize("value", ["true", 1, None, [True]])
def test_L80h_values_are_strict_booleans(field, value):
    with pytest.raises(ValueError):
        apply_change(base_with(), modify(**{field: value}))


def test_L80h_a_missing_table_names_no_resource():
    for change in (modify("ghost", pitr_enabled=True), delete("ghost")):
        with pytest.raises(TargetNotFound) as raised:
            apply_change(base_with(), change)
        assert "ghost" not in str(raised.value)


def test_L80h_delete_takes_no_options():
    with pytest.raises(ValueError):
        apply_change(base_with(), Change(op="delete", resource_type="dynamodb_table", resource_id=ORDERS, fields={"skip_backup": True}))


def test_L80h_deletion_protection_blocks_the_delete_until_the_branch_turns_it_off():
    base = base_with(table(deletion_protection_enabled=True))
    with pytest.raises(ValueError, match="deletion_protection_enabled"):
        apply_change(base, delete())
    branch = apply_changes(base, [modify(deletion_protection_enabled=False), delete()])
    assert branch.dynamodb.tables == []
    unknown = base_with(table(deletion_protection_enabled=None))
    assert apply_change(unknown, delete()).dynamodb.tables == []  # unknown is not "protected"


def test_L80h_the_table_is_a_graph_node_with_the_fields_a_diff_needs():
    graph = build_graph(base_with(table(pitr_enabled=True, deletion_protection_enabled=True)))
    node = next(n for n in graph.nodes if n.resource_type == "dynamodb_table")
    assert node.base["pitr_enabled"] is True and node.base["deletion_protection_enabled"] is True
    from app.graph_schema import validate_graph
    validate_graph(graph)


# ── L80i four formats ──────────────────────────────────────────────────────────

def _api(operation, **parameters):
    return translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "dynamodb", "operation": operation, "parameters": parameters}]})


def _cli(command):
    return translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [command]}))


def _tf_object(name=ORDERS, pitr=False, protection=False):
    return {"name": name, "id": name, "arn": arn(name), "billing_mode": "PAY_PER_REQUEST", "deletion_protection_enabled": protection,
            "point_in_time_recovery": [{"enabled": pitr, "recovery_period_in_days": 35 if pitr else 0}], "hash_key": "k"}


def _tf(actions, before, after, unknown=None):
    return translate_plan({"format_version": "1.2", "resource_changes": [{
        "address": "aws_dynamodb_table.orders", "type": "aws_dynamodb_table", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}}}]})


def _cfn(action, properties=None, before=None, replacement="False", policy=None):
    change = {"Action": action, "LogicalResourceId": "Orders", "ResourceType": "AWS::DynamoDB::Table",
              "PhysicalResourceId": ORDERS, "Replacement": replacement}
    if properties is not None:
        change["AfterContext"] = json.dumps({"Properties": properties})
    if before is not None:
        change["BeforeContext"] = json.dumps({"Properties": before})
    if policy:
        change["Details"] = []
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": change}]})
    return translate_api_calls(doc), extras


def _state(result, base):
    assert result["unknown_fields"] == [] and result["unmodeled"] == []
    return apply_changes(base, result["changes"]).dynamodb.model_dump(mode="json")


def _same(results, base):
    states = {name: _state(result, base) for name, result in results.items()}
    assert len({json.dumps(s, sort_keys=True) for s in states.values()}) == 1, states
    answers = {name: json.dumps(_answers(_dump(_check(base, apply_changes(base, r["changes"]))))["data"], sort_keys=True) for name, r in results.items()}
    assert len(set(answers.values())) == 1, answers
    calls = {name: json.dumps(build_api_calls(base, r["changes"]), sort_keys=True) for name, r in results.items()}
    assert len(set(calls.values())) == 1, calls
    return states


def test_L80i_delete_gives_the_same_branch_and_the_same_data_answer_in_all_four_formats():
    base = base_with()
    cfn, extras = _cfn("Remove", before={"TableName": ORDERS})
    assert extras == []
    results = {"api": _api("DeleteTable", TableName=ORDERS), "cli": _cli(f"aws dynamodb delete-table --table-name {ORDERS}"),
               "cfn": cfn, "terraform": _tf(["delete"], _tf_object(), None)}
    states = _same(results, base)
    assert next(iter(states.values()))["tables"] == []
    for name, result in results.items():
        assert [(c.op, c.resource_type, c.resource_id, c.fields) for c in result["changes"]] == [("delete", "dynamodb_table", ORDERS, {})], name
    body = _dump(_check(base, apply_changes(base, results["terraform"]["changes"])))
    assert data_facts(body)[0]["has_recovery_point"] is False


def test_L80i_the_arn_of_the_table_names_it_in_a_delete_call():
    result = _api("DeleteTable", TableName=arn(ORDERS))
    assert [(c.op, c.resource_id) for c in result["changes"]] == [("delete", ORDERS)]


def test_L80i_turning_pitr_off_gives_the_same_branch_in_all_four_formats():
    base = base_with(table(pitr_enabled=True))
    cfn, extras = _cfn("Modify", {"TableName": ORDERS, "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False}},
                       before={"TableName": ORDERS, "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}})
    assert extras == []
    results = {
        "api": _api("UpdateContinuousBackups", TableName=ORDERS, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": False}),
        "cli": _cli(f"aws dynamodb update-continuous-backups --table-name {ORDERS} --point-in-time-recovery-specification '{{\"PointInTimeRecoveryEnabled\":false}}'"),
        "cfn": cfn,
        "terraform": _tf(["update"], _tf_object(pitr=True), _tf_object(pitr=False)),
    }
    states = _same(results, base)
    assert next(iter(states.values()))["tables"][0]["pitr_enabled"] is False
    for name, result in results.items():
        assert [(c.op, c.resource_id, c.fields) for c in result["changes"]] == [("modify", ORDERS, {"pitr_enabled": False})], name
        body = _dump(_check(base, apply_changes(base, result["changes"])))
        assert [f["change"] for f in data_facts(body)] == ["recovery_removed"], name
    assert [c["operation"] for c in build_api_calls(base, results["api"]["changes"])] == ["UpdateContinuousBackups"]


def test_L80i_deletion_protection_gives_the_same_branch_in_all_four_formats():
    base = base_with(table(deletion_protection_enabled=True))
    cfn, extras = _cfn("Modify", {"TableName": ORDERS, "DeletionProtectionEnabled": False},
                       before={"TableName": ORDERS, "DeletionProtectionEnabled": True})
    assert extras == []
    results = {
        "api": _api("UpdateTable", TableName=ORDERS, DeletionProtectionEnabled=False),
        "cli": _cli(f"aws dynamodb update-table --table-name {ORDERS} --no-deletion-protection-enabled"),
        "cfn": cfn,
        "terraform": _tf(["update"], _tf_object(protection=True), _tf_object(protection=False)),
    }
    states = _same(results, base)
    assert next(iter(states.values()))["tables"][0]["deletion_protection_enabled"] is False
    assert [c["operation"] for c in build_api_calls(base, results["api"]["changes"])] == ["UpdateTable"]


def test_L80i_cloudformation_string_booleans_are_read_and_unresolved_values_are_extras():
    ok, extras = _cfn("Modify", {"TableName": ORDERS, "DeletionProtectionEnabled": "true"}, before={"TableName": ORDERS, "DeletionProtectionEnabled": "false"})
    assert extras == [] and [c.fields for c in ok["changes"]] == [{"deletion_protection_enabled": True}]
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Modify", "LogicalResourceId": "Orders", "ResourceType": "AWS::DynamoDB::Table", "PhysicalResourceId": ORDERS,
        "Replacement": "False", "AfterContext": json.dumps({"Properties": {"TableName": ORDERS, "DeletionProtectionEnabled": {"Ref": "Flag"}}}),
        "BeforeContext": json.dumps({"Properties": {"TableName": ORDERS, "DeletionProtectionEnabled": True}})}}]})
    assert doc["calls"] == [] and [e["type"] for e in extras] and "MissingPropertyValues" in json.dumps(extras)


def test_L80i_a_cloudformation_replacement_deletes_the_table_and_says_the_new_one_is_not_modeled():
    result, extras = _cfn("Modify", {"TableName": ORDERS}, before={"TableName": ORDERS}, replacement="True")
    assert [(c.op, c.resource_id) for c in result["changes"]] == [("delete", ORDERS)]


def test_L80i_a_terraform_replace_deletes_the_table_and_the_new_table_is_unmodeled():
    result = _tf(["delete", "create"], _tf_object(), _tf_object(), {"arn": True, "id": True})
    assert [(c.op, c.resource_id) for c in result["changes"]] == [("delete", ORDERS)]
    assert [u["address"] for u in result["unmodeled"]] == ["aws_dynamodb_table.orders"]


def test_L80i_terraform_create_is_unmodeled_and_unknown_values_stay_visible():
    created = _tf(["create"], None, _tf_object(), {"arn": True, "id": True})
    assert created["changes"] == [] and [u["address"] for u in created["unmodeled"]] == ["aws_dynamodb_table.orders"]
    unknown = _tf(["update"], _tf_object(pitr=True), _tf_object(pitr=True), {"point_in_time_recovery": [{"enabled": True}]})
    assert unknown["changes"] == [] and [(u["address"], u["field"]) for u in unknown["unknown_fields"]] == [
        ("aws_dynamodb_table.orders", "point_in_time_recovery")]
    same = _tf(["update"], _tf_object(), _tf_object())
    assert same["changes"] == [] and same["unknown_fields"] == []


def test_L80i_unsupported_api_members_are_unknown_fields():
    result = _api("UpdateTable", TableName=ORDERS, DeletionProtectionEnabled=True, BillingMode="PROVISIONED")
    assert [c.fields for c in result["changes"]] == [{"deletion_protection_enabled": True}]
    assert [(u["field"], u["reason"]) for u in result["unknown_fields"]] == [("BillingMode", "unsupported_attribute")]
    only = _api("UpdateTable", TableName=ORDERS, BillingMode="PROVISIONED")
    assert only["changes"] == [] and [u["field"] for u in only["unknown_fields"]] == ["BillingMode"]


def test_L80i_invalid_calls_are_rejected_not_guessed():
    for bad in (dict(TableName=""), dict()):
        with pytest.raises(ValueError):
            _api("DeleteTable", **bad)
    with pytest.raises(ValueError):
        _api("UpdateContinuousBackups", TableName=ORDERS, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": "yes"})
    with pytest.raises(ValueError):
        _api("UpdateTable", TableName=ORDERS, DeletionProtectionEnabled="yes")


def test_L80i_other_dynamodb_calls_stay_unmodeled():
    result = _api("CreateBackup", TableName=ORDERS, BackupName="manual-1")
    assert result["changes"] == [] and len(result["unmodeled"]) == 1


# ── L80j hand-back ─────────────────────────────────────────────────────────────

def test_L80j_hand_back_builds_the_exact_calls():
    base = base_with(table(pitr_enabled=True, deletion_protection_enabled=False))
    assert [(c["service"], c["operation"], c["params"]) for c in build_api_calls(base, [delete()])] == [
        ("dynamodb", "DeleteTable", {"TableName": ORDERS})]
    assert [(c["operation"], c["params"]) for c in build_api_calls(base, [modify(pitr_enabled=False)])] == [
        ("UpdateContinuousBackups", {"TableName": ORDERS, "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": False}})]
    assert [(c["operation"], c["params"]) for c in build_api_calls(base, [modify(deletion_protection_enabled=True)])] == [
        ("UpdateTable", {"TableName": ORDERS, "DeletionProtectionEnabled": True})]
    both = build_api_calls(base, [modify(pitr_enabled=False, deletion_protection_enabled=True)])
    assert [c["operation"] for c in both] == ["UpdateContinuousBackups", "UpdateTable"]


def test_L80j_every_call_is_valid_against_the_botocore_model():
    import botocore.session
    from botocore.validate import ParamValidator

    model = botocore.session.get_session().get_service_model("dynamodb")
    base = base_with()
    for change in (delete(), modify(pitr_enabled=True), modify(deletion_protection_enabled=True)):
        for call in build_api_calls(base, [change]):
            shape = model.operation_model(call["operation"]).input_shape
            assert not ParamValidator().validate(call["params"], shape).has_errors(), call


def test_L80j_a_table_that_is_not_in_the_snapshot_is_refused():
    with pytest.raises(UnmappableChanges):
        build_api_calls(base_with(), [delete("ghost")])


# ── L80k catalog and IAM ───────────────────────────────────────────────────────

def test_L80k_catalog_fields_trace_to_botocore_dynamodb_members():
    catalog = CATALOG["dynamodb_table"]
    assert resolve(catalog["pitr_enabled"]).type_name == "boolean"
    assert resolve(catalog["deletion_protection_enabled"]).type_name == "boolean"
    assert {source.service for source in catalog.values() if hasattr(source, "service")} == {"dynamodb"}
    from app.field_catalog import Derived
    assert {f for f, s in catalog.items() if isinstance(s, Derived)} >= {"arn", "item_count", "has_backup", "billing_mode"}


# What the managed policy arn:aws:iam::aws:policy/SecurityAudit grants for DynamoDB, from
# https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html (fetched 2026-11-07).
SECURITY_AUDIT_DYNAMODB_READS = {
    "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTable", "dynamodb:ListBackups", "dynamodb:ListTables",
}


@pytest.mark.parametrize("path", ["iam-role.yaml", "backend/cloudformation/iam-role.yaml"])
def test_L80k_the_role_covers_every_dynamodb_read_the_collector_makes_and_grants_no_dynamodb_write(path):
    from app.dynamodb_table import COLLECTOR_OPERATIONS

    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    document = yaml.load((ROOT / path).read_text(), Loader=Loader)
    properties = document["Resources"]["EmfirgeReadOnlyRole"]["Properties"]
    assert "arn:aws:iam::aws:policy/SecurityAudit" in properties["ManagedPolicyArns"]
    explicit = {a for statement in properties["Policies"][0]["PolicyDocument"]["Statement"] for a in statement["Action"]
                if a.startswith("dynamodb:")}
    needed = {f"dynamodb:{operation}" for operation in COLLECTOR_OPERATIONS}
    assert needed <= explicit | SECURITY_AUDIT_DYNAMODB_READS
    assert not [a for a in explicit if a.split(":")[1].startswith(("Put", "Update", "Delete", "Create", "Restore", "Batch", "Tag", "Untag", "Scan", "Query", "GetItem"))]


def test_L80k_the_collector_operations_are_what_the_collector_calls(fake_aws, monkeypatch):
    from botocore.client import BaseClient
    from app.dynamodb_table import COLLECTOR_OPERATIONS

    _make(fake_aws)
    seen = set()
    original = BaseClient._make_api_call
    monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (seen.add(op), original(self, op, params))[1])
    _collect()
    assert seen == set(COLLECTOR_OPERATIONS)


# ── L80l compatibility and boundary ────────────────────────────────────────────

def test_L80l_old_snapshots_without_the_new_fields_load_with_unknowns_not_guesses():
    legacy = base_with().model_dump(mode="json")
    for t in legacy["dynamodb"]["tables"]:
        t.pop("deletion_protection_enabled", None)
    old = AWSInfrastructure.model_validate(legacy)
    assert find(old).deletion_protection_enabled is None
    bare = DynamoDBTable(name="x", arn=arn("x"))
    assert bare.item_count is None and bare.deletion_protection_enabled is None
    restored = AWSInfrastructure.model_validate(json.loads(base_with().model_dump_json()))
    assert find(restored) == find(base_with())


def test_L80l_dynamodb_logic_lives_in_adapter_modules_only():
    from tests.laws.test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, CORE_MODULES, _imported_names

    assert "dynamodb_table" in ADAPTER_MODULES and "dynamodb_table" not in CORE_MODULES
    for core in CORE_MODULES:
        assert "dynamodb_table" not in _imported_names(core), core
    assert ALLOWED["delete_lens"] == {"mutations"} and ALLOWED["verdict"] == {
        "tags", "iam_escalation", "mutations", "models", "plan_ingest", "scanners"}


def test_L80l_no_free_text_of_the_data_answer_holds_a_table_name_or_arn():
    base = base_with(table(item_count=0))
    body = _dump(_check(base, apply_change(base, delete())))
    answer = _answers(body)["data"]
    texts = [v for v in _json_values({"checked": answer["checked"], "unknown": [u["reason"] for u in answer["unknown"]]}) if isinstance(v, str)]
    assert texts and not [t for t in texts if ORDERS in t or ACCOUNT in t or "arn:aws" in t]


def test_L80l_api_branch_flow_blocks_the_delete_and_lists_the_capability(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = base_with()
    main._branch_request_log.clear()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l80-api", "name": "l80-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    capabilities = client.get("/branches/capabilities").json()
    entry = next(r for r in capabilities["resources"] if r["resource_type"] == "dynamodb_table")
    assert entry["operations"] == ["delete", "modify"]
    assert [c["allowed_fields"] for c in entry["constraints"]] == [["pitr_enabled", "deletion_protection_enabled"]]
    bad = client.post(f"/branches/{branch_id}/changes", json={"op": "modify", "resource_type": "dynamodb_table", "resource_id": ORDERS,
                                                              "fields": {"pitr_enabled": "true"}})
    assert bad.status_code == 422, bad.text
    ok = client.post(f"/branches/{branch_id}/changes", json={"op": "delete", "resource_type": "dynamodb_table", "resource_id": ORDERS, "fields": {}})
    assert ok.status_code == 200, ok.text
    verdict = client.get(f"/branches/{branch_id}/verdict").json()
    assert verdict["verdict"] == "block" and "data_store_deleted_no_recovery_point" in {r["code"] for r in verdict["reasons"]}
    handback = client.get(f"/branches/{branch_id}/handback")
    assert handback.status_code == 200, handback.text
    assert [(c["service"], c["operation"]) for c in handback.json()["calls"]] == [("dynamodb", "DeleteTable")]
    main._branch_request_log.clear()
