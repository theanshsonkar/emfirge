"""L87: every changed setting on a branch is in the check, judged or named as not judged. Never silent.

``GET /branches/{id}/check`` lists ``changed_settings``: one entry per (resource, setting) that differs between the
base and the branch, outside the six answers. Each entry says whether a check reads that setting (``judged`` and
``judged_by`` the damages) or not. Field NAMES only, never values. This is a statement about our own checks, not
about AWS behaviour.

L87a  an unchanged branch has an empty list
L87b  generic: every setting a branch can change, on every resource type it can modify, gives an entry
L87c  entry shape is closed; judged <-> judged_by; no value, no verdict-like name; sorted and unique
L87d  values never appear (tags, policies, secrets, ids of other resources)
L87e  deterministic: repeat, and shuffled independent changes
L87f  a changed setting is a change: not "unchanged", no baseline
L87g  noise: computed fields and counts do not bury the settings; tags are one entry per resource
L87h  the judged map is declared in the adapter, names real fields, and the reading code really uses each one
L87i  the core stays neutral (L56) and holds no field knowledge of its own
L87j  the judged / not judged split is honest for known examples
"""
from __future__ import annotations

import copy
import json
import random
import re
from pathlib import Path

import pytest

from app.field_catalog import CATALOG, Derived
from app.models import DynamoDBData, DynamoDBTable, NetworkACL, RolePolicy, SchedulerData, SchedulerSchedule
from app.mutations import _MUTATION_CAPABILITIES, Change, apply_change
from tests.incidents.synthetic_base import load_synthetic_base

from .test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, AWS_LIBS, CORE_MODULES
from .test_cloudfront_laws import DIST, base_with, distribution

APP_DIR = Path(__file__).resolve().parents[2] / "app"
DAMAGES = ("data", "exposure", "money", "availability", "control", "outside_world")
ENTRY_KEYS = {"resource_id", "resource_type", "field", "judged", "judged_by"}
ROLE = "arn:aws:iam::000000000000:role/DlWorkerRole"
SENTINEL = "zzsentinelvalue"
REVISION = "r" * 64


def _check(base, branch=None):
    from app.aws_check import check_for_branch
    branch = base.model_copy(deep=True) if branch is None else branch
    return check_for_branch(base, branch, branch_id="law-branch", base_analysis_id="law-base", branch_revision=REVISION)


def _settings(base, branch) -> list[dict]:
    return _check(base, branch).model_dump(mode="json")["changed_settings"]


def _law_base():
    base = base_with(distribution())
    acl = NetworkACL(id="acl-law-base", vpc_id=base.vpc.subnets[0].vpc_id if base.vpc.subnets else "vpc-law")
    schedule = SchedulerSchedule(name="sched-law-base", state="DISABLED", schedule_expression="rate(1 day)",
                                 target_arn="arn:aws:lambda:us-east-1:000000000000:function:dl-worker",
                                 target_role_arn=ROLE, flexible_time_window_mode="OFF")
    table = DynamoDBTable(name="ddb-law-base", arn="arn:aws:dynamodb:us-east-1:000000000000:table/ddb-law-base", item_count=1)
    base = base.model_copy(update={"vpc": base.vpc.model_copy(update={"nacls": [acl]}),
                                   "scheduler": SchedulerData(schedules=[schedule]),
                                   "dynamodb": DynamoDBData(total_tables=1, tables=[table])})
    base = apply_change(base, Change(op="add", resource_type="iam_user", resource_id="law-user", fields={}))
    # the synthetic base carries stale security group attachments; a branch recomputes them, so settle them first
    settled = apply_change(base, Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"imdsv2_required": False}))
    return settled if settled.model_dump() != base.model_dump() else base


# resource type -> (resource id the change names, resource type/id the diff reports)
SAMPLES = {
    "ec2_instance": ("i-dl-web", "ec2_instance", "i-dl-web"),
    "security_group": ("sg-dl-unused", "security_group", "sg-dl-unused"),
    "rds_instance": ("db-dl-prod", "rds_instance", "db-dl-prod"),
    "s3_bucket": ("dl-data-bucket", "s3_bucket", "dl-data-bucket"),
    "lambda_function": ("dl-worker", "lambda_function", "dl-worker"),
    "iam_role": (ROLE, "iam_role", "iam-role-DlWorkerRole"),
    "iam_role_policy": (ROLE, "iam_role", "iam-role-DlWorkerRole"),
    "iam_user": ("law-user", "iam_user", "law-user"),
    "scheduler_schedule": ("default/sched-law-base", "scheduler_schedule", "default/sched-law-base"),
    "dynamodb_table": ("ddb-law-base", "dynamodb_table", "ddb-law-base"),
    "cloudfront_distribution": (DIST, "cloudfront_distribution", DIST),
    "network_acl": ("acl-law-base", "network_acl", "acl-law-base"),
    "route_table": ("rtb-dl-pub", "route_table", "rtb-dl-pub"),
}

class _Multi(dict):
    """A candidate that sets several fields at once (a setting that is only valid together with another)."""


_STATEMENT = [{"effect": "allow", "actions": ["s3:GetObject"], "resources": ["*"]}]
_RULE = [{"protocol": "tcp", "from_port": 8443, "to_port": 8443, "ip_ranges": ["10.1.0.0/16"]}]
_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
# extra candidates per (type, field); bool / int / str flips are generated from the current value
CANDIDATES = {
    ("ec2_instance", "type"): ["t3.large", "m5.large"],
    ("ec2_instance", "subnet_id"): ["subnet-dl-priv"],
    ("ec2_instance", "sg_ids"): [["sg-dl-unused"], ["sg-dl-db"], []],
    ("ec2_instance", "state"): ["stopped", "running"],
    ("ec2_instance", "instance_profile_arn"): ["arn:aws:iam::000000000000:instance-profile/law-alt"],
    ("ec2_instance", "block_devices"): [[{"volume_id": "vol-dl-data", "device_name": "/dev/sdf", "delete_on_termination": True}], []],
    ("ec2_instance", "tags"): [{"law": SENTINEL}],
    ("security_group", "name"): ["law-renamed"],
    ("security_group", "rules"): [_RULE],
    ("security_group", "egress_rules"): [_RULE],
    ("security_group", "tags"): [{"law": SENTINEL}],
    ("rds_instance", "sg_ids"): [["sg-dl-unused"], []],
    ("rds_instance", "subnet_id"): ["subnet-dl-priv"],
    ("rds_instance", "engine"): ["postgres", "mysql"],
    ("rds_instance", "port"): [5433, 3307],
    ("rds_instance", "backup_retention_days"): [3, 0],
    ("rds_instance", "log_exports"): [["audit"], ["postgresql"], []],
    ("rds_instance", "monitoring_interval"): [60, 0],
    ("rds_instance", "tags"): [{"law": SENTINEL}],
    ("s3_bucket", "policy"): [json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                                                                                  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::dl-data-bucket/*"}]})],
    ("s3_bucket", "tags"): [{"law": SENTINEL}],
    ("lambda_function", "role_arn"): [ROLE.replace("DlWorkerRole", "DlAppRole")],
    ("lambda_function", "vpc_id"): ["vpc-law-alt"],
    ("lambda_function", "subnet_ids"): [["subnet-dl-priv"]],
    ("lambda_function", "sg_ids"): [["sg-dl-unused"]],
    ("lambda_function", "secret_refs"): [[SENTINEL], ["arn:aws:secretsmanager:us-east-1:000000000000:secret:law-alt"]],
    ("lambda_function", "tags"): [{"law": SENTINEL}],
    ("iam_role", "trust_policy"): [_TRUST],
    ("iam_role_policy", "access_statements"): [_STATEMENT],
    ("iam_user", "access_statements"): [_STATEMENT],
    ("iam_user", "policy_documents"): [[{"name": "law", "kind": "inline", "statements": _STATEMENT}]],
    ("iam_role_policy", "policy_documents"): [[{"name": "law", "kind": "inline", "statements": _STATEMENT}]],
    ("scheduler_schedule", "state"): ["ENABLED"],
    ("scheduler_schedule", "schedule_expression"): ["rate(2 days)"],
    ("scheduler_schedule", "schedule_expression_timezone"): ["Europe/Paris"],
    ("scheduler_schedule", "flexible_time_window_mode"): ["FLEXIBLE"],
    ("scheduler_schedule", "flexible_time_window_minutes"): [_Multi(flexible_time_window_mode="FLEXIBLE", flexible_time_window_minutes=5)],
    ("scheduler_schedule", "target_arn"): ["arn:aws:lambda:us-east-1:000000000000:function:dl-batch"],
    ("scheduler_schedule", "target_role_arn"): [ROLE.replace("DlWorkerRole", "DlAppRole")],
    ("scheduler_schedule", "start_date"): ["2030-01-01T00:00:00Z"],
    ("scheduler_schedule", "end_date"): ["2031-01-01T00:00:00Z"],
    ("scheduler_schedule", "action_after_completion"): ["DELETE"],
    ("scheduler_schedule", "has_input"): [True],
    ("scheduler_schedule", "unmodeled_settings"): [["Description"]],
    ("cloudfront_distribution", "aliases"): [["law.example.com"]],
    ("cloudfront_distribution", "price_class"): ["PriceClass_100"],
    ("cloudfront_distribution", "web_acl_id"): ["arn:aws:wafv2:us-east-1:000000000000:global/webacl/law/11111111-1111-1111-1111-111111111111"],
    ("cloudfront_distribution", "default_cache_behavior"): [{"viewer_protocol_policy": "https-only"}],
    ("cloudfront_distribution", "cache_behaviors"): [{"feed.xml": {"viewer_protocol_policy": "https-only"}}],
    ("cloudfront_distribution", "origins"): [None],  # built from the current origins below
    ("cloudfront_distribution", "extra"): [{"Comment": "law"}],
    ("cloudfront_distribution", "withheld_settings"): [["OriginCustomHeaders"]],
    ("network_acl", "vpc_id"): ["vpc-law-alt"],
    ("network_acl", "associated_subnet_ids"): [["subnet-dl-priv"]],
    ("network_acl", "entries"): [[{"rule_number": 100, "protocol": "-1", "rule_action": "allow", "egress": False, "cidr_block": "10.0.0.0/8"}]],
    ("route_table", "vpc_id"): ["vpc-law-alt"],
    ("route_table", "routes"): [[{"destination_cidr": "10.9.0.0/16", "target_type": "local", "target_id": "local"}]],
}


def _current(base, rtype, rid):
    from app.mutations import _collection, _identity
    items = [i for i in _collection(base, rtype if rtype != "iam_role_policy" else "iam_role") if _identity(rtype, i) == rid]
    return items[0].model_dump() if items else {}


def _candidates(base, rtype, rid, field):
    current = _current(base, rtype, rid).get(field)
    out = list(CANDIDATES.get((rtype, field), []))
    if isinstance(current, bool):
        out.append(not current)
    elif current is None:
        out += [True, 1, "law-alt"]
    elif isinstance(current, int):
        out.append(current + 1)
    elif isinstance(current, str):
        out.append(current + "-alt")
    if rtype == "cloudfront_distribution" and field == "origins":
        dist = next(d for d in base.cloudfront.distributions if d.id == DIST)
        origins = [o.model_dump(mode="json") for o in dist.origins]
        origins[0] = {**origins[0], "origin_access_control_id": "E3OACLAW00002"}
        out.insert(0, origins)
    return [c for c in out if c is not None]


def _settable(rtype):
    """Catalog fields that are not derived and that a branch modify accepts (the capability's allowed_fields, when it narrows)."""
    allowed = None
    for constraint in _MUTATION_CAPABILITIES[rtype]["constraints"]:
        if "modify" in constraint["operations"] and constraint.get("allowed_fields"):
            allowed = set(constraint["allowed_fields"])
    return sorted(f for f, s in CATALOG[rtype].items() if not isinstance(s, Derived) and (allowed is None or f in allowed))


def _modify_types():
    return sorted(t for t, c in _MUTATION_CAPABILITIES.items() if "modify" in c["operations"])


def _find_change(base, rtype, field):
    """The first candidate value the branch accepts that actually changes the model."""
    rid = SAMPLES[rtype][0]
    errors = []
    for value in _candidates(base, rtype, rid, field):
        fields = dict(value) if isinstance(value, _Multi) else {field: copy.deepcopy(value)}
        change = Change(op="modify", resource_type=rtype, resource_id=rid, fields=fields)
        try:
            branch = apply_change(base, change)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{value!r}: {exc}")
            continue
        if branch.model_dump() != base.model_dump():
            return change, branch
        errors.append(f"{value!r}: no change")
    pytest.fail(f"no sample value for {rtype}.{field}; add one to CANDIDATES ({errors[:3]})")


def _all_cases():
    return [(t, f) for t in _modify_types() for f in _settable(t)]


# ── L87a ──────────────────────────────────────────────────────────

def test_L87a_an_unchanged_branch_has_an_empty_list():
    """L87a: the base compared with itself lists no changed settings, and the key is always present."""
    base = _law_base()
    body = _check(base).model_dump(mode="json")
    assert body["changed_settings"] == []


# ── L87b: the generic law ─────────────────────────────────────────

def test_L87b_every_modifiable_type_is_covered_by_the_samples():
    """L87b: a new modify-capable resource type must be added to SAMPLES (and so to the law)."""
    assert set(_modify_types()) == set(SAMPLES)


@pytest.mark.parametrize("rtype,field", _all_cases())
def test_L87b_changing_any_settable_field_gives_an_entry(rtype, field):
    """L87b: for every modify-capable type and every settable catalog field, the check lists the change (judged or not)."""
    base = _law_base()
    change, branch = _find_change(base, rtype, field)
    _, report_type, report_id = SAMPLES[rtype]
    entries = [e for e in _settings(base, branch) if e["resource_id"] == report_id]
    assert entries, f"{rtype}.{field} changed and nothing in changed_settings names {report_id}"
    assert {e["resource_type"] for e in entries} == {report_type}
    model_fields = set(RolePolicy.model_fields) if rtype in {"iam_role", "iam_role_policy"} else set(
        _MUTATION_CAPABILITIES[rtype]["model"].model_fields)
    if field in model_fields:
        assert field in {e["field"] for e in entries}, (rtype, field, sorted(e["field"] for e in entries))
    # the check as a whole is not unchanged
    body = _check(base, branch).model_dump(mode="json")
    assert report_id in next(c for c in body["changes"] if c["change"] == "modified")["resource_ids"]


def test_L87b_every_entry_of_a_settable_change_is_a_field_of_the_resource_or_a_graph_setting():
    """L87b: an entry names a field of the resource; it is never an empty or layer-only string."""
    base = _law_base()
    for rtype, field in _all_cases():
        _, branch = _find_change(base, rtype, field)
        for entry in _settings(base, branch):
            assert re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?", entry["field"]), (rtype, field, entry)


# ── L87c: shape ───────────────────────────────────────────────────

def test_L87c_closed_shape_and_judged_matches_judged_by():
    """L87c: five keys, judged iff judged_by is non-empty, judged_by are damage names, sorted, no duplicates."""
    base = _law_base()
    seen_judged = seen_not = False
    for rtype, field in _all_cases():
        _, branch = _find_change(base, rtype, field)
        entries = _settings(base, branch)
        for e in entries:
            assert set(e) == ENTRY_KEYS
            assert isinstance(e["judged"], bool)
            assert e["judged"] == bool(e["judged_by"])
            assert set(e["judged_by"]) <= set(DAMAGES)
            assert e["judged_by"] == sorted(set(e["judged_by"]))
            seen_judged |= e["judged"]
            seen_not |= not e["judged"]
        keys = [(e["resource_type"], e["resource_id"], e["field"]) for e in entries]
        assert keys == sorted(keys) and len(keys) == len(set(keys)), keys
    assert seen_judged and seen_not


def test_L87c_no_verdict_like_names_in_the_schema():
    """L87c: the new models are closed and carry no verdict-like field name."""
    from app.check_facts import ChangedSetting, CheckResult
    assert ChangedSetting.model_config.get("extra") == "forbid"
    assert set(ChangedSetting.model_fields) == ENTRY_KEYS
    assert "changed_settings" in CheckResult.model_fields
    for name in list(ChangedSetting.model_fields) + ["changed_settings"]:
        assert not any(part in name for part in ("verdict", "level", "severity", "score", "rule", "code", "fix", "risk", "safe"))


# ── L87d: no values ───────────────────────────────────────────────

def test_L87d_values_never_appear_in_the_list():
    """L87d: tags, policies, secret refs, statements and other values changed on the branch never show up in the list."""
    base = _law_base()
    sentinels = ["zzsentinelvalue", "law-alt", "10.9.0.0/16", "law.example.com", "Europe/Paris", "2030-01-01", "PriceClass_100",
                 "s3:GetObject", "10.1.0.0/16", "law-renamed", "vpc-law-alt", "subnet-law-alt", "t3.large", "E3OACLAW00002"]
    for rtype, field in _all_cases():
        change, branch = _find_change(base, rtype, field)
        encoded = json.dumps(_settings(base, branch), sort_keys=True)
        for needle in sentinels + [json.dumps(v) for v in change.fields.values() if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 99]:
            if needle in json.dumps(base.model_dump(mode="json")):
                continue  # a value the base already carries is not a leak of the branch
            assert needle not in encoded, (rtype, field, needle)
    # and the whole result carries no key that is not a name
    tagged = apply_change(base, Change(op="modify", resource_type="s3_bucket", resource_id="dl-data-bucket", fields={"tags": {"k": SENTINEL}}))
    assert SENTINEL not in json.dumps(_settings(base, tagged))


# ── L87e: determinism ─────────────────────────────────────────────

def test_L87e_repeat_and_shuffled_changes_give_identical_lists():
    """L87e: same branch twice, and independent changes applied in any order, give the same list."""
    base = _law_base()
    changes = [_find_change(base, t, f)[0] for t, f in (
        ("ec2_instance", "imdsv2_required"), ("s3_bucket", "logging_enabled"), ("rds_instance", "multi_az"),
        ("lambda_function", "secret_refs"), ("security_group", "tags"), ("dynamodb_table", "pitr_enabled"))]
    def run(order):
        branch = base
        for change in order:
            branch = apply_change(branch, change)
        return json.dumps(_settings(base, branch), sort_keys=False)
    first = run(changes)
    assert first == run(changes)
    for seed in range(5):
        shuffled = list(changes)
        random.Random(seed).shuffle(shuffled)
        assert run(shuffled) == first
    assert len(json.loads(first)) >= 6


# ── L87f: a change is a change ────────────────────────────────────

def test_L87f_a_setting_only_change_is_not_unchanged():
    """L87f: a branch whose only change is a setting no check reads has no baseline and lists the resource as modified."""
    base = _law_base()
    branch = apply_change(base, Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"imdsv2_required": True}))
    body = _check(base, branch).model_dump(mode="json")
    assert body["baseline"] is None
    assert "i-dl-web" in next(c for c in body["changes"] if c["change"] == "modified")["resource_ids"]
    assert [(e["field"], e["judged"]) for e in body["changed_settings"]] == [("imdsv2_required", False)]


def test_L87f_core_is_unchanged_counts_a_changed_setting():
    """L87f: the core says changed when the neutral list holds a setting, even with nothing else changed."""
    from app.check_facts import CheckInputs, assemble
    from app.verdict import CombinedVerdict
    verdict = CombinedVerdict.model_validate(json.loads(_empty_verdict_json()))
    verdict = verdict.model_copy(update={"resources_modified": [{"id": "x-1", "resource_type": "thing", "changed": ["colour"]}],
                                         "modeled_state_unchanged": True})
    result = assemble(verdict, CheckInputs(branch_id="b", base_analysis_id=None, branch_revision=None))
    assert result.baseline is None
    assert [(s.resource_id, s.resource_type, s.field, s.judged) for s in result.changed_settings] == [("x-1", "thing", "colour", False)]


def _empty_verdict_json() -> str:
    from app.verdict import combined_verdict
    base = _law_base()
    return combined_verdict(base, base.model_copy(deep=True), run_scanners=False).model_dump_json()


# ── L87g: noise ───────────────────────────────────────────────────

def test_L87g_computed_fields_and_counts_do_not_bury_the_settings():
    """L87g: a setting change lists the setting, not the counts, flags and edge lists computed from it."""
    base = _law_base()
    branch = apply_change(base, Change(op="modify", resource_type="security_group", resource_id="sg-dl-unused", fields={"rules": _RULE}))
    fields = [e["field"] for e in _settings(base, branch)]
    assert fields == ["rules"], fields
    branch = apply_change(base, Change(op="modify", resource_type="s3_bucket", resource_id="dl-data-bucket",
                                       fields={"policy": CANDIDATES[("s3_bucket", "policy")][0]}))
    fields = {e["field"] for e in _settings(base, branch)}
    assert "policy" in fields
    assert not {f for f in fields if f.startswith(("base.", "security.", "cost.", "limits.", "telemetry."))} & {"base.has_policy"}


def test_L87g_derived_fields_alone_are_still_listed():
    """L87g: a resource whose only differences are computed fields is not silent: they are listed."""
    from app.check_facts import CheckInputs, assemble
    from app.verdict import CombinedVerdict
    verdict = CombinedVerdict.model_validate(json.loads(_empty_verdict_json())).model_copy(update={
        "resources_modified": [{"id": "x-1", "resource_type": "thing", "changed": ["base.rules_count"]},
                               {"id": "x-2", "resource_type": "thing", "changed": ["colour", "base.rules_count"]}]})
    inputs = CheckInputs(branch_id="b", base_analysis_id=None, branch_revision=None, derived_fields={"thing": {"rules_count"}})
    got = [(s.resource_id, s.field) for s in assemble(verdict, inputs).changed_settings]
    assert got == [("x-1", "rules_count"), ("x-2", "colour")]


def test_L87g_tags_are_one_entry_per_resource():
    """L87g: several tag changes on a resource are one 'tags' entry, no tag key or value."""
    base = _law_base()
    branch = apply_change(base, Change(op="modify", resource_type="lambda_function", resource_id="dl-worker",
                                       fields={"tags": {"a": SENTINEL, "b": "two", "c": "three"}}))
    entries = [e for e in _settings(base, branch) if e["resource_id"] == "dl-worker"]
    assert [e["field"] for e in entries] == ["tags"]


# ── L87h: the judged map ──────────────────────────────────────────

def _judged():
    from app.aws_check_fields import JUDGED_FIELDS
    return JUDGED_FIELDS


def _source(module: str) -> str:
    return (APP_DIR / f"{module}.py").read_text()


def test_L87h_the_judged_map_is_declared_in_an_adapter_module():
    """L87h: JUDGED_FIELDS lives in an adapter module and is what the check passes to the core."""
    from app import aws_check_fields
    assert "aws_check_fields" in ADAPTER_MODULES
    assert aws_check_fields.JUDGED_FIELDS
    assert "JUDGED_FIELDS" in _source("aws_check")
    assert "JUDGED_FIELDS" not in _source("check_facts")


def test_L87h_every_declared_field_is_a_real_field_and_a_real_damage():
    """L87h: a declared (type, field) is a field of that resource's model or catalog; its damages are the six names."""
    for rtype, fields in _judged().items():
        model = _MUTATION_CAPABILITIES.get(rtype, {}).get("model")
        known = set(CATALOG.get(rtype, {})) | (set(model.model_fields) if model else set())
        if rtype == "iam_role":
            known |= set(RolePolicy.model_fields)
        assert known, rtype
        for field, declaration in fields.items():
            assert field in known, (rtype, field)
            assert declaration.damages and set(declaration.damages) <= set(DAMAGES), (rtype, field)
            assert declaration.readers, (rtype, field)


def _reads(module: str) -> set[str]:
    """Attribute names and exact string constants the module's code uses (docstrings and comments do not count)."""
    import ast
    tree = ast.parse(_source(module))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            names.add(node.value)
    return names


def test_L87h_the_reading_code_really_uses_each_declared_field():
    """L87h: for every declared field, each named reader module's CODE names it (attribute or key, not a comment); a grep-style check."""
    for rtype, fields in _judged().items():
        for field, declaration in fields.items():
            for reader in declaration.readers:
                assert (APP_DIR / f"{reader}.py").exists(), (rtype, field, reader)
                assert field in _reads(reader), f"{reader}.py never reads {rtype}.{field}"


def test_L87h_a_field_the_reader_stops_using_fails_the_law():
    """L87h: mutation style: rename the field in a reader's code and the reads check no longer finds it."""
    import ast
    module, field = "aws_check", "logging_enabled"
    assert field in _reads(module)
    class Rename(ast.NodeTransformer):
        def visit_Attribute(self, node):
            self.generic_visit(node)
            if node.attr == field:
                node.attr = field + "_x"
            return node
        def visit_Constant(self, node):
            return ast.copy_location(ast.Constant(node.value + "_x"), node) if node.value == field else node
    mutated = ast.unparse(Rename().visit(ast.parse(_source(module))))
    assert f".{field}_x" in mutated and not re.search(rf"\.{field}\b", mutated)


@pytest.mark.parametrize("rtype,field,value,damage", [
    ("s3_bucket", "logging_enabled", True, "control"),
    ("security_group", "rules", [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}], "exposure"),
    ("rds_instance", "backup_retention_days", 0, "data"),
    ("ec2_instance", "type", "m5.4xlarge", "money"),
    ("scheduler_schedule", "state", "ENABLED", "outside_world"),
])
def test_L87h_a_declared_field_really_reaches_its_damage(rtype, field, value, damage):
    """L87h: for a sample of declared fields, changing the field gives a fact in the declared damage (the declaration is behaviour, not a wish)."""
    base = _law_base()
    rid, _, report_id = SAMPLES[rtype]
    branch = apply_change(base, Change(op="modify", resource_type=rtype, resource_id=rid, fields={field: value}))
    body = _check(base, branch).model_dump(mode="json")
    assert damage in _judged()[rtype][field].damages
    answer = next(a for a in body["answers"] if a["damage"] == damage)
    assert any(report_id in json.dumps(f) for f in answer["facts"]), (rtype, field, damage)


def test_L87h_judged_by_comes_only_from_the_declaration():
    """L87h: an entry is judged exactly when its field is declared for its type, and judged_by equals the declared damages."""
    base = _law_base()
    declared = _judged()
    checked = 0
    for rtype, field in _all_cases():
        _, branch = _find_change(base, rtype, field)
        for e in _settings(base, branch):
            expected = declared.get(e["resource_type"], {}).get(e["field"])
            assert e["judged_by"] == (sorted(expected.damages) if expected else []), e
            checked += 1
    assert checked > 50


# ── L87i: neutral core ────────────────────────────────────────────

def test_L87i_check_facts_stays_a_core_module_without_aws_knowledge():
    """L87i (L56): check_facts imports nothing from an adapter or SDK and names no catalog field."""
    import ast
    tree = ast.parse(_source("check_facts"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[1] if node.module.startswith("app.") else node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
    assert "check_facts" in CORE_MODULES and ALLOWED["check_facts"] == set()
    assert not imported & (ADAPTER_MODULES | AWS_LIBS)
    text = _source("check_facts")
    for needle in ("imdsv2_required", "publicly_accessible", "logging_enabled", "versioning_enabled", "pitr_enabled", "web_acl_id"):
        assert needle not in text


# ── L87j: honest split ────────────────────────────────────────────

@pytest.mark.parametrize("rtype,field,judged_by", [
    ("ec2_instance", "imdsv2_required", []),
    ("ec2_instance", "state", []),
    ("rds_instance", "encrypted", []),
    ("rds_instance", "deletion_protection", []),
    ("s3_bucket", "logging_enabled", ["control"]),
    ("rds_instance", "backup_retention_days", ["data"]),
    ("ec2_instance", "type", ["money"]),
    ("security_group", "rules", ["exposure"]),
])
def test_L87j_known_examples(rtype, field, judged_by):
    """L87j: known settings keep their declared status; an unread setting is named as not judged, not dropped."""
    base = _law_base()
    _, branch = _find_change(base, rtype, field)
    got = {e["field"]: e["judged_by"] for e in _settings(base, branch)}
    assert got[field] == judged_by


# ── L87k: the API ─────────────────────────────────────────────────

def test_L87k_the_check_endpoint_returns_changed_settings(shared_test_db, monkeypatch):
    """L87k: GET /branches/{id}/check carries changed_settings (names only) outside the six answers; none when unchanged."""
    from fastapi.testclient import TestClient
    from app import auth, database, main
    from app.database import AnalysisLog
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    client = TestClient(main.app)
    db = database.SessionLocal()
    try:
        db.add(AnalysisLog(aws_account_id="000000000000", findings_json=json.dumps({
            "analysis_id": "l87-scan", "infrastructure": load_synthetic_base("delete").model_dump(mode="json")})))
        db.commit()
    finally:
        db.close()
    main._branch_request_log.clear()
    branch_id = client.post("/branches", json={"base_analysis_id": "l87-scan", "name": "l87"}).json()["branch_id"]
    main._branch_request_log.clear()
    assert client.get(f"/branches/{branch_id}/check").json()["changed_settings"] == []
    change = Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"imdsv2_required": False})
    main._branch_request_log.clear()
    assert client.post(f"/branches/{branch_id}/changes", json={**change.model_dump(), "expected_change_count": 0}).status_code == 200
    main._branch_request_log.clear()
    body = client.get(f"/branches/{branch_id}/check").json()
    assert [(e["resource_id"], e["field"], e["judged"], e["judged_by"]) for e in body["changed_settings"]
            if e["field"] == "imdsv2_required"] == [("i-dl-web", "imdsv2_required", False, [])]
    assert "changed_settings" not in {k for a in body["answers"] for k in a}
