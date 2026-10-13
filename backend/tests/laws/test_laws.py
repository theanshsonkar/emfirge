import copy
import json
import os
from pathlib import Path

import pytest
from hypothesis import given, strategies as st
from fastapi.testclient import TestClient

from app import branches, database, main, verdict
from app.diffing import diff_infrastructure
from app.egraph import build_graph, get_internet_reachable_set
from app.mutations import Change, apply_change, apply_changes
from app.rules import run_all_checks
from app.scoring import calculate_score
from app.verdict import combined_verdict
from tests.incidents.base import build_incident_base
from tests.incidents.test_incidents import incident_branch_db

PORTS = st.sampled_from([22, 80, 443, 3306, 5432, 6379, 8000, 5173])
SOURCES = st.sampled_from(["0.0.0.0/0", "10.0.0.0/16", "203.0.113.10/32"])
RULE = st.builds(
    lambda p, src: {"protocol": "tcp", "from_port": p, "to_port": p, "ip_ranges": [src]},
    PORTS, SOURCES,
)
RULES = st.lists(RULE, max_size=4, unique_by=lambda r: (r["from_port"], r["ip_ranges"][0]))


def _scan_total_resources(infra):
    # Mirrors the scan path in app/main.py (~3074-3091). Phase 0 #4 should replace this with one shared function.
    return (
        infra.ec2.instance_count + len(infra.ec2.security_groups) + len(infra.ec2.ebs_volumes)
        + len(infra.ec2.elastic_ips) + infra.s3.total_buckets + len(infra.rds.instances)
        + len(infra.iam.iam_users) + (1 if infra.cloudtrail.is_enabled else 0)
        + infra.lambda_data.function_count + infra.secrets_manager.total_secrets
        + (1 if infra.guardduty.is_enabled else 0) + infra.vpc.total_vpcs + len(infra.vpc.subnets)
        + infra.kms.total_cmks + infra.sns.total_topics + infra.ecs.total_task_definitions
    )


def _scan_score(infra):
    findings = run_all_checks(infra, build_graph(infra))
    return calculate_score(findings, _scan_total_resources(infra), infra)["overall_risk_score"]


def _changes_for_rules(sg_id, rules):
    return Change(op="modify", resource_type="security_group", resource_id=sg_id, fields={"rules": rules})


@pytest.mark.xfail(strict=True, reason="Phase 0 #4: one score")
@given(st.integers(min_value=0, max_value=15))
def test_L1_empty_branch_score_matches_scan_with_variable_resource_count(extra_buckets):
    base = build_incident_base()
    for index in range(extra_buckets):
        base = apply_change(base, Change(
            op="add", resource_type="s3_bucket", resource_id=f"private-extra-{index}",
            fields={"is_public": False},
        ))
    result = combined_verdict(base, copy.deepcopy(base), run_scanners=False)
    assert result.verdict == "pass"
    assert result.score_before == _scan_score(base)


@given(RULES)
def test_L2_apply_and_empty_diff_preserve_base(rules):
    base = build_incident_base()
    original = base.model_dump()
    branch = apply_change(base, _changes_for_rules("sg-inc-web", rules))
    assert base.model_dump() == original == build_incident_base().model_dump()
    rolled = apply_changes(base, [])
    diff = diff_infrastructure(base, rolled)
    assert not diff.added_nodes and not diff.removed_nodes and not diff.added_edges and not diff.removed_edges
    assert not diff.added_findings and not diff.removed_findings
    assert not diff.newly_internet_reachable and not diff.no_longer_internet_reachable
    assert diff.score_after == diff.score_before


def test_L2_http_scenarios_rollback_to_empty_is_identical(incident_branch_db, monkeypatch):
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "_BRANCH_LIMIT", 10000)
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    main._branch_request_log.clear()
    client = TestClient(main.app)
    for scenario in json.loads((Path(__file__).parents[1] / "incidents" / "scenarios.json").read_text()):
        main._branch_request_log.clear()
        created = client.post("/branches", json={"base_analysis_id": "incident", "name": f"law-{scenario['id']}"})
        assert created.status_code == 200
        branch_id = created.json()["branch_id"]
        accepted = True
        for count, change in enumerate(scenario["changes"]):
            response = client.post(
                f"/branches/{branch_id}/changes",
                json={**change, "expected_change_count": count},
            )
            if response.status_code != 200:
                accepted = False
                break
        if not accepted:
            continue
        rolled = client.post(f"/branches/{branch_id}/rollback-to-count", json={"target_change_count": 0})
        assert rolled.status_code == 200
        diff = client.get(f"/branches/{branch_id}/diff")
        assert diff.status_code == 200
        payload = diff.json()
        assert not payload["added_nodes"] and not payload["removed_nodes"]
        assert not payload["added_edges"] and not payload["removed_edges"]
        assert not payload["added_findings"] and not payload["removed_findings"]
        assert not payload["newly_internet_reachable"] and not payload["no_longer_internet_reachable"]
        assert payload["score_after"] == payload["score_before"]


@given(
    st.sampled_from(["sg-inc-web", "sg-inc-latent"]),
    RULES,
    st.integers(min_value=0, max_value=3),
)
def test_L3_ingress_monotonic_reachability(sg_id, rules, remove_count):
    base = build_incident_base()
    old = set(get_internet_reachable_set(build_graph(base)))
    sg = next(x for x in base.ec2.security_groups if x.id == sg_id)
    added = apply_change(base, _changes_for_rules(sg_id, sg.rules + rules))
    assert old <= get_internet_reachable_set(build_graph(added))
    removed_rules = sg.rules[remove_count:]
    removed = apply_change(base, _changes_for_rules(sg_id, removed_rules))
    assert get_internet_reachable_set(build_graph(removed)) <= old


@pytest.mark.xfail(strict=True, reason="Phase 0 #2: verdict policy")
@given(
    st.sampled_from(["sg-inc-web", "sg-inc-latent"]),
    RULES,
    st.booleans(),
)
def test_L4_only_introduced_critical_findings_block(sg_id, rules, public_bucket):
    base = build_incident_base()
    change = _changes_for_rules(sg_id, rules)
    if public_bucket:
        branch = apply_change(base, Change(
            op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"is_public": True},
        ))
    else:
        branch = apply_change(base, change)
    result = combined_verdict(base, branch, run_scanners=False)
    base_findings = run_all_checks(base, build_graph(base))
    branch_findings = run_all_checks(branch, build_graph(branch))
    def keyed(findings):
        return {
            (finding.rule_id, finding.resource_id): finding
            for bucket in findings.values() if isinstance(bucket, list)
            for finding in bucket
        }
    introduced = set(keyed(branch_findings)) - set(keyed(base_findings))
    introduced_critical = any(keyed(branch_findings)[key].severity == "Critical" for key in introduced)
    if introduced_critical:
        assert result.verdict == "block"


@pytest.mark.xfail(strict=True, reason="Phase 0 #4: one score")
@given(st.lists(st.sampled_from(["inc-data-bucket", "inc-assets-bucket", "i-inc-web", "sg-inc-latent", "inc-worker"]), min_size=1, max_size=3, unique=True))
def test_L5_deletion_never_increases_score(resource_ids):
    base = build_incident_base()
    resource_types = {
        "inc-data-bucket": "s3_bucket", "inc-assets-bucket": "s3_bucket",
        "i-inc-web": "ec2_instance", "sg-inc-latent": "security_group", "inc-worker": "lambda_function",
    }
    branch = base
    for resource_id in resource_ids:
        if resource_id == "sg-inc-latent":
            continue
        branch = apply_change(branch, Change(op="delete", resource_type=resource_types[resource_id], resource_id=resource_id))
    diff = diff_infrastructure(base, branch)
    assert diff.score_after <= diff.score_before


@pytest.mark.xfail(strict=True, reason="Phase 0 #1: malformed changes")
def test_L6_invalid_fields_and_types_rejected():
    base = build_incident_base()
    invalid = [
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"unknown": 1}),
        Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules": [{"protocol": "tcp", "from_port": "22", "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]}),
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"is_public": "yes"}),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-inc-web", fields={"sg_ids": "sg-x"}),
    ]
    for change in invalid:
        with pytest.raises((ValueError, TypeError)):
            apply_change(base, change)


@given(RULES)
def test_L7_same_snapshot_and_changes_are_deterministic(rules):
    base = build_incident_base()
    change = _changes_for_rules("sg-inc-web", rules)
    left = apply_change(base, change)
    right = apply_change(base, change)
    assert diff_infrastructure(base, left).model_dump() == diff_infrastructure(base, right).model_dump()
    assert combined_verdict(base, left, run_scanners=False).model_dump(exclude={"branch_revision"}) == combined_verdict(base, right, run_scanners=False).model_dump(exclude={"branch_revision"})
