import copy

import pytest
from hypothesis import given, settings, strategies as st

from app.diffing import diff_infrastructure
from app.egraph import build_graph, get_internet_reachable_set
from app.mutations import Change, apply_change, apply_changes
from app.rules import run_all_checks
from app.scoring import calculate_score
from app.verdict import combined_verdict
from tests.incidents.base import build_incident_base

PORTS = st.sampled_from([22, 80, 443, 3306, 5432, 6379, 8000, 5173])
SOURCES = st.sampled_from(["0.0.0.0/0", "10.0.0.0/16", "203.0.113.10/32"])
RULE = st.builds(lambda p, src: {"protocol":"tcp", "from_port":p, "to_port":p, "ip_ranges":[src]}, PORTS, SOURCES)
RULES = st.lists(RULE, max_size=4, unique_by=lambda r: (r["from_port"], r["ip_ranges"][0]))


def _score(infra):
    return calculate_score(run_all_checks(infra, build_graph(infra)), infrastructure=infra)["overall_risk_score"]


def test_L1_empty_branch_pass_and_scan_score_matches():
    base = build_incident_base()
    result = combined_verdict(base, copy.deepcopy(base), run_scanners=False)
    assert result.verdict == "pass"
    assert result.score_before == _score(base)


@given(RULES)
@settings(deadline=None, max_examples=8)
def test_L2_apply_then_rollback_is_identical(rules):
    base = build_incident_base()
    change = Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules": rules})
    branch = apply_change(base, change)
    rolled = apply_changes(branch, [])
    diff = diff_infrastructure(branch, rolled)
    assert not diff.added_nodes and not diff.removed_nodes and not diff.added_edges and not diff.removed_edges
    assert not diff.added_findings and not diff.removed_findings
    assert get_internet_reachable_set(build_graph(branch)) == get_internet_reachable_set(build_graph(rolled))
    assert _score(branch) == _score(rolled)


@given(st.sampled_from(["sg-inc-web", "sg-inc-latent"]), RULES)
@settings(deadline=None, max_examples=8)
def test_L3_ingress_monotonic_reachability(sg_id, rules):
    base = build_incident_base()
    sg = next(x for x in base.ec2.security_groups if x.id == sg_id)
    old = set(get_internet_reachable_set(build_graph(base)))
    added = copy.deepcopy(base)
    sg_added = next(x for x in added.ec2.security_groups if x.id == sg_id)
    sg_added.rules = sg_added.rules + rules
    assert old <= get_internet_reachable_set(build_graph(added))
    removed = copy.deepcopy(base)
    sg_removed = next(x for x in removed.ec2.security_groups if x.id == sg_id)
    sg_removed.rules = []
    assert get_internet_reachable_set(build_graph(removed)) <= old


@pytest.mark.xfail(strict=True, reason="Phase 0 #2: verdict policy")
@given(RULES)
@settings(deadline=None, max_examples=8)
def test_L4_critical_finding_means_block_even_if_other_findings_removed(rules):
    base = build_incident_base()
    branch = apply_change(base, Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules": rules}))
    result = combined_verdict(base, branch, run_scanners=False)
    branch_findings = run_all_checks(branch, build_graph(branch))["critical_risks"]
    if any(f.severity == "Critical" for f in branch_findings):
        assert result.verdict == "block"


@pytest.mark.xfail(strict=True, reason="Phase 0 #4: one score")
@given(st.sampled_from(["inc-data-bucket", "inc-assets-bucket", "i-inc-web", "sg-inc-latent"]))
@settings(deadline=None, max_examples=8)
def test_L5_deletion_never_increases_score(resource_id):
    base = build_incident_base()
    resource_type = "s3_bucket" if resource_id.startswith("inc-") else ("ec2_instance" if resource_id.startswith("i-") else "security_group")
    branch = apply_change(base, Change(op="delete", resource_type=resource_type, resource_id=resource_id))
    assert _score(branch) <= _score(base)


@pytest.mark.xfail(strict=True, reason="Phase 0 #1: malformed changes")
def test_L6_invalid_fields_and_types_rejected():
    base = build_incident_base()
    invalid = [
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"unknown": 1}),
        Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules":[{"protocol":"tcp","from_port":"22","to_port":22,"ip_ranges":["0.0.0.0/0"]}]}),
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"is_public":"yes"}),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-inc-web", fields={"sg_ids":"sg-x"}),
    ]
    for change in invalid:
        with pytest.raises((ValueError, TypeError)):
            apply_change(base, change)


@given(RULES)
@settings(deadline=None, max_examples=8)
def test_L7_same_snapshot_and_changes_are_deterministic(rules):
    base = build_incident_base()
    change = Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules": rules})
    left = apply_change(base, change)
    right = apply_change(base, change)
    assert diff_infrastructure(base, left).model_dump() == diff_infrastructure(base, right).model_dump()
    assert combined_verdict(base, left, run_scanners=False).model_dump(exclude={"branch_revision"}) == combined_verdict(base, right, run_scanners=False).model_dump(exclude={"branch_revision"})
