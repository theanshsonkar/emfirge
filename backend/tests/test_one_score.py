from app.demo_seed import build_demo_infrastructure
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.mutations import Change, apply_change
from app.rules import run_all_checks
from app.scoring import score_snapshot
from tests.incidents.base import build_incident_base


def _restricted(base):
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    rules = [dict(rule, ip_ranges=["203.0.113.10/32"]) for rule in sg.rules]
    return apply_change(base, Change(
        op="modify", resource_type="security_group", resource_id="sg-inc-web",
        fields={"rules": rules},
    ))


def test_scan_score_matches_empty_branch_score_for_incident_and_demo():
    for base in (build_incident_base(), build_demo_infrastructure()):
        findings = run_all_checks(base, build_graph(base))
        scan_score = score_snapshot(base, findings=findings)["overall_risk_score"]
        diff = diff_infrastructure(base, base)
        assert diff.score_before == scan_score == diff.score_after


def test_deleting_resources_never_increases_score():
    base = build_incident_base()
    resource_types = {
        "i-inc-web": "ec2_instance",
        "inc-data-bucket": "s3_bucket",
        "inc-worker": "lambda_function",
    }
    for resource_id, resource_type in resource_types.items():
        branch = apply_change(base, Change(
            op="delete", resource_type=resource_type, resource_id=resource_id,
        ))
        diff = diff_infrastructure(base, branch)
        assert diff.score_after <= diff.score_before


def test_real_fix_increases_score_and_new_critical_is_capped():
    base = build_incident_base()
    fixed = _restricted(base)
    fixed_diff = diff_infrastructure(base, fixed)
    assert fixed_diff.score_after > fixed_diff.score_before

    sg = next(item for item in fixed.ec2.security_groups if item.id == "sg-inc-web")
    netted = apply_change(fixed, Change(
        op="modify", resource_type="security_group", resource_id="sg-inc-web",
        fields={"rules": sg.rules + [{
            "protocol": "tcp", "from_port": 5432, "to_port": 5432,
            "ip_ranges": ["0.0.0.0/0"],
        }]},
    ))
    netted_diff = diff_infrastructure(base, netted)
    assert netted_diff.score_after <= netted_diff.score_before
    assert "capped: new Critical finding" in netted_diff.score_notes
