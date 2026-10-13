from app.mutations import Change, apply_change
from app.diffing import diff_infrastructure
from app.verdict import combined_verdict
from tests.incidents.base import build_incident_base


def _sg_change(sg_id, rules):
    return Change(op="modify", resource_type="security_group", resource_id=sg_id, fields={"rules": rules})


def test_opening_new_web_port_is_active_exposure_and_blocks_on_critical_finding():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    branch = apply_change(base, _sg_change("sg-inc-web", sg.rules + [{"protocol": "tcp", "from_port": 5432, "to_port": 5432, "ip_ranges": ["0.0.0.0/0"]}]))
    diff = diff_infrastructure(base, branch)
    assert {tuple(item[field] for field in ("resource_id", "protocol", "from_port", "to_port", "source", "state")) for item in diff.newly_exposed} >= {("i-inc-web", "tcp", 5432, 5432, "0.0.0.0/0", "active")}
    assert combined_verdict(base, branch, run_scanners=False).verdict == "block"


def test_documentation_cidr_is_external_but_narrowing_does_not_add_exposure():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    branch = apply_change(base, _sg_change("sg-inc-web", [{**rule, "ip_ranges": ["203.0.113.10/32"]} if rule["from_port"] == 22 else rule for rule in sg.rules]))
    assert diff_infrastructure(base, branch).newly_exposed == []


def test_latent_exposure_warns_and_latent_sg_delete_passes():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-latent")
    branch = apply_change(base, _sg_change(sg.id, sg.rules + [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]))
    assert any(item["state"] == "latent" for item in diff_infrastructure(base, branch).newly_exposed)
    assert combined_verdict(base, branch, run_scanners=False).verdict == "warn"
    deleted = apply_change(base, Change(op="delete", resource_type="security_group", resource_id=sg.id))
    assert combined_verdict(base, deleted, run_scanners=False).verdict == "pass"


def test_data_store_delete_blocks_and_instance_delete_warns():
    base = build_incident_base()
    bucket = apply_change(base, Change(op="delete", resource_type="s3_bucket", resource_id="inc-assets-bucket"))
    result = combined_verdict(base, bucket, run_scanners=False)
    assert result.verdict == "block"
    assert any(reason["code"] == "data_store_deleted_no_recovery_point" for reason in result.reasons)
    instance = apply_change(base, Change(op="delete", resource_type="ec2_instance", resource_id="i-inc-web"))
    assert combined_verdict(base, instance, run_scanners=False).verdict == "warn"
