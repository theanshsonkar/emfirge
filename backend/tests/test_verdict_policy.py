from app.mutations import Change, apply_change
from app.diffing import diff_infrastructure
from app.models import NetworkInterface
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


def test_adding_instance_to_existing_web_sg_blocks_with_critical_exposure():
    base = build_incident_base()
    branch = apply_change(base, Change(op="add", resource_type="ec2_instance", resource_id="i-inc-new", fields={
        "type": "t3.micro", "state": "running", "sg_ids": ["sg-inc-web"],
        "subnet_id": "subnet-inc-pub", "has_public_ip": True, "imdsv2_required": True,
    }))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "block"
    assert any(reason["code"] == "introduced_critical_exposure" for reason in result.reasons)


def test_adding_database_port_to_existing_open_sg_blocks():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    branch = apply_change(base, _sg_change("sg-inc-web", sg.rules + [{
        "protocol": "tcp", "from_port": 3306, "to_port": 3306, "ip_ranges": ["0.0.0.0/0"],
    }]))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "block"
    assert any(reason["code"] == "introduced_critical_exposure" for reason in result.reasons)


def test_adding_web_port_does_not_warn_for_new_exposure():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    branch = apply_change(base, _sg_change("sg-inc-web", sg.rules + [{
        "protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["0.0.0.0/0"],
    }]))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict != "block"
    assert not any(reason["code"] == "new_exposure" for reason in result.reasons)


def test_restricting_ssh_passes_without_warn_reasons():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-web")
    branch = apply_change(base, _sg_change("sg-inc-web", [{
        **rule, "ip_ranges": ["203.0.113.10/32"]} if rule["from_port"] == 22 else rule for rule in sg.rules]))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "pass"
    assert not result.reasons


def test_latent_exposure_warns_with_latent_reason():
    base = build_incident_base()
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-inc-latent")
    branch = apply_change(base, _sg_change(sg.id, sg.rules + [{
        "protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"],
    }]))
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "warn"
    assert any(reason["code"] == "latent_exposure" for reason in result.reasons)


def test_denied_network_interface_scan_blocks_latent_candidate():
    base = build_incident_base()
    branch = apply_change(base, _sg_change("sg-inc-latent", base.ec2.security_groups[1].rules + [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]))
    branch.network_interfaces = None
    branch.collection = {"network_interfaces": "denied"}
    result = combined_verdict(base, branch, run_scanners=False)
    assert result.verdict == "block"
    assert "latent_exposure" not in {reason["code"] for reason in result.reasons}


def test_interface_using_security_group_blocks():
    base = build_incident_base()
    branch = apply_change(base, _sg_change("sg-inc-latent", base.ec2.security_groups[1].rules + [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]))
    branch.network_interfaces = [NetworkInterface(id="eni-extra", sg_ids=["sg-inc-latent"])]
    branch.collection = {"network_interfaces": "ok"}
    assert combined_verdict(base, branch, run_scanners=False).verdict == "block"


def test_deleted_instance_attachment_is_ignored_for_latent_exposure():
    base = build_incident_base()
    base.network_interfaces = [NetworkInterface(id="eni-latent", sg_ids=["sg-inc-latent"], attached_resource="i-inc-web")]
    branch = apply_change(base, _sg_change("sg-inc-latent", base.ec2.security_groups[1].rules + [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]))
    branch = apply_change(branch, Change(op="delete", resource_type="ec2_instance", resource_id="i-inc-web"))
    assert combined_verdict(base, branch, run_scanners=False).verdict == "warn"
    assert "latent_exposure" in {reason["code"] for reason in combined_verdict(base, branch, run_scanners=False).reasons}
