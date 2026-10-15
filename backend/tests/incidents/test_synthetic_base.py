import pytest

from tests.incidents.synthetic_base import load_synthetic_base, merge_patch


def test_merge_patch_recurses_and_deletes_nulls():
    assert merge_patch({"a": {"b": 1, "c": 2}, "keep": 3}, {"a": {"b": 4, "c": None}}) == {"a": {"b": 4}, "keep": 3}


def test_merge_patch_replaces_non_dict_values():
    assert merge_patch({"a": {"b": 1}}, {"a": [1, 2]}) == {"a": [1, 2]}


def test_merge_patch_non_dict_patch_replaces_target():
    assert merge_patch({"a": 1}, ["replacement"]) == ["replacement"]


def test_load_synthetic_base_applies_patch_then_loads():
    base = load_synthetic_base("delete", {"collection": {"network_interfaces": "denied"}})
    assert base.network_interfaces is None
    assert base.collection["network_interfaces"] == "denied"
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-dl-web")
    assert any(rule["from_port"] == 443 and "0.0.0.0/0" in rule["ip_ranges"] for rule in sg.rules)


def test_load_synthetic_base_rejects_unknown_key():
    with pytest.raises(ValueError, match="Unknown synthetic base key"):
        load_synthetic_base("delete", {"unknown": True})


def test_delete_synthetic_base_contains_phase_d_relationships():
    base = load_synthetic_base("delete")
    volume = next(item for item in base.ec2.ebs_volumes if item.id == "vol-dl-root")
    instance = next(item for item in base.ec2.instances if item.id == "i-dl-web")
    assert volume.attached_to == "i-dl-web"
    device = next(item for item in instance.block_devices if item.volume_id == "vol-dl-root")
    assert device.delete_on_termination is True
    assert any(item.id == "snap-dl-root" for item in base.ec2.ebs_snapshots)

    prod = next(item for item in base.rds.rds_instances if item.id == "db-dl-prod")
    assert prod.backup_retention_days == 7
    assert prod.deletion_protection is False
    report = next(item for item in base.rds.rds_snapshots if item.id == "dlsnap-reports")
    assert report.db_instance_id == "db-dl-reports"

    roles = {item.role_name: item.last_used_at for item in base.iam.role_policies}
    assert roles["DlBatchRole"] == "2026-09-30T00:00:00Z"
    assert roles["DlAppRole"] is None
    from tests.incidents.synthetic_base import PENDING_FIELDS
    assert PENDING_FIELDS == set()
