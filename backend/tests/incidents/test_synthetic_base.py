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
