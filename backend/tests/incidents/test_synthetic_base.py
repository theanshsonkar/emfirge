import pytest

from tests.incidents.synthetic_base import load_synthetic_base, merge_patch


def test_merge_patch_recurses_and_deletes_nulls():
    assert merge_patch({"a": {"b": 1, "c": 2}, "keep": 3}, {"a": {"b": 4, "c": None}}) == {"a": {"b": 4}, "keep": 3}


def test_merge_patch_replaces_non_dict_values():
    assert merge_patch({"a": {"b": 1}}, {"a": [1, 2]}) == {"a": [1, 2]}


def test_merge_patch_non_dict_patch_replaces_target():
    assert merge_patch({"a": 1}, ["replacement"]) == ["replacement"]


def test_load_synthetic_base_applies_patch_then_defers():
    with pytest.raises(NotImplementedError, match="Phase D: synthetic base loader not built yet"):
        load_synthetic_base("delete", {"collection": {"network_interfaces": "denied"}})
