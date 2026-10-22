"""L51 EBS volume add: typed branch add, AWS defaults and limits, honest unknowns."""
import json

import boto3
import pytest
from moto import mock_aws

from app.aws_api_ingest import translate_api_calls
from app.aws_cli_ingest import parse_cli_commands
from app.aws_collector import collect_ec2
from app.cfn_ingest import convert_change_set
from app.cost import EBS_GP3_GB_MONTH_USD, cost_sides
from app.diffing import diff_infrastructure
from app.mutations import Change, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

AZ = "ap-south-1a"


def volume(ident="vol-l51", fields=None):
    return Change(op="add", resource_type="ebs_volume", resource_id=ident,
                  fields={"availability_zone": AZ, "size_gb": 20, "volume_type": "gp3"} if fields is None else fields)


def find(infra, ident):
    return next(item for item in infra.ec2.ebs_volumes if item.id == ident)


def new_volume(base, branch):
    known = {item.id for item in base.ec2.ebs_volumes}
    return next(item for item in branch.ec2.ebs_volumes if item.id not in known)


def test_L51a_add_is_pure_typed_and_uses_aws_defaults():
    base = load_synthetic_base("delete")
    before = base.model_dump(mode="json")
    branch = apply_change(base, volume(fields={"availability_zone": AZ, "size_gb": 20}))
    assert base.model_dump(mode="json") == before
    item = find(branch, "vol-l51")
    # AWS documents gp2 as the CreateVolume default; a new volume is unattached and untagged.
    assert (item.size_gb, item.volume_type, item.availability_zone, item.state, item.attached_to, item.tags) == (
        20, "gp2", AZ, "available", None, {})
    caps = {entry.resource_type: entry for entry in mutation_capabilities().resources}
    assert caps["ebs_volume"].operations == ["add", "delete"]


@pytest.mark.parametrize("fields", [
    {"availability_zone": AZ},                                      # no size, no snapshot
    {"availability_zone": AZ, "size_gb": 0},
    {"availability_zone": AZ, "size_gb": 16385, "volume_type": "gp3"},
    {"availability_zone": AZ, "size_gb": 100, "volume_type": "st1"},  # st1 starts at 125
    {"availability_zone": AZ, "size_gb": 2, "volume_type": "io1"},
    {"availability_zone": AZ, "size_gb": 2000, "volume_type": "standard"},
    {"availability_zone": AZ, "size_gb": 20, "volume_type": "gp9"},
    {"availability_zone": AZ, "size_gb": "20"},
    {"availability_zone": "us-east-1a", "size_gb": 20},             # not in the snapshot region
    {"availability_zone": AZ, "size_gb": 20, "state": "in-use"},
    {"availability_zone": AZ, "size_gb": 20, "attached_to": "i-dl-web"},
    {"availability_zone": AZ, "size_gb": 20, "snapshot_id": "snap-dl-root"},
])
def test_L51b_invalid_adds_are_rejected(fields):
    with pytest.raises(ValueError):
        apply_change(load_synthetic_base("delete"), volume(fields=fields))


def test_L51b_limits_accept_the_documented_edges_and_reject_duplicates():
    base = load_synthetic_base("delete")
    for fields in ({"size_gb": 16384, "volume_type": "gp3"}, {"size_gb": 65536, "volume_type": "io2"},
                   {"size_gb": 125, "volume_type": "sc1"}, {"size_gb": 1, "volume_type": "standard"}):
        apply_change(base, volume(fields={"availability_zone": AZ, **fields}))
    with pytest.raises(ValueError):
        apply_change(apply_change(base, volume()), volume())
    with pytest.raises(ValueError):
        apply_change(base, volume(ident="vol-dl-root"))


def test_L51c_missing_zone_is_an_explicit_unknown():
    base = load_synthetic_base("delete")
    branch = apply_change(base, volume(fields={"size_gb": 20}))
    assert find(branch, "vol-l51").availability_zone is None
    result = combined_verdict(base, branch, run_scanners=False)
    assert any(r["code"] == "unspecified_values" and r["resources"] == ["vol-l51"] for r in result.reasons)
    assert "unspecified_change_fields" in result.coverage_warnings
    with pytest.raises(UnmappableChanges):
        build_api_calls(base, [volume(fields={"size_gb": 20})])


def test_L51d_add_shows_in_graph_diff_and_cost_and_unattached_is_an_orphan_warning():
    base = load_synthetic_base("delete")
    branch = apply_change(base, volume())
    diff = diff_infrastructure(base, branch)
    assert any(item["id"] == "vol-l51" and item["resource_type"] == "ebs_volume" for item in diff.resources_added)
    assert diff.newly_internet_reachable == []
    before, after, _, _ = cost_sides(base, branch)
    assert after.known_monthly_usd - before.known_monthly_usd == pytest.approx(20 * EBS_GP3_GB_MONTH_USD)
    result = combined_verdict(base, branch, run_scanners=False)
    # An unattached volume is pure cost: the orphan rule warns, nothing blocks.
    assert result.verdict == "warn", result.reasons
    assert all(reason["level"] != "block" for reason in result.reasons)


def test_L51e_added_volume_can_be_deleted_again_on_the_same_branch():
    base = load_synthetic_base("delete")
    branch = apply_changes(base, [volume(), Change(op="delete", resource_type="ebs_volume", resource_id="vol-l51")])
    assert {item.id for item in branch.ec2.ebs_volumes} == {item.id for item in base.ec2.ebs_volumes}


def test_L51f_handback_is_exact_and_never_invents_a_volume_id():
    base = load_synthetic_base("delete")
    tagged = volume(fields={"availability_zone": AZ, "size_gb": 20, "volume_type": "gp3", "tags": {"team": "data"}})
    assert build_api_calls(base, [tagged]) == [{"change_index": 0, "service": "ec2", "operation": "CreateVolume", "params": {
        "AvailabilityZone": AZ, "Size": 20, "VolumeType": "gp3",
        "TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "team", "Value": "data"}]}]}}]


def test_L51f_moto_roundtrip(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        base = load_synthetic_base("delete")
        base = type(base).model_validate({**base.model_dump(), "region": "us-east-1",
                                          "ec2": collect_ec2(None, None, None, "us-east-1", []).model_dump()})
        change = volume(ident="", fields={"availability_zone": "us-east-1b", "size_gb": 30, "volume_type": "gp3", "tags": {"team": "data"}})
        predicted = new_volume(base, apply_change(base, change))
        ec2 = boto3.client("ec2", region_name="us-east-1")
        for call in build_api_calls(base, [change]):
            ec2.create_volume(**call["params"])
        after = type(base).model_validate({**base.model_dump(), "ec2": collect_ec2(None, None, None, "us-east-1", []).model_dump()})
        actual = new_volume(base, after)
        fields = ("size_gb", "volume_type", "availability_zone", "state", "attached_to", "tags")
        assert {f: getattr(actual, f) for f in fields} == {f: getattr(predicted, f) for f in fields}


def test_L51g_every_input_format_gives_the_same_branch():
    base = load_synthetic_base("delete")
    api = translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "CreateVolume", "parameters": {
        "AvailabilityZone": AZ, "Size": 20, "VolumeType": "gp3", "ClientToken": "x",
        "TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "team", "Value": "data"}]}]}}]})
    cli = translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [
        f"aws ec2 create-volume --availability-zone {AZ} --size 20 --volume-type gp3 "
        "--tag-specifications '[{\"ResourceType\": \"volume\", \"Tags\": [{\"Key\": \"team\", \"Value\": \"data\"}]}]'"]}))
    cfn_doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Add", "LogicalResourceId": "Data", "ResourceType": "AWS::EC2::Volume",
        "AfterContext": json.dumps({"Properties": {"AvailabilityZone": AZ, "Size": 20, "VolumeType": "gp3",
                                                   "Tags": [{"Key": "team", "Value": "data"}]}})}}]})
    assert extras == []
    cfn = translate_api_calls(cfn_doc)
    tf = translate_plan({"format_version": "1.2", "resource_changes": [{"address": "aws_ebs_volume.data", "type": "aws_ebs_volume",
        "change": {"actions": ["create"], "before": None,
                   "after": {"availability_zone": AZ, "size": 20, "type": "gp3", "tags": {"team": "data"}, "tags_all": {"team": "data"}},
                   "after_unknown": {"id": True, "arn": True}}}]})
    states = {}
    for name, result in {"api": api, "cli": cli, "cfn": cfn, "terraform": tf}.items():
        assert result["unknown_fields"] == [], (name, result["unknown_fields"])
        assert [c.resource_type for c in result["changes"]] == ["ebs_volume"], name
        branch = apply_changes(base, result["changes"])
        item = new_volume(base, branch)
        states[name] = (item.size_gb, item.volume_type, item.availability_zone, json.dumps(item.tags), combined_verdict(base, branch, run_scanners=False).verdict)
        assert [c["params"] for c in build_api_calls(base, result["changes"])] == [{
            "AvailabilityZone": AZ, "Size": 20, "VolumeType": "gp3",
            "TagSpecifications": [{"ResourceType": "volume", "Tags": [{"Key": "team", "Value": "data"}]}]}], name
    assert len(set(states.values())) == 1, states


def test_L51h_unmodeled_inputs_stay_visible():
    from_snapshot = translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "CreateVolume",
        "parameters": {"AvailabilityZone": AZ, "SnapshotId": "snap-dl-root"}}]})
    assert from_snapshot["changes"] == [] and from_snapshot["unmodeled"]
    encrypted = translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "CreateVolume",
        "parameters": {"AvailabilityZone": AZ, "Size": 20, "Encrypted": True, "Iops": 3000}}]})
    assert {item["field"] for item in encrypted["unknown_fields"]} == {"Encrypted", "Iops"}


def test_L51i_api_branch_flow_runs_end_to_end(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = load_synthetic_base("delete")
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l51-api", "name": "l51-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    capabilities = client.get("/branches/capabilities").json()
    assert {"resource_type": "ebs_volume", "operations": ["add", "delete"], "constraints": []} in capabilities["resources"]
    rejected = client.post(f"/branches/{branch_id}/changes", json={
        "op": "add", "resource_type": "ebs_volume", "resource_id": "vol-bad", "fields": {"availability_zone": AZ}})
    assert rejected.status_code == 422, rejected.text
    response = client.post(f"/branches/{branch_id}/changes", json=volume().model_dump(include={"op", "resource_type", "resource_id", "fields"}))
    assert response.status_code == 200, response.text
    diff = client.get(f"/branches/{branch_id}/diff").json()
    assert any(item["id"] == "vol-l51" for item in diff["resources_added"])
    assert client.get(f"/branches/{branch_id}/verdict").json()["verdict"] == "warn"
    handback = client.get(f"/branches/{branch_id}/handback")
    assert handback.status_code == 200, handback.text
