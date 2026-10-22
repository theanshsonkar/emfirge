"""L52 route table add: a new table copies the VPC local routes and can make a subnet public."""
import json

import pytest

from app.aws_api_ingest import translate_api_calls
from app.cfn_ingest import convert_change_set
from app.diffing import diff_infrastructure
from app.mutations import Change, TargetNotFound, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

VPC, IGW, PUBLIC, PRIVATE = "vpc-dl0001", "igw-dl0001", "subnet-dl-pub", "subnet-dl-priv"
LOCAL = {"destination_cidr": "10.20.0.0/16", "target_type": "local", "target_id": "local"}
DEFAULT_IGW = {"destination_cidr": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": IGW}


def table(ident="rtb-l52", **fields):
    return Change(op="add", resource_type="route_table", resource_id=ident, fields={"vpc_id": VPC, **fields})


def find(infra, ident):
    return next(item for item in infra.vpc.route_tables if item.id == ident)


def exposed_base():
    """i-l52 has a public IP and 443 open to the world, but sits in the private subnet.

    The public web instance is removed so no multi-hop pivot already reaches it.
    """
    base = apply_change(load_synthetic_base("delete"), Change(op="delete", resource_type="ec2_instance", resource_id="i-dl-web"))
    base = apply_change(base, Change(op="add", resource_type="ec2_instance", resource_id="i-l52", fields={
        "type": "t3.micro", "state": "running", "subnet_id": PRIVATE, "sg_ids": ["sg-dl-web"], "has_public_ip": True}))
    return type(base).model_validate(base.model_dump())  # a snapshot, not a branch: no delete ledger


def test_L52a_add_is_pure_and_copies_the_vpc_local_routes():
    base = load_synthetic_base("delete")
    before = base.model_dump(mode="json")
    branch = apply_change(base, table())
    assert base.model_dump(mode="json") == before
    item = find(branch, "rtb-l52")
    assert (item.vpc_id, item.is_main, item.associated_subnet_ids, item.tags) == (VPC, False, [], {})
    assert [route.model_dump() for route in item.routes] == [LOCAL]
    # An unassociated table changes nothing else.
    assert branch.vpc.public_subnet_ids == base.vpc.public_subnet_ids
    caps = {entry.resource_type: entry for entry in mutation_capabilities().resources}
    assert caps["route_table"].operations == ["add", "modify"]


@pytest.mark.parametrize("fields,error", [
    ({"vpc_id": None}, ValueError),
    ({"vpc_id": "vpc-missing"}, TargetNotFound),
    ({"routes": [{"destination_cidr": "0.0.0.0/0", "target_type": "internet_gateway", "target_id": "igw-other"}]}, ValueError),
    ({"routes": [{"destination_cidr": "10.99.0.0/16", "target_type": "local", "target_id": "local"}]}, ValueError),
    ({"routes": [{"destination_cidr": "10.20.0.0/16", "target_type": "nat_gateway", "target_id": "nat-x"}]}, ValueError),
    ({"routes": [DEFAULT_IGW, DEFAULT_IGW]}, ValueError),
    ({"associated_subnet_ids": ["subnet-missing"]}, TargetNotFound),
    ({"associated_subnet_ids": [PRIVATE, PRIVATE]}, ValueError),
    ({"is_main": True}, ValueError),
])
def test_L52b_invalid_adds_are_rejected(fields, error):
    base = load_synthetic_base("delete")
    change = table(**fields)
    if fields.get("vpc_id", VPC) is None:
        change = Change(op="add", resource_type="route_table", resource_id="rtb-l52", fields={})
    with pytest.raises(error):
        apply_change(base, change)
    with pytest.raises(ValueError):
        apply_change(apply_change(base, table()), table())


def test_L52b_igw_route_needs_complete_attachment_evidence():
    base = load_synthetic_base("delete")
    data = base.model_dump(mode="json")
    data["vpc"]["internet_gateway_attachments_complete"] = False
    unknown = type(base).model_validate(data)
    with pytest.raises(ValueError, match="attachment evidence"):
        apply_change(unknown, table(routes=[DEFAULT_IGW]))


def test_L52c_associating_moves_the_subnet_and_an_igw_route_makes_it_public():
    base = load_synthetic_base("delete")
    branch = apply_change(base, table(routes=[DEFAULT_IGW], associated_subnet_ids=[PRIVATE]))
    assert find(branch, "rtb-dl-priv").associated_subnet_ids == []
    assert find(branch, "rtb-l52").associated_subnet_ids == [PRIVATE]
    assert sorted(branch.vpc.public_subnet_ids) == [PRIVATE, PUBLIC]
    # The same table without an IGW route keeps the subnet private.
    private = apply_change(base, table(associated_subnet_ids=[PRIVATE]))
    assert private.vpc.public_subnet_ids == [PUBLIC]


def test_L52d_a_new_public_route_table_exposes_what_the_old_one_hid():
    from app.egraph import build_graph, get_internet_reachable_set
    base = exposed_base()
    assert "i-l52" not in get_internet_reachable_set(build_graph(base))
    public = apply_change(base, table(routes=[DEFAULT_IGW], associated_subnet_ids=[PRIVATE]))
    result = combined_verdict(base, public, run_scanners=False)
    assert "i-l52" in result.newly_internet_reachable, result.newly_internet_reachable
    assert result.verdict != "pass"
    assert any(r["code"] == "newly_internet_reachable" and "i-l52" in r["resources"] for r in result.reasons), result.reasons
    still_private = apply_change(base, table(associated_subnet_ids=[PRIVATE]))
    assert combined_verdict(base, still_private, run_scanners=False).newly_internet_reachable == []


def test_L52e_diff_lists_the_new_table():
    base = load_synthetic_base("delete")
    diff = diff_infrastructure(base, apply_change(base, table()))
    assert any(item["id"] == "rtb-l52" and item["resource_type"] == "route_table" for item in diff.resources_added)


def test_L52f_handback_creates_the_table_and_never_invents_its_id():
    base = load_synthetic_base("delete")
    assert build_api_calls(base, [table(tags={"Name": "l52"})]) == [{"change_index": 0, "service": "ec2", "operation": "CreateRouteTable",
        "params": {"VpcId": VPC, "TagSpecifications": [{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": "l52"}]}]}}]
    for changes in (
        [table(routes=[DEFAULT_IGW])],
        [table(associated_subnet_ids=[PRIVATE])],
        [table(), Change(op="modify", resource_type="route_table", resource_id="rtb-l52", fields={"routes": [LOCAL, DEFAULT_IGW]})],
    ):
        with pytest.raises(UnmappableChanges) as exc:
            build_api_calls(base, changes)
        assert any(item["reason"] == "depends_on_branch_created_route_table" for item in exc.value.changes)


def test_L52g_every_input_format_gives_the_same_branch():
    base = load_synthetic_base("delete")
    api = translate_api_calls({"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": "CreateRouteTable", "parameters": {
        "VpcId": VPC, "TagSpecifications": [{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": "l52"}]}]}}]})
    cfn_doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Add", "LogicalResourceId": "Rt", "ResourceType": "AWS::EC2::RouteTable",
        "AfterContext": json.dumps({"Properties": {"VpcId": VPC, "Tags": [{"Key": "Name", "Value": "l52"}]}})}}]})
    assert extras == []
    cfn = translate_api_calls(cfn_doc)
    tf = translate_plan({"format_version": "1.2", "resource_changes": [{"address": "aws_route_table.extra", "type": "aws_route_table",
        "change": {"actions": ["create"], "before": None,
                   "after": {"vpc_id": VPC, "route": [], "tags": {"Name": "l52"}, "tags_all": {"Name": "l52"}},
                   "after_unknown": {"id": True, "arn": True, "owner_id": True}}}]})
    states = {}
    for name, result in {"api": api, "cfn": cfn, "terraform": tf}.items():
        assert result["unknown_fields"] == [], (name, result["unknown_fields"])
        branch = apply_changes(base, result["changes"])
        item = next(t for t in branch.vpc.route_tables if t.id not in {"rtb-dl-pub", "rtb-dl-priv"})
        states[name] = (item.vpc_id, json.dumps([r.model_dump() for r in item.routes]), json.dumps(item.tags))
        assert [c["operation"] for c in build_api_calls(base, result["changes"])] == ["CreateRouteTable"], name
    assert len(set(states.values())) == 1, states


def test_L52g_terraform_inline_routes_map_and_unknown_targets_stay_visible():
    base = load_synthetic_base("delete")
    plan = {"format_version": "1.2", "resource_changes": [{"address": "aws_route_table.public", "type": "aws_route_table",
        "change": {"actions": ["create"], "before": None,
                   "after": {"vpc_id": VPC, "route": [
                       {"cidr_block": "0.0.0.0/0", "gateway_id": IGW},
                       {"cidr_block": "192.168.0.0/16", "transit_gateway_id": "tgw-1"}]},
                   "after_unknown": {"id": True}}}]}
    result = translate_plan(plan)
    assert result["changes"][0].fields["routes"] == [DEFAULT_IGW]
    assert result["unknown_fields"] == [{"address": "aws_route_table.public", "field": "route", "reason": "unsupported_attribute"}]
    branch = apply_changes(base, result["changes"])
    assert any(r.target_type == "internet_gateway" for t in branch.vpc.route_tables if t.id.startswith("new-") for r in t.routes)
    # Deleting a Terraform route table is still an unmodeled delete.
    gone = translate_plan({"format_version": "1.2", "resource_changes": [{"address": "aws_route_table.public", "type": "aws_route_table",
        "change": {"actions": ["delete"], "before": {"id": "rtb-dl-pub", "vpc_id": VPC}, "after": None}}]})
    assert gone["changes"] == [] and gone["unmodeled"]


def test_L52h_legacy_snapshot_without_table_tags_still_branches():
    base = load_synthetic_base("delete")
    assert all(item.tags is None for item in base.vpc.route_tables)
    assert find(apply_change(base, table()), "rtb-l52").tags == {}
