"""L48 NAT gateway add laws: typed branch add, honest unknowns, and no new ingress."""
import json

import pytest

from app.aws_api_ingest import translate_api_calls
from app.aws_cli_ingest import parse_cli_commands
from app.cfn_ingest import convert_change_set
from app.cost import HOURS_PER_MONTH, NAT_GATEWAY_HOURLY_USD, cost_sides
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.limits import limit_checks, limits_delta
from app.mutations import Change, TargetNotFound, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

PUBLIC, PRIVATE, VPC = "subnet-dl-pub", "subnet-dl-priv", "vpc-dl0001"
EIP = "eipalloc-l48"


def nat(ident="nat-l48", fields=None):
    return Change(op="add", resource_type="nat_gateway", resource_id=ident,
                  fields={"subnet_id": PUBLIC, "allocation_id": EIP} if fields is None else fields)


def private_default_route(target="nat-l48"):
    return Change(op="modify", resource_type="route_table", resource_id="rtb-dl-priv", fields={"routes": [
        {"destination_cidr": "10.20.0.0/16", "target_type": "local", "target_id": "local"},
        {"destination_cidr": "0.0.0.0/0", "target_type": "nat_gateway", "target_id": target},
    ]})


def verdict(base, branch):
    return combined_verdict(base, branch, run_scanners=False)


def codes(result):
    return {reason["code"] for reason in result.reasons}


def detail(infra, ident):
    return next(item for item in infra.vpc.nat_gateway_details if item.id == ident)


def test_L48a_add_is_pure_typed_and_uses_aws_defaults():
    base = load_synthetic_base("delete")
    before = base.model_dump(mode="json")
    branch = apply_change(base, nat())
    assert base.model_dump(mode="json") == before
    assert "nat-l48" in branch.vpc.nat_gateways and "nat-l48" not in base.vpc.nat_gateways
    item = detail(branch, "nat-l48")
    # AWS documents public as the CreateNatGateway default; the VPC follows from the subnet.
    assert (item.subnet_id, item.vpc_id, item.connectivity_type, item.allocation_id, item.state) == (
        PUBLIC, VPC, "public", EIP, "available")
    caps = {entry.resource_type: entry for entry in mutation_capabilities().resources}
    assert caps["nat_gateway"].operations == ["add"]


def test_L48b_invalid_adds_are_rejected():
    base = load_synthetic_base("delete")
    with pytest.raises((ValueError, TargetNotFound)):
        apply_change(base, nat(fields={"subnet_id": "subnet-missing", "allocation_id": EIP}))
    for fields in (
        {"subnet_id": PUBLIC, "connectivity_type": "internet"},
        {"subnet_id": PRIVATE, "connectivity_type": "private", "allocation_id": EIP},
        {"subnet_id": PUBLIC, "allocation_id": EIP, "state": "available"},
        {"subnet_id": PUBLIC, "allocation_id": EIP, "vpc_id": VPC},
        {"subnet_id": 7},
    ):
        with pytest.raises(ValueError):
            apply_change(base, nat(fields=fields))
    added = apply_change(base, nat())
    with pytest.raises(ValueError):
        apply_change(added, nat())
    with pytest.raises(ValueError):
        apply_change(base, Change(op="delete", resource_type="nat_gateway", resource_id="nat-l48", fields={}))


@pytest.mark.parametrize("fields, unspecified", [
    ({}, True),
    ({"allocation_id": EIP}, True),
    ({"subnet_id": PUBLIC}, True),
    ({"subnet_id": PUBLIC, "allocation_id": EIP}, False),
    ({"subnet_id": PRIVATE, "connectivity_type": "private"}, False),
])
def test_L48c_missing_required_values_are_explicit_unknowns(fields, unspecified):
    base = load_synthetic_base("delete")
    result = verdict(base, apply_change(base, nat(fields=fields)))
    reasons = [item for item in result.reasons if item["code"] == "unspecified_values" and "nat-l48" in item["resources"]]
    assert bool(reasons) is unspecified
    if unspecified:
        assert "unspecified_change_fields" in result.coverage_warnings
        assert "nat-l48" not in reasons[0]["message"]
        assert result.verdict != "pass"


def test_L48d_add_shows_in_graph_diff_cost_and_limits():
    base = load_synthetic_base("delete")
    branch = apply_change(base, nat())
    node = next(item for item in build_graph(branch).nodes if item["id"] == "nat-l48")
    assert node["type"] == "nat_gateway"
    diff = diff_infrastructure(base, branch)
    assert {"id": "nat-l48", "resource_type": "nat_gateway"}.items() <= next(
        item for item in diff.resources_added if item["id"] == "nat-l48").items()
    assert not diff.resources_removed
    before, after, _changes, delta = cost_sides(base, branch)
    expected = NAT_GATEWAY_HOURLY_USD * HOURS_PER_MONTH
    assert after.known_monthly_usd - before.known_monthly_usd == pytest.approx(expected)
    assert delta.known_provisioned_delta == pytest.approx(expected)
    assert any(item.check == "nat_gateways_per_az" and item.current == 1 for item in limit_checks(branch))
    assert limits_delta(base, branch).introduced == []
    # A NAT nothing routes to still costs money: the orphan finding warns until a route uses it.
    alone = verdict(base, branch)
    assert alone.verdict == "warn" and {item["rule_id"] for item in alone.native_added} == {"EMFIRGE-ORPHAN-001"}
    assert verdict(base, apply_changes(base, [nat(), private_default_route()])).verdict == "pass"


@pytest.mark.parametrize("subnet, connectivity, allocation", [
    (PUBLIC, "public", EIP), (PRIVATE, "public", EIP), (PRIVATE, "private", None), (PUBLIC, "private", None),
])
def test_L48e_nat_never_creates_internet_ingress(subnet, connectivity, allocation):
    base = load_synthetic_base("delete")
    fields = {"subnet_id": subnet, "connectivity_type": connectivity}
    if allocation:
        fields["allocation_id"] = allocation
    branch = apply_changes(base, [nat(fields=fields), private_default_route()])
    diff = diff_infrastructure(base, branch)
    assert diff.newly_internet_reachable == []
    result = verdict(base, branch)
    assert not codes(result) & {"newly_internet_reachable", "new_exposure", "introduced_critical_exposure"}
    assert result.newly_exposed == []
    assert PRIVATE not in branch.vpc.public_subnet_ids


def test_L48f_handback_is_exact_and_never_invents_a_nat_id():
    base = load_synthetic_base("delete")
    assert build_api_calls(base, [nat()]) == [{"change_index": 0, "service": "ec2", "operation": "CreateNatGateway",
        "params": {"SubnetId": PUBLIC, "ConnectivityType": "public", "AllocationId": EIP}}]
    private = nat(fields={"subnet_id": PRIVATE, "connectivity_type": "private"})
    assert build_api_calls(base, [private])[0]["params"] == {"SubnetId": PRIVATE, "ConnectivityType": "private"}
    for incomplete in ({}, {"subnet_id": PUBLIC}):
        with pytest.raises(UnmappableChanges):
            build_api_calls(base, [nat(fields=incomplete)])
    # AWS assigns the NAT id, so a route to a NAT created on this branch is a gap, not a call with a made-up id.
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [nat(), private_default_route()])
    assert any(item["reason"] == "depends_on_branch_created_nat_gateway" for item in exc.value.changes)


def _api(parameters):
    return translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "ec2", "operation": "CreateNatGateway", "parameters": parameters}]})


def test_L48g_every_input_format_gives_the_same_branch():
    base = load_synthetic_base("delete")
    api = _api({"SubnetId": PUBLIC, "AllocationId": EIP, "TagSpecifications": [], "ClientToken": "x"})
    cli = translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [
        f"aws ec2 create-nat-gateway --subnet-id {PUBLIC} --allocation-id {EIP}"]}))
    cfn_doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Add", "LogicalResourceId": "Nat", "ResourceType": "AWS::EC2::NatGateway",
        "AfterContext": json.dumps({"Properties": {"SubnetId": PUBLIC, "AllocationId": EIP}})}}]})
    assert extras == []
    cfn = translate_api_calls(cfn_doc)
    tf = translate_plan({"format_version": "1.2", "resource_changes": [{"address": "aws_nat_gateway.main", "type": "aws_nat_gateway",
        "change": {"actions": ["create"], "before": None,
                   "after": {"subnet_id": PUBLIC, "allocation_id": EIP, "connectivity_type": "public"},
                   "after_unknown": {"id": True}}}]})
    results = {"api": api, "cli": cli, "cfn": cfn, "terraform": tf}
    states = {}
    for name, result in results.items():
        assert result["unknown_fields"] == [], name
        assert [c.resource_type for c in result["changes"]] == ["nat_gateway"], name
        branch = apply_changes(base, result["changes"])
        item = next(x for x in branch.vpc.nat_gateway_details if x.id not in base.vpc.nat_gateways)
        states[name] = (item.subnet_id, item.connectivity_type, item.allocation_id, verdict(base, branch).verdict)
        # Ingested NATs have no id until AWS assigns one; the hand-back must still be exact.
        assert [call["params"] for call in build_api_calls(base, result["changes"])] == [
            {"SubnetId": PUBLIC, "ConnectivityType": "public", "AllocationId": EIP}], name
    assert len(set(states.values())) == 1, states


def test_L48h_unknown_or_unsupported_inputs_stay_visible():
    tf = translate_plan({"format_version": "1.2", "resource_changes": [{"address": "aws_nat_gateway.main", "type": "aws_nat_gateway",
        "change": {"actions": ["create"], "before": None, "after": {"connectivity_type": "public"},
                   "after_unknown": {"id": True, "subnet_id": True, "allocation_id": True}}}]})
    assert {item["field"] for item in tf["unknown_fields"]} >= {"subnet_id", "allocation_id"}
    assert tf["changes"][0].fields == {"connectivity_type": "public"}
    api = _api({"SubnetId": PUBLIC, "AllocationId": EIP, "SecondaryAllocationIds": ["eipalloc-2"]})
    assert any(item["field"] == "SecondaryAllocationIds" and item["reason"] == "unsupported_attribute" for item in api["unknown_fields"])
    with pytest.raises(ValueError):
        _api({"AllocationId": EIP})


def test_L48i_nat_delete_is_still_an_unmodeled_delete():
    result = translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "ec2", "operation": "DeleteNatGateway", "parameters": {"NatGatewayId": "nat-existing"}}]})
    assert result["changes"] == []
    assert result["unmodeled"] and result["unmodeled"][0]["type"] == "ec2.DeleteNatGateway"
    assert result["unmodeled"][0]["actions"] == ["delete"]


def test_L48j_collector_shape_round_trips_through_snapshot_json():
    base = load_synthetic_base("delete")
    branch = apply_change(base, nat())
    restored = type(branch).model_validate(json.loads(branch.model_dump_json()))
    assert detail(restored, "nat-l48") == detail(branch, "nat-l48")
    legacy = base.model_dump(mode="json")
    legacy["vpc"].pop("nat_gateway_details", None)
    legacy["vpc"]["nat_gateways"] = ["nat-legacy"]
    old = type(base).model_validate(legacy)
    assert old.vpc.nat_gateway_details == []
    assert any(item["id"] == "nat-legacy" for item in build_graph(old).nodes)


def test_L48k_api_branch_flow_runs_end_to_end(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = load_synthetic_base("delete")
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l48-api", "name": "l48-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    capabilities = client.get("/branches/capabilities").json()
    assert {"resource_type": "nat_gateway", "operations": ["add"], "constraints": []} in capabilities["resources"]
    rejected = client.post(f"/branches/{branch_id}/changes", json={
        "op": "add", "resource_type": "nat_gateway", "resource_id": "nat-bad",
        "fields": {"subnet_id": PRIVATE, "connectivity_type": "private", "allocation_id": EIP}})
    assert rejected.status_code == 422, rejected.text
    for change in (nat(), private_default_route()):
        response = client.post(f"/branches/{branch_id}/changes", json=change.model_dump(include={"op", "resource_type", "resource_id", "fields"}))
        assert response.status_code == 200, response.text
    diff = client.get(f"/branches/{branch_id}/diff").json()
    assert any(item["id"] == "nat-l48" and item["resource_type"] == "nat_gateway" for item in diff["resources_added"])
    assert diff["newly_internet_reachable"] == []
    assert diff["cost_after"]["known_monthly_usd"] - diff["cost_before"]["known_monthly_usd"] == pytest.approx(
        NAT_GATEWAY_HOURLY_USD * HOURS_PER_MONTH)
    result = client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "pass", result["reasons"]
    handback = client.get(f"/branches/{branch_id}/handback")
    assert handback.status_code == 422, handback.text
    assert any(item["reason"] == "depends_on_branch_created_nat_gateway" for item in handback.json()["changes"])
