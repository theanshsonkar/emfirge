"""Law 34: changing network ACLs changes internet exposure predictably."""
import pytest

from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, InternetGatewayAttachment,
    NACLEntry, NetworkACL, Route, RouteTable, SecurityGroup, VPCData, VPCSubnet,
)
from app.mutations import Change, apply_change
from app.typed_handback import UnmappableChanges, build_api_calls
from app import branches, egraph, main
from tests.test_plan_ingest import plan_client  # noqa: F401

VPC, SUBNET, INSTANCE = "vpc-l34", "subnet-l34", "i-l34"


def _reachable(state):
    return INSTANCE in egraph.get_internet_reachable_set(egraph.build_graph(state))


def _entry(number, *, egress=False, action="deny", protocol="-1", lo=None, hi=None):
    return NACLEntry(rule_number=number, protocol=protocol, rule_action=action,
                     egress=egress, cidr_block="0.0.0.0/0", port_from=lo, port_to=hi)


def _base(*, exposed=False):
    ingress = [_entry(100, action="allow", protocol="tcp", lo=22, hi=22)] if exposed else [
        _entry(100, protocol="tcp", lo=22, hi=22),
        _entry(200, action="allow"),
    ]
    acl_a = NetworkACL(
        id="acl-a", vpc_id=VPC, associated_subnet_ids=[SUBNET],
        association_ids={"aclassoc-a": SUBNET},
        entries=ingress + [_entry(100, egress=True, action="allow"),
                            _entry(32767), _entry(32767, egress=True)],
    )
    acl_b = NetworkACL(id="acl-b", vpc_id=VPC,
                       entries=[_entry(32767), _entry(32767, egress=True)])
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instances=[EC2Instance(id=INSTANCE, type="t3.micro", state="running",
                                   subnet_id=SUBNET, sg_ids=["sg-l34"], has_public_ip=True)],
            security_groups=[SecurityGroup(
                id="sg-l34", name="ssh", attached_to=[INSTANCE],
                rules=[{"protocol": "tcp", "from_port": 22, "to_port": 22,
                        "ip_ranges": ["0.0.0.0/0"]}],
                egress_rules=[{"protocol": "-1", "from_port": 0, "to_port": 65535,
                               "ip_ranges": ["0.0.0.0/0"]}],
            )],
        ),
        vpc=VPCData(
            subnets=[VPCSubnet(id=SUBNET, vpc_id=VPC, cidr="10.34.0.0/24")],
            route_tables=[RouteTable(
                id="rt-l34", vpc_id=VPC, is_main=True,
                associated_subnet_ids=[SUBNET],
                routes=[Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway",
                              target_id="igw-l34")],
            )],
            internet_gateways=["igw-l34"],
            internet_gateway_attachments=[InternetGatewayAttachment(
                internet_gateway_id="igw-l34", vpc_id=VPC, state="available")],
            internet_gateway_attachments_complete=True,
            nacls=[acl_a, acl_b],
        ),
    )


def _api(client, calls, base):
    branch_id = client.post("/branches", json={"base_analysis_id": "l34", "name": "l34"}).json()["branch_id"]
    response = client.post(f"/branches/{branch_id}/plans/aws-api",
                           json={"format": "aws-api-calls/1", "calls": calls})
    assert response.status_code == 200, response.text
    return branch_id, response.json()


def _verdict(client, branch_id):
    response = client.get(f"/branches/{branch_id}/verdict")
    assert response.status_code == 200, response.text
    return response.json()


def _public_ssh_call():
    return {"service": "ec2", "operation": "CreateNetworkAclEntry", "parameters": {
        "NetworkAclId": "acl-a", "RuleNumber": 50, "Protocol": "tcp",
        "PortRange": {"From": 22, "To": 22}, "CidrBlock": "0.0.0.0/0",
        "RuleAction": "allow", "Egress": False,
    }}


def test_L34a_create_network_acl_entry_exposes_instance(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    branch_id, body = _api(plan_client, [_public_ssh_call()], _base())
    assert body["applied"] and body["rejected"] == []
    verdict = _verdict(plan_client, branch_id)
    assert any(item["resource_id"] == INSTANCE for item in verdict["newly_exposed"])
    assert _reachable(branches.rebuild_branch_state(branches.get_branch(branch_id)))
    assert not _reachable(_base())
    assert not any(reason["code"] == "unseen_change" for reason in verdict["reasons"])


def test_L34b_cli_create_matches_api(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    api_branch, _ = _api(plan_client, [_public_ssh_call()], _base())
    cli_branch = plan_client.post("/branches", json={"base_analysis_id": "l34", "name": "cli"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{cli_branch}/plans/aws-cli", json={
        "format": "aws-cli/1", "commands": [
            "aws ec2 create-network-acl-entry --network-acl-id acl-a --rule-number 50 --protocol tcp --port-range From=22,To=22 --cidr-block 0.0.0.0/0 --rule-action allow --ingress"
        ]})
    assert response.status_code == 200, response.text
    left, right = _verdict(plan_client, api_branch), _verdict(plan_client, cli_branch)
    assert left["verdict"] == right["verdict"]
    assert left["newly_exposed"] == right["newly_exposed"]


def test_L34c_delete_entry_is_directional_and_stateless_return_path(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base(exposed=True))
    for egress in (False, True):
        branch_id, body = _api(plan_client, [{"service": "ec2", "operation": "DeleteNetworkAclEntry",
            "parameters": {"NetworkAclId": "acl-a", "RuleNumber": 100, "Egress": egress}}], _base(exposed=True))
        verdict = _verdict(plan_client, branch_id)
        assert body["applied"] and not verdict["newly_exposed"]
        assert _reachable(_base(exposed=True))
        assert not _reachable(branches.rebuild_branch_state(branches.get_branch(branch_id)))
        assert any(item["resource_id"] == INSTANCE for item in verdict["no_longer_exposed"])
        state = branches.rebuild_branch_state(branches.get_branch(branch_id))
        acl = next(item for item in state.vpc.nacls if item.id == "acl-a")
        if egress:
            assert any(not item.egress and item.rule_number == 100 for item in acl.entries)


def test_L34d_replace_association_removes_exposure_and_unknown_is_unseen(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base(exposed=True))
    branch_id, _ = _api(plan_client, [{"service": "ec2", "operation": "ReplaceNetworkAclAssociation",
        "parameters": {"AssociationId": "aclassoc-a", "NetworkAclId": "acl-b"}}], _base(exposed=True))
    verdict = _verdict(plan_client, branch_id)
    assert not verdict["newly_exposed"]
    assert _reachable(_base(exposed=True))
    assert not _reachable(branches.rebuild_branch_state(branches.get_branch(branch_id)))
    assert any(item["resource_id"] == INSTANCE for item in verdict["no_longer_exposed"])
    state = branches.rebuild_branch_state(branches.get_branch(branch_id))
    assert SUBNET not in next(a for a in state.vpc.nacls if a.id == "acl-a").associated_subnet_ids
    unknown, _ = _api(plan_client, [{"service": "ec2", "operation": "ReplaceNetworkAclAssociation",
        "parameters": {"AssociationId": "missing", "NetworkAclId": "acl-b"}}], _base(exposed=True))
    assert any(r["code"] == "unseen_change" for r in _verdict(plan_client, unknown)["reasons"])


def test_L34e_create_acl_then_associate_denies_by_default(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base(exposed=True))
    branch_id, body = _api(plan_client, [
        {"service": "ec2", "operation": "CreateNetworkAcl", "parameters": {"VpcId": VPC}},
        {"service": "ec2", "operation": "ReplaceNetworkAclAssociation",
         "parameters": {"AssociationId": "aclassoc-a", "NetworkAclId": "acl-new-1"}},
    ], _base(exposed=True))
    verdict = _verdict(plan_client, branch_id)
    assert body["applied"] and not verdict["newly_exposed"]
    assert _reachable(_base(exposed=True))
    assert not _reachable(branches.rebuild_branch_state(branches.get_branch(branch_id)))
    assert any(item["resource_id"] == INSTANCE for item in verdict["no_longer_exposed"])


def test_L34f_unknown_acl_entry_is_unseen_and_does_not_change(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    branch_id, body = _api(plan_client, [{"service": "ec2", "operation": "CreateNetworkAclEntry",
        "parameters": {**_public_ssh_call()["parameters"], "NetworkAclId": "missing"}}], _base())
    assert body["applied"] == []
    assert any(r["code"] == "unseen_change" for r in _verdict(plan_client, branch_id)["reasons"])


def test_L34g_apply_change_invariants():
    base = _base()
    added = apply_change(base, Change(op="add", resource_type="network_acl", resource_id="acl-new",
                                      fields={"vpc_id": VPC}))
    assert len(next(a for a in added.vpc.nacls if a.id == "acl-new").entries) == 4
    duplicate = {"entries": [_entry(1), _entry(1)], "vpc_id": VPC}
    try:
        apply_change(base, Change(op="add", resource_type="network_acl", resource_id="dup", fields=duplicate))
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate NACL rules must fail")
    import pytest
    with pytest.raises(ValueError):
        apply_change(base, Change(op="delete", resource_type="network_acl", resource_id="acl-a"))
    default = base.model_copy(deep=True)
    default.vpc.nacls[0].is_default = True
    default.vpc.nacls[0].associated_subnet_ids = []
    with pytest.raises(ValueError):
        apply_change(default, Change(op="delete", resource_type="network_acl", resource_id="acl-a"))
    moved = apply_change(base, Change(op="modify", resource_type="network_acl", resource_id="acl-b",
        fields={"associated_subnet_ids": [SUBNET]}))
    assert SUBNET not in next(a for a in moved.vpc.nacls if a.id == "acl-a").associated_subnet_ids


def test_L34h_handback_moves_association_from_source_acl():
    base = _base()
    changed = apply_change(base, Change(op="modify", resource_type="network_acl", resource_id="acl-b",
        fields={"associated_subnet_ids": [SUBNET]}))
    calls = build_api_calls(base, [Change(op="modify", resource_type="network_acl", resource_id="acl-b",
        fields={"associated_subnet_ids": [SUBNET]})])
    assert calls == [{"change_index": 0, "service": "ec2", "operation": "ReplaceNetworkAclAssociation",
                      "params": {"AssociationId": "aclassoc-a", "NetworkAclId": "acl-b"}}]
    assert SUBNET in next(acl for acl in changed.vpc.nacls if acl.id == "acl-b").associated_subnet_ids


def test_L34i_duplicate_network_acl_entry_is_unmodeled_and_unchanged(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    call = _public_ssh_call()
    call["parameters"]["RuleNumber"] = 100
    branch_id, body = _api(plan_client, [call], _base())
    assert body["applied"] == []
    assert any(item.get("detail") == "rule number already exists" for item in body["unmodeled"])
    state = branches.rebuild_branch_state(branches.get_branch(branch_id))
    assert state == _base()


def test_L34j_invalid_network_acl_entry_rule_numbers_are_unmodeled(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    calls = []
    for number in (0, 32767):
        call = _public_ssh_call()
        call["parameters"]["RuleNumber"] = number
        calls.append(call)
    branch_id, body = _api(plan_client, calls, _base())
    assert body["applied"] == []
    assert [item.get("detail") for item in body["unmodeled"]] == ["invalid network ACL entry", "invalid network ACL entry"]
    assert branches.rebuild_branch_state(branches.get_branch(branch_id)) == _base()


def test_L34k_handback_network_acl_add_is_not_mapped():
    with pytest.raises(UnmappableChanges) as raised:
        build_api_calls(_base(), [Change(op="add", resource_type="network_acl", resource_id="acl-new",
                                         fields={"vpc_id": VPC})])
    assert raised.value.changes[0]["reason"] == "operation_not_mapped"
