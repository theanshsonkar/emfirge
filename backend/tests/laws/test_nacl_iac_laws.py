"""Law 35: Terraform and CloudFormation NACL changes are judged."""
import json

from app import branches, egraph, main
from app.models import NetworkACL
from tests.laws.test_nacl_change_laws import _base, _entry, INSTANCE, SUBNET, VPC, _reachable
from tests.test_plan_ingest import plan_client
from tests.test_cfn_route import post_cfn, resource


def _item(address, typ, actions, before=None, after=None, after_unknown=None):
    return {"address": address, "mode": "managed", "type": typ,
            "change": {"actions": actions, "before": before, "after": after,
                        "after_unknown": after_unknown or {}}}


def _plan(*items):
    return {"format_version": "1.0", "resource_changes": list(items)}


def _verdict(client, branch):
    return client.get(f"/branches/{branch}/verdict").json()


def _base_with_default():
    result = _base()
    result.vpc.nacls.append(NetworkACL(
        id="acl-default", vpc_id=VPC, is_default=True,
        entries=[_entry(100, action="allow"), _entry(100, egress=True, action="allow")],
    ))
    return result


def _terraform(client, payload):
    branch = client.post("/branches", json={"base_analysis_id": "l35", "name": "l35"}).json()["branch_id"]
    response = client.post(f"/branches/{branch}/plans/terraform", json=payload)
    return branch, response


def test_L35a_terraform_acl_rule_create_matches_api_exposure(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    branch, response = _terraform(plan_client, _plan(_item("aws_network_acl_rule.ssh", "aws_network_acl_rule", ["create"], after={
        "network_acl_id": "acl-a", "rule_number": 50, "egress": False, "protocol": "tcp", "rule_action": "allow",
        "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22})))
    assert response.status_code == 200, response.text
    verdict = _verdict(plan_client, branch)
    assert any(x["resource_id"] == INSTANCE for x in verdict["newly_exposed"])
    assert _reachable(branches.rebuild_branch_state(branches.get_branch(branch))) and not _reachable(_base())
    assert not any(x["code"] == "unseen_change" for x in verdict["reasons"])


def test_L35b_terraform_acl_rule_delete_removes_exposure(plan_client, monkeypatch):
    base = _base(exposed=True)
    assert _reachable(base)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    branch, response = _terraform(plan_client, _plan(_item("aws_network_acl_rule.ssh", "aws_network_acl_rule", ["delete"], before={
        "network_acl_id": "acl-a", "rule_number": 100, "egress": False, "protocol": "tcp", "rule_action": "allow",
        "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22})))
    assert response.status_code == 200, response.text
    verdict = _verdict(plan_client, branch)
    assert not _reachable(branches.rebuild_branch_state(branches.get_branch(branch)))
    assert any(x["resource_id"] == INSTANCE for x in verdict["no_longer_exposed"])


def test_L35c_terraform_association_move_and_delete_default(plan_client, monkeypatch):
    base = _base(exposed=True); base.vpc.nacls.append(NetworkACL(id="acl-default", vpc_id=VPC, is_default=True,
        entries=[_entry(100, action="allow"), _entry(100, egress=True, action="allow")]))
    assert _reachable(base)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    move, response = _terraform(plan_client, _plan(_item("aws_network_acl_association.move", "aws_network_acl_association", ["update"],
        before={"subnet_id": SUBNET, "network_acl_id": "acl-a"}, after={"subnet_id": SUBNET, "network_acl_id": "acl-b"})))
    assert response.status_code == 200 and not _reachable(branches.rebuild_branch_state(branches.get_branch(move)))

    base_nonexposed = _base()
    base_nonexposed.vpc.nacls.append(NetworkACL(id="acl-default", vpc_id=VPC, is_default=True,
        entries=[_entry(100, action="allow"), _entry(100, egress=True, action="allow")]))
    assert not _reachable(base_nonexposed)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base_nonexposed)
    delete, response = _terraform(plan_client, _plan(_item("aws_network_acl_association.move", "aws_network_acl_association", ["delete"],
        before={"subnet_id": SUBNET, "network_acl_id": "acl-a"})))
    assert response.status_code == 200
    state = branches.rebuild_branch_state(branches.get_branch(delete))
    assert _reachable(state)
    assert SUBNET in next(a for a in state.vpc.nacls if a.id == "acl-default").associated_subnet_ids
    assert SUBNET not in next(a for a in state.vpc.nacls if a.id == "acl-a").associated_subnet_ids


def test_L35d_default_acl_inline_rules_are_authoritative(plan_client, monkeypatch):
    base = _base(exposed=True); base.vpc.nacls[0].is_default = True
    assert _reachable(base)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    branch, response = _terraform(plan_client, _plan(_item("aws_default_network_acl.default", "aws_default_network_acl", ["update"],
        after={"default_network_acl_id": "acl-a", "ingress": [{"rule_no": 50, "action": "allow", "protocol": "tcp", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}], "egress": []})))
    assert response.status_code == 200
    state = branches.rebuild_branch_state(branches.get_branch(branch)); acl = next(a for a in state.vpc.nacls if a.id == "acl-a")
    assert {(entry.rule_number, entry.egress, entry.rule_action) for entry in acl.entries} == {
        (50, False, "allow"), (32767, False, "deny"), (32767, True, "deny")}
    assert any(entry.rule_number == 50 and not entry.egress and entry.rule_action == "allow" for entry in acl.entries)
    assert all(entry.rule_number == 32767 and entry.rule_action == "deny" for entry in acl.entries if entry.rule_number != 50)
    assert not any(entry.egress and entry.rule_action == "allow" for entry in acl.entries)
    assert not _reachable(state)


def test_L35e_unknown_acl_id_is_unseen(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    branch, response = _terraform(plan_client, _plan(_item("aws_network_acl_rule.x", "aws_network_acl_rule", ["create"],
        after={"network_acl_id": None}, after_unknown={"network_acl_id": True})))
    assert response.status_code == 200 and any(x["code"] == "unseen_change" for x in _verdict(plan_client, branch)["reasons"])


def test_L35f_cfn_acl_entry_matches_exposure(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    context = json.dumps({"Properties": {"NetworkAclId": "acl-a", "RuleNumber": 50, "Protocol": 6, "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}}})
    branch, _, response = post_cfn(plan_client, [resource("Add", "AWS::EC2::NetworkAclEntry", BeforeContext=context, AfterContext=context)])
    assert response.status_code == 200, response.text
    assert any(x["resource_id"] == INSTANCE for x in _verdict(plan_client, branch)["newly_exposed"])


def test_L35g_cfn_association_move_and_unknown_subnet(plan_client, monkeypatch):
    base = _base(exposed=True); monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    assert _reachable(base)
    context = json.dumps({"Properties": {"SubnetId": SUBNET, "NetworkAclId": "acl-b"}})
    branch, _, response = post_cfn(plan_client, [resource("Modify", "AWS::EC2::SubnetNetworkAclAssociation", BeforeContext=context, AfterContext=context)])
    assert response.status_code == 200 and not _reachable(branches.rebuild_branch_state(branches.get_branch(branch)))
    unknown, _, response = post_cfn(plan_client, [resource("Add", "AWS::EC2::SubnetNetworkAclAssociation", AfterContext=json.dumps({"Properties": {"SubnetId": "missing", "NetworkAclId": "acl-b"}}))])
    assert response.status_code == 200 and any(x["code"] == "unseen_change" for x in _verdict(plan_client, unknown)["reasons"])


def test_L35h_cfn_unresolved_ref_is_unseen(plan_client, monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: _base())
    context = json.dumps({"Properties": {"NetworkAclId": {"Ref": "Acl"}, "RuleNumber": 50, "Protocol": 6, "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}})
    branch, _, response = post_cfn(plan_client, [resource("Add", "AWS::EC2::NetworkAclEntry", AfterContext=context)])
    assert response.status_code == 200 and any(x["code"] == "unseen_change" for x in _verdict(plan_client, branch)["reasons"])
