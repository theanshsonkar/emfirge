import json

import pytest

from app import branches
from app.plan_ingest import translate_plan
from tests.test_plan_ingest import _post, plan_client  # noqa: F401
from tests.test_cfn_route import post_cfn, resource
from tests.incidents.synthetic_base import load_synthetic_base


def test_ipv6_ingress_rule_is_modeled_as_open_ingress():
    result = translate_plan({"format_version": "1.0", "resource_changes": [{
        "address": "aws_vpc_security_group_ingress_rule.ssh", "type": "aws_vpc_security_group_ingress_rule",
        "change": {"actions": ["create"], "before": None,
                    "after": {"security_group_id": "sg-test", "cidr_ipv6": "::/0", "from_port": 22,
                               "to_port": 22, "ip_protocol": "tcp"}},
    }]}, sg_rules={"sg-test": {"rules": [], "egress_rules": []}})
    assert result["changes"][0].fields["rules"][0]["ip_ranges"] == ["::/0"]


def _item(address, typ, actions, before=None, after=None, after_unknown=None):
    return {"address": address, "mode": "managed", "type": typ,
            "change": {"actions": actions, "before": before, "after": after,
                        "after_unknown": after_unknown or {}}}


def _plan(*items, configuration=None):
    result = {"format_version": "1.0", "resource_changes": list(items)}
    if configuration is not None:
        result["configuration"] = {"root_module": {"resources": configuration}}
    return result


def _state_rules(branch_id, sg_id):
    state = branches.rebuild_branch_state(branches.get_branch(branch_id))
    group = next((group for group in state.ec2.security_groups if group.id == sg_id), None)
    assert group is not None, f"security group {sg_id} was not created in branch state"
    return group.rules, group.egress_rules


def _verdict(client, branch_id):
    response = client.get(f"/branches/{branch_id}/verdict")
    assert response.status_code == 200, response.text
    return response.json()


def test_vpc_security_group_ingress_rule_ipv6_route_exposes_port(plan_client):
    branch_id, _, response = _post(plan_client, _plan(_item(
        "aws_vpc_security_group_ingress_rule.ssh", "aws_vpc_security_group_ingress_rule", ["create"],
        after={"security_group_id": "sg-dl-web", "cidr_ipv6": "::/0", "from_port": 22,
               "to_port": 22, "ip_protocol": "tcp"})))
    assert response.status_code == 200, response.text
    rules, _ = _state_rules(branch_id, "sg-dl-web")
    assert any(rule["from_port"] == 22 and rule["ip_ranges"] == ["::/0"] for rule in rules)
    assert any(reason["code"] == "introduced_critical_exposure" for reason in _verdict(plan_client, branch_id)["reasons"])


def test_vpc_security_group_egress_rule_is_stored_as_egress_without_ingress_exposure(plan_client):
    branch_id, _, response = _post(plan_client, _plan(_item(
        "aws_vpc_security_group_egress_rule.all", "aws_vpc_security_group_egress_rule", ["create"],
        after={"security_group_id": "sg-dl-web", "cidr_ipv4": "0.0.0.0/0", "from_port": 0,
               "to_port": 0, "ip_protocol": "-1"})))
    assert response.status_code == 200, response.text
    _, egress = _state_rules(branch_id, "sg-dl-web")
    assert any(rule["ip_ranges"] == ["0.0.0.0/0"] for rule in egress)
    verdict = _verdict(plan_client, branch_id)
    assert not any(reason["code"] == "introduced_critical_exposure" for reason in verdict["reasons"])
    assert not verdict["newly_exposed"]


@pytest.mark.parametrize(("value", "expected_ranges"), [
    ({"type": "ingress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 80, "to_port": 80, "protocol": "tcp"}, ["0.0.0.0/0"]),
    ({"type": "ingress", "ipv6_cidr_blocks": ["::/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}, ["::/0"]),
    ({"type": "egress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0, "protocol": "-1"}, ["0.0.0.0/0"]),
])
def test_security_group_rule_route_models_ingress_ipv6_and_egress(plan_client, value, expected_ranges):
    branch_id, _, response = _post(plan_client, _plan(_item(
        "aws_security_group_rule.rule", "aws_security_group_rule", ["create"],
        after={"security_group_id": "sg-dl-web", **value})))
    assert response.status_code == 200, response.text
    rules, egress = _state_rules(branch_id, "sg-dl-web")
    stored = egress if value["type"] == "egress" else rules
    assert any(rule["ip_ranges"] == expected_ranges for rule in stored)
    if value["type"] == "egress":
        assert not _verdict(plan_client, branch_id)["newly_exposed"]


def test_ipv6_all_protocol_ingress_is_equivalent_to_aws_api(plan_client):
    terraform = _item(
        "aws_vpc_security_group_ingress_rule.all", "aws_vpc_security_group_ingress_rule", ["create"],
        after={"security_group_id": "sg-dl-web", "cidr_ipv6": "::/0", "from_port": -1,
               "to_port": -1, "ip_protocol": "-1"})
    tf_branch, _, response = _post(plan_client, _plan(terraform))
    assert response.status_code == 200, response.text
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "ipv6-api"}).json()["branch_id"]
    api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{"service": "ec2",
        "operation": "AuthorizeSecurityGroupIngress", "parameters": {"GroupId": "sg-dl-web",
        "IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}}]})
    assert api_response.status_code == 200, api_response.text
    tf_verdict = _verdict(plan_client, tf_branch)
    api_verdict = _verdict(plan_client, api_branch)
    assert tf_verdict["verdict"] == api_verdict["verdict"]
    assert tf_verdict["newly_exposed"] == api_verdict["newly_exposed"]
    assert tf_verdict["newly_exposed"]


def test_deleting_standalone_ingress_rule_removes_existing_exposure(plan_client, monkeypatch):
    base = load_synthetic_base("delete", {"security_groups": [{"id": "sg-dl-web", "name": "dl-web", "vpc_id": "vpc-dl0001",
        "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]}]})
    monkeypatch.setattr("app.main.get_infrastructure_for_analysis", lambda _id: base)
    branch_id, _, response = _post(plan_client, _plan(_item(
        "aws_security_group_rule.ssh", "aws_security_group_rule", ["delete"],
        before={"security_group_id": "sg-dl-web", "type": "ingress", "cidr_blocks": ["0.0.0.0/0"],
                "from_port": 22, "to_port": 22, "protocol": "tcp"})))
    assert response.status_code == 200, response.text
    rules, _ = _state_rules(branch_id, "sg-dl-web")
    assert not any(rule["from_port"] == 22 and "0.0.0.0/0" in rule["ip_ranges"] for rule in rules)
    assert not _verdict(plan_client, branch_id)["newly_exposed"]


@pytest.mark.parametrize("actions", [["update"], ["delete", "create"]])
def test_rule_update_and_replace_can_introduce_ipv6_exposure(plan_client, actions):
    before = {"security_group_id": "sg-dl-web", "cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22, "protocol": "tcp"}
    after = {"security_group_id": "sg-dl-web", "ipv6_cidr_blocks": ["::/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}
    branch_id, _, response = _post(plan_client, _plan(_item("aws_security_group_rule.ssh", "aws_security_group_rule", actions, before, after)))
    assert response.status_code == 200, response.text
    rules, _ = _state_rules(branch_id, "sg-dl-web")
    assert any(rule["ip_ranges"] == ["::/0"] for rule in rules)
    assert any(item["source"] == "::/0" and item["from_port"] == 22 for item in _verdict(plan_client, branch_id)["newly_exposed"])


def test_unknown_rule_parent_uses_configuration_reference_to_new_security_group(plan_client):
    sg = _item("aws_security_group.new", "aws_security_group", ["create"],
               after={"id": "sg-new", "name": "new", "ingress": []})
    rule = _item("aws_vpc_security_group_ingress_rule.ssh", "aws_vpc_security_group_ingress_rule", ["create"],
                 after={"security_group_id": None, "cidr_ipv6": "::/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
                 after_unknown={"security_group_id": True})
    config = [{"address": "aws_vpc_security_group_ingress_rule.ssh", "expressions": {
        "security_group_id": {"references": ["aws_security_group.new.id"]}}}]
    branch_id, _, response = _post(plan_client, _plan(sg, rule, configuration=config))
    assert response.status_code == 200, response.text
    rules, _ = _state_rules(branch_id, "sg-new")
    assert any(rule["ip_ranges"] == ["::/0"] for rule in rules)
    assert not any(reason["code"] == "unseen_change" for reason in _verdict(plan_client, branch_id)["reasons"])


@pytest.mark.parametrize("after", [
    {"security_group_id": None, "cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
    {"security_group_id": "sg-not-in-branch", "cidr_ipv4": "0.0.0.0/0", "from_port": 22, "to_port": 22, "ip_protocol": "tcp"},
])
def test_unresolvable_or_missing_rule_parent_blocks_unseen_change(plan_client, after):
    unknown = after["security_group_id"] is None
    item = _item("aws_vpc_security_group_ingress_rule.ssh", "aws_vpc_security_group_ingress_rule", ["create"],
                 after=after, after_unknown={"security_group_id": True} if unknown else {})
    branch_id, _, response = _post(plan_client, _plan(item))
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch_id)["reasons"]
    assert any(reason["code"] == "unseen_change" and reason["message"].startswith("Emfirge can't see this: ") for reason in reasons)


@pytest.mark.parametrize(("typ", "actions"), [(typ, actions) for typ in (
    "aws_network_acl", "aws_network_acl_rule", "aws_network_acl_association",
    "aws_default_network_acl", "aws_default_security_group") for actions in ((["create"]), (["update"]), (["delete"]))])
def test_unread_terraform_network_types_block_unseen_change(plan_client, typ, actions):
    branch_id, _, response = _post(plan_client, _plan(_item(f"{typ}.x", typ, actions, before={}, after={})))
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch_id)["reasons"]
    assert any(reason["code"] == "unseen_change" and reason["message"].startswith("Emfirge can't see this: ") for reason in reasons)


@pytest.mark.parametrize("operation", ["CreateNetworkAcl", "DeleteNetworkAcl", "CreateNetworkAclEntry",
    "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry", "ReplaceNetworkAclAssociation"])
def test_unread_aws_api_network_operations_block_unseen_change(plan_client, operation):
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "api-firewall"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": operation, "parameters": {}}]})
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch_id)["reasons"]
    assert any(reason["code"] == "unseen_change" and reason["message"].startswith("Emfirge can't see this: ") for reason in reasons)


@pytest.mark.parametrize("typ", ["AWS::EC2::NetworkAclEntry", "AWS::EC2::SecurityGroupEgress"])
def test_unread_cloudformation_network_types_block_unseen_change(plan_client, typ):
    branch_id, _, response = post_cfn(plan_client, [resource("Add", typ)])
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch_id)["reasons"]
    assert any(reason["code"] == "unseen_change" and reason["message"].startswith("Emfirge can't see this: ") for reason in reasons)


def test_unrelated_unknown_aws_type_still_warns(plan_client):
    branch_id, _, response = _post(plan_client, _plan(_item("aws_sqs_queue.queue", "aws_sqs_queue", ["create"], after={"name": "synthetic"})))
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch_id)["reasons"]
    assert any(reason["code"] == "unmodeled_change" and reason["level"] == "warn" for reason in reasons)
    assert not any(reason["code"] == "unseen_change" for reason in reasons)


def _egress_api_call(operation, cidr="0.0.0.0/0"):
    return {"format": "aws-api-calls/1", "calls": [{"service": "ec2", "operation": operation,
        "parameters": {"GroupId": "sg-dl-web", "IpPermissions": [{"IpProtocol": "tcp",
            "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": cidr}]}]}}]}


def test_authorize_security_group_egress_adds_rule_without_no_match(plan_client):
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "egress-api"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json=_egress_api_call("AuthorizeSecurityGroupEgress"))
    assert response.status_code == 200, response.text
    assert not any(item["reason"] == "no_matching_rule" for item in response.json()["unknown_fields"])
    _, egress = _state_rules(branch_id, "sg-dl-web")
    assert any(rule["protocol"] == "tcp" and rule["from_port"] == 443 and rule["ip_ranges"] == ["0.0.0.0/0"] for rule in egress)


def test_revoke_security_group_egress_removes_only_matching_cidr(plan_client, monkeypatch):
    base = load_synthetic_base("delete")
    group = next(item for item in base.ec2.security_groups if item.id == "sg-dl-web")
    group.egress_rules = [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                           "ip_ranges": ["0.0.0.0/0", "10.0.0.0/8"], "source_sg_ids": [], "dest_sg_ids": []}]
    monkeypatch.setattr("app.main.get_infrastructure_for_analysis", lambda _id: base)
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "egress-revoke"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json=_egress_api_call("RevokeSecurityGroupEgress"))
    assert response.status_code == 200, response.text
    _, egress = _state_rules(branch_id, "sg-dl-web")
    assert egress == [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                       "ip_ranges": ["10.0.0.0/8"], "source_sg_ids": [], "dest_sg_ids": []}]


def test_terraform_and_authorize_security_group_egress_match(plan_client):
    terraform = _plan(_item(
        "aws_vpc_security_group_egress_rule.https", "aws_vpc_security_group_egress_rule", ["create"],
        after={"security_group_id": "sg-dl-web", "cidr_ipv4": "0.0.0.0/0", "from_port": 443,
               "to_port": 443, "ip_protocol": "tcp"}))
    tf_branch_id, _, response = _post(plan_client, terraform)
    assert response.status_code == 200, response.text
    api_branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "egress-parity"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{api_branch_id}/plans/aws-api", json=_egress_api_call("AuthorizeSecurityGroupEgress"))
    assert response.status_code == 200, response.text
    _, tf_egress = _state_rules(tf_branch_id, "sg-dl-web")
    _, api_egress = _state_rules(api_branch_id, "sg-dl-web")
    egress_fields = ("protocol", "from_port", "to_port", "ip_ranges", "dest_sg_ids")
    assert [{key: rule.get(key, []) for key in egress_fields} for rule in tf_egress] == [
        {key: rule.get(key, []) for key in egress_fields} for rule in api_egress]
