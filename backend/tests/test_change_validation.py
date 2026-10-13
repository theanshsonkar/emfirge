import copy

import pytest
from fastapi.testclient import TestClient

from app import main
from app.demo_seed import build_demo_infrastructure
from app.mutations import Change, apply_change
from test_demo_flow import demo_branch_db


def _client_for_demo(monkeypatch):
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: build_demo_infrastructure())
    return TestClient(main.app)


def _create_branch(client):
    response = client.post("/branches", json={"base_analysis_id": "demo", "name": "validation"})
    assert response.status_code == 200
    return response.json()["branch_id"]


def test_http_rejects_cidrs_and_preserves_security_group_change_count(
    demo_branch_db, monkeypatch,
):
    client = _client_for_demo(monkeypatch)
    branch_id = _create_branch(client)
    before = client.get(f"/branches/{branch_id}").json()["num_changes"]
    response = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "security_group", "resource_id": "sg-demo-public",
        "fields": {"rules": [{
            "protocol": "tcp", "from_port": 22, "to_port": 22,
            "cidrs": ["0.0.0.0/0"],
        }]},
    })
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail == "Request could not be completed"
    assert "sg-demo-public" not in detail
    assert client.get(f"/branches/{branch_id}").json()["num_changes"] == before


def test_http_rejects_non_boolean_s3_public_flag_and_preserves_change_count(
    demo_branch_db, monkeypatch,
):
    client = _client_for_demo(monkeypatch)
    branch_id = _create_branch(client)
    before = client.get(f"/branches/{branch_id}").json()["num_changes"]
    response = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "s3_bucket",
        "resource_id": "emfirge-demo-artifacts-000000000000",
        "fields": {"is_public": "yes"},
    })
    assert response.status_code == 422
    assert client.get(f"/branches/{branch_id}").json()["num_changes"] == before


@pytest.mark.parametrize(
    "change",
    [
        Change(op="modify", resource_type="iam_role_policy", resource_id="role-arn",
               fields={"access_statements": [{
                   "effect": "allow", "actions": [], "resources": [],
                   "unexpected": "PLANTED-VALUE-123",
               }]}),
        Change(op="modify", resource_type="route_table", resource_id="rtb",
               fields={"routes": [{
                   "destination_cidr": "0.0.0.0/0", "target_type": "nat_gateway",
                   "target_id": "nat", "unexpected": "PLANTED-VALUE-123",
               }]}),
        Change(op="modify", resource_type="security_group", resource_id="sg",
               fields={"rules": [{
                   "protocol": "tcp", "from_port": "22", "to_port": 22,
                   "ip_ranges": [],
               }]}),
        Change(op="modify", resource_type="ec2_instance", resource_id="i",
               fields={"sg_ids": "sg-x"}),
        Change(op="modify", resource_type="security_group", resource_id="sg",
               fields={"rules": [{"protocol": "tcp", "ip_ranges": ["not-a-cidr"]}]}),
        Change(op="add", resource_type="ec2_instance", resource_id="i-new",
               fields={"type": "t3.micro", "state": "running", "sg_ids": [],
                       "unknown_top_level": "PLANTED-VALUE-123"}),
    ],
    ids=[
        "iam-unknown-statement-key", "route-unknown-route-key", "string-port",
        "string-sg-ids", "invalid-cidr", "unknown-ec2-field",
    ],
)
def test_engine_rejects_malformed_change_and_does_not_echo_submitted_value(change):
    with pytest.raises(ValueError) as raised:
        apply_change(build_demo_infrastructure(), change)
    assert "PLANTED-VALUE-123" not in str(raised.value)


def test_accepts_exact_existing_security_group_rules_from_snapshot():
    base = build_demo_infrastructure()
    for group in base.ec2.security_groups:
        result = apply_change(base, Change(
            op="modify", resource_type="security_group", resource_id=group.id,
            fields={"rules": copy.deepcopy(group.rules), "egress_rules": copy.deepcopy(group.egress_rules)},
        ))
        changed = next(item for item in result.ec2.security_groups if item.id == group.id)
        assert changed.rules == group.rules
        assert changed.egress_rules == group.egress_rules


def test_accepts_security_group_rule_with_every_allowed_key_in_collector_shape():
    base = build_demo_infrastructure()
    rule = {
        "dest_sg_ids": ["sg-demo-db"], "from_port": 443,
        "ip_ranges": ["10.0.0.0/16"], "protocol": "tcp",
        "source_sg_ids": ["sg-demo-public"], "to_port": 443,
    }
    result = apply_change(base, Change(
        op="modify", resource_type="security_group", resource_id="sg-demo-public",
        fields={"rules": [rule]},
    ))
    assert result.ec2.security_groups[0].rules == [rule]


def test_accepts_all_traffic_security_group_rule_in_collector_port_convention():
    base = build_demo_infrastructure()
    rule = {"protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}
    result = apply_change(base, Change(
        op="modify", resource_type="security_group", resource_id="sg-demo-public",
        fields={"egress_rules": [rule]},
    ))
    assert result.ec2.security_groups[0].egress_rules == [rule]


def test_accepts_iam_access_statement_with_every_allowed_key():
    base = build_demo_infrastructure()
    statement = {
        "effect": "allow", "actions": ["s3:GetObject"], "resources": ["*"],
        "is_not_action": False, "is_not_resource": False, "has_condition": False,
    }
    role_arn = base.iam.role_policies[0].role_arn
    result = apply_change(base, Change(
        op="modify", resource_type="iam_role_policy", resource_id=role_arn,
        fields={"access_statements": [statement]},
    ))
    assert [item.model_dump() for item in result.iam.role_policies[0].access_statements] == [statement]


def test_accepts_valid_route():
    base = build_demo_infrastructure()
    route = {
        "destination_cidr": "0.0.0.0/0", "target_type": "internet_gateway",
        "target_id": "igw-demo-001",
    }
    result = apply_change(base, Change(
        op="modify", resource_type="route_table", resource_id="rtb-demo-public",
        fields={"routes": [route]},
    ))
    assert [item.model_dump() for item in result.vpc.route_tables[0].routes] == [route]
