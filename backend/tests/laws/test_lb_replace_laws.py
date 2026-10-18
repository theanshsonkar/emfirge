import pytest

from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.test_plan_ingest import _post


FIELDS = {
    "aws_lb": ["internal", "load_balancer_type", "security_groups", "subnets", "subnet_mapping", "ip_address_type"],
    "aws_alb": ["internal", "load_balancer_type", "security_groups", "subnets", "subnet_mapping", "ip_address_type"],
    "aws_lb_listener": ["port", "protocol", "ssl_policy", "certificate_arn", "default_action"],
    "aws_alb_listener": ["port", "protocol", "ssl_policy", "certificate_arn", "default_action"],
    "aws_lb_listener_rule": ["action", "condition", "listener_arn"],
    "aws_alb_listener_rule": ["action", "condition", "listener_arn"],
    "aws_lb_listener_certificate": ["certificate_arn", "listener_arn"],
    "aws_alb_listener_certificate": ["certificate_arn", "listener_arn"],
    "aws_lb_target_group": ["port", "protocol", "target_type", "vpc_id"],
    "aws_alb_target_group": ["port", "protocol", "target_type", "vpc_id"],
    "aws_lb_target_group_attachment": ["target_group_arn", "target_id", "port"],
    "aws_alb_target_group_attachment": ["target_group_arn", "target_id", "port"],
}


def _item(typ, actions, before, after, unknown=None):
    return {"address": f"{typ}.x", "mode": "managed", "type": typ,
            "change": {"actions": actions, "before": before, "after": after,
                        "after_unknown": unknown or {}}}


def _verdict(client, branch):
    return client.get(f"/branches/{branch}/verdict").json()


@pytest.mark.parametrize("typ", list(FIELDS))
def test_L45_like_for_like_replace_warns_stateless(plan_client, typ):
    values = {field: f"value-{index}" for index, field in enumerate(FIELDS[typ])}
    branch, _body, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [_item(typ, ["delete", "create"], values, dict(values))]})
    assert response.status_code == 200, response.text
    reasons = _verdict(plan_client, branch)["reasons"]
    assert any(r["level"] == "warn" and r["code"] == "stateless_replace" for r in reasons)
    assert "unmodeled_delete" not in {r["code"] for r in reasons}
    message = next(r["message"] for r in reasons if r["code"] == "stateless_replace")
    assert f"Terraform plan replaces {typ} without changing its network or security settings" in message
    if typ in {"aws_lb", "aws_alb"}:
        assert "DNS name will change" in message


def test_L45_changed_unknown_and_delete_remain_blocked(plan_client):
    cases = [
        _item("aws_lb", ["delete", "create"], {"internal": True}, {"internal": False}),
        _item("aws_lb_listener", ["delete", "create"], {"port": 443}, {"port": 8443}),
        _item("aws_lb_target_group", ["delete", "create"], {"vpc_id": "vpc-1"}, {}, {"vpc_id": True}),
        _item("aws_lb", ["delete"], {"internal": True}, None),
    ]
    for item in cases:
        branch, _body, response = _post(plan_client, {"format_version": "1.0", "resource_changes": [item]})
        assert response.status_code == 200, response.text
        verdict = _verdict(plan_client, branch)
        assert verdict["verdict"] == "block"
        assert "stateless_replace" not in {r["code"] for r in verdict["reasons"]}


def test_L45_real_blocking_change_still_blocks_with_lb_replace(plan_client):
    resources = [
        _item("aws_lb", ["delete", "create"], {"internal": True}, {"internal": True}),
        _item("aws_dynamodb_table", ["delete"], {"name": "data"}, None),
    ]
    branch, _body, response = _post(plan_client, {"format_version": "1.0", "resource_changes": resources})
    assert response.status_code == 200, response.text
    verdict = _verdict(plan_client, branch)
    assert verdict["verdict"] == "block"
    assert "stateless_replace" in {r["code"] for r in verdict["reasons"]}
    assert "unmodeled_delete" in {r["code"] for r in verdict["reasons"]}
