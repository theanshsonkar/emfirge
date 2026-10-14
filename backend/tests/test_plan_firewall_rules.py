from app.plan_ingest import translate_plan


def test_ipv6_ingress_rule_is_modeled_as_open_ingress():
    result = translate_plan({"format_version": "1.0", "resource_changes": [{
        "address": "aws_vpc_security_group_ingress_rule.ssh", "type": "aws_vpc_security_group_ingress_rule",
        "change": {"actions": ["create"], "before": None,
                    "after": {"security_group_id": "sg-test", "cidr_ipv6": "::/0", "from_port": 22,
                               "to_port": 22, "ip_protocol": "tcp"}},
    }]}, sg_rules={"sg-test": {"rules": [], "egress_rules": []}})
    assert result["changes"][0].fields["rules"][0]["ip_ranges"] == ["::/0"]
