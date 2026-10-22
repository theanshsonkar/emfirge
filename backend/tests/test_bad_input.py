import random

import pytest
from pydantic import ValidationError

from app.models import AWSInfrastructure, EC2Data, EC2Instance, SecurityGroup, VPCData, VPCSubnet
from app.mutations import Change, SecurityGroupRuleChange, _validate_change, apply_change, apply_changes
from app.verdict import combined_verdict


def base(*, groups=True, subnets=False):
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(security_groups=[SecurityGroup(id="sg-existing", name="existing")] if groups else []),
        vpc=VPCData(subnets=[VPCSubnet(id="subnet-existing", vpc_id="vpc-1")] if subnets else []),
    )


def sg_change(rule):
    return Change(op="modify", resource_type="security_group", resource_id="sg-existing", fields={"rules": [rule]})


def test_t1_rejects_reversed_tcp_ports():
    with pytest.raises(ValueError, match="from_port.*to_port"):
        apply_change(base(), sg_change({"protocol": "tcp", "from_port": 443, "to_port": 80, "ip_ranges": ["0.0.0.0/0"]}))


def test_t2_icmp_and_all_protocols_are_not_port_ranges():
    for protocol, start, end in (("icmp", 8, 0), ("icmpv6", 8, 0), ("-1", -1, -1)):
        apply_change(base(), sg_change({"protocol": protocol, "from_port": start, "to_port": end, "ip_ranges": ["0.0.0.0/0"]}))


def test_t3_port_order_property():
    rng = random.Random(0)
    for _ in range(500):
        start, end = rng.randrange(65536), rng.randrange(65536)
        change = sg_change({"protocol": rng.choice(["tcp", "udp"]), "from_port": start, "to_port": end, "ip_ranges": ["10.0.0.0/8"]})
        if start <= end:
            _validate_change(change)
        else:
            with pytest.raises(ValueError):
                _validate_change(change)


def test_t4_rule_requires_source():
    with pytest.raises(ValueError, match="source is required"):
        apply_change(base(), sg_change({"protocol": "tcp", "from_port": 1, "to_port": 2}))


def test_t5_cidrs_is_exact_unknown_field_and_not_no_source():
    with pytest.raises(ValueError) as exc:
        apply_change(base(), sg_change({"protocol": "tcp", "from_port": 1, "to_port": 2, "cidrs": ["0.0.0.0/0"]}))
    assert "security_group.rules[0]: unknown field 'cidrs' (allowed: dest_sg_ids, from_port, ip_ranges, protocol, source_sg_ids, to_port)" in str(exc.value)
    assert "source is required" not in str(exc.value)


@pytest.mark.parametrize("state", ["pending", "running", "shutting-down", "terminated", "stopping", "stopped"])
def test_t6_ec2_states(state):
    apply_change(base(), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={"type": "t3.micro", "state": state}))


def test_t6_bad_state_and_t11_missing_required_fields():
    with pytest.raises(ValueError, match="pending.*running.*shutting-down"):
        apply_change(base(), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={"type": "t3.micro", "state": "banana"}))
    with pytest.raises(ValidationError, match="2 validation errors for EC2Instance"):
        apply_change(base(), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={}))


def test_t7_referential_checks_and_t8_stacking():
    with pytest.raises(ValueError, match="not found"):
        apply_change(base(subnets=True), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={"type": "t3.micro", "state": "running", "sg_ids": ["sg-0doesnotexist"]}))
    with pytest.raises(ValueError, match="not found"):
        apply_change(base(subnets=True), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={"type": "t3.micro", "state": "running", "subnet_id": "subnet-nope"}))
    changes = [Change(op="add", resource_type="security_group", resource_id="sg-new1", fields={"name": "new"}), Change(op="add", resource_type="ec2_instance", resource_id="i-1", fields={"type": "t3.micro", "state": "running", "sg_ids": ["sg-new1"]})]
    result = apply_changes(base(), changes)
    assert result.ec2.instances[0].sg_ids == ["sg-new1"]


def test_t9_modify_empty_rejected_delete_empty_allowed():
    with pytest.raises(ValueError, match="modify needs at least one field"):
        apply_change(base(), Change(op="modify", resource_type="security_group", resource_id="sg-existing", fields={}))
    result = apply_change(base(), Change(op="delete", resource_type="security_group", resource_id="sg-existing", fields={}))
    assert result.ec2.security_groups == []


def test_t10_unspecified_values_is_a_verdict_reason_without_id_in_message():
    change = Change(op="add", resource_type="ec2_instance", resource_id="i-unspecified", fields={"type": "t3.micro", "state": "running"})
    result = combined_verdict(base(), apply_change(base(), change), run_scanners=False)
    reason = next(item for item in result.reasons if item["code"] == "unspecified_values")
    assert reason["level"] == "warn" and reason["resources"] == ["i-unspecified"]
    assert "i-unspecified" not in reason["message"]
    assert "unspecified_change_fields" in result.coverage_warnings


def test_t10_fully_placed_ec2_has_no_unspecified_reason():
    change = Change(op="add", resource_type="ec2_instance", resource_id="i-placed", fields={"type": "t3.micro", "state": "running", "subnet_id": "subnet-existing", "sg_ids": ["sg-existing"]})
    result = combined_verdict(base(subnets=True), apply_change(base(subnets=True), change), run_scanners=False)
    assert not any(item["code"] == "unspecified_values" for item in result.reasons)


def test_t12_terraform_bad_ingress_is_rejected_not_applied():
    from app.plan_ingest import translate_plan
    document = {"format_version": "1.0", "resource_changes": [{
        "address": "aws_security_group.x", "type": "aws_security_group",
        "change": {"actions": ["create"], "before": None, "after": {
            "name": "x", "ingress": [{"protocol": "tcp", "from_port": 443,
            "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}],
        }, "after_unknown": {}},
    }]}
    translated = translate_plan(document)
    rejected = []
    for change, address in zip(translated["changes"], translated["addresses"]):
        try:
            apply_change(base(), change)
        except ValueError:
            rejected.append(address)
    assert rejected == ["aws_security_group.x"]


def test_t10_terraform_ec2_add_without_subnet_gets_unspecified_values():
    from app.plan_ingest import translate_plan

    document = {"format_version": "1.0", "resource_changes": [{
        "address": "aws_instance.unplaced", "type": "aws_instance",
        "change": {"actions": ["create"], "before": None,
                   "after": {"instance_type": "t3.micro"}, "after_unknown": {}},
    }]}
    translated = translate_plan(document)
    change = translated["changes"][0]
    result = combined_verdict(base(), apply_change(base(), change), run_scanners=False)
    reason = next(item for item in result.reasons if item["code"] == "unspecified_values")
    generated_id = result and next(instance.id for instance in apply_change(base(), change).ec2.instances)
    assert reason["level"] == "warn"
    assert generated_id in reason["resources"]
    assert generated_id not in reason["message"]
    assert "unspecified_change_fields" in result.coverage_warnings
