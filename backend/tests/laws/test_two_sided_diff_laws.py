"""L47 two-sided branch diff laws: additive resource and cost before/after views."""
import json

from app.cost import estimate_monthly_cost
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.models import AWSInfrastructure, EC2Instance, S3Bucket
from app.verdict import combined_verdict
from tests.laws.test_nacl_laws import infra as make_infra


def _base():
    return make_infra([], sg_ports=(22, 22)).model_copy(update={
        "ec2": make_infra([], sg_ports=(22, 22)).ec2.model_copy(update={
            "instances": [EC2Instance(id="i-l47", type="t3.micro", state="running", subnet_id="subnet-l33", sg_ids=["sg-l33"], has_public_ip=True)],
        }),
    })


def _variants():
    base = _base()
    instance = EC2Instance(id="i-l47-added", type="t3.micro", state="running", subnet_id="subnet-l33", sg_ids=["sg-l33"], has_public_ip=True)
    added = base.model_copy(update={"ec2": base.ec2.model_copy(update={"instances": base.ec2.instances + [instance]})})
    removed = base.model_copy(update={"ec2": base.ec2.model_copy(update={"instances": []})})
    sg = base.ec2.security_groups[0].model_copy(update={"rules": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}]})
    sg_changed = base.model_copy(update={"ec2": base.ec2.model_copy(update={"security_groups": [sg]})})
    usage = base.model_copy(update={"s3": base.s3.model_copy(update={"buckets": [S3Bucket(name="l47-usage")]})})
    combo = added.model_copy(update={"s3": usage.s3})
    return [base, base.model_copy(deep=True), added, removed, sg_changed, usage, combo]


def _canon_nodes(infra):
    return {str(node.id): node for node in build_graph(infra).nodes}


def test_L47a_ids_and_L47f_privacy_for_every_ordered_pair():
    variants = _variants()
    for before in variants:
        for after in variants:
            result = diff_infrastructure(before, after).model_dump(mode="json")
            old, new = _canon_nodes(before), _canon_nodes(after)
            added = set(new) - set(old)
            removed = set(old) - set(new)
            modified = {key for key in set(old) & set(new) if json.dumps(old[key].model_dump(mode="json"), sort_keys=True) != json.dumps(new[key].model_dump(mode="json"), sort_keys=True)}
            assert {item["id"] for item in result["resources_added"]} == added == set(result["added_nodes"])
            assert {item["id"] for item in result["resources_removed"]} == removed == set(result["removed_nodes"])
            assert {item["id"] for item in result["resources_modified"]} == modified == set(result["modified_nodes"])
            for item in result["resources_modified"]:
                assert item["changed"]
                assert all(field == "resource_type" or field in {"base", "security", "cost", "limits", "telemetry"} or field.startswith(("base.", "security.", "cost.", "limits.", "telemetry.")) for field in item["changed"])
                assert all(field.count(".") <= 1 for field in item["changed"])


def test_L47b_symmetry_and_L47c_identity():
    variants = _variants()
    for before in variants:
        for after in variants:
            left = diff_infrastructure(before, after).model_dump(mode="json")
            right = diff_infrastructure(after, before).model_dump(mode="json")
            assert left["resources_added"] == right["resources_removed"]
            assert left["resources_removed"] == right["resources_added"]
            assert {x["id"] for x in left["resources_modified"]} == {x["id"] for x in right["resources_modified"]}
            assert left["cost_before"] == right["cost_after"]
            assert left["cost_after"] == right["cost_before"]
            if before == after:
                assert all(not left[key] for key in ("resources_added", "resources_removed", "resources_modified", "cost_changes"))
                assert left["cost_before"] == left["cost_after"]


def test_L47d_and_L47e_cost_honesty():
    base, usage = _variants()[0], _variants()[5]
    result = diff_infrastructure(base, usage).model_dump(mode="json")
    expected = round(sum(item.monthly_usd for item in estimate_monthly_cost(base).resources if item.monthly_usd is not None), 2)
    assert result["cost_before"]["known_monthly_usd"] == expected
    assert result["cost_after"]["status"] == "partial"
    assert result["cost_after"]["unknown_count"] >= 1
    assert any(item["after_monthly_usd"] is None for item in result["cost_changes"] if item["resource_id"] == "l47-usage")


def test_L47g_combined_verdict_copies_two_sided_fields():
    before, after = _variants()[0], _variants()[2]
    diff = diff_infrastructure(before, after)
    verdict = combined_verdict(before, after)
    payload = verdict.model_dump(mode="json")
    for key in ("resources_added", "resources_removed", "resources_modified", "cost_before", "cost_after", "cost_changes"):
        assert payload[key] == getattr(diff, key)
