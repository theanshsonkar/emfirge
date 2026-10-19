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



def test_L47b_cost_changes_and_findings_swap():
    for before in _variants():
        for after in _variants():
            left = diff_infrastructure(before, after).model_dump(mode="json")
            right = diff_infrastructure(after, before).model_dump(mode="json")
            left_cost = {(item["resource_type"], item["resource_id"]): item for item in left["cost_changes"]}
            right_cost = {(item["resource_type"], item["resource_id"]): item for item in right["cost_changes"]}
            assert set(left_cost) == set(right_cost)
            for key in left_cost:
                lhs, rhs = left_cost[key], right_cost[key]
                assert lhs["before_monthly_usd"] == rhs["after_monthly_usd"]
                assert lhs["after_monthly_usd"] == rhs["before_monthly_usd"]
                assert lhs["before_basis"] == rhs["after_basis"]
                assert lhs["after_basis"] == rhs["before_basis"]
            assert sorted(json.dumps(item, sort_keys=True) for item in left["added_findings"]) == sorted(
                json.dumps(item, sort_keys=True) for item in right["removed_findings"]
            )
            assert sorted(json.dumps(item, sort_keys=True) for item in left["removed_findings"]) == sorted(
                json.dumps(item, sort_keys=True) for item in right["added_findings"]
            )
            left_modified = {item["id"]: item["changed"] for item in left["resources_modified"]}
            right_modified = {item["id"]: item["changed"] for item in right["resources_modified"]}
            assert left_modified == right_modified


def test_L47d_cost_sides_match_brute_force_for_every_pair():
    estimated, unknown = False, False
    for before in _variants():
        for after in _variants():
            result = diff_infrastructure(before, after).model_dump(mode="json")
            expected_before = round(sum(
                item.monthly_usd for item in estimate_monthly_cost(before).resources
                if item.monthly_usd is not None
            ), 2)
            expected_after = round(sum(
                item.monthly_usd for item in estimate_monthly_cost(after).resources
                if item.monthly_usd is not None
            ), 2)
            assert result["cost_before"]["known_monthly_usd"] == expected_before
            assert result["cost_after"]["known_monthly_usd"] == expected_after
            status = result["cost_delta"]["status"]
            if status == "estimated":
                estimated = True
                assert abs((expected_after - expected_before) - result["cost_delta"]["value"]) <= 0.01
            elif status == "unknown":
                unknown = True
            elif status == "n/a":
                assert not result["cost_changes"]
                assert all(
                    item["before_basis"] in {None, "free"}
                    and item["after_basis"] in {None, "free"}
                    for item in result["cost_changes"]
                )
    assert estimated
    assert unknown


def test_L47d_removed_instance_cost_change():
    base, removed = _variants()[0], _variants()[3]
    result = diff_infrastructure(base, removed).model_dump(mode="json")
    change = next(item for item in result["cost_changes"] if item["resource_id"] == "i-l47")
    assert isinstance(change["before_monthly_usd"], float)
    assert change["before_monthly_usd"] > 0
    assert change["after_monthly_usd"] is None
    assert change["after_basis"] is None
    assert result["cost_after"]["known_monthly_usd"] < result["cost_before"]["known_monthly_usd"]


def test_L47g_verdict_matches_diff_for_several_pairs():
    variants = _variants()
    pairs = [(0, 0), (0, 2), (0, 3), (0, 5), (4, 6)]
    fields = ("resources_added", "resources_removed", "resources_modified", "cost_before", "cost_after", "cost_changes")
    for before_index, after_index in pairs:
        before, after = variants[before_index], variants[after_index]
        diff = diff_infrastructure(before, after).model_dump(mode="json")
        verdict = combined_verdict(before, after).model_dump(mode="json")
        for field in fields:
            assert verdict[field] == diff[field]
        assert verdict["cost_delta"] == diff["cost_delta"]


def test_L47_api_branch_diff_and_verdict_show_two_sides(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = _base()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l47-api", "name": "l47-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    changed = client.post(f"/branches/{branch_id}/changes", json={
        "op": "add", "resource_type": "ec2_instance", "resource_id": "i-l47-api",
        "fields": {
            "type": "t3.micro", "state": "running", "subnet_id": "subnet-l33",
            "sg_ids": ["sg-l33"], "has_public_ip": True,
        },
    })
    assert changed.status_code == 200, changed.text
    for endpoint in ("diff", "verdict"):
        response = client.get(f"/branches/{branch_id}/{endpoint}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["resources_added"]) == 1
        assert body["resources_added"][0]["resource_type"] == "ec2_instance"
        added_id = body["resources_added"][0]["id"]
        assert added_id in body["added_nodes"]
        assert body["cost_after"]["known_monthly_usd"] > body["cost_before"]["known_monthly_usd"]
        assert any(
            item["before_basis"] is None and item["after_monthly_usd"] > 0
            for item in body["cost_changes"]
        )
