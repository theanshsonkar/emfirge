"""L53 stacked cross-type changes: add EC2 -> attach IAM role -> open SG.

Each step alone is harmless or only partly exposed; the bucket the role can read
becomes internet reachable only when all three are on the branch.
"""
import itertools

import pytest

from app.diffing import diff_infrastructure
from app.mutations import Change, TargetNotFound, apply_changes
from app.typed_handback import UnmappableChanges, build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

PROFILE = "arn:aws:iam::000000000000:instance-profile/DlWorkerRole"
ROLE_NODE, BUCKET, SG = "iam-role-DlWorkerRole", "dl-data-bucket", "sg-dl-unused"

ADD = Change(op="add", resource_type="ec2_instance", resource_id="i-l53", fields={
    "type": "t3.micro", "state": "running", "subnet_id": "subnet-dl-pub", "sg_ids": [SG], "has_public_ip": True})
ATTACH = Change(op="modify", resource_type="ec2_instance", resource_id="i-l53", fields={"instance_profile_arn": PROFILE})
OPEN = Change(op="modify", resource_type="security_group", resource_id=SG, fields={"rules": [
    {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []}]})
STACK = [ADD, ATTACH, OPEN]


def verdict(base, changes):
    return combined_verdict(base, apply_changes(base, changes), run_scanners=False)


def test_L53a_only_the_full_stack_exposes_the_data_the_role_can_read():
    base = load_synthetic_base("delete")
    full = verdict(base, STACK)
    assert full.verdict == "block"
    assert {"i-l53", ROLE_NODE, BUCKET} <= set(full.newly_internet_reachable)
    for subset in ([ADD], [ADD, ATTACH], [ADD, OPEN]):
        partial = verdict(base, subset)
        assert BUCKET not in partial.newly_internet_reachable, [c.op + ":" + c.resource_type for c in subset]
        assert ROLE_NODE not in partial.newly_internet_reachable
    # The instance itself is exposed as soon as its SG opens, with or without the role.
    assert "i-l53" in verdict(base, [ADD, OPEN]).newly_internet_reachable
    assert verdict(base, [ADD, ATTACH]).newly_internet_reachable == []


def test_L53b_valid_orders_give_the_same_branch_and_verdict():
    base = load_synthetic_base("delete")
    results = {}
    for order in itertools.permutations(STACK):
        try:
            branch = apply_changes(base, list(order))
        except TargetNotFound:
            # Attaching a role to an instance that does not exist yet is rejected, never deferred.
            assert order.index(ATTACH) < order.index(ADD)
            continue
        result = combined_verdict(base, branch, run_scanners=False)
        results[tuple(id(c) for c in order)] = (branch.model_dump_json(), result.verdict, tuple(sorted(result.newly_internet_reachable)))
    assert len(results) == 3  # ADD first or OPEN first, ATTACH after ADD
    assert len(set(results.values())) == 1


def test_L53c_diff_vs_base_shows_every_type_touched():
    base = load_synthetic_base("delete")
    diff = diff_infrastructure(base, apply_changes(base, STACK))
    assert any(item["id"] == "i-l53" and item["resource_type"] == "ec2_instance" for item in diff.resources_added)
    assert any(item["id"] == SG for item in diff.resources_modified)
    edges = {(edge["from"], edge["to"], edge["relationship"]) for edge in diff.added_edges}
    assert {("i-l53", ROLE_NODE, "uses_iam_role"), ("INTERNET", "i-l53", "REACHES_VIA_SG")} <= edges


def test_L53d_every_prefix_is_a_pure_function_of_the_base():
    base = load_synthetic_base("delete")
    before = base.model_dump_json()
    step = base
    for count in range(1, len(STACK) + 1):
        step = apply_changes(step, [STACK[count - 1]])
        assert step.model_dump_json() == apply_changes(base, STACK[:count]).model_dump_json()
    assert base.model_dump_json() == before


def test_L53e_handback_never_names_a_branch_created_instance_or_group():
    base = load_synthetic_base("delete")
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, STACK)
    reasons = [item["reason"] for item in exc.value.changes]
    assert reasons == ["operation_not_mapped", "depends_on_branch_created_ec2_instance"]
    # A created security group cannot be referenced by a later change either.
    new_sg = Change(op="add", resource_type="security_group", resource_id="sg-l53", fields={"name": "l53"})
    uses_it = Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"sg_ids": ["sg-l53"]})
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [new_sg, uses_it])
    assert "depends_on_branch_created_security_group" in [item["reason"] for item in exc.value.changes]


def test_L53e_the_same_stack_on_existing_resources_hands_back_exactly():
    base = load_synthetic_base("delete")
    attach = Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web", fields={"instance_profile_arn": PROFILE})
    calls = build_api_calls(base, [attach, OPEN])
    assert [(c["operation"], c["params"]) for c in calls] == [
        ("AssociateIamInstanceProfile", {"InstanceId": "i-dl-web", "IamInstanceProfile": {"Arn": PROFILE}}),
        ("AuthorizeSecurityGroupIngress", {"GroupId": SG, "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
    ]
    # Replacing a profile needs the association id, which Emfirge does not collect.
    replace = Change(op="modify", resource_type="ec2_instance", resource_id="i-dl-web",
                     fields={"instance_profile_arn": "arn:aws:iam::000000000000:instance-profile/DlAppRole"})
    with pytest.raises(UnmappableChanges):
        build_api_calls(apply_changes(base, [attach]), [replace])


def test_L53f_api_branch_stacks_rolls_back_and_discards(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = load_synthetic_base("delete")
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l53-api", "name": "l53-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    seen = []
    for change in STACK:
        response = client.post(f"/branches/{branch_id}/changes", json=change.model_dump(include={"op", "resource_type", "resource_id", "fields"}))
        assert response.status_code == 200, response.text
        seen.append(client.get(f"/branches/{branch_id}/verdict").json())
    assert [item["verdict"] for item in seen] == ["warn", "warn", "block"]
    assert BUCKET in seen[-1]["newly_internet_reachable"]
    # Diff anytime equals the pure prefix diff.
    assert {item["id"] for item in client.get(f"/branches/{branch_id}/diff").json()["resources_added"]} == {
        item["id"] for item in diff_infrastructure(base, apply_changes(base, STACK)).resources_added}
    rolled = client.post(f"/branches/{branch_id}/rollback", json={"expected_change_count": 3})
    assert rolled.status_code == 200, rolled.text
    after_rollback = client.get(f"/branches/{branch_id}/verdict").json()
    assert after_rollback["verdict"] == seen[1]["verdict"] and BUCKET not in after_rollback["newly_internet_reachable"]
    # Attaching to an instance the branch never added is a 404/422, not a silent no-op.
    other = client.post(f"/branches/{branch_id}/changes", json={**ATTACH.model_dump(include={"op", "resource_type", "fields"}), "resource_id": "i-missing"})
    assert other.status_code in {404, 422}, other.text
    discarded = client.post(f"/branches/{branch_id}/discard", json={})
    assert discarded.status_code == 200, discarded.text
