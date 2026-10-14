import copy
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, strategies as st
from fastapi.testclient import TestClient

from app import branches, database, main, verdict
from app.diffing import diff_infrastructure
from app.egraph import build_graph, find_attack_path, get_internet_reachable_set
from app.exposure import compute_exposures
from app.mutations import Change, apply_change, apply_changes
from app.rules import run_all_checks
from app.scoring import calculate_score
from app.verdict import combined_verdict
from app.models import NetworkInterface
from tests.incidents.base import build_incident_base
from tests.incidents.test_incidents import incident_branch_db

PORTS = st.sampled_from([22, 80, 443, 3306, 5432, 6379, 8000, 5173])
SOURCES = st.sampled_from(["0.0.0.0/0", "10.0.0.0/16", "203.0.113.10/32"])
RULE = st.builds(
    lambda p, src: {"protocol": "tcp", "from_port": p, "to_port": p, "ip_ranges": [src]},
    PORTS, SOURCES,
)
RULES = st.lists(RULE, max_size=4, unique_by=lambda r: (r["from_port"], r["ip_ranges"][0]))


def _scan_total_resources(infra):
    # Mirrors the scan path in app/main.py (~3074-3091). Phase 0 #4 should replace this with one shared function.
    return (
        infra.ec2.instance_count + len(infra.ec2.security_groups) + len(infra.ec2.ebs_volumes)
        + len(infra.ec2.elastic_ips) + infra.s3.total_buckets + len(infra.rds.instances)
        + len(infra.iam.iam_users) + (1 if infra.cloudtrail.is_enabled else 0)
        + infra.lambda_data.function_count + infra.secrets_manager.total_secrets
        + (1 if infra.guardduty.is_enabled else 0) + infra.vpc.total_vpcs + len(infra.vpc.subnets)
        + infra.kms.total_cmks + infra.sns.total_topics + infra.ecs.total_task_definitions
    )


def _scan_score(infra):
    findings = run_all_checks(infra, build_graph(infra))
    return calculate_score(findings, _scan_total_resources(infra), infra)["overall_risk_score"]


def _changes_for_rules(sg_id, rules):
    return Change(op="modify", resource_type="security_group", resource_id=sg_id, fields={"rules": rules})


@given(st.integers(min_value=0, max_value=15))
def test_L1_empty_branch_score_matches_scan_with_variable_resource_count(extra_buckets):
    base = build_incident_base()
    for index in range(extra_buckets):
        base = apply_change(base, Change(
            op="add", resource_type="s3_bucket", resource_id=f"private-extra-{index}",
            fields={"is_public": False},
        ))
    result = combined_verdict(base, copy.deepcopy(base), run_scanners=False)
    assert result.verdict == "pass"
    assert result.score_before == _scan_score(base)


@given(RULES)
def test_L2_apply_and_empty_diff_preserve_base(rules):
    base = build_incident_base()
    original = base.model_dump()
    branch = apply_change(base, _changes_for_rules("sg-inc-web", rules))
    assert base.model_dump() == original == build_incident_base().model_dump()
    rolled = apply_changes(base, [])
    diff = diff_infrastructure(base, rolled)
    assert not diff.added_nodes and not diff.removed_nodes and not diff.added_edges and not diff.removed_edges
    assert not diff.added_findings and not diff.removed_findings
    assert not diff.newly_internet_reachable and not diff.no_longer_internet_reachable
    assert diff.score_after == diff.score_before


def test_L2_http_scenarios_rollback_to_empty_is_identical(incident_branch_db, monkeypatch):
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    monkeypatch.setattr(main, "_BRANCH_LIMIT", 10000)
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    main._branch_request_log.clear()
    client = TestClient(main.app)
    for scenario in json.loads((Path(__file__).parents[1] / "incidents" / "scenarios.json").read_text()):
        main._branch_request_log.clear()
        created = client.post("/branches", json={"base_analysis_id": "incident", "name": f"law-{scenario['id']}"})
        assert created.status_code == 200
        branch_id = created.json()["branch_id"]
        accepted = True
        for count, change in enumerate(scenario["changes"]):
            response = client.post(
                f"/branches/{branch_id}/changes",
                json={**change, "expected_change_count": count},
            )
            if response.status_code != 200:
                accepted = False
                break
        if not accepted:
            continue
        rolled = client.post(f"/branches/{branch_id}/rollback-to-count", json={"target_change_count": 0})
        assert rolled.status_code == 200
        diff = client.get(f"/branches/{branch_id}/diff")
        assert diff.status_code == 200
        payload = diff.json()
        assert not payload["added_nodes"] and not payload["removed_nodes"]
        assert not payload["added_edges"] and not payload["removed_edges"]
        assert not payload["added_findings"] and not payload["removed_findings"]
        assert not payload["newly_internet_reachable"] and not payload["no_longer_internet_reachable"]
        assert payload["score_after"] == payload["score_before"]


@given(
    st.sampled_from(["sg-inc-web", "sg-inc-latent"]),
    RULES,
    st.integers(min_value=0, max_value=3),
)
def test_L3_ingress_monotonic_reachability(sg_id, rules, remove_count):
    base = build_incident_base()
    old = set(get_internet_reachable_set(build_graph(base)))
    sg = next(x for x in base.ec2.security_groups if x.id == sg_id)
    added = apply_change(base, _changes_for_rules(sg_id, sg.rules + rules))
    assert old <= get_internet_reachable_set(build_graph(added))
    removed_rules = sg.rules[remove_count:]
    removed = apply_change(base, _changes_for_rules(sg_id, removed_rules))
    assert get_internet_reachable_set(build_graph(removed)) <= old


@pytest.mark.parametrize("evidence", ["read-and-unused", "read-and-used-by-an-interface", "denied"])
def test_L4_only_introduced_critical_findings_block(evidence):
    base = build_incident_base()
    branch = apply_change(base, _changes_for_rules("sg-inc-latent", [{
        "protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]
    }]))
    if evidence == "read-and-unused":
        branch.network_interfaces = []
        branch.collection = {"network_interfaces": "ok"}
    elif evidence == "read-and-used-by-an-interface":
        branch.network_interfaces = [NetworkInterface(id="eni-extra", sg_ids=["sg-inc-latent"], attached_resource="i-extra")]
        branch.collection = {"network_interfaces": "ok"}
    else:
        branch.network_interfaces = None
        branch.collection = {"network_interfaces": "denied"}
    result = combined_verdict(base, branch, run_scanners=False)
    codes = {reason["code"] for reason in result.reasons}
    blocking = {"introduced_critical_exposure", "introduced_critical_finding", "privilege_escalation", "data_store_deleted_no_recovery_point"}
    if evidence == "read-and-unused":
        assert "latent_exposure" in codes
        assert result.verdict == ("block" if codes & blocking else "warn")
    else:
        assert result.verdict == "block"
        assert "latent_exposure" not in codes


@given(st.lists(st.sampled_from(["inc-data-bucket", "inc-assets-bucket", "i-inc-web", "sg-inc-latent", "inc-worker"]), min_size=1, max_size=3, unique=True))
def test_L5_deletion_never_increases_score(resource_ids):
    base = build_incident_base()
    resource_types = {
        "inc-data-bucket": "s3_bucket", "inc-assets-bucket": "s3_bucket",
        "i-inc-web": "ec2_instance", "sg-inc-latent": "security_group", "inc-worker": "lambda_function",
    }
    branch = base
    for resource_id in resource_ids:
        if resource_id == "sg-inc-latent":
            continue
        branch = apply_change(branch, Change(op="delete", resource_type=resource_types[resource_id], resource_id=resource_id))
    diff = diff_infrastructure(base, branch)
    assert diff.score_after <= diff.score_before


def test_L6_invalid_fields_and_types_rejected():
    base = build_incident_base()
    invalid = [
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"unknown": 1}),
        Change(op="modify", resource_type="security_group", resource_id="sg-inc-web", fields={"rules": [{"protocol": "tcp", "from_port": "22", "to_port": 22, "ip_ranges": ["0.0.0.0/0"]}]}),
        Change(op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket", fields={"is_public": "yes"}),
        Change(op="modify", resource_type="ec2_instance", resource_id="i-inc-web", fields={"sg_ids": "sg-x"}),
    ]
    for change in invalid:
        with pytest.raises((ValueError, TypeError)):
            apply_change(base, change)


@given(RULES)
def test_L7_same_snapshot_and_changes_are_deterministic(rules):
    base = build_incident_base()
    change = _changes_for_rules("sg-inc-web", rules)
    left = apply_change(base, change)
    right = apply_change(base, change)
    assert diff_infrastructure(base, left).model_dump() == diff_infrastructure(base, right).model_dump()
    assert combined_verdict(base, left, run_scanners=False).model_dump(exclude={"branch_revision"}) == combined_verdict(base, right, run_scanners=False).model_dump(exclude={"branch_revision"})


@given(RULES, RULES, st.booleans(), st.booleans(), st.booleans())
def test_L8_verdict_is_exactly_the_reason_policy(web_rules, latent_rules, public_bucket, delete_bucket, delete_instance):
    """The verdict is a pure projection of reason levels, never score heuristics."""
    base = build_incident_base()
    branch = apply_change(base, _changes_for_rules("sg-inc-web", web_rules))
    branch = apply_change(branch, _changes_for_rules("sg-inc-latent", latent_rules))
    branch = apply_change(branch, Change(
        op="modify", resource_type="s3_bucket", resource_id="inc-data-bucket",
        fields={"is_public": public_bucket},
    ))
    if delete_bucket:
        branch = apply_change(branch, Change(
            op="delete", resource_type="s3_bucket", resource_id="inc-assets-bucket",
        ))
    if delete_instance:
        branch = apply_change(branch, Change(
            op="delete", resource_type="ec2_instance", resource_id="i-inc-web",
        ))

    result = combined_verdict(base, branch, run_scanners=False)
    levels = {reason["level"] for reason in result.reasons}
    if "block" in levels:
        assert result.verdict == "block"
    elif "warn" in levels:
        assert result.verdict == "warn"
    else:
        assert result.reasons == []
        assert result.verdict == "pass"


def _normalized_attack_paths(infra):
    """Mirror the attack-path route: exposures grouped by entry resource."""
    graph = build_graph(infra)
    exposures_by_entry = {}
    for exposure in compute_exposures(infra, graph):
        exposures_by_entry.setdefault(exposure.resource_id, []).append(exposure)
    paths = set()
    for entry, exposures in sorted(exposures_by_entry.items()):
        path = find_attack_path(graph, entry)
        severity = "critical" if any(
            exposure.source in ("0.0.0.0/0", "::/0")
            and exposure.from_port <= 22 <= exposure.to_port
            for exposure in exposures
        ) else "moderate"
        node_ids = tuple(node["id"] for node in (path or [{"id": entry}]))
        paths.add((node_ids, severity))
    return paths




CIDRS = [
    {"CidrIp": "0.0.0.0/0"},
    {"CidrIp": "10.0.0.0/8"},
    {"CidrIp": "192.168.1.0/24"},
]
PORT_CHOICES = st.one_of(
    st.sampled_from([22, 3389, 3306, 5432, 6379, 80, 443]),
    st.integers(min_value=1, max_value=65535),
)


@st.composite
def _raw_permission(draw, *, require_ipv4_any=False):
    protocol = draw(st.sampled_from(["tcp", "udp", "-1"]))
    if protocol == "-1":
        ports = {}
    else:
        start = draw(PORT_CHOICES)
        ports = {"FromPort": start, "ToPort": start + draw(st.integers(min_value=0, max_value=65535 - start))}
    ranges = draw(st.lists(st.sampled_from(CIDRS), unique_by=lambda item: item["CidrIp"], max_size=3))
    if require_ipv4_any and not any(item["CidrIp"] == "0.0.0.0/0" for item in ranges):
        ranges = [{"CidrIp": "0.0.0.0/0"}] + ranges
    return {
        "IpProtocol": protocol,
        **ports,
        "IpRanges": ranges,
        "Ipv6Ranges": [],
        "UserIdGroupPairs": draw(st.lists(st.fixed_dictionaries({"GroupId": st.just("sg-peer")}), max_size=1)),
    }


@st.composite
def _raw_permissions(draw):
    required = draw(_raw_permission(require_ipv4_any=True))
    rest = draw(st.lists(_raw_permission(), min_size=0, max_size=3))
    return [required, *rest]


def _collect_raw_web_sg(permissions):
    sg = {
        "GroupId": "sg-inc-web", "GroupName": "incident-web",
        "IpPermissions": permissions, "IpPermissionsEgress": [],
    }
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {"Reservations": []}
    ec2.describe_security_groups.return_value = {"SecurityGroups": [sg]}
    ec2.describe_addresses.return_value = {"Addresses": []}
    ec2.describe_route_tables.return_value = {"RouteTables": []}
    ec2.get_paginator.return_value = MagicMock(paginate=lambda: [{}])
    elb, asg = MagicMock(), MagicMock()
    elb.describe_load_balancers.return_value = {"LoadBalancers": []}
    asg.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    from app.aws_collector import collect_ec2
    with patch(
        "app.aws_collector.boto3.client",
        lambda service, **_: {"ec2": ec2, "elbv2": elb, "autoscaling": asg}[service],
    ):
        return collect_ec2("key", "secret", "token", "ap-south-1", [])


def _incident_with_collected_web(base, collected):
    web = next(sg for sg in collected.security_groups if sg.id == "sg-inc-web")
    target = next(sg for sg in base.ec2.security_groups if sg.id == "sg-inc-web")
    target.rules = web.rules
    target.egress_rules = web.egress_rules
    base.ec2.ssh_open_to_internet = collected.ssh_open_to_internet
    base.ec2.rdp_open_to_internet = collected.rdp_open_to_internet
    base.ec2.ssh_security_group_id = collected.ssh_security_group_id
    base.ec2.rdp_security_group_id = collected.rdp_security_group_id
    base.ec2.open_security_groups = collected.open_security_groups
    return base


def _finding_keys(infra):
    findings = run_all_checks(infra, build_graph(infra))
    categories = ("critical_risks", "moderate_risks", "low_risks", "cost_findings")
    return {
        (getattr(item, "rule_id", None), getattr(item, "resource_id", None), getattr(item, "severity", None))
        for category in categories for item in findings[category]
    }


@given(_raw_permissions())
def test_L17_ipv6_any_is_internet_like_ipv4_any(permissions):
    base = _incident_with_collected_web(build_incident_base(), _collect_raw_web_sg(permissions))
    twin_permissions = copy.deepcopy(permissions)
    for original_permission, permission in zip(permissions, twin_permissions):
        ipv4_any = {"CidrIp": "0.0.0.0/0"}
        had_ipv4_any = ipv4_any in original_permission["IpRanges"]
        permission["IpRanges"] = [item for item in permission["IpRanges"] if item != ipv4_any]
        if had_ipv4_any:
            permission["Ipv6Ranges"].append({"CidrIpv6": "::/0"})
    twin = _incident_with_collected_web(build_incident_base(), _collect_raw_web_sg(twin_permissions))

    original_web = next(sg for sg in base.ec2.security_groups if sg.id == "sg-inc-web")
    twin_web = next(sg for sg in twin.ec2.security_groups if sg.id == "sg-inc-web")
    assert (base.ec2.ssh_open_to_internet, base.ec2.rdp_open_to_internet) == (twin.ec2.ssh_open_to_internet, twin.ec2.rdp_open_to_internet)
    assert _finding_keys(base) == _finding_keys(twin)
    assert get_internet_reachable_set(build_graph(base)) == get_internet_reachable_set(build_graph(twin))
    assert _normalized_attack_paths(base) == _normalized_attack_paths(twin)
    left = combined_verdict(base, apply_change(base, _changes_for_rules("sg-inc-web", original_web.rules)), run_scanners=False)
    right = combined_verdict(twin, apply_change(twin, _changes_for_rules("sg-inc-web", twin_web.rules)), run_scanners=False)
    assert (left.verdict, {reason["code"] for reason in left.reasons}) == (right.verdict, {reason["code"] for reason in right.reasons})


def test_L17_sanity_paths_nonempty():
    permissions = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
                    "UserIdGroupPairs": []}]
    base = _incident_with_collected_web(build_incident_base(), _collect_raw_web_sg(permissions))
    twin_permissions = copy.deepcopy(permissions)
    twin_permissions[0]["IpRanges"] = []
    twin_permissions[0]["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
    twin = _incident_with_collected_web(build_incident_base(), _collect_raw_web_sg(twin_permissions))
    assert _normalized_attack_paths(base)
    assert _normalized_attack_paths(base) == _normalized_attack_paths(twin)
