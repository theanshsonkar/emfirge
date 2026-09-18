


def test_trivy_high_reachable_blocks_when_checkov_unavailable(monkeypatch, infra):
    patch_diff(monkeypatch, newly_internet_reachable=["bucket"])
    checkov = Mock(side_effect=[
        {"available": False, "findings": []},
        {"available": False, "findings": []},
    ])
    trivy = Mock(side_effect=[
        {"available": True, "findings": []},
        {"available": True, "findings": [{
            "source": "trivy", "check_id": "AVD-AWS-0001", "resource": "bucket",
            "severity": "HIGH", "title": "Public bucket", "guideline": "https://example.test",
        }]},
    ])
    monkeypatch.setattr("app.verdict.run_checkov", checkov)
    monkeypatch.setattr("app.verdict.run_trivy", trivy)

    result = combined_verdict(infra, infra)

    assert result.verdict == "block"
    assert result.scanner_available is True
    assert result.scanner_added == [{
        "source": "trivy", "check_id": "AVD-AWS-0001", "resource": "bucket",
        "severity": "high", "title": "Public bucket", "guideline": "https://example.test",
    }]
    assert checkov.call_count == trivy.call_count == 2


def test_same_scanner_identity_keeps_both_sources(monkeypatch, infra):
    patch_diff(monkeypatch)
    checkov = Mock(side_effect=[
        {"available": True, "findings": []},
        {"available": True, "findings": [{
            "check_id": "SHARED-001", "resource": "bucket", "severity": "HIGH", "title": "Checkov title",
        }]},
    ])
    trivy = Mock(side_effect=[
        {"available": True, "findings": []},
        {"available": True, "findings": [{
            "source": "trivy", "check_id": "SHARED-001", "resource": "bucket", "severity": "HIGH", "title": "Trivy title",
        }]},
    ])
    monkeypatch.setattr("app.verdict.run_checkov", checkov)
    monkeypatch.setattr("app.verdict.run_trivy", trivy)

    result = combined_verdict(infra, infra)

    assert {(item["source"], item["check_id"], item["resource"]) for item in result.scanner_added} == {
        ("checkov", "SHARED-001", "bucket"),
        ("trivy", "SHARED-001", "bucket"),
    }


def test_scanner_results_are_fully_serialized_deterministically(monkeypatch, infra):
    patch_diff(monkeypatch, newly_internet_reachable=["bucket"])
    checkov = Mock()
    trivy = Mock()
    monkeypatch.setattr("app.verdict.run_checkov", checkov)
    monkeypatch.setattr("app.verdict.run_trivy", trivy)

    def set_scan_results():
        checkov.side_effect = [
            {"available": True, "findings": []},
            {"available": True, "findings": [{
                "check_id": "C-2", "resource": "bucket", "severity": "HIGH", "title": "Public bucket",
            }]},
        ]
        trivy.side_effect = [
            {"available": True, "findings": []},
            {"available": True, "findings": [{
                "source": "trivy", "check_id": "T-1", "resource": "other", "severity": "LOW", "title": "Logging",
            }]},
        ]

    set_scan_results()
    first = combined_verdict(infra, infra)
    set_scan_results()
    second = combined_verdict(infra, infra)

    assert first.model_dump() == second.model_dump()
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.diffing import DiffResult
from app.models import AWSInfrastructure, EC2Data, ElasticIP, VPCData, VPCSubnet
from app.verdict import combined_verdict


@pytest.fixture
def infra():
    return AWSInfrastructure(region="us-east-1")


def patch_diff(monkeypatch, **kwargs):
    monkeypatch.setattr("app.verdict.diff_infrastructure", lambda base, branch: DiffResult(**kwargs))


def patch_non_checkov_scanners_unavailable(monkeypatch):
    """Stub trivy AND cloudsplaining as unavailable.

    Both must be stubbed explicitly. This helper previously patched only
    trivy, which left run_cloudsplaining pointing at the real scanner -- so
    every test using it silently depended on cloudsplaining NOT being
    installed in the test environment. The moment it became a declared
    dependency (it is imported in-process by scanners.py) those tests
    started seeing 2/3 scanners run instead of 1/3 and failed. A test's
    scanner coverage must come from what it stubs, never from what happens
    to be on the machine.
    """
    unavailable = Mock(return_value={"available": False, "findings": []})
    monkeypatch.setattr("app.verdict.run_trivy", unavailable)
    monkeypatch.setattr("app.verdict.run_cloudsplaining", unavailable)


def test_native_critical_reachable_blocks(monkeypatch, infra):
    patch_diff(
        monkeypatch,
        added_findings=[{"rule_id": "open_ssh", "resource_id": "i-1", "severity": "Critical"}],
        newly_internet_reachable=["i-1"],
    )
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "block"
    assert result.native_added[0]["source"] == "native"
    assert result.native_added[0]["severity"] == "critical"


def test_moderate_nonreachable_warns(monkeypatch, infra):
    patch_diff(monkeypatch, added_findings=[{"rule_id": "weak", "resource_id": "r-1", "severity": "Moderate"}])
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "warn"
    assert result.native_added[0]["severity"] == "medium"


def test_no_new_risk_is_pass_and_keeps_scores(monkeypatch, infra):
    patch_diff(monkeypatch, score_before=80, score_after=95, score_delta=15)
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "pass"
    assert (result.score_before, result.score_after, result.score_delta) == (80, 95, 15)
    assert result.scanner_available is False
    assert result.scanner_added == result.scanner_removed == []
    assert "DEGRADED" not in result.summary
    # run_scanners=False is a deliberate caller choice, not a silent failure,
    # so it must not raise a coverage warning.
    assert result.coverage_warnings == []


def test_scanner_unavailable_keeps_native_only(monkeypatch, infra):
    patch_diff(monkeypatch, added_findings=[{"rule_id": "native", "resource_id": "r", "severity": "LOW"}])
    patch_non_checkov_scanners_unavailable(monkeypatch)
    scanner = Mock(side_effect=RuntimeError("missing checkov"))
    monkeypatch.setattr("app.verdict.run_checkov", scanner)
    result = combined_verdict(infra, infra)
    assert result.scanner_available is False
    assert result.scanner_added == result.scanner_removed == []
    # Degradation must be stated loudly, not as a trailing parenthetical: a
    # verdict computed without the borrowed scanners previously read the same
    # as a fully-covered one.
    assert "DEGRADED" in result.summary
    assert result.coverage_warnings, "a missing scanner must produce a coverage warning"
    assert "NOT full coverage" in result.coverage_warnings[0]
    assert scanner.call_count == 2


def test_scanner_status_names_each_scanner_and_its_reason(monkeypatch, infra):
    """The reason a scanner did not run must survive, not be swallowed."""
    patch_diff(monkeypatch)
    patch_non_checkov_scanners_unavailable(monkeypatch)
    monkeypatch.setattr(
        "app.verdict.run_checkov",
        Mock(side_effect=FileNotFoundError("checkov")),
    )
    result = combined_verdict(infra, infra)

    # Every scanner is accounted for by name -- a scanner missing from this map
    # is a scanner nobody can tell ran or not.
    assert set(result.scanner_status) == {"checkov", "trivy", "cloudsplaining"}
    assert result.scanner_status["checkov"].startswith("unavailable")
    assert "FileNotFoundError" in result.scanner_status["checkov"], (
        "the real failure reason must be preserved, not collapsed to 'unknown'"
    )


def test_partial_coverage_still_warns(monkeypatch, infra):
    """One scanner running is NOT full coverage, even though scanner_available is True."""
    patch_diff(monkeypatch)
    patch_non_checkov_scanners_unavailable(monkeypatch)
    monkeypatch.setattr(
        "app.verdict.run_checkov",
        Mock(side_effect=[{"available": True, "findings": []}, {"available": True, "findings": []}]),
    )
    result = combined_verdict(infra, infra)

    assert result.scanner_available is True, "checkov ran"
    assert result.scanner_status["checkov"] == "ok"
    assert result.coverage_warnings, (
        "scanner_available=True must not imply full coverage -- trivy and "
        "cloudsplaining did not run and the caller has to be told"
    )
    assert "1/3" in result.coverage_warnings[0]


def test_scanner_high_reachable_blocks(monkeypatch, infra):
    patch_diff(monkeypatch, newly_internet_reachable=["bucket"])
    patch_non_checkov_scanners_unavailable(monkeypatch)
    scans = [
        {"available": True, "findings": []},
        {"available": True, "findings": [{"check_id": "CKV_AWS_1", "resource": "bucket", "severity": "HIGH", "title": "Public bucket"}]},
    ]
    scanner = Mock(side_effect=scans)
    monkeypatch.setattr("app.verdict.run_checkov", scanner)
    result = combined_verdict(infra, infra)
    assert result.verdict == "block"
    assert result.scanner_available is True
    assert result.scanner_added[0]["source"] == "checkov"
    assert result.scanner_added[0]["severity"] == "high"
    assert scanner.call_count == 2


def test_scanner_dict_and_list_deltas_are_identity_based(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_non_checkov_scanners_unavailable(monkeypatch)
    scans = [
        {"available": True, "findings": [{"check_id": "A", "resource": "same", "severity": "LOW", "title": "old"}, {"check_id": "R", "resource": "gone", "severity": "HIGH", "title": "gone"}]},
        [{"check_id": "A", "resource": "same", "severity": "CRITICAL", "title": "new"}, {"check_id": "N", "resource": "new", "severity": "UNKNOWN", "title": "new"}],
    ]
    monkeypatch.setattr("app.verdict.run_checkov", Mock(side_effect=scans))
    result = combined_verdict(infra, infra)
    assert [(x["check_id"], x["severity"]) for x in result.scanner_added] == [("N", "low")]
    assert [(x["check_id"], x["severity"]) for x in result.scanner_removed] == [("R", "high")]


def test_duplicate_scanner_identity_uses_deterministic_representative(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_non_checkov_scanners_unavailable(monkeypatch)
    scans = [
        {"available": True, "findings": []},
        {"available": True, "findings": [
            {"check_id": "A", "resource": "r", "severity": "LOW", "title": "z"},
            {"check_id": "A", "resource": "r", "severity": "HIGH", "title": "a"},
        ]},
    ]
    monkeypatch.setattr("app.verdict.run_checkov", Mock(side_effect=scans))
    result = combined_verdict(infra, infra)
    assert result.scanner_added[0]["title"] == "a"
    assert result.scanner_added[0]["severity"] == "high"


def test_privilege_escalation_text_blocks_high_without_reachability(monkeypatch, infra):
    patch_diff(monkeypatch, added_findings=[{"rule_id": "iam:PassRole", "resource_id": "role", "severity": "HIGH"}])
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "block"


def test_results_are_deterministic(monkeypatch, infra):
    patch_diff(monkeypatch, added_findings=[
        {"rule_id": "b", "resource_id": "2", "severity": "low"},
        {"rule_id": "a", "resource_id": "1", "severity": "critical"},
    ], newly_internet_reachable=["2", "1"])
    first = combined_verdict(infra, infra, run_scanners=False)
    second = combined_verdict(infra, infra, run_scanners=False)
    assert first == second
    assert first.newly_internet_reachable == ["1", "2"]


def patch_cost_and_graph(monkeypatch, base_graph=None, branch_graph=None, reachable=(), monthly=0.0, notes=()):
    monkeypatch.setattr(
        "app.verdict.cost.cost_delta",
        Mock(return_value=SimpleNamespace(monthly_delta_usd=monthly, unknown_notes=list(notes))),
    )
    monkeypatch.setattr(
        "app.verdict.build_graph",
        Mock(side_effect=[base_graph or {"nodes": []}, branch_graph or {"nodes": []}]),
    )
    monkeypatch.setattr("app.verdict.get_internet_reachable_set", Mock(return_value=set(reachable)))


def role_graph(escalating=False):
    return {"nodes": [{
        "id": "iam-role-app",
        "type": "iam_role",
        "base": {"has_privilege_escalation": escalating},
    }]}


def test_priced_ec2_cost_increase_does_not_change_pass(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, monthly=7.59)
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "pass"
    assert result.cost_delta_monthly_usd == 7.59
    assert "cost_delta=7.59" in result.summary


def test_s3_cost_delta_is_zero_but_reports_unknown_notes(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, notes=("branch: s3_bucket/data: usage unknown",))
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "pass"
    assert result.cost_delta_monthly_usd == 0.0
    assert result.cost_unknown_notes == ["branch: s3_bucket/data: usage unknown"]
    assert "cost unknown" in result.summary


def test_newly_escalating_unreachable_role_warns(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, branch_graph=role_graph(True))
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "warn"
    assert result.introduces_privilege_escalation is True


def test_newly_escalating_reachable_role_blocks(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, branch_graph=role_graph(True), reachable=("iam-role-app",))
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "block"
    assert result.introduces_privilege_escalation is True


def test_existing_escalating_role_is_not_introduced(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, base_graph=role_graph(True), branch_graph=role_graph(True), reachable=("iam-role-app",))
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "pass"
    assert result.introduces_privilege_escalation is False


def test_cost_and_graph_results_are_deterministic(monkeypatch, infra):
    patch_diff(monkeypatch)
    patch_cost_and_graph(monkeypatch, branch_graph=role_graph(True), monthly=12.34, notes=("z", "a"))
    first = combined_verdict(infra, infra, run_scanners=False)
    monkeypatch.setattr("app.verdict.cost.cost_delta", Mock(return_value=SimpleNamespace(monthly_delta_usd=12.34, unknown_notes=["z", "a"])))
    monkeypatch.setattr("app.verdict.build_graph", Mock(side_effect=[role_graph(False), role_graph(True)]))
    second = combined_verdict(infra, infra, run_scanners=False)
    assert first == second


def test_sixth_eip_limit_is_serialized_and_warns(monkeypatch, infra):
    patch_diff(monkeypatch)
    branch = AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(elastic_ips=[
            ElasticIP(allocation_id=f"eip-{i}", public_ip=f"192.0.2.{i}", is_attached=False)
            for i in range(6)
        ]),
    )
    result = combined_verdict(infra, branch, run_scanners=False)
    assert result.verdict == "warn"
    assert len(result.limits_introduced) == 1
    finding = result.limits_introduced[0]
    assert set(finding) == {"check", "scope", "current", "limit", "status", "basis"}
    assert finding == {
        "check": "eips_per_region",
        "scope": "region",
        "current": 6,
        "limit": 5,
        "status": "exceeded",
        "basis": "AWS DEFAULTS, region-general, as of 2026-09-15; EIP count compared with the regional default quota",
    }
    assert "capacity_breaches=eips_per_region/region" in result.summary


def test_subnet_ip_capacity_limit_is_serialized_and_warns(monkeypatch, infra):
    patch_diff(monkeypatch)
    base = AWSInfrastructure(vpc=VPCData(subnets=[VPCSubnet(
        id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/28", resources=["resource-0"],
    )]))
    branch = AWSInfrastructure(vpc=VPCData(subnets=[VPCSubnet(
        id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/28",
        resources=[f"resource-{i}" for i in range(11)],
    )]))
    result = combined_verdict(base, branch, run_scanners=False)
    finding = next(item for item in result.limits_introduced if item["check"] == "subnet_ip_capacity")
    assert result.verdict == "warn"
    assert set(finding) == {"check", "scope", "current", "limit", "status", "basis"}
    assert finding == {
        "check": "subnet_ip_capacity",
        "scope": "subnet-1",
        "current": 11,
        "limit": 11,
        "status": "exceeded",
        "basis": (
            "AWS DEFAULTS, region-general, as of 2026-09-15; IPv4 subnet capacity uses AWS's 5 reserved addresses; "
            "current is observed unique subnet resources and concrete instances/functions"
        ),
    }


def test_no_limit_transition_is_empty_and_keeps_pass(monkeypatch, infra):
    patch_diff(monkeypatch)
    result = combined_verdict(infra, infra, run_scanners=False)
    assert result.verdict == "pass"
    assert result.limits_introduced == []
    assert result.limits_resolved == []


def test_exceeded_limit_never_turns_existing_block_into_different_verdict(monkeypatch, infra):
    patch_diff(
        monkeypatch,
        added_findings=[{"rule_id": "open_ssh", "resource_id": "i-1", "severity": "HIGH"}],
        newly_internet_reachable=["i-1"],
    )
    branch = AWSInfrastructure(ec2=EC2Data(elastic_ips=[
        ElasticIP(allocation_id=f"eip-{i}", public_ip=f"192.0.2.{i}", is_attached=False)
        for i in range(6)
    ]))
    result = combined_verdict(infra, branch, run_scanners=False)
    assert result.verdict == "block"
    assert any(item["status"] == "exceeded" for item in result.limits_introduced)


def test_limit_results_and_serialization_are_repeatedly_deterministic(monkeypatch, infra):
    patch_diff(monkeypatch)
    base = AWSInfrastructure(vpc=VPCData(subnets=[VPCSubnet(
        id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/28",
    )]))
    branch = AWSInfrastructure(
        ec2=EC2Data(elastic_ips=[
            ElasticIP(allocation_id=f"eip-{i}", public_ip=f"192.0.2.{i}", is_attached=False)
            for i in range(6)
        ]),
        vpc=VPCData(subnets=[VPCSubnet(
            id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/28",
            resources=[f"resource-{i}" for i in range(11)],
        )]),
    )
    first = combined_verdict(base, branch, run_scanners=False)
    second = combined_verdict(base, branch, run_scanners=False)
    assert {item["check"] for item in first.limits_introduced} == {
        "eips_per_region", "subnet_ip_capacity",
    }
    assert first.model_dump() == second.model_dump()



def _mock_cloudsplaining_verdict_scanners(monkeypatch):
    role = "arn:aws:iam::123456789012:role/CloudRole"
    unavailable = Mock(return_value={"available": False, "findings": []})
    cloudsplaining = Mock(side_effect=[
        {"available": True, "findings": []},
        {"available": True, "findings": [{
            "source": "cloudsplaining",
            "check_id": "PrivilegeEscalation",
            "resource": role,
            "severity": "HIGH",
            "title": "Cloudsplaining detected PrivilegeEscalation risk",
        }]},
    ])
    monkeypatch.setattr("app.verdict.run_checkov", unavailable)
    monkeypatch.setattr("app.verdict.run_trivy", unavailable)
    monkeypatch.setattr("app.verdict.run_cloudsplaining", cloudsplaining)
    return role, unavailable, cloudsplaining


def test_cloudsplaining_high_finding_on_newly_reachable_role_blocks(monkeypatch, infra):
    role, checkov_trivy, cloudsplaining = _mock_cloudsplaining_verdict_scanners(monkeypatch)
    patch_diff(monkeypatch, newly_internet_reachable=[role])

    result = combined_verdict(infra, infra)

    assert result.scanner_added == [{
        "source": "cloudsplaining",
        "check_id": "PrivilegeEscalation",
        "resource": role,
        "severity": "high",
        "title": "Cloudsplaining detected PrivilegeEscalation risk",
        "guideline": None,
    }]
    assert result.scanner_available is True
    assert result.verdict == "block"
    assert checkov_trivy.call_count == 4
    assert cloudsplaining.call_count == 2


def test_cloudsplaining_verdict_serialization_is_deterministic(monkeypatch, infra):
    role, checkov_trivy, cloudsplaining = _mock_cloudsplaining_verdict_scanners(monkeypatch)
    patch_diff(monkeypatch, newly_internet_reachable=[role])
    first = combined_verdict(infra, infra).model_dump()

    checkov_trivy.reset_mock()
    cloudsplaining.reset_mock()
    cloudsplaining.side_effect = [
        {"available": True, "findings": []},
        {"available": True, "findings": [{
            "source": "cloudsplaining",
            "check_id": "PrivilegeEscalation",
            "resource": role,
            "severity": "HIGH",
            "title": "Cloudsplaining detected PrivilegeEscalation risk",
        }]},
    ]
    second = combined_verdict(infra, infra).model_dump()

    assert first == second
