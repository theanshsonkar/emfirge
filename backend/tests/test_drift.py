"""
Tests for drift_service.py — compare_findings logic.
Zero AWS/LLM calls.
"""
import pytest
from app.drift_service import compare_findings


def make_finding(rule_id, resource_id, severity="Critical"):
    return {
        "rule_id": rule_id,
        "resource_id": resource_id,
        "severity": severity,
        "issue": f"Issue for {rule_id}",
    }


class TestCompareFindings:
    def test_new_finding_detected(self):
        current = [make_finding("EMFIRGE-EC2-002", "sg-001")]
        previous = []
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 1
        assert new_f[0]["rule_id"] == "EMFIRGE-EC2-002"
        assert fixed_f == []
        assert sev_changed == []

    def test_fixed_finding_detected(self):
        current = []
        previous = [make_finding("EMFIRGE-EC2-002", "sg-001")]
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert new_f == []
        assert len(fixed_f) == 1
        assert fixed_f[0]["rule_id"] == "EMFIRGE-EC2-002"
        assert sev_changed == []

    def test_unchanged_finding_not_in_either(self):
        finding = make_finding("EMFIRGE-S3-001", "my-bucket")
        new_f, fixed_f, sev_changed = compare_findings([finding], [finding])
        assert new_f == []
        assert fixed_f == []
        assert sev_changed == []

    def test_multiple_new_and_fixed(self):
        current = [
            make_finding("EMFIRGE-EC2-002", "sg-001"),
            make_finding("EMFIRGE-IAM-001", "root-account"),
        ]
        previous = [
            make_finding("EMFIRGE-S3-001", "my-bucket"),
            make_finding("EMFIRGE-IAM-001", "root-account"),
        ]
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 1
        assert new_f[0]["rule_id"] == "EMFIRGE-EC2-002"
        assert len(fixed_f) == 1
        assert fixed_f[0]["rule_id"] == "EMFIRGE-S3-001"
        assert sev_changed == []

    def test_empty_both_returns_empty(self):
        new_f, fixed_f, sev_changed = compare_findings([], [])
        assert new_f == []
        assert fixed_f == []
        assert sev_changed == []

    def test_same_rule_different_resource_treated_as_new(self):
        """Same rule_id but different resource_id = different finding."""
        current = [make_finding("EMFIRGE-EC2-002", "sg-002")]
        previous = [make_finding("EMFIRGE-EC2-002", "sg-001")]
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 1
        assert new_f[0]["resource_id"] == "sg-002"
        assert len(fixed_f) == 1
        assert fixed_f[0]["resource_id"] == "sg-001"

    def test_key_is_rule_id_plus_resource_id(self):
        """Findings are keyed by rule_id::resource_id — both must match."""
        f1 = make_finding("EMFIRGE-EC2-002", "sg-001")
        f2 = make_finding("EMFIRGE-EC2-003", "sg-001")  # same resource, different rule
        new_f, fixed_f, sev_changed = compare_findings([f1], [f2])
        assert len(new_f) == 1
        assert len(fixed_f) == 1

    def test_none_rule_id_handled(self):
        """Findings with None rule_id should not crash."""
        current = [{"rule_id": None, "resource_id": "sg-001", "severity": "Critical", "issue": "test"}]
        previous = []
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 1

    def test_none_resource_id_handled(self):
        current = [{"rule_id": "EMFIRGE-EC2-002", "resource_id": None, "severity": "Critical", "issue": "test"}]
        previous = []
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 1

    def test_large_scan_diff(self):
        """Performance sanity — 100 findings each side."""
        current = [make_finding(f"RULE-{i}", f"resource-{i}") for i in range(100)]
        previous = [make_finding(f"RULE-{i}", f"resource-{i}") for i in range(50, 150)]
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert len(new_f) == 50   # 0-49 are new
        assert len(fixed_f) == 50  # 100-149 are fixed

    def test_severity_change_detected(self):
        """Same finding with different severity = severity_changed event."""
        current = [make_finding("EMFIRGE-EC2-002", "sg-001", severity="Low")]
        previous = [make_finding("EMFIRGE-EC2-002", "sg-001", severity="Critical")]
        new_f, fixed_f, sev_changed = compare_findings(current, previous)
        assert new_f == []
        assert fixed_f == []
        assert len(sev_changed) == 1
        assert sev_changed[0]["severity"] == "Low"
        assert sev_changed[0]["previous_severity"] == "Critical"
        assert sev_changed[0]["change_reason"] == "graph_context"

    def test_severity_unchanged_not_in_changed(self):
        """Same severity = not in severity_changed."""
        finding = make_finding("EMFIRGE-EC2-002", "sg-001", severity="Critical")
        new_f, fixed_f, sev_changed = compare_findings([finding], [finding])
        assert sev_changed == []
