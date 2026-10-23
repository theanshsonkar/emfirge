"""
Tests for the compliance evaluation engine and API endpoint.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.compliance import evaluate_framework, evaluate_all_frameworks

client = TestClient(app)


# ── UNIT TESTS: compliance.py ─────────────────────────────────────

class TestEvaluateFramework:
    """Test the pure evaluation logic (no DB, no API)."""

    def test_cis_nothing_fails_when_no_rules_fired(self):
        """If no rules fired, nothing fails and uncovered requirements are not passes."""
        result = evaluate_framework("cis-aws-1.5", set(), infrastructure=None)
        assert result["id"] == "cis-aws-1.5"
        assert result["name"] == "CIS AWS Foundations Benchmark"
        assert result["version"] == "1.5"
        assert result["totalControls"] == 63
        assert result["failedControls"] == 0
        assert result["passedControls"] + result["partialControls"] < 63
        assert result["notEvaluatedControls"] > 0

    def test_cis_fails_when_rules_fire(self):
        """Controls should fail when their mapped rule_id is in fired set."""
        fired = {"EMFIRGE-IAM-001", "EMFIRGE-EC2-002", "EMFIRGE-S3-001"}
        result = evaluate_framework("cis-aws-1.5", fired, infrastructure=None)
        assert result["failedControls"] == 3

        # Verify specific controls failed (Prowler's CIS 1.5 numbering)
        controls_by_id = {c["id"]: c for c in result["controls"]}
        assert controls_by_id["1.4"]["status"] == "fail"  # IAM-001 = root access key
        assert controls_by_id["5.2"]["status"] == "fail"  # EC2-002 = SSH open (SG)
        assert controls_by_id["5.3"]["status"] == "fail"  # EC2-002 = SSH open (SG, ::/0 requirement shares the check)

    def test_cis_not_applicable_when_no_resources(self):
        """Controls should be N/A when the service has no resources."""
        infra = {
            "ec2": {"instance_count": 0, "security_groups": []},
            "s3": {"total_buckets": 0},
            "rds": {"instances": []},
            "lambda_data": {"function_count": 0},
            "ecs": {"total_task_definitions": 0},
            "vpc": {"total_vpcs": 2},
            "kms": {"total_cmks": 0},
            "waf": {"total_albs": 0},
        }
        result = evaluate_framework("cis-aws-1.5", set(), infrastructure=infra)

        controls_by_id = {c["id"]: c for c in result["controls"]}
        # RDS public access (fully covered by an RDS rule) is N/A with no RDS
        assert controls_by_id["2.3.3"]["status"] == "not_applicable"
        # KMS rotation N/A with no CMKs
        assert controls_by_id["3.8"]["status"] == "not_applicable"
        # S3 encryption-at-rest N/A with no buckets
        assert controls_by_id["2.1.1"]["status"] == "not_applicable"
        # VPC flow logs applies (2 VPCs), so it passes
        assert controls_by_id["3.9"]["status"] == "pass"
        # A requirement Emfirge does not evaluate stays not_evaluated, never N/A or pass
        assert controls_by_id["1.1"]["status"] == "not_evaluated"

        assert result["naControls"] == 3

    def test_soc2_evaluation(self):
        """SOC 2 framework evaluates correctly."""
        fired = {"EMFIRGE-IAM-003", "EMFIRGE-CT-001"}
        result = evaluate_framework("soc2", fired, infrastructure=None)
        assert result["id"] == "soc2"
        assert result["totalControls"] == 27
        assert result["failedControls"] == 4

        controls_by_id = {c["label"]: c for c in result["controls"]}
        # CT-001 maps to cloudtrail_multi_region_enabled, listed in CC2.1, CC7.2, A1.2, PI1.3 (IAM-003 has no mapping)
        for label in ("CC2.1", "CC7.2", "A1.2", "PI1.3"):
            assert controls_by_id[label]["status"] == "fail"
        assert controls_by_id["CC6.1"]["status"] != "fail"

    def test_soc2_unmapped_control_is_not_a_pass(self):
        """Controls with no mapped rule are not_evaluated, never pass."""
        result = evaluate_framework("soc2", set(), infrastructure=None)
        controls_by_id = {c["label"]: c for c in result["controls"]}
        # CC6.7 (in-transit encryption checks) and CC7.5 have no Emfirge rule
        assert controls_by_id["CC6.7"]["status"] == "not_evaluated"
        assert controls_by_id["CC7.5"]["status"] == "not_evaluated"

    def test_unknown_framework_returns_error(self):
        """Unknown framework ID returns error dict."""
        result = evaluate_framework("pci-dss", set())
        assert "error" in result

    def test_evaluate_all_frameworks(self):
        """evaluate_all_frameworks returns both CIS and SOC2."""
        results = evaluate_all_frameworks({"EMFIRGE-IAM-001"})
        assert len(results) == 2
        assert results[0]["id"] == "cis-aws-1.5"
        assert results[1]["id"] == "soc2"

    def test_descriptions_match_status(self):
        """Pass controls get pass description, fail controls get fail description."""
        fired = {"EMFIRGE-EC2-002"}
        result = evaluate_framework("cis-aws-1.5", fired)
        controls_by_id = {c["id"]: c for c in result["controls"]}

        # 5.2 should fail and name the rule that fired
        assert controls_by_id["5.2"]["status"] == "fail"
        assert "EMFIRGE-EC2-002" in controls_by_id["5.2"]["description"]

        # 3.9 (VPC flow logs) is fully covered and nothing fired, so it passes
        assert controls_by_id["3.9"]["status"] == "pass"
        assert "none fired" in controls_by_id["3.9"]["description"]

    def test_counts_add_up(self):
        """passed + failed + na should equal total."""
        fired = {"EMFIRGE-IAM-001", "EMFIRGE-S3-001"}
        infra = {
            "ec2": {"instance_count": 0},
            "s3": {"total_buckets": 3},
            "rds": {"instances": []},
            "lambda_data": {"function_count": 0},
            "ecs": {"total_task_definitions": 0},
            "vpc": {"total_vpcs": 1},
            "kms": {"total_cmks": 0},
            "waf": {"total_albs": 0},
        }
        result = evaluate_framework("cis-aws-1.5", fired, infrastructure=infra)
        assert (result["passedControls"] + result["failedControls"] + result["naControls"]
                + result["partialControls"] + result["notEvaluatedControls"]) == result["totalControls"]


# ── API ENDPOINT TESTS ────────────────────────────────────────────

class TestComplianceEndpoint:
    """Test the GET /compliance/{analysis_id} route."""

    def _make_findings_json(self, fired_rules=None, include_infra=True):
        """Helper to build a realistic findings_json blob."""
        findings = {
            "analysis_id": "test-uuid-123",
            "timestamp": "2024-01-01T00:00:00",
            "region_analyzed": "us-east-1",
            "critical_risks": [],
            "moderate_risks": [],
            "best_practices": [],
            "cost_findings": [],
        }
        if fired_rules:
            for rule_id in fired_rules:
                findings["critical_risks"].append({
                    "rule_id": rule_id,
                    "category": "Security",
                    "severity": "Critical",
                    "issue": f"Test issue for {rule_id}",
                    "recommendation": "Fix it",
                    "aws_service": "test",
                })
        if include_infra:
            findings["infrastructure"] = {
                "ec2": {"instance_count": 2, "security_groups": []},
                "s3": {"total_buckets": 3},
                "rds": {"instances": ["db-1"]},
                "lambda_data": {"function_count": 1},
                "ecs": {"total_task_definitions": 0},
                "vpc": {"total_vpcs": 2},
                "kms": {"total_cmks": 1},
                "waf": {"total_albs": 1},
            }
        return json.dumps(findings)

    def test_compliance_endpoint_success(self):
        """Endpoint returns compliance data for a valid analysis_id."""
        mock_log = MagicMock()
        mock_log.findings_json = self._make_findings_json(
            fired_rules=["EMFIRGE-IAM-001", "EMFIRGE-EC2-002"]
        )

        with patch("app.database.SessionLocal") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = mock_log

            resp = client.get("/compliance/test-uuid-123")
            assert resp.status_code == 200
            data = resp.json()

            assert data["analysis_id"] == "test-uuid-123"
            assert "frameworks" in data
            assert len(data["frameworks"]) == 2
            assert "fired_rule_ids" in data

            # CIS framework
            cis = data["frameworks"][0]
            assert cis["id"] == "cis-aws-1.5"
            assert cis["failedControls"] == 3  # IAM-001 -> 1.4; EC2-002 -> 5.2 and 5.3

            # SOC2 framework
            soc2 = data["frameworks"][1]
            assert soc2["id"] == "soc2"
            assert soc2["failedControls"] == 2  # EC2-002 (SSH) is a check of CC6.6 and CC7.2

    def test_compliance_endpoint_not_found(self):
        """Returns 404 when analysis_id doesn't exist."""
        with patch("app.database.SessionLocal") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = None

            resp = client.get("/compliance/nonexistent-id")
            assert resp.status_code == 404

    def test_compliance_endpoint_invalid_id(self):
        """Returns 400 for invalid analysis_id format."""
        resp = client.get("/compliance/'; DROP TABLE--")
        assert resp.status_code == 400

    def test_compliance_endpoint_no_findings(self):
        """All controls pass when scan has zero findings."""
        mock_log = MagicMock()
        mock_log.findings_json = self._make_findings_json(fired_rules=[])

        with patch("app.database.SessionLocal") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = mock_log

            resp = client.get("/compliance/test-uuid-123")
            assert resp.status_code == 200
            data = resp.json()

            cis = data["frameworks"][0]
            assert cis["failedControls"] == 0

    def test_compliance_endpoint_na_detection(self):
        """Controls are N/A when service has no resources."""
        mock_log = MagicMock()
        findings = {
            "analysis_id": "test-uuid-123",
            "timestamp": "2024-01-01T00:00:00",
            "critical_risks": [],
            "moderate_risks": [],
            "best_practices": [],
            "cost_findings": [],
            "infrastructure": {
                "ec2": {"instance_count": 0},
                "s3": {"total_buckets": 0},
                "rds": {"instances": []},
                "lambda_data": {"function_count": 0},
                "ecs": {"total_task_definitions": 0},
                "vpc": {"total_vpcs": 1},
                "kms": {"total_cmks": 0},
                "waf": {"total_albs": 0},
            },
        }
        mock_log.findings_json = json.dumps(findings)

        with patch("app.database.SessionLocal") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.query.return_value.filter.return_value.order_by.return_value.first.return_value = mock_log

            resp = client.get("/compliance/test-uuid-123")
            assert resp.status_code == 200
            data = resp.json()

            cis = data["frameworks"][0]
            assert cis["naControls"] > 0  # Should have N/A controls
