"""
Tests for FastAPI routes — uses TestClient, mocks AWS + LLM calls.
Zero real AWS calls, zero LLM calls.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# -- HEALTH / STATUS -----------------------------------------------

class TestHealthRoutes:
    def test_root_returns_ok(self):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "2.0"

    def test_health_returns_healthy(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# -- LOGS / HISTORY ------------------------------------------------

class TestLogsRoutes:
    def test_logs_returns_list(self):
        with patch("app.main.get_recent_logs", return_value=[]):
            resp = client.get("/logs")
            assert resp.status_code == 200
            assert "logs" in resp.json()
            assert "count" in resp.json()

    def test_history_returns_scans(self):
        with patch("app.main.get_recent_logs", return_value=[]):
            resp = client.get("/history")
            assert resp.status_code == 200
            data = resp.json()
            assert "scans" in data
            assert "count" in data

    def test_history_limit_param(self):
        with patch("app.main.get_recent_logs", return_value=[]) as mock_logs:
            resp = client.get("/history?limit=5")
            assert resp.status_code == 200
            mock_logs.assert_called_once_with(limit=5, account_id=None)

    def test_get_log_by_id_not_found(self):
        with patch("app.main.get_log_by_id", return_value={}):
            resp = client.get("/logs/99999")
            assert resp.status_code == 404

    def test_get_log_by_id_found(self):
        fake_log = {"id": 1, "risk_score": 75, "region_analyzed": "us-east-1"}
        with patch("app.main.get_log_by_id", return_value=fake_log):
            resp = client.get("/logs/1")
            assert resp.status_code == 200
            assert resp.json()["id"] == 1

    def test_history_with_account_id(self):
        with patch("app.main.get_recent_logs", return_value=[]) as mock_logs:
            resp = client.get("/history?limit=10&account_id=123456789012")
            assert resp.status_code == 200
            mock_logs.assert_called_once_with(limit=10, account_id="123456789012")

    def test_logs_with_account_id(self):
        with patch("app.main.get_recent_logs", return_value=[]) as mock_logs:
            resp = client.get("/logs?account_id=123456789012")
            assert resp.status_code == 200
            mock_logs.assert_called_once_with(limit=20, account_id="123456789012")

    def test_get_log_by_id_with_account_id(self):
        fake_log = {"id": 1, "risk_score": 75, "region_analyzed": "us-east-1"}
        with patch("app.main.get_log_by_id", return_value=fake_log):
            resp = client.get("/logs/1?account_id=123456789012")
            assert resp.status_code == 200

    def test_drift_events_returns_list(self):
        with patch("app.main.get_drift_events", return_value=[]):
            resp = client.get("/drift/events")
            assert resp.status_code == 200
            data = resp.json()
            assert "events" in data
            assert "count" in data


# -- GITHUB ROUTES -------------------------------------------------

class TestGitHubRoutes:
    def test_install_url_returns_url(self):
        resp = client.get("/github/install-url")
        assert resp.status_code == 200
        assert "url" in resp.json()

    def test_github_repos_returns_empty_on_error(self):
        """When GitHub auth fails, should return empty list not 500."""
        with patch("app.github_service._get_private_key", side_effect=Exception("no key")):
            resp = client.get("/github/repos?installation_id=123")
            assert resp.status_code == 200
            assert resp.json()["repos"] == []

    def test_github_webhook_invalid_signature(self):
        # Need a secret configured for signature validation to actually run
        with patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": "test-secret"}):
            resp = client.post(
                "/github/webhook",
                content=b'{"action": "opened"}',
                headers={"X-Hub-Signature-256": "sha256=invalidsig", "Content-Type": "application/json"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "invalid signature"

    def test_github_webhook_no_secret_accepts_all(self):
        """When no webhook secret configured, all payloads accepted."""
        with patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": ""}):
            resp = client.post(
                "/github/webhook",
                content=b'{"action": "opened"}',
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"


# -- REMEDIATION INSIGHT -------------------------------------------

class TestRemediationInsight:
    def test_insight_returns_200_with_gemini_mocked(self):
        mock_response = MagicMock()
        mock_response.text = '{"what_this_fixes": "Closes SSH", "why_it_matters": "Prevents brute force"}'

        with patch("app.main._check_insight_rate_limit"):
            with patch("google.genai.Client") as mock_client:
                mock_client.return_value.models.generate_content.return_value = mock_response
                resp = client.post("/remediation/generate-insight", json={
                    "severity": "Critical",
                    "issue": "SSH open to internet",
                    "recommendation": "Restrict SSH",
                    "aws_service": "EC2",
                })
                assert resp.status_code == 200
                data = resp.json()
                assert "what_this_fixes" in data
                assert "why_it_matters" in data

    def test_insight_falls_back_on_gemini_failure(self):
        with patch("app.main._check_insight_rate_limit"):
            with patch("google.genai.Client", side_effect=Exception("Gemini down")):
                resp = client.post("/remediation/generate-insight", json={
                    "severity": "Critical",
                    "issue": "SSH open to internet",
                    "recommendation": "Restrict SSH",
                    "aws_service": "EC2",
                })
                # Should never 500 - always falls back
                assert resp.status_code == 200
                data = resp.json()
                assert "what_this_fixes" in data

    def test_insight_rate_limited(self):
        from fastapi import HTTPException
        with patch("app.main._check_insight_rate_limit", side_effect=HTTPException(status_code=429, detail="Rate limit")):
            resp = client.post("/remediation/generate-insight", json={
                "severity": "Critical",
                "issue": "test",
                "recommendation": "fix",
                "aws_service": "EC2",
            })
            assert resp.status_code == 429


# -- TERRAFORM GENERATE --------------------------------------------

class TestTerraformGenerate:
    def test_terraform_returns_hcl(self):
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text='resource "aws_security_group_rule" "fix" {}')]

        with patch("app.main._check_terraform_rate_limit"):
            with patch("anthropic.Anthropic") as mock_anthropic_cls:
                mock_anthropic_cls.return_value.messages.create.return_value = mock_message
                with patch("shutil.which", return_value=None):
                    resp = client.post("/remediation/generate-terraform", json={
                        "severity": "Critical",
                        "issue": "SSH open",
                        "recommendation": "Restrict SSH",
                        "aws_service": "EC2",
                    })
                    assert resp.status_code == 200
                    data = resp.json()
                    assert "hcl" in data
                    assert data["errors"] == "terraform CLI not available — skipping validation"

    def test_terraform_returns_empty_on_claude_failure(self):
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("Claude down")

        with patch("app.main._check_terraform_rate_limit"):
            with patch("anthropic.Anthropic", return_value=mock_client):
                resp = client.post("/remediation/generate-terraform", json={
                    "severity": "Critical",
                    "issue": "SSH open",
                    "recommendation": "Restrict SSH",
                    "aws_service": "EC2",
                })
                assert resp.status_code == 200
                data = resp.json()
                assert data["hcl"] == ""


# -- ANALYZE ENDPOINT ----------------------------------------------

class TestAnalyzeEndpoint:
    def _make_mock_infra(self):
        """Build a minimal AWSInfrastructure for mocking collect_infrastructure."""
        from app.models import AWSInfrastructure
        return AWSInfrastructure(region="us-east-1")

    def test_analyze_rate_limited_at_5_scans(self):
        with patch("app.main.get_scan_count_today", return_value=15):
            with patch("app.main.agentops", create=True) as mock_ao:
                mock_ao.start_session.return_value = MagicMock()
                mock_ao.init = MagicMock()
                resp = client.post("/analyze", json={
                    "role_arn": "arn:aws:iam::123456789012:role/EmfirgeRole",
                    "region": "us-east-1",
                })
                assert resp.status_code == 429
                assert "5" in resp.json()["detail"]

    def test_analyze_invalid_role_arn_returns_400(self):
        from app.aws_collector import collect_infrastructure
        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", side_effect=ValueError("Could not assume the IAM role")):
                with patch("app.main.agentops", create=True):
                    resp = client.post("/analyze", json={
                        "role_arn": "arn:aws:iam::123456789012:role/BadRole",
                        "region": "us-east-1",
                    })
                    assert resp.status_code == 400

    def test_analyze_full_flow_mocked(self):
        """Full scan flow with all external calls mocked — verifies response shape."""
        from app.models import AWSInfrastructure
        mock_infra = AWSInfrastructure(region="us-east-1")

        mock_ai = {
            "ai_summary": "Test summary",
            "recommended_improvements": ["Fix SSH"],
            "priority_actions": [],
            "latency_ms": 100,
        }

        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", return_value=mock_ai):
                    with patch("app.main.save_report", return_value="reports/test.json"):
                        with patch("app.main.get_report_url", return_value="https://s3.example.com/report"):
                            with patch("app.main.save_analysis", return_value=1):
                                with patch("app.main.get_previous_scan_for_account", return_value={}):
                                    with patch("app.main.agentops", create=True):
                                        resp = client.post("/analyze", json={
                                            "role_arn": "arn:aws:iam::123456789012:role/EmfirgeRole",
                                            "region": "us-east-1",
                                        })
                                        assert resp.status_code == 200
                                        data = resp.json()
                                        # Verify all required response fields
                                        required_fields = [
                                            "analysis_id", "overall_risk_score", "overall_risk_level",
                                            "security_score", "critical_risks", "moderate_risks",
                                            "ai_summary", "warnings", "scan_duration_seconds",
                                        ]
                                        for field in required_fields:
                                            assert field in data, f"Missing field: {field}"

    def test_analyze_s3_failure_surfaces_warning(self):
        from app.models import AWSInfrastructure
        mock_infra = AWSInfrastructure(region="us-east-1")
        mock_ai = {"ai_summary": "ok", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0}

        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", return_value=mock_ai):
                    with patch("app.main.save_report", side_effect=Exception("S3 down")):
                        with patch("app.main.save_analysis", return_value=1):
                            with patch("app.main.get_previous_scan_for_account", return_value={}):
                                with patch("app.main.agentops", create=True):
                                    resp = client.post("/analyze", json={
                                        "role_arn": "arn:aws:iam::123456789012:role/EmfirgeRole",
                                        "region": "us-east-1",
                                    })
                                    assert resp.status_code == 200
                                    data = resp.json()
                                    # S3 failure should surface in warnings, not crash
                                    assert any("S3" in w for w in data["warnings"])


# -- ANALYZE STREAM (SSE) ENDPOINT ---------------------------------

class TestAnalyzeStreamEndpoint:
    """Tests for the SSE streaming /analyze/stream endpoint."""

    def test_stream_rate_limited_at_5_scans(self):
        with patch("app.main.get_scan_count_today", return_value=15):
            resp = client.post("/analyze/stream", json={
                "role_arn": "arn:aws:iam::123456789012:role/EmfirgeRole",
                "region": "us-east-1",
            })
            assert resp.status_code == 429
            assert "5" in resp.json()["detail"]

    def test_stream_whitelisted_account_bypasses_limit(self):
        """Whitelisted accounts (demo) should not be rate limited."""
        from app.models import AWSInfrastructure
        mock_ai = {"ai_summary": "ok", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0}

        # Account 000000000000 is whitelisted via WHITELISTED_ACCOUNTS env var — should bypass rate limit even at 99 scans
        with patch.dict("os.environ", {"WHITELISTED_ACCOUNTS": "000000000000"}):
          with patch("app.main.get_scan_count_today", return_value=99):
            with patch("app.main.generate_explanation", return_value=mock_ai):
                with patch("app.main.save_report", return_value="reports/test.json"):
                    with patch("app.main.get_report_url", return_value="https://s3.example.com/report"):
                        with patch("app.main.save_analysis", return_value=1):
                            with patch("app.main.get_previous_scan_for_account", return_value={}):
                                resp = client.post("/analyze/stream", json={
                                    "role_arn": "arn:aws:iam::000000000000:role/EmfirgeReadOnly",
                                    "region": "us-east-1",
                                })
                                # Whitelisted account - should stream, not 429
                                assert resp.status_code == 200
                                assert "text/event-stream" in resp.headers["content-type"]

    def test_stream_demo_returns_sse_with_complete_event(self):
        """Demo scan should stream progress + complete events."""
        from app.models import AWSInfrastructure
        mock_ai = {"ai_summary": "Demo summary", "recommended_improvements": ["Fix SSH"], "priority_actions": [], "latency_ms": 0}

        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.generate_explanation", return_value=mock_ai):
                with patch("app.main.save_report", return_value="reports/test.json"):
                    with patch("app.main.get_report_url", return_value="https://s3.example.com/report"):
                        with patch("app.main.save_analysis", return_value=1):
                            with patch("app.main.get_previous_scan_for_account", return_value={}):
                                resp = client.post("/analyze/stream", json={
                                    "role_arn": "arn:aws:iam::000000000000:role/EmfirgeReadOnly",
                                    "region": "us-east-1",
                                })
                                assert resp.status_code == 200
                                assert "text/event-stream" in resp.headers["content-type"]

                                # Parse SSE events from response body
                                body = resp.text
                                assert "event: progress" in body
                                assert "event: complete" in body

                                # Extract the complete event data
                                lines = body.split("\n")
                                complete_data = None
                                for i, line in enumerate(lines):
                                    if line.strip() == "event: complete":
                                        # Next data: line has the payload
                                        for j in range(i + 1, len(lines)):
                                            if lines[j].startswith("data:"):
                                                complete_data = json.loads(lines[j][5:].strip())
                                                break
                                        break

                                assert complete_data is not None, "No 'complete' event found in SSE stream"
                                assert "analysis_id" in complete_data
                                assert "overall_risk_score" in complete_data
                                assert isinstance(complete_data["overall_risk_score"], int)

    def test_stream_returns_error_event_on_bad_role(self):
        """If role assumption fails, should emit error event, not crash."""
        from botocore.exceptions import ClientError

        error_response = {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}}
        mock_error = ClientError(error_response, "AssumeRole")

        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("boto3.client") as mock_boto:
                mock_sts = MagicMock()
                mock_sts.assume_role.side_effect = mock_error
                mock_boto.return_value = mock_sts
                resp = client.post("/analyze/stream", json={
                    "role_arn": "arn:aws:iam::123456789012:role/BadRole",
                    "region": "us-east-1",
                })
                assert resp.status_code == 200  # SSE always returns 200
                body = resp.text
                assert "event: error" in body
                assert "assume" in body.lower() or "role" in body.lower()
