"""
EMFIRGE BETA-READINESS AUDIT — Comprehensive stress tests.
Covers: rate limiters, input validation, edge cases, security, error handling.
Zero real AWS/LLM calls — all external dependencies mocked.
"""
import pytest
import time
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import (
    app,
    _insight_request_log, _terraform_request_log,
    _pr_request_log, _simulate_request_log, _feedback_request_log,
    _check_insight_rate_limit, _check_terraform_rate_limit, _check_pr_rate_limit,
)
from app.models import AWSInfrastructure, RiskFinding
from app.scoring import calculate_score, _weighted_risk
from app.rules import run_all_checks
from app.egraph import build_graph

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════
# 1. RATE LIMITER STRESS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestInsightRateLimit:
    """POST /remediation/generate-insight — 5 req/60s per IP."""

    def setup_method(self):
        _insight_request_log.clear()

    def test_first_request_allowed(self):
        _check_insight_rate_limit("10.0.0.1")  # should not raise

    def test_fifth_request_allowed(self):
        for i in range(5):
            _check_insight_rate_limit(f"10.0.0.{i}")  # different IPs

    def test_sixth_request_from_same_ip_blocked(self):
        from fastapi import HTTPException
        for _ in range(5):
            _check_insight_rate_limit("10.0.0.99")
        with pytest.raises(HTTPException) as exc:
            _check_insight_rate_limit("10.0.0.99")
        assert exc.value.status_code == 429

    def test_different_ips_independent(self):
        for _ in range(5):
            _check_insight_rate_limit("10.0.0.1")
        _check_insight_rate_limit("10.0.0.2")  # different IP, should work

    def test_window_expires_allows_new_requests(self):
        now = time.time()
        _insight_request_log["10.0.0.50"] = [now - 120] * 5  # all expired
        _check_insight_rate_limit("10.0.0.50")  # should work - old timestamps pruned


class TestTerraformRateLimit:
    """POST /remediation/generate-terraform — 5 req/60s per IP."""

    def setup_method(self):
        _terraform_request_log.clear()

    def test_sixth_request_blocked(self):
        from fastapi import HTTPException
        for _ in range(5):
            _check_terraform_rate_limit("10.0.1.1")
        with pytest.raises(HTTPException) as exc:
            _check_terraform_rate_limit("10.0.1.1")
        assert exc.value.status_code == 429
        assert "Terraform" in exc.value.detail


class TestPRRateLimit:
    """POST /github/pr — 10 req/60s per IP."""

    def setup_method(self):
        _pr_request_log.clear()

    def test_eleventh_request_blocked(self):
        from fastapi import HTTPException
        for _ in range(10):
            _check_pr_rate_limit("10.0.2.1")
        with pytest.raises(HTTPException) as exc:
            _check_pr_rate_limit("10.0.2.1")
        assert exc.value.status_code == 429


class TestSimulateRateLimit:
    """POST /simulate — 10 req/60s per IP (in-memory)."""

    def setup_method(self):
        _simulate_request_log.clear()

    def test_simulate_rate_limit_at_10(self):
        """11th simulate request from same IP should get 429."""
        now = time.time()
        # TestClient uses 'testclient' as client.host, so seed that IP
        _simulate_request_log["testclient"] = [now] * 10
        resp = client.post("/simulate", json={"query": "test", "analysis_id": "fake-id"})
        assert resp.status_code == 429


class TestFeedbackRateLimit:
    """POST /feedback — 5 req/3600s per IP."""

    def setup_method(self):
        if isinstance(_feedback_request_log, dict):
            _feedback_request_log.clear()

    def test_feedback_rate_limit_blocks_after_5(self):
        now = time.time()
        # TestClient uses 'testclient' as client.host
        _feedback_request_log["testclient"] = [now] * 5
        resp = client.post("/feedback", json={
            "message": "Great tool!",
            "name": "Test",
            "email": "test@test.com",
        })
        assert resp.status_code == 429


class TestScanDailyLimit:
    """POST /analyze — 5 scans/day per AWS account (DB-backed)."""

    def test_rate_limit_returns_429_not_500(self):
        """The bug we fixed: HTTPException(429) was caught by except Exception → 500."""
        with patch("app.main.get_scan_count_today", return_value=15):
            with patch("app.main.agentops", create=True) as mock_ao:
                mock_ao.start_session.return_value = MagicMock()
                resp = client.post("/analyze", json={
                    "role_arn": "arn:aws:iam::123456789012:role/EmfirgeRole",
                    "region": "us-east-1",
                })
                assert resp.status_code == 429
                assert "5" in resp.json()["detail"]

    def test_whitelisted_account_bypasses_limit(self):
        """Account 111111111111 is whitelisted via WHITELISTED_ACCOUNTS env var — should bypass rate limiting."""
        mock_infra = AWSInfrastructure(region="us-east-1")
        mock_ai = {"ai_summary": "ok", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0}
        with patch.dict("os.environ", {"WHITELISTED_ACCOUNTS": "111111111111"}):
          with patch("app.main.get_scan_count_today", return_value=99):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", return_value=mock_ai):
                    with patch("app.main.save_report", return_value="r.json"):
                        with patch("app.main.get_report_url", return_value="https://s3/r"):
                            with patch("app.main.save_analysis", return_value=1):
                                with patch("app.main.get_previous_scan_for_account", return_value={}):
                                    with patch("app.main.agentops", create=True):
                                        resp = client.post("/analyze", json={
                                            "role_arn": "arn:aws:iam::111111111111:role/EmfirgeRole",
                                            "region": "us-east-1",
                                        })
                                        assert resp.status_code == 200

    def test_unknown_account_id_not_rate_limited(self):
        """Malformed ARN → account_id='unknown' → no rate limit check."""
        with patch("app.main.collect_infrastructure", side_effect=ValueError("bad")):
            with patch("app.main.agentops", create=True):
                resp = client.post("/analyze", json={
                    "role_arn": "not-a-valid-arn",
                    "region": "us-east-1",
                })
                assert resp.status_code == 400  # ValueError, not 429


# ═══════════════════════════════════════════════════════════════════
# 2. INPUT VALIDATION & SECURITY
# ═══════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Malformed inputs should return 4xx, never 500."""

    def test_analyze_empty_body(self):
        resp = client.post("/analyze", json={})
        assert resp.status_code == 422  # Pydantic validation

    def test_analyze_missing_region(self):
        resp = client.post("/analyze", json={"role_arn": "arn:aws:iam::123:role/R"})
        assert resp.status_code == 422

    def test_analyze_missing_role_arn(self):
        resp = client.post("/analyze", json={"region": "us-east-1"})
        assert resp.status_code == 422

    def test_insight_empty_body(self):
        resp = client.post("/remediation/generate-insight", json={})
        assert resp.status_code == 422

    def test_terraform_empty_body(self):
        resp = client.post("/remediation/generate-terraform", json={})
        assert resp.status_code == 422

    def test_feedback_empty_message(self):
        with patch("app.main._feedback_request_log", {}):
            resp = client.post("/feedback", json={"message": ""})
            assert resp.status_code == 400

    def test_feedback_too_long_message(self):
        with patch("app.main._feedback_request_log", {}):
            resp = client.post("/feedback", json={"message": "x" * 2001})
            assert resp.status_code == 400

    def test_feedback_short_message_rejected(self):
        with patch("app.main._feedback_request_log", {}):
            resp = client.post("/feedback", json={"message": "ab"})
            assert resp.status_code == 400

    def test_simulate_empty_body(self):
        resp = client.post("/simulate", json={})
        assert resp.status_code == 422

    def test_simulate_missing_analysis_id(self):
        resp = client.post("/simulate", json={"query": "test"})
        assert resp.status_code == 422

    def test_history_negative_limit(self):
        with patch("app.main.get_recent_logs", return_value=[]):
            resp = client.get("/history?limit=-1")
            assert resp.status_code == 200  # FastAPI coerces, no crash

    def test_logs_invalid_log_id(self):
        resp = client.get("/logs/not-a-number")
        assert resp.status_code == 422

    def test_github_repos_missing_installation_id(self):
        resp = client.get("/github/repos")
        assert resp.status_code == 422


class TestGraphInputValidation:
    """Input sanitization for the graph endpoint at /egraph/{id}."""

    def test_sql_injection_in_analysis_id_blocked(self):
        resp = client.get("/egraph/'; DROP TABLE analysis_logs; --")
        assert resp.status_code == 400
        assert "Invalid" in resp.json()["detail"]

    def test_like_pattern_injection_blocked(self):
        resp = client.get("/egraph/%25%25")
        assert resp.status_code == 400

    def test_valid_uuid_format_accepted(self):
        """Valid UUID format should pass regex, then 404 if not found."""
        with patch("app.database.SessionLocal") as mock_session:
            mock_s = MagicMock()
            mock_s.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
            mock_session.return_value = mock_s
            resp = client.get("/egraph/550e8400-e29b-41d4-a716-446655440000")
            assert resp.status_code == 404

    def test_empty_analysis_id_rejected(self):
        resp = client.get("/egraph/")
        # FastAPI returns 404 for empty path segment (no route match)
        assert resp.status_code in (404, 405)


class TestWebhookSecurity:
    """POST /github/webhook — HMAC verification."""

    def test_valid_hmac_accepted(self):
        import hmac
        import hashlib
        secret = "test-secret-123"
        body = b'{"action": "opened"}'
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        with patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": secret}):
            resp = client.post("/github/webhook", content=body,
                               headers={"X-Hub-Signature-256": sig, "Content-Type": "application/json"})
            assert resp.json()["status"] == "ok"

    def test_tampered_body_rejected(self):
        import hmac
        import hashlib
        secret = "test-secret-123"
        body = b'{"action": "opened"}'
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        with patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": secret}):
            resp = client.post("/github/webhook", content=b'{"action": "TAMPERED"}',
                               headers={"X-Hub-Signature-256": sig, "Content-Type": "application/json"})
            assert resp.json()["status"] == "invalid signature"


# ═══════════════════════════════════════════════════════════════════
# 3. ERROR HANDLING & GRACEFUL DEGRADATION
# ═══════════════════════════════════════════════════════════════════

class TestGracefulDegradation:
    """Every LLM/external failure should degrade gracefully, never 500."""

    def test_insight_gemini_timeout_returns_fallback(self):
        with patch("app.main._check_insight_rate_limit"):
            with patch("google.genai.Client", side_effect=TimeoutError("timeout")):
                resp = client.post("/remediation/generate-insight", json={
                    "severity": "Critical", "issue": "SSH open",
                    "recommendation": "Restrict", "aws_service": "EC2",
                })
                assert resp.status_code == 200
                assert resp.json()["what_this_fixes"] == "Restrict"

    def test_insight_gemini_returns_invalid_json(self):
        mock_resp = MagicMock()
        mock_resp.text = "This is not JSON at all"
        with patch("app.main._check_insight_rate_limit"):
            with patch("google.genai.Client") as mock_client:
                mock_client.return_value.models.generate_content.return_value = mock_resp
                resp = client.post("/remediation/generate-insight", json={
                    "severity": "Moderate", "issue": "No encryption",
                    "recommendation": "Enable encryption", "aws_service": "S3",
                })
                assert resp.status_code == 200
                assert "Enable encryption" in resp.json()["what_this_fixes"]

    def test_terraform_anthropic_constructor_failure(self):
        """Anthropic() constructor fails — should return empty HCL, not 500."""
        with patch("app.main._check_terraform_rate_limit"):
            with patch("anthropic.Anthropic", side_effect=Exception("No API key")):
                resp = client.post("/remediation/generate-terraform", json={
                    "severity": "Critical", "issue": "SSH open",
                    "recommendation": "Restrict", "aws_service": "EC2",
                })
                assert resp.status_code == 200
                assert resp.json()["hcl"] == ""

    def test_analyze_gemini_failure_still_returns_scan(self):
        mock_infra = AWSInfrastructure(region="us-east-1")
        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", side_effect=Exception("Gemini down")):
                    with patch("app.main.save_report", return_value="r.json"):
                        with patch("app.main.get_report_url", return_value="https://s3/r"):
                            with patch("app.main.save_analysis", return_value=1):
                                with patch("app.main.get_previous_scan_for_account", return_value={}):
                                    with patch("app.main.agentops", create=True):
                                        resp = client.post("/analyze", json={
                                            "role_arn": "arn:aws:iam::123456789012:role/R",
                                            "region": "us-east-1",
                                        })
                                        assert resp.status_code == 200
                                        data = resp.json()
                                        assert any("Gemini" in w or "AI summary" in w for w in data["warnings"])

    def test_analyze_db_failure_still_returns_scan(self):
        mock_infra = AWSInfrastructure(region="us-east-1")
        mock_ai = {"ai_summary": "ok", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0}
        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", return_value=mock_ai):
                    with patch("app.main.save_report", return_value="r.json"):
                        with patch("app.main.get_report_url", return_value="https://s3/r"):
                            with patch("app.main.save_analysis", return_value=-1):
                                with patch("app.main.get_previous_scan_for_account", return_value={}):
                                    with patch("app.main.agentops", create=True):
                                        resp = client.post("/analyze", json={
                                            "role_arn": "arn:aws:iam::123456789012:role/R",
                                            "region": "us-east-1",
                                        })
                                        assert resp.status_code == 200
                                        assert any("database" in w.lower() or "graph" in w.lower()
                                                   for w in resp.json()["warnings"])


# ═══════════════════════════════════════════════════════════════════
# 4. SCORING STRESS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestScoringStress:
    """Edge cases and stress scenarios for the scoring engine."""

    def test_zero_resources_no_crash(self):
        scores = calculate_score({}, total_resources=0)
        assert 0 <= scores["overall_risk_score"] <= 100

    def test_one_resource_with_critical(self):
        findings = {
            "critical_risks": [RiskFinding(
                rule_id="T-001", category="Security", severity="Critical",
                confidence="HIGH", issue="test", recommendation="fix",
                aws_service="EC2", blast_radius=0,
            )],
        }
        scores = calculate_score(findings, total_resources=1)
        # 1 Critical/HIGH on 1 resource: score should be noticeably below 100
        # Floor penalty = 5, plus weighted risk penalty
        assert scores["overall_risk_score"] < 95

    def test_1000_findings_no_crash(self):
        findings = {
            "critical_risks": [RiskFinding(
                rule_id=f"T-{i}", category="Security", severity="Critical",
                confidence="HIGH", issue=f"issue {i}", recommendation="fix",
                aws_service="EC2", blast_radius=i % 10,
            ) for i in range(500)],
            "moderate_risks": [RiskFinding(
                rule_id=f"M-{i}", category="Security", severity="Moderate",
                confidence="HIGH", issue=f"issue {i}", recommendation="fix",
                aws_service="S3", blast_radius=0,
            ) for i in range(500)],
        }
        scores = calculate_score(findings, total_resources=100)
        assert scores["overall_risk_score"] == 0  # maxed out

    def test_huge_blast_radius_no_overflow(self):
        findings = [RiskFinding(
            rule_id="T-001", category="Security", severity="Critical",
            confidence="HIGH", issue="test", recommendation="fix",
            aws_service="EC2", blast_radius=999999,
        )]
        risk = _weighted_risk(findings)
        assert risk > 0
        assert risk < float("inf")

    def test_all_severity_levels_scored(self):
        for sev in ["Critical", "Moderate", "Low"]:
            for conf in ["HIGH", "MEDIUM", "LOW"]:
                findings = [RiskFinding(
                    rule_id="T-001", category="Security", severity=sev,
                    confidence=conf, issue="test", recommendation="fix",
                    aws_service="EC2",
                )]
                risk = _weighted_risk(findings)
                assert risk >= 0

    def test_score_monotonically_decreases_with_more_criticals(self):
        prev_score = 100
        for n in range(1, 11):
            findings = {
                "critical_risks": [RiskFinding(
                    rule_id=f"T-{i}", category="Security", severity="Critical",
                    confidence="HIGH", issue="test", recommendation="fix",
                    aws_service="EC2",
                ) for i in range(n)],
            }
            scores = calculate_score(findings, total_resources=20)
            assert scores["overall_risk_score"] <= prev_score
            prev_score = scores["overall_risk_score"]


# ═══════════════════════════════════════════════════════════════════
# 5. RULES ENGINE STRESS TESTS
# ═══════════════════════════════════════════════════════════════════

class TestRulesStress:
    """Edge cases for the rules engine."""

    def test_100_security_groups_no_crash(self):
        from app.models import EC2Data, SecurityGroup
        sgs = [SecurityGroup(
            id=f"sg-{i:03d}", name=f"sg-{i}",
            rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp",
                     "ip_ranges": ["0.0.0.0/0"] if i % 2 == 0 else ["10.0.0.0/8"]}],
            attached_to=[f"i-{i:03d}"],
        ) for i in range(100)]
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(security_groups=sgs),
        )
        results = run_all_checks(infra)
        assert isinstance(results, dict)
        assert "critical_risks" in results

    def test_50_s3_buckets_no_crash(self):
        from app.models import S3Data, S3Bucket
        buckets = [S3Bucket(
            name=f"bucket-{i}", is_public=(i % 3 == 0), is_empty=(i % 5 == 0),
        ) for i in range(50)]
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                total_buckets=50,
                public_buckets=[b.name for b in buckets if b.is_public],
                unencrypted_buckets=[b.name for b in buckets if b.is_public],
                buckets=buckets,
            ),
        )
        results = run_all_checks(infra)
        assert isinstance(results, dict)

    def test_graph_with_100_nodes_no_crash(self):
        from app.models import EC2Data, EC2Instance, SecurityGroup
        instances = [EC2Instance(
            id=f"i-{i:03d}", type="t3.micro", sg_ids=[f"sg-{i:03d}"],
            state="running", imdsv2_required=True,
        ) for i in range(50)]
        sgs = [SecurityGroup(
            id=f"sg-{i:03d}", name=f"sg-{i}",
            rules=[], attached_to=[f"i-{i:03d}"],
        ) for i in range(50)]
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(instances=instances, security_groups=sgs, instance_count=50),
        )
        graph = build_graph(infra)
        assert len(graph.nodes) >= 100  # 50 instances + 50 SGs

    def test_all_services_empty_no_crash(self):
        """Completely empty account — every service returns defaults."""
        infra = AWSInfrastructure(region="us-east-1")
        results = run_all_checks(infra)
        graph = build_graph(infra)
        scores = calculate_score(results, 0, infra)
        assert scores["overall_risk_score"] >= 0
        assert graph.nodes == []


# ═══════════════════════════════════════════════════════════════════
# 6. API ENDPOINT COMPLETENESS
# ═══════════════════════════════════════════════════════════════════

class TestAPICompleteness:
    """Every route responds correctly to basic requests."""

    def test_root_endpoint(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["version"] == "2.0"

    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "status" in resp.json()

    def test_logs_endpoint(self):
        with patch("app.main.get_recent_logs", return_value=[]):
            resp = client.get("/logs")
            assert resp.status_code == 200

    def test_history_endpoint(self):
        with patch("app.main.get_recent_logs", return_value=[]):
            resp = client.get("/history")
            assert resp.status_code == 200

    def test_drift_events_endpoint(self):
        with patch("app.main.get_drift_events", return_value=[]):
            resp = client.get("/drift/events")
            assert resp.status_code == 200

    def test_github_install_url(self):
        resp = client.get("/github/install-url")
        assert resp.status_code == 200
        assert "url" in resp.json()

    def test_simulate_remaining_unknown_id(self):
        with patch("app.database.SessionLocal") as mock_session:
            mock_s = MagicMock()
            mock_s.query.return_value.order_by.return_value.limit.return_value.all.return_value = []
            mock_session.return_value = mock_s
            resp = client.get("/simulate/remaining?analysis_id=nonexistent")
            assert resp.status_code == 200
            data = resp.json()
            assert data["remaining"] == 10
            assert data["limit"] == 10

    def test_feedback_get_endpoint(self):
        with patch("app.main.get_feedback", return_value=[]):
            with patch.dict("os.environ", {"FEEDBACK_ADMIN_KEY": "test-key"}):
                resp = client.get("/feedback?key=test-key")
                assert resp.status_code == 200

    def test_feedback_get_blocked_without_key(self):
        with patch.dict("os.environ", {"FEEDBACK_ADMIN_KEY": "real-secret"}):
            resp = client.get("/feedback")
            assert resp.status_code == 403

    def test_feedback_get_blocked_with_wrong_key(self):
        with patch.dict("os.environ", {"FEEDBACK_ADMIN_KEY": "real-secret"}):
            resp = client.get("/feedback?key=wrong-key")
            assert resp.status_code == 403

    def test_feedback_get_limit_capped(self):
        with patch("app.main.get_feedback", return_value=[]) as mock_fb:
            with patch.dict("os.environ", {"FEEDBACK_ADMIN_KEY": "test-key"}):
                resp = client.get("/feedback?limit=999&key=test-key")
                assert resp.status_code == 200
                mock_fb.assert_called_once_with(limit=100)


# ═══════════════════════════════════════════════════════════════════
# 7. CORS VERIFICATION
# ═══════════════════════════════════════════════════════════════════

class TestCORS:
    """CORS headers are set correctly for the frontend."""

    def test_production_origin_allowed(self):
        resp = client.options("/", headers={
            "Origin": "https://emfirge.vercel.app",
            "Access-Control-Request-Method": "GET",
        })
        assert resp.headers.get("access-control-allow-origin") == "https://emfirge.vercel.app"

    def test_localhost_origin_allowed(self):
        resp = client.options("/", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        })
        assert "localhost" in resp.headers.get("access-control-allow-origin", "")

    def test_random_origin_blocked(self):
        resp = client.options("/", headers={
            "Origin": "https://evil-site.com",
            "Access-Control-Request-Method": "GET",
        })
        assert resp.headers.get("access-control-allow-origin") != "https://evil-site.com"


# ═══════════════════════════════════════════════════════════════════
# 8. RESPONSE SHAPE VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestResponseShapes:
    """Verify response JSON shapes match what the frontend expects."""

    def test_analyze_response_has_all_fields(self):
        mock_infra = AWSInfrastructure(region="us-east-1")
        mock_ai = {"ai_summary": "ok", "recommended_improvements": ["Fix SSH"],
                    "priority_actions": [], "latency_ms": 0}
        with patch("app.main.get_scan_count_today", return_value=0):
            with patch("app.main.collect_infrastructure", return_value=mock_infra):
                with patch("app.main.generate_explanation", return_value=mock_ai):
                    with patch("app.main.save_report", return_value="r.json"):
                        with patch("app.main.get_report_url", return_value="https://s3/r"):
                            with patch("app.main.save_analysis", return_value=1):
                                with patch("app.main.get_previous_scan_for_account", return_value={}):
                                    with patch("app.main.agentops", create=True):
                                        resp = client.post("/analyze", json={
                                            "role_arn": "arn:aws:iam::123456789012:role/R",
                                            "region": "us-east-1",
                                        })
                                        data = resp.json()
                                        required = [
                                            "analysis_id", "timestamp", "region_analyzed",
                                            "overall_risk_score", "overall_risk_level",
                                            "security_score", "availability_score",
                                            "disaster_recovery_score", "cost_score", "cost_level",
                                            "maturity_score", "maturity_bonus", "maturity_checks_passed",
                                            "simulation_baseline",
                                            "critical_risks", "moderate_risks",
                                            "best_practices", "cost_findings",
                                            "toxic_combinations",
                                            "ai_summary", "recommended_improvements",
                                            "priority_actions", "warnings",
                                            "total_resources_scanned", "scan_duration_seconds",
                                            "report_url",
                                        ]
                                        for field in required:
                                            assert field in data, f"Missing: {field}"

    def test_history_response_shape(self):
        fake_logs = [
            {"id": 2, "timestamp": "2026-05-05", "region_analyzed": "us-east-1",
             "risk_score": 70, "risk_level": "MODERATE", "security_score": 65,
             "availability_score": 80, "cost_score": 90, "critical_count": 2,
             "moderate_count": 5, "latency_ms": 3000},
            {"id": 1, "timestamp": "2026-05-04", "region_analyzed": "us-east-1",
             "risk_score": 75, "risk_level": "MODERATE", "security_score": 60,
             "availability_score": 80, "cost_score": 90, "critical_count": 3,
             "moderate_count": 6, "latency_ms": 2800},
        ]
        with patch("app.main.get_recent_logs", return_value=fake_logs):
            resp = client.get("/history")
            data = resp.json()
            assert "scans" in data
            assert len(data["scans"]) == 2
            assert "score_delta" in data["scans"][0]
            assert "trend" in data["scans"][0]
            assert data["scans"][0]["score_delta"] == -5  # 70 - 75
            assert data["scans"][0]["trend"] == "improved"
