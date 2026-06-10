"""
Tests for scoring.py — zero AWS/LLM calls.
"""
import pytest
from app.scoring import calculate_score, _weighted_risk, _score_from_risk
from app.models import RiskFinding


def make_finding(severity="Critical", confidence="HIGH", blast_radius=0, category="Security"):
    return RiskFinding(
        rule_id="TEST-001",
        category=category,
        severity=severity,
        confidence=confidence,
        issue="test issue",
        recommendation="fix it",
        aws_service="EC2",
        blast_radius=blast_radius,
    )


class TestWeightedRisk:
    def test_critical_high_weighs_most(self):
        f = make_finding("Critical", "HIGH")
        assert _weighted_risk([f]) == 20.0

    def test_critical_low_weighs_less(self):
        f_high = make_finding("Critical", "HIGH")
        f_low = make_finding("Critical", "LOW")
        assert _weighted_risk([f_high]) > _weighted_risk([f_low])

    def test_blast_radius_amplifies_weight(self):
        f_no_blast = make_finding("Critical", "HIGH", blast_radius=0)
        f_with_blast = make_finding("Critical", "HIGH", blast_radius=9)
        assert _weighted_risk([f_with_blast]) > _weighted_risk([f_no_blast])

    def test_empty_findings_zero_risk(self):
        assert _weighted_risk([]) == 0.0

    def test_multiple_findings_sum(self):
        findings = [make_finding("Critical", "HIGH")] * 3
        assert _weighted_risk(findings) == 60.0

    def test_unknown_severity_treated_as_low(self):
        f = make_finding("Unknown", "HIGH")
        # Should not crash, treated as Low
        result = _weighted_risk([f])
        assert result >= 0


class TestScoreFromRisk:
    def test_zero_risk_gives_100(self):
        assert _score_from_risk(0.0, 10) == 100

    def test_high_risk_gives_low_score(self):
        score = _score_from_risk(1000.0, 10)
        assert score == 0

    def test_score_bounded_0_to_100(self):
        for risk in [0, 10, 100, 1000, 99999]:
            s = _score_from_risk(risk, 10)
            assert 0 <= s <= 100

    def test_larger_account_penalized_less(self):
        """Same risk on a bigger account should score higher (more resources = proportionally smaller penalty)."""
        risk = 100.0
        small_score = _score_from_risk(risk, 5)
        large_score = _score_from_risk(risk, 100)
        assert large_score > small_score


class TestCalculateScore:
    def test_no_findings_scores_high(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        assert scores["overall_risk_score"] >= 80

    def test_many_criticals_scores_low(self, nightmare_infra):
        from app.rules import run_all_checks
        findings = run_all_checks(nightmare_infra)
        scores = calculate_score(findings, 10, nightmare_infra)
        assert scores["overall_risk_score"] < 50

    def test_clean_account_scores_higher_than_nightmare(self, clean_infra, nightmare_infra):
        from app.rules import run_all_checks
        clean_findings = run_all_checks(clean_infra)
        nightmare_findings = run_all_checks(nightmare_infra)
        clean_scores = calculate_score(clean_findings, 10, clean_infra)
        nightmare_scores = calculate_score(nightmare_findings, 10, nightmare_infra)
        assert clean_scores["overall_risk_score"] > nightmare_scores["overall_risk_score"]

    def test_maturity_bonus_applied(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        assert scores["maturity_bonus"] > 0
        assert scores["maturity_score"] > 0

    def test_maturity_checks_passed_list(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        assert "guardduty_enabled" in scores["maturity_checks_passed"]
        assert "cloudtrail_multiregion" in scores["maturity_checks_passed"]

    def test_nightmare_no_maturity_bonus(self, nightmare_infra):
        scores = calculate_score({}, 10, nightmare_infra)
        assert scores["maturity_bonus"] == 0.0

    def test_risk_level_thresholds(self):
        # Score >= 85 → LOW
        scores = calculate_score({}, 10)
        assert scores["overall_risk_level"] == "LOW"

    def test_all_required_keys_present(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        required = [
            "overall_risk_score", "overall_risk_level",
            "security_score", "availability_score", "disaster_recovery_score",
            "cost_score", "cost_level",
            "maturity_score", "maturity_bonus", "maturity_checks_passed",
        ]
        for key in required:
            assert key in scores, f"Missing key: {key}"

    def test_cost_level_values(self):
        scores = calculate_score({}, 10)
        assert scores["cost_level"] in ("OPTIMIZED", "REVIEW NEEDED", "ACTION REQUIRED")

    def test_score_never_exceeds_100(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        assert scores["overall_risk_score"] <= 100

    def test_category_scores_independent(self, nightmare_infra):
        from app.rules import run_all_checks
        findings = run_all_checks(nightmare_infra)
        scores = calculate_score(findings, 10, nightmare_infra)
        # Security score should be low for nightmare account
        assert scores["security_score"] < 60


class TestCriticalFloorPenalty:
    """Critical/HIGH findings impose a flat penalty regardless of account size."""

    def test_critical_floor_reduces_score(self):
        from app.scoring import _critical_floor_penalty
        findings = [make_finding("Critical", "HIGH")] * 3
        penalty = _critical_floor_penalty(findings)
        assert penalty == 15  # 3 × 5

    def test_critical_medium_not_penalised(self):
        from app.scoring import _critical_floor_penalty
        findings = [make_finding("Critical", "MEDIUM")]
        penalty = _critical_floor_penalty(findings)
        assert penalty == 0

    def test_large_account_still_penalised_for_criticals(self):
        """Same 3 Critical/HIGH findings — large account should NOT score 98+ anymore."""
        findings = {
            'critical_risks': [make_finding("Critical", "HIGH")] * 3,
            'moderate_risks': [],
            'low_risks': [],
        }
        scores = calculate_score(findings, total_resources=200)
        # Without floor penalty this would be ~98. With floor it should be noticeably lower.
        assert scores["overall_risk_score"] < 90

    def test_no_criticals_no_penalty(self):
        from app.scoring import _critical_floor_penalty
        findings = [make_finding("Moderate", "HIGH")] * 5
        assert _critical_floor_penalty(findings) == 0


class TestMaturityBonusCap:
    """Maturity bonus is capped at +5 when critical findings exist."""

    def test_maturity_capped_with_criticals(self, clean_infra):
        # clean_infra has full maturity (all checks pass) → normally +15
        # But if we inject criticals, bonus should cap at +5
        findings = {
            'critical_risks': [make_finding("Critical", "HIGH")] * 2,
            'moderate_risks': [],
            'low_risks': [],
        }
        scores = calculate_score(findings, 10, clean_infra)
        assert scores["maturity_bonus"] <= 5.0

    def test_maturity_uncapped_without_criticals(self, clean_infra):
        scores = calculate_score({}, 10, clean_infra)
        # clean_infra passes all maturity checks → bonus should be > 5
        assert scores["maturity_bonus"] > 5.0


class TestCategoryNormalization:
    """Category scores use per-category resource counts, not total resources."""

    def test_availability_score_responsive(self, nightmare_infra):
        """Nightmare infra has availability issues — score should reflect that."""
        from app.rules import run_all_checks
        findings = run_all_checks(nightmare_infra)
        scores = calculate_score(findings, 10, nightmare_infra)
        # With per-category normalization, availability should drop below 95
        # (old formula always showed 95+ because it divided by total resources)
        assert scores["availability_score"] < 95

    def test_dr_score_responsive(self, nightmare_infra):
        """Nightmare infra has DR issues — score should reflect that."""
        from app.rules import run_all_checks
        findings = run_all_checks(nightmare_infra)
        scores = calculate_score(findings, 10, nightmare_infra)
        # DR has findings (no backup, no deletion protection, low retention, no versioning)
        # With per-category normalization this should be noticeably below 100
        assert scores["disaster_recovery_score"] < 90

    def test_clean_infra_high_category_scores(self, clean_infra):
        """Clean infra should still score high across all categories."""
        from app.rules import run_all_checks
        findings = run_all_checks(clean_infra)
        scores = calculate_score(findings, 10, clean_infra)
        assert scores["security_score"] >= 80
        assert scores["availability_score"] >= 80
        assert scores["disaster_recovery_score"] >= 80
