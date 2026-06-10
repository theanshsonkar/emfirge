"""
Tests for POST /remediation/verify-fix endpoint and fix_mutations module.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.fix_mutations import FIX_MUTATIONS
from app.demo_seed import get_demo_infrastructure
from app.models import AWSInfrastructure
from app.scoring import calculate_score

client = TestClient(app)


class TestFixMutations:
    """Unit tests for individual mutation functions."""

    def _get_demo_dict(self):
        return get_demo_infrastructure().model_dump()

    def test_fix_ssh_open(self):
        infra = self._get_demo_dict()
        # Verify SSH is open before fix
        assert infra['ec2']['ssh_open_to_internet'] is True
        # Apply fix
        result = FIX_MUTATIONS["EMFIRGE-EC2-002"](infra, "sg-0a1b2c3d4e5f00002")
        assert result is True
        assert infra['ec2']['ssh_open_to_internet'] is False
        # Verify the rule was removed from the SG
        sg = next(s for s in infra['ec2']['security_groups'] if s['id'] == 'sg-0a1b2c3d4e5f00002')
        assert len(sg['rules']) == 0

    def test_fix_s3_public(self):
        infra = self._get_demo_dict()
        assert "acme-public-assets" in infra['s3']['public_buckets']
        result = FIX_MUTATIONS["EMFIRGE-S3-001"](infra, "acme-public-assets")
        assert result is True
        assert "acme-public-assets" not in infra['s3']['public_buckets']
        bucket = next(b for b in infra['s3']['buckets'] if b['name'] == 'acme-public-assets')
        assert bucket['is_public'] is False

    def test_fix_s3_encryption(self):
        infra = self._get_demo_dict()
        assert "acme-data-lake" in infra['s3']['unencrypted_buckets']
        result = FIX_MUTATIONS["EMFIRGE-S3-002"](infra, "acme-data-lake")
        assert result is True
        assert "acme-data-lake" not in infra['s3']['unencrypted_buckets']

    def test_fix_rds_public(self):
        infra = self._get_demo_dict()
        assert "acme-analytics-db" in infra['rds']['publicly_accessible']
        result = FIX_MUTATIONS["EMFIRGE-RDS-002"](infra, "acme-analytics-db")
        assert result is True
        assert "acme-analytics-db" not in infra['rds']['publicly_accessible']
        rds = next(r for r in infra['rds']['rds_instances'] if r['id'] == 'acme-analytics-db')
        assert rds['publicly_accessible'] is False

    def test_fix_rds_encryption(self):
        infra = self._get_demo_dict()
        assert "acme-analytics-db" in infra['rds']['unencrypted_instances']
        result = FIX_MUTATIONS["EMFIRGE-RDS-003"](infra, "acme-analytics-db")
        assert result is True
        assert "acme-analytics-db" not in infra['rds']['unencrypted_instances']

    def test_fix_ec2_imdsv2(self):
        infra = self._get_demo_dict()
        inst = next(i for i in infra['ec2']['instances'] if i['id'] == 'i-0abc000000000003')
        assert inst['imdsv2_required'] is False
        result = FIX_MUTATIONS["EMFIRGE-EC2-009"](infra, "i-0abc000000000003")
        assert result is True
        inst = next(i for i in infra['ec2']['instances'] if i['id'] == 'i-0abc000000000003')
        assert inst['imdsv2_required'] is True

    def test_fix_waf(self):
        infra = self._get_demo_dict()
        alb_arn = infra['waf']['albs_without_waf'][0]
        result = FIX_MUTATIONS["EMFIRGE-WAF-001"](infra, alb_arn)
        assert result is True
        assert alb_arn not in infra['waf']['albs_without_waf']

    def test_unknown_resource_returns_false(self):
        infra = self._get_demo_dict()
        result = FIX_MUTATIONS["EMFIRGE-EC2-002"](infra, "sg-nonexistent")
        assert result is False

    def test_all_mutations_return_valid_config(self):
        """Every mutation in the map should be callable and return bool."""
        infra = self._get_demo_dict()
        for rule_id, fn in FIX_MUTATIONS.items():
            result = fn(infra, "dummy-resource")
            assert isinstance(result, bool), f"{rule_id} did not return bool"


class TestVerifyFixEndpoint:
    """Integration tests for POST /remediation/verify-fix."""

    def _mock_db_with_demo(self):
        """Create a mock that returns demo infrastructure from DB."""
        from app.demo_seed import get_demo_infrastructure
        from app.rules import run_all_checks
        from app.egraph import build_graph
        from app.scoring import calculate_score

        infra = get_demo_infrastructure()
        graph = build_graph(infra)
        findings = run_all_checks(infra, graph)

        # Build a minimal findings_data dict like what's stored in DB
        scores = calculate_score(findings, 50, infra)
        findings_data = {
            'analysis_id': 'test-analysis-123',
            'infrastructure': infra.model_dump(),
            'overall_risk_score': scores['overall_risk_score'],
            'total_resources_scanned': 50,
            'critical_risks': [f.model_dump() for f in findings.get('critical_risks', [])],
            'moderate_risks': [f.model_dump() for f in findings.get('moderate_risks', [])],
            'low_risks': [f.model_dump() for f in findings.get('low_risks', [])],
            'best_practices': [f.model_dump() for f in findings.get('best_practices', [])],
            'cost_findings': [f.model_dump() for f in findings.get('cost_findings', [])],
            'toxic_combinations': [],
        }

        mock_log = MagicMock()
        mock_log.findings_json = json.dumps(findings_data)
        mock_log.aws_account_id = '000000000000'

        return mock_log

    def test_unsupported_rule_returns_cannot_simulate(self):
        resp = client.post('/remediation/verify-fix', json={
            'analysis_id': 'test-123',
            'rule_id': 'EMFIRGE-UNKNOWN-999',
            'resource_id': 'some-resource',
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data['can_simulate'] is False

    @patch("app.database.SessionLocal")
    def test_verify_fix_ssh_open(self, mock_session_cls):
        mock_log = self._mock_db_with_demo()
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_log]
        mock_session_cls.return_value = mock_session

        resp = client.post('/remediation/verify-fix', json={
            'analysis_id': 'test-analysis-123',
            'rule_id': 'EMFIRGE-EC2-002',
            'resource_id': 'sg-0a1b2c3d4e5f00002',
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data['can_simulate'] is True
        assert data['score_delta'] >= 0  # Score should improve or stay same
        assert data['safe_to_apply'] is True
        # The SSH finding should be in findings_removed
        removed_rules = [f.get('rule_id') for f in data['findings_removed']]
        assert 'EMFIRGE-EC2-002' in removed_rules

    @patch("app.database.SessionLocal")
    def test_verify_fix_s3_public(self, mock_session_cls):
        mock_log = self._mock_db_with_demo()
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_log]
        mock_session_cls.return_value = mock_session

        resp = client.post('/remediation/verify-fix', json={
            'analysis_id': 'test-analysis-123',
            'rule_id': 'EMFIRGE-S3-001',
            'resource_id': 'acme-public-assets',
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data['can_simulate'] is True
        assert data['safe_to_apply'] is True

    def test_missing_analysis_id_returns_404(self):
        resp = client.post('/remediation/verify-fix', json={
            'analysis_id': 'nonexistent-id',
            'rule_id': 'EMFIRGE-EC2-002',
            'resource_id': 'sg-0a1b2c3d4e5f00002',
        })
        assert resp.status_code == 404
