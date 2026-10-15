import json

from app import auth, branches, database, in_use_evidence, main
from app.demo_seed import get_demo_infrastructure
from app.evidence_models import EvidenceRecord
from app.database import AnalysisLog

from .test_tenant_isolation import tenant_client


def _headers(key):
    return {'X-API-Key': key}


def _same_not_found(resp_hidden, hidden_id, resp_missing, missing_id):
    assert resp_hidden.status_code == resp_missing.status_code
    assert json.dumps(resp_hidden.json()).replace(hidden_id, '<ID>') == json.dumps(resp_missing.json()).replace(missing_id, '<ID>')


def _make_analysis_real():
    """Give fixture analysis A a valid snapshot for a non-vacuous verify-fix result."""
    session = database.SessionLocal()
    try:
        row = session.query(AnalysisLog).filter_by(aws_account_id='111111111111').one()
        findings = json.loads(row.findings_json)
        findings.update({
            'infrastructure': get_demo_infrastructure().model_dump(),
            'overall_risk_score': 0,
            'total_resources_scanned': 1,
            'critical_risks': [],
            'moderate_risks': [],
            'low_risks': [],
            'best_practices': [],
            'cost_findings': [],
            'toxic_combinations': [],
        })
        row.findings_json = json.dumps(findings)
        session.commit()
    finally:
        session.close()


def _make_a_branch():
    return branches.create_branch(
        get_demo_infrastructure(), 'tenant-law-evidence', base_analysis_id='a-uuid'
    )


def test_verify_fix_hides_other_tenant_analysis(tenant_client):
    client, key_a, key_b, _ = tenant_client
    _make_analysis_real()
    payload = {
        'analysis_id': 'a-uuid',
        'rule_id': 'EMFIRGE-EC2-002',
        'resource_id': 'sg-0a1b2c3d4e5f00002',
    }

    own = client.post('/remediation/verify-fix', headers=_headers(key_a), json=payload)
    hidden = client.post('/remediation/verify-fix', headers=_headers(key_b), json=payload)
    never_seen = client.post(
        '/remediation/verify-fix',
        headers=_headers(key_b),
        json={**payload, 'analysis_id': 'never-seen'},
    )

    assert own.status_code == 200
    assert own.json()['can_simulate'] is True
    assert hidden.status_code == never_seen.status_code == 404
    _same_not_found(hidden, 'a-uuid', never_seen, 'never-seen')


def test_evidence_estimate_hides_other_tenant_branch(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _make_a_branch()
    path = f'/branches/{branch_id}/in-use-evidence/estimate?sources=cloudtrail_events'

    own = client.get(path, headers=_headers(key_a))
    hidden = client.get(path, headers=_headers(key_b))
    never_seen = client.get(
        '/branches/never-seen/in-use-evidence/estimate?sources=cloudtrail_events',
        headers=_headers(key_b),
    )

    assert own.status_code == 200
    assert own.json()['estimate_id']
    assert own.json()['branch_revision']
    assert hidden.status_code == never_seen.status_code == 404
    _same_not_found(hidden, branch_id, never_seen, 'never-seen')


def test_evidence_collection_hides_other_tenant_and_cannot_write(tenant_client, monkeypatch):
    client, key_a, key_b, _ = tenant_client
    branch_id = _make_a_branch()
    seeded = EvidenceRecord(
        resource_id='seed-resource', resource_type='ec2_instance',
        source='cloudtrail_events', status='no_data', used=None,
        window_days=90, observed_at='2026-10-01T00:00:00Z',
    )
    branches.save_evidence(branch_id, 'seed-estimate', [seeded])
    before = [record.model_dump(mode='json') for record in branches.list_evidence(branch_id)]
    estimate = client.get(
        f'/branches/{branch_id}/in-use-evidence/estimate?sources=cloudtrail_events',
        headers=_headers(key_a),
    ).json()
    body = {
        'role_arn': 'arn:aws:iam::111111111111:role/EmfirgeRole',
        'sources': ['cloudtrail_events'],
        'accept_estimate_id': estimate['estimate_id'],
    }

    monkeypatch.setattr(main, 'assume_role_credentials', lambda *_: ({'AccessKeyId': 'x'}, '111111111111'))
    monkeypatch.setattr(main, 'read_evidence', lambda *args, **kwargs: [])
    own = client.post(f'/branches/{branch_id}/in-use-evidence', headers=_headers(key_a), json=body)
    hidden = client.post(f'/branches/{branch_id}/in-use-evidence', headers=_headers(key_b), json=body)
    never_seen = client.post('/branches/never-seen/in-use-evidence', headers=_headers(key_b), json=body)
    after = [record.model_dump(mode='json') for record in branches.list_evidence(branch_id)]

    assert own.status_code == 200
    assert own.json()['estimate_id'] == estimate['estimate_id']
    assert hidden.status_code == never_seen.status_code == 404
    _same_not_found(hidden, branch_id, never_seen, 'never-seen')
    assert after == before
