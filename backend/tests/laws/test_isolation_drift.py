import json

import pytest

from app import database
from app.database import AnalysisLog
from tests.laws.test_tenant_isolation import tenant_client
from app.drift_service import compare_findings


@pytest.fixture
def drift_tenant(tenant_client):
    client, key_a, key_b, ids = tenant_client
    db = database.SessionLocal()
    try:
        db.add(AnalysisLog(
            aws_account_id='111111111111',
            findings_json=json.dumps({
                'analysis_id': 'a-uuid-2',
                'findings': [
                    {'rule_id': 'A-RULE', 'resource_id': 'a-resource', 'severity': 'Critical'},
                ],
            }),
        ))
        db.commit()
        ids['a-second'] = db.query(AnalysisLog).filter_by(
            aws_account_id='111111111111',
        ).order_by(AnalysisLog.id.desc()).first().id
    finally:
        db.close()
    return client, key_a, key_b, ids


def _response(response):
    return response.status_code, response.json()


def test_drift_events_account_parameter_is_not_found_across_tenants(drift_tenant):
    client, key_a, key_b, _ = drift_tenant
    a = client.get('/drift/events?account_id=111111111111', headers={'X-API-Key': key_a})
    b_a = client.get('/drift/events?account_id=111111111111', headers={'X-API-Key': key_b})
    b_never = client.get('/drift/events?account_id=999999999999', headers={'X-API-Key': key_b})

    assert a.status_code == 200
    assert a.json()['events']
    assert {event['aws_account_id'] for event in a.json()['events']} == {'111111111111'}
    assert _response(b_a) == _response(b_never)


def test_drift_events_unfiltered_route_is_tenant_scoped(drift_tenant):
    client, key_a, key_b, _ = drift_tenant
    a = client.get('/drift/events', headers={'X-API-Key': key_a})
    b = client.get('/drift/events', headers={'X-API-Key': key_b})

    assert a.status_code == 200
    assert a.json()['events']
    assert {event['aws_account_id'] for event in a.json()['events']} == {'111111111111'}
    assert b.status_code == 200
    assert {event['aws_account_id'] for event in b.json()['events']} == {'222222222222'}
    assert all(event['aws_account_id'] != '111111111111' for event in b.json()['events'])


def test_compare_findings_uses_a_account_logs_without_cross_tenant_data(drift_tenant):
    _, _, _, ids = drift_tenant
    db = database.SessionLocal()
    try:
        logs = db.query(AnalysisLog).filter(
            AnalysisLog.aws_account_id == '111111111111',
        ).order_by(AnalysisLog.id).all()
        assert len(logs) == 2
        previous = json.loads(logs[0].findings_json).get('findings', [])
        current = json.loads(logs[1].findings_json).get('findings', [])
        second_id = logs[1].id
    finally:
        db.close()

    new_findings, fixed_findings, severity_changed = compare_findings(current, previous)
    assert new_findings or fixed_findings or severity_changed
    assert ids['a-second'] == second_id
