from app import auth, database
from app.database import AnalysisLog

from .test_tenant_isolation import tenant_client


def _empty_project(client):
    key = auth.create_api_key('tenant-law-empty')
    client.get('/project', headers={'X-API-Key': key})
    return {'X-API-Key': key}


def _remove_b_log(ids):
    db = database.SessionLocal()
    try:
        db.query(AnalysisLog).filter(AnalysisLog.id == ids['222222222222']).delete()
        db.commit()
    finally:
        db.close()


def test_logs_list_isolation(tenant_client):
    client, key_a, key_b, ids = tenant_client
    _remove_b_log(ids)
    a = client.get('/logs', headers={'X-API-Key': key_a})
    b = client.get('/logs', headers={'X-API-Key': key_b})
    empty = client.get('/logs', headers=_empty_project(client))
    assert a.status_code == 200
    assert ids['111111111111'] in {row['id'] for row in a.json()['logs']}
    assert ids['111111111111'] not in {row['id'] for row in b.json()['logs']}
    assert b.json() == empty.json()


def test_history_list_isolation(tenant_client):
    client, key_a, key_b, ids = tenant_client
    _remove_b_log(ids)
    a = client.get('/history', headers={'X-API-Key': key_a})
    b = client.get('/history', headers={'X-API-Key': key_b})
    empty = client.get('/history', headers=_empty_project(client))
    assert a.status_code == 200
    assert ids['111111111111'] in {row['id'] for row in a.json()['scans']}
    assert ids['111111111111'] not in {row['id'] for row in b.json()['scans']}
    assert b.json() == empty.json()


def test_log_by_id_isolation(tenant_client):
    client, key_a, key_b, ids = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    own = client.get(f"/logs/{ids['111111111111']}", headers=headers_a)
    hidden = client.get(f"/logs/{ids['111111111111']}", headers=headers_b)
    missing = client.get('/logs/999999999', headers=headers_b)
    assert own.status_code == 200
    assert own.json()['id'] == ids['111111111111']
    assert (hidden.status_code, hidden.json()) == (missing.status_code, missing.json())


def test_log_by_uuid_isolation(tenant_client):
    client, key_a, key_b, _ = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    own = client.get('/logs/by-uuid/a-uuid', headers=headers_a)
    hidden = client.get('/logs/by-uuid/a-uuid', headers=headers_b)
    missing = client.get('/logs/by-uuid/nonexistent-analysis', headers=headers_b)
    assert own.status_code == 200
    assert own.json()['findings_json']
    assert (hidden.status_code, hidden.json()) == (missing.status_code, missing.json())


def test_graph_by_analysis_id_isolation(tenant_client):
    client, key_a, key_b, _ = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    own = client.get('/egraph/a-uuid', headers=headers_a)
    hidden = client.get('/egraph/a-uuid', headers=headers_b)
    missing = client.get('/egraph/nonexistent-analysis', headers=headers_b)
    assert own.status_code == 200
    assert own.json()['analysis_id'] == 'a-uuid'
    assert (hidden.status_code, hidden.json()) == (missing.status_code, missing.json())


def test_compliance_by_analysis_id_isolation(tenant_client):
    client, key_a, key_b, _ = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    own = client.get('/compliance/a-uuid', headers=headers_a)
    hidden = client.get('/compliance/a-uuid', headers=headers_b)
    missing = client.get('/compliance/nonexistent-analysis', headers=headers_b)
    assert own.status_code == 200
    assert own.json()['analysis_id'] == 'a-uuid'
    assert (hidden.status_code, hidden.json()) == (missing.status_code, missing.json())
