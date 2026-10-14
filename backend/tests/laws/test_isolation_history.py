from app import auth

from .test_tenant_isolation import tenant_client


def _empty_project_headers(client):
    key = auth.create_api_key('tenant-law-empty')
    client.get('/project', headers={'X-API-Key': key})
    return {'X-API-Key': key}


def test_logs_list_hides_other_tenant(tenant_client):
    client, key_a, key_b, ids = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    headers_empty = _empty_project_headers(client)

    own = client.get('/logs?account_id=111111111111', headers=headers_a)
    hidden = client.get('/logs?account_id=111111111111', headers=headers_b)
    empty = client.get('/logs', headers=headers_empty)
    never_seen = client.get('/logs?account_id=999999999999', headers=headers_b)

    assert own.status_code == 200
    assert {row['id'] for row in own.json()['logs']} == {ids['111111111111']}
    assert hidden.status_code == empty.status_code == never_seen.status_code == 200
    assert hidden.json() == empty.json() == never_seen.json()
    assert str(ids['111111111111']) not in str(hidden.json())


def test_history_list_hides_other_tenant(tenant_client):
    client, key_a, key_b, ids = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}
    headers_empty = _empty_project_headers(client)

    own = client.get('/history?account_id=111111111111', headers=headers_a)
    hidden = client.get('/history?account_id=111111111111', headers=headers_b)
    empty = client.get('/history', headers=headers_empty)
    never_seen = client.get('/history?account_id=999999999999', headers=headers_b)

    assert own.status_code == 200
    assert {row['id'] for row in own.json()['scans']} == {ids['111111111111']}
    assert hidden.status_code == empty.status_code == never_seen.status_code == 200
    assert hidden.json() == empty.json() == never_seen.json()
    assert str(ids['111111111111']) not in str(hidden.json())


def test_log_detail_hides_other_tenant(tenant_client):
    client, key_a, key_b, ids = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}

    own = client.get(f"/logs/{ids['111111111111']}", headers=headers_a)
    hidden = client.get(f"/logs/{ids['111111111111']}", headers=headers_b)
    never_seen = client.get('/logs/999999999', headers=headers_b)

    assert own.status_code == 200
    assert own.json()['id'] == ids['111111111111']
    assert hidden.status_code == never_seen.status_code == 404
    assert hidden.json() == never_seen.json() == {'detail': 'Log not found'}


def test_log_uuid_detail_hides_other_tenant(tenant_client):
    client, key_a, key_b, _ = tenant_client
    headers_a = {'X-API-Key': key_a}
    headers_b = {'X-API-Key': key_b}

    own = client.get('/logs/by-uuid/a-uuid', headers=headers_a)
    hidden = client.get('/logs/by-uuid/a-uuid', headers=headers_b)
    never_seen = client.get('/logs/by-uuid/never-seen', headers=headers_b)

    assert own.status_code == 200
    assert 'a-uuid' in own.json()['findings_json']
    assert hidden.status_code == never_seen.status_code == 404
    assert hidden.json() == never_seen.json() == {'detail': 'Analysis not found'}
