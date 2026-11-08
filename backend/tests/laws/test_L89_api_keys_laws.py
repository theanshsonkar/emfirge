"""L89: a signed-in user can make, list and revoke API keys for their own project.

L89a  create returns the raw key once; list never shows a key or hash; the stored row holds only the hash
L89b  a created key authenticates; a revoked key stops working at once
L89c  project A cannot list or revoke project B's keys (404, and B's key keeps working)
L89d  at most 10 active keys per project (409); revoking frees a slot
L89e  every route needs a signed-in caller (no key, no access); self-host mode gets a clear refusal
L89f  works for a sign-in token caller too, and the CLI manifest describes the three commands
"""
import re

import pytest
from fastapi.testclient import TestClient

from app import auth, database
from app.cli_manifest import build_manifest
from app.database import APIKey
from app.main import app

KEY_RE = re.compile(r"^emf_[A-Za-z0-9_-]{20,}$")


@pytest.fixture
def client(shared_test_db, monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    return TestClient(app)


def _h(key):
    return {'Authorization': f'Bearer {key}'}


def _login(name):
    return auth.create_api_key(name)


def test_L89a_create_returns_key_once_and_list_hides_it(client):
    boot = _login('l89a-proj')
    r = client.post('/auth/api-keys', headers=_h(boot), json={'name': 'ci runner'})
    assert r.status_code == 200, r.text
    body = r.json()
    assert KEY_RE.match(body['key'])
    assert set(body) == {'key', 'key_id', 'prefix', 'created_at', 'warning'}
    assert body['prefix'] == body['key'][4:12]
    assert 'only time' in body['warning']
    listing = client.get('/auth/api-keys', headers=_h(boot))
    assert listing.status_code == 200
    text = listing.text
    assert body['key'] not in text and auth.hash_key(body['key']) not in text and 'emf_' not in text
    row = next(k for k in listing.json()['keys'] if k['key_id'] == body['key_id'])
    assert set(row) == {'key_id', 'name', 'prefix', 'created_at', 'last_used_at', 'active'}
    assert row['active'] is True and row['name'] == 'ci runner' and row['prefix'] == body['prefix']
    assert next(k for k in listing.json()['keys'] if k['key_id'] != body['key_id'])['name'] is None
    db = database.SessionLocal()
    try:
        stored = db.get(APIKey, body['key_id'])
        assert stored.key_hash == auth.hash_key(body['key'])
        assert body['key'] not in repr(stored.__dict__)
        assert stored.project_name == 'l89a-proj'
    finally:
        db.close()


def test_L89a_name_is_optional_and_bounded(client):
    boot = _login('l89a-name')
    assert client.post('/auth/api-keys', headers=_h(boot)).status_code == 200  # no body at all
    assert client.post('/auth/api-keys', headers=_h(boot), json={'name': 'x' * 81}).status_code == 422
    assert client.post('/auth/api-keys', headers=_h(boot), json={'name': 7}).status_code == 422


def test_L89b_new_key_works_and_revoked_key_stops(client):
    boot = _login('l89b-proj')
    made = client.post('/auth/api-keys', headers=_h(boot), json={}).json()
    new = made['key']
    assert client.get('/auth/api-keys', headers=_h(new)).status_code == 200
    assert client.get('/project', headers=_h(new)).status_code == 200
    for r in (client.delete(f"/auth/api-keys/{made['key_id']}", headers=_h(boot)),):
        assert r.status_code == 200 and r.json()['active'] is False
    assert client.get('/project', headers=_h(new)).status_code == 401
    assert client.get('/auth/api-keys', headers=_h(new)).status_code == 401
    # revoking again is harmless
    assert client.delete(f"/auth/api-keys/{made['key_id']}", headers=_h(boot)).status_code == 200
    listing = client.get('/auth/api-keys', headers=_h(boot)).json()['keys']
    assert next(k for k in listing if k['key_id'] == made['key_id'])['active'] is False


def test_L89b_post_revoke_alias_for_clients_without_delete(client):
    boot = _login('l89b2-proj')
    made = client.post('/auth/api-keys', headers=_h(boot), json={}).json()
    r = client.post(f"/auth/api-keys/{made['key_id']}/revoke", headers=_h(boot))
    assert r.status_code == 200 and r.json() == {'key_id': made['key_id'], 'active': False}
    assert client.get('/project', headers=_h(made['key'])).status_code == 401


def test_L89c_projects_cannot_touch_each_others_keys(client):
    a, b = _login('l89c-a'), _login('l89c-b')
    kb = client.post('/auth/api-keys', headers=_h(b), json={}).json()
    keys_a = client.get('/auth/api-keys', headers=_h(a)).json()['keys']
    assert kb['key_id'] not in {k['key_id'] for k in keys_a}
    for r in (client.delete(f"/auth/api-keys/{kb['key_id']}", headers=_h(a)),
              client.post(f"/auth/api-keys/{kb['key_id']}/revoke", headers=_h(a))):
        assert r.status_code == 404
    assert client.get('/project', headers=_h(kb['key'])).status_code == 200
    assert client.delete('/auth/api-keys/999999', headers=_h(a)).status_code == 404


def test_L89d_ten_active_keys_per_project(client):
    boot = _login('l89d-proj')  # the bootstrap key counts as one active key
    made = []
    for _ in range(9):
        r = client.post('/auth/api-keys', headers=_h(boot), json={})
        assert r.status_code == 200, r.text
        made.append(r.json())
    r = client.post('/auth/api-keys', headers=_h(boot), json={})
    assert r.status_code == 409
    assert 'emf_' not in r.text
    client.delete(f"/auth/api-keys/{made[0]['key_id']}", headers=_h(boot))
    assert client.post('/auth/api-keys', headers=_h(boot), json={}).status_code == 200


def test_L89e_every_route_needs_a_caller(client):
    for method, path in (('post', '/auth/api-keys'), ('get', '/auth/api-keys'),
                         ('delete', '/auth/api-keys/1'), ('post', '/auth/api-keys/1/revoke')):
        assert getattr(client, method)(path).status_code == 401, (method, path)
        assert getattr(client, method)(path, headers=_h('emf_nope')).status_code == 401, (method, path)


def test_L89e_self_host_has_no_project_to_hold_keys(shared_test_db, monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    c = TestClient(app)
    assert c.post('/auth/api-keys', json={}).status_code == 400
    assert c.get('/auth/api-keys').status_code == 400


def test_L89f_sign_in_token_caller_gets_keys_for_its_own_project(shared_test_db, monkeypatch, supabase_env):
    from tests.supabase_fake import make_token
    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    c = TestClient(app)
    tok_a, tok_b = make_token('l89f-a'), make_token('l89f-b')
    made = c.post('/auth/api-keys', headers=_h(tok_a), json={})
    assert made.status_code == 200, made.text
    key = made.json()['key']
    db = database.SessionLocal()
    try:
        assert db.get(APIKey, made.json()['key_id']).project_name == 'sb-l89f-a'
    finally:
        db.close()
    assert c.get('/auth/api-keys', headers=_h(key)).status_code == 200
    assert c.delete(f"/auth/api-keys/{made.json()['key_id']}", headers=_h(tok_b)).status_code == 404


def test_L89f_manifest_describes_key_commands():
    cmds = {c['name']: c for c in build_manifest()['commands']}
    create, lst, revoke = cmds['key create'], cmds['key list'], cmds['key revoke']
    assert create['request'] == {'method': 'POST', 'path': '/auth/api-keys', 'body': {'name': 'name'}}
    assert lst['request'] == {'method': 'GET', 'path': '/auth/api-keys'}
    assert revoke['request']['method'] == 'POST' and revoke['request']['path'] == '/auth/api-keys/{key-id}/revoke'
    text = create['summary'] + ' '.join(create.get('usage', [])) + ' '.join(a['help'] for a in create['args'])
    assert ("Store it as EMFIRGE_API_KEY in your environment's secret settings. "
            "Never paste it into a chat or commit it.") in text
    assert create['response'] == {'reveal': ['key']}
    for name, c in cmds.items():
        assert ('reveal' in c.get('response', {})) == (name == 'key create'), name
