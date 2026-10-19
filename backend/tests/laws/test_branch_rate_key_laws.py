import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.main import app

from .test_tenant_isolation import tenant_client


IP1 = ('203.0.113.1', 50000)
IP2 = ('203.0.113.2', 50001)


def _headers(key=None, **extra):
    headers = dict(extra)
    if key is not None:
        headers['X-API-Key'] = key
    return headers


def _client(address):
    return TestClient(app, client=address)


@pytest.fixture(autouse=True)
def branch_rate_law_setup(monkeypatch):
    monkeypatch.setenv('EMFIRGE_BRANCH_RATE_LIMIT', '2')
    main._branch_request_log.clear()
    yield
    main._branch_request_log.clear()


def test_l_rl1_project_isolation(tenant_client):
    _, key_a, key_b, _ = tenant_client
    client = _client(IP1)
    headers_a = _headers(key_a)
    assert client.get('/branches', headers=headers_a).status_code == 200
    assert client.get('/branches', headers=headers_a).status_code == 200
    assert client.get('/branches', headers=headers_a).status_code == 429
    assert client.get('/branches', headers=_headers(key_b)).status_code == 200


def test_l_rl2_same_project_shares_bucket_across_ips(tenant_client):
    _, key_a, _, _ = tenant_client
    assert _client(IP1).get('/branches', headers=_headers(key_a)).status_code == 200
    assert _client(IP1).get('/branches', headers=_headers(key_a)).status_code == 200
    assert _client(IP2).get('/branches', headers=_headers(key_a)).status_code == 429


def test_l_rl3_spoofed_proxy_headers_ignored(tenant_client, monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    client = _client(IP1)
    for n in range(3):
        response = client.get('/branches', headers=_headers(
            **{'X-Forwarded-For': f'198.51.100.{n}', 'X-Real-IP': f'198.51.101.{n}',
               'CF-Connecting-IP': f'198.51.102.{n}', 'Forwarded': f'for=198.51.103.{n}'}))
        assert response.status_code == (200 if n < 2 else 429)

    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    main._branch_request_log.clear()
    client.get('/branches', headers=_headers(tenant_client[1]))
    client.get('/branches', headers=_headers(tenant_client[1]))
    assert client.get('/branches', headers=_headers(
        tenant_client[1], **{'X-Forwarded-For': '10.0.0.1', 'X-Real-IP': '10.0.0.2',
                              'CF-Connecting-IP': '10.0.0.3', 'Forwarded': 'for=10.0.0.4',
                              'X-Project-Id': '999999'})).status_code == 429


def test_l_rl4_unauthenticated_fallback_is_client_ip(tenant_client, monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    assert _client(IP1).get('/branches').status_code == 200
    assert _client(IP1).get('/branches').status_code == 200
    assert _client(IP1).get('/branches').status_code == 429
    assert _client(IP2).get('/branches').status_code == 200


def test_l_rl5_failed_auth_cannot_burn_project_bucket(tenant_client):
    _, key_a, _, _ = tenant_client
    client = _client(IP1)
    for _ in range(3):
        assert client.get('/branches', headers=_headers('bad-token')).status_code == 401
    assert client.get('/branches', headers=_headers(key_a)).status_code == 200
    assert client.get('/branches', headers=_headers(key_a)).status_code == 200


def test_l_rl6_rate_limit_contract(tenant_client, monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    client = _client(IP1)
    assert client.get('/branches').status_code == 200
    assert client.get('/branches').status_code == 200
    response = client.get('/branches')
    assert response.status_code == 429
    assert 'Retry in' in response.json()['detail']
    assert int(response.headers['Retry-After']) > 0
