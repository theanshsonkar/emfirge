"""Route-level laws for project-scoped rate-limit keys."""

import pytest
from fastapi.testclient import TestClient

from app import auth, main
from app.main import app

from .test_tenant_isolation import tenant_client


IP1 = ('203.0.113.1', 50000)
IP2 = ('203.0.113.2', 50001)

_PAYLOADS = {
    'simulate': {'analysis_id': 'missing-analysis', 'query': 'test'},
    'insight': {
        'severity': 'high', 'issue': 'open access', 'recommendation': 'restrict access',
        'aws_service': 'ec2',
    },
    'terraform': {
        'severity': 'high', 'issue': 'open access', 'recommendation': 'restrict access',
        'aws_service': 'ec2',
    },
    'unified-fix': {
        'severity': 'high', 'issue': 'open access', 'recommendation': 'restrict access',
        'aws_service': 'ec2', 'rule_id': 'EMFIRGE-EC2-002',
    },
    'github-pr': {
        'installation_id': 1, 'repo': 'example/repo',
        'finding': {'resource_id': 'sg-1', 'resource_type': 'security_group', 'aws_service': 'ec2'},
        'hcl': 'resource "aws_security_group" "fix" {}',
    },
}

ROUTES = (
    pytest.param('simulate', '/simulate', 'post', '_SIMULATE_LIMIT', main._simulate_request_log, id='simulate'),
    pytest.param('insight', '/remediation/generate-insight', 'post', '_INSIGHT_LIMIT', main._insight_request_log, id='insight'),
    pytest.param('terraform', '/remediation/generate-terraform', 'post', '_TERRAFORM_LIMIT', main._terraform_request_log, id='terraform-generate'),
    pytest.param('unified-fix', '/remediation/fix', 'post', '_TERRAFORM_LIMIT', main._terraform_request_log, id='terraform-unified-fix'),
    pytest.param('github-pr', '/github/pr', 'post', '_PR_LIMIT', main._pr_request_log, id='github-pr'),
)


def _headers(key=None, **extra):
    headers = dict(extra)
    if key is not None:
        headers['X-API-Key'] = key
    return headers


def _client(address):
    return TestClient(app, client=address)


def _request(client, route, headers):
    return getattr(client, route[2])(route[1], headers=headers, json=_PAYLOADS[route[0]])


@pytest.fixture(autouse=True)
def rate_law_setup(monkeypatch):
    # The GitHub route has a legacy feature gate, but its rate limiter is still
    # a migrated route contract that must be exercised here.
    app.dependency_overrides[auth.legacy_ci_enabled] = lambda: None
    for log in (main._insight_request_log, main._terraform_request_log,
                main._pr_request_log, main._simulate_request_log,
                main._feedback_request_log):
        log.clear()
    monkeypatch.setattr(main, 'get_llm_usage_count_today', lambda *args: 0)
    monkeypatch.setattr(main, 'get_simulation_count_today', lambda *args: 0)
    monkeypatch.setattr(main, 'save_feedback', lambda **kwargs: 1)
    import app.github_service as github_service
    monkeypatch.setattr(github_service, 'get_github_client', lambda installation_id: object())
    monkeypatch.setattr(github_service, 'search_tf_files', lambda *args: [])
    monkeypatch.setattr(github_service, 'create_fix_pr', lambda *args, **kwargs: {'pr_url': 'https://example.invalid/pr/1', 'pr_number': 1, 'branch': 'fix'})
    monkeypatch.setattr(main, 'get_tf_index', lambda *args: [])
    yield
    app.dependency_overrides.pop(auth.legacy_ci_enabled, None)
    for log in (main._insight_request_log, main._terraform_request_log,
                main._pr_request_log, main._simulate_request_log,
                main._feedback_request_log):
        log.clear()


@pytest.mark.parametrize('route_name,path,method,limit_name,log', ROUTES)
def test_l1_projects_same_ip_are_isolated(route_name, path, method, limit_name, log, tenant_client, monkeypatch):
    route = (route_name, path, method, limit_name, log)
    _, key_a, key_b, _ = tenant_client
    expected_limit = 2 if route_name != 'simulate' or getattr(main, limit_name, None) == 10 else 10
    monkeypatch.setattr(main, limit_name, 2, raising=False)
    client = _client(IP1)
    for _ in range(expected_limit):
        assert _request(client, route, _headers(key_a)).status_code != 429
    assert _request(client, route, _headers(key_a)).status_code == 429
    assert _request(client, route, _headers(key_b)).status_code != 429


@pytest.mark.parametrize('route_name,path,method,limit_name,log', ROUTES)
def test_l2_project_shares_bucket_across_ips(route_name, path, method, limit_name, log, tenant_client, monkeypatch):
    route = (route_name, path, method, limit_name, log)
    _, key_a, _, _ = tenant_client
    expected_limit = 2 if route_name != 'simulate' or getattr(main, limit_name, None) == 10 else 10
    monkeypatch.setattr(main, limit_name, 2, raising=False)
    for _ in range(expected_limit):
        assert _request(_client(IP1), route, _headers(key_a)).status_code != 429
    assert _request(_client(IP2), route, _headers(key_a)).status_code == 429


@pytest.mark.parametrize('route_name,path,method,limit_name,log', ROUTES)
def test_l3_proxy_headers_cannot_change_bucket(route_name, path, method, limit_name, log, tenant_client, monkeypatch):
    route = (route_name, path, method, limit_name, log)
    expected_limit = 2 if route_name != 'simulate' or getattr(main, limit_name, None) == 10 else 10
    monkeypatch.setattr(main, limit_name, 2, raising=False)
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    client = _client(IP1)
    for n in range(expected_limit + 1):
        spoof = {
            'X-Forwarded-For': f'198.51.100.{n}',
            'X-Real-IP': f'198.51.101.{n}',
            'CF-Connecting-IP': f'198.51.102.{n}',
            'Forwarded': f'for=198.51.103.{n}',
        }
        response = _request(client, route, _headers(**spoof))
        assert response.status_code != 429 if n < expected_limit else response.status_code == 429

    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    main._insight_request_log.clear(); main._terraform_request_log.clear()
    main._pr_request_log.clear(); main._simulate_request_log.clear()
    _, key_a, _, _ = tenant_client
    assert _request(client, route, _headers(key_a)).status_code != 429
    assert _request(client, route, _headers(key_a)).status_code != 429
    response = _request(client, route, _headers(
        key_a, **{'X-Forwarded-For': '10.0.0.1', 'X-Real-IP': '10.0.0.2',
                  'CF-Connecting-IP': '10.0.0.3', 'Forwarded': 'for=10.0.0.4',
                  'X-Project-Id': '999999'}))
    assert response.status_code == 429


@pytest.mark.parametrize('route_name,path,method,limit_name,log', ROUTES)
def test_l4_failed_auth_does_not_consume_bucket(route_name, path, method, limit_name, log, tenant_client, monkeypatch):
    route = (route_name, path, method, limit_name, log)
    _, key_a, _, _ = tenant_client
    monkeypatch.setattr(main, limit_name, 2, raising=False)
    client = _client(IP1)
    for _ in range(3):
        assert _request(client, route, _headers('bad-token')).status_code == 401
    assert _request(client, route, _headers(key_a)).status_code != 429
    assert _request(client, route, _headers(key_a)).status_code != 429


def test_kept_feedback_limiter_remains_per_ip(monkeypatch):
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    body = {'message': 'Useful feedback'}
    client_1 = _client(IP1)
    for _ in range(5):
        assert client_1.post('/feedback', json=body).status_code == 200
    assert client_1.post('/feedback', json=body).status_code == 429
    assert _client(IP2).post('/feedback', json=body).status_code == 200
