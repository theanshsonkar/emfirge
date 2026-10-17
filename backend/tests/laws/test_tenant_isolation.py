import json

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app import auth, database
from app.auth import get_caller, legacy_ci_enabled
from app.database import AccountBinding, AnalysisLog, DriftEvent, Project
from app.main import app


@pytest.fixture(params=['api_key', 'supabase_jwt'], ids=['api_key', 'supabase_jwt'])
def tenant_client(shared_test_db, monkeypatch, request, supabase_env):
    mode = request.param
    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    client = TestClient(app)
    if mode == 'supabase_jwt':
        from tests.supabase_fake import make_token
        key_a = make_token('tenant-law-a')
        key_b = make_token('tenant-law-b')
        name_a, name_b = 'sb-tenant-law-a', 'sb-tenant-law-b'
    else:
        key_a = auth.create_api_key('tenant-law-a')
        key_b = auth.create_api_key('tenant-law-b')
        name_a, name_b = 'tenant-law-a', 'tenant-law-b'
    client.get('/project', headers={'X-API-Key': key_a})
    client.get('/project', headers={'X-API-Key': key_b})
    db = database.SessionLocal()
    try:
        pa = db.query(Project).filter_by(name=name_a).one()
        pb = db.query(Project).filter_by(name=name_b).one()
        db.add_all([
            AccountBinding(aws_account_id='111111111111', project_id=pa.id),
            AccountBinding(aws_account_id='222222222222', project_id=pb.id),
            AnalysisLog(aws_account_id='111111111111', findings_json=json.dumps({'analysis_id': 'a-uuid'})),
            AnalysisLog(aws_account_id='222222222222', findings_json=json.dumps({'analysis_id': 'b-uuid'})),
            DriftEvent(aws_account_id='111111111111', rule_id='a'),
            DriftEvent(aws_account_id='222222222222', rule_id='b'),
        ])
        db.commit()
        ids = {row.aws_account_id: row.id for row in db.query(AnalysisLog).all()}
    finally:
        db.close()
    return client, key_a, key_b, ids


def test_hosted_lists_and_details_are_scoped(tenant_client):
    client, key_a, _, ids = tenant_client
    headers = {'X-API-Key': key_a}
    assert {row['id'] for row in client.get('/logs', headers=headers).json()['logs']} == {ids['111111111111']}
    assert {row['id'] for row in client.get('/history', headers=headers).json()['scans']} == {ids['111111111111']}
    assert {row['aws_account_id'] for row in client.get('/drift/events', headers=headers).json()['events']} == {'111111111111'}
    assert client.get(f"/logs/{ids['222222222222']}", headers=headers).json() == {'detail': 'Log not found'}
    assert client.get('/logs/by-uuid/b-uuid', headers=headers).json() == {'detail': 'Analysis not found'}
    assert client.get('/logs?account_id=222222222222', headers=headers).json() == {'logs': [], 'count': 0}


def test_self_host_remains_unrestricted(tenant_client, monkeypatch):
    client, _, _, _ = tenant_client
    monkeypatch.setattr(auth, 'AUTH_ENABLED', False)
    assert len(client.get('/logs').json()['logs']) == 2


def test_tenant_routes_have_caller_dependency():
    public = {'/', '/health', '/admin/account-bindings/{aws_account_id}', '/feedback', '/docs', '/docs/oauth2-redirect', '/openapi.json', '/redoc', '/auth/link-project'}  # self-authenticating: requires Supabase token AND API key

    def has_dependency(deps, dependency):
        return any(dep.call is dependency or has_dependency(dep.dependencies, dependency) for dep in deps)

    def has_caller(deps):
        return has_dependency(deps, get_caller)

    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in public:
            continue
        if route.path.startswith('/ci/') or (route.path.startswith('/github/') and route.path != '/github/install-url'):
            assert has_dependency(route.dependant.dependencies, legacy_ci_enabled), route.path
        else:
            assert has_caller(route.dependant.dependencies), route.path
