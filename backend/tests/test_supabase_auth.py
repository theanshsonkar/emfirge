import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import auth, database
from app.main import app
from tests.supabase_fake import TEST_SUPABASE_URL, JWKS, make_token, unsigned_token, hs256_with_key


@pytest.fixture
def client(shared_test_db, supabase_env):
    return TestClient(app)


def project(client, token, header='Authorization'):
    return client.get('/project', headers={header: f'Bearer {token}'}).json()


def test_valid_es256_token_returns_project(client):
    result = project(client, make_token('user-es'))
    assert result['mode'] == 'hosted'
    assert result['project'].startswith('sb-user-es')
    assert result['external_id']


def test_valid_rs256_token_returns_project(client):
    result = project(client, make_token('user-rs', alg='RS256'))
    assert result['mode'] == 'hosted'
    assert result['external_id']


def test_same_sub_reuses_project_and_external_id_different_sub_isolated(client):
    a = project(client, make_token('same'))
    again = project(client, make_token('same'))
    b = project(client, make_token('other'))
    assert (a['project'], a['external_id']) == (again['project'], again['external_id'])
    assert a['project'] != b['project']
    assert a['external_id'] != b['external_id']


def test_jwt_in_x_api_key_header_works(client):
    token = make_token('x-api-key-user')
    response = client.get('/project', headers={'X-API-Key': token})
    assert response.status_code == 200
    assert response.json()['external_id']


def test_supabase_identity_has_only_minimal_columns(shared_test_db):
    columns = {column['name'] for column in inspect(shared_test_db.kw['bind'] if False else database.engine).get_columns('supabase_identities')}
    assert columns == {'id', 'supabase_user_id', 'project_id', 'created_at'}


def test_unset_supabase_url_rejects_valid_token(client, monkeypatch):
    monkeypatch.delenv('SUPABASE_URL')
    response = client.get('/project', headers={'Authorization': f'Bearer {make_token("unset")}'} )
    assert response.status_code == 401


def test_jwks_failure_returns_503(client, monkeypatch):
    from app import supabase_auth
    monkeypatch.setattr(supabase_auth, '_jwks_fetcher', lambda base: (_ for _ in ()).throw(RuntimeError('down')))
    supabase_auth.reset_jwks_cache()
    response = client.get('/project', headers={'Authorization': f'Bearer {make_token("down")}'} )
    assert response.status_code == 503
    assert response.json() == {'detail': 'Sign-in is temporarily unavailable'}


def test_tokens_never_appear_in_logs_or_output(client, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    valid = make_token('logging-valid')
    invalid = valid + 'x'
    client.get('/project', headers={'Authorization': f'Bearer {valid}'})
    client.get('/project', headers={'Authorization': f'Bearer {invalid}'})
    output = capsys.readouterr()
    assert valid not in caplog.text and invalid not in caplog.text
    assert valid not in output.out and valid not in output.err
    assert invalid not in output.out and invalid not in output.err


def test_existing_api_keys_still_work(client):
    key = auth.create_api_key('legacy-project')
    response = client.get('/project', headers={'X-API-Key': key})
    assert response.status_code == 200
    assert response.json()['project'] == 'legacy-project'


@pytest.mark.parametrize('case', [
    'expired', 'wrong_iss', 'wrong_aud', 'bad_signature', 'unknown_kid', 'none',
    'hs256_random', 'hs256_ec_public', 'missing_sub', 'missing_exp', 'anonymous', 'anon_role', 'garbage',
])
def test_l22_invalid_tokens_match_bad_api_key(client, case, fake_keys):
    baseline = client.get('/project', headers={'X-API-Key': 'bogus'}).json()
    ec_key, _ = fake_keys
    if case == 'expired': token = make_token('bad', exp_delta=-3600)
    elif case == 'wrong_iss': token = make_token('bad', iss='https://wrong/auth/v1')
    elif case == 'wrong_aud': token = make_token('bad', aud='anon')
    elif case == 'bad_signature': token = make_token('bad', key=ec.generate_private_key(ec.SECP256R1()))
    elif case == 'unknown_kid': token = make_token('bad', kid='unknown')
    elif case == 'none': token = unsigned_token({'sub': 'bad', 'iss': f'{TEST_SUPABASE_URL}/auth/v1', 'aud': 'authenticated', 'exp': 9999999999})
    elif case == 'hs256_random': token = make_token('bad', alg='HS256', kid='test-ec', key='random-secret')
    elif case == 'hs256_ec_public':
        pem = ec_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        token = hs256_with_key({'sub': 'bad'}, pem)
    elif case == 'missing_sub': token = make_token('bad', drop=('sub',))
    elif case == 'missing_exp': token = make_token('bad', drop=('exp',))
    elif case == 'anonymous': token = make_token('bad', extra={'is_anonymous': True})
    elif case == 'anon_role': token = make_token('bad', extra={'role': 'anon'})
    else: token = 'a.b.c'
    response = client.get('/project', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 401
    assert response.json() == baseline
