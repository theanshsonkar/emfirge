import boto3
from moto import mock_aws

from app import trusted_account
from tests.supabase_fake import make_token


def project(client, token):
    response = client.get('/project', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    return response.json()


def reset_cache():
    trusted_account._cached_account_id = None


def test_env_override_wins(client, monkeypatch):
    reset_cache()
    monkeypatch.setenv('EMFIRGE_TRUSTED_ACCOUNT_ID', '222222222222')
    assert project(client, make_token('trusted-env'))['trusted_account_id'] == '222222222222'


def test_sts_fallback_with_moto(client, monkeypatch):
    reset_cache()
    monkeypatch.delenv('EMFIRGE_TRUSTED_ACCOUNT_ID', raising=False)
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
    with mock_aws():
        boto3.client('sts', region_name='us-east-1').get_caller_identity()
        assert project(client, make_token('trusted-moto'))['trusted_account_id'] == '123456789012'


def test_sts_failure_returns_null(client, monkeypatch):
    reset_cache()
    monkeypatch.delenv('EMFIRGE_TRUSTED_ACCOUNT_ID', raising=False)
    monkeypatch.setattr(trusted_account.boto3, 'client', lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('STS down')))
    result = client.get('/project', headers={'Authorization': f'Bearer {make_token("trusted-failure")}'} )
    assert result.status_code == 200
    assert result.json()['trusted_account_id'] is None


def test_invalid_env_ignored(client, monkeypatch):
    reset_cache()
    monkeypatch.setenv('EMFIRGE_TRUSTED_ACCOUNT_ID', 'abc')
    sts = type('StsStub', (), {'get_caller_identity': lambda self: {'Account': '333333333333'}})()
    monkeypatch.setattr(trusted_account.boto3, 'client', lambda *args, **kwargs: sts)
    assert project(client, make_token('trusted-invalid-env'))['trusted_account_id'] == '333333333333'


def test_cached_after_success(client, monkeypatch):
    reset_cache()
    monkeypatch.delenv('EMFIRGE_TRUSTED_ACCOUNT_ID', raising=False)
    calls = []

    class StsStub:
        def get_caller_identity(self):
            calls.append(1)
            return {'Account': '333333333333'}

    monkeypatch.setattr(trusted_account.boto3, 'client', lambda *args, **kwargs: StsStub())
    token = make_token('trusted-cached')
    assert project(client, token)['trusted_account_id'] == '333333333333'
    assert project(client, token)['trusted_account_id'] == '333333333333'
    assert len(calls) == 1
