import logging

import logging

from app import trusted_account
from tests.supabase_fake import make_token


STS_ACCOUNT = "222222222222"
ENV_ACCOUNT = "111111111111"


def reset_cache():
    trusted_account._cached_account_id = None


def sts_stub(account=None, error=None):
    class StsStub:
        def get_caller_identity(self):
            if error is not None:
                raise error
            return {"Account": account}

    return StsStub()


def test_sts_wins_over_different_env_and_warns(monkeypatch, caplog):
    reset_cache()
    monkeypatch.setenv("EMFIRGE_TRUSTED_ACCOUNT_ID", ENV_ACCOUNT)
    monkeypatch.setattr(
        trusted_account.boto3, "client", lambda *args, **kwargs: sts_stub(STS_ACCOUNT)
    )

    with caplog.at_level(logging.WARNING):
        assert trusted_account.verified_trusted_account_id() == STS_ACCOUNT

    assert "EMFIRGE_TRUSTED_ACCOUNT_ID does not match the server credentials account; using the credentials account" in caplog.text
    assert ENV_ACCOUNT not in caplog.text
    assert STS_ACCOUNT not in caplog.text


def test_env_is_used_when_sts_raises(monkeypatch):
    reset_cache()
    monkeypatch.setenv("EMFIRGE_TRUSTED_ACCOUNT_ID", ENV_ACCOUNT)
    monkeypatch.setattr(
        trusted_account.boto3,
        "client",
        lambda *args, **kwargs: sts_stub(error=RuntimeError("STS down")),
    )

    assert trusted_account.verified_trusted_account_id() == ENV_ACCOUNT


def test_sts_is_used_without_env(monkeypatch):
    reset_cache()
    monkeypatch.delenv("EMFIRGE_TRUSTED_ACCOUNT_ID", raising=False)
    monkeypatch.setattr(
        trusted_account.boto3, "client", lambda *args, **kwargs: sts_stub(STS_ACCOUNT)
    )

    assert trusted_account.verified_trusted_account_id() == STS_ACCOUNT


def test_both_sts_and_env_fail(monkeypatch):
    reset_cache()
    monkeypatch.setenv("EMFIRGE_TRUSTED_ACCOUNT_ID", "not-an-account")
    monkeypatch.setattr(
        trusted_account.boto3,
        "client",
        lambda *args, **kwargs: sts_stub(error=RuntimeError("STS down")),
    )

    assert trusted_account.verified_trusted_account_id() is None


def test_project_reports_sts_account_when_env_differs(client, monkeypatch):
    reset_cache()
    monkeypatch.setenv("EMFIRGE_TRUSTED_ACCOUNT_ID", ENV_ACCOUNT)
    monkeypatch.setattr(
        trusted_account.boto3, "client", lambda *args, **kwargs: sts_stub(STS_ACCOUNT)
    )

    response = client.get(
        "/project", headers={"Authorization": f"Bearer {make_token('trusted-truth')}"}
    )

    assert response.status_code == 200
    assert response.json()["trusted_account_id"] == STS_ACCOUNT
