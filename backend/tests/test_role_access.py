import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from app import role_access
from app.database import AccountBinding, AccountBindingEvent, Project
from app.auth import Caller


@pytest.fixture
def db_session(shared_test_db):
    session = shared_test_db()
    try:
        yield session
    finally:
        session.close()


ROLE = 'arn:aws:iam::123456789012:role/Emfirge'


class FakeSTS:
    def __init__(self, accepted):
        self.accepted = accepted
        self.calls = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        accepted = self.accepted
        external_id = kwargs['ExternalId']
        if accepted != 'ANY' and external_id not in accepted:
            raise ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'denied'}},
                'AssumeRole',
            )
        return {'Credentials': {'AccessKeyId': 'a', 'SecretAccessKey': 's', 'SessionToken': 't'}}


def caller(project_id=1, name='a', external_id='project-a'):
    return Caller('hosted', project_id, name, external_id)


def test_invalid_arn_is_rejected(db_session, monkeypatch):
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role('not-an-arn', caller(), db_session)
    assert exc.value.status_code == 400


def test_failed_unbound_attempt_does_not_bind(db_session, monkeypatch):
    sts = FakeSTS({'project-a'})
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException):
        role_access.assume_customer_role(ROLE, caller(external_id='wrong'), db_session)
    assert db_session.query(AccountBinding).count() == 0


def test_any_external_id_is_unsafe(db_session, monkeypatch):
    sts = FakeSTS('ANY')
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(ROLE, caller(), db_session)
    assert exc.value.status_code == 403
    assert exc.value.detail == role_access.UNSAFE_DETAIL
    assert db_session.query(AccountBinding).count() == 0


def test_success_binds_account_and_reuses_binding(db_session, monkeypatch):
    sts = FakeSTS({'project-a'})
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    role_access.assume_customer_role(ROLE, caller(), db_session)
    assert db_session.query(AccountBinding).count() == 1
    assert db_session.query(AccountBindingEvent).filter_by(action='bind').count() == 1
    role_access.assume_customer_role(ROLE, caller(), db_session)
    assert len(sts.calls) == 3  # real + random probe, then real


def test_probe_non_access_denied_error_returns_503_without_binding(db_session, monkeypatch):
    class FailingSTS:
        def __init__(self):
            self.calls = []

        def assume_role(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                return {'Credentials': {'AccessKeyId': 'a', 'SecretAccessKey': 's', 'SessionToken': 't'}}
            raise ClientError(
                {'Error': {'Code': 'Throttling', 'Message': 'try again'}},
                'AssumeRole',
            )

    sts = FailingSTS()
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(ROLE, caller(), db_session)
    assert exc.value.status_code == 503
    assert exc.value.detail == 'Could not verify that this role checks its ExternalId. Try again.'
    assert db_session.query(AccountBinding).count() == 0
    assert db_session.query(AccountBindingEvent).count() == 0


def test_self_host_requires_external_id_and_passes_it_to_sts(db_session, monkeypatch):
    monkeypatch.delenv('EMFIRGE_EXTERNAL_ID', raising=False)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(
            ROLE, Caller('self-host', None, None, None), db_session,
        )
    assert exc.value.status_code == 503

    monkeypatch.setenv('EMFIRGE_EXTERNAL_ID', 'test-external-id-0123456789abcdefghij')
    sts = FakeSTS({'test-external-id-0123456789abcdefghij'})
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    role_access.assume_customer_role(
        ROLE, Caller('self-host', None, None, 'test-external-id-0123456789abcdefghij'), db_session,
    )
    assert [call['ExternalId'] for call in sts.calls] == ['test-external-id-0123456789abcdefghij']
