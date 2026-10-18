import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import role_access
from app.auth import Caller
from app.database import AccountBinding
from app.demo_seed import DEMO_ROLE_ARN, DEMO_ROLE_ARN_V2
from app.main import app


ROLE = 'arn:aws:iam::123456789012:role/Victim'
DEMO_ARNS = [DEMO_ROLE_ARN, DEMO_ROLE_ARN_V2]



@pytest.fixture
def db_session(shared_test_db):
    session = shared_test_db()
    try:
        yield session
    finally:
        session.close()

def hosted():
    return Caller('hosted', 1, 'project-a', 'project-a-external')


def client():
    return TestClient(app)


def aws_error(code, message='arn:aws:iam::123456789012:role/Victim'):
    return ClientError({'Error': {'Code': code, 'Message': message}}, 'AssumeRole')


def assert_no_leak(detail, raw_message='arn:aws:iam::123456789012:role/Victim'):
    text = str(detail)
    assert '123456789012' not in text
    assert 'Victim' not in text
    assert 'arn:aws' not in text
    assert raw_message not in text


@pytest.mark.parametrize('demo_arn', DEMO_ARNS)
def test_l38_demo_analyze_never_touches_sts(demo_arn):
    with patch('app.role_access._sts_client', side_effect=AssertionError('STS called')):
        with patch('app.main.assume_customer_role', side_effect=AssertionError('assume called')):
            with patch('app.main.get_scan_count_today', return_value=0), patch('app.main.generate_explanation', return_value={'ai_summary': 'Demo', 'recommended_improvements': [], 'priority_actions': [], 'latency_ms': 0}), patch('app.main.save_report', return_value='report'), patch('app.main.get_report_url', return_value='url'), patch('app.main.save_analysis', return_value=1), patch('app.main.get_previous_scan_for_account', return_value={}):
                response = client().post('/analyze', json={'role_arn': demo_arn, 'region': 'us-east-1'})
    assert response.status_code == 200
    assert response.json()['analysis_id']


@pytest.mark.parametrize('demo_arn', DEMO_ARNS)
def test_l38_demo_stream_never_touches_sts(demo_arn):
    with patch('app.role_access._sts_client', side_effect=AssertionError('STS called')):
        with patch('app.main.assume_customer_role', side_effect=AssertionError('assume called')):
            with patch('app.main.get_scan_count_today', return_value=0), patch('app.main.generate_explanation', return_value={'ai_summary': 'Demo', 'recommended_improvements': [], 'priority_actions': [], 'latency_ms': 0}), patch('app.main.save_report', return_value='report'), patch('app.main.get_report_url', return_value='url'), patch('app.main.save_analysis', return_value=1), patch('app.main.get_previous_scan_for_account', return_value={}):
                response = client().post('/analyze/stream', json={'role_arn': demo_arn, 'region': 'us-east-1'})
    assert response.status_code == 200
    assert 'event: complete' in response.text


@pytest.mark.parametrize('role_arn', [
    'arn:aws:iam::000000000000:role/EmfirgeReadOnlyX',
    'arn:aws:iam::000000000001:role/EmfirgeReadOnly',
])
def test_l38b_similar_non_demo_arn_still_assumes(role_arn):
    with patch('app.main.assume_customer_role', side_effect=HTTPException(503, 'sentinel')) as assumed:
        response = client().post('/analyze/stream', json={'role_arn': role_arn, 'region': 'us-east-1'})
    assert response.status_code == 503
    assumed.assert_called_once()


def test_l39a_access_denied_is_safe_forbidden(db_session, monkeypatch):
    sts = MagicMock()
    sts.assume_role.side_effect = aws_error('AccessDenied')
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(ROLE, hosted(), db_session)
    assert exc.value.status_code == 403
    assert 'trust_or_external_id' in exc.value.detail
    assert 'ExternalId' in exc.value.detail
    assert 'trust policy' in exc.value.detail
    assert_no_leak(exc.value.detail)


def test_l39b_bound_account_and_integrity_race_use_same_denial(db_session, monkeypatch):
    sts = MagicMock()
    sts.assume_role.side_effect = aws_error('AccessDenied')
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException) as first:
        role_access.assume_customer_role(ROLE, hosted(), db_session)
    db_session.add(AccountBinding(aws_account_id='123456789012', project_id=99))
    db_session.commit()
    with pytest.raises(HTTPException) as bound:
        role_access.assume_customer_role(ROLE, hosted(), db_session)
    assert bound.value.detail == first.value.detail


@pytest.mark.parametrize(('error', 'expected'), [
    (aws_error('Throttling'), 'sts_throttled'),
    (aws_error('ExpiredToken'), 'emfirge_credentials'),
    (aws_error('InvalidClientTokenId'), 'emfirge_credentials'),
    (aws_error('SignatureDoesNotMatch'), 'emfirge_credentials'),
    (aws_error('RegionDisabledException'), 'sts_region_disabled'),
    (EndpointConnectionError(endpoint_url='https://sts.amazonaws.com'), 'sts_unreachable'),
    (aws_error('SomethingNew'), 'aws_error'),
    (RuntimeError('arn:aws:iam::123456789012:role/Victim'), 'internal_error'),
])
def test_l39c_and_l39d_safe_failure_classes(db_session, monkeypatch, error, expected):
    sts = MagicMock()
    sts.assume_role.side_effect = error
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(ROLE, hosted(), db_session)
    assert exc.value.status_code == 503
    assert expected in exc.value.detail
    assert 'trust_or_external_id' not in exc.value.detail
    assert_no_leak(exc.value.detail, str(error))


def test_l39b_integrity_error_race_uses_denial_text(db_session, monkeypatch):
    from sqlalchemy.exc import IntegrityError
    sts = MagicMock()
    sts.assume_role.side_effect = [
        {'Credentials': {'AccessKeyId': 'a', 'SecretAccessKey': 's', 'SessionToken': 't'}},
        ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'probe'}}, 'AssumeRole'),
    ]
    monkeypatch.setattr(role_access, '_sts_client', lambda: sts)
    original_flush = db_session.flush
    db_session.autoflush = False
    def race_flush():
        raise IntegrityError('insert', {}, Exception('race'))
    monkeypatch.setattr(db_session, 'flush', race_flush)
    with pytest.raises(HTTPException) as exc:
        role_access.assume_customer_role(ROLE, hosted(), db_session)
    assert exc.value.status_code == 403
    assert 'trust_or_external_id' in exc.value.detail
