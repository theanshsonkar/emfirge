"""RealAccount against AWS's emulator started with authentication ON, standing in for AWS (lab only; never real
AWS). The emulator requires SigV4 signatures made with that run's own keys, so it tells a request signed with the
owner's credentials from one that is not."""
from __future__ import annotations

import os
from pathlib import Path

import boto3
import botocore.config
import botocore.exceptions
import botocore.session
import pytest

from emfirge.aws.accounts import HttpAccount, sdk_client
from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.engines.emulator import BINARY
from emfirge.aws.engines.process import LocalProcess
from emfirge.aws.real import NotARead, RealAccount
from emfirge.core.model import WireRequest

pytestmark = pytest.mark.lab
PORT = 9852
HOME = Path.home() / '.aws' / 'emulator' / str(PORT)
CA = str(HOME / 'ca.pem')
URL = f'https://127.0.0.1:{PORT}'


@pytest.fixture(scope='module')
def stand_in(tmp_path_factory):
    proc = LocalProcess([str(BINARY), '--telemetry', 'off', '-a', 'on', '-p', str(PORT)], {'EMULATOR_TELEMETRY': 'off'},
                        tmp_path_factory.mktemp('real') / 'emulator.log')
    proc.start()
    try:
        proc.wait_until(f'{URL}/__admin/health', HOME / 'ca.pem')
        yield
    finally:
        proc.stop()


def owner_session() -> botocore.session.Session:
    """The owner's credential chain, as botocore reads it, pointed at the stand-in's own key file."""
    session = botocore.session.Session()
    session.set_config_variable('credentials_file', str(HOME / 'emulator_credentials'))
    session.set_config_variable('config_file', os.devnull)
    session.set_config_variable('profile', 'default')
    return session


def owner_client(service: str):
    s = owner_session()
    return s.create_client(service, region_name='us-west-2', endpoint_url=URL, verify=CA,
                           config=botocore.config.Config(s3={'addressing_style': 'path'}, retries={'max_attempts': 1}))


def real(codec: AwsCodec) -> RealAccount:
    return RealAccount(codec, AwsCatalog(), 'us-west-2', session=owner_session(), endpoint_url=URL, ca=CA)


def test_the_stand_in_refuses_a_request_signed_with_dummy_keys(stand_in):
    client = boto3.client('sqs', endpoint_url=URL, region_name='us-west-2', aws_access_key_id='dummy',
                          aws_secret_access_key='dummy', verify=CA, config=botocore.config.Config(retries={'max_attempts': 1}))
    with pytest.raises(botocore.exceptions.ClientError) as e:
        client.list_queues()
    assert e.value.response['ResponseMetadata']['HTTPStatusCode'] in (401, 403)


def test_the_stand_in_refuses_an_unsigned_request(stand_in):
    """It names its service (the emulator needs that to answer at all) but carries no signature."""
    request = AwsCodec('us-west-2').encode('sqs', 'ListQueues', {}).wire
    assert 'Signature=0' in request.headers['Authorization']
    r = HttpAccount('raw', URL, CA).send(request)
    assert r.status in (400, 401, 403), r.body[:200]


def test_a_read_signed_with_dummy_keys_is_re_signed_and_answered(stand_in):
    owner_client('sqs').create_queue(QueueName='real-queue')
    codec = AwsCodec('us-west-2')
    account = real(codec)
    queues = sdk_client(account, 'sqs', 'us-west-2').list_queues()['QueueUrls']
    assert [u for u in queues if u.endswith('/real-queue')]
    assert account.sent == 1


def test_an_error_answer_comes_back_as_it_came(stand_in):
    client = sdk_client(real(AwsCodec('us-west-2')), 's3', 'us-west-2')
    with pytest.raises(botocore.exceptions.ClientError) as e:
        client.get_bucket_policy(Bucket='no-such-bucket-here')
    assert e.value.response['Error']['Code'] == 'NoSuchBucket'


def test_a_changing_call_never_leaves_real_py(stand_in):
    account = real(AwsCodec('us-west-2'))
    client = sdk_client(account, 'sqs', 'us-west-2')
    with pytest.raises(NotARead):
        client.create_queue(QueueName='must-not-exist')
    with pytest.raises(NotARead):
        client.delete_queue(QueueUrl=f'{URL}/000000000000/real-queue')
    assert account.sent == 0
    names = owner_client('sqs').list_queues().get('QueueUrls', [])
    assert not [u for u in names if u.endswith('/must-not-exist')]
    assert [u for u in names if u.endswith('/real-queue')]


def test_a_request_it_cannot_decode_is_sent_nowhere(stand_in):
    account = real(AwsCodec('us-west-2'))
    with pytest.raises(NotARead):
        account.send(WireRequest('POST', '/', '', {}, b'hello'))
    assert account.sent == 0
