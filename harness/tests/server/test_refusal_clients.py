"""A refusal reaches the agent's own tools as a normal error with our code, and no tool retries it.

The branch runs behind the real HTTP server on 127.0.0.1 and is sealed, so it refuses every call; real boto3
clients (five protocols) and the real AWS CLI call it. A counter on the server shows each call arrived once.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import boto3
import botocore.config
import botocore.exceptions
import pytest

from emfirge.aws.codec import AwsCodec
from emfirge.aws.curated import Where, curated
from emfirge.branch import Branch
from emfirge.core.model import WireRequest, WireResponse
from emfirge.server.http import BranchServer

AWS_CLI = Path(sys.executable).with_name('aws')


class Nowhere:
    """An account that must never be called."""
    name = 'nowhere'

    def __init__(self) -> None:
        self.calls = 0

    def send(self, request: WireRequest) -> WireResponse:
        self.calls += 1
        raise AssertionError('a sealed branch sent a call on')


class Counting:
    """Wraps Branch.handle to count the requests that arrive."""

    def __init__(self, branch: Branch) -> None:
        self._branch, self.hits = branch, 0

    def __getattr__(self, name):
        return getattr(self._branch, name)

    def handle(self, request: WireRequest) -> WireResponse:
        self.hits += 1
        return self._branch.handle(request)


@pytest.fixture(scope='module')
def server():
    codec = AwsCodec('us-west-2')
    catalog, outcomes, copier = curated(codec, Where('us-west-2', '000000000000'))
    real, engine = Nowhere(), Nowhere()
    branch = Counting(Branch(codec, catalog, copier, real, engine, outcomes))
    branch.seal()
    srv = BranchServer(branch, 0).start()
    yield srv, branch, real, engine
    srv.stop()


CALLS = [('dynamodb', 'describe_table', {'TableName': 't'}),            # json
         ('lambda', 'get_function', {'FunctionName': 'f'}),             # rest-json
         ('s3', 'get_bucket_policy', {'Bucket': 'b'}),                  # rest-xml (S3)
         ('route53', 'get_hosted_zone', {'Id': 'Z1'}),                  # rest-xml
         ('iam', 'get_role', {'RoleName': 'r'}),                        # query
         ('elbv2', 'describe_load_balancers', {}),                      # query
         ('ec2', 'describe_security_groups', {})]                       # ec2


@pytest.mark.parametrize('service,method,params', CALLS)
@pytest.mark.parametrize('mode', ['standard', 'legacy'])
def test_sdk_sees_a_client_error_with_our_code_and_does_not_retry(server, service, method, params, mode):
    srv, branch, real, engine = server
    cfg = botocore.config.Config(retries={'mode': mode, 'max_attempts': 5})
    c = boto3.client(service, endpoint_url=srv.url, region_name='us-west-2', aws_access_key_id='x',
                     aws_secret_access_key='x', config=cfg)
    before = branch.hits
    with pytest.raises(botocore.exceptions.ClientError) as e:
        getattr(c, method)(**params)
    assert e.value.response['Error']['Code'] == 'EmfirgeCannotTell'
    assert 'Emfirge cannot tell' in e.value.response['Error']['Message']
    assert branch.hits - before == 1 and e.value.response['ResponseMetadata']['RetryAttempts'] == 0
    assert real.calls == engine.calls == 0


@pytest.mark.skipif(not AWS_CLI.exists(), reason='the AWS CLI is not installed next to this python')
@pytest.mark.parametrize('argv', [['ec2', 'describe-security-groups'], ['iam', 'get-role', '--role-name', 'r'],
                                  ['s3api', 'get-bucket-policy', '--bucket', 'b'], ['dynamodb', 'describe-table', '--table-name', 't']])
def test_the_aws_cli_prints_a_clean_error_and_does_not_retry(server, argv):
    srv, branch, _, _ = server
    env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
    env.update(AWS_ACCESS_KEY_ID='x', AWS_SECRET_ACCESS_KEY='x', AWS_DEFAULT_REGION='us-west-2', AWS_MAX_ATTEMPTS='5',
               AWS_CONFIG_FILE='/dev/null', AWS_SHARED_CREDENTIALS_FILE='/dev/null')
    before = branch.hits
    out = subprocess.run([str(AWS_CLI), '--endpoint-url', srv.url, *argv], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode != 0
    assert 'EmfirgeCannotTell' in out.stderr and 'Emfirge cannot tell' in out.stderr
    assert 'Unable to parse' not in out.stderr and 'retries' not in out.stderr.lower()
    assert branch.hits - before == 1
