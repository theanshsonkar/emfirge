"""The generic copier on local fakes (lab only, never real AWS): a role with its policies and instance profile, a
bucket with its objects and settings (reading data switched on), a function with its code, each rebuilt in the engine
from published data only. What it cannot rebuild (a topic's subscriptions) is refused, not copied half. With reading
data switched off (the default), a bucket is copied with its keys only, and every answer stays right or is refused."""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from emfirge.aws.accounts import HttpAccount, sdk_client
from emfirge.aws.engines import EmulatorEngine
from emfirge.branch.overlay import State
from emfirge.core.model import ResourceRef
from emfirge.core.ports import CannotTell
from emfirge.server.wiring import build

from tests.branch.test_lab_branch import LOC, clients

pytestmark = pytest.mark.lab
REAL, ENGINE = 9843, 9844
DOC = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:ListBucket', 'Resource': '*'}]})
TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
                                                            'Action': 'sts:AssumeRole'}]})


def seed(c) -> None:
    iam = c('iam')
    iam.create_role(RoleName='r1', AssumeRolePolicyDocument=TRUST, Description='copied')
    iam.put_role_policy(RoleName='r1', PolicyName='inline', PolicyDocument=DOC)
    arn = iam.create_policy(PolicyName='managed', PolicyDocument=DOC)['Policy']['Arn']
    iam.attach_role_policy(RoleName='r1', PolicyArn=arn)
    iam.create_instance_profile(InstanceProfileName='p1')
    iam.add_role_to_instance_profile(InstanceProfileName='p1', RoleName='r1')
    s3 = c('s3')
    s3.create_bucket(Bucket='gen-bucket-1', **LOC)
    s3.put_object(Bucket='gen-bucket-1', Key='a/x.txt', Body=b'hello')
    s3.put_bucket_versioning(Bucket='gen-bucket-1', VersioningConfiguration={'Status': 'Enabled'})
    code = io.BytesIO()
    with zipfile.ZipFile(code, 'w') as z:
        z.writestr('h.py', 'def h(e, c):\n    return 1\n')
    c('lambda').create_function(FunctionName='f1', Runtime='python3.12', Role='arn:aws:iam::000000000000:role/r1',
                                Handler='h.h', Code={'ZipFile': code.getvalue()}, Timeout=42)
    c('lambda').get_waiter('function_active_v2').wait(FunctionName='f1')
    topic = c('sns').create_topic(Name='t1')['TopicArn']
    c('sqs').create_queue(QueueName='q1')
    c('sns').subscribe(TopicArn=topic, Protocol='sqs', Endpoint='arn:aws:sqs:us-west-2:000000000000:q1')


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    work = tmp_path_factory.mktemp('generic')
    real, engine = EmulatorEngine(REAL, work, name='real'), EmulatorEngine(ENGINE, work)
    real.start()
    engine.start()
    try:
        seed(clients(real.url, real.ca))
        branch = build(HttpAccount('real', real.url, real.ca), engine, copier='generic', copy_data=True)
        yield branch, lambda s: sdk_client(engine, s, 'us-west-2')
    finally:
        engine.stop()
        real.stop()


def copy(branch, type_, id_) -> State:
    try:
        branch.copy(ResourceRef(type_, id_))
    except CannotTell:
        pass
    return branch.overlay.state(ResourceRef(type_, id_))


def test_a_role_comes_with_its_policies_and_its_instance_profile(lab):
    branch, engine = lab
    assert copy(branch, 'iam:role', 'r1') is State.COPIED
    iam = engine('iam')
    assert iam.list_role_policies(RoleName='r1')['PolicyNames'] == ['inline']
    assert [p['PolicyName'] for p in iam.list_attached_role_policies(RoleName='r1')['AttachedPolicies']] == ['managed']
    assert [r['RoleName'] for r in iam.get_instance_profile(InstanceProfileName='p1')['InstanceProfile']['Roles']] == ['r1']
    assert iam.get_role(RoleName='r1')['Role']['Description'] == 'copied'


def test_a_bucket_comes_with_its_objects_and_settings(lab):
    branch, engine = lab
    assert copy(branch, 's3:bucket', 'gen-bucket-1') is State.COPIED
    s3 = engine('s3')
    assert s3.get_object(Bucket='gen-bucket-1', Key='a/x.txt')['Body'].read() == b'hello'
    assert s3.get_bucket_versioning(Bucket='gen-bucket-1')['Status'] == 'Enabled'


def test_a_function_comes_with_its_code(lab):
    branch, engine = lab
    assert copy(branch, 'lambda:function', 'f1') is State.COPIED
    cfg = engine('lambda').get_function_configuration(FunctionName='f1')
    assert cfg['Timeout'] == 42 and cfg['CodeSize'] > 0


def test_what_cannot_be_rebuilt_is_refused_not_copied_half(lab):
    branch, _ = lab
    assert copy(branch, 'sns:topic', 't1') is State.OPAQUE
    assert 'Subscriptions' in branch.overlay.why_opaque(ResourceRef('sns:topic', 't1'))


NAMES_REAL, NAMES_ENGINE, NAMES_BRANCH = 9845, 9846, 9847


@pytest.fixture(scope='module')
def names_only(tmp_path_factory):
    """A branch in the pure configuration (no curated code) with reading data off, served over HTTP."""
    from emfirge.server.http import BranchServer
    from tests.branch.test_lab_branch import clients as make_clients
    work = tmp_path_factory.mktemp('names')
    real, engine = EmulatorEngine(NAMES_REAL, work, name='real'), EmulatorEngine(NAMES_ENGINE, work)
    real.start()
    engine.start()
    server = None
    try:
        rc = make_clients(real.url, real.ca)
        rc('s3').create_bucket(Bucket='names-only-1', **LOC)
        for k in ('a.txt', 'b.txt'):
            rc('s3').put_object(Bucket='names-only-1', Key=k, Body=b'real-' + k.encode())
        branch = build(HttpAccount('real', real.url, real.ca), engine, catalog='generic', copier='generic')
        server = BranchServer(branch, NAMES_BRANCH).start()
        yield make_clients(server.url), rc, branch, lambda s: sdk_client(engine, s, 'us-west-2')
    finally:
        if server:
            server.stop()
        engine.stop()
        real.stop()


def _try(f):
    import botocore.exceptions
    try:
        return f()
    except botocore.exceptions.ClientError as e:
        return e.response['Error']['Code']


def _code(f, **kw):
    import botocore.exceptions
    try:
        f(**kw)
        return 'ok'
    except botocore.exceptions.ClientError as e:
        return e.response['Error']['Code']


def test_without_reading_data_a_bucket_is_copied_with_its_keys_only(names_only):
    bc, rc, branch, engine = names_only
    s3 = bc('s3')
    s3.put_bucket_versioning(Bucket='names-only-1', VersioningConfiguration={'Status': 'Suspended'})   # copies it
    ref = ResourceRef('s3:bucket', 'names-only-1')
    assert branch.overlay.state(ref) is State.COPIED
    assert engine('s3').get_object(Bucket='names-only-1', Key='a.txt')['Body'].read() == b''          # a placeholder
    # an unchanged object's body and head: the real ones, or refused (the bucket holding it was changed). Never the
    # placeholder's
    got = _try(lambda: s3.get_object(Bucket='names-only-1', Key='a.txt')['Body'].read())
    assert got in (b'real-a.txt', 'EmfirgeCannotTell')
    # deleting a bucket that is not empty is refused by the engine, as by AWS
    assert _code(s3.delete_bucket, Bucket='names-only-1') == 'BucketNotEmpty'
    # a listing after a change to the contents is right, or refused: never the placeholders' sizes
    s3.delete_object(Bucket='names-only-1', Key='b.txt')
    listed = _code(s3.list_objects_v2, Bucket='names-only-1')
    if listed == 'ok':
        keys = {o['Key']: o['Size'] for o in s3.list_objects_v2(Bucket='names-only-1')['Contents']}
        assert keys == {'a.txt': len(b'real-a.txt')}
    else:
        assert listed == 'EmfirgeCannotTell'
    assert rc('s3').get_object(Bucket='names-only-1', Key='b.txt')['Body'].read() == b'real-b.txt'      # real untouched


@pytest.mark.xfail(strict=True, reason='needs the branch: a HEAD on a copied resource goes to the engine (router: '
                                       'no body to lay over) without the faithful check, so a placeholder answers')
def test_without_reading_data_a_head_of_an_object_is_real_or_refused(names_only):
    bc, _, _, _ = names_only
    got = _try(lambda: bc('s3').head_object(Bucket='names-only-1', Key='a.txt')['ContentLength'])
    assert got in (len(b'real-a.txt'), 'EmfirgeCannotTell', '400')
