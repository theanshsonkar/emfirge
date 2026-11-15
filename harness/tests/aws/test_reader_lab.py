"""The reader on a seeded local emulator standing in for the real account (lab only; never real AWS).
Cross-service links that only a crawl of several services finds, and experiment 21's crawl and adapter fixes."""
from __future__ import annotations

import json
from pathlib import Path

import boto3
import botocore.config
import pytest

from emfirge.aws.accounts import HttpAccount
from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.engines import EmulatorEngine
from emfirge.aws.reader import AccountReader, ReaderSettings
from emfirge.aws.vocabulary import AWS_VOCABULARY
from emfirge.branch.guard import ReadOnly
from emfirge.core.model import Change, ChangeType, ResourceRef
from emfirge.graph import Graph

pytestmark = pytest.mark.lab
PORT = 9860
A = '000000000000'
LOC = {'CreateBucketConfiguration': {'LocationConstraint': 'us-west-2'}}


def trust(service: str) -> str:
    return json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': service},
                                                               'Action': 'sts:AssumeRole'}]})


def seed(c) -> dict:
    s3, iam, ec2, sqs = c('s3'), c('iam'), c('ec2'), c('sqs')
    s3.create_bucket(Bucket='lab-artifacts', **LOC)
    s3.create_bucket(Bucket='lab-unused', **LOC)
    iam.create_role(RoleName='lab-worker-role', AssumeRolePolicyDocument=trust('ec2.amazonaws.com'))
    iam.put_role_policy(RoleName='lab-worker-role', PolicyName='read', PolicyDocument=json.dumps({'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::lab-artifacts/*'}]}))
    policy = iam.create_policy(PolicyName='lab-shared', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': f'arn:aws:sqs:us-west-2:{A}:lab-orders'}]}))['Policy']['Arn']
    iam.attach_role_policy(RoleName='lab-worker-role', PolicyArn=policy)
    iam.create_instance_profile(InstanceProfileName='lab-worker-profile')
    iam.add_role_to_instance_profile(InstanceProfileName='lab-worker-profile', RoleName='lab-worker-role')
    vpc = ec2.create_vpc(CidrBlock='10.40.0.0/16')['Vpc']['VpcId']
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock='10.40.1.0/24')['Subnet']['SubnetId']
    ami = ec2.describe_images(Owners=['amazon'])['Images'][0]['ImageId']
    instance = ec2.run_instances(ImageId=ami, InstanceType='t3.micro', MinCount=1, MaxCount=1, SubnetId=subnet,
                                 IamInstanceProfile={'Name': 'lab-worker-profile'})['Instances'][0]['InstanceId']
    dlq = sqs.create_queue(QueueName='lab-orders-dlq')['QueueUrl']
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
    sqs.create_queue(QueueName='lab-orders', Attributes={'RedrivePolicy': json.dumps({'deadLetterTargetArn': dlq_arn,
                                                                                     'maxReceiveCount': '3'})})
    return {'instance': instance}


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    work = tmp_path_factory.mktemp('reader')
    emulator = EmulatorEngine(PORT, Path(work))
    emulator.start()
    try:
        cfg = botocore.config.Config(retries={'max_attempts': 1}, s3={'addressing_style': 'path'})
        c = lambda s: boto3.client(s, endpoint_url=emulator.url, region_name='us-west-2', aws_access_key_id='x',
                                   aws_secret_access_key='x', verify=emulator.ca, config=cfg)
        ids = seed(c)
        codec, catalog = AwsCodec('us-west-2'), AwsCatalog(account=A, region='us-west-2')
        real = ReadOnly(HttpAccount('real', emulator.url, emulator.ca), codec, catalog)
        yield AccountReader(real, codec, catalog, 'us-west-2', ReaderSettings(services=('iam', 'ec2', 's3', 'sqs'))), ids, real
    finally:
        emulator.stop()


def test_a_bucket_delete_reaches_the_role_its_profile_and_the_instance(lab):
    reader, ids, real = lab
    bucket = ResourceRef('s3:bucket', 'lab-artifacts')
    change = Change(bucket, ChangeType.DELETED)
    got = reader.before([change])
    affected = {a.ref for a in Graph(AWS_VOCABULARY).affects([change], got.states, {}).affected()}
    assert {ResourceRef('iam:role', 'lab-worker-role'), ResourceRef('iam:instance-profile', 'lab-worker-profile'),
            ResourceRef('ec2:instance', ids['instance'])} <= affected
    assert ResourceRef('s3:bucket', 'lab-unused') not in affected
    assert got.reads <= reader.settings.budget and not got.unknowns
    assert real.blocked == 0


def test_one_resource_is_one_ref_never_its_internal_id(lab):
    reader, _, _ = lab
    got = reader.before([Change(ResourceRef('s3:bucket', 'lab-artifacts'), ChangeType.DELETED)])
    roles = [r for r in got.states if r.type == 'iam:role']
    assert ResourceRef('iam:role', 'lab-worker-role') in roles
    assert not [r for r in got.states if r.id.startswith(('AROA', 'AIPA', 'ANPA'))]
    assert not [r for r in got.states if r.type.startswith('iam:policy') and r.id.startswith('arn:')]


def test_queue_attributes_are_read_with_all(lab):
    reader, _, _ = lab
    got = reader.before([Change(ResourceRef('sqs:queue', 'lab-orders-dlq'), ChangeType.DELETED)])
    orders = got.states.get(ResourceRef('sqs:queue', 'lab-orders'), {})
    assert 'deadLetterTargetArn' in json.dumps(orders)
    affected = {a.ref for a in Graph(AWS_VOCABULARY).affects([Change(ResourceRef('sqs:queue', 'lab-orders-dlq'),
                                                                     ChangeType.DELETED)], got.states, {}).affected()}
    assert ResourceRef('sqs:queue', 'lab-orders') in affected


def test_the_reverse_read_of_a_role_does_not_make_it_name_its_profile(lab):
    reader, _, _ = lab
    role = ResourceRef('iam:role', 'lab-worker-role')
    got = reader.before([Change(role, ChangeType.MODIFIED)])
    assert 'lab-worker-profile' not in json.dumps(got.states[role])
    assert 'lab-worker-role' in json.dumps(got.states[ResourceRef('iam:instance-profile', 'lab-worker-profile')])


def test_a_small_budget_ends_in_an_unknown(lab):
    reader, _, _ = lab
    small = AccountReader(reader._real, reader._codec, reader._catalog, 'us-west-2', ReaderSettings(budget=10))
    got = small.before([Change(ResourceRef('s3:bucket', 'lab-artifacts'), ChangeType.DELETED)])
    assert got.reads == 10 and any('budget' in u.what for u in got.unknowns)

