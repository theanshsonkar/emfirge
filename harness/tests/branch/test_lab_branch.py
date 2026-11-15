"""The branch on local fakes (lab only, never real AWS): experiment 14's eight places where the old fake differed from
AWS, one test each, and two branches in one process. Each gap is now right, or an honest refusal, never a wrong
answer.
"""
from __future__ import annotations

import io
import json
import zipfile

import boto3
import botocore.config
import botocore.exceptions
import pytest

from emfirge.aws.accounts import HttpAccount
from emfirge.aws.engines import EmulatorEngine, MotoEngine
from emfirge.server.http import BranchServer
from emfirge.server.wiring import build

pytestmark = pytest.mark.lab
REAL, ENGINE, ENGINE2, BRANCH, BRANCH2 = 9560, 9561, 9562, 9563, 9564
TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                                            'Action': 'sts:AssumeRole'}]})
LOC = {'CreateBucketConfiguration': {'LocationConstraint': 'us-west-2'}}


def clients(url: str, ca: str | None = None):
    cfg = botocore.config.Config(retries={'max_attempts': 1}, s3={'addressing_style': 'path'})
    return lambda s: boto3.client(s, endpoint_url=url, region_name='us-west-2', aws_access_key_id='x',
                                  aws_secret_access_key='x', verify=ca if ca else None, config=cfg)


def seed(c) -> dict:
    ids = {}
    s3, iam, ec2 = c('s3'), c('iam'), c('ec2')
    s3.create_bucket(Bucket='gap-media', **LOC)
    s3.put_object(Bucket='gap-media', Key='feed.xml', Body=b'<rss/>')
    iam.create_role(RoleName='worker-role', AssumeRolePolicyDocument=TRUST)
    iam.create_role(RoleName='fn-role', AssumeRolePolicyDocument=TRUST.replace('ec2.', 'lambda.'))
    iam.create_instance_profile(InstanceProfileName='worker-profile')
    iam.add_role_to_instance_profile(InstanceProfileName='worker-profile', RoleName='worker-role')
    ids['vpc'] = ec2.create_vpc(CidrBlock='10.30.0.0/16')['Vpc']['VpcId']
    igw = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=ids['vpc'])
    ids['sg'] = ec2.create_security_group(GroupName='web', Description='web', VpcId=ids['vpc'])['GroupId']
    ids['zone'] = c('route53').create_hosted_zone(Name='gap.example', CallerReference='gap-1')['HostedZone']['Id']
    code = io.BytesIO()
    with zipfile.ZipFile(code, 'w') as z:
        z.writestr('h.py', 'def h(e, c):\n    return 1\n')
    c('lambda').create_function(FunctionName='fn', Runtime='python3.12', Role='arn:aws:iam::000000000000:role/fn-role',
                                Handler='h.h', Code={'ZipFile': code.getvalue()})
    c('lambda').get_waiter('function_active_v2').wait(FunctionName='fn')
    c('ssm').put_parameter(Name='/gap/p', Value='real', Type='String')
    return ids


def fingerprint(c) -> dict:
    return {'buckets': sorted(b['Name'] for b in c('s3').list_buckets()['Buckets']),
            'objects': [o['Key'] for o in c('s3').list_objects_v2(Bucket='gap-media').get('Contents', [])],
            'worker-policies': c('iam').list_role_policies(RoleName='worker-role')['PolicyNames'],
            'sg': c('ec2').describe_security_groups(GroupIds=[c.ids['sg']])['SecurityGroups'][0]['IpPermissions'],
            'param': c('ssm').get_parameter(Name='/gap/p')['Parameter']['Value'],
            'records': len(c('route53').list_resource_record_sets(HostedZoneId=c.ids['zone'])['ResourceRecordSets'])}


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    work = tmp_path_factory.mktemp('lab')
    real = EmulatorEngine(REAL, work, name='real')
    engine = EmulatorEngine(ENGINE, work)
    real.start()
    engine.start()
    server = None
    try:
        rc = clients(real.url, real.ca)
        rc.ids, rc.account = seed(rc), HttpAccount('real', real.url, real.ca)
        before = fingerprint(rc)
        branch = build(rc.account, engine)
        server = BranchServer(branch, BRANCH).start()
        yield clients(server.url), rc, branch
        assert fingerprint(rc) == before, 'the real account changed under the branch'
    finally:
        if server:
            server.stop()
        engine.stop()
        real.stop()


def refusal(f, **kw) -> str:
    with pytest.raises(botocore.exceptions.ClientError) as e:
        f(**kw)
    assert e.value.response['Error']['Code'] == 'EmfirgeCannotTell', e.value.response['Error']
    return e.value.response['Error']['Message']


def test_gap1_a_server_side_copy_from_a_real_bucket_into_a_new_bucket_works(lab):
    bc, _, _ = lab
    s3 = bc('s3')
    s3.create_bucket(Bucket='gap-new', **LOC)
    s3.copy_object(Bucket='gap-new', Key='feed.xml', CopySource={'Bucket': 'gap-media', 'Key': 'feed.xml'})
    assert s3.get_object(Bucket='gap-new', Key='feed.xml')['Body'].read() == b'<rss/>'


def test_gap2_a_role_in_an_instance_profile_is_refused_in_plain_words(lab):
    bc, _, _ = lab
    msg = refusal(bc('iam').put_role_policy, RoleName='worker-role', PolicyName='x', PolicyDocument=TRUST)
    assert 'instance profile' in msg and 'Nothing was changed' in msg
    assert 'instance profile' in refusal(bc('iam').delete_role, RoleName='worker-role')
    assert bc('iam').get_instance_profile(InstanceProfileName='worker-profile')['InstanceProfile']['Roles']


def test_gap3_a_group_in_a_vpc_with_a_gateway_is_refused(lab):
    bc, rc, _ = lab
    msg = refusal(bc('ec2').authorize_security_group_ingress, GroupId=rc.ids['sg'],
                  IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}])
    assert 'gateways' in msg


def test_gap4_instance_and_cloudfront_changes_are_refused(lab):
    bc, _, _ = lab
    assert 'cannot place' in refusal(bc('ec2').modify_instance_attribute, InstanceId='i-0123456789abcdef0',
                                     UserData={'Value': b'#!/bin/bash'})
    assert 'cannot place' in refusal(bc('cloudfront').create_invalidation, DistributionId='E123',
                                     InvalidationBatch={'Paths': {'Quantity': 1, 'Items': ['/x']}, 'CallerReference': 'c'})


def test_gap5_a_dns_change_is_refused_not_answered_wrong(lab):
    bc, rc, _ = lab
    batch = {'Changes': [{'Action': 'UPSERT', 'ResourceRecordSet': {'Name': 'feeds.gap.example', 'Type': 'CNAME', 'TTL': 60,
                                                                   'ResourceRecords': [{'Value': 'x.example.com'}]}}]}
    assert 'cannot place' in refusal(bc('route53').change_resource_record_sets, HostedZoneId=rc.ids['zone'], ChangeBatch=batch)


def test_gap6_refusals_parse_in_xml_protocols_and_plain_lists_are_answered(lab):
    bc, _, _ = lab
    assert 'stateMachines' in bc('stepfunctions').list_state_machines()
    assert 'LoadBalancers' in bc('elbv2').describe_load_balancers()


def test_gap7_usage_evidence_comes_from_the_real_account(lab):
    bc, rc, _ = lab
    real = rc('iam').get_role(RoleName='fn-role')['Role']
    bc('iam').tag_role(RoleName='fn-role', Tags=[{'Key': 'team', 'Value': 'media'}])   # copies the role
    got = bc('iam').get_role(RoleName='fn-role')['Role']
    assert got.get('RoleLastUsed') == real.get('RoleLastUsed') and got['Tags'] == [{'Key': 'team', 'Value': 'media'}]


def test_gap8_a_test_invoke_is_refused_because_its_effects_cannot_be_told(lab):
    bc, _, _ = lab
    assert 'run code' in refusal(bc('lambda').invoke, FunctionName='fn', Payload=b'{}')


def test_every_refusal_is_in_the_report(lab):
    _, _, branch = lab
    assert len(branch.unknowns()) >= 7 and all(u.where == 'branch' for u in branch.unknowns())


def test_two_branches_in_one_process_are_isolated(lab, tmp_path):
    bc, rc, first = lab
    second_engine = MotoEngine(ENGINE2, tmp_path)
    second_engine.start()
    server = None
    try:
        second = build(rc.account, second_engine)
        server = BranchServer(second, BRANCH2).start()
        b2 = clients(server.url)
        bc('ssm').put_parameter(Name='/gap/p', Value='one', Type='String', Overwrite=True)
        b2('ssm').delete_parameter(Name='/gap/p')
        assert bc('ssm').get_parameter(Name='/gap/p')['Parameter']['Value'] == 'one'
        with pytest.raises(botocore.exceptions.ClientError):
            b2('ssm').get_parameter(Name='/gap/p')
        assert rc('ssm').get_parameter(Name='/gap/p')['Parameter']['Value'] == 'real'
        assert {c.type.value for c in first.changes() if c.ref.id == 'gap/p'} == {'modified'}
        assert {c.type.value for c in second.changes()} == {'deleted'}
    finally:
        if server:
            server.stop()
        second_engine.stop()
