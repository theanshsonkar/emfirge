"""The default branch (generic catalog first, copiers in the measured order) on experiment 14's gaps, on local fakes
(lab only, never real AWS). Where the curated branch refused (tests/branch/test_lab_branch.py), the default branch
answers; each answer must be the one the account itself gives to the same call (the account is an emulator here, so
"right" means "the same as the emulator that plays the account"). The real account must not change.
"""
from __future__ import annotations

import botocore.exceptions
import pytest

from emfirge.aws.accounts import HttpAccount
from emfirge.aws.engines import EmulatorEngine
from emfirge.server.http import BranchServer
from emfirge.server.wiring import build

from tests.branch.test_lab_branch import LOC, clients, fingerprint, seed

pytestmark = pytest.mark.lab
REAL, ENGINE, BRANCH = 9840, 9841, 9842


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    work = tmp_path_factory.mktemp('layered')
    real, engine = EmulatorEngine(REAL, work, name='real'), EmulatorEngine(ENGINE, work)
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


def outcome(f, **kw) -> str:
    """'ok', or the error code."""
    try:
        f(**kw)
        return 'ok'
    except botocore.exceptions.ClientError as e:
        return e.response['Error']['Code']


def test_a_role_in_an_instance_profile_is_copied_with_its_profile(lab):
    bc, _, branch = lab
    assert outcome(bc('iam').put_role_policy, RoleName='worker-role', PolicyName='x', PolicyDocument='{"Version": '
                   '"2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}') == 'ok'
    assert outcome(bc('iam').delete_role, RoleName='worker-role') == 'DeleteConflict'   # what AWS says, too
    assert bc('iam').get_instance_profile(InstanceProfileName='worker-profile')['InstanceProfile']['Roles']


def test_a_group_in_a_vpc_with_a_gateway_takes_a_rule(lab):
    bc, rc, _ = lab
    rule = {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}
    assert outcome(bc('ec2').authorize_security_group_ingress, GroupId=rc.ids['sg'], IpPermissions=[rule]) == 'ok'
    perms = bc('ec2').describe_security_groups(GroupIds=[rc.ids['sg']])['SecurityGroups'][0]['IpPermissions']
    assert any(p.get('FromPort') == 22 for p in perms)


def test_changes_to_things_that_do_not_exist_answer_as_the_account_does_or_are_refused(lab):
    """The account's own read may call a made-up id malformed rather than missing: then the copier cannot tell
    whether the thing exists, and refuses."""
    bc, rc, _ = lab
    calls = [('ec2', 'modify_instance_attribute', dict(InstanceId='i-0123456789abcdef0', UserData={'Value': b'#!'})),
             ('cloudfront', 'create_invalidation', dict(DistributionId='E123', InvalidationBatch={
                 'Paths': {'Quantity': 1, 'Items': ['/x']}, 'CallerReference': 'c'}))]
    for service, method, kw in calls:
        assert outcome(getattr(bc(service), method), **kw) in (outcome(getattr(rc(service), method), **kw),
                                                               'EmfirgeCannotTell')


def test_a_dns_change_is_answered_and_read_back(lab):
    bc, rc, _ = lab
    batch = {'Changes': [{'Action': 'UPSERT', 'ResourceRecordSet': {'Name': 'feeds.gap.example', 'Type': 'CNAME',
                                                                   'TTL': 60, 'ResourceRecords': [{'Value': 'x.example.com'}]}}]}
    assert outcome(bc('route53').change_resource_record_sets, HostedZoneId=rc.ids['zone'], ChangeBatch=batch) == 'ok'
    names = [r['Name'] for r in bc('route53').list_resource_record_sets(HostedZoneId=rc.ids['zone'])['ResourceRecordSets']]
    assert 'feeds.gap.example.' in names


def test_a_copy_from_a_real_bucket_into_a_new_bucket_works(lab):
    bc, _, _ = lab
    s3 = bc('s3')
    s3.create_bucket(Bucket='gap-new2', **LOC)
    s3.copy_object(Bucket='gap-new2', Key='feed.xml', CopySource={'Bucket': 'gap-media', 'Key': 'feed.xml'})
    assert s3.get_object(Bucket='gap-new2', Key='feed.xml')['Body'].read() == b'<rss/>'


def test_an_invoke_is_still_refused(lab):
    bc, _, _ = lab
    with pytest.raises(botocore.exceptions.ClientError) as e:
        bc('lambda').invoke(FunctionName='fn', Payload=b'{}')
    assert e.value.response['Error']['Code'] == 'EmfirgeCannotTell'
