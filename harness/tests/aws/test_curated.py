"""The hand-written types behind the ports: kinds, which resources a call names, list answers, born ids. No network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from emfirge.aws.codec import AwsCodec, decode_body
from emfirge.aws.curated import SPECS, Where, curated
from emfirge.aws.curated.kinds import kind_of
from emfirge.core.model import Kind, ResourceRef

CODEC = AwsCodec('us-west-2')
CATALOG, OUTCOMES, COPIER = curated(CODEC, Where('us-west-2', '000000000000'))
SVCREF = Path.home() / '.cache' / 'emfirge-lab' / 'specs' / 'svcref'
ACCT = '000000000000'


def refs(service, op, **params):
    return CATALOG.refs(CODEC.encode(service, op, params))


@pytest.mark.parametrize('op,kind', [('GetRole', Kind.READ), ('ListRoles', Kind.LIST), ('Scan', Kind.READ),
                                     ('PutRolePolicy', Kind.PERMISSION), ('TagResource', Kind.TAGGING),
                                     ('UpdateFunctionConfiguration', Kind.WRITE), ('Invoke', Kind.UNKNOWN),
                                     ('ReceiveMessage', Kind.WRITE)])
def test_kinds(op, kind):
    assert kind_of(op) is kind


@pytest.mark.skipif(not SVCREF.exists(), reason='Service Authorization Reference not downloaded')
@pytest.mark.parametrize('spec', SPECS, ids=lambda s: s.type)
def test_types_use_the_service_authorization_reference_vocabulary(spec):
    prefix, name = spec.type.split(':', 1)
    published = {r['Name'] for r in json.loads((SVCREF / f'{prefix}.json').read_text())['Resources']}
    assert name in published


def test_names_ids_arns_and_urls():
    assert refs('lambda', 'GetFunctionConfiguration', FunctionName='publisher').primary == (ResourceRef('lambda:function', 'publisher'),)
    r = refs('lambda', 'CreateFunction', FunctionName='thumb', Role=f'arn:aws:iam::{ACCT}:role/app-role', Runtime='python3.12',
             Handler='h.h', Code={'ZipFile': b'x'})
    assert r.primary == (ResourceRef('lambda:function', 'thumb'),) and r.mentioned == (ResourceRef('iam:role', 'app-role'),)
    assert refs('sqs', 'GetQueueAttributes', QueueUrl=f'https://sqs.us-west-2.amazonaws.com/{ACCT}/jobs').primary == \
        (ResourceRef('sqs:queue', 'jobs'),)
    assert refs('ssm', 'GetParameter', Name='/app/db-url').primary == (ResourceRef('ssm:parameter', 'app/db-url'),)
    assert refs('iam', 'AttachRolePolicy', RoleName='r', PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess').mentioned == ()
    assert refs('ec2', 'DescribeSecurityGroups', Filters=[{'Name': 'vpc-id', 'Values': ['vpc-0000000000000008c']}]).mentioned == \
        (ResourceRef('ec2:vpc', 'vpc-0000000000000008c'),)


def test_a_copy_names_its_source_bucket():
    r = refs('s3', 'CopyObject', Bucket='new', Key='k', CopySource='media/feed.xml')   # as boto3 sends it
    assert ResourceRef('s3:bucket', 'media') in r.all and ResourceRef('s3:bucket', 'new') in r.all and r.complete


def test_what_cannot_be_placed_is_incomplete():
    assert not refs('route53', 'ChangeResourceRecordSets', HostedZoneId='Z1',
                    ChangeBatch={'Changes': [{'Action': 'UPSERT', 'ResourceRecordSet': {'Name': 'a', 'Type': 'A'}}]}).complete
    assert not refs('ec2', 'ModifyInstanceAttribute', InstanceId='i-0123456789abcdef0', Attribute='userData').complete
    assert not refs('kms', 'DisableKey', KeyId='alias/app').complete
    assert not refs('lambda', 'PutFunctionConcurrency', FunctionName=f'arn:aws:states:us-west-2:{ACCT}:stateMachine:x',
                    ReservedConcurrentExecutions=1).complete
    assert refs('kms', 'CreateKey').complete   # a creation names nothing that exists
    assert not refs('iam', 'UpdateAccountPasswordPolicy', MinimumPasswordLength=12).complete


def test_rules_on_other_buses_are_named_but_not_copied():
    r = refs('events', 'DescribeRule', Name='x', EventBusName='custom')
    assert not r.primary
    arn = f'arn:aws:events:us-west-2:{ACCT}:rule/custom/x'
    assert refs('events', 'ListTagsForResource', ResourceARN=arn).all == (ResourceRef('events:rule-on-custom-event-bus', 'custom/x'),)


def test_reads_of_include_the_lists_that_show_it():
    reads = CATALOG.reads_of(ResourceRef('lambda:function', 'f'))
    assert reads[0] == ('lambda', 'GetFunctionConfiguration', {'FunctionName': 'f'}) and ('lambda', 'ListFunctions', {}) in reads
    assert CATALOG.reads_of(ResourceRef('cloud:unknown', 'x')) == []


def test_list_answers_say_which_item_is_which_resource():
    xml = (b'<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><securityGroupInfo>'
           b'<item><groupId>sg-0000000000000000a</groupId></item></securityGroupInfo></DescribeSecurityGroupsResponse>')
    call = CODEC.encode('ec2', 'DescribeSecurityGroups', {})
    [slot] = OUTCOMES.listed(call, decode_body(xml))
    assert slot.refs == (ResourceRef('ec2:security-group', 'sg-0000000000000000a'),) and 'ec2:security-group' in slot.types
    call = CODEC.encode('lambda', 'ListLayers', {})
    [slot] = OUTCOMES.listed(call, {'Layers': [{'LayerName': 'x'}]})
    assert slot.refs == (None,) and 'lambda:function' in slot.types   # cannot tell: a merge would refuse


def test_a_page_of_several_is_refused():
    from emfirge.core.ports import CannotTell
    with pytest.raises(CannotTell):
        OUTCOMES.listed(CODEC.encode('lambda', 'ListFunctions', {}), {'Functions': [], 'NextMarker': 'm'})


def test_born_ids_removes_and_opaque():
    call = CODEC.encode('ec2', 'CreateSecurityGroup', {'GroupName': 'g', 'Description': 'd', 'VpcId': 'vpc-0000000000000008c'})
    body = decode_body(b'<CreateSecurityGroupResponse><groupId>sg-0000000000000000f</groupId></CreateSecurityGroupResponse>')
    assert OUTCOMES.born(call, body) == (ResourceRef('ec2:security-group', 'sg-0000000000000000f'),)
    assert OUTCOMES.born(CODEC.encode('iam', 'CreateRole', {'RoleName': 'r', 'AssumeRolePolicyDocument': '{}'}),
                         {'Role': {'RoleName': 'r'}}) == ()
    assert OUTCOMES.removes(CODEC.encode('dynamodb', 'DeleteTable', {'TableName': 't'}))
    assert not OUTCOMES.removes(CODEC.encode('dynamodb', 'UpdateTable', {'TableName': 't'}))
    assert OUTCOMES.opaque(CODEC.encode('s3', 'PutObject', {'Bucket': 'b', 'Key': 'k', 'Body': b'x'}))


def test_eighteen_types_have_a_copier():
    assert sum(1 for s in SPECS if s.copy is not None) == 18


def test_a_secret_id_names_the_secret_in_every_operation():
    assert refs('secretsmanager', 'GetResourcePolicy', SecretId='app/key').primary == (ResourceRef('secretsmanager:Secret', 'app/key'),)
