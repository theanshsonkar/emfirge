"""Generic outcomes: lists, born ids and deletes from botocore's models and the catalog. No network."""
from __future__ import annotations

from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.layered import LayeredCatalog
from emfirge.aws.outcomes_generic import GenericOutcomes, list_ops
from emfirge.core.model import ResourceRef

ACCT = '000000000000'
CODEC = AwsCodec('us-west-2')
CATALOG = LayeredCatalog(AwsCatalog(account=ACCT, region='us-west-2'), CODEC)
OUT = GenericOutcomes(CODEC, CATALOG)


def call(service, op, **params):
    return CODEC.encode(service, op, params)


def test_a_list_of_names_holds_its_type():
    [slot] = OUT.listed(call('dynamodb', 'ListTables'), {'TableNames': ['a', 'b']})
    assert slot.refs == (ResourceRef('dynamodb:table', 'a'), ResourceRef('dynamodb:table', 'b'))
    assert slot.types == {'dynamodb:table'}


def test_list_items_by_arn_and_by_the_field_named_like_the_arn_variable():
    [slot] = OUT.listed(call('lambda', 'ListFunctions'), {'Functions': [{'FunctionName': 'f', 'Runtime': 'python3.12'}]})
    assert slot.refs == (ResourceRef('lambda:function', 'f'),)
    [slot] = OUT.listed(call('scheduler', 'ListSchedules'), {'Schedules': [
        {'Arn': f'arn:aws:scheduler:us-west-2:{ACCT}:schedule/default/s', 'Name': 's'}]})
    assert slot.refs == (ResourceRef('scheduler:schedule', 'default/s'),)


def test_a_queue_url_list_gives_queue_names():
    [slot] = OUT.listed(call('sqs', 'ListQueues'), {'QueueUrls': [f'https://sqs.us-west-2.amazonaws.com/{ACCT}/jobs']})
    assert slot.refs == (ResourceRef('sqs:queue', 'jobs'),)


def test_a_list_named_after_no_type_says_it_cannot_tell_its_items():
    [slot] = OUT.listed(call('logs', 'DescribeQueries'), {'queries': [{'queryId': 'q1'}]})
    assert slot.refs == (None,) and 'logs:log-group' in slot.types     # 'queries' are not 'scheduled-query' items


def test_born_ids_are_the_ones_the_request_did_not_carry():
    c = call('ec2', 'CreateSecurityGroup', GroupName='g', Description='d', VpcId='vpc-0123456789abcdef0')
    assert OUT.born(c, {'CreateSecurityGroupResponse': {'groupId': 'sg-0123456789abcdef9'}}) == \
        (ResourceRef('ec2:security-group', 'sg-0123456789abcdef9'),)
    c = call('sns', 'CreateTopic', Name='alerts')
    assert OUT.born(c, {'CreateTopicResponse': {'CreateTopicResult': {
        'TopicArn': f'arn:aws:sns:us-west-2:{ACCT}:alerts'}}}) == ()


def test_deletes_come_from_the_types_delete_operations():
    assert OUT.removes(call('lambda', 'DeleteFunction', FunctionName='f'))
    assert OUT.removes(call('kms', 'ScheduleKeyDeletion', KeyId='1234abcd-12ab-34cd-56ef-1234567890ab'))
    assert not OUT.removes(call('iam', 'DeleteRolePolicy', RoleName='r', PolicyName='p'))


def test_list_reads_of_a_type():
    assert 'ListFunctions' in list_ops(CODEC, 'lambda', 'lambda:function')
    assert 'DescribeLogGroups' in list_ops(CODEC, 'logs', 'logs:log-group')
