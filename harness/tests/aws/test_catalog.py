"""AwsCatalog: kinds, refs and reads, from AWS's published lists only. Pure: no network, no emulator.

Account 000000000000 is the emulator's; every name is made up."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from emfirge.aws.catalog import AwsCatalog
from emfirge.core.model import Call, Kind, ResourceRef, WireRequest

A = '000000000000'
R = 'us-west-2'
WIRE = WireRequest('POST', '/', '', {}, b'')


@pytest.fixture(scope='module')
def cat() -> AwsCatalog:
    return AwsCatalog(account=A, region=R)


def call(cat: AwsCatalog, svc: str, op: str, /, **params) -> Call:
    return Call(svc, op, params, cat.kind(svc, op), WIRE)


def primary(cat: AwsCatalog, svc: str, op: str, /, **params) -> list[str]:
    return [str(r) for r in cat.refs(call(cat, svc, op, **params)).primary]


def mentioned(cat: AwsCatalog, svc: str, op: str, /, **params) -> list[str]:
    return [str(r) for r in cat.refs(call(cat, svc, op, **params)).mentioned]


def arn(service: str, resource: str, region: str = R, account: str = A) -> str:
    return f'arn:aws:{service}:{region}:{account}:{resource}'


# ------------------------------------------------------------------ kinds
@pytest.mark.parametrize('service, op, kind', [
    ('lambda', 'UpdateFunctionConfiguration', Kind.WRITE),
    ('lambda', 'GetFunction', Kind.READ),
    ('lambda', 'ListFunctions', Kind.LIST),
    ('lambda', 'TagResource', Kind.TAGGING),
    ('iam', 'AttachRolePolicy', Kind.PERMISSION),
    ('iam', 'PutRolePolicy', Kind.PERMISSION),
    ('s3', 'PutBucketPolicy', Kind.PERMISSION),
    ('s3', 'ListObjectsV2', Kind.LIST),          # by its action s3:ListBucket
    ('s3', 'DeleteObjects', Kind.WRITE),         # by s3:DeleteObject, named in the same words
    ('ec2', 'DescribeInstances', Kind.LIST),
    ('ec2', 'RunInstances', Kind.WRITE),
    ('dynamodb', 'Scan', Kind.READ),
    ('kms', 'ScheduleKeyDeletion', Kind.WRITE),
])
def test_kind_comes_from_the_reference(cat, service, op, kind):
    assert cat.kind(service, op) is kind


def test_unknown_operation_is_unknown_never_a_read(cat):
    assert cat.kind('lambda', 'NoSuchOperation') is Kind.UNKNOWN
    assert cat.kind('no-such-service', 'GetThing') is Kind.UNKNOWN
    refs = cat.refs(call(cat, 'no-such-service', 'GetThing', Name='x'))
    assert refs.complete is False


# ------------------------------------------------------------------ lambda: name, ARN, qualifier converge
def test_lambda_function_by_name_arn_and_qualifier_is_one_ref(cat):
    want = ['lambda:function/publisher']
    assert primary(cat, 'lambda', 'UpdateFunctionConfiguration', FunctionName='publisher') == want
    assert primary(cat, 'lambda', 'UpdateFunctionConfiguration', FunctionName=arn('lambda', 'function:publisher')) == want
    assert primary(cat, 'lambda', 'PutFunctionConcurrency', FunctionName='publisher:live', ReservedConcurrentExecutions=1) == want
    assert primary(cat, 'lambda', 'TagResource', Resource=arn('lambda', 'function:publisher'), Tags={'a': 'b'}) == want
    assert cat.parse_arn(arn('lambda', 'function:publisher:$LATEST')) == ResourceRef('lambda:function', 'publisher')


def test_lambda_create_names_the_new_function_and_mentions_what_it_uses(cat):
    refs = cat.refs(call(cat, 'lambda', 'CreateFunction', FunctionName='thumb', Role=f'arn:aws:iam::{A}:role/service/app-role',
                         KMSKeyArn=arn('kms', 'key/1234abcd-12ab-34cd-56ef-1234567890ab')))
    assert [str(r) for r in refs.primary] == ['lambda:function/thumb']
    assert {str(r) for r in refs.mentioned} == {'iam:role/app-role', 'kms:key/1234abcd-12ab-34cd-56ef-1234567890ab'}
    assert refs.complete


def test_lambda_event_source_mapping_by_uuid(cat):
    assert primary(cat, 'lambda', 'UpdateEventSourceMapping', UUID='a1b2', BatchSize=5) == ['lambda:eventSourceMapping/a1b2']


# ------------------------------------------------------------------ s3: buckets, objects, policies
def test_s3_bucket_and_object(cat):
    assert primary(cat, 's3', 'PutBucketVersioning', Bucket='media', VersioningConfiguration={}) == ['s3:bucket/media']
    assert primary(cat, 's3', 'PutObject', Bucket='media', Key='ep/1.mp3') == ['s3:object/media/ep/1.mp3']
    assert mentioned(cat, 's3', 'PutObject', Bucket='media', Key='ep/1.mp3') == ['s3:bucket/media']
    assert cat.parse_arn('arn:aws:s3:::media/ep/1.mp3') == ResourceRef('s3:object', 'media/ep/1.mp3')


def test_s3_delete_objects_is_placed_on_the_bucket_that_holds_them(cat):
    refs = cat.refs(call(cat, 's3', 'DeleteObjects', Bucket='media', Delete={'Objects': [{'Key': 'a'}]}))
    assert [str(r) for r in refs.primary] == ['s3:bucket/media'] and refs.complete


def test_mentions_inside_a_policy_document(cat):
    policy = json.dumps({'Statement': [
        {'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{A}:role/reader'}, 'Action': 's3:GetObject',
         'Resource': 'arn:aws:s3:::media/*'},
        {'Effect': 'Allow', 'Principal': {'Service': 'sns.amazonaws.com'}, 'Action': 's3:PutObject',
         'Resource': 'arn:aws:s3:::logs-bucket/*', 'Condition': {'ArnLike': {'aws:SourceArn': arn('sns', 'alerts')}}}]})
    refs = cat.refs(call(cat, 's3', 'PutBucketPolicy', Bucket='media', Policy=policy))
    assert [str(r) for r in refs.primary] == ['s3:bucket/media']
    assert [str(r) for r in refs.mentioned] == ['iam:role/reader', 's3:bucket/logs-bucket', 'sns:topic/alerts']


# ------------------------------------------------------------------ iam
def test_iam_role_by_name_and_by_arn_with_path_converge(cat):
    want = ['iam:role/app-role']
    assert primary(cat, 'iam', 'UpdateAssumeRolePolicy', RoleName='app-role', PolicyDocument='{}') == want
    assert cat.parse_arn(f'arn:aws:iam::{A}:role/team/app-role') == ResourceRef('iam:role', 'app-role')


def test_iam_aws_managed_policy_is_not_a_resource_of_the_account(cat):
    refs = cat.refs(call(cat, 'iam', 'AttachRolePolicy', RoleName='app-role', PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'))
    assert [str(r) for r in refs.primary] == ['iam:role/app-role'] and not refs.mentioned


def test_iam_customer_policy_user_and_instance_profile(cat):
    pol = f'arn:aws:iam::{A}:policy/app-policy'
    assert mentioned(cat, 'iam', 'AttachRolePolicy', RoleName='app-role', PolicyArn=pol) == ['iam:policy/app-policy']
    assert primary(cat, 'iam', 'CreatePolicyVersion', PolicyArn=pol, PolicyDocument='{}') == ['iam:policy/app-policy']
    assert primary(cat, 'iam', 'DeleteAccessKey', UserName='ci-user', AccessKeyId='AKIAEXAMPLE') == ['iam:user/ci-user']
    assert primary(cat, 'iam', 'AddRoleToInstanceProfile', InstanceProfileName='worker', RoleName='r') == ['iam:instance-profile/worker']


# ------------------------------------------------------------------ ec2
def test_ec2_plural_lists_give_one_ref_each_and_match_the_arn(cat):
    assert primary(cat, 'ec2', 'TerminateInstances', InstanceIds=['i-0a', 'i-0b']) == ['ec2:instance/i-0a', 'ec2:instance/i-0b']
    assert cat.parse_arn(arn('ec2', 'instance/i-0a')) == ResourceRef('ec2:instance', 'i-0a')


def test_ec2_security_group_vpc_subnet(cat):
    assert primary(cat, 'ec2', 'AuthorizeSecurityGroupIngress', GroupId='sg-0a', IpPermissions=[]) == ['ec2:security-group/sg-0a']
    assert cat.parse_arn(arn('ec2', 'security-group/sg-0a')) == ResourceRef('ec2:security-group', 'sg-0a')
    assert primary(cat, 'ec2', 'DeleteVpc', VpcId='vpc-0a') == ['ec2:vpc/vpc-0a']
    assert primary(cat, 'ec2', 'DeleteSubnet', SubnetId='subnet-0a') == ['ec2:subnet/subnet-0a']


def test_ec2_group_named_by_name_not_id_cannot_be_placed(cat):
    """GroupName is not the group's id: the catalog must not take one for the other."""
    refs = cat.refs(call(cat, 'ec2', 'AuthorizeSecurityGroupIngress', GroupName='web', IpPermissions=[]))
    assert refs.primary == () and refs.complete is False


def test_ec2_create_of_a_thing_whose_id_the_service_gives_is_complete(cat):
    refs = cat.refs(call(cat, 'ec2', 'CreateSecurityGroup', GroupName='cache', Description='d', VpcId='vpc-0a'))
    assert refs.primary == () and [str(r) for r in refs.mentioned] == ['ec2:vpc/vpc-0a'] and refs.complete


def test_ec2_create_tags_names_its_resources_by_bare_ids_and_cannot_be_placed(cat):
    assert cat.refs(call(cat, 'ec2', 'CreateTags', Resources=['i-0a'], Tags=[])).complete is False


# ------------------------------------------------------------------ dynamodb, sqs, sns
def test_dynamodb_table_by_name_and_arn(cat):
    want = ['dynamodb:table/episodes']
    assert primary(cat, 'dynamodb', 'UpdateTable', TableName='episodes') == want
    assert primary(cat, 'dynamodb', 'UpdateTable', TableName=arn('dynamodb', 'table/episodes')) == want
    assert cat.parse_arn(arn('dynamodb', 'table/episodes/index/*')) == ResourceRef('dynamodb:table', 'episodes')


def test_sqs_queue_by_url_and_by_arn_converge(cat):
    want = ['sqs:queue/jobs']
    assert primary(cat, 'sqs', 'SetQueueAttributes', QueueUrl=f'https://sqs.{R}.amazonaws.com/{A}/jobs', Attributes={}) == want
    assert primary(cat, 'sqs', 'PurgeQueue', QueueUrl=f'http://localhost:4566/{A}/jobs') == want
    assert cat.parse_arn(arn('sqs', 'jobs')) == ResourceRef('sqs:queue', 'jobs')


def test_sns_topic_and_subscription_endpoint(cat):
    refs = cat.refs(call(cat, 'sns', 'Subscribe', TopicArn=arn('sns', 'alerts'), Protocol='sqs', Endpoint=arn('sqs', 'jobs')))
    assert [str(r) for r in refs.primary] == ['sns:topic/alerts']
    assert [str(r) for r in refs.mentioned] == ['sqs:queue/jobs']


# ------------------------------------------------------------------ cloudfront, route53
def test_cloudfront_distribution_by_id(cat):
    assert primary(cat, 'cloudfront', 'UpdateDistribution', Id='E1ABC', DistributionConfig={}, IfMatch='x') == ['cloudfront:distribution/E1ABC']
    assert primary(cat, 'cloudfront', 'CreateInvalidation', DistributionId='E1ABC', InvalidationBatch={}) == ['cloudfront:distribution/E1ABC']


def test_route53_record_change_is_placed_on_the_hosted_zone(cat):
    want = ['route53:hostedzone/Z0123']
    batch = {'Changes': [{'Action': 'UPSERT', 'ResourceRecordSet': {'Name': 'a.example.com', 'Type': 'CNAME'}}]}
    assert primary(cat, 'route53', 'ChangeResourceRecordSets', HostedZoneId='Z0123', ChangeBatch=batch) == want
    assert primary(cat, 'route53', 'ChangeResourceRecordSets', HostedZoneId='/hostedzone/Z0123', ChangeBatch=batch) == want
    assert cat.parse_arn('arn:aws:route53:::hostedzone/Z0123') == ResourceRef('route53:hostedzone', 'Z0123')


# ------------------------------------------------------------------ rds, events, scheduler, logs
def test_rds_instance(cat):
    assert primary(cat, 'rds', 'ModifyDBInstance', DBInstanceIdentifier='db1') == ['rds:db/db1']
    assert cat.parse_arn(arn('rds', 'db:db1')) == ResourceRef('rds:db', 'db1')
    assert primary(cat, 'rds', 'ModifyDBCluster', DBClusterIdentifier='c1') == ['rds:cluster/c1']


def test_events_rule_by_name_and_arn(cat):
    want = ['events:rule-on-default-event-bus/nightly']
    assert primary(cat, 'events', 'DisableRule', Name='nightly') == want
    assert cat.parse_arn(arn('events', 'rule/nightly')) == ResourceRef('events:rule-on-default-event-bus', 'nightly')
    assert primary(cat, 'events', 'DisableRule', Name='nightly', EventBusName='orders') == ['events:rule-on-custom-event-bus/orders/nightly']
    assert primary(cat, 'events', 'PutTargets', Rule='nightly', Targets=[]) == want


def test_events_rule_on_named_default_bus_is_the_default_rule(cat):
    """Override: same_as_absent events:rule-on-custom-event-bus EventBusName=default."""
    assert primary(cat, 'events', 'DisableRule', Name='nightly', EventBusName='default') == ['events:rule-on-default-event-bus/nightly']


def test_scheduler_name_without_group_is_the_default_group(cat):
    """Override: absent_means scheduler:schedule GroupName=default."""
    want = ['scheduler:schedule/default/daily']
    assert primary(cat, 'scheduler', 'UpdateSchedule', Name='daily', ScheduleExpression='rate(1 day)', FlexibleTimeWindow={}, Target={}) == want
    assert cat.parse_arn(arn('scheduler', 'schedule/default/daily')) == ResourceRef('scheduler:schedule', 'default/daily')


def test_logs_group_by_name_and_by_arn_with_star(cat):
    want = ResourceRef('logs:log-group', '/aws/lambda/publisher')
    assert cat.refs(call(cat, 'logs', 'PutRetentionPolicy', logGroupName='/aws/lambda/publisher', retentionInDays=1)).primary == (want,)
    assert cat.parse_arn(arn('logs', 'log-group:/aws/lambda/publisher:*')) == want


# ------------------------------------------------------------------ kms, secrets, ssm
def test_kms_key_by_id_and_arn_and_alias_by_name_and_arn(cat):
    key = '1234abcd-12ab-34cd-56ef-1234567890ab'
    assert primary(cat, 'kms', 'DisableKey', KeyId=key) == [f'kms:key/{key}']
    assert primary(cat, 'kms', 'DisableKey', KeyId=arn('kms', f'key/{key}')) == [f'kms:key/{key}']
    assert primary(cat, 'kms', 'DisableKey', KeyId='alias/app') == ['kms:alias/app']
    assert primary(cat, 'kms', 'DisableKey', KeyId=arn('kms', 'alias/app')) == ['kms:alias/app']


def test_secret_by_name_and_by_arn_converge(cat):
    """Override: arn_suffix secretsmanager:Secret SecretId."""
    want = ['secretsmanager:Secret/app/api-key']
    assert primary(cat, 'secretsmanager', 'PutSecretValue', SecretId='app/api-key', SecretString='x') == want
    assert primary(cat, 'secretsmanager', 'PutSecretValue', SecretId=arn('secretsmanager', 'secret:app/api-key-AbC123'), SecretString='x') == want


def test_ssm_parameter_by_name_and_arn(cat):
    want = ['ssm:parameter/app/db-url']
    assert primary(cat, 'ssm', 'PutParameter', Name='/app/db-url', Value='v', Type='String', Overwrite=True) == want
    assert primary(cat, 'ssm', 'DeleteParameter', Name=arn('ssm', 'parameter/app/db-url')) == want


# ------------------------------------------------------------------ stepfunctions, ecs, elbv2, apigateway
def test_stepfunctions_state_machine_by_arn(cat):
    assert primary(cat, 'stepfunctions', 'UpdateStateMachine', stateMachineArn=arn('states', 'stateMachine:flow')) == ['states:statemachine/flow']


def test_ecs_service_by_names_and_by_arn(cat):
    assert primary(cat, 'ecs', 'UpdateService', cluster='prod', service='web') == ['ecs:service/prod/web']
    assert primary(cat, 'ecs', 'UpdateService', cluster='prod', service=arn('ecs', 'service/prod/web')) == ['ecs:service/prod/web']


def test_ecs_service_without_cluster_is_the_default_cluster(cat):
    """Override: absent_means ecs:service ClusterName=default."""
    assert primary(cat, 'ecs', 'UpdateService', service='web') == ['ecs:service/default/web']


def test_elbv2_load_balancer_by_arn(cat):
    lb = arn('elasticloadbalancing', 'loadbalancer/app/web/50dc6c495c0c9188')
    assert cat.refs(call(cat, 'elbv2', 'ModifyLoadBalancerAttributes', LoadBalancerArn=lb, Attributes=[])).primary == \
        (ResourceRef('elasticloadbalancing:loadbalancer/app/', 'web/50dc6c495c0c9188'),)


def test_apigateway_rest_api(cat):
    assert primary(cat, 'apigateway', 'UpdateRestApi', restApiId='a1b2c3', patchOperations=[]) == ['apigateway:RestApi/a1b2c3']


# ------------------------------------------------------------------ complete
def test_changing_call_without_its_resource_is_incomplete(cat):
    assert cat.refs(call(cat, 'lambda', 'UpdateFunctionConfiguration', Timeout=3)).complete is False


def test_reads_are_complete_even_unplaced(cat):
    assert cat.refs(call(cat, 'lambda', 'ListFunctions')).complete is True


def test_account_level_change_with_no_resource_in_the_list_is_complete(cat):
    refs = cat.refs(call(cat, 'iam', 'UpdateAccountPasswordPolicy', MinimumPasswordLength=14))
    assert cat.kind('iam', 'UpdateAccountPasswordPolicy') is Kind.WRITE and refs.primary == () and refs.complete


# ------------------------------------------------------------------ reads_of
def test_reads_of_fill_the_id_into_the_reads(cat):
    reads = cat.reads_of(ResourceRef('lambda:function', 'publisher'))
    assert ('lambda', 'GetFunction', {'FunctionName': 'publisher'}) in reads
    assert ('lambda', 'ListTags', {'Resource': arn('lambda', 'function:publisher')}) in reads
    assert ('scheduler', 'GetSchedule', {'GroupName': 'default', 'Name': 'daily'}) in cat.reads_of(ResourceRef('scheduler:schedule', 'default/daily'))
    assert ('ec2', 'DescribeSecurityGroups', {'GroupIds': ['sg-0a']}) in cat.reads_of(ResourceRef('ec2:security-group', 'sg-0a'))
    assert ('iam', 'GetRole', {'RoleName': 'app-role'}) in cat.reads_of(ResourceRef('iam:role', 'app-role'))


def test_reads_that_need_an_arn_wait_for_the_account():
    bare = AwsCatalog()
    reads = bare.reads_of(ResourceRef('lambda:function', 'publisher'))
    assert ('lambda', 'GetFunction', {'FunctionName': 'publisher'}) in reads
    assert not any(op == 'ListTags' for _, op, _ in reads)


def test_reads_never_include_data_plane_reads(cat):
    ops = {op for _, op, _ in cat.reads_of(ResourceRef('dynamodb:table', 'episodes'))}
    assert 'DescribeTable' in ops and not ops & {'Scan', 'Query', 'GetItem'}


# ------------------------------------------------------------------ resource types
def test_resource_type_flags_come_from_published_data(cat):
    bucket = cat.resource_type('s3:bucket')
    assert bucket.cfn_type == 'AWS::S3::Bucket' and bucket.holds_data and bucket.id_given_by_service is False
    assert cat.resource_type('s3:object').parent == 's3:bucket'
    assert cat.resource_type('ec2:security-group').id_given_by_service is True
    assert cat.resource_type('lambda:function').cfn_type == 'AWS::Lambda::Function'
    assert 'SecretString' in cat.resource_type('secretsmanager:Secret').write_only_settings
    assert cat.resource_type('nothing:here') is None


# ------------------------------------------------------------------ cost and speed
OVERRIDES = Path(__file__).resolve().parents[2] / 'src/emfirge/aws/data/overrides.json'


def test_every_override_says_why_and_has_its_test(cat):
    raw = json.loads(OVERRIDES.read_text())
    entries = [e for v in raw.values() if isinstance(v, list) for e in v]
    assert len(entries) == cat.overrides_count == 4
    here = Path(__file__).read_text()
    for e in entries:
        assert e['why'] and e['test'].startswith('tests/aws/test_catalog.py::')
        assert re.search(rf"def {e['test'].split('::')[1]}\(", here)


def test_first_use_of_a_service_is_fast():
    fresh = AwsCatalog()
    start = time.perf_counter()
    fresh.refs(Call('ecs', 'UpdateService', {'cluster': 'c', 'service': 's'}, Kind.WRITE, WIRE))
    assert time.perf_counter() - start < 0.1


def test_describe_calls_aws_cannot_scope_still_name_their_resources(cat):
    """EC2's Describe* actions list no resource type; a read of a branched group must still be routable."""
    assert primary(cat, 'ec2', 'DescribeSecurityGroups', GroupIds=['sg-0a']) == ['ec2:security-group/sg-0a']
    assert primary(cat, 'ec2', 'DescribeInstances', InstanceIds=['i-0a']) == ['ec2:instance/i-0a']
