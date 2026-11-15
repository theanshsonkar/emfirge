"""Planning inverse calls (aws/undo/plan.py): given one journal entry and the reads before and after, the planned
inverse. Pure: botocore's models only, no network. The resources and values are made up."""
import pytest

from emfirge.aws.codec import AwsCodec
from emfirge.aws.undo.model import Models
from emfirge.aws.undo.plan import NoPlan, Read, View, plan, shows
from emfirge.branch.journal import Entry
from emfirge.core.model import ResourceRef

MODELS = Models(AwsCodec('us-west-2'))
PARAM = ResourceRef('ssm:parameter', 'app/url')
ROLE = ResourceRef('iam:role', 'app-role')
GROUP = ResourceRef('ec2:security-group', 'sg-0abc1234')


def entry(service, operation, refs=(), born=(), **params) -> Entry:
    return Entry(1, service, operation, params, 200, tuple(refs), tuple(born))


def view(*reads, ids=()) -> View:
    return View(tuple(Read(op, body, listed) for op, body, listed in reads), ids)


def no_names(service, operation, args):
    return ()


def steps(p):
    return [(s.operation, dict(s.args)) for s in p.steps]


# ---------------------------------------------------------------------- G1: the same operation, old values
def test_g1_puts_the_old_value_back_and_keeps_request_options():
    e = entry('ssm', 'PutParameter', [PARAM], Name='/app/url', Value='new', Type='String', Overwrite=True)
    before = view(('GetParameter', {'Parameter': {'Name': '/app/url', 'Value': 'old', 'Type': 'String', 'Version': 1}}, False))
    after = view(('GetParameter', {'Parameter': {'Name': '/app/url', 'Value': 'new', 'Type': 'String', 'Version': 2}}, False))
    p = plan(e, before, after, MODELS, no_names)
    assert p.strategy == 'G1'
    assert steps(p) == [('PutParameter', {'Name': '/app/url', 'Value': 'old', 'Type': 'String', 'Overwrite': True})]


def test_g1_refuses_when_the_reads_do_not_show_what_the_call_set():
    """The old value was found, but the read at the end of the session does not hold the value sent: a comparison
    could not see whether it came back."""
    e = entry('ssm', 'PutParameter', [PARAM], Name='/app/url', Value='new', Type='String', Overwrite=True)
    before = view(('GetParameter', {'Parameter': {'Value': 'old', 'Type': 'String'}}, False))
    after = view(('GetParameter', {'Parameter': {'Value': 'something else', 'Type': 'String'}}, False))
    with pytest.raises(NoPlan, match='do not show the value the call set for Value'):
        plan(e, before, after, MODELS, no_names)


def test_g1_finds_a_noun_qualified_name():
    doc = '{"Statement": [{"Principal": {"Service": "a"}}]}'
    new = '{"Statement": [{"Principal": {"Service": ["a", "b"]}}]}'
    e = entry('iam', 'UpdateAssumeRolePolicy', [ROLE], RoleName='app-role', PolicyDocument=new)
    p = plan(e, view(('GetRole', {'Role': {'AssumeRolePolicyDocument': doc}}, False)),
             view(('GetRole', {'Role': {'AssumeRolePolicyDocument': new}}, False)), MODELS, no_names)
    assert steps(p) == [('UpdateAssumeRolePolicy', {'RoleName': 'app-role', 'PolicyDocument': doc})]


def test_g1_sets_one_map_key_back_by_its_name():
    topic = ResourceRef('sns:topic', 'alerts')
    e = entry('sns', 'SetTopicAttributes', [topic], TopicArn='arn:aws:sns:us-west-2:000000000000:alerts',
              AttributeName='DisplayName', AttributeValue='New!')
    p = plan(e, view(('GetTopicAttributes', {'Attributes': {'DisplayName': ''}}, False)),
             view(('GetTopicAttributes', {'Attributes': {'DisplayName': 'New!'}}, False)), MODELS, no_names)
    assert steps(p) == [('SetTopicAttributes', {'TopicArn': 'arn:aws:sns:us-west-2:000000000000:alerts',
                                                'AttributeName': 'DisplayName', 'AttributeValue': ''})]


def test_g1_offers_the_map_narrowed_to_the_keys_the_call_set():
    queue = ResourceRef('sqs:queue', 'jobs')
    url = 'https://sqs.us-west-2.amazonaws.com/000000000000/jobs'
    e = entry('sqs', 'SetQueueAttributes', [queue], QueueUrl=url, Attributes={'VisibilityTimeout': '120'})
    p = plan(e, view(('GetQueueAttributes', {'Attributes': {'VisibilityTimeout': '45', 'QueueArn': 'q'}}, False)),
             view(('GetQueueAttributes', {'Attributes': {'VisibilityTimeout': '120', 'QueueArn': 'q'}}, False)),
             MODELS, no_names)
    assert p.steps[0].narrowed == {'QueueUrl': url, 'Attributes': {'VisibilityTimeout': '45'}}


def test_g1_looks_in_lists_only_at_the_item_of_the_resource():
    group = ResourceRef('logs:log-group', '/aws/lambda/fn')
    e = entry('logs', 'PutRetentionPolicy', [group], logGroupName='/aws/lambda/fn', retentionInDays=1)
    listing = lambda days: {'logGroups': [{'logGroupName': '/other', 'retentionInDays': 3},
                                          {'logGroupName': '/aws/lambda/fn', 'retentionInDays': days}]}
    p = plan(e, view(('DescribeLogGroups', listing(14), True), ids=('/aws/lambda/fn',)),
             view(('DescribeLogGroups', listing(1), True), ids=('/aws/lambda/fn',)), MODELS, no_names)
    assert steps(p) == [('PutRetentionPolicy', {'logGroupName': '/aws/lambda/fn', 'retentionInDays': 14})]


def test_a_setting_no_read_shows_is_not_planned():
    fn = ResourceRef('lambda:function', 'fn')
    e = entry('lambda', 'UpdateFunctionCode', [fn], FunctionName='fn', ZipFile=b'code')
    with pytest.raises(NoPlan, match='no inverse verb for Update'):
        plan(e, view(('GetFunctionConfiguration', {'CodeSha256': 'x'}, False)),
             view(('GetFunctionConfiguration', {'CodeSha256': 'y'}, False)), MODELS, no_names)


# ---------------------------------------------------------------------- G2: the inverse by name
@pytest.mark.parametrize('service,op,params,inverse', [
    ('iam', 'AttachRolePolicy', {'RoleName': 'r', 'PolicyArn': 'arn:aws:iam::000000000000:policy/p'}, 'DetachRolePolicy'),
    ('events', 'DisableRule', {'Name': 'nightly'}, 'EnableRule'),
    ('lambda', 'AddPermission', {'FunctionName': 'fn', 'StatementId': 's1', 'Action': 'lambda:InvokeFunction',
                                 'Principal': 's3.amazonaws.com'}, 'RemovePermission'),
    ('lambda', 'CreateAlias', {'FunctionName': 'fn', 'Name': 'live', 'FunctionVersion': '1'}, 'DeleteAlias'),
    ('iam', 'CreateRole', {'RoleName': 'new-role', 'AssumeRolePolicyDocument': '{}'}, 'DeleteRole'),
    ('kms', 'DisableKey', {'KeyId': 'k-1'}, 'EnableKey'),
    ('ec2', 'AuthorizeSecurityGroupIngress', {'GroupId': 'sg-0abc1234', 'IpPermissions': [
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]},
     'RevokeSecurityGroupIngress'),
])
def test_g2_inverts_by_verb_pair(service, op, params, inverse):
    p = plan(entry(service, op, **params), view(), view(), MODELS, no_names)
    assert p.strategy == 'G2' and p.steps[0].operation == inverse
    assert all(p.steps[0].args[k] == v for k, v in params.items() if k in p.steps[0].args)


def test_g2_deletes_what_a_put_made_from_nothing():
    e = entry('iam', 'PutRolePolicy', [ROLE], RoleName='app-role', PolicyName='extra', PolicyDocument='{}')
    p = plan(e, view(('ListRolePolicies', {'PolicyNames': ['logs']}, False)),
             view(('ListRolePolicies', {'PolicyNames': ['logs', 'extra']}, False)), MODELS, no_names)
    assert steps(p) == [('DeleteRolePolicy', {'RoleName': 'app-role', 'PolicyName': 'extra'})]


def test_g2_does_not_delete_what_a_put_only_changed():
    e = entry('ssm', 'PutParameter', [PARAM], Name='/app/url', Value='new', Type='String', Overwrite=True)
    before = view(('GetParameter', {'Parameter': {'Value': 'old', 'Type': 'String'}}, False))
    after = view(('GetParameter', {'Parameter': {'Value': 'other', 'Type': 'String'}}, False))
    with pytest.raises(NoPlan, match='Put changed something that existed'):
        plan(e, before, after, MODELS, no_names)


def test_g2_names_a_created_thing_by_the_id_the_service_gave_it():
    e = entry('ec2', 'CreateSecurityGroup', born=[GROUP], GroupName='cache', Description='c', VpcId='vpc-0abc1234')
    names = lambda service, op, args: (GROUP,) if args.get('GroupId') == GROUP.id else ()
    p = plan(e, view(), view(), MODELS, names)
    assert p.steps[0].operation == 'DeleteSecurityGroup' and p.steps[0].args['GroupId'] == GROUP.id
    assert 'GroupName' in p.steps[0].optional       # dropped if the engine refuses both together


def test_g2_untags_new_keys_and_puts_old_values_back():
    fn = 'arn:aws:lambda:us-west-2:000000000000:function:fn'
    e = entry('lambda', 'TagResource', [ResourceRef('lambda:function', 'fn')], Resource=fn,
              Tags={'team': 'media', 'env': 'prod'})
    p = plan(e, view(('ListTags', {'Tags': {'env': 'dev'}}, False)), view(), MODELS, no_names)
    assert steps(p) == [('UntagResource', {'Resource': fn, 'TagKeys': ['team']}),
                        ('TagResource', {'Resource': fn, 'Tags': {'env': 'dev'}})]


@pytest.mark.parametrize('service,op,params,why', [
    ('s3', 'PutObject', {'Bucket': 'b', 'Key': 'k', 'Body': b'x'}, 'writes data'),
    ('lambda', 'PublishVersion', {'FunctionName': 'fn'}, 'no operation DeleteVersion'),
    ('dynamodb', 'UpdateContinuousBackups', {'TableName': 't', 'PointInTimeRecoverySpecification': {
        'PointInTimeRecoveryEnabled': True}}, 'no inverse verb for Update'),
    ('iam', 'CreatePolicyVersion', {'PolicyArn': 'arn:aws:iam::000000000000:policy/p', 'PolicyDocument': '{}'},
     'no value for VersionId'),
    ('sqs', 'PurgeQueue', {'QueueUrl': 'https://sqs.us-west-2.amazonaws.com/000000000000/q'}, 'no inverse verb'),
])
def test_no_plan_says_why(service, op, params, why):
    with pytest.raises(NoPlan, match=why):
        plan(entry(service, op, **params), view(), view(), MODELS, no_names)


# ---------------------------------------------------------------------- does a read show a value
@pytest.mark.parametrize('seen,sent,expected', [
    ('120', 120, True), (True, 'true', True), ({'a': 1, 'b': 2}, {'a': 1}, True), ({'a': 1}, {'a': 2}, False),
    ([{'Id': 't1'}, {'Id': 't2'}], [{'Id': 't2'}], True), ([{'Id': 't1'}], [{'Id': 't2'}], False),
    ('{"a": [1, 2]}', '{"a":[1,2]}', True), (None, 'x', False),
])
def test_shows(seen, sent, expected):
    assert shows(seen, sent) is expected
