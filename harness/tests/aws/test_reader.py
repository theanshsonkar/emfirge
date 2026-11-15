"""The reader of the account's settings, without a network: placing list items as the catalog's refs (experiment 21's
crawl and adapter fixes, one test each), and the reader's order, budget and reverse reads against a fake account."""
from __future__ import annotations

import json
from typing import Any

import pytest

from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.places import Places, fill_value, item_context
from emfirge.aws.reader import AccountReader, ReaderSettings, plain
from emfirge.core.model import Change, ChangeType, ResourceRef, WireRequest, WireResponse

A = '000000000000'


@pytest.fixture(scope='module')
def codec() -> AwsCodec:
    return AwsCodec('us-west-2')


@pytest.fixture(scope='module')
def catalog() -> AwsCatalog:
    return AwsCatalog(account=A, region='us-west-2')


@pytest.fixture(scope='module')
def places(codec, catalog) -> Places:
    return Places(codec, catalog)


# ---------------------------------------------------------------------- crawl gaps (experiment 21)
def test_a_parameter_is_filled_from_its_stem_plus_arn(places, codec):
    """taskDefinition from a listing's taskDefinitionArns."""
    ctx = item_context({}, {}, 'taskDefinitionArn', f'arn:aws:ecs:us-west-2:{A}:task-definition/web:3')
    assert places.fill('ecs', 'DescribeTaskDefinition', ctx) == {'taskDefinition': f'arn:aws:ecs:us-west-2:{A}:task-definition/web:3'}


def test_a_list_parameter_takes_one_value(codec):
    shape = codec.model('ecs').operation_model('DescribeServices').input_shape.members['services']
    assert fill_value({'serviceArn': 'arn:x'}, 'services', shape) == ['arn:x']


def test_a_read_that_answers_nothing_without_all_is_asked_for_all(places):
    assert places.extras('sqs', 'GetQueueAttributes') == {'AttributeNames': ['All']}


def test_a_list_of_the_accounts_own_things_only(places):
    assert places.extras('iam', 'ListPolicies') == {'Scope': 'Local'}


def test_lowercase_items_and_id_are_placed(places):
    item = {'id': 'a1b2c3', 'name': 'shop', 'createdDate': 'x', 'apiKeySource': 'HEADER', 'endpointConfiguration': {}}
    got = places.place('apigateway', 'GetRestApis', 'items', '', item, {})
    assert got and got.ref.id == 'a1b2c3' and got.ref.type.lower() == 'apigateway:restapi'


def test_a_listing_that_needs_a_parent_is_known(places):
    assert ('ListServices', 'ecs:service') in places.listings('ecs')


# ---------------------------------------------------------------------- one resource is one ref
def test_a_load_balancer_is_one_resource_by_its_arn(places, catalog):
    arn = f'arn:aws:elasticloadbalancing:us-west-2:{A}:loadbalancer/app/web/50dc6c495c0c9188'
    item = {'LoadBalancerArn': arn, 'LoadBalancerName': 'web', 'DNSName': 'web-1.elb', 'Type': 'application', 'Scheme': 'x'}
    got = places.place('elbv2', 'DescribeLoadBalancers', 'LoadBalancers', '', item, {})
    assert got.ref == catalog.parse_arn(arn)


def test_a_role_named_with_its_internal_id_is_the_role(places):
    item = {'RoleName': 'app-role', 'RoleId': 'AROA1234567890ABCDEF'}
    got = places.place('iam', 'ListEntitiesForPolicy', 'PolicyRoles', '', item, {'PolicyArn': f'arn:aws:iam::{A}:policy/p'})
    assert got.ref == ResourceRef('iam:role', 'app-role')


def test_a_role_listed_under_a_path_is_the_role_by_name(places):
    item = {'RoleName': 'r1', 'RoleId': 'AROA1', 'Arn': f'arn:aws:iam::{A}:role/team/r1', 'Path': '/team/'}
    assert places.place('iam', 'ListRoles', 'Roles', '', item, {}).ref == ResourceRef('iam:role', 'r1')


def test_an_aws_owned_policy_is_not_a_resource_of_the_account(places):
    item = {'PolicyName': 'AdministratorAccess', 'Arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
    assert places.place('iam', 'ListPolicies', 'Policies', '', item, {}) is None


def test_a_two_field_reference_is_a_reference_not_a_whole_resource(places):
    got = places.place('iam', 'ListAttachedRolePolicies', 'AttachedPolicies', '',
                       {'PolicyName': 'p', 'PolicyArn': f'arn:aws:iam::{A}:policy/p'}, {'RoleName': 'r'})
    assert got.ref == ResourceRef('iam:policy', 'p') and not got.full


@pytest.mark.parametrize('service,op,key,parent,item,expected', [
    ('sqs', 'ListQueues', 'QueueUrls', '', f'https://sqs.us-west-2.amazonaws.com/{A}/orders', 'sqs:queue/orders'),
    ('dynamodb', 'ListTables', 'TableNames', '', 't1', 'dynamodb:table/t1'),
    ('s3', 'ListBuckets', 'Buckets', '', {'Name': 'b1', 'CreationDate': 'x'}, 's3:bucket/b1'),
    ('ec2', 'DescribeInstances', 'Instances', 'Reservations', {'InstanceId': 'i-0123456789abcdef0'}, 'ec2:instance/i-0123456789abcdef0'),
    ('cloudfront', 'ListDistributions', 'Items', 'DistributionList', {'Id': 'E2ABCDEF123456', 'DomainName': 'd.example.net'},
     'cloudfront:distribution/E2ABCDEF123456'),
    ('scheduler', 'ListSchedules', 'Schedules', '', {'Name': 'weekly', 'GroupName': 'default', 'State': 'ENABLED'},
     'scheduler:schedule/default/weekly'),
    ('ecs', 'ListServices', 'serviceArns', '', f'arn:aws:ecs:us-west-2:{A}:service/shop/web', 'ecs:service/shop/web'),
])
def test_items_are_placed_as_the_catalogs_refs(places, service, op, key, parent, item, expected):
    assert str(places.place(service, op, key, parent, item, {}).ref) == expected


def test_a_reservation_is_not_a_resource_its_instances_are(places):
    assert places.place('ec2', 'DescribeInstances', 'Reservations', '', {'ReservationId': 'r-0123456789abcdef0'}, {}) is None


# ---------------------------------------------------------------------- the reader on a fake account
class FakeAccount:
    """Answers a few JSON reads; every other read is 'not found'. Fails the test if anything but a read arrives."""
    name = 'fake'

    def __init__(self, codec: AwsCodec, catalog: AwsCatalog, answers: dict[str, Any]) -> None:
        self._codec, self._catalog, self._answers = codec, catalog, answers
        self.seen: list[str] = []

    def send(self, request: WireRequest) -> WireResponse:
        call = self._codec.decode(request)
        assert call and self._catalog.kind(call.service, call.operation).reads_only, call
        self.seen.append(call.name)
        answer = self._answers.get(call.name)
        if callable(answer):
            answer = answer(call.params)
        if answer is None:
            return WireResponse(400, {'Content-Type': 'application/x-amz-json-1.0'},
                                json.dumps({'__type': 'ResourceNotFoundException', 'message': 'no'}).encode())
        body = bytes(answer) if isinstance(answer, bytes) else json.dumps(answer).encode()
        return WireResponse(200, {'Content-Type': 'application/json'}, body)


FN_ARN = f'arn:aws:lambda:us-west-2:{A}:function:publisher'
TABLE_ARN = f'arn:aws:dynamodb:us-west-2:{A}:table/episodes'
ANSWERS = {
    'dynamodb.ListTables': {'TableNames': ['episodes', 'unused']},
    'dynamodb.DescribeTable': lambda p: {'Table': {'TableName': p['TableName'], 'TableArn': f'arn:aws:dynamodb:us-west-2:{A}:table/{p["TableName"]}',
                                                   'StreamSpecification': {'StreamEnabled': False}}},
    'lambda.ListFunctions': {'Functions': [{'FunctionName': 'publisher', 'FunctionArn': FN_ARN, 'Runtime': 'python3.12',
                                            'Environment': {'Variables': {'TABLE': TABLE_ARN}}}]},
    'lambda.ListEventSourceMappings': {'EventSourceMappings': [
        {'UUID': '0b6f3d2e-4a7c-4d6b-9c51-0f2b8d7a6e11', 'FunctionArn': FN_ARN, 'EventSourceArn': TABLE_ARN, 'State': 'Enabled',
         'BatchSize': 10}]},
}


def reader(codec, catalog, budget=400, answers=ANSWERS) -> tuple[AccountReader, FakeAccount]:
    account = FakeAccount(codec, catalog, answers)
    settings = ReaderSettings(budget=budget, services=('lambda', 'dynamodb'))
    return AccountReader(account, codec, catalog, 'us-west-2', settings), account


def test_states_are_keyed_by_the_catalogs_refs_and_the_function_names_the_table(codec, catalog):
    r, account = reader(codec, catalog)
    got = r.before([Change(ResourceRef('dynamodb:table', 'episodes'), ChangeType.DELETED)])
    table, fn = ResourceRef('dynamodb:table', 'episodes'), ResourceRef('lambda:function', 'publisher')
    assert {table, fn, ResourceRef('dynamodb:table', 'unused')} <= set(got.states)
    assert TABLE_ARN in json.dumps(got.states[fn])
    assert got.reads == len(account.seen) and not got.unknowns
    assert account.seen[0].startswith('dynamodb.')        # the changed resource is read first


def test_a_created_resource_is_not_read_on_the_real_account(codec, catalog):
    r, account = reader(codec, catalog)
    r.before([Change(ResourceRef('dynamodb:table', 'brand-new'), ChangeType.CREATED)])
    assert not any('brand-new' in json.dumps(c) for c in account.seen)


def test_the_budget_stops_the_reader_with_an_unknown(codec, catalog):
    r, account = reader(codec, catalog, budget=5)
    got = r.before([Change(ResourceRef('dynamodb:table', 'episodes'), ChangeType.DELETED)])
    assert got.reads == 5 == len(account.seen)
    assert [u.where for u in got.unknowns] == ['reader'] and 'budget of 5 reads' in got.unknowns[0].what


def test_a_changed_resource_keeps_only_its_own_reads(codec, catalog):
    """So its state before compares with the branch's state after, which is made of the same reads."""
    r, _ = reader(codec, catalog)
    table = ResourceRef('dynamodb:table', 'episodes')
    got = r.before([Change(table, ChangeType.MODIFIED)])
    assert not any(name.endswith('[]') for name in got.states[table])


IAM_XML = 'https://iam.amazonaws.com/doc/2010-05-08/'
PROFILE_ARN = f'arn:aws:iam::{A}:instance-profile/worker-profile'


def xml(op: str, inner: str) -> str:
    return f'<{op}Response xmlns="{IAM_XML}"><{op}Result>{inner}</{op}Result></{op}Response>'


class XmlAccount(FakeAccount):
    def send(self, request: WireRequest) -> WireResponse:
        r = super().send(request)
        if r.status == 200:
            return WireResponse(200, {'Content-Type': 'text/xml'}, r.body)
        return WireResponse(404, {'Content-Type': 'text/xml'}, b'<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity'
                                                              b'</Code><Message>no</Message></Error></ErrorResponse>')


def test_a_reverse_read_records_the_other_resource_and_not_a_link_to_it(codec, catalog):
    """'the instance profiles of this role' are profiles that name the role, not the other way round."""
    role = ResourceRef('iam:role', 'worker-role')
    answers = {
        'iam.GetRole': lambda p: xml('GetRole', f'<Role><RoleName>worker-role</RoleName><RoleId>AROA0000000000000001</RoleId>'
                                                f'<Arn>arn:aws:iam::{A}:role/worker-role</Arn><Path>/</Path></Role>').encode(),
        'iam.ListInstanceProfilesForRole': lambda p: xml('ListInstanceProfilesForRole', (
            '<InstanceProfiles><member><InstanceProfileName>worker-profile</InstanceProfileName>'
            f'<InstanceProfileId>AIPA0000000000000001</InstanceProfileId><Arn>{PROFILE_ARN}</Arn><Path>/</Path>'
            f'<Roles><member><RoleName>worker-role</RoleName><Arn>arn:aws:iam::{A}:role/worker-role</Arn></member></Roles>'
            '</member></InstanceProfiles>')).encode(),
    }
    account = XmlAccount(codec, catalog, {})
    account._answers = {k: (lambda f: (lambda p: _Raw(f(p))))(v) for k, v in answers.items()}
    r = AccountReader(account, codec, catalog, 'us-west-2', ReaderSettings(services=()))
    got = r.before([Change(role, ChangeType.MODIFIED)])
    profile = ResourceRef('iam:instance-profile', 'worker-profile')
    assert profile in got.states
    assert 'worker-role' in json.dumps(got.states[profile])
    assert 'worker-profile' not in json.dumps(got.states[role])


class _Raw(bytes):
    """An answer body already in its wire format."""


def test_the_branchs_states_are_parsed_like_the_readers(codec, catalog):
    r, _ = reader(codec, catalog)
    xml = {'<GetRoleResponse': {'GetRoleResult': {'Role': {'RoleName': 'r', 'Arn': f'arn:aws:iam::{A}:role/r',
                                                           'CreateDate': '2026-01-01T00:00:00Z'}}}}
    out = r.after({ResourceRef('iam:role', 'r'): {'GetRole': xml}})
    assert out[ResourceRef('iam:role', 'r')]['GetRole']['Role']['RoleName'] == 'r'


def test_plain_turns_times_into_text():
    import datetime
    assert plain({'a': [datetime.datetime(2026, 1, 1)]}) == {'a': ['2026-01-01T00:00:00']}
