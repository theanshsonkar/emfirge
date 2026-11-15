"""The layered catalog and copier: generic first, curated only where the generic one does not know. No network."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.codec import AwsCodec
from emfirge.aws.curated import Where, curated
from emfirge.aws.errors import UnknownType
from emfirge.aws.generic_copy import Copied
from emfirge.aws.layered import LayeredCatalog, LayeredCopier, copier_order, runs_code_actions
from emfirge.core.model import Kind, ResourceRef, WireRequest, WireResponse
from emfirge.core.ports import CannotTell

ACCT = '000000000000'
CODEC = AwsCodec('us-west-2')
GENERIC = AwsCatalog(account=ACCT, region='us-west-2')
CURATED, _, _ = curated(CODEC, Where('us-west-2', ACCT))
LAYERED = LayeredCatalog(GENERIC, CODEC, CURATED)
BARE = LayeredCatalog(GENERIC, CODEC, None)
RUNS_CODE = Path(__file__).resolve().parents[2] / 'src/emfirge/aws/data/runs_code.json'


def refs(catalog, service, op, **params):
    return catalog.refs(CODEC.encode(service, op, params))


# ------------------------------------------------------------------ kinds
@pytest.mark.parametrize('service,op', [('lambda', 'Invoke'), ('lambda', 'InvokeAsync'), ('apigateway', 'TestInvokeMethod'),
                                        ('stepfunctions', 'StartExecution'), ('ecs', 'RunTask'), ('ssm', 'SendCommand')])
def test_calls_that_run_customer_code_are_unknown(service, op):
    assert LAYERED.kind(service, op) is Kind.UNKNOWN and 'own code' in LAYERED.why_kind(service, op)


def test_every_runs_code_line_says_why_and_has_its_test():
    raw = json.loads(RUNS_CODE.read_text())
    here = Path(__file__).read_text()
    for e in raw['actions']:
        assert e['why'] and e['test'].startswith('tests/aws/test_layered.py::')
        assert f"def {e['test'].split('::')[1]}(" in here
    assert len(runs_code_actions()) == len(raw['actions']) == 6


def test_other_kinds_are_the_generic_catalogs():
    for service, op in [('lambda', 'PutFunctionEventInvokeConfig'), ('iam', 'GetRole'), ('sqs', 'ReceiveMessage')]:
        assert LAYERED.kind(service, op) is GENERIC.kind(service, op)


# ------------------------------------------------------------------ refs: one vocabulary
@pytest.mark.parametrize('service,op,params,want', [
    ('secretsmanager', 'GetSecretValue', {'SecretId': f'arn:aws:secretsmanager:us-west-2:{ACCT}:secret:app/k-AbC123'},
     ResourceRef('secretsmanager:Secret', 'app/k')),
    ('ssm', 'GetParameter', {'Name': '/app/db-url'}, ResourceRef('ssm:parameter', 'app/db-url')),
    ('ssm', 'GetParameter', {'Name': 'db-url'}, ResourceRef('ssm:parameter', 'db-url')),
    ('iam', 'GetPolicy', {'PolicyArn': f'arn:aws:iam::{ACCT}:policy/team/p'}, ResourceRef('iam:policy', 'p')),
    ('logs', 'PutRetentionPolicy', {'logGroupName': '/x/y', 'retentionInDays': 1}, ResourceRef('logs:log-group', '/x/y')),
])
def test_curated_and_generic_name_the_same_resource_the_same_way(service, op, params, want):
    assert refs(CURATED, service, op, **params).primary == refs(GENERIC, service, op, **params).primary == (want,)


def test_an_object_is_placed_on_its_bucket():
    r = refs(LAYERED, 's3', 'PutObject', Bucket='b', Key='k')
    assert r.primary == (ResourceRef('s3:bucket', 'b'),) and r.complete


def test_a_read_by_an_arn_member_reads_that_resource():
    r = refs(BARE, 'sns', 'GetSubscriptionAttributes', SubscriptionArn=f'arn:aws:sns:us-west-2:{ACCT}:alerts:1111-2222')
    assert r.primary == (ResourceRef('sns:topic', 'alerts'),)


def test_a_change_that_names_what_nothing_places_is_not_complete():
    assert refs(GENERIC, 'ecs', 'DeregisterTaskDefinition', taskDefinition='web:1').complete
    assert not refs(BARE, 'ecs', 'DeregisterTaskDefinition', taskDefinition='web:1').complete
    assert refs(BARE, 'iam', 'UpdateAccountPasswordPolicy', MinimumPasswordLength=12).complete   # account level


def test_the_curated_naming_adds_what_only_it_finds():
    r = refs(LAYERED, 's3', 'CopyObject', Bucket='new', Key='k', CopySource='media/feed.xml')
    assert ResourceRef('s3:bucket', 'media') in r.mentioned and ResourceRef('s3:bucket', 'media') not in refs(BARE, 's3', 'CopyObject', Bucket='new', Key='k', CopySource='media/feed.xml').all
    assert LAYERED.fallbacks['refs: named only by the curated naming'] >= 1


# ------------------------------------------------------------------ reads
def test_curated_reads_come_first_then_generic_then_lists():
    reads = LAYERED.reads_of(ResourceRef('sqs:queue', 'jobs'))
    ops = [op for _, op, _ in reads]
    assert ops[0] == 'GetQueueAttributes' and 'GetQueueUrl' in ops and ('sqs', 'ListQueues', {}) in reads


def test_the_read_named_after_the_type_comes_first():
    assert BARE.reads_of(ResourceRef('route53:hostedzone', 'Z1'))[0][1] == 'GetHostedZone'
    assert BARE.reads_of(ResourceRef('rds:db', 'd1'))[0][1] == 'DescribeDBInstances'


# ------------------------------------------------------------------ the copier stack
@dataclass
class Fake:
    name: str
    raises: type | None = None
    writes: bool = False
    calls: int = 0

    def copy(self, ref, place):
        self.calls += 1
        if self.writes:
            place.engine.send(CODEC.encode('sqs', 'CreateQueue', {'QueueName': 'q'}).wire)
        if self.raises:
            raise self.raises(f'{self.name} says no')
        return Copied(True, notes=(f'copied by {self.name}',), faithful=frozenset())


class Place:
    real = None

    class engine:
        name = 'engine'

        @staticmethod
        def send(request: WireRequest) -> WireResponse:
            return WireResponse(200, {}, b'{}')

    def need(self, ref): ...
    def engine_value(self, v): return v
    def same(self, a, b): ...
    def known(self, a): return False


def stack(first, second, order=None):
    return LayeredCopier({'generic': first, 'curated': second}, order or {'*': ('generic', 'curated')}, CODEC, LAYERED)


def test_the_next_copier_tries_only_when_the_first_does_not_know_the_type():
    a, b = Fake('generic', UnknownType), Fake('curated')
    assert stack(a, b).copy(ResourceRef('x:y', 'z'), Place()).notes == ('copied by curated',)
    a, b = Fake('generic', CannotTell), Fake('curated')
    with pytest.raises(CannotTell, match='generic says no'):
        stack(a, b).copy(ResourceRef('x:y', 'z'), Place())
    assert b.calls == 0


def test_a_copier_that_wrote_to_the_engine_is_not_followed_by_another():
    a, b = Fake('generic', UnknownType, writes=True), Fake('curated')
    with pytest.raises(CannotTell):
        stack(a, b).copy(ResourceRef('x:y', 'z'), Place())
    assert b.calls == 0


def test_the_order_per_type_is_the_measured_data():
    order = copier_order()
    assert order['*'] == ('generic', 'curated')
    assert all(v == ('curated', 'generic') for k, v in order.items() if k != '*')
    s = stack(Fake('generic'), Fake('curated'), order)
    assert s.order_of('dynamodb:table')[0] == 'curated' and s.order_of('lambda:function')[0] == 'generic'


def test_while_reading_data_is_off_a_change_taking_data_from_another_resource_is_not_placed():
    params = dict(Bucket='new', Key='k', CopySource='media/feed.xml')
    assert not refs(LayeredCatalog(GENERIC, CODEC, CURATED), 's3', 'CopyObject', **params).complete
    assert refs(LayeredCatalog(GENERIC, CODEC, CURATED, copy_data=True), 's3', 'CopyObject', **params).complete
    assert refs(LAYERED, 's3', 'PutObject', Bucket='b', Key='k').complete
