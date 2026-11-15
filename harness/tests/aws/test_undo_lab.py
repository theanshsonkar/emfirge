"""The undo prover end to end on local emulators (lab only, never real AWS): an emulator plays the real account, a
fresh one is each branch's engine. Each change runs through the branch, the branch is sealed, the diff read, then
the prover puts the change back on the engine. The real account is never changed."""
from __future__ import annotations

import json

import boto3
import botocore.config
import pytest

from emfirge.aws.accounts import HttpAccount, sdk_client
from emfirge.aws.codec import AwsCodec
from emfirge.aws.engines import EmulatorEngine
from emfirge.aws.undo import prover_for
from emfirge.branch.proving import EngineSpent
from emfirge.core.model import ChangeType, Undo
from emfirge.server.wiring import build

pytestmark = pytest.mark.lab
REAL, ENGINE = 9790, 9791
REGION = 'us-west-2'
TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service':
                    'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})
POLICY = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sqs:*', 'Resource': '*'}]})
FN = f'arn:aws:lambda:{REGION}:000000000000:function:nothing-here'


class Through:
    def __init__(self, branch) -> None:
        self.name, self._branch = 'branch', branch

    def send(self, request):
        return self._branch.handle(request)


@pytest.fixture(scope='module')
def real(tmp_path_factory):
    work = tmp_path_factory.mktemp('undo-lab')
    e = EmulatorEngine(REAL, work, name='real')
    e.start()
    try:
        cfg = botocore.config.Config(retries={'max_attempts': 1})
        c = lambda s: boto3.client(s, endpoint_url=e.url, region_name=REGION, aws_access_key_id='x',
                                   aws_secret_access_key='x', verify=str(e.ca_path), config=cfg)
        c('ssm').put_parameter(Name='/lab/url', Value='old', Type='String')
        c('iam').create_role(RoleName='lab-role', AssumeRolePolicyDocument=TRUST)
        arn = c('iam').create_policy(PolicyName='lab-policy', PolicyDocument=POLICY)['Policy']['Arn']
        c('events').put_rule(Name='lab-rule', ScheduleExpression='rate(1 day)', State='ENABLED')
        c('events').put_targets(Rule='lab-rule', Targets=[{'Id': 't1', 'Arn': FN}])
        yield HttpAccount('real', e.url, str(e.ca_path)), c, arn, work
    finally:
        e.stop()


def prove(real, call):
    """Run `call(client_factory)` through a fresh branch; return the facts per change and the branch."""
    account, c, arn, work = real
    engine = EmulatorEngine(ENGINE, work)
    engine.start()
    try:
        codec = AwsCodec(REGION)
        branch = build(account, engine, REGION, codec)
        call(lambda s: sdk_client(Through(branch), s, REGION), arn)
        branch.seal()
        changes = branch.changes()
        prover = prover_for(branch, changes, codec)
        return {c.ref.type: (c.type, prover.prove(c)) for c in changes}, branch
    finally:
        engine.stop()


def test_a_parameter_overwritten_comes_back_with_a_new_version_so_no(real):
    facts, branch = prove(real, lambda c, arn: c('ssm').put_parameter(Name='/lab/url', Value='new', Type='String',
                                                                       Overwrite=True))
    kind, fact = facts['ssm:parameter']
    assert kind is ChangeType.MODIFIED and fact.undo is Undo.NO and 'Version' in fact.reasons[0]
    assert real[1]('ssm').get_parameter(Name='/lab/url')['Parameter']['Value'] == 'old'
    with pytest.raises(EngineSpent):
        branch.changes()


def test_an_attached_policy_is_detached_and_found_equal_so_yes(real):
    facts, _ = prove(real, lambda c, arn: c('iam').attach_role_policy(RoleName='lab-role', PolicyArn=arn))
    assert facts['iam:role'][1].undo is Undo.YES
    assert facts['iam:role'][1].reasons[0].startswith('put back on the branch and compared')


def test_a_created_role_is_deleted_and_gone_so_yes(real):
    facts, _ = prove(real, lambda c, arn: c('iam').create_role(RoleName='lab-new', AssumeRolePolicyDocument=TRUST))
    kind, fact = facts['iam:role']
    assert kind is ChangeType.CREATED and fact.undo is Undo.YES


def test_a_disabled_rule_is_enabled_again_so_yes(real):
    facts, _ = prove(real, lambda c, arn: c('events').disable_rule(Name='lab-rule'))
    assert facts['events:rule-on-default-event-bus'][1].undo is Undo.YES


def test_a_target_put_into_a_list_that_merges_is_not_taken_out_by_a_re_put_so_no(real):
    facts, _ = prove(real, lambda c, arn: c('events').put_targets(Rule='lab-rule', Targets=[{'Id': 't2', 'Arn': FN}]))
    fact = facts['events:rule-on-default-event-bus'][1]
    assert fact.undo is Undo.NO and 'ListTargetsByRule.Targets' in fact.reasons[0]
