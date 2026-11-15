"""AwsReversibility: static undo facts from the compiled catalog and the change only. Pure: no network.

The DELETED cases follow experiment 11's table of steps that were not put back exactly (I10 RoleId, D12 table,
C04 security group id, X03 secret, N05 topic, P04 parameter, G03 log group); I18 (a deleted access key) is a
change of the user at state level and is caught by the credential detector. Every name is made up."""
from __future__ import annotations

import pytest

from emfirge.aws.catalog import AwsCatalog
from emfirge.aws.reversibility import LOST_ON_DELETE, NOT_PROVEN, AwsReversibility
from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef, Undo

F = FieldChange


@pytest.fixture(scope='module')
def rev() -> AwsReversibility:
    return AwsReversibility(AwsCatalog())


def ref(type_: str, id_: str = 'x') -> ResourceRef:
    return ResourceRef(type_, id_)


def assess(rev, type_, change_type, fields=(), calls=()):
    return rev.assess(Change(ref(type_), change_type, tuple(fields), tuple(calls)))


# ---------------------------------------------------------------------- deleted
@pytest.mark.parametrize('type_, must_say', [
    ('iam:role', []),                                                # I10: only the general reason (RoleId)
    ('dynamodb:table', ['holds data']),                              # D12
    ('ec2:security-group', ['AWS gives it its id', 'SecurityGroupIngress']),   # C04
    ('secretsmanager:Secret', ['AWS gives it its id', 'SecretString']),        # X03
    ('sns:topic', ['holds data', 'AWS gives it its id']),            # N05
    ('ssm:parameter', ['never read back (AllowedPattern, Description, Policies, Tier)']),  # P04
    ('logs:log-group', []),                                          # G03
    ('s3:object', ['holds data']),                                   # S06
    ('lambda:function', ['holds data', 'Code, PublishToLatestPublished, SnapStart']),   # L19
])
def test_a_delete_is_never_undoable_and_says_why(rev, type_, must_say):
    fact = assess(rev, type_, ChangeType.DELETED)
    assert fact.undo is Undo.NO
    assert fact.reasons[-1] == LOST_ON_DELETE
    text = ' | '.join(fact.reasons)
    for words in must_say:
        assert words in text


def test_a_delete_of_a_type_the_catalog_does_not_know(rev):
    fact = assess(rev, 'acme:thing', ChangeType.DELETED)
    assert fact.undo is Undo.NO and 'does not know the type' in fact.reasons[0]


# ---------------------------------------------------------------------- created
@pytest.mark.parametrize('type_', ['lambda:function', 'iam:role', 's3:bucket', 's3:object', 'dynamodb:table',
                                   'ec2:security-group', 'scheduler:schedule'])
def test_a_create_is_undoable_when_the_type_can_be_deleted(rev, type_):
    fact = assess(rev, type_, ChangeType.CREATED)
    assert fact.undo is Undo.YES and 'can be deleted again' in fact.reasons[0]


def test_a_create_of_a_type_with_no_delete_call_is_unknown(rev):
    assert assess(rev, 'servicequotas:quota', ChangeType.CREATED).undo is Undo.UNKNOWN
    assert assess(rev, 'acme:thing', ChangeType.CREATED).undo is Undo.UNKNOWN


def test_a_create_that_is_on_from_the_start_is_not_undoable(rev):
    """A new schedule that is enabled fires before anyone deletes it again."""
    fact = assess(rev, 'scheduler:schedule', ChangeType.CREATED, [F('State', None, 'ENABLED')])
    assert fact.undo is Undo.NO and 'turns something on' in fact.reasons[0]


# ---------------------------------------------------------------------- modified
def test_a_modify_is_not_proven_by_static_facts(rev):
    fact = assess(rev, 'lambda:function', ChangeType.MODIFIED, [F('Timeout', 30, 60)])
    assert fact.undo is Undo.UNKNOWN and fact.reasons == (NOT_PROVEN,)


def test_a_modify_of_a_write_only_setting_is_not_undoable(rev):
    fact = assess(rev, 'secretsmanager:Secret', ChangeType.MODIFIED, [F('SecretString', 'a', 'b')])
    assert fact.undo is Undo.NO
    assert fact.reasons[0].startswith('SecretString can be written but never read back')


@pytest.mark.parametrize('path', ['Code', 'Code.ZipFile', 'Configuration.Code.ZipFile'])
def test_write_only_matches_whole_blocks_and_nested_paths(rev, path):
    fact = assess(rev, 'lambda:function', ChangeType.MODIFIED, [F(path, 'a', 'b')])
    assert fact.undo is Undo.NO and fact.reasons[0].startswith(f'{path} can be written but never read back')


def test_write_only_does_not_match_a_readable_neighbour(rev):
    assert assess(rev, 'lambda:function', ChangeType.MODIFIED, [F('Code.Location', 'u1', 'u2')]).undo is Undo.UNKNOWN


def test_a_modify_that_turns_a_schedule_on(rev):
    fact = assess(rev, 'scheduler:schedule', ChangeType.MODIFIED, [F('State', 'DISABLED', 'ENABLED')])
    assert fact.undo is Undo.NO and 'turns something on' in fact.reasons[0]


def test_a_removed_access_key_is_not_undoable(rev):
    """Exp 11 I18: the user loses a key whose secret is never shown again."""
    fact = assess(rev, 'iam:user', ChangeType.MODIFIED,
                  [F('AccessKeyMetadata.0', {'AccessKeyId': 'AKIDEXAMPLE', 'Status': 'Active'}, None)])
    assert fact.undo is Undo.NO and 'credential' in fact.reasons[0]


def test_an_email_subscription_is_not_undoable(rev):
    """Exp 11 N03: the confirmation e-mail has gone out."""
    fact = assess(rev, 'sns:topic', ChangeType.MODIFIED,
                  [F('Subscriptions.1', None, {'Protocol': 'email', 'Endpoint': 'ops@example.com'})])
    assert fact.undo is Undo.NO and 'outside the account' in fact.reasons[0]


# ---------------------------------------------------------------------- action
@pytest.mark.parametrize('call', ['sqs.PurgeQueue', 'service-quotas.RequestServiceQuotaIncrease', 'lambda.Invoke'])
def test_an_action_that_runs_sends_or_empties_is_not_undoable(rev, call):
    fact = assess(rev, 'sqs:queue', ChangeType.ACTION, calls=[call])
    assert fact.undo is Undo.NO and call in fact.reasons[0]


def test_an_action_of_another_kind_is_unknown(rev):
    fact = assess(rev, 'dynamodb:table', ChangeType.ACTION, calls=['dynamodb.PutItem'])
    assert fact.undo is Undo.UNKNOWN and 'dynamodb.PutItem' in fact.reasons[0]


def test_same_change_same_fact(rev):
    c = Change(ref('scheduler:schedule'), ChangeType.MODIFIED, (F('State', 'DISABLED', 'ENABLED'),))
    assert rev.assess(c) == rev.assess(c) == AwsReversibility(AwsCatalog()).assess(c)
