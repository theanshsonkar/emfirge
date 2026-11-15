"""The generic detectors on real field names and call names from many AWS services (and their known misses).

The detectors know no service: these names come from the services' own read answers and SDK operations, and show
that one short list of words carries across them. Pure."""
from __future__ import annotations

import pytest

from emfirge.core.model import FieldChange
from emfirge.gate.detectors import action_reason, field_reasons, leaves, segments

F = FieldChange

TURNS_ON = [   # (service, field change)
    ('scheduler', F('State', 'DISABLED', 'ENABLED')),
    ('events', F('State', 'DISABLED', 'ENABLED')),
    ('lambda', F('Environment.Variables.DRY_RUN', 'true', 'false')),
    ('lambda', F('Environment.Variables.DRY_RUN', 'true', None)),
    ('lambda', F('EventSourceMappings.0.State', 'Disabled', 'Enabled')),
    ('dynamodb', F('ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus',
                   'DISABLED', 'ENABLED')),
    ('dynamodb', F('TimeToLiveDescription.TimeToLiveStatus', None, 'ENABLED')),
    ('kms', F('KeyMetadata.KeyState', 'Disabled', 'Enabled')),
    ('kms', F('KeyMetadata.Enabled', False, True)),
    ('cloudwatch', F('MetricAlarms.0.ActionsEnabled', False, True)),
    ('cloudfront', F('DistributionConfig.Enabled', False, True)),
    ('ec2', F('Reservations.0.Instances.0.Monitoring.State', 'disabled', 'enabled')),
    ('s3', F('VersioningConfiguration.Status', None, 'Enabled')),
    ('codepipeline', F('stageStates.0.inboundTransitionState.enabled', False, True)),
]

NOT_TURNING_ON = [
    ('kms', F('KeyMetadata.KeyState', 'Enabled', 'Disabled')),                 # turning off
    ('events', F('State', 'ENABLED', 'DISABLED')),
    ('s3', F('VersioningConfiguration.Status', 'Enabled', 'Suspended')),
    ('lambda', F('LastUpdateStatus', 'Successful', 'InProgress')),            # a status, not a switch value
    ('lambda', F('Environment.Variables.DRY_RUN', 'false', 'true')),           # back to dry run
    ('lambda', F('Timeout', 30, 60)),
    ('lambda', F('Configuration.State', None, 'Active')),                     # 'Active' means ready, not running
    ('dynamodb', F('Table.TableStatus', None, 'ACTIVE')),
    ('s3', F('PublicAccessBlockConfiguration.BlockPublicAcls', True, False)),  # left to the public-access lens
    ('sqs', F('Attributes.VisibilityTimeout', '45', '120')),
    ('iam', F('Role.AssumeRolePolicyDocument.Statement.0.Effect', 'Allow', 'Deny')),
]

KNOWN_MISSES = [   # things that do turn something on, in words the list does not have (documented, not hidden)
    ('ecs', F('services.0.desiredCount', 0, 2)),
    ('glue', F('Trigger.State', 'CREATED', 'ACTIVATED')),
    ('cloudtrail', F('IsLogging', False, True)),
    ('autoscaling', F('AutoScalingGroups.0.SuspendedProcesses.0.ProcessName', 'Launch', None)),
]

OUTSIDE = [
    ('sns', F('Subscriptions.1.Endpoint', None, 'ops@example.com')),
    ('sns', F('Subscriptions.1.Endpoint', None, 'https://hooks.example.com/alert')),
    ('sns', F('Subscriptions.1.Endpoint', None, '+15555550100')),
    ('budgets', F('Subscribers.0.Address', None, 'owner@example.com')),
    ('events', F('ApiDestination.InvocationEndpoint', 'https://a.example.com', 'https://b.example.com')),
    ('lambda', F('Environment.Variables.ALERT_EMAIL', None, 'me@example.com')),
]
NOT_OUTSIDE = [
    ('ec2', F('NetworkInterfaces.0.PrivateIpAddress', None, '10.0.0.5')),
    ('sns', F('Subscriptions.1.Endpoint', None, 'arn-of-a-queue-in-the-account')),
    ('sns', F('Subscriptions.1.Endpoint', 'ops@example.com', 'ops@example.com')),
    ('lambda', F('Environment.Variables.FEED_URL', None, 'https://feeds.example.com')),   # no address word in key
]

CREDENTIAL = [
    ('iam', F('AccessKeyMetadata.0', {'AccessKeyId': 'AKIDEXAMPLE', 'Status': 'Active'}, None)),
    ('iam', F('AccessKeyMetadata.0.AccessKeyId', 'AKIDEXAMPLE', None)),
    ('iam', F('LoginProfile.Password', 'x', 'y')),
    ('secretsmanager', F('SecretString', 'old', 'new')),
    ('rds', F('DBInstances.0.MasterUserSecret', {'SecretArn': 's1', 'SecretStatus': 'active'}, None)),
]
NOT_CREDENTIAL = [
    ('iam', F('AccessKeyMetadata.0.Status', 'Active', 'Inactive')),       # deactivating is reversible
    ('rds', F('DBInstances.0.MasterUserSecret.SecretArn', 's1', 's2')),   # a pointer, not the secret
    ('iam', F('AccessKeyMetadata.1', None, {'AccessKeyId': 'AKIDNEW'})),  # a new key (nothing lost)
    ('kms', F('KeyMetadata.KeyId', 'k1', 'k1')),
]


def services(*tables) -> set[str]:
    return {s for table in tables for s, _ in table}


def test_the_lists_cover_at_least_eight_services():
    assert len(services(TURNS_ON, NOT_TURNING_ON, OUTSIDE, CREDENTIAL)) >= 8


@pytest.mark.parametrize('service, change', TURNS_ON, ids=lambda x: x if isinstance(x, str) else x.path)
def test_turns_on(service, change):
    assert any('turns something on' in r for r in field_reasons([change]))


@pytest.mark.parametrize('service, change', NOT_TURNING_ON + KNOWN_MISSES,
                         ids=lambda x: x if isinstance(x, str) else x.path)
def test_does_not_turn_on(service, change):
    assert not any('turns something on' in r for r in field_reasons([change]))


@pytest.mark.parametrize('service, change', OUTSIDE, ids=lambda x: x if isinstance(x, str) else x.path)
def test_outside_address(service, change):
    assert any('outside the account' in r for r in field_reasons([change]))


@pytest.mark.parametrize('service, change', NOT_OUTSIDE, ids=lambda x: x if isinstance(x, str) else x.path)
def test_not_an_outside_address(service, change):
    assert not any('outside the account' in r for r in field_reasons([change]))


@pytest.mark.parametrize('service, change', CREDENTIAL, ids=lambda x: x if isinstance(x, str) else x.path)
def test_credential_lost(service, change):
    assert any('credential' in r for r in field_reasons([change]))


@pytest.mark.parametrize('service, change', NOT_CREDENTIAL, ids=lambda x: x if isinstance(x, str) else x.path)
def test_credential_not_lost(service, change):
    assert not any('credential' in r for r in field_reasons([change]))


@pytest.mark.parametrize('call', ['sqs.PurgeQueue', 'lambda.Invoke', 'sns.Publish', 'ses.SendEmail',
                                  'stepfunctions.StartExecution', 'service-quotas.RequestServiceQuotaIncrease',
                                  'ec2.RebootInstances', 'ssm.SendCommand', 'athena.StartQueryExecution'])
def test_action_verbs(call):
    assert action_reason([call])


@pytest.mark.parametrize('call', ['dynamodb.PutItem', 's3.PutObject', 'sqs.SetQueueAttributes', 'acme.Runaway',
                                  'acme.Starting'])
def test_not_action_verbs(call):
    """'Runaway' and 'Starting' begin with a verb's letters, not with the verb."""
    assert action_reason([call]) is None


def test_segments_normalize_paths():
    assert segments('Environment.Variables.DRY_RUN') == ['environment', 'variables', 'dryrun']
    assert segments('LifecycleConfiguration/Rules/*/Transition') == ['lifecycleconfiguration', 'rules', 'transition']
    assert segments('Reservations.0.Instances.12.State') == ['reservations', 'instances', 'state']


def test_leaves_split_whole_items_into_values():
    got = list(leaves([F('Items.0', {'Id': 'a', 'Tags': [{'k': 'v'}]}, None)]))
    assert [(x.path, x.before, x.after) for x in got] == [('Items.0.Id', 'a', None), ('Items.0.Tags.0.k', 'v', None)]


def test_one_reason_per_kind_and_no_reason_for_nothing():
    assert field_reasons([]) == ()
    twice = [F('State', 'DISABLED', 'ENABLED'), F('State', 'DISABLED', 'ENABLED')]
    assert len(field_reasons(twice)) == 1
