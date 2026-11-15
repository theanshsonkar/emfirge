"""CloudWatch Logs groups, SSM parameters, Secrets Manager secrets and KMS keys."""
from __future__ import annotations

import re
from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

LOG_GROUP, PARAMETER, SECRET, KEY = 'logs:log-group', 'ssm:parameter', 'secretsmanager:Secret', 'kms:key'


def copy_log_group(x: CopyContext, n: str) -> bool:
    lg, e = x.real('logs'), x.engine('logs')
    g = [g for g in lg.describe_log_groups(logGroupNamePrefix=n)['logGroups'] if g['logGroupName'] == n]
    if not g:
        return False
    g = g[0]
    if lg.describe_subscription_filters(logGroupName=n)['subscriptionFilters']:
        raise CannotTell('subscription filters are not copied yet')
    kw = pick(g, 'logGroupClass')
    if g.get('kmsKeyId'):
        kw['kmsKeyId'] = x.ref(g['kmsKeyId'])
    tags = lg.list_tags_log_group(logGroupName=n).get('tags')
    e.create_log_group(logGroupName=n, **kw, **({'tags': tags} if tags else {}))
    if g.get('retentionInDays'):
        e.put_retention_policy(logGroupName=n, retentionInDays=g['retentionInDays'])
    for f in lg.describe_metric_filters(logGroupName=n)['metricFilters']:
        e.put_metric_filter(logGroupName=n, filterName=f['filterName'], filterPattern=f['filterPattern'],
                            metricTransformations=f['metricTransformations'])
    return True   # log events are not copied


def parameter_id(v: str, p: Mapping[str, Any]) -> str:
    """The ARN's form of a parameter name: without the leading '/'."""
    return v.lstrip('/')


def parameter_name(key: str) -> str:
    """Back from the ARN's form: a name with a path starts with '/'."""
    return '/' + key if '/' in key else key


def copy_parameter(x: CopyContext, key: str) -> bool:
    ssm, e = x.real('ssm'), x.engine('ssm')
    n = parameter_name(key)
    h = x.find(ssm.get_parameter_history, Name=n, WithDecryption=True)
    if h is None:
        return False
    if h.get('NextToken'):
        raise CannotTell('the parameter history is too long to replay')
    for i, v in enumerate(h['Parameters']):   # replaying the history reproduces the version numbers
        kw = pick(v, 'Description', 'AllowedPattern', 'Tier', 'DataType')
        if v['Type'] == 'SecureString' and v.get('KeyId'):
            kw['KeyId'] = x.ref(v['KeyId'])
        e.put_parameter(Name=n, Value=v['Value'], Type=v['Type'], Overwrite=i > 0, **kw)
        if v.get('Labels'):
            e.label_parameter_version(Name=n, ParameterVersion=v['Version'], Labels=v['Labels'])
    tags = ssm.list_tags_for_resource(ResourceType='Parameter', ResourceId=n).get('TagList')
    if tags:
        e.add_tags_to_resource(ResourceType='Parameter', ResourceId=n, Tags=tags)
    return True


def copy_secret(x: CopyContext, n: str) -> bool:
    sm, e = x.real('secretsmanager'), x.engine('secretsmanager')
    d = x.find(sm.describe_secret, SecretId=n)
    if d is None:
        return False
    if d.get('DeletedDate') or d.get('RotationEnabled'):
        raise CannotTell('secrets pending deletion or with rotation are not copied yet')
    v = x.find(sm.get_secret_value, SecretId=n) or {}
    kw = pick(d, 'Description', 'Tags')
    kw.update(pick(v, 'SecretString', 'SecretBinary'))
    if d.get('KmsKeyId'):
        kw['KmsKeyId'] = x.ref(d['KmsKeyId'])
    ed = e.create_secret(Name=d['Name'], **kw)
    x.same(d['ARN'], ed['ARN'])
    if v.get('VersionId') and ed.get('VersionId'):
        x.same(v['VersionId'], ed['VersionId'])
    pol = sm.get_resource_policy(SecretId=n).get('ResourcePolicy')
    if pol:
        e.put_resource_policy(SecretId=d['Name'], ResourcePolicy=pol)
    return True


def key_id(v: str, p: Mapping[str, Any]) -> str | None:
    """A key id; an alias name cannot be told apart from a key without a read, so it is not recognized."""
    return v if re.fullmatch(r'(mrk-)?[0-9a-f-]{32,36}', v) else None


def copy_key(x: CopyContext, k: str) -> bool:
    kms, e = x.real('kms'), x.engine('kms')
    m = x.find(kms.describe_key, KeyId=k)
    if m is None:
        return False
    m = m['KeyMetadata']
    if m.get('KeyManager') == 'AWS' or m.get('Origin') != 'AWS_KMS' or m.get('MultiRegion'):
        raise CannotTell('AWS managed, imported and multi-Region keys are not copied')
    kw = pick(m, 'Description', 'KeyUsage', 'KeySpec')
    tags = kms.list_resource_tags(KeyId=k).get('Tags')
    if tags:
        kw['Tags'] = tags
    ek = e.create_key(Policy=kms.get_key_policy(KeyId=k, PolicyName='default')['Policy'], **kw)['KeyMetadata']['KeyId']
    x.same(k, ek)
    if m.get('KeySpec', 'SYMMETRIC_DEFAULT') == 'SYMMETRIC_DEFAULT' and kms.get_key_rotation_status(KeyId=k).get('KeyRotationEnabled'):
        e.enable_key_rotation(KeyId=ek)
    for a in kms.list_aliases(KeyId=k)['Aliases']:
        e.create_alias(AliasName=a['AliasName'], TargetKeyId=ek)
    if m['KeyState'] == 'Disabled':
        e.disable_key(KeyId=ek)
    elif m['KeyState'] == 'PendingDeletion':
        e.schedule_key_deletion(KeyId=ek, PendingWindowInDays=m.get('PendingDeletionWindowInDays', 30))
    elif m['KeyState'] != 'Enabled':
        raise CannotTell(f"keys in state {m['KeyState']} are not copied")
    return True   # the key material is new: what the real key encrypted cannot be decrypted on the branch


TYPES = [
    TypeSpec(LOG_GROUP, 'logs', params=('logGroupName', 'logGroupIdentifier'), arn=r'log-group:([^:]+)(?::.*)?',
             lists=(('DescribeLogGroups', 'logGroups', 'logGroupName'),), removed_by=('DeleteLogGroup',),
             reads=lambda w, n: [('DescribeMetricFilters', {'logGroupName': n}),
                                 ('DescribeSubscriptionFilters', {'logGroupName': n})],
             copy=copy_log_group),
    TypeSpec(PARAMETER, 'ssm', params=('Name',), arn=r'parameter/(.+)', ops=r'Parameter',
             lists=(('DescribeParameters', 'Parameters', 'Name'),), removed_by=('DeleteParameter',), canon=parameter_id,
             reads=lambda w, k: [('GetParameter', {'Name': parameter_name(k)})], copy=copy_parameter),
    TypeSpec(SECRET, 'secretsmanager', params=('SecretId', 'Name'), arn=r'secret:(.+)-[A-Za-z0-9]{6}', ops=r'Secret',
             lists=(('ListSecrets', 'SecretList', 'Name'),), removed_by=('DeleteSecret',),
             reads=lambda w, n: [('DescribeSecret', {'SecretId': n}), ('GetSecretValue', {'SecretId': n}),
                                 ('GetResourcePolicy', {'SecretId': n})],
             copy=copy_secret),
    TypeSpec(KEY, 'kms', params=('KeyId', 'TargetKeyId'), arn=r'key/(.+)', service_ids=True,
             lists=(('ListKeys', 'Keys', 'KeyId'),), canon=key_id,
             reads=lambda w, k: [('DescribeKey', {'KeyId': k}), ('GetKeyPolicy', {'KeyId': k, 'PolicyName': 'default'}),
                                 ('GetKeyRotationStatus', {'KeyId': k}), ('ListResourceTags', {'KeyId': k}),
                                 ('ListAliases', {'KeyId': k})],
             copy=copy_key),
]
