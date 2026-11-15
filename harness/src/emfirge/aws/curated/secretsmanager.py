"""Secrets Manager: secrets (with their current value and resource policy)."""
from __future__ import annotations

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

SECRET = 'secretsmanager:Secret'


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


TYPES = [
    TypeSpec(SECRET, 'secretsmanager', params=('SecretId', 'Name'), arn=r'secret:(.+)-[A-Za-z0-9]{6}',
             lists=(('ListSecrets', 'SecretList', 'Name'),), removed_by=('DeleteSecret',),
             reads=lambda w, n: [('DescribeSecret', {'SecretId': n}), ('GetSecretValue', {'SecretId': n}),
                                 ('GetResourcePolicy', {'SecretId': n})],
             copy=copy_secret),
]
