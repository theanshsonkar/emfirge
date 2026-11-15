"""KMS: customer managed keys (new key material: what the real key encrypted cannot be decrypted on the branch)."""
from __future__ import annotations

import re
from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

KEY = 'kms:key'


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
    TypeSpec(KEY, 'kms', params=('KeyId', 'TargetKeyId'), arn=r'key/(.+)', service_ids=True,
             lists=(('ListKeys', 'Keys', 'KeyId'),), canon=key_id,
             reads=lambda w, k: [('DescribeKey', {'KeyId': k}), ('GetKeyPolicy', {'KeyId': k, 'PolicyName': 'default'}),
                                 ('GetKeyRotationStatus', {'KeyId': k}), ('ListResourceTags', {'KeyId': k}),
                                 ('ListAliases', {'KeyId': k})],
             copy=copy_key),
]
