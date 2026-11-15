"""SSM Parameter Store: parameters, with their version history replayed."""
from __future__ import annotations

from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

PARAMETER = 'ssm:parameter'


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


TYPES = [
    TypeSpec(PARAMETER, 'ssm', params=('Name',), arn=r'parameter/(.+)', ops=r'Parameter',
             lists=(('DescribeParameters', 'Parameters', 'Name'),), removed_by=('DeleteParameter',), canon=parameter_id,
             reads=lambda w, k: [('GetParameter', {'Name': parameter_name(k)})], copy=copy_parameter),
]
