"""Lambda: functions (with their permissions and event source mappings) and event source mappings."""
from __future__ import annotations

import json
from typing import Any

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, Where, pick

FUNCTION, MAPPING = 'lambda:function', 'lambda:eventSourceMapping'
MAPPING_BUSY = ('Creating', 'Enabling', 'Disabling', 'Updating')


def permission_args(s: dict[str, Any]) -> dict[str, Any]:
    """A resource-policy statement back into AddPermission arguments."""
    a = {'StatementId': s['Sid'], 'Action': s['Action'] if isinstance(s['Action'], str) else s['Action'][0]}
    p = s['Principal']
    a['Principal'] = p if isinstance(p, str) else (p.get('Service') or p.get('AWS'))
    for cond in (s.get('Condition') or {}).values():
        for k, v in cond.items():
            name = {'aws:sourcearn': 'SourceArn', 'aws:sourceaccount': 'SourceAccount', 'aws:principalorgid': 'PrincipalOrgID'}
            if k.lower() in name:
                a[name[k.lower()]] = v
    return a


def function_reads(w: Where, n: str) -> list:
    arn = f'arn:aws:lambda:{w.region}:{w.account}:function:{n}'
    return [('GetFunctionConfiguration', {'FunctionName': n}), ('GetFunctionConcurrency', {'FunctionName': n}),
            ('GetPolicy', {'FunctionName': n}), ('ListTags', {'Resource': arn}), ('ListAliases', {'FunctionName': n}),
            ('ListVersionsByFunction', {'FunctionName': n}), ('ListEventSourceMappings', {'FunctionName': n})]


def copy_function(x: CopyContext, n: str) -> bool:
    lam = x.real('lambda')
    f = x.find(lam.get_function, FunctionName=n)
    if f is None:
        return False
    c = f['Configuration']
    if c.get('PackageType') == 'Image' or c.get('Layers'):
        raise CannotTell('image functions and layers are not copied')
    if len(lam.list_versions_by_function(FunctionName=n)['Versions']) > 1 or lam.list_aliases(FunctionName=n)['Aliases']:
        raise CannotTell('published versions and aliases cannot be reproduced')
    if x.find(lam.get_function_url_config, FunctionName=n):
        raise CannotTell('function URLs are not copied')
    kw = pick(c, 'Runtime', 'Handler', 'Description', 'Timeout', 'MemorySize', 'Architectures', 'EphemeralStorage')
    if c.get('Environment', {}).get('Variables'):
        kw['Environment'] = {'Variables': c['Environment']['Variables']}
    if c.get('TracingConfig'):
        kw['TracingConfig'] = {'Mode': c['TracingConfig']['Mode']}
    if c.get('LoggingConfig'):
        kw['LoggingConfig'] = pick(c['LoggingConfig'], 'LogFormat', 'LogGroup', 'ApplicationLogLevel', 'SystemLogLevel')
    if c.get('KMSKeyArn'):
        kw['KMSKeyArn'] = x.ref(c['KMSKeyArn'])
    if c.get('DeadLetterConfig', {}).get('TargetArn'):
        kw['DeadLetterConfig'] = {'TargetArn': x.ref(c['DeadLetterConfig']['TargetArn'])}
    if c.get('VpcConfig', {}).get('SubnetIds'):
        kw['VpcConfig'] = {'SubnetIds': [x.ref(s) for s in c['VpcConfig']['SubnetIds']],
                           'SecurityGroupIds': [x.ref(g) for g in c['VpcConfig']['SecurityGroupIds']]}
    if f.get('Tags'):
        kw['Tags'] = f['Tags']
    el = x.engine('lambda')
    el.create_function(FunctionName=n, Role=x.ref(c['Role']), Code={'ZipFile': x.fetch(f['Code']['Location'])}, **kw)
    x.wait('lambda', 'function_active_v2', FunctionName=n)
    rc = f.get('Concurrency', {}).get('ReservedConcurrentExecutions')
    if rc is not None:
        el.put_function_concurrency(FunctionName=n, ReservedConcurrentExecutions=rc)
    pol = x.find(lam.get_policy, FunctionName=n)
    for s in (json.loads(pol['Policy'])['Statement'] if pol else []):
        el.add_permission(FunctionName=n, **permission_args(s))
    for m in lam.list_event_source_mappings(FunctionName=n)['EventSourceMappings']:
        x.need(MAPPING, m['UUID'])
    return True


def copy_mapping(x: CopyContext, u: str) -> bool:
    m = x.find(x.real('lambda').get_event_source_mapping, UUID=u)
    if m is None:
        return False
    kw = pick(m, 'BatchSize', 'MaximumBatchingWindowInSeconds', 'FilterCriteria', 'ScalingConfig', 'FunctionResponseTypes',
              'StartingPosition', 'MaximumRetryAttempts', 'MaximumRecordAgeInSeconds', 'BisectBatchOnFunctionError',
              'ParallelizationFactor')
    kw['Enabled'] = m.get('State') not in ('Disabled', 'Disabling')
    el = x.engine('lambda')
    e = el.create_event_source_mapping(EventSourceArn=x.ref(m['EventSourceArn']), FunctionName=x.ref(m['FunctionArn']), **kw)
    x.same(u, e['UUID'])
    x.settle(lambda: el.get_event_source_mapping(UUID=e['UUID']), 'State', MAPPING_BUSY)
    return True


TYPES = [
    TypeSpec(FUNCTION, 'lambda', params=('FunctionName',), arn=r'function:([^:]+)(?::.+)?',
             lists=(('ListFunctions', 'Functions', 'FunctionName'),), removed_by=('DeleteFunction',),
             canon=lambda v, p: v.split(':')[0] if ':' in v else v, reads=function_reads, copy=copy_function),
    TypeSpec(MAPPING, 'lambda', params=('UUID',), arn=r'event-source-mapping:(.+)', service_ids=True,
             lists=(('ListEventSourceMappings', 'EventSourceMappings', 'UUID'),), removed_by=('DeleteEventSourceMapping',),
             reads=lambda w, u: [('GetEventSourceMapping', {'UUID': u})], copy=copy_mapping),
]
