"""EventBridge Scheduler schedules and EventBridge rules (default group and default bus only)."""
from __future__ import annotations

from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

SCHEDULE = 'scheduler:schedule'
RULE, RULE_ON_BUS = 'events:rule-on-default-event-bus', 'events:rule-on-custom-event-bus'


def schedule_key(v: str, p: Mapping[str, Any]) -> str:
    return f"{p.get('GroupName') or 'default'}/{v}"


def schedule_reads(w: Any, k: str) -> list:
    g, n = k.split('/', 1)
    return [('GetSchedule', dict({'Name': n}, **({'GroupName': g} if g != 'default' else {})))]


def copy_schedule(x: CopyContext, k: str) -> bool:
    g, n = k.split('/', 1)
    if g != 'default':
        raise CannotTell('schedule groups are not copied yet')
    s = x.find(x.real('scheduler').get_schedule, Name=n, GroupName=g)
    if s is None:
        return False
    t = dict(s['Target'])
    t['Arn'], t['RoleArn'] = x.ref(t['Arn']), x.ref(t['RoleArn'])
    if t.get('DeadLetterConfig', {}).get('Arn'):
        t['DeadLetterConfig'] = {'Arn': x.ref(t['DeadLetterConfig']['Arn'])}
    x.engine('scheduler').create_schedule(
        Name=n, GroupName=g, Target=t, FlexibleTimeWindow=s['FlexibleTimeWindow'], ScheduleExpression=s['ScheduleExpression'],
        **pick(s, 'ScheduleExpressionTimezone', 'State', 'Description', 'StartDate', 'EndDate', 'KmsKeyArn', 'ActionAfterCompletion'))
    return True


def rule_on_default_bus(v: str, p: Mapping[str, Any]) -> str | None:
    """A rule name names a rule on the default bus; one on another bus is a different type, not copied yet."""
    return v if (p.get('EventBusName') or 'default') == 'default' else None


def copy_rule(x: CopyContext, n: str) -> bool:
    ev, e = x.real('events'), x.engine('events')
    r = x.find(ev.describe_rule, Name=n)
    if r is None:
        return False
    kw = pick(r, 'ScheduleExpression', 'EventPattern', 'State', 'Description')
    if r.get('RoleArn'):
        kw['RoleArn'] = x.ref(r['RoleArn'])
    tags = ev.list_tags_for_resource(ResourceARN=r['Arn']).get('Tags')
    e.put_rule(Name=n, **kw, **({'Tags': tags} if tags else {}))
    targets = ev.list_targets_by_rule(Rule=n)['Targets']
    for t in targets:   # a target is a reference the service does not check: translate, do not copy
        t['Arn'] = x.tr(t['Arn'])
        if t.get('RoleArn'):
            t['RoleArn'] = x.ref(t['RoleArn'])
    if targets:
        e.put_targets(Rule=n, Targets=targets)
    return True


TYPES = [
    TypeSpec(SCHEDULE, 'scheduler', params=('Name',), arn=r'schedule/(.+)', ops=r'Schedule(?!Group)',
             lists=(('ListSchedules', 'Schedules', 'Arn'),), removed_by=('DeleteSchedule',), canon=schedule_key,
             reads=schedule_reads, copy=copy_schedule),
    TypeSpec(RULE, 'events', params=('Name', 'Rule'), arn=r'rule/([^/]+)', ops=r'Rule|Targets',
             lists=(('ListRules', 'Rules', 'Arn'),), removed_by=('DeleteRule',), canon=rule_on_default_bus,
             reads=lambda w, n: [('DescribeRule', {'Name': n}), ('ListTargetsByRule', {'Rule': n})], copy=copy_rule),
    TypeSpec(RULE_ON_BUS, 'events', arn=r'rule/([^/]+/[^/]+)'),
]
