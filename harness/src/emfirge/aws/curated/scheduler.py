"""EventBridge Scheduler: schedules in the default group."""
from __future__ import annotations

from typing import Any, Mapping

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

SCHEDULE = 'scheduler:schedule'


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


TYPES = [
    TypeSpec(SCHEDULE, 'scheduler', params=('Name',), arn=r'schedule/(.+)', ops=r'Schedule(?!Group)',
             lists=(('ListSchedules', 'Schedules', 'Arn'),), removed_by=('DeleteSchedule',), canon=schedule_key,
             reads=schedule_reads, copy=copy_schedule),
]
