"""EventBridge: rules on the default bus (rules on other buses are named, not copied)."""
from __future__ import annotations

from typing import Any, Mapping

from .context import CopyContext
from .spec import TypeSpec, pick

RULE, RULE_ON_BUS = 'events:rule-on-default-event-bus', 'events:rule-on-custom-event-bus'


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
    TypeSpec(RULE, 'events', params=('Name', 'Rule'), arn=r'rule/([^/]+)', ops=r'Rule|Targets',
             lists=(('ListRules', 'Rules', 'Arn'),), removed_by=('DeleteRule',), canon=rule_on_default_bus,
             reads=lambda w, n: [('DescribeRule', {'Name': n}), ('ListTargetsByRule', {'Rule': n})], copy=copy_rule),
    TypeSpec(RULE_ON_BUS, 'events', arn=r'rule/([^/]+/[^/]+)'),
]
