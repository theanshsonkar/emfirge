"""CloudWatch Logs: log groups (with retention and metric filters; log events are not copied)."""
from __future__ import annotations

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

LOG_GROUP = 'logs:log-group'


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


TYPES = [
    TypeSpec(LOG_GROUP, 'logs', params=('logGroupName', 'logGroupIdentifier'), arn=r'log-group:([^:]+)(?::.*)?',
             lists=(('DescribeLogGroups', 'logGroups', 'logGroupName'),), removed_by=('DeleteLogGroup',),
             reads=lambda w, n: [('DescribeMetricFilters', {'logGroupName': n}),
                                 ('DescribeSubscriptionFilters', {'logGroupName': n})],
             copy=copy_log_group),
]
