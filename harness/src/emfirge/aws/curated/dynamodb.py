"""DynamoDB: tables (small tables only, with their items, TTL and point-in-time recovery)."""
from __future__ import annotations

from typing import Any

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

TABLE = 'dynamodb:table'
MAX_ITEMS = 1000


def _throughput(p: dict[str, Any]) -> dict[str, Any]:
    return {'ReadCapacityUnits': p['ReadCapacityUnits'], 'WriteCapacityUnits': p['WriteCapacityUnits']}


def create_args(d: dict[str, Any]) -> dict[str, Any]:
    """A described table back into CreateTable arguments."""
    mode = d.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
    kw: dict[str, Any] = {'AttributeDefinitions': d['AttributeDefinitions'], 'KeySchema': d['KeySchema'], 'BillingMode': mode}
    if mode == 'PROVISIONED':
        kw['ProvisionedThroughput'] = _throughput(d['ProvisionedThroughput'])

    def index(i: dict[str, Any]) -> dict[str, Any]:
        out = pick(i, 'IndexName', 'KeySchema', 'Projection')
        if mode == 'PROVISIONED' and 'ProvisionedThroughput' in i:
            out['ProvisionedThroughput'] = _throughput(i['ProvisionedThroughput'])
        return out
    if d.get('GlobalSecondaryIndexes'):
        kw['GlobalSecondaryIndexes'] = [index(i) for i in d['GlobalSecondaryIndexes']]
    if d.get('LocalSecondaryIndexes'):
        kw['LocalSecondaryIndexes'] = [pick(i, 'IndexName', 'KeySchema', 'Projection') for i in d['LocalSecondaryIndexes']]
    if d.get('StreamSpecification'):
        kw['StreamSpecification'] = d['StreamSpecification']
    if d.get('DeletionProtectionEnabled'):
        kw['DeletionProtectionEnabled'] = True
    if d.get('TableClassSummary', {}).get('TableClass'):
        kw['TableClass'] = d['TableClassSummary']['TableClass']
    return kw


def copy_table(x: CopyContext, t: str) -> bool:
    ddb, e = x.real('dynamodb'), x.engine('dynamodb')
    d = x.find(ddb.describe_table, TableName=t)
    if d is None:
        return False
    d = d['Table']
    if d['TableStatus'] != 'ACTIVE':
        raise CannotTell(f"the table is {d['TableStatus']}")
    items = ddb.scan(TableName=t, Limit=MAX_ITEMS + 1) if x.copy_data else {'Items': []}   # reading items: owner's call
    if items.get('LastEvaluatedKey') or len(items['Items']) > MAX_ITEMS:
        raise CannotTell('the table is too big to copy')
    kw = create_args(d)
    tags = ddb.list_tags_of_resource(ResourceArn=d['TableArn']).get('Tags')
    if tags:
        kw['Tags'] = tags
    ed = e.create_table(TableName=t, **kw)['TableDescription']
    if d.get('TableId') and ed.get('TableId'):
        x.same(d['TableId'], ed['TableId'])
    x.wait('dynamodb', 'table_exists', TableName=t)
    ttl = ddb.describe_time_to_live(TableName=t)['TimeToLiveDescription']
    if ttl.get('TimeToLiveStatus') in ('ENABLED', 'ENABLING'):
        e.update_time_to_live(TableName=t, TimeToLiveSpecification={'Enabled': True, 'AttributeName': ttl['AttributeName']})
    pitr = ddb.describe_continuous_backups(TableName=t)['ContinuousBackupsDescription'].get('PointInTimeRecoveryDescription', {})
    if pitr.get('PointInTimeRecoveryStatus') == 'ENABLED':
        e.update_continuous_backups(TableName=t, PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True})
    for it in items['Items']:
        e.put_item(TableName=t, Item=it)
    return True


TYPES = [
    TypeSpec(TABLE, 'dynamodb', params=('TableName',), arn=r'table/([^/]+)(?:/.*)?',
             lists=(('ListTables', 'TableNames', None),), removed_by=('DeleteTable',),
             reads=lambda w, t: [('DescribeTable', {'TableName': t}), ('DescribeTimeToLive', {'TableName': t}),
                                 ('DescribeContinuousBackups', {'TableName': t})],
             copy=copy_table),
]
