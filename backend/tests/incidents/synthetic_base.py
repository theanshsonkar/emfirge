import json
from pathlib import Path

from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, IAMData, LambdaData, LambdaFunction,
    NetworkInterface, RDSData, RDSInstance, RolePolicy, Route, RouteTable, S3Bucket,
    S3Data, SecurityGroup, VPCData, VPCSubnet, InternetGatewayAttachment, EBSVolume, EBSSnapshot, RDSSnapshot,
)

PENDING_FIELDS = set()


def merge_patch(target, patch):
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict):
            result[key] = merge_patch(result.get(key), value)
        else:
            result[key] = value
    return result


def _check_keys(data):
    allowed = {'schema', 'name', 'account_id', 'region', 'collected_at', 'collection',
               'vpc', 'internet_gateway', 'subnets', 'route_tables', 'security_groups',
               'ec2_instances', 'ebs_volumes', 'ebs_snapshots', 'rds_instances',
               'rds_snapshots', 's3_buckets', 'iam_roles', 'lambda_functions',
               'network_interfaces'}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f'Unknown synthetic base key(s): {sorted(unknown)}')


def load_synthetic_base(name: str, patch: dict | None = None):
    path = Path(__file__).with_name(f'{name}_base.json')
    data = json.loads(path.read_text())
    if patch is not None:
        data = merge_patch(data, patch)
    _check_keys(data)

    instance_rows = data.get('ec2_instances', [])
    rds_rows = data.get('rds_instances', [])
    lambda_rows = data.get('lambda_functions', [])
    consumers = {}
    for row in instance_rows + rds_rows:
        for sg_id in row.get('sg_ids', []):
            consumers.setdefault(sg_id, []).append(row['id'])
    # Lambda SGs are not present in this fixture schema, but preserve support.
    for row in lambda_rows:
        for sg_id in row.get('sg_ids', []):
            consumers.setdefault(sg_id, []).append(row['name'])

    groups = []
    for row in data.get('security_groups', []):
        known = {'id', 'name', 'vpc_id', 'ingress'}
        unknown = set(row) - known
        if unknown:
            raise ValueError(f'Unknown synthetic security group key(s): {sorted(unknown)}')
        groups.append(SecurityGroup(
            id=row['id'], name=row['name'],
            rules=[dict(rule, source_sg_ids=rule.get('source_security_group_ids', []))
                   for rule in row.get('ingress', [])],
            attached_to=consumers.get(row['id'], []),
        ))

    vpc_row = data.get('vpc', {})
    vpc_id = vpc_row.get('id', '')
    igw = data.get('internet_gateway')
    subnets = [VPCSubnet(**row, resources=[item['id'] for item in instance_rows if item.get('subnet_id') == row['id']])
               for row in data.get('subnets', [])]
    route_tables = [RouteTable(
        id=row['id'], vpc_id=vpc_id, associated_subnet_ids=row.get('subnet_ids', []),
        is_main=False, routes=[Route(**route) for route in row.get('routes', [])],
    ) for row in data.get('route_tables', [])]
    public_subnets = {subnet_id for table in route_tables if any(route.target_type == 'internet_gateway' for route in table.routes) for subnet_id in table.associated_subnet_ids}
    vpc = VPCData(
        total_vpcs=1 if vpc_id else 0, internet_gateways=[igw['id']] if igw else [],
        internet_gateway_attachments=[InternetGatewayAttachment(internet_gateway_id=igw['id'], vpc_id=vpc_id, state='available')] if igw else [],
        internet_gateway_attachments_complete=bool(igw), public_subnet_ids=sorted(public_subnets),
        subnets=[item.model_copy(update={'is_public': item.id in public_subnets}) for item in subnets],
        route_tables=route_tables,
    )
    iam_roles = []
    for row in data.get('iam_roles', []):
        iam_roles.append(RolePolicy(role_name=row['name'], role_arn=row['arn'], access_statements=row.get('access_statements', []),
                                    accessible_resources=[resource for statement in row.get('access_statements', []) if statement.get('effect') == 'Allow' for resource in statement.get('resources', [])]))
    return AWSInfrastructure(
        region=data.get('region', ''), ec2=EC2Data(instance_count=len(instance_rows), instance_ids=[row['id'] for row in instance_rows], instances=[EC2Instance(**row) for row in instance_rows], security_groups=groups, ebs_volumes=[EBSVolume(**row) for row in data.get('ebs_volumes', [])], ebs_snapshots=[EBSSnapshot(**row) for row in data.get('ebs_snapshots', [])]),
        s3=S3Data(total_buckets=len(data.get('s3_buckets', [])), buckets=[S3Bucket(**row) for row in data.get('s3_buckets', [])]),
        rds=RDSData(instances=[row['id'] for row in rds_rows], rds_instances=[RDSInstance(**row) for row in rds_rows], rds_snapshots=[RDSSnapshot(**row) for row in data.get('rds_snapshots', [])]),
        iam=IAMData(role_policies=[RolePolicy(role_name=row['name'], role_arn=row['arn'], last_used_at=row.get('last_used_at'), access_statements=row.get('access_statements', []),
                                    accessible_resources=[resource for statement in row.get('access_statements', []) if statement.get('effect') == 'Allow' for resource in statement.get('resources', [])]) for row in data.get('iam_roles', [])]), lambda_data=LambdaData(function_count=len(lambda_rows), functions=[LambdaFunction(**row) for row in lambda_rows]),
        vpc=vpc, network_interfaces=(None if data.get('collection', {}).get('network_interfaces') != 'ok' else
            (None if data.get('network_interfaces') is None else [NetworkInterface(**row) for row in data.get('network_interfaces', [])])) ,
        collection=data.get('collection', {}),
    )
