"""EC2: a VPC is copied whole, with its subnets and security groups (simple VPCs only)."""
from __future__ import annotations

from typing import Any

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, pick

VPC, SUBNET, GROUP = 'ec2:vpc', 'ec2:subnet', 'ec2:security-group'


def tag_spec(kind: str, r: dict[str, Any]) -> dict[str, Any]:
    return {'TagSpecifications': [{'ResourceType': kind, 'Tags': r['Tags']}]} if r.get('Tags') else {}


def rules(perms: list[dict[str, Any]], x: CopyContext | None = None) -> list[dict[str, Any]]:
    """IpPermissions as described -> as accepted; group references copied and translated when x is given."""
    out = []
    for p in perms:
        q = pick(p, 'IpProtocol', 'IpRanges', 'Ipv6Ranges', 'PrefixListIds')
        if 'FromPort' in p:
            q['FromPort'], q['ToPort'] = p['FromPort'], p['ToPort']
        if p.get('UserIdGroupPairs'):
            q['UserIdGroupPairs'] = [dict(pick(g, 'Description'), GroupId=(x.ref(g['GroupId']) if x else g['GroupId']))
                                     for g in p['UserIdGroupPairs']]
        out.append(q)
    return out


def copy_vpc(x: CopyContext, v: str) -> bool:
    ec2, e = x.real('ec2'), x.engine('ec2')
    r = x.find(ec2.describe_vpcs, VpcIds=[v])
    if r is None:
        return False
    r = r['Vpcs'][0]
    F = [{'Name': 'vpc-id', 'Values': [v]}]
    if r.get('IsDefault'):
        raise CannotTell('the default VPC is not copied')
    if ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [v]}])['InternetGateways'] or \
            ec2.describe_network_interfaces(Filters=F)['NetworkInterfaces'] or len(ec2.describe_route_tables(Filters=F)['RouteTables']) > 1:
        raise CannotTell('VPCs with gateways, network interfaces (instances) or extra route tables are not copied yet')
    ev = e.create_vpc(CidrBlock=r['CidrBlock'], InstanceTenancy=r.get('InstanceTenancy', 'default'), **tag_spec('vpc', r))['Vpc']['VpcId']
    x.same(v, ev)
    for a in ('enableDnsSupport', 'enableDnsHostnames'):
        A = a[0].upper() + a[1:]
        e.modify_vpc_attribute(VpcId=ev, **{A: {'Value': ec2.describe_vpc_attribute(VpcId=v, Attribute=a)[A]['Value']}})
    for c in r.get('CidrBlockAssociationSet', [])[1:]:
        e.associate_vpc_cidr_block(VpcId=ev, CidrBlock=c['CidrBlock'])
    for s in ec2.describe_subnets(Filters=F)['Subnets']:
        es = e.create_subnet(VpcId=ev, CidrBlock=s['CidrBlock'], AvailabilityZone=s['AvailabilityZone'], **tag_spec('subnet', s))['Subnet']['SubnetId']
        x.same(s['SubnetId'], es)
        if s.get('MapPublicIpOnLaunch'):
            e.modify_subnet_attribute(SubnetId=es, MapPublicIpOnLaunch={'Value': True})
        x.adopt(SUBNET, s['SubnetId'])
    groups = ec2.describe_security_groups(Filters=F)['SecurityGroups']
    for g in groups:   # first every group, so that rules naming each other can be translated
        if g['GroupName'] == 'default':
            mine = [{'Name': 'vpc-id', 'Values': [ev]}, {'Name': 'group-name', 'Values': ['default']}]
            eg = e.describe_security_groups(Filters=mine)['SecurityGroups'][0]['GroupId']
        else:
            eg = e.create_security_group(GroupName=g['GroupName'], Description=g['Description'], VpcId=ev,
                                         **tag_spec('security-group', g))['GroupId']
        x.same(g['GroupId'], eg)
    for g in groups:   # then make each group's rules equal the real ones
        eg = x.tr(g['GroupId'])
        cur = e.describe_security_groups(GroupIds=[eg])['SecurityGroups'][0]
        if cur.get('IpPermissions'):
            e.revoke_security_group_ingress(GroupId=eg, IpPermissions=rules(cur['IpPermissions']))
        if cur.get('IpPermissionsEgress'):
            e.revoke_security_group_egress(GroupId=eg, IpPermissions=rules(cur['IpPermissionsEgress']))
        if g.get('IpPermissions'):
            e.authorize_security_group_ingress(GroupId=eg, IpPermissions=rules(g['IpPermissions'], x))
        if g.get('IpPermissionsEgress'):
            e.authorize_security_group_egress(GroupId=eg, IpPermissions=rules(g['IpPermissionsEgress'], x))
        x.adopt(GROUP, g['GroupId'])
    return True


def in_vpc(describe: str, member: str, type_: str):
    """Subnets and groups are copied with their VPC; their own copy only makes sure the VPC is there."""
    def copy(x: CopyContext, k: str) -> bool:
        r = x.find(getattr(x.real('ec2'), describe), **{member: [k]})
        if r is None:
            return False
        x.ref(next(iter(v for key, v in r.items() if key != 'ResponseMetadata'))[0]['VpcId'])
        if not x.known(k):
            raise CannotTell(f'the {type_} was not copied with its VPC')
        return True
    return copy


TYPES = [
    TypeSpec(VPC, 'ec2', params=('VpcId', 'VpcIds'), id=r'vpc-[0-9a-f]{8,17}', arn=r'vpc/(vpc-[0-9a-f]+)', service_ids=True,
             lists=(('DescribeVpcs', 'Vpcs', 'VpcId'),), removed_by=('DeleteVpc',),
             reads=lambda w, v: [('DescribeVpcs', {'VpcIds': [v]}),
                                 ('DescribeVpcAttribute', {'VpcId': v, 'Attribute': 'enableDnsSupport'}),
                                 ('DescribeVpcAttribute', {'VpcId': v, 'Attribute': 'enableDnsHostnames'})],
             copy=copy_vpc),
    TypeSpec(SUBNET, 'ec2', params=('SubnetId', 'SubnetIds'), id=r'subnet-[0-9a-f]{8,17}', arn=r'subnet/(subnet-[0-9a-f]+)',
             service_ids=True, lists=(('DescribeSubnets', 'Subnets', 'SubnetId'),), removed_by=('DeleteSubnet',),
             reads=lambda w, s: [('DescribeSubnets', {'SubnetIds': [s]})],
             copy=in_vpc('describe_subnets', 'SubnetIds', 'subnet')),
    TypeSpec(GROUP, 'ec2', params=('GroupId', 'GroupIds'), id=r'sg-[0-9a-f]{8,17}', arn=r'security-group/(sg-[0-9a-f]+)',
             service_ids=True, lists=(('DescribeSecurityGroups', 'SecurityGroups', 'GroupId'),),
             removed_by=('DeleteSecurityGroup',),
             reads=lambda w, g: [('DescribeSecurityGroups', {'GroupIds': [g]})],
             copy=in_vpc('describe_security_groups', 'GroupIds', 'security group')),
]
