"""Synthetic graph coverage fixture for Law 27."""
from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, SecurityGroup, LoadBalancer,
    EBSVolume, ElasticIP, S3Data, S3Bucket, RDSData, RDSInstance,
    IAMData, RolePolicy, AccessStatement, LambdaData, LambdaFunction,
    SecretsManagerData, VPCData, VPCSubnet, RouteTable, Route,
    NetworkACL, NACLEntry, VPCPeeringConnection, TransitGatewayAttachment,
    VPNGateway, InterfaceEndpoint, ECSData, APIGatewayData,
    APIGatewayInstance, ElastiCacheData, ElastiCacheCluster, SQSData,
    SQSQueue, DynamoDBData, DynamoDBTable,
)


ACCOUNT = "000000000000"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/CoverageRole"
TARGET_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/TargetRole"
VPC_ID = "vpc-0cov0001"
SUBNET_ID = "subnet-0cov0001"
SG_ID = "sg-0cov0001"
INSTANCE_ID = "i-0cov0001"
BUCKET = "coverage-bucket-000000000000"


def build_coverage_infrastructure() -> AWSInfrastructure:
    """Return deterministic, entirely synthetic data exercising graph builders."""
    return AWSInfrastructure(
        region=REGION,
        ec2=EC2Data(
            instances=[EC2Instance(id=INSTANCE_ID, type="t3.micro", state="running", sg_ids=[SG_ID], subnet_id=SUBNET_ID, has_public_ip=True)],
            security_groups=[SecurityGroup(id=SG_ID, name="coverage", rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}], attached_to=[INSTANCE_ID])],
            load_balancers=[LoadBalancer(arn="arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/cov/1", type="application", target_instances=[INSTANCE_ID])],
            ebs_volumes=[EBSVolume(id="vol-0cov0001", size_gb=8, volume_type="gp3", availability_zone="us-east-1a", attached_to=INSTANCE_ID)],
            elastic_ips=[ElasticIP(allocation_id="eipalloc-0cov0001", public_ip="198.51.100.1", is_attached=True)],
        ),
        s3=S3Data(buckets=[S3Bucket(name=BUCKET, has_cloudfront=True, policy="allow")]),
        rds=RDSData(rds_instances=[RDSInstance(id="db-0cov0001", sg_ids=[SG_ID], subnet_id=SUBNET_ID, encrypted=True)]),
        lambda_data=LambdaData(functions=[LambdaFunction(name="coverage-lambda", role_arn=ROLE_ARN, vpc_id=VPC_ID, subnet_ids=[SUBNET_ID], sg_ids=[SG_ID], secret_refs=["secret-0cov0001"])]),
        secrets_manager=SecretsManagerData(),
        iam=IAMData(role_policies=[
            RolePolicy(role_name="CoverageRole", role_arn=ROLE_ARN, trusted_services=["lambda.amazonaws.com"], trusted_role_arns=[TARGET_ROLE_ARN], accessible_resources=[f"arn:aws:s3:::{BUCKET}"], access_statements=[AccessStatement(effect="Allow", actions=["s3:GetObject"], resources=[f"arn:aws:s3:::{BUCKET}/*"])]),
            RolePolicy(role_name="TargetRole", role_arn=TARGET_ROLE_ARN, trusted_role_arns=[ROLE_ARN]),
        ]),
        ecs=ECSData(task_role_arns=[TARGET_ROLE_ARN]),
        vpc=VPCData(
            subnets=[VPCSubnet(id=SUBNET_ID, vpc_id=VPC_ID, cidr="10.0.1.0/24", resources=[INSTANCE_ID, "coverage-lambda"], is_public=True)],
            route_tables=[RouteTable(id="rtb-0cov0001", vpc_id=VPC_ID, is_main=True, associated_subnet_ids=[SUBNET_ID], routes=[Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id="igw-0cov0001"), Route(destination_cidr="10.1.0.0/16", target_type="vpc_peering", target_id="pcx-0cov0001")])],
            internet_gateways=["igw-0cov0001"], nat_gateways=["nat-0cov0001"],
            public_subnet_ids=[SUBNET_ID],
            internet_gateway_attachments=[{"internet_gateway_id": "igw-0cov0001", "vpc_id": VPC_ID, "state": "available"}],
            internet_gateway_attachments_complete=True,
            nacls=[NetworkACL(id="acl-0cov0001", vpc_id=VPC_ID, associated_subnet_ids=[SUBNET_ID], entries=[NACLEntry(rule_number=100, protocol="-1", rule_action="allow", egress=False, cidr_block="0.0.0.0/0")])],
            vpc_peering_connections=[VPCPeeringConnection(id="pcx-0cov0001", requester_vpc_id=VPC_ID, accepter_vpc_id="vpc-0cov0002", status="active")],
            transit_gateway_attachments=[TransitGatewayAttachment(id="tgw-attach-0cov0001", transit_gateway_id="tgw-0cov0001", vpc_id=VPC_ID)],
            vpn_gateways=[VPNGateway(id="vgw-0cov0001", vpc_id=VPC_ID)],
            interface_endpoints=[InterfaceEndpoint(id="vpce-0cov0001", vpc_id=VPC_ID, service_name="com.amazonaws.us-east-1.s3")],
        ),
        api_gateway=APIGatewayData(apis=[APIGatewayInstance(id="api-0cov0001", name="coverage", api_type="REST", endpoint_type="REGIONAL", auth_type="IAM")]),
        elasticache=ElastiCacheData(clusters=[ElastiCacheCluster(id="cache-0cov0001", engine="redis", node_type="cache.t3.micro", vpc_id=VPC_ID, sg_ids=[SG_ID])]),
        sqs=SQSData(queues=[SQSQueue(url="https://sqs.us-east-1.amazonaws.com/000000000000/coverage", arn="arn:aws:sqs:us-east-1:000000000000:coverage", name="coverage")]),
        dynamodb=DynamoDBData(tables=[DynamoDBTable(name="coverage", arn="arn:aws:dynamodb:us-east-1:000000000000:table/coverage", pitr_enabled=True)]),
    )
