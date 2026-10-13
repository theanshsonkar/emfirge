from app.models import (
    AccessStatement, AWSInfrastructure, EC2Data, EC2Instance, IAMData,
    InternetGatewayAttachment, LambdaData, LambdaFunction, RolePolicy, Route,
    RouteTable, S3Bucket, S3Data, SecurityGroup, VPCData, VPCSubnet,
)

ACCOUNT = "000000000000"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/EmfirgeDemoAppRole"


def build_incident_base() -> AWSInfrastructure:
    vpc_id = "vpc-inc0001"
    subnet_id = "subnet-inc-pub"
    instance_id = "i-inc-web"
    sg_web = SecurityGroup(id="sg-inc-web", name="incident-web", rules=[
        {"protocol": "tcp", "from_port": p, "to_port": p, "ip_ranges": ["0.0.0.0/0"]}
        for p in (22, 80, 8000)
    ], egress_rules=[{"protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}], attached_to=[instance_id])
    sg_latent = SecurityGroup(id="sg-inc-latent", name="incident-latent", rules=[
        {"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["10.0.0.0/16"]}
    ], egress_rules=[{"protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}], attached_to=[])
    return AWSInfrastructure(region="ap-south-1",
        ec2=EC2Data(instance_count=1, instance_types=["t3.micro"], instance_ids=[instance_id], ssh_open_to_internet=True, ssh_security_group_id="sg-inc-web",
            instances=[EC2Instance(id=instance_id, type="t3.micro", state="running", sg_ids=[sg_web.id],
                                   subnet_id=subnet_id, has_public_ip=True, imdsv2_required=True)],
            security_groups=[sg_web, sg_latent]),
        s3=S3Data(total_buckets=2, buckets=[S3Bucket(name="inc-data-bucket", is_public=False, versioning_enabled=False),
                                            S3Bucket(name="inc-assets-bucket", is_public=False)]),
        iam=IAMData(role_policies=[RolePolicy(role_name="inc-lambda-role", role_arn=ROLE_ARN,
            accessible_resources=["arn:aws:s3:::inc-data-bucket/*"], access_statements=[AccessStatement(
                effect="Allow", actions=["s3:GetObject", "s3:PutObject"], resources=["arn:aws:s3:::inc-data-bucket/*"])] )]),
        lambda_data=LambdaData(function_count=1, functions=[LambdaFunction(name="inc-worker", role_arn=ROLE_ARN)]),
        vpc=VPCData(total_vpcs=1, internet_gateways=["igw-inc0001"],
            internet_gateway_attachments=[InternetGatewayAttachment(internet_gateway_id="igw-inc0001", vpc_id=vpc_id, state="available")],
            internet_gateway_attachments_complete=True, public_subnet_ids=[subnet_id],
            subnets=[VPCSubnet(id=subnet_id, vpc_id=vpc_id, cidr="172.31.1.0/24", resources=[instance_id], availability_zone="ap-south-1a", is_public=True)],
            route_tables=[RouteTable(id="rtb-inc-main", vpc_id=vpc_id, is_main=True, associated_subnet_ids=[subnet_id], routes=[
                Route(destination_cidr="172.31.0.0/16", target_type="local", target_id="local"),
                Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id="igw-inc0001")])]))
