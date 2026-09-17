"""
Demo Seed Infrastructure
========================
Returns a realistic AWSInfrastructure object for demo purposes.
Triggered when the user enters the demo ARN on the scan page.

To customize the demo:
- Edit the infrastructure below to add/remove resources
- Change the DEMO_ACCOUNT_ID or DEMO_ROLE_ARN constants
- The rules engine, scoring, LLM summary, and all downstream features
  (graph, simulation, remediation) run normally on this data.

No AWS API calls are made when demo mode is active.
"""
# Demo ARN = arn:aws:iam::000000000000:role/EmfirgeReadOnly

import os

from app.models import (
    AWSInfrastructure,
    EC2Data, EC2Instance, SecurityGroup, LoadBalancer, EBSVolume, ElasticIP,
    S3Data, S3Bucket,
    RDSData, RDSInstance,
    IAMData, IAMUser, RolePolicy, AccessStatement,
    CloudTrailData,
    CostData,
    CloudWatchData,
    GuardDutyData,
    LambdaData, LambdaFunction,
    SecretsManagerData,
    VPCData, VPCSubnet, RouteTable, Route,
    KMSData,
    ConfigData,
    SNSData,
    ECSData,
    WAFData,
    APIGatewayData, APIGatewayInstance,
    ElastiCacheData, ElastiCacheCluster,
    SQSData, SQSQueue,
    DynamoDBData, DynamoDBTable,
)

# Stable, intentionally fictitious identifiers used by the branch-flow demo.
DEMO_FLOW_ACCOUNT_ID = "000000000000"
DEMO_FLOW_ROLE_ARN = f"arn:aws:iam::{DEMO_FLOW_ACCOUNT_ID}:role/EmfirgeDemoAppRole"
DEMO_FLOW_REGION = "us-east-1"


def build_demo_infrastructure() -> AWSInfrastructure:
    """Return the small, secure, deterministic infrastructure used by demos/tests."""
    vpc_id = "vpc-demo-001"
    public_subnet_id = "subnet-demo-public"
    private_subnet_id = "subnet-demo-private"
    public_sg_id = "sg-demo-public"
    db_sg_id = "sg-demo-db"
    instance_id = "i-demo-web-001"
    rds_id = "demo-postgres"
    bucket_name = "emfirge-demo-artifacts-000000000000"

    # This is a fake ARN in the reserved all-zero demo account; no credentials exist.
    role_arn = DEMO_FLOW_ROLE_ARN
    public_sg = SecurityGroup(
        id=public_sg_id,
        name="demo-web-restricted",
        rules=[{"protocol": "tcp", "from_port": 22, "to_port": 22,
                 "ip_ranges": ["10.0.0.0/16"]}],
        egress_rules=[{"protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}],
        attached_to=[instance_id],
    )
    db_sg = SecurityGroup(
        id=db_sg_id,
        name="demo-database",
        rules=[{"protocol": "tcp", "from_port": 5432, "to_port": 5432,
                 "ip_ranges": ["10.0.0.0/16"]}],
        attached_to=[rds_id],
    )
    return AWSInfrastructure(
        region=DEMO_FLOW_REGION,
        ec2=EC2Data(
            instance_count=1,
            instance_types=["t3.micro"],
            instance_ids=[instance_id],
            instances=[EC2Instance(
                id=instance_id, type="t3.micro", sg_ids=[public_sg_id],
                subnet_id=public_subnet_id, state="running", imdsv2_required=True,
                has_public_ip=True, instance_profile_arn=role_arn,
            )],
            security_groups=[public_sg, db_sg],
        ),
        s3=S3Data(
            total_buckets=1,
            buckets=[S3Bucket(name=bucket_name, is_public=False, encrypted=False,
                              versioning_enabled=True)],
        ),
        rds=RDSData(
            instances=[rds_id],
            backup_enabled=True,
            backup_retention_days=7,
            rds_instances=[RDSInstance(
                id=rds_id, sg_ids=[db_sg_id], subnet_id=private_subnet_id,
                publicly_accessible=False, encrypted=True,
            )],
        ),
        iam=IAMData(role_policies=[RolePolicy(
            role_name="EmfirgeDemoAppRole",
            role_arn=role_arn,
            accessible_resources=[f"arn:aws:s3:::{bucket_name}"],
            access_statements=[AccessStatement(
                effect="Allow", actions=["s3:GetObject"],
                resources=[f"arn:aws:s3:::{bucket_name}/*"],
            )],
            policy_names=["DemoReadArtifacts"],
            trusted_services=["ec2.amazonaws.com"],
        )]),
        vpc=VPCData(
            total_vpcs=1,
            internet_gateways=["igw-demo-001"],
            nat_gateways=["nat-demo-001"],
            public_subnet_ids=[public_subnet_id],
            subnets=[
                VPCSubnet(id=public_subnet_id, vpc_id=vpc_id,
                          cidr="10.0.1.0/24", resources=[instance_id],
                          availability_zone="us-east-1a", is_public=True),
                VPCSubnet(id=private_subnet_id, vpc_id=vpc_id,
                          cidr="10.0.2.0/24", resources=[rds_id],
                          availability_zone="us-east-1a", is_public=False),
            ],
            route_tables=[
                RouteTable(id="rtb-demo-public", vpc_id=vpc_id,
                           associated_subnet_ids=[public_subnet_id],
                           routes=[Route(destination_cidr="0.0.0.0/0",
                                         target_type="internet_gateway",
                                         target_id="igw-demo-001")]),
                RouteTable(id="rtb-demo-private", vpc_id=vpc_id,
                           associated_subnet_ids=[private_subnet_id],
                           routes=[Route(destination_cidr="0.0.0.0/0",
                                         target_type="nat_gateway",
                                         target_id="nat-demo-001")]),
            ],
        ),
    )

# ── DEMO CONSTANTS ────────────────────────────────────────────────
DEMO_ACCOUNT_ID = os.getenv("DEMO_ACCOUNT_ID", "000000000000")
DEMO_ROLE_ARN = f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/EmfirgeReadOnly"
DEMO_REGION = "us-east-1"

# ── DEMO V2 (rich "Acme Fintech" graph) ───────────────────────────
# A second demo ARN whose seed is engineered to produce the best-looking
# graph: multiple internet-facing compute nodes funnel through ONE
# over-privileged IAM role (the chokepoint) that reaches 4 crown jewels.
DEMO_ACCOUNT_ID_V2 = os.getenv("DEMO_ACCOUNT_ID_V2", "000000000000")
DEMO_ROLE_ARN_V2 = f"arn:aws:iam::{DEMO_ACCOUNT_ID_V2}:role/EmfirgeReadOnly"


def is_demo_arn(role_arn: str) -> bool:
    """Check if the provided ARN is a demo trigger ARN (either version)."""
    a = role_arn.strip()
    return a == DEMO_ROLE_ARN or a == DEMO_ROLE_ARN_V2


def get_demo_infrastructure(role_arn: str = None) -> AWSInfrastructure:
    """
    Dispatch to the correct demo dataset based on the trigger ARN.

    - DEMO_ROLE_ARN_V2  -> rich "Acme Fintech" graph (best-looking topology)
    - DEMO_ROLE_ARN     -> original "Series A startup" graph (backward compatible)
    - None / anything    -> original graph (default)
    """
    if role_arn and role_arn.strip() == DEMO_ROLE_ARN_V2:
        return _build_acme_fintech()
    return _build_series_a_startup()


def _build_series_a_startup() -> AWSInfrastructure:
    """
    Build a realistic 'Series A startup' infrastructure with intentional
    security gaps that trigger 25-35 findings across all severity levels.
    """

    # ── SECURITY GROUPS ───────────────────────────────────────────
    security_groups = [
        SecurityGroup(
            id="sg-0a1b2c3d4e5f00001",
            name="web-public-sg",
            rules=[
                {"protocol": "tcp", "from_port": 80, "to_port": 80, "ip_ranges": ["0.0.0.0/0"]},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-0abc000000000001", "i-0abc000000000002"],
        ),
        SecurityGroup(
            id="sg-0a1b2c3d4e5f00002",
            name="ssh-open-sg",
            rules=[
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-0abc000000000003"],
        ),
        SecurityGroup(
            id="sg-0a1b2c3d4e5f00003",
            name="legacy-app-sg",
            rules=[
                {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "ip_ranges": ["0.0.0.0/0"]},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-0abc000000000004"],
        ),
        SecurityGroup(
            id="sg-0a1b2c3d4e5f00004",
            name="backend-sg",
            rules=[
                {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "ip_ranges": ["10.0.0.0/16"]},
                {"protocol": "tcp", "from_port": 6379, "to_port": 6379, "ip_ranges": ["10.0.0.0/16"]},
            ],
            attached_to=["i-0abc000000000005", "i-0abc000000000006"],
        ),
        SecurityGroup(
            id="sg-0a1b2c3d4e5f00005",
            name="monitoring-sg",
            rules=[
                {"protocol": "tcp", "from_port": 9090, "to_port": 9090, "ip_ranges": ["10.0.0.0/16"]},
            ],
            attached_to=["i-0abc000000000004"],
        ),
    ]

    # ── EC2 INSTANCES ─────────────────────────────────────────────
    instances = [
        EC2Instance(id="i-0abc000000000001", type="t3.medium", sg_ids=["sg-0a1b2c3d4e5f00001"], subnet_id="subnet-0001a", state="running", imdsv2_required=True),
        EC2Instance(id="i-0abc000000000002", type="t3.medium", sg_ids=["sg-0a1b2c3d4e5f00001"], subnet_id="subnet-0001b", state="running", imdsv2_required=True),
        EC2Instance(id="i-0abc000000000003", type="t3.large", sg_ids=["sg-0a1b2c3d4e5f00002"], subnet_id="subnet-0002a", state="running", imdsv2_required=False, instance_profile_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:instance-profile/LambdaBasicRole"),
        EC2Instance(id="i-0abc000000000004", type="m5.xlarge", sg_ids=["sg-0a1b2c3d4e5f00003", "sg-0a1b2c3d4e5f00005"], subnet_id="subnet-0001a", state="running", imdsv2_required=False),
        EC2Instance(id="i-0abc000000000005", type="t3.small", sg_ids=["sg-0a1b2c3d4e5f00004"], subnet_id="subnet-0002a", state="running", imdsv2_required=True),
        EC2Instance(id="i-0abc000000000006", type="t3.micro", sg_ids=["sg-0a1b2c3d4e5f00004"], subnet_id="subnet-0002b", state="stopped", imdsv2_required=False),
    ]

    # ── LOAD BALANCERS ────────────────────────────────────────────
    load_balancers = [
        LoadBalancer(
            arn=f"arn:aws:elasticloadbalancing:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:loadbalancer/app/web-alb/50dc6c495c0c9188",
            type="ALB",
            target_instances=["i-0abc000000000001", "i-0abc000000000002"],
        ),
        LoadBalancer(
            arn=f"arn:aws:elasticloadbalancing:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:loadbalancer/net/internal-nlb/a1b2c3d4e5f6g7h8",
            type="NLB",
            target_instances=["i-0abc000000000005"],
        ),
    ]

    # ── EBS VOLUMES ───────────────────────────────────────────────
    ebs_volumes = [
        EBSVolume(id="vol-0001", size_gb=50, volume_type="gp3", create_time="2024-08-15T10:00:00Z", availability_zone="us-east-1a"),
        EBSVolume(id="vol-0002", size_gb=50, volume_type="gp3", create_time="2024-08-15T10:00:00Z", availability_zone="us-east-1b"),
        EBSVolume(id="vol-0003", size_gb=100, volume_type="gp3", create_time="2024-06-01T10:00:00Z", availability_zone="us-east-1a"),
        EBSVolume(id="vol-0004", size_gb=200, volume_type="io1", create_time="2024-03-20T10:00:00Z", availability_zone="us-east-1a"),
    ]

    # ── ELASTIC IPs ───────────────────────────────────────────────
    elastic_ips = [
        ElasticIP(allocation_id="eipalloc-0001", public_ip="54.210.33.101", is_attached=True),
        ElasticIP(allocation_id="eipalloc-0002", public_ip="54.210.33.102", is_attached=False),  # orphaned
    ]

    # ── EC2 DATA ──────────────────────────────────────────────────
    ec2 = EC2Data(
        instance_count=6,
        instance_types=["t3.medium", "t3.medium", "t3.large", "m5.xlarge", "t3.small", "t3.micro"],
        has_load_balancer=True,
        auto_scaling_enabled=False,
        open_security_groups=["sg-0a1b2c3d4e5f00002", "sg-0a1b2c3d4e5f00003"],
        ssh_open_to_internet=True,
        rdp_open_to_internet=False,
        stopped_instances=["i-0abc000000000006"],
        free_tier_eligible=False,
        instance_ids=["i-0abc000000000001", "i-0abc000000000002", "i-0abc000000000003", "i-0abc000000000004", "i-0abc000000000005", "i-0abc000000000006"],
        ssh_security_group_id="sg-0a1b2c3d4e5f00002",
        rdp_security_group_id=None,
        instances=instances,
        security_groups=security_groups,
        load_balancers=load_balancers,
        ebs_volumes=ebs_volumes,
        elastic_ips=elastic_ips,
    )

    # ── S3 BUCKETS ────────────────────────────────────────────────
    s3 = S3Data(
        total_buckets=4,
        public_buckets=["acme-public-assets"],
        unencrypted_buckets=["acme-data-lake"],
        buckets_without_versioning=["acme-data-lake", "acme-logs"],
        buckets_without_logging=["acme-public-assets", "acme-data-lake", "acme-logs"],
        buckets=[
            S3Bucket(name="acme-public-assets", is_public=True, has_cloudfront=False, policy='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-public-assets/*"}]}'),
            S3Bucket(name="acme-data-lake", is_public=False, has_cloudfront=False, policy=None),
            S3Bucket(name="acme-logs", is_public=False, has_cloudfront=False, policy=None),
            S3Bucket(name="acme-app-static", is_public=True, has_cloudfront=True, policy=None),
        ],
    )

    # ── RDS INSTANCES ─────────────────────────────────────────────
    rds = RDSData(
        instances=["acme-prod-db", "acme-analytics-db"],
        multi_az_enabled=False,
        backup_enabled=True,
        backup_retention_days=3,
        publicly_accessible=["acme-analytics-db"],
        unencrypted_instances=["acme-analytics-db"],
        instances_without_deletion_protection=["acme-analytics-db"],
        instances_without_log_exports=["acme-prod-db", "acme-analytics-db"],
        rds_instances=[
            RDSInstance(id="acme-prod-db", sg_ids=["sg-0a1b2c3d4e5f00004"], publicly_accessible=False, encrypted=True),
            RDSInstance(id="acme-analytics-db", sg_ids=["sg-0a1b2c3d4e5f00003"], publicly_accessible=True, encrypted=False),
        ],
    )

    # ── IAM ───────────────────────────────────────────────────────
    iam = IAMData(
        root_has_access_keys=False,
        users_without_mfa=["deploy-bot", "intern-dev"],
        old_access_keys=["deploy-bot"],
        root_used_recently=False,
        users_with_admin_policy=["cto-admin"],
        iam_users=[
            IAMUser(username="cto-admin", has_console_access=True),
            IAMUser(username="deploy-bot", has_console_access=False),
            IAMUser(username="intern-dev", has_console_access=True),
            IAMUser(username="backend-svc", has_console_access=False),
            IAMUser(username="data-analyst", has_console_access=True),
        ],
        role_policies=[
            RolePolicy(
                role_name="LambdaAdminRole",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/LambdaAdminRole",
                accessible_resources=[],
                has_admin=True,
                policy_names=["AdministratorAccess"],
            ),
            RolePolicy(
                role_name="LambdaBasicRole",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/LambdaBasicRole",
                accessible_resources=[
                    f"arn:aws:s3:::acme-data-lake/*",
                    f"arn:aws:s3:::acme-logs/*",
                ],
                has_admin=False,
                policy_names=["S3DataAccess"],
            ),
            RolePolicy(
                role_name="ECSTaskRole",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/ECSTaskRole",
                accessible_resources=[
                    f"arn:aws:rds:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:db:acme-prod-db",
                    f"arn:aws:s3:::acme-data-lake/*",
                ],
                has_admin=False,
                policy_names=["ECSDataAccess"],
            ),
        ],
    )

    # ── CLOUDTRAIL ────────────────────────────────────────────────
    cloudtrail = CloudTrailData(
        is_enabled=True,
        is_multi_region=True,
        has_log_file_validation=False,
        trail_arn=f"arn:aws:cloudtrail:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:trail/acme-trail",
    )

    # ── COST ──────────────────────────────────────────────────────
    cost = CostData(
        monthly_cost=342.50,
        has_budget_alerts=False,
        has_billing_alarm=False,
        top_service="Amazon EC2",
        top_service_percentage=62.0,
    )

    # ── CLOUDWATCH ────────────────────────────────────────────────
    cloudwatch = CloudWatchData(
        has_alarms=False,
        has_billing_alarm=False,
    )

    # ── GUARDDUTY ─────────────────────────────────────────────────
    guardduty = GuardDutyData(
        is_enabled=False,
        detector_id=None,
    )

    # ── LAMBDA ────────────────────────────────────────────────────
    lambda_data = LambdaData(
        function_count=3,
        functions_with_admin_role=["acme-data-processor"],
        functions_with_outdated_runtime=["acme-legacy-cron"],
        functions_with_no_timeout=["acme-webhook-handler"],
        functions=[
            LambdaFunction(
                name="acme-data-processor",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/LambdaAdminRole",
                vpc_id="vpc-0001",
                subnet_ids=["subnet-0002a"],
                secret_refs=[f"arn:aws:secretsmanager:us-east-1:{DEMO_ACCOUNT_ID}:secret:prod/db-creds"],
            ),
            LambdaFunction(
                name="acme-legacy-cron",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/LambdaBasicRole",
                vpc_id=None,
                subnet_ids=[],
                secret_refs=[],
            ),
            LambdaFunction(
                name="acme-webhook-handler",
                role_arn=f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/LambdaBasicRole",
                vpc_id="vpc-0001",
                subnet_ids=["subnet-0001a"],
                secret_refs=[f"arn:aws:secretsmanager:us-east-1:{DEMO_ACCOUNT_ID}:secret:webhook-secret"],
            ),
        ],
    )

    # ── SECRETS MANAGER ───────────────────────────────────────────
    secrets_manager = SecretsManagerData(
        total_secrets=3,
        secrets_without_rotation=["prod/db-creds", "webhook-secret"],
    )

    # ── VPC ───────────────────────────────────────────────────────
    vpc = VPCData(
        total_vpcs=2,
        vpcs_without_flow_logs=["vpc-0001", "vpc-default"],
        default_vpc_in_use=True,
        default_vpc_id="vpc-default",
        missing_s3_endpoint=True,
        missing_dynamodb_endpoint=True,
        internet_gateways=["igw-demo-001"],
        nat_gateways=["nat-demo-001"],
        public_subnet_ids=["subnet-0001a", "subnet-0001b"],
        subnets=[
            VPCSubnet(id="subnet-0001a", vpc_id="vpc-0001", resources=["i-0abc000000000001", "i-0abc000000000004"], is_public=True),
            VPCSubnet(id="subnet-0001b", vpc_id="vpc-0001", resources=["i-0abc000000000002"], is_public=True),
            VPCSubnet(id="subnet-0002a", vpc_id="vpc-0001", resources=["i-0abc000000000003", "i-0abc000000000005"], is_public=True),
            VPCSubnet(id="subnet-0002b", vpc_id="vpc-0001", resources=["i-0abc000000000006"], is_public=False),
        ],
    )

    # ── KMS ───────────────────────────────────────────────────────
    kms = KMSData(
        total_cmks=2,
        cmks_without_rotation=["key-0001-abcd-1234"],
        cmks_pending_deletion=[],
    )

    # ── AWS CONFIG ────────────────────────────────────────────────
    config = ConfigData(
        is_enabled=False,
        is_recording=False,
        non_compliant_rules=[],
    )

    # ── SNS ───────────────────────────────────────────────────────
    sns = SNSData(
        total_topics=2,
        topics_without_encryption=[f"arn:aws:sns:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:acme-alerts"],
        topics_with_public_access=[],
    )

    # ── ECS ───────────────────────────────────────────────────────
    ecs = ECSData(
        total_task_definitions=2,
        tasks_with_privileged_containers=[f"arn:aws:ecs:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:task-definition/acme-worker:3"],
        tasks_without_resource_limits=[f"arn:aws:ecs:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:task-definition/acme-api:7"],
        task_role_arns=[f"arn:aws:iam::{DEMO_ACCOUNT_ID}:role/ECSTaskRole"],
    )

    # ── WAF ───────────────────────────────────────────────────────
    waf = WAFData(
        total_albs=1,
        albs_without_waf=[f"arn:aws:elasticloadbalancing:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:loadbalancer/app/web-alb/50dc6c495c0c9188"],
    )

    # ── API GATEWAY ───────────────────────────────────────────────
    api_gateway = APIGatewayData(
        total_apis=2,
        apis_without_auth=["api-public-webhook"],
        apis_without_throttling=["api-public-webhook", "api-internal"],
        apis_without_waf=["api-public-webhook", "api-internal"],
        apis=[
            APIGatewayInstance(
                id="api-public-webhook",
                name="Public Webhook API",
                api_type="HTTP",
                endpoint_type="REGIONAL",
                auth_type="NONE",
                has_waf=False,
                stage_names=["prod"],
            ),
            APIGatewayInstance(
                id="api-internal",
                name="Internal API",
                api_type="REST",
                endpoint_type="PRIVATE",
                auth_type="IAM",
                has_waf=False,
                stage_names=["v1"],
            ),
        ],
    )

    # ── ELASTICACHE ───────────────────────────────────────────────
    elasticache = ElastiCacheData(
        total_clusters=1,
        clusters_without_encryption=["acme-redis-001"],
        clusters_without_auth=["acme-redis-001"],
        clusters_without_transit_encryption=["acme-redis-001"],
        clusters=[
            ElastiCacheCluster(
                id="acme-redis-001",
                engine="redis",
                node_type="cache.t3.micro",
                encryption_at_rest=False,
                encryption_in_transit=False,
                auth_enabled=False,
                vpc_id="vpc-0001",
                subnet_group="acme-cache-subnet-group",
                sg_ids=["sg-0a1b2c3d4e5f00004"],
            ),
        ],
    )

    # ── SQS ───────────────────────────────────────────────────────
    sqs = SQSData(
        total_queues=2,
        queues_without_encryption=["acme-events"],
        queues_without_dlq=["acme-events"],
        queues_with_public_access=[],
        queues=[
            SQSQueue(
                url=f"https://sqs.{DEMO_REGION}.amazonaws.com/{DEMO_ACCOUNT_ID}/acme-events",
                arn=f"arn:aws:sqs:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:acme-events",
                name="acme-events",
                encrypted=False,
                has_dlq=False,
                is_public=False,
            ),
            SQSQueue(
                url=f"https://sqs.{DEMO_REGION}.amazonaws.com/{DEMO_ACCOUNT_ID}/acme-dlq",
                arn=f"arn:aws:sqs:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:acme-dlq",
                name="acme-dlq",
                encrypted=True,
                has_dlq=False,
                is_public=False,
            ),
        ],
    )

    # ── DYNAMODB ──────────────────────────────────────────────────
    dynamodb = DynamoDBData(
        total_tables=2,
        tables_without_pitr=["acme-sessions", "acme-events-log"],
        tables_without_encryption=[],
        tables_without_backup=["acme-sessions"],
        tables=[
            DynamoDBTable(
                name="acme-sessions",
                arn=f"arn:aws:dynamodb:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:table/acme-sessions",
                encryption_type="DEFAULT",
                pitr_enabled=False,
                has_backup=False,
                billing_mode="PAY_PER_REQUEST",
                item_count=15000,
            ),
            DynamoDBTable(
                name="acme-events-log",
                arn=f"arn:aws:dynamodb:{DEMO_REGION}:{DEMO_ACCOUNT_ID}:table/acme-events-log",
                encryption_type="KMS",
                pitr_enabled=False,
                has_backup=True,
                billing_mode="PAY_PER_REQUEST",
                item_count=250000,
            ),
        ],
    )

    # ── ASSEMBLE ──────────────────────────────────────────────────
    return AWSInfrastructure(
        ec2=ec2,
        s3=s3,
        rds=rds,
        iam=iam,
        cloudtrail=cloudtrail,
        cost=cost,
        cloudwatch=cloudwatch,
        guardduty=guardduty,
        lambda_data=lambda_data,
        secrets_manager=secrets_manager,
        vpc=vpc,
        kms=kms,
        config=config,
        sns=sns,
        ecs=ecs,
        waf=waf,
        api_gateway=api_gateway,
        elasticache=elasticache,
        sqs=sqs,
        dynamodb=dynamodb,
        region=DEMO_REGION,
        warnings=[],
    )


# ════════════════════════════════════════════════════════════════════
#  DEMO V2 — "Acme Fintech" — engineered for the best-looking graph
# ════════════════════════════════════════════════════════════════════
#
#  STORY (for narration / LinkedIn):
#    Acme is a fintech SaaS. Four internet-facing compute nodes (2 web
#    servers behind an ALB with no WAF, an SSH-open bastion, and a legacy
#    box with port 8080 open) plus a payment Lambda ALL assume ONE
#    over-privileged role: `AppServerRole`. That single role can read the
#    4 crown jewels — the production customer database (PII), the
#    customer-PII S3 data lake, the prod DB-credentials secret, and the
#    customer-sessions DynamoDB table.
#
#    => `iam-role-AppServerRole` is the CHOKEPOINT. Every internet→data
#       attack path funnels through it. Harden that one role and you kill
#       every path at once. A second, independent path exists through an
#       admin Lambda (`LambdaAdminRole`, has_admin=True).
#
#  GRAPH SHAPE THIS PRODUCES:
#    INTERNET ─┬─ web-alb ── web-1 / web-2 ─┐
#              ├─ bastion (SSH 22) ─────────┤
#              ├─ legacy (8080) ────────────┼─► iam-role-AppServerRole ─►┬─ RDS acme-prod-customers
#              ├─ public-webhook API GW ────┘        (CHOKEPOINT)        ├─ S3 acme-customer-pii
#              │                                                         ├─ secret prod/db-credentials
#              └─ (payment Lambda) ─────────────────────────────────────┴─ DynamoDB acme-customer-sessions
#
#    Plus: public+unencrypted analytics RDS, public S3 buckets, admin
#    Lambda path, ElastiCache/SQS/DynamoDB variety, and orphans
#    (unattached EBS/EIP, private unused API GW) for the cost story.
# ════════════════════════════════════════════════════════════════════

def _build_acme_fintech() -> AWSInfrastructure:
    """Rich demo infrastructure with one clear IAM-role chokepoint and
    multiple clean internet→crown-jewel attack paths."""

    acct = DEMO_ACCOUNT_ID_V2
    region = DEMO_REGION

    # ── SECURITY GROUPS ───────────────────────────────────────────
    security_groups = [
        SecurityGroup(
            id="sg-web-public",
            name="web-public-sg",
            rules=[
                {"protocol": "tcp", "from_port": 80, "to_port": 80, "ip_ranges": ["0.0.0.0/0"]},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-web000000000001", "i-web000000000002"],
        ),
        SecurityGroup(
            id="sg-ssh-open",
            name="bastion-ssh-open-sg",
            rules=[
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-bastion00000001"],
        ),
        SecurityGroup(
            id="sg-legacy-8080",
            name="legacy-app-sg",
            rules=[
                {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "ip_ranges": ["0.0.0.0/0"]},
                {"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["0.0.0.0/0"]},
            ],
            attached_to=["i-legacy000000001"],
        ),
        SecurityGroup(
            id="sg-backend",
            name="backend-private-sg",
            rules=[
                {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "ip_ranges": ["10.0.0.0/16"]},
                {"protocol": "tcp", "from_port": 6379, "to_port": 6379, "ip_ranges": ["10.0.0.0/16"]},
            ],
            attached_to=["i-backend00000001", "i-backend00000002"],
        ),
        SecurityGroup(
            id="sg-monitoring",
            name="monitoring-sg",
            rules=[
                {"protocol": "tcp", "from_port": 9090, "to_port": 9090, "ip_ranges": ["10.0.0.0/16"]},
            ],
            attached_to=["i-backend00000001"],
        ),
    ]

    # ── EC2 INSTANCES ─────────────────────────────────────────────
    # web-1, web-2, bastion, legacy → ALL use AppServerRole (the chokepoint).
    # imdsv2_required=False on internet-facing boxes adds the IMDSv1 SSRF path.
    app_profile = f"arn:aws:iam::{acct}:instance-profile/AppServerRole"
    instances = [
        EC2Instance(id="i-web000000000001", type="t3.medium", sg_ids=["sg-web-public"], subnet_id="subnet-pub-a", state="running", imdsv2_required=False, instance_profile_arn=app_profile),
        EC2Instance(id="i-web000000000002", type="t3.medium", sg_ids=["sg-web-public"], subnet_id="subnet-pub-b", state="running", imdsv2_required=False, instance_profile_arn=app_profile),
        EC2Instance(id="i-bastion00000001", type="t3.small", sg_ids=["sg-ssh-open"], subnet_id="subnet-pub-a", state="running", imdsv2_required=False, instance_profile_arn=app_profile),
        EC2Instance(id="i-legacy000000001", type="t3.large", sg_ids=["sg-legacy-8080"], subnet_id="subnet-pub-b", state="running", imdsv2_required=False, instance_profile_arn=app_profile),
        EC2Instance(id="i-backend00000001", type="m5.large", sg_ids=["sg-backend", "sg-monitoring"], subnet_id="subnet-priv-a", state="running", imdsv2_required=True),
        EC2Instance(id="i-backend00000002", type="m5.large", sg_ids=["sg-backend"], subnet_id="subnet-priv-b", state="running", imdsv2_required=True),
        EC2Instance(id="i-worker000000001", type="t3.micro", sg_ids=["sg-backend"], subnet_id="subnet-priv-a", state="stopped", imdsv2_required=False),
    ]

    # ── LOAD BALANCERS ────────────────────────────────────────────
    load_balancers = [
        LoadBalancer(
            arn=f"arn:aws:elasticloadbalancing:{region}:{acct}:loadbalancer/app/web-alb/50dc6c495c0c9188",
            type="ALB",
            target_instances=["i-web000000000001", "i-web000000000002"],
        ),
        LoadBalancer(
            arn=f"arn:aws:elasticloadbalancing:{region}:{acct}:loadbalancer/net/internal-nlb/a1b2c3d4e5f6g7h8",
            type="NLB",
            target_instances=["i-backend00000001"],
        ),
    ]

    # ── EBS VOLUMES (unattached → orphans / cost story) ───────────
    ebs_volumes = [
        EBSVolume(id="vol-orphan0001", size_gb=50, volume_type="gp3", create_time="2024-08-15T10:00:00Z", availability_zone="us-east-1a"),
        EBSVolume(id="vol-orphan0002", size_gb=100, volume_type="gp3", create_time="2024-06-01T10:00:00Z", availability_zone="us-east-1b"),
        EBSVolume(id="vol-orphan0003", size_gb=200, volume_type="io1", create_time="2024-03-20T10:00:00Z", availability_zone="us-east-1a"),
        EBSVolume(id="vol-orphan0004", size_gb=50, volume_type="gp3", create_time="2024-09-01T10:00:00Z", availability_zone="us-east-1b"),
    ]

    # ── ELASTIC IPs ───────────────────────────────────────────────
    elastic_ips = [
        ElasticIP(allocation_id="eipalloc-attached01", public_ip="52.20.14.201", is_attached=True),
        ElasticIP(allocation_id="eipalloc-orphan001", public_ip="52.20.14.202", is_attached=False),  # orphan
    ]

    ec2 = EC2Data(
        instance_count=7,
        instance_types=["t3.medium", "t3.medium", "t3.small", "t3.large", "m5.large", "m5.large", "t3.micro"],
        has_load_balancer=True,
        auto_scaling_enabled=False,
        open_security_groups=["sg-ssh-open", "sg-legacy-8080"],
        ssh_open_to_internet=True,
        rdp_open_to_internet=False,
        stopped_instances=["i-worker000000001"],
        free_tier_eligible=False,
        instance_ids=[i.id for i in instances],
        ssh_security_group_id="sg-ssh-open",
        rdp_security_group_id=None,
        instances=instances,
        security_groups=security_groups,
        load_balancers=load_balancers,
        ebs_volumes=ebs_volumes,
        elastic_ips=elastic_ips,
    )

    # ── S3 BUCKETS ────────────────────────────────────────────────
    # acme-customer-pii = crown jewel (reached via AppServerRole), unencrypted.
    # acme-cdn-assets = public BUT behind CloudFront (shows the "safe" downgrade).
    s3 = S3Data(
        total_buckets=5,
        public_buckets=["acme-public-assets"],
        unencrypted_buckets=["acme-customer-pii"],
        buckets_without_versioning=["acme-customer-pii", "acme-logs"],
        buckets_without_logging=["acme-public-assets", "acme-customer-pii", "acme-logs"],
        buckets=[
            S3Bucket(name="acme-customer-pii", is_public=False, has_cloudfront=False,
                     policy=None),
            S3Bucket(name="acme-public-assets", is_public=True, has_cloudfront=False,
                     policy='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-public-assets/*"}]}'),
            S3Bucket(name="acme-cdn-assets", is_public=True, has_cloudfront=True, policy=None),
            S3Bucket(name="acme-backups", is_public=False, has_cloudfront=False, policy=None),
            S3Bucket(name="acme-logs", is_public=False, has_cloudfront=False, policy=None),
        ],
    )

    # ── RDS INSTANCES ─────────────────────────────────────────────
    # acme-prod-customers = crown jewel (private, encrypted; reached via role).
    # acme-analytics = public + unencrypted (standalone critical).
    rds = RDSData(
        instances=["acme-prod-customers", "acme-analytics"],
        multi_az_enabled=False,
        backup_enabled=True,
        backup_retention_days=3,
        publicly_accessible=["acme-analytics"],
        unencrypted_instances=["acme-analytics"],
        instances_without_deletion_protection=["acme-analytics"],
        instances_without_log_exports=["acme-prod-customers", "acme-analytics"],
        rds_instances=[
            RDSInstance(id="acme-prod-customers", sg_ids=["sg-backend"], publicly_accessible=False, encrypted=True),
            RDSInstance(id="acme-analytics", sg_ids=["sg-legacy-8080"], publicly_accessible=True, encrypted=False),
        ],
    )

    # ── IAM ───────────────────────────────────────────────────────
    iam = IAMData(
        root_has_access_keys=False,
        users_without_mfa=["deploy-bot", "intern-dev", "contractor"],
        old_access_keys=["deploy-bot"],
        root_used_recently=False,
        users_with_admin_policy=["cto-admin"],
        iam_users=[
            IAMUser(username="cto-admin", has_console_access=True),
            IAMUser(username="deploy-bot", has_console_access=False),
            IAMUser(username="intern-dev", has_console_access=True),
            IAMUser(username="backend-svc", has_console_access=False),
            IAMUser(username="data-analyst", has_console_access=True),
            IAMUser(username="contractor", has_console_access=True),
        ],
        role_policies=[
            # THE CHOKEPOINT — over-privileged (but not admin) role reachable
            # from 4 EC2 instances + the payment Lambda. can_access the 4 crown jewels.
            RolePolicy(
                role_name="AppServerRole",
                role_arn=f"arn:aws:iam::{acct}:role/AppServerRole",
                accessible_resources=[
                    f"arn:aws:rds:{region}:{acct}:db:acme-prod-customers",
                    "arn:aws:s3:::acme-customer-pii",
                    "arn:aws:s3:::acme-customer-pii/*",
                    f"arn:aws:secretsmanager:{region}:{acct}:secret:prod/db-credentials-aB3xY9",
                    f"arn:aws:dynamodb:{region}:{acct}:table/acme-customer-sessions",
                ],
                has_admin=False,
                policy_names=["AppServerDataAccess"],
            ),
            # Second independent path — admin Lambda reaches ALL data stores.
            RolePolicy(
                role_name="LambdaAdminRole",
                role_arn=f"arn:aws:iam::{acct}:role/LambdaAdminRole",
                accessible_resources=[],
                has_admin=True,
                policy_names=["AdministratorAccess"],
            ),
            RolePolicy(
                role_name="LambdaBasicRole",
                role_arn=f"arn:aws:iam::{acct}:role/LambdaBasicRole",
                accessible_resources=[
                    "arn:aws:s3:::acme-logs/*",
                ],
                has_admin=False,
                policy_names=["S3LogsAccess"],
            ),
            RolePolicy(
                role_name="ECSTaskRole",
                role_arn=f"arn:aws:iam::{acct}:role/ECSTaskRole",
                accessible_resources=[
                    f"arn:aws:rds:{region}:{acct}:db:acme-prod-customers",
                    "arn:aws:s3:::acme-customer-pii/*",
                ],
                has_admin=False,
                policy_names=["ECSDataAccess"],
            ),
        ],
    )

    # ── CLOUDTRAIL ────────────────────────────────────────────────
    cloudtrail = CloudTrailData(
        is_enabled=True,
        is_multi_region=True,
        has_log_file_validation=False,
        trail_arn=f"arn:aws:cloudtrail:{region}:{acct}:trail/acme-org-trail",
    )

    # ── COST ──────────────────────────────────────────────────────
    cost = CostData(
        monthly_cost=892.40,
        has_budget_alerts=False,
        has_billing_alarm=False,
        top_service="Amazon EC2",
        top_service_percentage=58.0,
    )

    # ── CLOUDWATCH ────────────────────────────────────────────────
    cloudwatch = CloudWatchData(has_alarms=False, has_billing_alarm=False)

    # ── GUARDDUTY ─────────────────────────────────────────────────
    guardduty = GuardDutyData(is_enabled=False, detector_id=None)

    # ── LAMBDA ────────────────────────────────────────────────────
    # payment-processor uses AppServerRole → adds a 5th source into the chokepoint.
    # data-exporter uses LambdaAdminRole → the second independent path to all data.
    lambda_data = LambdaData(
        function_count=4,
        functions_with_admin_role=["acme-data-exporter"],
        functions_with_outdated_runtime=["acme-legacy-cron"],
        functions_with_no_timeout=["acme-webhook-handler"],
        functions=[
            LambdaFunction(
                name="acme-payment-processor",
                role_arn=f"arn:aws:iam::{acct}:role/AppServerRole",
                vpc_id="vpc-prod",
                subnet_ids=["subnet-priv-a"],
                secret_refs=["prod/db-credentials-aB3xY9"],
            ),
            LambdaFunction(
                name="acme-data-exporter",
                role_arn=f"arn:aws:iam::{acct}:role/LambdaAdminRole",
                vpc_id="vpc-prod",
                subnet_ids=["subnet-priv-b"],
                secret_refs=["stripe-api-key-9KpQ2m"],
            ),
            LambdaFunction(
                name="acme-legacy-cron",
                role_arn=f"arn:aws:iam::{acct}:role/LambdaBasicRole",
                vpc_id=None,
                subnet_ids=[],
                secret_refs=[],
            ),
            LambdaFunction(
                name="acme-webhook-handler",
                role_arn=f"arn:aws:iam::{acct}:role/LambdaBasicRole",
                vpc_id="vpc-prod",
                subnet_ids=["subnet-priv-a"],
                secret_refs=["jwt-signing-key-7Lm4Rt"],
            ),
        ],
    )

    # ── SECRETS MANAGER ───────────────────────────────────────────
    secrets_manager = SecretsManagerData(
        total_secrets=3,
        secrets_without_rotation=["prod/db-credentials", "stripe-api-key"],
    )

    # ── VPC ───────────────────────────────────────────────────────
    # subnet-pub-* are PUBLIC (required for internet reachability of web/bastion/legacy).
    vpc = VPCData(
        total_vpcs=2,
        vpcs_without_flow_logs=["vpc-prod", "vpc-default"],
        default_vpc_in_use=True,
        default_vpc_id="vpc-default",
        missing_s3_endpoint=True,
        missing_dynamodb_endpoint=True,
        internet_gateways=["igw-acme-001"],
        nat_gateways=["nat-acme-001"],
        public_subnet_ids=["subnet-pub-a", "subnet-pub-b"],
        subnets=[
            VPCSubnet(id="subnet-pub-a", vpc_id="vpc-prod", resources=["i-web000000000001", "i-bastion00000001"], is_public=True),
            VPCSubnet(id="subnet-pub-b", vpc_id="vpc-prod", resources=["i-web000000000002", "i-legacy000000001"], is_public=True),
            VPCSubnet(id="subnet-priv-a", vpc_id="vpc-prod", resources=["i-backend00000001", "i-worker000000001"], is_public=False),
            VPCSubnet(id="subnet-priv-b", vpc_id="vpc-prod", resources=["i-backend00000002"], is_public=False),
        ],
    )

    # ── KMS ───────────────────────────────────────────────────────
    kms = KMSData(
        total_cmks=2,
        cmks_without_rotation=["key-acme-app-01"],
        cmks_pending_deletion=[],
    )

    # ── AWS CONFIG ────────────────────────────────────────────────
    config = ConfigData(is_enabled=False, is_recording=False, non_compliant_rules=[])

    # ── SNS ───────────────────────────────────────────────────────
    sns = SNSData(
        total_topics=2,
        topics_without_encryption=[f"arn:aws:sns:{region}:{acct}:acme-ops-alerts"],
        topics_with_public_access=[],
    )

    # ── ECS ───────────────────────────────────────────────────────
    ecs = ECSData(
        total_task_definitions=2,
        tasks_with_privileged_containers=[f"arn:aws:ecs:{region}:{acct}:task-definition/acme-worker:5"],
        tasks_without_resource_limits=[f"arn:aws:ecs:{region}:{acct}:task-definition/acme-api:12"],
        task_role_arns=[f"arn:aws:iam::{acct}:role/ECSTaskRole"],
    )

    # ── WAF ───────────────────────────────────────────────────────
    waf = WAFData(
        total_albs=1,
        albs_without_waf=[f"arn:aws:elasticloadbalancing:{region}:{acct}:loadbalancer/app/web-alb/50dc6c495c0c9188"],
    )

    # ── API GATEWAY ───────────────────────────────────────────────
    # public-webhook = internet-reachable (no auth). internal-admin = PRIVATE
    # with no other edges → orphan (cost / hygiene story).
    api_gateway = APIGatewayData(
        total_apis=2,
        apis_without_auth=["api-public-webhook"],
        apis_without_throttling=["api-public-webhook", "api-internal-admin"],
        apis_without_waf=["api-public-webhook", "api-internal-admin"],
        apis=[
            APIGatewayInstance(
                id="api-public-webhook",
                name="Public Webhook API",
                api_type="HTTP",
                endpoint_type="REGIONAL",
                auth_type="NONE",
                has_waf=False,
                stage_names=["prod"],
            ),
            APIGatewayInstance(
                id="api-internal-admin",
                name="Internal Admin API",
                api_type="REST",
                endpoint_type="PRIVATE",
                auth_type="IAM",
                has_waf=False,
                stage_names=["v1"],
            ),
        ],
    )

    # ── ELASTICACHE ───────────────────────────────────────────────
    elasticache = ElastiCacheData(
        total_clusters=1,
        clusters_without_encryption=["acme-redis-prod"],
        clusters_without_auth=["acme-redis-prod"],
        clusters_without_transit_encryption=["acme-redis-prod"],
        clusters=[
            ElastiCacheCluster(
                id="acme-redis-prod",
                engine="redis",
                node_type="cache.t3.small",
                encryption_at_rest=False,
                encryption_in_transit=False,
                auth_enabled=False,
                vpc_id="vpc-prod",
                subnet_group="acme-cache-subnet-group",
                sg_ids=["sg-backend"],
            ),
        ],
    )

    # ── SQS ───────────────────────────────────────────────────────
    sqs = SQSData(
        total_queues=2,
        queues_without_encryption=["acme-payment-events"],
        queues_without_dlq=["acme-payment-events"],
        queues_with_public_access=[],
        queues=[
            SQSQueue(
                url=f"https://sqs.{region}.amazonaws.com/{acct}/acme-payment-events",
                arn=f"arn:aws:sqs:{region}:{acct}:acme-payment-events",
                name="acme-payment-events",
                encrypted=False,
                has_dlq=False,
                is_public=False,
            ),
            SQSQueue(
                url=f"https://sqs.{region}.amazonaws.com/{acct}/acme-dlq",
                arn=f"arn:aws:sqs:{region}:{acct}:acme-dlq",
                name="acme-dlq",
                encrypted=True,
                has_dlq=False,
                is_public=False,
            ),
        ],
    )

    # ── DYNAMODB ──────────────────────────────────────────────────
    # acme-customer-sessions = crown jewel (reached via AppServerRole).
    dynamodb = DynamoDBData(
        total_tables=2,
        tables_without_pitr=["acme-customer-sessions", "acme-audit-log"],
        tables_without_encryption=[],
        tables_without_backup=["acme-customer-sessions"],
        tables=[
            DynamoDBTable(
                name="acme-customer-sessions",
                arn=f"arn:aws:dynamodb:{region}:{acct}:table/acme-customer-sessions",
                encryption_type="DEFAULT",
                pitr_enabled=False,
                has_backup=False,
                billing_mode="PAY_PER_REQUEST",
                item_count=48000,
            ),
            DynamoDBTable(
                name="acme-audit-log",
                arn=f"arn:aws:dynamodb:{region}:{acct}:table/acme-audit-log",
                encryption_type="KMS",
                pitr_enabled=False,
                has_backup=True,
                billing_mode="PAY_PER_REQUEST",
                item_count=1200000,
            ),
        ],
    )

    # ── ASSEMBLE ──────────────────────────────────────────────────
    return AWSInfrastructure(
        ec2=ec2,
        s3=s3,
        rds=rds,
        iam=iam,
        cloudtrail=cloudtrail,
        cost=cost,
        cloudwatch=cloudwatch,
        guardduty=guardduty,
        lambda_data=lambda_data,
        secrets_manager=secrets_manager,
        vpc=vpc,
        kms=kms,
        config=config,
        sns=sns,
        ecs=ecs,
        waf=waf,
        api_gateway=api_gateway,
        elasticache=elasticache,
        sqs=sqs,
        dynamodb=dynamodb,
        region=region,
        warnings=[],
    )
