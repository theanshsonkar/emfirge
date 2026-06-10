"""
Shared fixtures for Emfirge test suite.
All fixtures build synthetic AWSInfrastructure objects — zero real AWS calls.
"""
import pytest
from app.models import (
    AWSInfrastructure, EC2Data, S3Data, RDSData, IAMData, IAMUser,
    CloudTrailData, CostData, CloudWatchData, GuardDutyData,
    LambdaData, LambdaFunction, SecretsManagerData, VPCData, VPCSubnet,
    KMSData, ConfigData, SNSData, ECSData, WAFData,
    APIGatewayData, APIGatewayInstance,
    ElastiCacheData, ElastiCacheCluster,
    SQSData, SQSQueue,
    DynamoDBData, DynamoDBTable,
    EC2Instance, SecurityGroup, S3Bucket, RDSInstance, LoadBalancer,
)


# -- HELPERS -------------------------------------------------------

def make_sg(sg_id="sg-001", name="default", rules=None, attached_to=None):
    return SecurityGroup(
        id=sg_id, name=name,
        rules=rules or [],
        attached_to=attached_to or [],
    )

def make_open_sg(sg_id="sg-ssh", port=22, attached_to=None):
    """Security group with a single port open to 0.0.0.0/0."""
    return SecurityGroup(
        id=sg_id, name=f"sg-port-{port}",
        rules=[{"from_port": port, "to_port": port, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
        attached_to=attached_to or ["i-001"],
    )

def make_instance(instance_id="i-001", sg_ids=None, imdsv2=True):
    return EC2Instance(
        id=instance_id, type="t3.micro",
        sg_ids=sg_ids or ["sg-001"],
        state="running", imdsv2_required=imdsv2,
    )


# -- SCENARIO FIXTURES ---------------------------------------------

@pytest.fixture
def clean_infra():
    """Ideal account — no findings expected."""
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=2,
            instance_types=["t3.micro", "t3.micro"],
            instance_ids=["i-001", "i-002"],
            has_load_balancer=True,
            auto_scaling_enabled=True,
            ssh_open_to_internet=False,
            rdp_open_to_internet=False,
            instances=[
                make_instance("i-001", imdsv2=True),
                make_instance("i-002", imdsv2=True),
            ],
            security_groups=[make_sg("sg-001", "web-sg", attached_to=["i-001", "i-002"])],
        ),
        s3=S3Data(
            total_buckets=2,
            public_buckets=[],
            unencrypted_buckets=[],
            buckets_without_versioning=[],
            buckets=[
                S3Bucket(name="my-app-data", is_public=False, is_empty=False),
                S3Bucket(name="my-logs", is_public=False, is_empty=False),
            ],
        ),
        rds=RDSData(
            instances=["prod-db"],
            multi_az_enabled=True,
            backup_enabled=True,
            backup_retention_days=7,
            publicly_accessible=[],
            unencrypted_instances=[],
            instances_without_deletion_protection=[],
            instances_without_log_exports=[],
            rds_instances=[RDSInstance(id="prod-db", publicly_accessible=False, encrypted=True)],
        ),
        iam=IAMData(
            root_has_access_keys=False,
            users_without_mfa=[],
            old_access_keys=[],
            root_used_recently=False,
            users_with_admin_policy=[],
            iam_users=[IAMUser(username="alice", has_console_access=True)],
        ),
        cloudtrail=CloudTrailData(is_enabled=True, is_multi_region=True, has_log_file_validation=True),
        cost=CostData(has_budget_alerts=True, has_billing_alarm=True),
        cloudwatch=CloudWatchData(has_alarms=True),
        guardduty=GuardDutyData(is_enabled=True, detector_id="det-001"),
        lambda_data=LambdaData(function_count=0),
        secrets_manager=SecretsManagerData(total_secrets=0),
        vpc=VPCData(total_vpcs=1, vpcs_without_flow_logs=[], default_vpc_in_use=False,
            subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001", "i-002"], is_public=True)],
        ),
        kms=KMSData(total_cmks=1, cmks_without_rotation=[], cmks_pending_deletion=[]),
        config=ConfigData(is_enabled=True, is_recording=True),
        sns=SNSData(total_topics=0),
        ecs=ECSData(total_task_definitions=0),
        waf=WAFData(total_albs=0),
    )


@pytest.fixture
def nightmare_infra():
    """Worst-case account — every major risk present."""
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=1,
            instance_types=["m5.xlarge"],
            instance_ids=["i-bad"],
            has_load_balancer=False,
            auto_scaling_enabled=False,
            ssh_open_to_internet=True,
            rdp_open_to_internet=True,
            ssh_security_group_id="sg-ssh",
            rdp_security_group_id="sg-rdp",
            instances=[make_instance("i-bad", sg_ids=["sg-ssh"], imdsv2=False)],
            security_groups=[
                make_open_sg("sg-ssh", 22, attached_to=["i-bad"]),
                make_open_sg("sg-rdp", 3389, attached_to=["i-bad"]),
            ],
        ),
        s3=S3Data(
            total_buckets=3,
            public_buckets=["prod-data-bucket", "backup-bucket", "test-bucket"],
            unencrypted_buckets=["prod-data-bucket", "backup-bucket"],
            buckets_without_versioning=["prod-data-bucket", "backup-bucket", "test-bucket"],
            buckets_without_logging=["prod-data-bucket", "backup-bucket", "test-bucket"],
            buckets=[
                S3Bucket(name="prod-data-bucket", is_public=True, is_empty=False),
                S3Bucket(name="backup-bucket", is_public=True, is_empty=False),
                S3Bucket(name="test-bucket", is_public=True, is_empty=True),
            ],
        ),
        rds=RDSData(
            instances=["prod-db"],
            multi_az_enabled=False,
            backup_enabled=False,
            backup_retention_days=0,
            publicly_accessible=["prod-db"],
            unencrypted_instances=["prod-db"],
            instances_without_deletion_protection=["prod-db"],
            instances_without_log_exports=["prod-db"],
            rds_instances=[RDSInstance(id="prod-db", publicly_accessible=True, encrypted=False)],
        ),
        iam=IAMData(
            root_has_access_keys=True,
            users_without_mfa=["alice", "bob"],
            old_access_keys=["alice (120 days)", "bob (200 days)"],
            root_used_recently=True,
            users_with_admin_policy=["alice"],
            iam_users=[
                IAMUser(username="alice", has_console_access=True),
                IAMUser(username="bob", has_console_access=True),
            ],
        ),
        cloudtrail=CloudTrailData(is_enabled=False),
        cost=CostData(has_budget_alerts=False, has_billing_alarm=False),
        cloudwatch=CloudWatchData(has_alarms=False),
        guardduty=GuardDutyData(is_enabled=False),
        lambda_data=LambdaData(
            function_count=2,
            functions_with_admin_role=["dangerous-fn"],
            functions_with_outdated_runtime=["legacy-fn"],
            functions_with_no_timeout=["dangerous-fn"],
            functions=[
                LambdaFunction(name="dangerous-fn", role_arn="arn:aws:iam::123:role/AdminRole"),
                LambdaFunction(name="legacy-fn"),
            ],
        ),
        secrets_manager=SecretsManagerData(
            total_secrets=2,
            secrets_without_rotation=["db-password", "api-key"],
        ),
        vpc=VPCData(
            total_vpcs=1,
            vpcs_without_flow_logs=["vpc-001"],
            default_vpc_in_use=True,
            default_vpc_id="vpc-001",
            missing_s3_endpoint=True,
            missing_dynamodb_endpoint=True,
            subnets=[VPCSubnet(id="subnet-bad", vpc_id="vpc-001", resources=["i-bad"], is_public=True)],
        ),
        kms=KMSData(
            total_cmks=2,
            cmks_without_rotation=["key-001"],
            cmks_pending_deletion=["key-002"],
        ),
        config=ConfigData(is_enabled=False),
        sns=SNSData(
            total_topics=2,
            topics_without_encryption=["arn:aws:sns:us-east-1:123:alerts"],
            topics_with_public_access=["arn:aws:sns:us-east-1:123:public-topic"],
        ),
        ecs=ECSData(
            total_task_definitions=1,
            tasks_with_privileged_containers=["arn:aws:ecs:us-east-1:123:task-definition/bad-task:1"],
            tasks_without_resource_limits=["arn:aws:ecs:us-east-1:123:task-definition/bad-task:1"],
        ),
        waf=WAFData(
            total_albs=1,
            albs_without_waf=["arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"],
        ),
    )


@pytest.fixture
def empty_infra():
    """Brand new account — no resources at all."""
    return AWSInfrastructure(region="ap-south-1")


@pytest.fixture
def partial_permissions_infra():
    """Account where several collectors returned empty due to permission errors."""
    return AWSInfrastructure(
        region="eu-west-1",
        ec2=EC2Data(),   # skipped
        s3=S3Data(total_buckets=5, public_buckets=[], unencrypted_buckets=[]),
        rds=RDSData(),   # skipped
        iam=IAMData(
            root_has_access_keys=False,
            users_without_mfa=["charlie"],
            iam_users=[IAMUser(username="charlie", has_console_access=True)],
        ),
        cloudtrail=CloudTrailData(is_enabled=True, is_multi_region=False),
        guardduty=GuardDutyData(is_enabled=False),
        warnings=["EC2 scan skipped: insufficient permissions", "RDS scan skipped: insufficient permissions"],
    )
