import boto3
import json
import time as _time_module
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, EndpointResolutionError
from botocore.config import Config
from app.models import (
    AWSCredentials, AWSInfrastructure,
    EC2Data, S3Data, RDSData, IAMData, IAMUser,
    CloudTrailData, CostData, CloudWatchData,
    GuardDutyData, LambdaData, SecretsManagerData,
    VPCData, KMSData, ConfigData, SNSData, ECSData, WAFData,
    APIGatewayData, APIGatewayInstance,
    ElastiCacheData, ElastiCacheCluster,
    SQSData, SQSQueue,
    DynamoDBData, DynamoDBTable,
    EBSVolume, ElasticIP
)
from datetime import datetime, timezone

# 10 second timeout for every boto3 call - prevents hangs on bad credentials
# max_attempts=2: one initial call + one retry. Faster failure (11s max vs 25s with 5 retries).
BOTO_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 2, 'mode': 'standard'})

def collect_infrastructure(credentials: AWSCredentials) -> AWSInfrastructure:
    region = credentials.region
    warnings = []

    # -- ASSUME ROLE -----------------------------------------------
    # Exchange the user's Role ARN for temporary credentials
    # These credentials expire after 1 hour automatically
    try:
        sts = boto3.client('sts', config=BOTO_CONFIG)
        assumed = sts.assume_role(
            RoleArn=credentials.role_arn,
            RoleSessionName='EmfirgeSecurityScan',
            ExternalId='aws-risk-agent',
            DurationSeconds=3600
        )
        key = assumed['Credentials']['AccessKeyId']
        secret = assumed['Credentials']['SecretAccessKey']
        token = assumed['Credentials']['SessionToken']
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            raise ValueError('Could not assume the IAM role. Make sure you deployed the Emfirge CloudFormation stack correctly.')
        elif code == 'InvalidClientTokenId':
            raise ValueError('Invalid Role ARN. Please check the ARN you copied from the CloudFormation stack output.')
        else:
            raise ValueError(f'Role assumption failed: {e.response["Error"]["Message"]}')
    except Exception as e:
        raise ValueError(f'Could not connect to AWS: {str(e)}')

    # -- VALIDATE REGION -------------------------------------------
    # Fail fast if region is invalid before firing all 10 threads
    try:
        sts2 = boto3.client(
            'sts',
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            aws_session_token=token,
            region_name=region,
            config=BOTO_CONFIG
        )
        sts2.get_caller_identity()
    except EndpointResolutionError:
        raise ValueError(f'Invalid AWS region: "{region}". Please use a valid region like ap-south-1 or us-east-1.')
    except ClientError as e:
        raise ValueError(f'AWS validation failed: {e.response["Error"]["Message"]}')
    except Exception as e:
        raise ValueError(f'Could not connect to AWS: {str(e)}')

    # -- PARALLEL SCANNING -----------------------------------------
    # All 10 collectors run simultaneously via ThreadPoolExecutor
    # threading.Lock() protects the shared warnings list from race conditions

    warnings_lock = threading.Lock()

    def safe_warnings(collector_fn):
        local_warnings = []
        result = collector_fn(key, secret, token, region, local_warnings)
        if local_warnings:
            with warnings_lock:
                warnings.extend(local_warnings)
        return result

    collectors = {
        'ec2':             collect_ec2,
        's3':              collect_s3,
        'rds':             collect_rds,
        'iam':             collect_iam,
        'cloudtrail':      collect_cloudtrail,
        'cost':            collect_cost,
        'cloudwatch':      collect_cloudwatch,
        'guardduty':       collect_guardduty,
        'lambda':          collect_lambda,
        'secrets_manager': collect_secrets_manager,
        'vpc':             collect_vpc,
        'kms':             collect_kms,
        'config':          collect_config,
        'sns':             collect_sns,
        'ecs':             collect_ecs,
        'waf':             collect_waf,
        'api_gateway':     collect_api_gateway,
        'elasticache':     collect_elasticache,
        'sqs':             collect_sqs,
        'dynamodb':        collect_dynamodb,
    }

    results = {}

    # Stagger collector groups to reduce AWS API throttling.
    # Heavy collectors (ec2, iam, s3) are spread across different groups.
    COLLECTOR_GROUPS = [
        ['ec2', 'rds', 'cloudtrail', 'kms'],
        ['s3', 'guardduty', 'sns', 'sqs'],
        ['iam', 'cost', 'cloudwatch', 'config'],
        ['lambda', 'vpc', 'ecs', 'waf'],
        ['secrets_manager', 'api_gateway', 'elasticache', 'dynamodb'],
    ]

    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_name = {}
        for group_idx, group in enumerate(COLLECTOR_GROUPS):
            for name in group:
                if name in collectors:
                    future = executor.submit(safe_warnings, collectors[name])
                    future_to_name[future] = name
            # 200ms stagger between groups (skip after last group)
            if group_idx < len(COLLECTOR_GROUPS) - 1:
                _time_module.sleep(0.2)

        # Safety: catch any collectors not in groups (future-proofing)
        grouped = {name for group in COLLECTOR_GROUPS for name in group}
        for name in set(collectors.keys()) - grouped:
            future = executor.submit(safe_warnings, collectors[name])
            future_to_name[future] = name

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result(timeout=20)
            except TimeoutError:
                msg = f'{name} collector timed out — results excluded from this scan'
                print(msg)
                warnings.append(msg)
                defaults = {
                    'ec2':             EC2Data(),
                    's3':              S3Data(),
                    'rds':             RDSData(),
                    'iam':             IAMData(),
                    'cloudtrail':      CloudTrailData(),
                    'cost':            CostData(),
                    'cloudwatch':      CloudWatchData(),
                    'guardduty':       GuardDutyData(),
                    'lambda':          LambdaData(),
                    'secrets_manager': SecretsManagerData(),
                    'vpc':             VPCData(),
                    'kms':             KMSData(),
                    'config':          ConfigData(),
                    'sns':             SNSData(),
                    'ecs':             ECSData(),
                    'waf':             WAFData(),
                    'api_gateway':     APIGatewayData(),
                    'elasticache':     ElastiCacheData(),
                    'sqs':             SQSData(),
                    'dynamodb':        DynamoDBData(),
                }
                results[name] = defaults[name]
            except Exception as e:
                print(f'{name} collector crashed unexpectedly: {e}')
                defaults = {
                    'ec2':             EC2Data(),
                    's3':              S3Data(),
                    'rds':             RDSData(),
                    'iam':             IAMData(),
                    'cloudtrail':      CloudTrailData(),
                    'cost':            CostData(),
                    'cloudwatch':      CloudWatchData(),
                    'guardduty':       GuardDutyData(),
                    'lambda':          LambdaData(),
                    'secrets_manager': SecretsManagerData(),
                    'vpc':             VPCData(),
                    'kms':             KMSData(),
                    'config':          ConfigData(),
                    'sns':             SNSData(),
                    'ecs':             ECSData(),
                    'waf':             WAFData(),
                    'api_gateway':     APIGatewayData(),
                    'elasticache':     ElastiCacheData(),
                    'sqs':             SQSData(),
                    'dynamodb':        DynamoDBData(),
                }
                results[name] = defaults[name]

    # -- POST-PROCESSING: Derive functions_with_admin_role from IAM data --
    # Instead of Lambda collector making duplicate IAM API calls, we cross-reference
    # the IAM collector's role_policies (which already parsed all role policies)
    # against each Lambda function's role_arn. Saves ~40% IAM API calls.
    iam_data = results['iam']
    lambda_data = results['lambda']

    admin_role_arns = set()
    for rp in iam_data.role_policies:
        if rp.has_admin:
            admin_role_arns.add(rp.role_arn)

    functions_with_admin = []
    for fn in lambda_data.functions:
        role_arn = fn['role_arn'] if isinstance(fn, dict) else fn.role_arn
        if role_arn and role_arn in admin_role_arns:
            fn_name = fn['name'] if isinstance(fn, dict) else fn.name
            functions_with_admin.append(fn_name)

    lambda_data.functions_with_admin_role = functions_with_admin

    return AWSInfrastructure(
        ec2=results['ec2'],
        s3=results['s3'],
        rds=results['rds'],
        iam=results['iam'],
        cloudtrail=results['cloudtrail'],
        cost=results['cost'],
        cloudwatch=results['cloudwatch'],
        guardduty=results['guardduty'],
        lambda_data=results['lambda'],
        secrets_manager=results['secrets_manager'],
        vpc=results['vpc'],
        kms=results['kms'],
        config=results['config'],
        sns=results['sns'],
        ecs=results['ecs'],
        waf=results['waf'],
        api_gateway=results['api_gateway'],
        elasticache=results['elasticache'],
        sqs=results['sqs'],
        dynamodb=results['dynamodb'],
        region=region,
        warnings=warnings
    )

# -- HELPER --------------------------------------------------------
def get_error_code(e: ClientError) -> str:
    return e.response['Error']['Code']

# -- EC2 COLLECTOR -------------------------------------------------
def collect_ec2(key, secret, token, region, warnings) -> EC2Data:
    instance_count = 0
    instance_types = []
    instance_ids = []
    open_security_groups = []
    ssh_open = False
    rdp_open = False
    ssh_security_group_id = None
    rdp_security_group_id = None
    stopped_instances = []
    free_tier_eligible = True
    has_load_balancer = False
    auto_scaling_enabled = False
    
    # Relationship tracking
    instances = []
    security_groups = []
    load_balancers = []
    ebs_volumes = []
    elastic_ips = []
    sg_to_instances = {}  # Track which instances use which security groups

    FREE_TIER_TYPES = ['t2.micro', 't3.micro']

    try:
        ec2 = boto3.client('ec2', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        response = ec2.describe_instances()
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_state = instance['State']['Name']
                instance_type = instance['InstanceType']
                sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                subnet_id = instance.get('SubnetId')
                metadata = instance.get('MetadataOptions', {})
                imdsv2_required = metadata.get('HttpTokens') == 'required'
                
                # Add to relationship tracking
                instances.append({
                    'id': instance_id,
                    'type': instance_type,
                    'sg_ids': sg_ids,
                    'subnet_id': subnet_id,
                    'state': instance_state,
                    'imdsv2_required': imdsv2_required,
                    'instance_profile_arn': instance.get('IamInstanceProfile', {}).get('Arn'),
                })
                
                # Track SG to instance mapping
                for sg_id in sg_ids:
                    if sg_id not in sg_to_instances:
                        sg_to_instances[sg_id] = []
                    sg_to_instances[sg_id].append(instance_id)
                
                if instance_state == 'running':
                    instance_count += 1
                    instance_types.append(instance_type)
                    instance_ids.append(instance_id)
                    if instance_type not in FREE_TIER_TYPES:
                        free_tier_eligible = False
                elif instance_state == 'stopped':
                    stopped_instances.append(instance_id)

        sgs = ec2.describe_security_groups()
        for sg in sgs['SecurityGroups']:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            rules = []
            
            for rule in sg['IpPermissions']:
                rules.append({
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'protocol': rule.get('IpProtocol'),
                    'ip_ranges': [ip.get('CidrIp') for ip in rule.get('IpRanges', [])]
                })
                
                for ip in rule.get('IpRanges', []):
                    if ip.get('CidrIp') == '0.0.0.0/0':
                        open_security_groups.append(sg_name)
                        port = rule.get('FromPort', 0)
                        if port == 22:
                            ssh_open = True
                            ssh_security_group_id = sg_id
                        if port == 3389:
                            rdp_open = True
                            rdp_security_group_id = sg_id
            
            # Add to relationship tracking
            security_groups.append({
                'id': sg_id,
                'name': sg_name,
                'rules': rules,
                'attached_to': sg_to_instances.get(sg_id, [])
            })

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'EC2 scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'EC2 scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'EC2 scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    try:
        elb = boto3.client('elbv2', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)
        lbs = elb.describe_load_balancers()
        has_load_balancer = len(lbs['LoadBalancers']) > 0
        
        # Track load balancer relationships
        for lb in lbs['LoadBalancers']:
            lb_arn = lb['LoadBalancerArn']
            lb_type = lb.get('Type', 'application')
            target_instances = []
            
            try:
                # Get target groups for this load balancer
                target_groups = elb.describe_target_groups(LoadBalancerArn=lb_arn)
                for tg in target_groups['TargetGroups']:
                    tg_arn = tg['TargetGroupArn']
                    # Get target health to find instances
                    health = elb.describe_target_health(TargetGroupArn=tg_arn)
                    for target in health['TargetHealthDescriptions']:
                        target_id = target['Target']['Id']
                        if target_id.startswith('i-'):  # EC2 instance
                            target_instances.append(target_id)
            except Exception:
                pass
            
            load_balancers.append({
                'arn': lb_arn,
                'type': lb_type,
                'target_instances': target_instances
            })
            
    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            warnings.append('Load Balancer scan skipped: insufficient permissions')
        print(f'ELB scan skipped: {code}')
    except Exception as e:
        print(f'ELB scan skipped: {e}')

    try:
        asg = boto3.client('autoscaling', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)
        groups = asg.describe_auto_scaling_groups()
        auto_scaling_enabled = len(groups['AutoScalingGroups']) > 0
    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            warnings.append('Auto Scaling scan skipped: insufficient permissions')
        print(f'Auto Scaling scan skipped: {code}')
    except Exception as e:
        print(f'Auto Scaling scan skipped: {e}')

    try:
        vols_resp = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
        for v in vols_resp.get('Volumes', []):
            ebs_volumes.append(EBSVolume(
                id=v['VolumeId'],
                size_gb=v['Size'],
                volume_type=v['VolumeType'],
                create_time=v['CreateTime'].isoformat(),
                availability_zone=v['AvailabilityZone'],
            ))
    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            warnings.append('EBS volumes scan skipped: insufficient permissions')
        else:
            print(f'EBS volumes scan skipped: {code}')
    except Exception as e:
        print(f'EBS volumes scan skipped: {e}')

    try:
        eips_resp = ec2.describe_addresses()
        for addr in eips_resp.get('Addresses', []):
            elastic_ips.append(ElasticIP(
                allocation_id=addr.get('AllocationId', addr['PublicIp']),
                public_ip=addr['PublicIp'],
                is_attached=addr.get('AssociationId') is not None,
            ))
    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            warnings.append('Elastic IPs scan skipped: insufficient permissions')
        else:
            print(f'Elastic IPs scan skipped: {code}')
    except Exception as e:
        print(f'Elastic IPs scan skipped: {e}')

    return EC2Data(
        instance_count=instance_count,
        instance_types=instance_types,
        instance_ids=instance_ids,
        has_load_balancer=has_load_balancer,
        auto_scaling_enabled=auto_scaling_enabled,
        open_security_groups=list(set(open_security_groups)),
        ssh_open_to_internet=ssh_open,
        rdp_open_to_internet=rdp_open,
        ssh_security_group_id=ssh_security_group_id,
        rdp_security_group_id=rdp_security_group_id,
        stopped_instances=stopped_instances,
        free_tier_eligible=free_tier_eligible,
        instances=instances,
        security_groups=security_groups,
        load_balancers=load_balancers,
        ebs_volumes=ebs_volumes,
        elastic_ips=elastic_ips,
    )

# -- S3 COLLECTOR --------------------------------------------------
def collect_s3(key, secret, token, region, warnings) -> S3Data:
    total_buckets = 0
    public_buckets = []
    unencrypted_buckets = []
    buckets_without_versioning = []
    buckets_without_logging = []
    buckets = []

    try:
        s3 = boto3.client('s3', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)
        bucket_list = s3.list_buckets()
        total_buckets = len(bucket_list['Buckets'])

        # --- CloudFront: call ONCE outside the bucket loop ---
        cf_bucket_names: set = set()
        try:
            cloudfront = boto3.client('cloudfront', aws_access_key_id=key,
                                     aws_secret_access_key=secret,
                                     aws_session_token=token,
                                     config=BOTO_CONFIG)
            distributions = cloudfront.list_distributions()
            for dist in distributions.get('DistributionList', {}).get('Items', []):
                for origin in dist.get('Origins', {}).get('Items', []):
                    domain = origin.get('DomainName', '')
                    # domain looks like "bucket-name.s3.amazonaws.com"
                    for b in bucket_list['Buckets']:
                        if b['Name'] in domain:
                            cf_bucket_names.add(b['Name'])
        except Exception:
            pass

        # --- Per-bucket check (thread-safe, no shared mutation) ---
        def _check_bucket(name: str) -> dict:
            """Returns a self-contained result dict for one bucket."""
            result = {
                'name': name,
                'is_public': False,
                'has_cloudfront': name in cf_bucket_names,
                'policy': None,
                'is_empty': False,
                'flags': {
                    'public': False,
                    'unencrypted': False,
                    'no_versioning': False,
                    'no_logging': False,
                }
            }

            # ACL check
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    if 'AllUsers' in grant['Grantee'].get('URI', ''):
                        result['is_public'] = True
                        result['flags']['public'] = True
            except ClientError as e:
                print(f'S3 ACL check skipped for {name}: {get_error_code(e)}')
            except Exception:
                pass

            # Encryption check
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                if get_error_code(e) == 'ServerSideEncryptionConfigurationNotFoundError':
                    result['flags']['unencrypted'] = True
                else:
                    print(f'S3 encryption check skipped for {name}: {get_error_code(e)}')
            except Exception:
                result['flags']['unencrypted'] = True

            # Versioning check
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get('Status') != 'Enabled':
                    result['flags']['no_versioning'] = True
            except ClientError as e:
                print(f'S3 versioning check skipped for {name}: {get_error_code(e)}')
            except Exception:
                result['flags']['no_versioning'] = True

            # Logging check
            try:
                logging_resp = s3.get_bucket_logging(Bucket=name)
                if 'LoggingEnabled' not in logging_resp:
                    result['flags']['no_logging'] = True
            except ClientError as e:
                print(f'S3 logging check skipped for {name}: {get_error_code(e)}')
            except Exception:
                result['flags']['no_logging'] = True

            # Policy
            try:
                policy_response = s3.get_bucket_policy(Bucket=name)
                result['policy'] = policy_response.get('Policy')
            except ClientError as e:
                if get_error_code(e) != 'NoSuchBucketPolicy':
                    print(f'S3 policy check skipped for {name}: {get_error_code(e)}')
            except Exception:
                pass

            # Empty check (orphan detection)
            try:
                response = s3.list_objects_v2(Bucket=name, MaxKeys=1)
                result['is_empty'] = response.get('KeyCount', 0) == 0
            except ClientError as e:
                print(f'S3 object count check skipped for {name}: {get_error_code(e)}')
            except Exception:
                pass

            return result

        # --- Run per-bucket checks in parallel ---
        bucket_names = [b['Name'] for b in bucket_list['Buckets']]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_check_bucket, name): name for name in bucket_names}
            for future in as_completed(futures):
                result = future.result()
                # Merge into aggregate lists
                if result['flags']['public']:
                    public_buckets.append(result['name'])
                if result['flags']['unencrypted']:
                    unencrypted_buckets.append(result['name'])
                if result['flags']['no_versioning']:
                    buckets_without_versioning.append(result['name'])
                if result['flags']['no_logging']:
                    buckets_without_logging.append(result['name'])
                buckets.append({
                    'name': result['name'],
                    'is_public': result['is_public'],
                    'has_cloudfront': result['has_cloudfront'],
                    'policy': result['policy'],
                    'is_empty': result['is_empty'],
                })

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'S3 scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'S3 scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'S3 scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return S3Data(
        total_buckets=total_buckets,
        public_buckets=public_buckets,
        unencrypted_buckets=unencrypted_buckets,
        buckets_without_versioning=buckets_without_versioning,
        buckets_without_logging=buckets_without_logging,
        buckets=buckets
    )

# -- RDS COLLECTOR -------------------------------------------------
def collect_rds(key, secret, token, region, warnings) -> RDSData:
    instances = []
    multi_az = False
    backup_enabled = False
    backup_retention = 0
    publicly_accessible = []
    unencrypted = []
    without_deletion_protection = []
    without_log_exports = []
    
    # Relationship tracking
    rds_instances = []

    try:
        rds = boto3.client('rds', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)
        dbs = rds.describe_db_instances()

        for db in dbs['DBInstances']:
            name = db['DBInstanceIdentifier']
            instances.append(name)
            sg_ids = [sg['VpcSecurityGroupId'] for sg in db.get('VpcSecurityGroups', [])]
            is_public = db.get('PubliclyAccessible', False)
            is_encrypted = db.get('StorageEncrypted', False)
            
            if db.get('MultiAZ'):
                multi_az = True
            if db.get('BackupRetentionPeriod', 0) > 0:
                backup_enabled = True
                backup_retention = db['BackupRetentionPeriod']
            if is_public:
                publicly_accessible.append(name)
            if not is_encrypted:
                unencrypted.append(name)
            if not db.get('DeletionProtection', False):
                without_deletion_protection.append(name)
            if not db.get('EnabledCloudwatchLogsExports', []):
                without_log_exports.append(name)
            
            # Add to relationship tracking
            rds_instances.append({
                'id': name,
                'sg_ids': sg_ids,
                'publicly_accessible': is_public,
                'encrypted': is_encrypted
            })

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'RDS scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'RDS scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'RDS scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return RDSData(
        instances=instances,
        multi_az_enabled=multi_az,
        backup_enabled=backup_enabled,
        backup_retention_days=backup_retention,
        publicly_accessible=publicly_accessible,
        unencrypted_instances=unencrypted,
        instances_without_deletion_protection=without_deletion_protection,
        instances_without_log_exports=without_log_exports,
        rds_instances=rds_instances
    )

# -- IAM COLLECTOR -------------------------------------------------
def collect_iam(key, secret, token, region, warnings) -> IAMData:
    root_has_keys = False
    users_without_mfa = []
    old_access_keys = []
    root_used_recently = False
    iam_users = []
    users_with_admin_policy = []
    role_policies = []

    try:
        iam = boto3.client('iam', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        try:
            summary = iam.get_account_summary()
            root_has_keys = summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0
        except ClientError as e:
            print(f'IAM root check skipped: {get_error_code(e)}')
        except Exception:
            pass

        users = iam.list_users()
        for user in users['Users']:
            username = user['UserName']
            
            # Check console access
            has_console_access = None
            try:
                iam.get_login_profile(UserName=username)
                has_console_access = True
            except ClientError as e:
                if get_error_code(e) == 'NoSuchEntity':
                    has_console_access = False
                else:
                    print(f'IAM console access check skipped for {username}: {get_error_code(e)}')
            except Exception:
                pass
            
            # Create user object
            iam_user = IAMUser(
                username=username,
                has_console_access=has_console_access
            )
            iam_users.append(iam_user)

            try:
                mfa = iam.list_mfa_devices(UserName=username)
                if len(mfa['MFADevices']) == 0:
                    users_without_mfa.append(username)
            except ClientError as e:
                print(f'IAM MFA check skipped for {username}: {get_error_code(e)}')
            except Exception:
                pass

            try:
                keys = iam.list_access_keys(UserName=username)
                for k in keys['AccessKeyMetadata']:
                    if k['Status'] == 'Active':
                        age = (datetime.now(timezone.utc) - k['CreateDate']).days
                        if age > 90:
                            old_access_keys.append(f"{username} ({age} days)")
            except ClientError as e:
                print(f'IAM access key check skipped for {username}: {get_error_code(e)}')
            except Exception:
                pass

            # Check attached policies for AdministratorAccess
            try:
                attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
                if any(p['PolicyName'] == 'AdministratorAccess' for p in attached):
                    users_with_admin_policy.append(username)
                    continue  # no need to check inline policies
            except ClientError as e:
                print(f'IAM attached policy check skipped for {username}: {get_error_code(e)}')
            except Exception:
                pass

            # Check inline policies for Action:* + Resource:*
            try:
                inline_names = iam.list_user_policies(UserName=username)['PolicyNames']
                for policy_name in inline_names:
                    try:
                        doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)['PolicyDocument']
                        if isinstance(doc, str):
                            import urllib.parse
                            doc = json.loads(urllib.parse.unquote(doc))
                        for stmt in doc.get('Statement', []):
                            actions = stmt.get('Action') or []
                            resources = stmt.get('Resource') or []
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            if stmt.get('Effect') == 'Allow' and '*' in actions and '*' in resources:
                                users_with_admin_policy.append(username)
                                break
                    except Exception:
                        pass
            except ClientError as e:
                print(f'IAM inline policy check skipped for {username}: {get_error_code(e)}')
            except Exception:
                pass

        try:
            iam.generate_credential_report()
            import csv, io
            report_content = iam.get_credential_report()
            csv_data = report_content['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_data))
            for row in reader:
                if row['user'] == '<root_account>':
                    last_used = row.get('password_last_used', 'N/A')
                    if last_used not in ['N/A', 'no_information', 'not_supported']:
                        last_used_date = datetime.strptime(
                            last_used[:10], '%Y-%m-%d'
                        ).replace(tzinfo=timezone.utc)
                        days_ago = (datetime.now(timezone.utc) - last_used_date).days
                        if days_ago < 30:
                            root_used_recently = True
        except ClientError as e:
            print(f'IAM credential report skipped: {get_error_code(e)}')
        except Exception:
            pass

        # -- ROLE POLICY COLLECTION (for graph can_access edges) -------
        # Collect policy documents for each role to determine what resources
        # each role can access. Skip AWS service-linked roles.
        import time as _time
        import urllib.parse as _urlparse

        try:
            roles_paginator = iam.get_paginator('list_roles')
            for roles_page in roles_paginator.paginate():
                for role in roles_page['Roles']:
                    role_name = role['RoleName']
                    role_arn = role['Arn']
                    role_path = role.get('Path', '/')

                    # Skip AWS service-linked roles (not user-controlled)
                    if '/aws-service-role/' in role_path:
                        continue

                    accessible_resources = []
                    has_admin = False
                    policy_names_list = []

                    # Check attached managed policies
                    try:
                        attached_resp = iam.list_attached_role_policies(RoleName=role_name)
                        for policy in attached_resp.get('AttachedPolicies', []):
                            policy_arn = policy['PolicyArn']
                            policy_names_list.append(policy['PolicyName'])

                            # Check for AdministratorAccess shortcut
                            if policy_arn == 'arn:aws:iam::aws:policy/AdministratorAccess':
                                has_admin = True
                                break

                            # Get the policy document for resource ARNs
                            try:
                                pol = iam.get_policy(PolicyArn=policy_arn)
                                version_id = pol['Policy']['DefaultVersionId']
                                version = iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=version_id
                                )
                                doc = version['PolicyVersion']['Document']
                                if isinstance(doc, str):
                                    doc = json.loads(_urlparse.unquote(doc))
                                for stmt in doc.get('Statement', []):
                                    if stmt.get('Effect') != 'Allow':
                                        continue
                                    actions = stmt.get('Action', [])
                                    resources = stmt.get('Resource', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    # Check for full admin
                                    if '*' in actions and '*' in resources:
                                        has_admin = True
                                        break
                                    # Collect resource ARNs for data services
                                    for res in resources:
                                        if any(svc in res for svc in [':s3:', ':rds:', ':lambda:', ':secretsmanager:', ':dynamodb:']):
                                            accessible_resources.append(res)
                                        elif res == '*':
                                            accessible_resources.append('*')
                                if has_admin:
                                    break
                            except ClientError:
                                pass
                            except Exception:
                                pass

                    except ClientError as e:
                        if get_error_code(e) == 'Throttling':
                            _time.sleep(0.2)
                        else:
                            print(f'IAM role policy check skipped for {role_name}: {get_error_code(e)}')
                        continue
                    except Exception:
                        continue

                    if has_admin:
                        accessible_resources = []  # has_admin flag is sufficient

                    # Check inline policies (only if not already admin)
                    if not has_admin:
                        try:
                            inline_resp = iam.list_role_policies(RoleName=role_name)
                            for pol_name in inline_resp.get('PolicyNames', []):
                                policy_names_list.append(pol_name)
                                try:
                                    pol_doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                                    doc = pol_doc_resp.get('PolicyDocument', {})
                                    if isinstance(doc, str):
                                        doc = json.loads(_urlparse.unquote(doc))
                                    for stmt in doc.get('Statement', []):
                                        if stmt.get('Effect') != 'Allow':
                                            continue
                                        actions = stmt.get('Action', [])
                                        resources = stmt.get('Resource', [])
                                        if isinstance(actions, str):
                                            actions = [actions]
                                        if isinstance(resources, str):
                                            resources = [resources]
                                        if '*' in actions and '*' in resources:
                                            has_admin = True
                                            accessible_resources = []
                                            break
                                        for res in resources:
                                            if any(svc in res for svc in [':s3:', ':rds:', ':lambda:', ':secretsmanager:', ':dynamodb:']):
                                                accessible_resources.append(res)
                                            elif res == '*':
                                                accessible_resources.append('*')
                                    if has_admin:
                                        break
                                except Exception:
                                    pass
                        except ClientError as e:
                            if get_error_code(e) == 'Throttling':
                                _time.sleep(0.2)
                        except Exception:
                            pass

                    # Only record roles that have meaningful access data
                    if has_admin or accessible_resources:
                        from app.models import RolePolicy
                        role_policies.append(RolePolicy(
                            role_name=role_name,
                            role_arn=role_arn,
                            accessible_resources=list(set(accessible_resources)),
                            has_admin=has_admin,
                            policy_names=policy_names_list,
                        ))

                    # Throttle between roles to stay under 15 TPS
                    _time.sleep(0.05)

        except ClientError as e:
            if get_error_code(e) in ['AccessDenied', 'UnauthorizedOperation']:
                warnings.append('IAM role policy scan skipped: insufficient permissions')
            else:
                print(f'IAM role policy scan skipped: {get_error_code(e)}')
        except Exception as e:
            print(f'IAM role policy scan skipped: {str(e)}')

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'IAM scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'IAM scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'IAM scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return IAMData(
        root_has_access_keys=root_has_keys,
        users_without_mfa=users_without_mfa,
        old_access_keys=old_access_keys,
        root_used_recently=root_used_recently,
        users_with_admin_policy=users_with_admin_policy,
        iam_users=iam_users,
        role_policies=role_policies,
    )

# -- CLOUDTRAIL COLLECTOR ------------------------------------------
def collect_cloudtrail(key, secret, token, region, warnings) -> CloudTrailData:
    is_enabled = False
    is_multi_region = False
    has_log_validation = False
    trail_arn = None

    try:
        ct = boto3.client('cloudtrail', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)
        trails = ct.describe_trails()

        for trail in trails['trailList']:
            try:
                status = ct.get_trail_status(Name=trail['TrailARN'])
                if status.get('IsLogging'):
                    is_enabled = True
                    trail_arn = trail['TrailARN']
            except ClientError as e:
                print(f'CloudTrail status check skipped: {get_error_code(e)}')
            except Exception:
                pass

            if trail.get('IsMultiRegionTrail'):
                is_multi_region = True
            if trail.get('LogFileValidationEnabled'):
                has_log_validation = True

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'CloudTrail scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'CloudTrail scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'CloudTrail scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return CloudTrailData(
        is_enabled=is_enabled,
        is_multi_region=is_multi_region,
        has_log_file_validation=has_log_validation,
        trail_arn=trail_arn
    )

# -- COST COLLECTOR ------------------------------------------------
# Cost Explorer removed - it charged $0.01 per scan to the user's AWS account
# Budget alerts and billing alarm checks are free and cover the important cases
def collect_cost(key, secret, token, region, warnings) -> CostData:
    has_budget_alerts = False
    has_billing_alarm = False

    try:
        sts = boto3.client('sts', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          config=BOTO_CONFIG)
        account_id = sts.get_caller_identity()['Account']
        budgets = boto3.client('budgets', aws_access_key_id=key,
                              aws_secret_access_key=secret,
                              aws_session_token=token,
                              region_name='us-east-1', config=BOTO_CONFIG)
        budget_list = budgets.describe_budgets(AccountId=account_id)
        has_budget_alerts = len(budget_list.get('Budgets', [])) > 0
    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'Budgets scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            print(f'Budgets scan skipped: {code}')
    except Exception as e:
        print(f'Budgets scan skipped: {e}')

    try:
        cw = boto3.client('cloudwatch', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name='us-east-1', config=BOTO_CONFIG)
        alarms = cw.describe_alarms()
        for alarm in alarms['MetricAlarms']:
            if 'billing' in alarm['AlarmName'].lower() or \
               alarm.get('Namespace') == 'AWS/Billing':
                has_billing_alarm = True
    except ClientError as e:
        print(f'CloudWatch billing check skipped: {get_error_code(e)}')
    except Exception as e:
        print(f'CloudWatch billing check skipped: {e}')

    return CostData(
        has_budget_alerts=has_budget_alerts,
        has_billing_alarm=has_billing_alarm
    )

# -- CLOUDWATCH COLLECTOR ------------------------------------------
def collect_cloudwatch(key, secret, token, region, warnings) -> CloudWatchData:
    has_alarms = False
    has_billing_alarm = False

    try:
        cw = boto3.client('cloudwatch', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)
        alarms = cw.describe_alarms()
        has_alarms = len(alarms['MetricAlarms']) > 0

        for alarm in alarms['MetricAlarms']:
            if 'billing' in alarm['AlarmName'].lower() or \
               alarm.get('Namespace') == 'AWS/Billing':
                has_billing_alarm = True

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'CloudWatch scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'CloudWatch scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'CloudWatch scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return CloudWatchData(
        has_alarms=has_alarms,
        has_billing_alarm=has_billing_alarm
    )

# -- GUARDDUTY COLLECTOR -------------------------------------------
def collect_guardduty(key, secret, token, region, warnings) -> GuardDutyData:
    is_enabled = False
    detector_id = None

    try:
        gd = boto3.client('guardduty', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)

        response = gd.list_detectors()
        detector_ids = response.get('DetectorIds', [])

        if detector_ids:
            detector_id = detector_ids[0]
            detector = gd.get_detector(DetectorId=detector_id)
            if detector.get('Status') == 'ENABLED':
                is_enabled = True

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'GuardDuty scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'GuardDuty scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'GuardDuty scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return GuardDutyData(
        is_enabled=is_enabled,
        detector_id=detector_id
    )

# -- LAMBDA COLLECTOR ----------------------------------------------
def collect_lambda(key, secret, token, region, warnings) -> LambdaData:
    function_count = 0
    functions_with_outdated_runtime = []
    functions_with_no_timeout = []
    
    # Relationship tracking
    functions = []

    DEPRECATED_RUNTIMES = [
        'python3.6', 'python3.7', 'python3.8',
        'nodejs10.x', 'nodejs12.x', 'nodejs14.x', 'nodejs16.x',
        'java8', 'java8.al2',
        'dotnetcore1.0', 'dotnetcore2.0', 'dotnetcore2.1', 'dotnetcore3.1',
        'ruby2.5', 'ruby2.7',
        'go1.x'
    ]

    RISKY_TIMEOUTS = [3, 900]

    try:
        lm = boto3.client('lambda', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)

        paginator = lm.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page['Functions']:
                function_count += 1
                fn_name = fn['FunctionName']
                runtime = fn.get('Runtime', '')
                timeout = fn.get('Timeout', 3)
                role_arn = fn.get('Role', '')
                vpc_config = fn.get('VpcConfig', {})
                vpc_id = vpc_config.get('VpcId')
                subnet_ids = vpc_config.get('SubnetIds', [])

                if runtime in DEPRECATED_RUNTIMES:
                    functions_with_outdated_runtime.append(fn_name)

                if timeout in RISKY_TIMEOUTS:
                    functions_with_no_timeout.append(fn_name)

                # Add to relationship tracking
                secret_refs = []
                env_vars = fn.get('Environment', {}).get('Variables', {})
                for k, value in env_vars.items():
                    if any(word in k.upper() for word in ['SECRET', 'PASSWORD', 'TOKEN', 'API_KEY', 'CREDENTIAL']):
                        secret_refs.append(f"env:{k}")
                    elif isinstance(value, str) and value.startswith('arn:aws:secretsmanager'):
                        secret_id = value.split(':')[-1]
                        secret_refs.append(secret_id)

                functions.append({
                    'name': fn_name,
                    'role_arn': role_arn,
                    'vpc_id': vpc_id,
                    'subnet_ids': subnet_ids,
                    'secret_refs': secret_refs
                })

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'Lambda scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'Lambda scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'Lambda scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    # NOTE: functions_with_admin_role is populated post-collection in
    # collect_infrastructure() by cross-referencing IAM role_policies.
    # This avoids duplicate IAM API calls (saves ~40% IAM TPS).
    return LambdaData(
        function_count=function_count,
        functions_with_admin_role=[],
        functions_with_outdated_runtime=functions_with_outdated_runtime,
        functions_with_no_timeout=functions_with_no_timeout,
        functions=functions
    )

# -- SECRETS MANAGER COLLECTOR -------------------------------------
def collect_secrets_manager(key, secret, token, region, warnings) -> SecretsManagerData:
    total_secrets = 0
    secrets_without_rotation = []

    try:
        sm = boto3.client('secretsmanager', aws_access_key_id=key,
                         aws_secret_access_key=secret,
                         aws_session_token=token,
                         region_name=region, config=BOTO_CONFIG)

        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for s in page['SecretList']:
                total_secrets += 1
                secret_name = s['Name']
                rotation_enabled = s.get('RotationEnabled', False)
                last_rotated = s.get('LastRotatedDate')

                if not rotation_enabled:
                    secrets_without_rotation.append(secret_name)
                elif last_rotated:
                    days_since_rotation = (datetime.now(timezone.utc) - last_rotated).days
                    if days_since_rotation > 90:
                        secrets_without_rotation.append(secret_name)

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'Secrets Manager scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'Secrets Manager scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'Secrets Manager scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return SecretsManagerData(
        total_secrets=total_secrets,
        secrets_without_rotation=secrets_without_rotation
    )

# -- VPC COLLECTOR -------------------------------------------------
def collect_vpc(key, secret, token, region, warnings) -> VPCData:
    total_vpcs = 0
    vpcs_without_flow_logs = []
    default_vpc_in_use = False
    default_vpc_id = None
    missing_s3_endpoint = False
    missing_dynamodb_endpoint = False
    
    # Network topology
    internet_gateways = []
    nat_gateways = []
    public_subnet_ids = set()
    
    # Relationship tracking
    subnets = []

    try:
        ec2 = boto3.client('ec2', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        # Get all VPCs
        vpcs_response = ec2.describe_vpcs()
        total_vpcs = len(vpcs_response['Vpcs'])

        # Check each VPC for default status and flow logs
        for vpc in vpcs_response['Vpcs']:
            vpc_id = vpc['VpcId']
            
            # Check if this is the default VPC
            if vpc.get('IsDefault', False):
                default_vpc_in_use = True
                default_vpc_id = vpc_id

            # Check flow logs for this VPC
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )
                if len(flow_logs['FlowLogs']) == 0:
                    vpcs_without_flow_logs.append(vpc_id)
            except ClientError as e:
                print(f'VPC flow logs check skipped for {vpc_id}: {get_error_code(e)}')
            except Exception:
                pass

        # -- INTERNET GATEWAYS -------------------------------------
        try:
            igws_response = ec2.describe_internet_gateways()
            for igw in igws_response.get('InternetGateways', []):
                internet_gateways.append(igw['InternetGatewayId'])
        except ClientError as e:
            print(f'Internet Gateways check skipped: {get_error_code(e)}')
        except Exception:
            pass

        # -- NAT GATEWAYS ------------------------------------------
        try:
            nats_response = ec2.describe_nat_gateways(
                Filters=[{'Name': 'state', 'Values': ['available']}]
            )
            for nat in nats_response.get('NatGateways', []):
                nat_gateways.append(nat['NatGatewayId'])
        except ClientError as e:
            print(f'NAT Gateways check skipped: {get_error_code(e)}')
        except Exception:
            pass

        # -- ROUTE TABLES → determine public subnets ---------------
        # A subnet is public if its route table has a 0.0.0.0/0 route via an IGW.
        # Subnets without an explicit route table association inherit the VPC's main RT.
        try:
            rts_response = ec2.describe_route_tables()
            # Track which subnets have explicit RT associations
            explicitly_associated_subnets = set()
            # Track VPCs whose main RT has an IGW route (their unassociated subnets are public)
            vpcs_with_public_main_rt = set()

            for rt in rts_response.get('RouteTables', []):
                has_igw_route = any(
                    r.get('GatewayId', '').startswith('igw-')
                    for r in rt.get('Routes', [])
                    if r.get('DestinationCidrBlock') == '0.0.0.0/0'
                )

                is_main_rt = False
                for assoc in rt.get('Associations', []):
                    if assoc.get('SubnetId'):
                        explicitly_associated_subnets.add(assoc['SubnetId'])
                        if has_igw_route:
                            public_subnet_ids.add(assoc['SubnetId'])
                    if assoc.get('Main', False):
                        is_main_rt = True

                if is_main_rt and has_igw_route:
                    vpcs_with_public_main_rt.add(rt.get('VpcId', ''))

        except ClientError as e:
            print(f'Route Tables check skipped: {get_error_code(e)}')
        except Exception:
            pass

        # Get all subnets and track which resources are in them
        try:
            subnets_response = ec2.describe_subnets()
            for subnet in subnets_response['Subnets']:
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                az = subnet.get('AvailabilityZone', '')
                resources = []
                
                # Track instances in this subnet
                try:
                    instances = ec2.describe_instances(
                        Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}]
                    )
                    for reservation in instances['Reservations']:
                        for instance in reservation['Instances']:
                            resources.append(instance['InstanceId'])
                except Exception:
                    pass
                
                # Determine if subnet is public:
                # 1. Explicitly associated with a route table that has IGW route, OR
                # 2. Not explicitly associated AND its VPC's main RT has IGW route
                is_public = subnet_id in public_subnet_ids
                if not is_public and subnet_id not in explicitly_associated_subnets:
                    if vpc_id in vpcs_with_public_main_rt:
                        is_public = True
                        public_subnet_ids.add(subnet_id)

                subnets.append({
                    'id': subnet_id,
                    'vpc_id': vpc_id,
                    'resources': resources,
                    'availability_zone': az,
                    'is_public': is_public,
                })
        except ClientError as e:
            print(f'VPC subnets check skipped: {get_error_code(e)}')
        except Exception:
            pass

        # Check for VPC endpoints
        try:
            endpoints = ec2.describe_vpc_endpoints()
            s3_endpoint_exists = False
            dynamodb_endpoint_exists = False
            
            for endpoint in endpoints['VpcEndpoints']:
                service_name = endpoint.get('ServiceName', '').lower()
                if 's3' in service_name:
                    s3_endpoint_exists = True
                if 'dynamodb' in service_name:
                    dynamodb_endpoint_exists = True
            
            missing_s3_endpoint = not s3_endpoint_exists
            missing_dynamodb_endpoint = not dynamodb_endpoint_exists
        except ClientError as e:
            print(f'VPC endpoints check skipped: {get_error_code(e)}')
        except Exception:
            pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'VPC scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'VPC scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'VPC scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return VPCData(
        total_vpcs=total_vpcs,
        vpcs_without_flow_logs=vpcs_without_flow_logs,
        default_vpc_in_use=default_vpc_in_use,
        default_vpc_id=default_vpc_id,
        missing_s3_endpoint=missing_s3_endpoint,
        missing_dynamodb_endpoint=missing_dynamodb_endpoint,
        internet_gateways=internet_gateways,
        nat_gateways=nat_gateways,
        public_subnet_ids=list(public_subnet_ids),
        subnets=subnets
    )

# -- KMS COLLECTOR -------------------------------------------------
def collect_kms(key, secret, token, region, warnings) -> KMSData:
    total_cmks = 0
    cmks_without_rotation = []
    cmks_pending_deletion = []

    try:
        kms = boto3.client('kms', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        # Get all KMS keys
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key_entry in page['Keys']:
                key_id = key_entry['KeyId']
                
                try:
                    # Get key metadata to check if it's customer-managed
                    key_metadata = kms.describe_key(KeyId=key_id)
                    key_manager = key_metadata['KeyMetadata'].get('KeyManager')
                    key_state = key_metadata['KeyMetadata'].get('KeyState')
                    
                    # Only process customer-managed keys
                    if key_manager == 'CUSTOMER':
                        total_cmks += 1
                        
                        # Check if key is scheduled for deletion
                        if key_state == 'PendingDeletion':
                            cmks_pending_deletion.append(key_id)
                        
                        # Check rotation status (only for enabled keys)
                        if key_state == 'Enabled':
                            try:
                                rotation_status = kms.get_key_rotation_status(KeyId=key_id)
                                if not rotation_status.get('KeyRotationEnabled', False):
                                    cmks_without_rotation.append(key_id)
                            except ClientError as e:
                                print(f'KMS rotation check skipped for {key_id}: {get_error_code(e)}')
                            except Exception:
                                pass
                
                except ClientError as e:
                    print(f'KMS key check skipped for {key_id}: {get_error_code(e)}')
                except Exception:
                    pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'KMS scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'KMS scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'KMS scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return KMSData(
        total_cmks=total_cmks,
        cmks_without_rotation=cmks_without_rotation,
        cmks_pending_deletion=cmks_pending_deletion
    )

# -- AWS CONFIG COLLECTOR ------------------------------------------
def collect_config(key, secret, token, region, warnings) -> ConfigData:
    is_enabled = False
    is_recording = False
    non_compliant_rules = []

    try:
        config = boto3.client('config', aws_access_key_id=key,
                             aws_secret_access_key=secret,
                             aws_session_token=token,
                             region_name=region, config=BOTO_CONFIG)

        # Check if Config is enabled
        try:
            recorders = config.describe_configuration_recorders()
            if len(recorders.get('ConfigurationRecorders', [])) > 0:
                is_enabled = True
                
                # Check if recorder is actively recording
                recorder_status = config.describe_configuration_recorder_status()
                for status in recorder_status.get('ConfigurationRecordersStatus', []):
                    if status.get('recording', False):
                        is_recording = True
                        break
        except ClientError as e:
            print(f'Config recorder check skipped: {get_error_code(e)}')
        except Exception:
            pass

        # If Config is enabled, check for non-compliant rules
        if is_enabled:
            try:
                compliance_response = config.describe_compliance_by_config_rule(
                    ComplianceTypes=['NON_COMPLIANT']
                )
                for rule in compliance_response.get('ComplianceByConfigRules', []):
                    rule_name = rule.get('ConfigRuleName')
                    if rule_name:
                        non_compliant_rules.append(rule_name)
            except ClientError as e:
                print(f'Config compliance check skipped: {get_error_code(e)}')
            except Exception:
                pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'AWS Config scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'AWS Config scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'AWS Config scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return ConfigData(
        is_enabled=is_enabled,
        is_recording=is_recording,
        non_compliant_rules=non_compliant_rules
    )

# -- SNS COLLECTOR -------------------------------------------------
def collect_sns(key, secret, token, region, warnings) -> SNSData:
    total_topics = 0
    topics_without_encryption = []
    topics_with_public_access = []

    try:
        sns = boto3.client('sns', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        # Get all SNS topics
        paginator = sns.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get('Topics', []):
                topic_arn = topic['TopicArn']
                total_topics += 1
                
                try:
                    # Get topic attributes
                    attributes = sns.get_topic_attributes(TopicArn=topic_arn)
                    attrs = attributes.get('Attributes', {})
                    
                    # Check encryption
                    if 'KmsMasterKeyId' not in attrs:
                        topics_without_encryption.append(topic_arn)
                    
                    # Check for public access in policy
                    policy_str = attrs.get('Policy', '{}')
                    try:
                        policy = json.loads(policy_str)
                        for statement in policy.get('Statement', []):
                            effect = statement.get('Effect', '')
                            principal = statement.get('Principal', {})
                            
                            # Check if Principal is "*" (public access)
                            if effect == 'Allow' and principal == '*':
                                topics_with_public_access.append(topic_arn)
                                break
                            # Also check if Principal is {"AWS": "*"}
                            if effect == 'Allow' and isinstance(principal, dict):
                                if principal.get('AWS') == '*':
                                    topics_with_public_access.append(topic_arn)
                                    break
                    except json.JSONDecodeError:
                        # Treat unparseable policies as potentially public (conservative approach)
                        print(f'SNS policy parsing failed for {topic_arn}, treating as potentially public')
                        topics_with_public_access.append(topic_arn)
                    except Exception:
                        pass
                
                except ClientError as e:
                    print(f'SNS topic check skipped for {topic_arn}: {get_error_code(e)}')
                except Exception:
                    pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'SNS scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'SNS scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'SNS scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return SNSData(
        total_topics=total_topics,
        topics_without_encryption=topics_without_encryption,
        topics_with_public_access=topics_with_public_access
    )

# -- ECS COLLECTOR -------------------------------------------------
def collect_ecs(key, secret, token, region, warnings) -> ECSData:
    total_task_definitions = 0
    tasks_with_privileged_containers = []
    tasks_without_resource_limits = []
    task_role_arns = []

    try:
        ecs = boto3.client('ecs', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        # Get all task definitions using paginator
        paginator = ecs.get_paginator('list_task_definitions')
        for page in paginator.paginate():
            for task_def_arn in page.get('taskDefinitionArns', []):
                total_task_definitions += 1
                
                try:
                    # Get task definition details
                    task_def_response = ecs.describe_task_definition(taskDefinition=task_def_arn)
                    task_def = task_def_response.get('taskDefinition', {})
                    
                    # Check each container definition
                    for container in task_def.get('containerDefinitions', []):
                        # Check for privileged mode
                        if container.get('privileged', False):
                            if task_def_arn not in tasks_with_privileged_containers:
                                tasks_with_privileged_containers.append(task_def_arn)
                        
                        # Check for resource limits (CPU and memory)
                        cpu = container.get('cpu', 0)
                        memory = container.get('memory', 0)
                        
                        # If either CPU or memory is missing/zero, flag it
                        if cpu == 0 or memory == 0:
                            if task_def_arn not in tasks_without_resource_limits:
                                tasks_without_resource_limits.append(task_def_arn)
                    
                    # Collect task role ARN if present
                    task_role = task_def.get('taskRoleArn', '')
                    if task_role:
                        task_role_arns.append(task_role)
                
                except ClientError as e:
                    print(f'ECS task definition check skipped for {task_def_arn}: {get_error_code(e)}')
                except Exception:
                    pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'ECS scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'ECS scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'ECS scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return ECSData(
        total_task_definitions=total_task_definitions,
        tasks_with_privileged_containers=tasks_with_privileged_containers,
        tasks_without_resource_limits=tasks_without_resource_limits,
        task_role_arns=task_role_arns
    )

# -- WAF COLLECTOR -------------------------------------------------
def collect_waf(key, secret, token, region, warnings) -> WAFData:
    total_albs = 0
    albs_without_waf = []

    try:
        # Get all Application Load Balancers
        elb = boto3.client('elbv2', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)
        
        lbs = elb.describe_load_balancers()
        
        # Filter for Application Load Balancers only
        albs = [lb for lb in lbs['LoadBalancers'] if lb.get('Type') == 'application']
        total_albs = len(albs)
        
        # Check WAF association for each ALB
        wafv2 = boto3.client('wafv2', aws_access_key_id=key,
                            aws_secret_access_key=secret,
                            aws_session_token=token,
                            region_name=region, config=BOTO_CONFIG)
        
        for alb in albs:
            alb_arn = alb['LoadBalancerArn']
            
            try:
                # Check if ALB has a WAF Web ACL associated
                wafv2.get_web_acl_for_resource(
                    ResourceArn=alb_arn
                )
                # If no exception, WAF is associated
            except ClientError as e:
                code = get_error_code(e)
                # WAFNonexistentItemException means no WAF is associated
                if code == 'WAFNonexistentItemException':
                    albs_without_waf.append(alb_arn)
                elif code in ['AccessDenied', 'UnauthorizedOperation']:
                    # Permission error - skip this ALB
                    print(f'WAF check skipped for {alb_arn}: {code}')
                else:
                    print(f'WAF check skipped for {alb_arn}: {code}')
            except Exception:
                pass

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'WAF scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'WAF scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'WAF scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return WAFData(
        total_albs=total_albs,
        albs_without_waf=albs_without_waf
    )


# -- API GATEWAY COLLECTOR -----------------------------------------
def collect_api_gateway(key, secret, token, region, warnings) -> APIGatewayData:
    total_apis = 0
    apis_without_auth = []
    apis_without_throttling = []
    apis_without_waf = []
    apis = []

    try:
        # -- HTTP & WebSocket APIs (API Gateway V2) ----------------
        apigwv2 = boto3.client('apigatewayv2', aws_access_key_id=key,
                               aws_secret_access_key=secret,
                               aws_session_token=token,
                               region_name=region, config=BOTO_CONFIG)

        try:
            v2_apis = apigwv2.get_apis().get('Items', [])
            for api in v2_apis:
                api_id = api['ApiId']
                api_name = api.get('Name', api_id)
                api_type = api.get('ProtocolType', 'HTTP')  # HTTP or WEBSOCKET
                total_apis += 1

                # Determine auth type from default route settings
                auth_type = 'NONE'
                if api.get('ApiKeySelectionExpression'):
                    auth_type = 'API_KEY'

                # Check stages for throttling and auth
                stage_names = []
                has_throttling = False
                try:
                    stages = apigwv2.get_stages(ApiId=api_id).get('Items', [])
                    for stage in stages:
                        stage_names.append(stage.get('StageName', ''))
                        throttle = stage.get('DefaultRouteSettings', {}).get('ThrottlingRateLimit')
                        if throttle and throttle > 0:
                            has_throttling = True
                        # Check stage-level auth
                        route_settings = stage.get('RouteSettings', {})
                        for rs in route_settings.values():
                            if rs.get('AuthorizationType') and rs['AuthorizationType'] != 'NONE':
                                auth_type = rs['AuthorizationType']
                except Exception:
                    pass

                # Check authorizers
                try:
                    authorizers = apigwv2.get_authorizers(ApiId=api_id).get('Items', [])
                    if authorizers:
                        auth_type = authorizers[0].get('AuthorizerType', 'JWT')
                except Exception:
                    pass

                endpoint_type = 'REGIONAL'  # V2 APIs are always regional

                if auth_type == 'NONE':
                    apis_without_auth.append(api_id)
                if not has_throttling:
                    apis_without_throttling.append(api_id)

                apis.append(APIGatewayInstance(
                    id=api_id,
                    name=api_name,
                    api_type=api_type,
                    endpoint_type=endpoint_type,
                    auth_type=auth_type,
                    has_waf=False,  # V2 APIs don't have direct WAF association via this API
                    stage_names=stage_names,
                ))
        except ClientError as e:
            code = get_error_code(e)
            if code not in ['AccessDenied', 'UnauthorizedOperation']:
                print(f'API Gateway V2 scan partial failure: {code}')

        # -- REST APIs (API Gateway V1) ----------------------------
        apigw = boto3.client('apigateway', aws_access_key_id=key,
                             aws_secret_access_key=secret,
                             aws_session_token=token,
                             region_name=region, config=BOTO_CONFIG)

        try:
            rest_apis = apigw.get_rest_apis().get('items', [])
            for api in rest_apis:
                api_id = api['id']
                api_name = api.get('name', api_id)
                total_apis += 1

                # Endpoint type
                endpoint_config = api.get('endpointConfiguration', {})
                endpoint_types = endpoint_config.get('types', ['REGIONAL'])
                endpoint_type = endpoint_types[0] if endpoint_types else 'REGIONAL'

                # Check stages for throttling
                stage_names = []
                has_throttling = False
                try:
                    stages = apigw.get_stages(restApiId=api_id).get('item', [])
                    for stage in stages:
                        stage_names.append(stage.get('stageName', ''))
                        method_settings = stage.get('methodSettings', {})
                        for settings in method_settings.values():
                            if settings.get('throttlingRateLimit', 0) > 0:
                                has_throttling = True
                except Exception:
                    pass

                # Determine auth - check if any authorizers exist
                auth_type = 'NONE'
                try:
                    authorizers = apigw.get_authorizers(restApiId=api_id).get('items', [])
                    if authorizers:
                        auth_type = authorizers[0].get('type', 'COGNITO_USER_POOLS')
                        if auth_type == 'COGNITO_USER_POOLS':
                            auth_type = 'COGNITO'
                        elif auth_type == 'TOKEN' or auth_type == 'REQUEST':
                            auth_type = 'JWT'
                except Exception:
                    pass

                # Check API key requirement as fallback auth
                if auth_type == 'NONE' and api.get('apiKeySource') == 'HEADER':
                    auth_type = 'API_KEY'

                if auth_type == 'NONE':
                    apis_without_auth.append(api_id)
                if not has_throttling:
                    apis_without_throttling.append(api_id)

                # WAF check for REST APIs
                has_waf = False
                try:
                    wafv2 = boto3.client('wafv2', aws_access_key_id=key,
                                        aws_secret_access_key=secret,
                                        aws_session_token=token,
                                        region_name=region, config=BOTO_CONFIG)
                    # REST API stage ARN format for WAF
                    for stage_name in stage_names:
                        stage_arn = f'arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}'
                        try:
                            wafv2.get_web_acl_for_resource(ResourceArn=stage_arn)
                            has_waf = True
                            break
                        except ClientError:
                            pass
                except Exception:
                    pass

                if not has_waf:
                    apis_without_waf.append(api_id)

                apis.append(APIGatewayInstance(
                    id=api_id,
                    name=api_name,
                    api_type='REST',
                    endpoint_type=endpoint_type,
                    auth_type=auth_type,
                    has_waf=has_waf,
                    stage_names=stage_names,
                ))
        except ClientError as e:
            code = get_error_code(e)
            if code not in ['AccessDenied', 'UnauthorizedOperation']:
                print(f'API Gateway REST scan partial failure: {code}')

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'API Gateway scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'API Gateway scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'API Gateway scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return APIGatewayData(
        total_apis=total_apis,
        apis_without_auth=apis_without_auth,
        apis_without_throttling=apis_without_throttling,
        apis_without_waf=apis_without_waf,
        apis=apis,
    )


# -- ELASTICACHE COLLECTOR -----------------------------------------
def collect_elasticache(key, secret, token, region, warnings) -> ElastiCacheData:
    total_clusters = 0
    clusters_without_encryption = []
    clusters_without_auth = []
    clusters_without_transit_encryption = []
    clusters = []

    try:
        ec = boto3.client('elasticache', aws_access_key_id=key,
                          aws_secret_access_key=secret,
                          aws_session_token=token,
                          region_name=region, config=BOTO_CONFIG)

        # Get replication groups first (Redis clusters with replication)
        repl_groups = {}
        try:
            rg_resp = ec.describe_replication_groups()
            for rg in rg_resp.get('ReplicationGroups', []):
                rg_id = rg['ReplicationGroupId']
                repl_groups[rg_id] = {
                    'at_rest': rg.get('AtRestEncryptionEnabled', False),
                    'in_transit': rg.get('TransitEncryptionEnabled', False),
                    'auth': rg.get('AuthTokenEnabled', False),
                }
        except ClientError as e:
            code = get_error_code(e)
            if code not in ['AccessDenied', 'UnauthorizedOperation']:
                print(f'ElastiCache replication groups check skipped: {code}')
        except Exception:
            pass

        # Get all cache clusters
        resp = ec.describe_cache_clusters(ShowCacheNodeInfo=True)
        for cluster in resp.get('CacheClusters', []):
            cluster_id = cluster['CacheClusterId']
            engine = cluster.get('Engine', 'redis')
            node_type = cluster.get('CacheNodeType', '')
            total_clusters += 1

            # Encryption info - check replication group if available
            rg_id = cluster.get('ReplicationGroupId')
            if rg_id and rg_id in repl_groups:
                encryption_at_rest = repl_groups[rg_id]['at_rest']
                encryption_in_transit = repl_groups[rg_id]['in_transit']
                auth_enabled = repl_groups[rg_id]['auth']
            else:
                encryption_at_rest = cluster.get('AtRestEncryptionEnabled', False)
                encryption_in_transit = cluster.get('TransitEncryptionEnabled', False)
                auth_enabled = cluster.get('AuthTokenEnabled', False)

            # Network info
            sg_ids = [sg['SecurityGroupId'] for sg in cluster.get('SecurityGroups', [])]
            subnet_group = cluster.get('CacheSubnetGroupName')

            # Determine VPC from cache subnet group
            vpc_id = None
            if subnet_group:
                try:
                    sg_resp = ec.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group)
                    groups = sg_resp.get('CacheSubnetGroups', [])
                    if groups:
                        vpc_id = groups[0].get('VpcId')
                except Exception:
                    pass

            if not encryption_at_rest:
                clusters_without_encryption.append(cluster_id)
            if not auth_enabled:
                clusters_without_auth.append(cluster_id)
            if not encryption_in_transit:
                clusters_without_transit_encryption.append(cluster_id)

            clusters.append(ElastiCacheCluster(
                id=cluster_id,
                engine=engine,
                node_type=node_type,
                encryption_at_rest=encryption_at_rest,
                encryption_in_transit=encryption_in_transit,
                auth_enabled=auth_enabled,
                vpc_id=vpc_id,
                subnet_group=subnet_group,
                sg_ids=sg_ids,
            ))

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'ElastiCache scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'ElastiCache scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'ElastiCache scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return ElastiCacheData(
        total_clusters=total_clusters,
        clusters_without_encryption=clusters_without_encryption,
        clusters_without_auth=clusters_without_auth,
        clusters_without_transit_encryption=clusters_without_transit_encryption,
        clusters=clusters,
    )


# -- SQS COLLECTOR ------------------------------------------------
def collect_sqs(key, secret, token, region, warnings) -> SQSData:
    total_queues = 0
    queues_without_encryption = []
    queues_without_dlq = []
    queues_with_public_access = []
    queues = []

    try:
        sqs = boto3.client('sqs', aws_access_key_id=key,
                           aws_secret_access_key=secret,
                           aws_session_token=token,
                           region_name=region, config=BOTO_CONFIG)

        # List all queues
        queue_urls = []
        try:
            resp = sqs.list_queues()
            queue_urls = resp.get('QueueUrls', [])
        except ClientError as e:
            code = get_error_code(e)
            if code in ['AccessDenied', 'UnauthorizedOperation']:
                msg = 'SQS scan skipped: insufficient permissions'
                print(msg)
                warnings.append(msg)
                return SQSData()
            raise

        total_queues = len(queue_urls)

        # Get attributes for each queue
        for url in queue_urls:
            try:
                attrs_resp = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=['All']
                )
                attrs = attrs_resp.get('Attributes', {})

                queue_arn = attrs.get('QueueArn', '')
                queue_name = url.split('/')[-1]

                # Encryption check - KmsMasterKeyId present means SSE-KMS
                encrypted = bool(attrs.get('KmsMasterKeyId') or attrs.get('SqsManagedSseEnabled') == 'true')

                # DLQ check - RedrivePolicy present means DLQ is configured
                has_dlq = bool(attrs.get('RedrivePolicy'))

                # Public access check - parse policy for Principal: "*"
                is_public = False
                policy_str = attrs.get('Policy', '')
                if policy_str:
                    try:
                        policy = json.loads(policy_str)
                        for statement in policy.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                principal = statement.get('Principal', {})
                                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                    # Check if there's a condition limiting access
                                    if not statement.get('Condition'):
                                        is_public = True
                    except (json.JSONDecodeError, TypeError):
                        pass

                if not encrypted:
                    queues_without_encryption.append(queue_name)
                if not has_dlq:
                    queues_without_dlq.append(queue_name)
                if is_public:
                    queues_with_public_access.append(queue_name)

                queues.append(SQSQueue(
                    url=url,
                    arn=queue_arn,
                    name=queue_name,
                    encrypted=encrypted,
                    has_dlq=has_dlq,
                    is_public=is_public,
                ))

            except ClientError as e:
                code = get_error_code(e)
                print(f'SQS attributes check skipped for {url}: {code}')
            except Exception as e:
                print(f'SQS attributes check skipped for {url}: {e}')

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'SQS scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'SQS scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'SQS scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return SQSData(
        total_queues=total_queues,
        queues_without_encryption=queues_without_encryption,
        queues_without_dlq=queues_without_dlq,
        queues_with_public_access=queues_with_public_access,
        queues=queues,
    )


# -- DYNAMODB COLLECTOR --------------------------------------------
def collect_dynamodb(key, secret, token, region, warnings) -> DynamoDBData:
    total_tables = 0
    tables_without_pitr = []
    tables_without_encryption = []
    tables_without_backup = []
    tables = []

    try:
        ddb = boto3.client('dynamodb', aws_access_key_id=key,
                           aws_secret_access_key=secret,
                           aws_session_token=token,
                           region_name=region, config=BOTO_CONFIG)

        # List all tables
        table_names = []
        try:
            paginator = ddb.get_paginator('list_tables')
            for page in paginator.paginate():
                table_names.extend(page.get('TableNames', []))
        except ClientError as e:
            code = get_error_code(e)
            if code in ['AccessDenied', 'UnauthorizedOperation']:
                msg = 'DynamoDB scan skipped: insufficient permissions'
                print(msg)
                warnings.append(msg)
                return DynamoDBData()
            raise

        total_tables = len(table_names)

        # Describe each table
        for table_name in table_names:
            try:
                desc = ddb.describe_table(TableName=table_name)
                table = desc.get('Table', {})

                table_arn = table.get('TableArn', '')
                item_count = table.get('ItemCount', 0)
                billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')

                # Encryption - check SSEDescription
                sse = table.get('SSEDescription', {})
                sse_status = sse.get('Status', '')
                if sse_status == 'ENABLED':
                    encryption_type = sse.get('SSEType', 'KMS')
                else:
                    encryption_type = 'DEFAULT'  # AWS-owned key (default)

                # PITR check
                pitr_enabled = False
                try:
                    pitr_resp = ddb.describe_continuous_backups(TableName=table_name)
                    pitr_desc = pitr_resp.get('ContinuousBackupsDescription', {})
                    pitr_status = pitr_desc.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', '')
                    pitr_enabled = pitr_status == 'ENABLED'
                except ClientError as e:
                    code = get_error_code(e)
                    if code not in ['AccessDenied', 'UnauthorizedOperation']:
                        print(f'DynamoDB PITR check skipped for {table_name}: {code}')
                except Exception:
                    pass

                # Backup check - see if any on-demand backups exist
                has_backup = False
                try:
                    backups = ddb.list_backups(TableName=table_name, Limit=1)
                    has_backup = len(backups.get('BackupSummaries', [])) > 0
                except ClientError as e:
                    code = get_error_code(e)
                    if code not in ['AccessDenied', 'UnauthorizedOperation']:
                        print(f'DynamoDB backup check skipped for {table_name}: {code}')
                except Exception:
                    pass

                if not pitr_enabled:
                    tables_without_pitr.append(table_name)
                if encryption_type == 'DEFAULT':
                    tables_without_encryption.append(table_name)
                if not has_backup:
                    tables_without_backup.append(table_name)

                tables.append(DynamoDBTable(
                    name=table_name,
                    arn=table_arn,
                    encryption_type=encryption_type,
                    pitr_enabled=pitr_enabled,
                    has_backup=has_backup,
                    billing_mode=billing_mode,
                    item_count=item_count,
                ))

            except ClientError as e:
                code = get_error_code(e)
                print(f'DynamoDB describe skipped for {table_name}: {code}')
            except Exception as e:
                print(f'DynamoDB describe skipped for {table_name}: {e}')

    except ClientError as e:
        code = get_error_code(e)
        if code in ['AccessDenied', 'UnauthorizedOperation']:
            msg = 'DynamoDB scan skipped: insufficient permissions'
            print(msg)
            warnings.append(msg)
        else:
            msg = f'DynamoDB scan skipped: {code}'
            print(msg)
            warnings.append(msg)
    except Exception as e:
        msg = f'DynamoDB scan skipped: unexpected error — {str(e)}'
        print(msg)
        warnings.append(msg)

    return DynamoDBData(
        total_tables=total_tables,
        tables_without_pitr=tables_without_pitr,
        tables_without_encryption=tables_without_encryption,
        tables_without_backup=tables_without_backup,
        tables=tables,
    )
