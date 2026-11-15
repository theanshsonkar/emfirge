"""Real field names and values from many AWS services, through the four built-in lenses, with no code per service.

Each row: a change at state level, as the branch gives it (path, before, after), and the exact finding codes. The
non-hits matter as much as the hits: an unchanged open rule, a narrowing, a step down, a harmless setting.
"""
from __future__ import annotations

import pytest

from emfirge.lenses.builtin import patterns

from lens_helpers import OTHER, OWN, allow, codes, modified, policy, url_encoded

BUCKET = 'arn:aws:s3:::demo-bucket'
PAB_ON = {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}
PAB_OFF = {k: False for k in PAB_ON}
WEB_443 = {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'web'}]}
SSH_ALL = {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
SSH_OFFICE = {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '10.0.0.0/8'}]}
LAMBDA_TRUST = policy(allow('sts:AssumeRole', principal={'Service': 'lambda.amazonaws.com'}, resource=None))
OTHER_TRUST = policy(allow('sts:AssumeRole', principal={'Service': 'lambda.amazonaws.com'}, resource=None),
                     allow('sts:AssumeRole', principal={'AWS': f'arn:aws:iam::{OTHER}:root'}, resource=None))
EVERYONE = {'AWS': '*'}
SSE = {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': 'alias/demo'}}]}

HITS = [
    # S3
    ('s3-bucket-policy-public', 's3:bucket', [('Policy', None, policy(allow('s3:GetObject', f'{BUCKET}/*', '*')))],
     {'public.policy_allows_everyone', 'permissions.allow_widened', 'permissions.principal_added'}),
    ('s3-public-access-block-off', 's3:bucket', [('PublicAccessBlockConfiguration', PAB_ON, PAB_OFF)], {'public.block_off'}),
    ('s3-public-access-block-deleted', 's3:bucket', [('PublicAccessBlockConfiguration', PAB_ON, None)], {'public.block_off'}),
    ('s3-acl-all-users', 's3:bucket', [('Grants', [], [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}])],
     {'public.grant_to_everyone'}),
    ('s3-versioning-suspended', 's3:bucket', [('GetBucketVersioning.Status', 'Enabled', 'Suspended')], {'data.protection_off'}),
    ('s3-mfa-delete-off', 's3:bucket', [('MFADelete', 'Enabled', 'Disabled')], {'data.protection_off'}),
    ('s3-encryption-removed', 's3:bucket', [('ServerSideEncryptionConfiguration', SSE, None)], {'data.protection_off'}),
    ('s3-lifecycle-expiry-added', 's3:bucket', [('Rules', [], [{'ID': 'tidy', 'Status': 'Enabled', 'Expiration': {'Days': 30}}])],
     {'data.expiry_added'}),
    # EC2 security groups
    ('sg-open-22-to-world', 'ec2:security-group', [('IpPermissions', [WEB_443], [WEB_443, SSH_ALL])], {'public.address_open'}),
    ('sg-open-3389-ipv6', 'ec2:security-group',
     [('IpPermissions', [], [{'IpProtocol': 'tcp', 'FromPort': 3389, 'ToPort': 3389, 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}])],
     {'public.address_open'}),
    ('sg-world-rule-moved-to-ssh', 'ec2:security-group', [('IpPermissions', [WEB_443], [{**WEB_443, 'FromPort': 22, 'ToPort': 22}])],
     {'public.address_open'}),
    # IAM
    ('iam-trust-other-account', 'iam:role', [('AssumeRolePolicyDocument', url_encoded(LAMBDA_TRUST), url_encoded(OTHER_TRUST))],
     {'permissions.trust_widened', 'permissions.principal_added'}),
    ('iam-inline-admin', 'iam:role', [('PolicyDocument', policy(allow(['dynamodb:GetItem'], 'arn:aws:dynamodb:us-east-1:000000000000:table/demo')),
                                       policy(allow('*', '*')))],
     {'permissions.allow_widened'}),
    ('iam-managed-admin-attached', 'iam:role', [('AttachedPolicies', [], [{'PolicyName': 'AdministratorAccess', 'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}])],
     {'permissions.policy_attached'}),
    ('iam-deny-removed', 'iam:role', [('PolicyDocument', policy(allow('s3:*'), allow('s3:DeleteBucket', effect='Deny')), policy(allow('s3:*')))],
     {'permissions.deny_removed'}),
    # Lambda
    ('lambda-resource-policy-public', 'lambda:function',
     [('Policy', None, policy(allow('lambda:InvokeFunction', 'arn:aws:lambda:us-east-1:000000000000:function:demo', '*')))],
     {'public.policy_allows_everyone', 'permissions.allow_added', 'permissions.principal_added'}),
    ('lambda-url-no-auth', 'lambda:function', [('FunctionUrlConfig', None, {'AuthType': 'NONE', 'FunctionUrl': 'https://demo.lambda-url.example/'})],
     {'public.grant_to_everyone'}),
    ('lambda-memory-up', 'lambda:function', [('Configuration.MemorySize', 256, 1024)], {'money.size_up'}),
    # RDS
    ('rds-publicly-accessible', 'rds:db', [('PubliclyAccessible', False, True)], {'public.flag_on'}),
    ('rds-deletion-protection-off', 'rds:db', [('DeletionProtection', True, False)], {'data.protection_off'}),
    ('rds-backup-retention-off', 'rds:db', [('BackupRetentionPeriod', 7, 0)], {'data.retention_shortened'}),
    ('rds-class-up', 'rds:db', [('DBInstanceClass', 'db.t3.micro', 'db.r6g.4xlarge')], {'money.class_changed'}),
    ('rds-snapshot-public', 'rds:snapshot', [('DBSnapshotAttributes', [{'AttributeName': 'restore', 'AttributeValues': []}],
                                             [{'AttributeName': 'restore', 'AttributeValues': ['all']}])], {'public.grant_to_everyone'}),
    # DynamoDB
    ('dynamodb-pitr-off', 'dynamodb:table', [('ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus', 'ENABLED', 'DISABLED')],
     {'data.protection_off'}),
    ('dynamodb-billing-provisioned', 'dynamodb:table', [('Table.BillingModeSummary.BillingMode', 'PAY_PER_REQUEST', 'PROVISIONED'),
                                                        ('Table.ProvisionedThroughput.ReadCapacityUnits', 0, 500)],
     {'money.plan_changed', 'money.size_up'}),
    ('dynamodb-deletion-protection-off', 'dynamodb:table', [('Table.DeletionProtectionEnabled', True, False)], {'data.protection_off'}),
    # SQS / SNS
    ('sqs-policy-public', 'sqs:queue', [('Attributes.Policy', None, policy(allow('sqs:SendMessage', 'arn:aws:sqs:us-east-1:000000000000:demo', EVERYONE)))],
     {'public.policy_allows_everyone', 'permissions.allow_added', 'permissions.principal_added'}),
    ('sqs-retention-shortened', 'sqs:queue', [('Attributes.MessageRetentionPeriod', '1209600', '60')], {'data.retention_shortened'}),
    ('sns-condition-removed', 'sns:topic',
     [('Attributes.Policy', policy(allow('sns:Publish', 'arn:aws:sns:us-east-1:000000000000:demo', '*', {'StringEquals': {'aws:SourceAccount': OWN}})),
       policy(allow('sns:Publish', 'arn:aws:sns:us-east-1:000000000000:demo', '*')))],
     {'public.policy_allows_everyone', 'permissions.condition_removed'}),
    # KMS
    ('kms-key-policy-opened', 'kms:key', [('Policy', policy(allow('kms:*', '*', {'AWS': f'arn:aws:iam::{OWN}:root'})),
                                          policy(allow('kms:*', '*', {'AWS': f'arn:aws:iam::{OWN}:root'}), allow('kms:Decrypt', '*', EVERYONE)))],
     {'public.policy_allows_everyone', 'permissions.allow_widened', 'permissions.principal_added'}),
    # EBS snapshot
    ('ebs-snapshot-public', 'ec2:snapshot', [('CreateVolumePermissions', [], [{'Group': 'all'}])], {'public.grant_to_everyone'}),
    # ECR
    ('ecr-policy-other-account', 'ecr:repository',
     [('policyText', None, policy(allow(['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'], principal={'AWS': f'arn:aws:iam::{OTHER}:root'}, resource=None)))],
     {'permissions.allow_added', 'permissions.principal_added'}),
    # OpenSearch
    ('opensearch-access-policy-public', 'es:domain', [('DomainConfig.AccessPolicies.Options', '', policy(allow('es:*', 'arn:aws:es:us-east-1:000000000000:domain/demo/*', EVERYONE)))],
     {'public.policy_allows_everyone', 'permissions.allow_widened', 'permissions.principal_added'}),
    # EKS
    ('eks-endpoint-public', 'eks:cluster', [('cluster.resourcesVpcConfig', {'endpointPublicAccess': False, 'publicAccessCidrs': []},
                                             {'endpointPublicAccess': True, 'publicAccessCidrs': ['0.0.0.0/0']})],
     {'public.flag_on', 'public.address_open'}),
    # Secrets Manager
    ('secret-policy-other-account', 'secretsmanager:secret',
     [('ResourcePolicy', None, policy(allow('secretsmanager:GetSecretValue', '*', {'AWS': f'arn:aws:iam::{OTHER}:role/reader'})))],
     {'permissions.allow_widened', 'permissions.principal_added'}),
    # CloudWatch Logs
    ('logs-retention-set', 'logs:log-group', [('retentionInDays', None, 1)], {'data.retention_shortened'}),
    # EC2 instance, Auto Scaling, EventBridge
    ('ec2-instance-type-up', 'ec2:instance', [('InstanceType', 't3.micro', 'm5.2xlarge')], {'money.class_changed'}),
    ('asg-capacity-up', 'autoscaling:group', [('DesiredCapacity', 2, 10), ('MaxSize', 4, 10)], {'money.size_up'}),
    ('events-rule-enabled', 'events:rule', [('State', 'DISABLED', 'ENABLED')], {'money.switched_on'}),
]

NON_HITS = [
    ('s3-policy-narrowed', 's3:bucket', [('Policy', policy(allow('s3:GetObject', '*', '*')), policy(allow('s3:GetObject', f'{BUCKET}/public/*', '*')))],
     {'permissions.allow_removed'}),   # narrower: no public news; who lost what is a fact of its own
    ('s3-policy-gets-source-ip-condition', 's3:bucket',
     [('Policy', policy(allow('s3:GetObject', f'{BUCKET}/*', '*')), policy(allow('s3:GetObject', f'{BUCKET}/*', '*', {'IpAddress': {'aws:SourceIp': '203.0.113.0/24'}})))],
     {'permissions.allow_removed'}),
    ('s3-public-access-block-on', 's3:bucket', [('PublicAccessBlockConfiguration', PAB_OFF, PAB_ON)], set()),
    ('s3-versioning-enabled', 's3:bucket', [('GetBucketVersioning.Status', 'Suspended', 'Enabled')], set()),
    ('s3-versioning-bare-status', 's3:bucket', [('Status', 'Enabled', 'Suspended')], set()),   # known limit: needs the read's name in the path
    ('s3-encryption-key-swapped', 's3:bucket', [('ServerSideEncryptionConfiguration.Rules', SSE['Rules'],
                                                 [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': 'alias/other'}}])], set()),
    ('sg-description-changed', 'ec2:security-group', [('IpPermissions', [WEB_443], [{**WEB_443, 'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'https'}]}])], set()),
    ('sg-rules-reordered', 'ec2:security-group', [('IpPermissions', [WEB_443, SSH_OFFICE], [SSH_OFFICE, WEB_443])], set()),
    ('sg-ssh-narrowed', 'ec2:security-group', [('IpPermissions', [WEB_443, SSH_ALL], [WEB_443, SSH_OFFICE])], set()),
    ('sg-egress-to-world', 'ec2:security-group', [('IpPermissionsEgress', [], [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])], set()),
    ('nacl-deny-world', 'ec2:network-acl', [('Entries', [], [{'RuleNumber': 90, 'Protocol': '6', 'RuleAction': 'deny', 'Egress': False,
                                                            'CidrBlock': '0.0.0.0/0', 'PortRange': {'From': 22, 'To': 22}}])], set()),
    ('iam-trust-narrowed', 'iam:role', [('AssumeRolePolicyDocument', url_encoded(OTHER_TRUST), url_encoded(LAMBDA_TRUST))], {'permissions.allow_removed'}),
    ('iam-same-policy-reformatted', 'iam:role', [('PolicyDocument', policy(allow(['s3:GetObject', 's3:PutObject'], f'{BUCKET}/*')),
                                                   policy(allow(['s3:PutObject', 's3:GetObject'], [f'{BUCKET}/*'])))], set()),
    ('kms-description-changed', 'kms:key', [('Description', 'old', 'new')], set()),
    ('lambda-memory-down', 'lambda:function', [('Configuration.MemorySize', 1024, 256)], set()),
    ('lambda-timeout-up', 'lambda:function', [('Configuration.Timeout', 3, 30)], set()),
    ('lambda-url-iam-auth', 'lambda:function', [('FunctionUrlConfig.AuthType', 'NONE', 'AWS_IAM')], set()),
    ('rds-retention-longer', 'rds:db', [('BackupRetentionPeriod', 7, 14)], set()),
    ('rds-made-private', 'rds:db', [('PubliclyAccessible', True, False)], set()),
    ('dynamodb-pitr-on', 'dynamodb:table', [('ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus', 'DISABLED', 'ENABLED')], set()),
    ('ec2-type-down', 'ec2:instance', [('InstanceType', 'm5.2xlarge', 'm5.large')], set()),
    ('tag-changed', 'ec2:instance', [('Tags', [{'Key': 'team', 'Value': 'a'}], [{'Key': 'team', 'Value': 'b'}])], set()),
    ('eks-public-already', 'eks:cluster', [('cluster.resourcesVpcConfig', {'endpointPublicAccess': True, 'publicAccessCidrs': ['0.0.0.0/0'], 'subnetIds': ['subnet-1']},
                                            {'endpointPublicAccess': True, 'publicAccessCidrs': ['0.0.0.0/0'], 'subnetIds': ['subnet-1', 'subnet-2']})], set()),
    ('cloudfront-cache-policy-swapped', 'cloudfront:distribution', [('DistributionConfig.DefaultCacheBehavior.CachePolicyId', 'policy-a', 'policy-b')], set()),
    ('logs-retention-removed', 'logs:log-group', [('retentionInDays', 7, None)], set()),
]


@pytest.mark.parametrize('case,type_,fields,expected', HITS, ids=[c[0] for c in HITS])
def test_hits(case, type_, fields, expected):
    assert codes([modified(type_, case, *fields)]) == expected


@pytest.mark.parametrize('case,type_,fields,expected', NON_HITS, ids=[c[0] for c in NON_HITS])
def test_non_hits(case, type_, fields, expected):
    assert codes([modified(type_, case, *fields)]) == expected


def test_at_least_ten_services_are_covered():
    services = {t.split(':')[0] for _, t, _, _ in HITS}
    assert len(services) >= 10, services


def test_every_service_specific_pattern_is_needed_by_a_hit():
    """Each per-service line in patterns.py names a row above that would fail without it."""
    names = {c[0] for c in HITS}
    assert {test for _, _, test in patterns.SERVICE_SPECIFIC} <= names
    assert len(patterns.SERVICE_SPECIFIC) == 8
