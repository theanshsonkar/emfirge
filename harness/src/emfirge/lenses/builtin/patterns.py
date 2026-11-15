"""AWS's words for the built-in lenses. The only module of emfirge.lenses that knows anything of one cloud, and all of
it is data: no service is named in any code path.

Most lines are AWS-wide (the IAM policy language, address ranges, words in setting names). A line that only one
service uses is listed in SERVICE_SPECIFIC with the service and the test that needs it; that count is the cost of
service knowledge in the lenses and must stay near zero.
"""
from __future__ import annotations

import re

from .vocabulary import DataWords, MoneyWords, PolicyWords, Protection, PublicValue, PublicWords


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_ON = frozenset({'true', 'enabled', 'enable', 'on', 'yes', '1'})
_OFF = frozenset({'false', 'disabled', 'disable', 'off', 'no', '0', 'suspended'})
_END = r'(?:^|[.>])'   # start of the last part of a path

# The variable every AWS SDK and CLI reads to talk to another endpoint: how an outside tool is pointed at a side.
ENDPOINT_VAR = 'AWS_ENDPOINT_URL'

# The IAM policy language (IAM, S3, SQS, SNS, KMS, Lambda, ECR, OpenSearch, Secrets Manager ... all use it).
POLICY = PolicyWords(
    effect_key='Effect', allow='Allow', deny='Deny',
    action='Action', not_action='NotAction', resource='Resource', not_resource='NotResource',
    principal='Principal', not_principal='NotPrincipal', condition='Condition',
    everyone=frozenset({'*', 'AWS:*'}),
    principal_classes=(
        ('everyone', _re(r'^(\*|AWS:\*)$')),
        ('service', _re(r'^Service:')),
        ('federated', _re(r'^Federated:')),
        ('account', _re(r'^(AWS|CanonicalUser):')),
    ),
    trust_actions=('sts:AssumeRole*', 'sts:TagSession', 'sts:SetSourceIdentity'),
    # From the S3 documentation "The meaning of public": condition keys that narrow a public principal.
    limiting_keys=frozenset({
        'aws:sourceip', 'aws:sourcearn', 'aws:sourcevpc', 'aws:sourcevpce', 'aws:sourceowner', 'aws:sourceaccount',
        'aws:userid', 'aws:principalorgid', 'aws:principalaccount', 'aws:principalarn',
        's3:dataaccesspointarn', 's3:dataaccesspointaccount',
    }),
    limiting_operators=frozenset({'stringequals', 'stringequalsignorecase', 'stringlike', 'arnequals', 'arnlike', 'ipaddress'}),
    any_value_prefix='foranyvalue:',
    ignored_operator_prefixes=('forallvalues:',),
    attached_keys=_re(_END + r'(PolicyArn|ManagedPolicyArns?)$'),
    status_words=_re(r'polic|permission|grant|acl|trust'),
)

PUBLIC = PublicWords(
    everyone_ranges=frozenset({'0.0.0.0/0', '::/0'}),
    context_keys=_re(r'port|protocol'),
    outbound=_re(r'egress|outbound'),
    deny_values=frozenset({'deny'}),
    open_flags=_re(_END + r'\w*public\w*$'),
    block_flags=_re(_END + r'(block|restrict|ignore)public\w*$'),
    values=(
        PublicValue(_re(r'^URI$'), _re(r'/global/(AllUsers|AuthenticatedUsers)$'), 'S3 ACL grant to all users'),
        PublicValue(_re(r'^Group$'), _re(r'^all$'), 'EC2 snapshot or image shared with everyone'),
        PublicValue(_re(r'^AttributeValues$'), _re(r'^all$'), 'RDS snapshot shared with everyone'),
        PublicValue(_re(r'^AuthType$'), _re(r'^NONE$'), 'Lambda function URL with no authentication'),
    ),
    on=_ON, off=_OFF,
    status_words=_re(r'public|polic|acl'),
)

DATA = DataWords(
    protections=(
        Protection('deletion protection', _re(_END + r'\w*(deletion|termination)protection\w*$'), 'switch'),
        Protection('point-in-time recovery', _re(_END + r'pointintimerecovery\w*$'), 'switch'),
        Protection('versioning', _re(r'versioning\w*(\.status)?$'), 'switch'),
        Protection('MFA delete', _re(_END + r'mfadelete$'), 'switch'),
        Protection('encryption', _re(_END + r'\w*encrypted$'), 'switch'),
        Protection('safety switch', _re(_END + r'\w*(dry_?run|read_?only)\w*$'), 'switch'),
        Protection('encryption', _re(_END + r'(\w*serversideencryption\w*|ssespecification|\w*encryptionconfiguration|kmskeyid)$'), 'present'),
        Protection('retention', _re(_END + r'retentionindays$'), 'retention', unset_is_forever=True),
        Protection('retention', _re(_END + r'\w*retention\w*$'), 'retention'),
        Protection('expiry', _re(r'expiration\w*(\.\w*days)?$'), 'expiry'),
    ),
    emptying_operations=_re(r'^(purge|truncate|empty|flush|wipe)|^(batch)?delete\w*(object|item|message|record|row|version|snapshot|backup|recoverypoint)s?$'),
    on=_ON, off=_OFF,
    status_words=_re(r'versioning|backup|recovery|retention|lifecycle|encryption|protection'),
)

MONEY = MoneyWords(
    class_keys=_re(_END + r'\w*(instancetype|instanceclass|nodetype)$'),
    ladder=('nano', 'micro', 'small', 'medium', 'large', 'xlarge'),
    numbered_size=_re(r'^(\d+)xlarge$'),
    growth_keys=_re(_END + r'(\w*capacity\w*|\w*count|\w*size|\w*storage\w*|provisioned\w*|\w*memory\w*|replicas|'
                    r'desired\w*|\w*iops|\w*throughput\w*|\w*shards?|\w*nodes?)$'),
    growth_ignore=_re(r'batch|page|retry|retries|error|fail|message|timeout|ephemeral|window|length'),
    plan_keys=_re(_END + r'\w*(billingmode|pricing\w*|tier)$'),
    running_keys=_re(_END + r'(state|status|enabled)(\.name)?$'),
    commitment_operations=_re(r'^(purchase|buy|increase|request\w*increase)'),
    on=frozenset({'enabled', 'running', 'true', 'on', 'active', 'started'}),
    off=frozenset({'disabled', 'stopped', 'false', 'off', 'paused', 'inactive'}),
)

# The lines above that only one service uses. (service, which pattern, the test that shows it is needed)
SERVICE_SPECIFIC: tuple[tuple[str, str, str], ...] = (
    ('S3', "PUBLIC.values: grantee URI ending /AllUsers or /AuthenticatedUsers", 's3-acl-all-users'),
    ('EC2', "PUBLIC.values: Group 'all' (snapshot / image shared with everyone)", 'ebs-snapshot-public'),
    ('RDS', "PUBLIC.values: AttributeValues 'all' (snapshot restore shared with everyone)", 'rds-snapshot-public'),
    ('Lambda', "PUBLIC.values: AuthType 'NONE' (function URL)", 'lambda-url-no-auth'),
    ('DynamoDB', "DATA: point-in-time recovery switch name", 'dynamodb-pitr-off'),
    ('S3', "DATA: versioning status (and MFA delete) names", 's3-versioning-suspended'),
    ('CloudWatch Logs', "DATA: RetentionInDays unset means kept forever", 'logs-retention-set'),
    ('IAM / STS', "POLICY.trust_actions: sts:AssumeRole* (who may take on a role)", 'iam-trust-other-account'),
)
