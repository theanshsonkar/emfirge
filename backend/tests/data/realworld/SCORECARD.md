# Real-world evaluation scorecard

Answer keys sha256 `e4a1a829fb0e2ca471b594b30c2b88567ccb9afb87272afc30c30f3a6bca0b29` (locked). Results: terraform 1.15.9, scanners on. Grading rules are in the docstring of `backend/scripts/realworld_score.py`.

## Totals

- Entries: 78 (77 misconfiguration/attack_path, 1 negative)
- caught: **11** / 77
- missed_ingest: **36** (Emfirge could not read the resource)
- missed_logic: **30** (resource read, no matching evidence)
- negatives correct: **1** of 1 (0 vacuous because the resource was unreadable)

## Per scenario

| scenario | entries | caught | missed_ingest | missed_logic | negative ok |
|---|---|---|---|---|---|
| cloudgoat/cloud_breach_s3 | 4 | 1 | 2 | 1 | 0/0 |
| cloudgoat/data_secrets | 6 | 1 | 2 | 3 | 0/0 |
| cloudgoat/ec2_ssrf | 6 | 1 | 3 | 2 | 0/0 |
| cloudgoat/iam_privesc_by_attachment | 5 | 0 | 3 | 2 | 0/0 |
| cloudgoat/iam_privesc_by_ec2 | 5 | 0 | 2 | 2 | 1/1 |
| cloudgoat/iam_privesc_by_key_rotation | 4 | 0 | 3 | 1 | 0/0 |
| cloudgoat/lambda_privesc | 3 | 0 | 2 | 1 | 0/0 |
| cloudgoat/rce_web_app | 7 | 2 | 4 | 1 | 0/0 |
| cloudgoat/rds_snapshot | 5 | 0 | 4 | 1 | 0/0 |
| cloudgoat/vpc_peering_overexposed | 12 | 4 | 6 | 2 | 0/0 |
| cloudgoat/vulnerable_lambda | 4 | 0 | 3 | 1 | 0/0 |
| terragoat/db-app | 1 | 1 | 0 | 0 | 0/0 |
| terragoat/ec2 | 4 | 1 | 1 | 2 | 0/0 |
| terragoat/kms | 1 | 0 | 1 | 0 | 0/0 |
| terragoat/lambda | 1 | 0 | 0 | 1 | 0/0 |
| terragoat/s3 | 10 | 0 | 0 | 10 | 0/0 |

## Per category

| category | entries | caught | missed_ingest | missed_logic | negative ok |
|---|---|---|---|---|---|
| attack_path | 3 | 0 | 3 | 0 | 0/0 |
| data_exposure | 8 | 0 | 5 | 3 | 0/0 |
| data_protection | 2 | 0 | 0 | 2 | 0/0 |
| encryption | 7 | 0 | 2 | 5 | 0/0 |
| iam_escalation | 30 | 0 | 19 | 11 | 0/0 |
| imds | 2 | 2 | 0 | 0 | 0/0 |
| logging | 3 | 0 | 0 | 3 | 0/0 |
| network | 6 | 1 | 3 | 1 | 1/1 |
| public_exposure | 5 | 3 | 0 | 2 | 0/0 |
| secrets_exposure | 12 | 5 | 4 | 3 | 0/0 |

## Clean set (false alarms)

### clean/terraform-aws-vpc (verdict: warn)
- Critical/High false alarms: 0
- Block reasons from security findings: 0
- Block reasons from ingest coverage (not security findings): 0
- Excluded account-level Critical/High findings (empty-base artifacts): 0

### clean/terraform-aws-s3-bucket (verdict: warn)
- Critical/High false alarms: 0
- Block reasons from security findings: 0
- Block reasons from ingest coverage (not security findings): 0
- Excluded account-level Critical/High findings (empty-base artifacts): 0

### clean/terraform-aws-rds (verdict: block)
- Critical/High false alarms: 1
  - [native] EMFIRGE-RDS-001 Critical on `complete-postgresql, new-rds_instance-90bbbd`: RDS automated backups are disabled
- Block reasons from security findings: 1
  - introduced_critical_finding: Introduced Critical finding (complete-postgresql, new-rds_instance-90bbbd)
- Block reasons from ingest coverage (not security findings): 0
- Excluded account-level Critical/High findings (empty-base artifacts): 0

### clean/terraform-aws-ec2-instance (verdict: warn)
- Critical/High false alarms: 12
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-2dd364`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-62dbe5`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-6553eb`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-8a8143`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-97a34f`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-b1b013`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-be17af`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-c4c87f`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-c60cfb`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-e2328a`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-ea23e0`: Ensure Instance Metadata Service Version 1 is not enabled
  - [checkov] CKV_AWS_79 high on `new-ec2_instance-ed2048`: Ensure Instance Metadata Service Version 1 is not enabled
- Block reasons from security findings: 0
- Block reasons from ingest coverage (not security findings): 0
- Excluded account-level Critical/High findings (empty-base artifacts): 0

## Why entries were missed

### Ingest failures (missed_ingest) by reason

| reason | entries touched | entries it alone blocks |
|---|---|---|
| rejected iam_role: pass the full role ARN | 12 | 11 |
| unmodeled: aws_iam_user_policy | 4 | 4 |
| unmodeled: aws_s3_object | 4 | 4 |
| unmodeled: aws_secretsmanager_secret | 3 | 3 |
| unmodeled: aws_iam_policy | 2 | 2 |
| unmodeled: aws_iam_role_policy | 2 | 2 |
| unmodeled: aws_route | 2 | 2 |
| unmodeled: aws_vpc_peering_connection | 2 | 1 |
| rejected ebs_snapshot: ebs_snapshot supports delete only | 1 | 1 |
| rejected rds_instance: rds_instance.encrypted: expected a boolean | 1 | 1 |
| rejected rds_snapshot: Target not found: rds_instance | 1 | 1 |
| unmodeled: aws_iam_instance_profile | 1 | 1 |
| unmodeled: aws_iam_role_policy_attachments_exclusive | 1 | 1 |
| unmodeled: aws_kms_key | 1 | 1 |

### missed_logic (30)

| entry | resource | category |
|---|---|---|
| terragoat.s3.01 | aws_s3_bucket.data | public_exposure |
| terragoat.s3.02 | aws_s3_bucket.data | encryption |
| terragoat.s3.03 | aws_s3_bucket.data | logging |
| terragoat.s3.04 | aws_s3_bucket.data | data_protection |
| terragoat.s3.05 | aws_s3_bucket.financials | encryption |
| terragoat.s3.06 | aws_s3_bucket.financials | logging |
| terragoat.s3.07 | aws_s3_bucket.financials | data_protection |
| terragoat.s3.08 | aws_s3_bucket.operations | encryption |
| terragoat.s3.09 | aws_s3_bucket.operations | logging |
| terragoat.s3.10 | aws_s3_bucket.data_science | encryption |
| terragoat.ec2.02 | aws_ebs_volume.web_host_storage | encryption |
| terragoat.ec2.04 | aws_security_group.web-node | public_exposure |
| terragoat.lambda.01 | aws_lambda_function.analysis_lambda | secrets_exposure |
| cloudgoat.cloud_breach_s3.03 | aws_s3_bucket.cg-cardholder-data-bucket | data_exposure |
| cloudgoat.ec2_ssrf.01 | aws_lambda_function.lambda_function | secrets_exposure |
| cloudgoat.ec2_ssrf.05 | aws_iam_user.shepard | iam_escalation |
| cloudgoat.iam_privesc_by_attachment.01 | aws_iam_user.kerrigan | iam_escalation |
| cloudgoat.iam_privesc_by_attachment.05 | aws_instance.super_critical_security_server | iam_escalation |
| cloudgoat.iam_privesc_by_ec2.01 | aws_iam_user.dev_user | iam_escalation |
| cloudgoat.iam_privesc_by_ec2.04 | aws_instance.admin_ec2 | iam_escalation |
| cloudgoat.iam_privesc_by_key_rotation.03 | aws_iam_user.admin | iam_escalation |
| cloudgoat.lambda_privesc.01 | aws_iam_user.chris | iam_escalation |
| cloudgoat.rds_snapshot.01 | aws_instance.cg-ec2-instance | iam_escalation |
| cloudgoat.vulnerable_lambda.01 | aws_lambda_function.policy_applier_lambda1 | iam_escalation |
| cloudgoat.vpc_peering_overexposed.10 | aws_instance.prod_ec2 | network |
| cloudgoat.vpc_peering_overexposed.11 | aws_db_instance.customer_db | data_exposure |
| cloudgoat.data_secrets.02 | aws_lambda_function.sensitive_lambda | secrets_exposure |
| cloudgoat.data_secrets.04 | aws_iam_user.lambda_user | iam_escalation |
| cloudgoat.data_secrets.05 | aws_iam_user.start_user | iam_escalation |
| cloudgoat.rce_web_app.01 | aws_s3_bucket.logs | data_exposure |

### Entry detail

| entry | status | evidence / reason |
|---|---|---|
| terragoat.s3.01 | missed_logic |  |
| terragoat.s3.02 | missed_logic |  |
| terragoat.s3.03 | missed_logic |  |
| terragoat.s3.04 | missed_logic |  |
| terragoat.s3.05 | missed_logic |  |
| terragoat.s3.06 | missed_logic |  |
| terragoat.s3.07 | missed_logic |  |
| terragoat.s3.08 | missed_logic |  |
| terragoat.s3.09 | missed_logic |  |
| terragoat.s3.10 | missed_logic |  |
| terragoat.ec2.01 | caught | native:EMFIRGE-EC2-016 |
| terragoat.ec2.02 | missed_logic |  |
| terragoat.ec2.03 | missed_ingest | rejected: ebs_snapshot: ValueError: ebs_snapshot supports delete only |
| terragoat.ec2.04 | missed_logic |  |
| terragoat.kms.01 | missed_ingest | unmodeled: aws_kms_key |
| terragoat.lambda.01 | missed_logic |  |
| terragoat.db-app.01 | caught | native:EMFIRGE-EC2-016 |
| cloudgoat.cloud_breach_s3.01 | caught | scanner:CKV_AWS_88 |
| cloudgoat.cloud_breach_s3.02 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.cloud_breach_s3.03 | missed_logic |  |
| cloudgoat.cloud_breach_s3.04 | missed_ingest | aws_iam_role.cg-banking-WAF-Role: rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.ec2_ssrf.01 | missed_logic |  |
| cloudgoat.ec2_ssrf.02 | caught | scanner:CKV_AWS_88 |
| cloudgoat.ec2_ssrf.03 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.ec2_ssrf.04 | missed_ingest | unmodeled: aws_s3_object |
| cloudgoat.ec2_ssrf.05 | missed_logic |  |
| cloudgoat.ec2_ssrf.06 | missed_ingest | aws_iam_role.ec2_role: rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.iam_privesc_by_attachment.01 | missed_logic |  |
| cloudgoat.iam_privesc_by_attachment.02 | missed_ingest | unmodeled: aws_iam_policy |
| cloudgoat.iam_privesc_by_attachment.03 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.iam_privesc_by_attachment.04 | missed_ingest | unmodeled: aws_iam_instance_profile |
| cloudgoat.iam_privesc_by_attachment.05 | missed_logic |  |
| cloudgoat.iam_privesc_by_ec2.01 | missed_logic |  |
| cloudgoat.iam_privesc_by_ec2.02 | missed_ingest | unmodeled: aws_iam_role_policy |
| cloudgoat.iam_privesc_by_ec2.03 | missed_ingest | unmodeled: aws_iam_user_policy |
| cloudgoat.iam_privesc_by_ec2.04 | missed_logic |  |
| cloudgoat.iam_privesc_by_ec2.05 | negative_correct |  |
| cloudgoat.iam_privesc_by_key_rotation.01 | missed_ingest | unmodeled: aws_iam_user_policy |
| cloudgoat.iam_privesc_by_key_rotation.02 | missed_ingest | unmodeled: aws_iam_user_policy |
| cloudgoat.iam_privesc_by_key_rotation.03 | missed_logic |  |
| cloudgoat.iam_privesc_by_key_rotation.04 | missed_ingest | unmodeled: aws_secretsmanager_secret |
| cloudgoat.lambda_privesc.01 | missed_logic |  |
| cloudgoat.lambda_privesc.02 | missed_ingest | unmodeled: aws_iam_policy |
| cloudgoat.lambda_privesc.03 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.rds_snapshot.01 | missed_logic |  |
| cloudgoat.rds_snapshot.02 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.rds_snapshot.03 | missed_ingest | unmodeled: aws_s3_object |
| cloudgoat.rds_snapshot.04 | missed_ingest | unmodeled: aws_iam_user_policy |
| cloudgoat.rds_snapshot.05 | missed_ingest | rejected: rds_snapshot: TargetNotFound: Target not found: rds_instance |
| cloudgoat.vulnerable_lambda.01 | missed_logic |  |
| cloudgoat.vulnerable_lambda.02 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.vulnerable_lambda.03 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.vulnerable_lambda.04 | missed_ingest | unmodeled: aws_secretsmanager_secret |
| cloudgoat.vpc_peering_overexposed.01 | caught | native:EMFIRGE-EC2-016; scanner:CKV_AWS_79 |
| cloudgoat.vpc_peering_overexposed.02 | caught | native:EMFIRGE-EC2-016; scanner:CKV_AWS_79 |
| cloudgoat.vpc_peering_overexposed.03 | missed_ingest | unmodeled: aws_vpc_peering_connection |
| cloudgoat.vpc_peering_overexposed.04 | missed_ingest | unmodeled: aws_route |
| cloudgoat.vpc_peering_overexposed.05 | missed_ingest | unmodeled: aws_route |
| cloudgoat.vpc_peering_overexposed.06 | caught | scanner:CKV2_AWS_5 |
| cloudgoat.vpc_peering_overexposed.07 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.vpc_peering_overexposed.08 | missed_ingest | unmodeled: aws_iam_role_policy |
| cloudgoat.vpc_peering_overexposed.09 | caught | native:EMFIRGE-EC2-016 |
| cloudgoat.vpc_peering_overexposed.10 | missed_logic |  |
| cloudgoat.vpc_peering_overexposed.11 | missed_logic |  |
| cloudgoat.vpc_peering_overexposed.12 | missed_ingest | aws_iam_role.dev_ec2_role: rejected: iam_role: ValueError: pass the full role ARN; aws_vpc_peering_connection.dev_to_prod: unmodeled: aws_vpc_peering_connection |
| cloudgoat.data_secrets.01 | caught | native:EMFIRGE-EC2-016 |
| cloudgoat.data_secrets.02 | missed_logic |  |
| cloudgoat.data_secrets.03 | missed_ingest | rejected: iam_role: ValueError: pass the full role ARN |
| cloudgoat.data_secrets.04 | missed_logic |  |
| cloudgoat.data_secrets.05 | missed_logic |  |
| cloudgoat.data_secrets.06 | missed_ingest | unmodeled: aws_secretsmanager_secret |
| cloudgoat.rce_web_app.01 | missed_logic |  |
| cloudgoat.rce_web_app.02 | caught | scanner:CKV_AWS_88 |
| cloudgoat.rce_web_app.03 | missed_ingest | unmodeled: aws_iam_role_policy_attachments_exclusive |
| cloudgoat.rce_web_app.04 | missed_ingest | unmodeled: aws_s3_object |
| cloudgoat.rce_web_app.05 | missed_ingest | unmodeled: aws_s3_object |
| cloudgoat.rce_web_app.06 | caught | native:EMFIRGE-EC2-016 |
| cloudgoat.rce_web_app.07 | missed_ingest | rejected: rds_instance: ValueError: rds_instance.encrypted: expected a boolean |

## Notes

- Grader amendment after the first grading run: aggregate native findings whose resource_id is a comma-joined id list are now tokenised (before: the clean RDS Critical was wrongly excluded as account-level). Per-entry totals were identical before and after (11 caught / 36 missed_ingest / 30 missed_logic / 1 negative correct).
- All 10 TerraGoat S3 entries are missed_logic because translate_plan keeps only `tags` for aws_s3_bucket (acl, versioning, encryption and logging are dropped), so Emfirge only emitted the aggregate 'All S3 buckets are private' finding. Same for Lambda (environment variables) and EBS snapshots.
- The clean EC2 false alarms are Checkov IMDSv1 findings: `metadata_options` is unknown at plan time, so the instance is treated as IMDSv1. The clean RDS Critical (backups disabled) matches `backup_retention_period = 0` set in the example itself (examples/complete-postgres/main.tf:134-135), so it is arguably a true finding rather than a false alarm.
- TerraGoat ec2.tf has two fake key values replaced by placeholders (SOURCE.json `redactions`); this can only reduce secret-scanner evidence on `aws_instance.web_host`.
- Provider pins: aws 5.100.0 (CloudGoat), 4.67.0 (TerraGoat), unpinned 6.x for the clean examples.
