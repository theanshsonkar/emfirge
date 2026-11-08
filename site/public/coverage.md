# What a branch can change, and what it can judge.

Emfirge reads far more of your account than it can change on a branch. This page is the honest line between the two. Anything on the wrong side of it is listed as unmodeled or unknown instead of passing.

Human version: https://emfirge.cloud/coverage/

*Figure 1. The 18 resource types a branch can change today. Each pip is an operation it supports: green for add, outlined for modify, red for delete.*

## Resources a branch can change

**Eighteen resource types today.**

| Resource type | Add | Modify | Delete | Notes |
|---|---|---|---|---|
| `ec2_instance` | yes | yes | yes |  |
| `security_group` | yes | yes | yes | Attachments derive from instance `sg_ids`. |
| `rds_instance` | yes | yes | yes |  |
| `s3_bucket` | yes | yes | yes | Public-by-bucket-policy is detected. `policy_public` is derived from `policy`. |
| `lambda_function` | yes | yes | yes |  |
| `network_acl` | yes | yes | yes | Modify replaces the complete `entries` and/or `associated_subnet_ids`. |
| `iam_role` | yes | yes | yes | Modify covers the trust policy. |
| `iam_role_policy` |  | yes |  | Replaces the complete `access_statements` list of an existing role, by role ARN. |
| `iam_user` | yes | yes |  | Modify sets the console and access-key flags, or replaces the complete statement list. |
| `iam_instance_profile` | yes |  |  | The ID is the instance profile ARN; the one field is `role_arn`. |
| `nat_gateway` | yes |  |  | AWS assigns the ID; `subnet_id` and `connectivity_type` are needed. |
| `route_table` | yes | yes |  | Modify replaces the complete `routes` list. New internet-gateway routes need attachment evidence. |
| `rds_snapshot` | yes |  | yes | Add is a manual snapshot of an existing database. |
| `ebs_volume` | yes |  | yes | `size_gb` is required for an add. |
| `ebs_snapshot` |  |  | yes |  |
| `dynamodb_table` |  | yes | yes | Modify sets point-in-time recovery or deletion protection. Adding a table is not modeled. |
| `cloudfront_distribution` |  | yes |  | Modify changes `enabled`, aliases, price class, web ACL, origins and cache behaviors. Adding or deleting a distribution is not modeled. |
| `scheduler_schedule` | yes | yes | yes | EventBridge Scheduler schedules. |

Most types also carry `tags`; a tag change replaces the complete user tag set, and `aws:` tags are kept. The live endpoint `GET /branches/capabilities` is the authoritative list, and `GET /branches/field-catalog` lists every settable field with the AWS API member it stands for, taken from AWS's own API models. A value AWS would reject is rejected.

### Not modeled.

Every resource type that is not in the table, and every operation left empty in it. A change to one of them is read but not modeled: it is listed as unmodeled and cannot pass.

## When emfirge can't model it

**Anything not modeled is listed. It never passes quietly.**

- A change to an unmodeled type or operation is listed as unmodeled and makes the verdict stricter (`unmodeled_change` warns; `unmodeled_delete` blocks).
- A missing value AWS requires is flagged `unspecified_values`, never filled with a guess.
- A source that was not collected is an unknown in the answer, not a silent "nothing found".
- A scanner that did not run is reported as not run; `coverage_warnings` says the result is not full coverage.

## Lenses and their status

**Each lens looks at the branch from one angle. Together they feed the checks.**

| Lens | Asks | Status |
|---|---|---|
| Security | Does this expose something, or open a privilege-escalation path? | Live |
| Dependencies | What breaks if this is removed? Is it still in use? Can it be recovered? | Live |
| Compliance | Which CIS AWS Foundations 1.5 and SOC 2 controls flip? Uncovered controls are never `pass`. These are mapped checks, not an audit. | Live |
| Cost | What does it cost before and after? AWS Price List, **us-east-1 only**, provisioned charges only, no load-balancer capacity units. | Early |
| Limits | Will it hit an AWS quota? AWS default quotas only, not your approved increases, and no forecasting. | Early |
| Yours | Bring your own evaluator against the same branch. | Planned |

Usage-based cost (data transfer, requests, invocations) is excluded and labelled unknown. Application latency, throughput and runtime correctness need a real run and are not modeled.

## What each check is built from

**The engine parts and the data behind each of the six checks.**

| Check | Engine parts | Data sources |
|---|---|---|
| Data | Dependencies lens: a deleted data store against the snapshots and backups that survive. Recovery points the branch removes: deleted snapshots, backups, versioning or point-in-time recovery turned off. | Your read-only scan: EBS volumes and snapshots, RDS snapshots and backup settings, S3 versioning, DynamoDB tables. |
| Exposure | Security lens: the ingress-rule diff, internet reachability over security groups, network ACLs, route tables and gateways, S3 public access, role trust, RDS default ports. Opt-in IAM Access Analyzer checks, which can only make the verdict stricter. | Your scan. AWS documentation for S3 public access and RDS ports. IAM Access Analyzer, with your role, only after you accept an estimate. |
| Money | Cost lens: provisioned cost before and after, per resource and in total. | The AWS Price List (us-east-1 on-demand prices, vendored). |
| Availability | Dependencies lens: the dependency graph walked up to 10 levels, and lost internal and internet paths. Role permission facts, the CloudFront Host-header fact, schedules turned off or deleted, recent use. | Your scan: network interfaces, IAM role last-used. policy_sentry IAM action data. AWS CloudFront documentation. CloudTrail and CloudWatch evidence over 90 days, opt-in. |
| Control | Security lens: admin access added or removed, privilege-escalation paths added, permissions added, S3 access logging. | pathfinding.cloud (92 escalation paths). policy_sentry IAM action data. Your scan: IAM roles and users, S3 logging. |
| Outside world | A per-service table written by hand (AWS Support, Service Quotas, SES, Route 53 Domains, Marketplace, Savings Plans), and schedule changes. | AWS documentation, one page cited per table entry. Your scan: EventBridge Scheduler schedules. |

The Compliance lens (CIS 1.5 and SOC 2, from Prowler) feeds `emfirge context --compliance`, and the Limits lens feeds the `capacity` reason in the verdict. Neither is part of the six checks. Lenses are internals; they are named here so you can see where each answer comes from.

## Where the checks come from

**Public data, with the source kept next to every fact. Not hand-written lists.**

Counts from the repository:

| Source | Count |
|---|---|
| pathfinding.cloud escalation paths | 92 |
| scanner check reads | 55 |
| native reason codes in verdict.py | 32 |
| Prowler check metadata files | 21 |
| scanner severity crosswalk entries | 21 |

| Source | Used for |
|---|---|
| [pathfinding.cloud](https://pathfinding.cloud) | IAM privilege-escalation paths (92) |
| [policy_sentry](https://github.com/salesforce/policy_sentry) | IAM access levels and the catalog of actions per service |
| [Prowler](https://github.com/prowler-cloud/prowler) | CIS 1.5 and SOC 2 control lists, and scanner severities |
| AWS API models and Price List | The field catalog, and provisioned cost |
| [Checkov](https://github.com/bridgecrewio/checkov) | An advisory configuration scanner on each verdict. It warns; it does not block on its own. Trivy is off. |

The numbers in the chart are counted from the repository, not estimated. Every behavior is pinned by a numbered law, a property test that must always hold; there are 88, L1 to L88. [Read the laws](https://github.com/theanshsonkar/emfirge/tree/main/backend/tests/laws).

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
