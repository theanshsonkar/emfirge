# What a branch can change, and what it can judge.

Emfirge reads far more of your account than it can change on a branch. This page is the honest line between the two. Anything on the wrong side of it degrades the verdict instead of passing.

Human version: https://emfirge.cloud/coverage/

*Figure 1. The 14 resource types a branch can change today. Each pip is an operation it supports: green for add, outlined for modify, red for delete.*

## Resources a branch can change

**Fourteen resource types today.**

| Resource type | Add | Modify | Delete | Notes |
|---|---|---|---|---|
| `ec2_instance` | yes | yes | yes |  |
| `security_group` | yes | yes | yes | Attachments derive from instance `sg_ids`. |
| `rds_instance` | yes | yes | yes |  |
| `s3_bucket` | yes | yes | yes | Public-by-bucket-policy is detected. |
| `lambda_function` | yes | yes | yes |  |
| `network_acl` | yes | yes | yes | Modify replaces the complete `entries` and/or `associated_subnet_ids`. |
| `iam_role` | yes | yes | yes | Modify covers the trust policy. |
| `iam_role_policy` |  | yes |  | Replaces the complete `access_statements` list of an existing role. |
| `iam_user` | yes |  |  |  |
| `nat_gateway` | yes |  |  | AWS assigns the ID; `subnet_id` and `connectivity_type` are needed. |
| `route_table` | yes | yes |  | Modify replaces the complete `routes` list. New internet-gateway routes need attachment evidence. |
| `rds_snapshot` | yes |  | yes | Add is a manual snapshot of an existing database. |
| `ebs_volume` | yes |  | yes | `size_gb` is required for an add. |
| `ebs_snapshot` |  |  | yes |  |

Most types also carry `tags`; a tag change replaces the complete user tag set, and `aws:` tags are kept. The live endpoint `GET /branches/capabilities` is the authoritative list, and `GET /branches/field-catalog` lists every settable field with the AWS API member it stands for, taken from AWS's own API models. A value AWS would reject is rejected.

### Not modeled yet.

CloudFront, DynamoDB and EventBridge Scheduler. A change to them is read but not modeled, so it cannot pass.

## When emfirge can't model it

**Anything not modeled degrades the verdict. It never passes quietly.**

- A change to an unmodeled type or operation is listed as unmodeled and makes the verdict stricter (`unmodeled_change`; `unmodeled_delete` blocks).
- A missing value AWS requires is flagged `unspecified_values`, never filled with a guess.
- A collection gap is shown in the diff, not hidden.
- A scanner that did not run is reported as not run; `coverage_warnings` says the result is not full coverage.

## Lenses and their status

**Each lens looks at the branch from one angle. Together they feed the six checks.**

| Lens | Asks | Status |
|---|---|---|
| Security | Does this expose something, or open a privilege-escalation path? | Live |
| Dependencies | What breaks if this is removed? Is it still in use? Can it be recovered? | Live |
| Compliance | Which CIS AWS Foundations 1.5 and SOC 2 controls flip? Uncovered controls are never `pass`. These are mapped checks, not an audit. | Live |
| Cost | What does it cost before and after? AWS Price List, **us-east-1 only**, provisioned charges only, no load-balancer capacity units. | Early |
| Limits | Will it hit an AWS quota? AWS default quotas only, not your approved increases, and no forecasting. | Early |
| Yours | Bring your own evaluator against the same branch. | Planned |

Usage-based cost (data transfer, requests, invocations) is excluded and labelled unknown. Application latency, throughput and runtime correctness need a real run and are not modeled.

## Where the checks come from

**Public data, with the source kept next to every fact. Not hand-written lists.**

Counts from the repository:

| Source | Count |
|---|---|
| pathfinding.cloud escalation paths | 92 |
| scanner check reads | 55 |
| native reason codes in verdict.py | 30 |
| Prowler check metadata files | 21 |
| scanner severity crosswalk entries | 21 |

| Source | Used for |
|---|---|
| [pathfinding.cloud](https://pathfinding.cloud) | IAM privilege-escalation paths (92) |
| [policy_sentry](https://github.com/salesforce/policy_sentry) | IAM access levels for every action pattern |
| [Prowler](https://github.com/prowler-cloud/prowler) | CIS 1.5 and SOC 2 control lists, and scanner severities |
| AWS API models and Price List | The field catalog, and provisioned cost |
| [Checkov](https://github.com/bridgecrewio/checkov) | An advisory configuration scanner on each verdict. It warns; it does not block on its own. Trivy is off. |

The numbers in the chart are counted from the repository, not estimated. Every behavior is pinned by a numbered law, a property test that must always hold. [Read the laws](https://github.com/theanshsonkar/emfirge/tree/main/backend/tests/laws).

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
