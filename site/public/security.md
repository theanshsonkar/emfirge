# Security & privacy. Only what is true today.

What emfirge can reach, what your agent's model sees, what the hosted engine stores, and how to delete it. Where the code and an older document disagree, this page follows the code.

Human version: https://emfirge.cloud/security/

## The read-only role

**Emfirge reaches your account through one IAM role that can read and cannot write.**

*Figure 1. Read flows out of your account through the role; nothing flows in. The role holds no write permission, so there is no path for emfirge to change a resource.*

| Part of the role | What it grants |
|---|---|
| Managed policy | AWS `SecurityAudit`: configuration reads across services. |
| Usage evidence | `cloudwatch:GetMetricStatistics` and `GetMetricData`. |
| Policy checks | `access-analyzer:CheckNoPublicAccess` and `ValidatePolicy`, used only for opt-in checks. |
| Extra reads | A short list of List/Describe/Get actions for IAM role policies, Lambda, ECS task definitions, SNS, KMS (including key rotation status), AWS Config, CloudFront (distribution config, tags, cache and origin request policies, origin access controls), API Gateway v2, SQS, GuardDuty, Budgets, WAFv2, EventBridge Scheduler (`ListSchedules`, `GetSchedule`) and Secrets Manager (names only). |
| Trust | Assumable only from emfirge's AWS account and only with an ExternalId unique to you. |
| Writes | None. |

Emfirge calls AWS STS for temporary credentials (one hour, held in memory, never stored). It never asks for your access keys. Read the template yourself: [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml).

**Revoke it:** delete the CloudFormation stack. Access ends at once.

## Tokenization

**Identifiers are replaced with tokens on your machine before a model sees them.**

*Figure 2. An account ID becomes a token on your machine, before the text reaches the model. The map from token back to ID stays on your disk.*

| Mode | What is tokenized |
|---|---|
| `strict` (default) | Everything recognized: ARNs (including DynamoDB, SQS, SNS, Scheduler, CloudFront and WAF), instance, security group, Elastic IP, volume, subnet, VPC, network interface, route table, gateway and ACL IDs, IPs, account IDs, and bucket, role, user, function and secret names. CloudFront aliases, origin domains and path patterns, and Scheduler targets are masked too, also in a branch diff. |
| `balanced` | The same, except generic network topology IDs (volume, subnet, VPC, network interface, route table, internet gateway, NAT gateway and ACL IDs), which stay as they are. |
| `off` | Nothing. Best output for a personal or demo account. Presigned download links still have their credentials removed. |

Resource tag values are hidden in `strict` and `balanced`: tag keys such as `owner` stay readable, and each value becomes a `TAG_` token. The token map (`~/.emfirge/tokens.json`) lives only on your machine, in a folder only your user can read. It is never sent to emfirge or to a model provider. Set the mode with `EMFIRGE_PRIVACY`, or for the MCP adapter with `npx @emfirge/mcp privacy`.

Every `emfirge` answer goes through the same redaction as the MCP tools, so branch and check output are tokenized in `strict` too. Tokenization protects what **your agent's model** sees. It does not hide anything from the hosted engine, which needs the real identifiers to answer.

## What the hosted engine stores

**Your account's configuration, your branches, and a fingerprint of what your agent sends to `try`. Not your data.**

| Stored | Contents |
|---|---|
| Scans | A summary and findings with real AWS resource IDs, your account ID and region, plus the infrastructure snapshot. Newer resource types are kept without their secrets: CloudFront origin custom header values and the Scheduler target `Input` payload are withheld, and DynamoDB table items are never read. |
| Branches | A full copy of your account's modeled state as the base, and the ordered changes on it. |
| What your agent sends to `try` | Only a SHA-256 of a Terraform plan, CloudFormation change set or CLI command, never its text. Your agent applies its own original plan. |
| Usage evidence (opt-in) | Per resource: status, used and holds-data flags, metric peaks, last event time and event name. Never CloudTrail user names, IP addresses, access keys or raw events. |
| Policy checks (opt-in) | Which resource was checked and the answers, never the policy text. |
| Server logs | No account IDs, resource IDs, ARNs, bucket, role or repo names. Errors are logged as the error type. |

### Never stored

Your AWS access keys; the contents of your resources (S3 objects, database rows, DynamoDB items, secret values, EC2 user data text); plan text; and anything about accounts you did not scan.

On the CLI and MCP path the engine never calls an AI model: every request carries the header that tells the backend to skip its AI summaries, and your own agent's model sees only what the CLI prints. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) also covers the web dashboard, which does not carry that header and does send real IDs to LLM providers; the CLI path does not use it.

## Retention and deletion

**Nothing expires by itself. You can delete everything linked to an AWS account.**

- There is no automatic expiry. Nothing is deleted because of its age, there are no retention sweeps, and no retention period is promised. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) says the same.
- `npx @emfirge/mcp purge --role-arn ARN` first proves you control the account by assuming your role. It then deletes, in one transaction, the scans, drift records, simulation logs, feedback, usage records and account bindings for that account, the branches linked to it with their plans, evidence and policy checks, and the stored scan reports in S3. It returns a count per table, then removes your local token map. A test fails if a table is added without a purge-or-keep decision.
- `emfirge branch discard` deletes the branch and its plans, evidence and policy checks.
- Purge does not remove your login (workspace, API keys as hashes, sign-in identity) or the legacy GitHub integration tables. Email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) to delete those, or anything else.

> Retention periods and sweeps are not designed yet.

## Open source, reporting and certifications

| Part | License |
|---|---|
| Engine (`backend/`) and the CloudFormation template | AGPL-3.0 |
| MCP adapter (`mcp/`) and the `emfirge` CLI (`cli/`) | Apache-2.0 |

You can read every check. Self-hosting the engine is possible under the license but is not supported.

**Certifications:** emfirge holds none today. Its CIS and SOC 2 mapping reports which controls its checks cover; it is not an audit.

**Reporting a vulnerability:** email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) rather than opening a public issue. The aim is to acknowledge within 48 hours and give an initial assessment within 7 days. Read [SECURITY.md](https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md) and [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md).

**Advisory, not a gate:** a `block` is a verdict. Emfirge does not stop an agent, person or pipeline with its own AWS credentials from applying a change.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
