# Security & privacy. Only what is true today.

What emfirge can reach, what your agent's model sees, what the hosted engine stores, and what is still being built. Where the code and an older document disagree, this page follows the code.

Human version: https://emfirge.cloud/security/

## The read-only role

**Emfirge reaches your account through one IAM role that can read and cannot write.**

*Figure 1. Read flows out of your account through the role; nothing flows in. The role holds no write permission, so there is no path for emfirge to change a resource.*

| Part of the role | What it grants |
|---|---|
| Managed policy | AWS `SecurityAudit`: configuration reads across services. |
| Usage evidence | `cloudwatch:GetMetricStatistics` and `GetMetricData`. |
| Policy checks | `access-analyzer:CheckNoPublicAccess` and `ValidatePolicy`, used only for opt-in checks. |
| Extra reads | A short list of List/Describe/Get actions for IAM role policies, Lambda, ECS task definitions, SNS, KMS (including key rotation status), AWS Config, CloudFront, API Gateway v2, SQS, GuardDuty, Budgets, WAFv2 and Secrets Manager (names only). |
| Trust | Assumable only from emfirge's AWS account and only with an ExternalId unique to you. |
| Writes | None. |

Emfirge calls AWS STS for temporary credentials (one hour, never stored). It never asks for your access keys. Read the template yourself: [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml).

**Revoke it:** delete the CloudFormation stack. Access ends at once.

## Tokenization

**Identifiers are replaced with tokens on your machine before a model sees them.**

*Figure 2. An account ID becomes a token on your machine, before the text reaches the model. The map from token back to ID stays on your disk.*

| Mode | What is tokenized |
|---|---|
| `strict` (default) | Everything recognized: ARNs, IDs, IPs, account IDs, bucket and role names. |
| `balanced` | ARNs, EC2, security group, EIP and IAM IDs, IPs and account IDs. Subnet, VPC and volume IDs stay raw. |
| `off` | Nothing. Best output for a personal or demo account. |

The token map (`~/.emfirge/tokens.json`) lives only on your machine. It is never sent to emfirge or to a model provider. Set the mode with `emfirge privacy`.

Tokenization protects what **your agent's model** sees. It does not hide anything from the hosted engine, which needs the real identifiers to answer. [TODO Ansh: confirm that every verb's output is tokenized in strict mode, including branch and check output; older docs said branch responses were not.]

## What the hosted engine stores

**Your account's configuration, your branches, and what you send to `try`. Not your data.**

| Stored | Contents |
|---|---|
| Scans | A summary and findings with real AWS resource IDs, your account ID and region, plus the infrastructure snapshot. |
| Branches | A full copy of your account's modeled state as the base, and the ordered changes on it. |
| What you send to `try` | The text of a Terraform plan, CloudFormation change set or CLI command is kept as submitted. It can contain values such as Lambda environment variables, so do not put secrets in a plan you submit. |
| Usage evidence (opt-in) | Per resource: status, used and holds-data flags, metric peaks, last event time and event name. Never CloudTrail user names, IP addresses, access keys or raw events. |
| Policy checks (opt-in) | Which resource was checked and the answers, never the policy text. |

### Never stored

Your AWS access keys; the contents of your resources (S3 objects, database rows, secret values); and anything about accounts you did not scan.

Emfirge has no AI inside, so no model provider sees your data from the engine. Your own agent's model sees only what the CLI prints. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) also covers the web dashboard, which does send real IDs to LLM providers; the CLI path does not use it.

## Retention and deletion

**Retention and deletion controls are being built.**

Until then, email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) to delete your data.

- PRIVACY.md describes a 90-day retention period. That automatic sweep is not built yet, so data is kept until you ask for deletion.
- `emfirge purge` removes scan records, drift records, simulation logs and the matching stored reports for your account. It does not yet remove branches, submitted plans, evidence or policy checks.
- Discarding a branch marks it closed. It does not delete its data.

> [TODO Ansh: update PRIVACY.md to match this page, and tell us when sweeps, full purge and branch deletion ship so this section can change.]

## Open source, reporting and certifications

| Part | License |
|---|---|
| Engine (`backend/`) and the CloudFormation template | AGPL-3.0 |
| MCP adapter (`mcp/`) | Apache-2.0 |

You can read every check. Self-hosting the engine is possible under the license but is not supported.

**Certifications:** emfirge holds none today. Its CIS and SOC 2 mapping reports which controls its checks cover; it is not an audit.

**Reporting a vulnerability:** email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) rather than opening a public issue. The aim is to acknowledge within 48 hours and give an initial assessment within 7 days. Read [SECURITY.md](https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md) and [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md).

**Advisory, not a gate:** a `block` is a verdict. Emfirge does not stop an agent, person or pipeline with its own AWS credentials from applying a change.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
