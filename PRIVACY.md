# Privacy & Data Handling

> Last updated: 2026-11-07

This page says what Emfirge stores, who sees your data, and how to delete it.
It only says what the code does today. Where we have not built something yet,
we say so.

Lines ending in an HTML comment like `<!-- law: L71a -->` are promises that a
test in this repo checks. One test (L71h) also checks this page against the
code, so the tables below cannot drift from the database. <!-- law: L71h -->

---

## What Emfirge sees

When you scan an AWS account:

1. You give us a role ARN. The server uses it to call AWS STS and get
   **temporary credentials** for one hour. It sends your project's ExternalId
   with the request.
2. The credentials are held in memory for the scan. None of our tables or
   reports has a place to store them.
3. **Read-only AWS API calls** collect resource metadata: instance IDs,
   security group rules, bucket names, IAM role policies and so on.
4. The rule engine computes findings. The findings and the metadata behind
   them are saved (see the table below).

We never ask for your AWS access keys. The IAM role you create has the
AWS-managed `SecurityAudit` policy plus a few extra read-only permissions
(CloudWatch metrics, IAM Access Analyzer checks, and a list of read calls for
services such as Lambda, ECS, KMS, SNS and SQS). It has no write permission.
You can delete the CloudFormation stack at any time to cut off access.

The collector does not read the contents of your resources. For secrets it
keeps **names only**:

- Lambda: it keeps the names of environment variables that look like secrets
  (the name contains SECRET, PASSWORD, TOKEN, API_KEY or CREDENTIAL), and the
  name of any Secrets Manager secret an environment variable points to. It
  never keeps the values.
- EC2 user data: it keeps one yes/no flag, "looks like it has secrets". It
  never keeps the user data text.

---

## What we store, and for how long

There is **no automatic expiry yet**. Nothing is deleted because of its age.
There are no sweeps and no S3 expiry rules in the code. Data stays until
you purge it, or discard a branch. We have not designed retention periods, so
we do not promise any. <!-- law: L71h -->

<!-- privacy-storage:start -->
| Where | What it holds | Deleted by purge | Kept for |
|---|---|---|---|
| Postgres `analysis_logs` | One row per scan: scores, counts, region, AWS account ID, the AI summary text, and the full report (findings and collected metadata, with real resource IDs) | yes | until you purge |
| Postgres `drift_events` | Findings that appeared or were fixed between scans: rule, resource ID, issue text, severity, AWS account ID | yes | until you purge |
| Postgres `simulation_logs` | The text of each simulation question you asked, with your AWS account ID | yes | until you purge |
| Postgres `feedback` | What you type in the feedback form: message, name, email, AWS account ID, page | yes | until you purge (only rows that carry your AWS account ID are found) |
| Postgres `llm_usage` | AWS account ID, which AI feature was used (insight or terraform) and a timestamp. No content | yes | until you purge |
| Postgres `account_bindings` | Which project your AWS account ID is linked to | yes | until you purge |
| Postgres `account_binding_events` | A log of link and refused-link events: AWS account ID, project, action, actor | yes | until you purge |
| Postgres `branch_logs` | Simulation branches: name, the base infrastructure snapshot, and the list of changes | yes | until you discard the branch or purge |
| Postgres `branch_owners` | Which project owns a branch | yes | until you discard the branch or purge |
| Postgres `plan_logs` | Plan receipts (Terraform, CloudFormation, AWS CLI/API): the sha256 of the plan and the ingest outcome. Never the plan text | yes | until you discard the branch or purge |
| Postgres `branch_evidence_logs` | Opt-in in-use evidence for a branch | yes | until you discard the branch or purge |
| Postgres `branch_policy_check_logs` | Opt-in policy check results for a branch | yes | until you discard the branch or purge |
| Postgres `projects` | Your login workspace: name and your ExternalId | no | until you ask us to delete your login |
| Postgres `api_keys` | Your API keys as hashes, with project name, active flag and last-used time | no | until you ask us to delete your login |
| Postgres `supabase_identities` | Your sign-in user ID and the project it maps to | no | until you ask us to delete your login |
| Postgres `tf_resources` | Legacy GitHub integration only: repo name, file path and the raw HCL of indexed Terraform resource blocks | no | until you ask us to delete it |
| Postgres `ci_api_keys` | Legacy GitHub integration only: hashed CI keys, GitHub installation ID, repo name | no | until you ask us to delete it |
| S3 `reports/` | The same JSON scan report as `analysis_logs`, one file per scan | yes | until you purge |
<!-- privacy-storage:end -->

Notes on the table:

- Rows marked "no" belong to your login or to the legacy GitHub integration.
  They are not keyed by AWS account, so purge cannot find them. To remove
  them, email us (see Contact).
- A branch made without a scan as its base has no AWS account link. Purge
  cannot find it. Discard it to delete it.
- The legacy GitHub routes (`tf_resources`, `ci_api_keys`) are switched off
  whenever the server requires sign-in (`EMFIRGE_REQUIRE_AUTH`). They only
  work on a server that runs without it, for example a self-hosted one.
- API keys are stored as hashes. CI keys are stored as sha256 digests too, and
  older plain-text CI keys are converted at startup. <!-- law: L71d -->
- The server keeps only the sha256 of an uploaded Terraform plan, never the
  text. At startup it blanks any plan text stored by older versions.
  <!-- law: L71c -->
- Scan reports are written to S3 only under `reports/`. The scan response
  includes a download link that works for one hour. <!-- law: L71h -->

### Discarding a branch

Discarding a branch deletes the branch and its plans, in-use evidence and
policy checks. It does not leave a copy behind. <!-- law: L71b -->

### In-use evidence (opt-in)

In-use evidence is read-only. It is collected only after you accept a cost
estimate, for resources the branch deletes. It uses `cloudtrail:LookupEvents`
and `cloudwatch:GetMetricStatistics`. If the Emfirge role lacks either
permission, the evidence is marked denied and the verdict is unchanged.
Per-resource records store status, used and holds-data flags, metric peaks and
latest values, the last event time, and the AWS event name. CloudTrail user
names, IP addresses, access keys and raw events are not stored. Evidence is
kept with its branch (see the table).

### AWS policy checks (opt-in)

Policy checks run only after you accept an estimate. For the S3 bucket
policies and role trust policies a branch changes, the Emfirge engine sends the
policy document to AWS IAM Access Analyzer (`CheckNoPublicAccess`) using your
own role, in your AWS account. It is not sent to any other third party. The
calls are billed to your AWS account, about $0.002 per policy
([AWS pricing](https://aws.amazon.com/iam/access-analyzer/pricing/)). Emfirge
already holds these policies from the scan. The check stores no policy text,
only which resource was checked, the AWS answer and Emfirge's own answer, with
the branch. The role needs `access-analyzer:CheckNoPublicAccess` and
`access-analyzer:ValidatePolicy`. If you made your role from an older template,
update your CloudFormation role stack to add them. Without them the check does
not run: the verdict uses Emfirge's own logic and notes that the AWS check was
not run.

---

## What we do not store

- Your AWS access keys. We never receive them. Only temporary STS credentials
  are used, in memory.
- Secret values, user data text, or Terraform plan text (see above).
- Customer identifiers in server logs. Logs carry no account IDs, resource IDs,
  ARNs, bucket or role names, or repo names. Errors are logged as the error
  type, plus the AWS error code for an AWS error. <!-- law: L71g -->

---

## What the LLM sees

The backend calls two AI providers. These are the only calls in the code:

| Endpoint | Model | What is sent | Skipped for the MCP? |
|---|---|---|---|
| `/analyze` and `/analyze/stream` (AI summary) | Gemini `gemini-2.5-flash` | Region, risk score, and up to 5 findings (critical first): issue text, resource ID, region, category, attack path, blast radius count | yes |
| `/remediation/generate-insight` | Gemini `gemini-2.5-flash` | One finding: service, severity, issue, resource ID, region, attack path, recommendation | yes |
| `/simulate` (narrative) | Claude `claude-haiku-4-5-20251001` | Your query, blast radius counts, attack chain captions, and the first part of the infrastructure graph text (real resource IDs) | yes |
| `/simulate/component` (narrative) | Claude `claude-haiku-4-5-20251001` | Component type and settings, up to 5 new findings, score change | yes |
| `/remediation/generate-terraform` | Claude `claude-haiku-4-5-20251001` | Rule, issue text and resource type. If the first draft is wrong, the draft is sent back for a retry | yes |
| `/remediation/fix` (Terraform draft) | Claude `claude-haiku-4-5-20251001` | Rule, issue, resource ID and type, region, severity, recommendation, attack path. If the first draft is wrong, the draft is sent back for a retry | yes |

"Skipped for the MCP" means the request carries the MCP header (`X-MCP` or
`X-Source: mcp`) or the raw flag. Then the backend does not call a model. It
returns a plain, rule-based answer instead, and your own AI host writes the
text. Every request the MCP's backend client sends carries that header.
`/simulate/component` honours the header only (not the query flag). It never
calls a model for the MCP. <!-- law: L71e -->

Anyone else calling these endpoints (for example the web dashboard, or `curl`
without the header) sends the real resource IDs shown above to Gemini or
Claude. We do not control what those providers do with that data beyond their
own terms. If that is not acceptable, use the MCP, or self-host the backend.

### Privacy modes in the MCP

The MCP can replace AWS identifiers with tokens on your machine before data
reaches your AI host. Set the mode with the `EMFIRGE_PRIVACY` environment
variable, or with `npx @emfirge/mcp privacy <strict|balanced|off>`.

```
What your AI sees:            "SG_001 has SSH open to the internet,
                               reachable from EC2_001 to S3_001"

What is on your disk:         SG_001  -> sg-0a1b2c3d4e5f6789
                              EC2_001 -> i-0abc000000000003
                              S3_001  -> acme-customer-pii-bucket
```

| Mode | What is replaced with tokens |
|---|---|
| `strict` (default) | Everything the MCP recognises as an identifier: ARNs, instance, security group, EIP, volume, subnet, VPC, network interface, route table, gateway and ACL IDs, IPs, account IDs, and bucket, role, user, function and secret names |
| `balanced` | The same, except generic network topology IDs (volume, subnet, VPC, network interface, route table, internet gateway, NAT gateway and ACL IDs) stay as they are |
| `off` | Nothing. Your own resource names pass through. Presigned download links still have their credentials removed |

The token map is the file `~/.emfirge/tokens.json` on your machine. The MCP
never uploads it. When you ask about `SG_001`, the MCP swaps the real ID back
in locally before it calls the backend.

### Files the MCP writes on your machine

The MCP writes `~/.emfirge/tokens.json`, `~/.emfirge/credentials.json` (your
sign-in refresh token) and `~/.emfirge/notice-shown`. The folder is mode 0700
and each file is mode 0600, so only your user can read them. If an older file
was more open, the MCP tightens it. <!-- law: L71f -->

---

## Deleting your data

To delete everything we hold that is linked to one AWS account, call
`POST /privacy/purge` with the role ARN, signed in as the project that owns the
account. The MCP has a command for it:

```bash
npx @emfirge/mcp purge --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnly
```

What purge does:

1. The backend assumes your role to **verify you control the AWS account**.
2. It deletes the rows marked "yes" in the table above, for that account, in
   one transaction. Every table is either purged or listed as kept, with a
   reason. A test fails if a new table is added without that choice.
3. It deletes the S3 reports for those scans.
4. It returns a count of deleted records per table, plus `s3_objects`.

<!-- law: L71a -->

The MCP command then deletes your local `~/.emfirge/tokens.json`. It does
**not** delete `~/.emfirge/credentials.json`. Remove that file yourself, or
sign out, if you want your local sign-in gone too.

The MCP command signs in with your stored credentials, or with your API key
(`EMFIRGE_API_KEY`). Without either it stops, sends nothing, leaves your local
files alone and asks you to sign in first. <!-- law: L71i -->

### Want zero data on emfirge.cloud at all?

The backend is open source under AGPL-3.0. You can read the code in
`backend/` and run your own copy, then point the MCP at it:

```bash
EMFIRGE_BASE_URL=https://your-backend.example.com npx @emfirge/mcp install
```

We do not actively support self-hosting (no `docker-compose up`, no setup
wizard), but the source is yours under the license terms.

---

## Changes to this policy

We will announce material changes:

- In the GitHub repo's release notes
- In `mcp/CHANGELOG.md` (with a major version bump for breaking changes)

---

## Contact

For privacy questions, security reports, or to ask us to delete your login or
legacy data: **ansh@emfirge.cloud**

For everything else, open a GitHub issue or discussion.
