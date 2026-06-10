# Privacy & Data Handling

> Last updated: 2026-06-10

This document explains exactly what data Emfirge collects, where it is
stored, for how long, and how to delete it. Cloud-security users are
paranoid by trade — we'd rather over-disclose than hide anything.

---

## What Emfirge sees

When you scan an AWS account via the MCP or via the dashboard at
emfirge.cloud:

1. Your role ARN is used to call AWS STS and get **temporary credentials**
   (1-hour validity, ExternalId-protected, never stored)
2. **Read-only AWS API calls** collect resource metadata (instance IDs,
   security group rules, S3 bucket names, IAM role policies, etc.)
3. Findings are computed by the rule engine and saved

We never ask for or receive your AWS access keys. The IAM role you create
has the AWS-managed `SecurityAudit` policy plus a few extra read-only
permissions — no write access of any kind.

---

## What gets saved server-side (on emfirge.cloud)

| Storage | Contents | Retention |
|---|---|---|
| Postgres `analysis_logs` | Scan summary, full findings JSON (with real AWS resource IDs), AWS account ID, region | **90 days** |
| Postgres `findings` | Per-finding rows: rule_id, severity, resource_id, attack_path | 90 days |
| Postgres `simulation_logs` | Simulation queries (text only, no resource data) | indefinitely |
| Postgres `drift_events` | Findings deltas between scans | indefinitely |
| Postgres `llm_usage` | Daily counters (timestamps only, no content) | indefinitely |
| S3 `emfirge-reports/snapshots/` | Gzipped infrastructure snapshot (full graph) | **90 days** |
| S3 `emfirge-reports/reports/` | Pretty JSON scan reports | 90 days |

After retention, data is auto-deleted by S3 lifecycle rules and database
sweeps.

---

## What we explicitly do NOT save

- Your AWS access keys (we never see them — STS temporary tokens only)
- The contents of your resources (S3 object bodies, RDS rows, secret values,
  encrypted blobs, etc.)
- AWS API responses outside the resource metadata we explicitly collect
- Any data from scans you didn't initiate
- Browser cookies / fingerprints / analytics on the dashboard

---

## What the LLM sees

This is the part most security-conscious users care about most.

### Via the MCP (Claude Desktop / Cursor / Kiro / Cline / Continue)

In **`strict` mode (default)**, the MCP tokenizes every AWS identifier
locally before any data reaches the LLM:

```
What Claude/your-LLM sees:    "SG_001 has SSH open to the internet,
                               reachable from EC2_001 to S3_001"

What's actually on your disk: SG_001  -> sg-0a1b2c3d4e5f6789
                              EC2_001 -> i-0abc000000000003
                              S3_001  -> acme-customer-pii-bucket
```

The mapping (`~/.emfirge/tokens.json`) lives **only on your machine**. It is
never sent to:

- The Emfirge backend
- Anthropic, OpenAI, Google, or any LLM provider
- Any third party

When you ask follow-up questions like "fix SG_001", the MCP locally looks up
the real ID, sends it to the backend, then re-tokenizes the response on the
way back.

### Privacy modes

Set via the `EMFIRGE_PRIVACY` environment variable:

| Mode | What's tokenized | LLM context | Best for |
|---|---|---|---|
| `strict` (default) | Everything: ARNs, IDs, IPs, account IDs, bucket names, role names | Lowest | Banks, healthcare, regulated industries |
| `balanced` | ARNs, EC2/SG/EIP/IAM IDs, IPs, account IDs. Subnet/VPC/volume IDs left raw. | Medium | Most users |
| `off` | Nothing — everything passes through raw | Highest, best LLM output | Personal accounts, demo, debugging |

Override at any time: `EMFIRGE_PRIVACY=off npx @emfirge/mcp install`

### Via the dashboard at emfirge.cloud

The dashboard sends **real AWS resource IDs** to:

- **Gemini 2.5 Flash** — for the AI summary on each scan
- **Claude Haiku** — for simulation narratives and Terraform fix generation
- **Claude Sonnet** — for follow-up simulation responses

This is disclosed in the UI on simulation and remediation pages. If this is
not acceptable for your use case, use the MCP in `strict` mode instead, or
self-host the backend.

---

## Deleting your data

You can delete every record we hold about your AWS account at any time:

```bash
npx @emfirge/mcp purge --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnly
```

What this does:

1. The MCP CLI calls `POST /privacy/purge` on the backend
2. The backend re-assumes your role to **verify you control the AWS account**
   (prevents anyone else from purging your data)
3. Deletes every row in `analysis_logs`, `findings`, `drift_events`, and
   `simulation_logs` for your AWS account ID
4. Deletes every S3 snapshot and report file for your scans
5. Wipes your local `~/.emfirge/tokens.json` mapping

Returns a per-table count of deleted records. Takes ~10 seconds.

After purge, the only reference to your account that remains is the row
count in `llm_usage` (just timestamps and counts — no content).

### Want zero data on emfirge.cloud at all?

The full backend is open source under BUSL 1.1. You can read the code in
`backend/` and deploy your own copy. Then point the
MCP at your URL:

```bash
EMFIRGE_BASE_URL=https://your-backend.example.com npx @emfirge/mcp install
```

We don't actively support self-hosting (no `docker-compose up`, no setup
wizard) — but the source is yours under the license terms.

---

## Changes to this policy

We'll announce material changes:

- In the GitHub repo's release notes
- In `mcp/CHANGELOG.md` (with a major version bump for breaking changes)

---

## Contact

For privacy questions, security / vulnerability reports, or anything
else: **ansh@emfirge.cloud**

For everything else, open a GitHub issue or discussion.
