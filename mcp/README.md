<div align="center">

# 🛡️ Emfirge

**Privacy-first AWS security, inside your AI.**

Trace attack paths from the internet to your sensitive data, calculate blast radius,
and prove fixes *before* you apply them — without your resource IDs ever reaching the LLM.

[Website][website] · [Source][repo] · [MCP Registry][registry] · [Privacy][privacy] · [Report an issue][issues]

[![npm](https://img.shields.io/npm/v/@emfirge/mcp.svg)](https://www.npmjs.com/package/@emfirge/mcp)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-listed-blue.svg)][registry]
[![License: BUSL 1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)][license]
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

</div>

---

Your AI can read your code, but it can't see your cloud. Emfirge fixes that. It scans your
live AWS account, builds a graph of every resource and how they connect, then lets your
assistant walk attack paths, simulate breaches, and verify fixes — all from a conversation.

The AI never guesses. Emfirge clones your infrastructure graph, applies the change, and
re-runs **58 deterministic rules**. Your assistant reads back what the engine *proved*.

|  |  |
|---|---|
| 🕸️ **Graph-based** | Maps every AWS resource and relationship — not isolated resource linting like Checkov/tfsec. |
| 🎯 **Attack paths** | Weighted-Dijkstra routes from the internet to your data, ranked by *exploit difficulty*, not hop count. |
| 💥 **Blast radius** | See exactly what an attacker reaches once they land on a resource. |
| 🔒 **Privacy-first** | Resource IDs are tokenized on your machine *before* anything reaches the LLM. The mapping never leaves. |
| ✅ **Proven fixes** | Clone the graph → apply the change → re-run every rule → diff. A real simulation, not a hunch. |
| 📋 **Compliance** | CIS AWS Foundations 1.5 + SOC 2, per-control pass/fail, mapped to MITRE ATT&CK. |

---

## Install (30 seconds)

```bash
npx @emfirge/mcp install
```

Auto-detects and wires up **Claude Desktop, Cursor, Kiro, Cline, Continue, and Codex CLI**,
then asks you to pick a privacy mode. Restart your client and just ask:

> *"Scan my AWS account, role `arn:aws:iam::123456789012:role/EmfirgeReadOnly`, region us-east-1"*

**No role yet?** Say **"help me set up Emfirge"** — your assistant hands you a one-click
CloudFormation deploy link for a read-only IAM role.

**Free.** 15 scans/day per AWS account. No signup. No API keys.

### Try it with zero setup

Use the demo ARN — fake infrastructure, the real engine:

```
arn:aws:iam::194722410583:role/EmfirgeReadOnly    region: us-east-1
```

> *"Scan with `arn:aws:iam::194722410583:role/EmfirgeReadOnly` in `us-east-1`"*

> Want a visual graph instead? **[emfirge.cloud][website]** — same engine, browser UI, free during beta.

---

## What your AI gets

| Tool | What it does |
|---|---|
| `emfirge_setup_help` | Returns a clickable CloudFormation deploy link (for first-time setup). |
| `emfirge_scan` | Scan an AWS account — returns risk score, finding counts, and an `analysis_id`. |
| `emfirge_get_findings` | Full findings list for a scan, filterable by severity. |
| `emfirge_attack_paths` | Attack paths from the internet to internal resources, plus chokepoints. |
| `emfirge_verify_fix` | Simulate a fix and see the real score delta — **no changes to your AWS**. |
| `emfirge_check_compliance` | CIS AWS Foundations / SOC 2 per-control status. |
| `emfirge_simulate_breach` | Full kill-chain walkthrough — attack stages, blast radius, follow-up moves. |

All seven tools are **deterministic on the backend — no LLM calls inside the MCP path**.
Your host LLM (Claude / Cursor / etc.) is the only AI in the loop, and in `strict` mode it
only ever sees tokenized data.

---

## Privacy by default

In `strict` mode (the default), every AWS identifier is tokenized locally *before* it
reaches your LLM:

```
What the LLM sees:    "SG_001 has SSH open → reaches S3_001"
What's on your disk:  SG_001 = sg-0a1b2c3d
                      S3_001 = acme-customer-pii
```

The mapping lives at `~/.emfirge/tokens.json` and is **never sent to Emfirge, Anthropic,
or anyone**. When you say *"fix SG_001"*, the MCP resolves the real ID locally, calls the
backend, and re-tokenizes the response.

| Mode | What's tokenized | Best for |
|---|---|---|
| `strict` *(default)* | Every AWS ID — ARNs, EC2/SG/IAM/S3, IPs, account IDs, bucket names | Banks, healthcare, regulated industries |
| `balanced` | ARNs, EC2/SG/EIP/IAM IDs, IPs, account IDs. Subnets/VPCs/volumes raw. | Most users |
| `off` | Nothing — raw IDs go to the LLM | Personal accounts, demo, debugging |

```bash
npx @emfirge/mcp privacy strict|balanced|off   # change mode across every wired client
npx @emfirge/mcp privacy                        # show current mode
```

> **Honest note:** tokenization sits between the MCP and the LLM. The Emfirge backend
> *does* receive real IDs — it has to, to call AWS. It stores them for 90 days, then
> auto-deletes. Full details in [PRIVACY.md][privacy]. Wipe everything anytime with
> `npx @emfirge/mcp purge --role-arn <ARN>`.

---

## How it works

```
┌──────────────┐   role ARN    ┌──────────────┐  read-only   ┌─────┐
│ Your machine │──────────────▶│ emfirge.cloud│─────────────▶│ AWS │
│  (MCP host)  │               │   (scanner)  │  STS, 1 hr   └─────┘
└──────┬───────┘               └──────┬───────┘
       │ tokenized IDs                │ findings + graph
       ▼                              ▼
┌──────────────┐               ┌──────────────┐
│  Your LLM    │               │ Postgres + S3│
│ (Claude/etc) │               │  (90-day TTL)│
└──────────────┘               └──────────────┘
```

1. **You ask your AI to scan.** The MCP calls the backend with your read-only role ARN.
2. **The backend assumes the role** (1-hour STS token, ExternalId-scoped), scans 16 AWS
   services, builds the graph, runs the rules, and returns findings.
3. **The MCP tokenizes** every resource ID locally, then hands the safe version to your LLM.
4. **Your assistant reasons over it** — attack paths, fixes, compliance — and you never
   leave the chat.

---

## Under the hood

- **Weighted Dijkstra attack paths** — edges weighted by exploit difficulty (0 = metadata,
  1 = trivial network reach, 3 = needs a shell). A 5-hop trivial path ranks more dangerous
  than a 2-hop credential theft.
- **Brandes' betweenness centrality** — finds chokepoint nodes where hardening one resource
  kills the most attack paths at once.
- **Deterministic fix simulator** — graph mutation + full rule re-run, no LLM in the
  verification path. Proof, not a guess.
- **58 graph-aware rules** with context-aware severity — SSH-open behind an ALB drops
  Critical → Low; public S3 with CloudFront drops Critical → Low.
- **Toxic-combo detection** — dangerous pattern pairs like *public RDS + no CloudTrail*.

Coverage: EC2, Lambda, ECS, S3, EBS, RDS, IAM, Secrets Manager, KMS, VPC, Security Groups,
WAF, CloudFront, SNS, CloudTrail, GuardDuty, CloudWatch, AWS Config, Budgets.

---

## Manual configuration

If auto-install doesn't work, add this to your client's MCP config:

```json
{
  "mcpServers": {
    "emfirge": {
      "command": "npx",
      "args": ["-y", "@emfirge/mcp"],
      "env": { "EMFIRGE_PRIVACY": "strict" }
    }
  }
}
```

Config file locations:

- **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac), `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Cursor** — `~/.cursor/mcp.json`
- **Kiro** — `~/.kiro/settings/mcp.json`
- **Cline** — `~/Library/Application Support/Cline/cline_mcp_settings.json`
- **Continue** — `~/.continue/config.json`

> MCP requires a desktop AI client (stdio transport). Web Claude / ChatGPT / Gemini don't
> support MCP yet — use **[emfirge.cloud][website]** for those.

---

## CLI

```
npx @emfirge/mcp install                         # auto-wire to all detected clients
npx @emfirge/mcp install --privacy=balanced      # non-interactive: skip the prompt
npx @emfirge/mcp uninstall                        # remove from all clients
npx @emfirge/mcp status                           # show what's wired up + privacy mode
npx @emfirge/mcp privacy <strict|balanced|off>    # change privacy mode everywhere
npx @emfirge/mcp tokens                           # list local token mappings
npx @emfirge/mcp purge --role-arn <ARN>           # delete all your scan data
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `EMFIRGE_BASE_URL` | `https://emfirge.cloud/api` | Backend URL — override to point at a self-hosted backend |
| `EMFIRGE_PRIVACY` | `strict` | `strict`, `balanced`, or `off` |
| `EMFIRGE_TRUSTED_ACCOUNT_ID` | `282027772803` | AWS account ID to trust in the IAM role (for `setup_help`) |
| `EMFIRGE_EXTERNAL_ID` | `aws-risk-agent` | ExternalId for STS assume-role |

---

## Security model

- **Read-only IAM role** — zero write permissions.
- **ExternalId** — prevents confused-deputy attacks.
- **Scoped trust** — only Emfirge's AWS account can assume the role.
- **STS temporary credentials** — expire in 1 hour, never stored.
- **Instant revoke** — delete the CloudFormation stack and all access is gone.

---

## License

[BUSL 1.1][license] — free for non-production and small production use (up to $1M ARR or
100 employees). Auto-converts to Apache 2.0 in 2030.

---

<div align="center">

**See your cloud the way an attacker does — from inside your AI.**

[Website][website] · [Source][repo] · [MCP Registry][registry]

</div>

[website]: https://emfirge.cloud
[repo]: https://github.com/theanshsonkar/emfirge
[registry]: https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.theanshsonkar/emfirge
[privacy]: https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md
[license]: https://github.com/theanshsonkar/emfirge/blob/main/LICENSE
[issues]: https://github.com/theanshsonkar/emfirge/issues
