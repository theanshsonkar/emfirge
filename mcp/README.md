# @emfirge/mcp

MCP server for [Emfirge](https://emfirge.cloud) — graph-based AWS
attack-path scanning. Privacy-first.

```bash
npx @emfirge/mcp install
```

Auto-detects and wires up: Claude Desktop, Cursor, Kiro, Cline, Continue.
Restart your client. Then ask:

> "Scan my AWS account, role `arn:aws:iam::123456789012:role/EmfirgeReadOnly`,
> region us-east-1"

**No AWS account?** Use the demo ARN — fake infrastructure, real engine, zero setup:

```
arn:aws:iam::194722410583:role/EmfirgeReadOnly
region: us-east-1
```

> *"Scan with `arn:aws:iam::194722410583:role/EmfirgeReadOnly` in `us-east-1`"*

Don't have a role yet but want to scan your real AWS? Just say **"help me set up Emfirge"** — your
assistant will give you a one-click CloudFormation deploy link.

**Limit:** 15 scans/day per AWS account. No signup. No API keys.

---

## Privacy by default

In `strict` mode (default), AWS resource IDs are tokenized before they
reach the LLM:

```
What the LLM sees:    "SG_001 has SSH open"
What's on your disk:  SG_001 = sg-0a1b2c3d
```

Mapping lives at `~/.emfirge/tokens.json`. **Never sent anywhere.**

You pick a privacy mode the first time you run `npx @emfirge/mcp install`.
Change it any time afterwards:

```bash
npx @emfirge/mcp privacy strict      # default — hide every AWS ID
npx @emfirge/mcp privacy balanced    # hide ARNs / IAM / IPs / account IDs only
npx @emfirge/mcp privacy off         # send raw IDs (best LLM output, least private)
npx @emfirge/mcp privacy             # show current mode per client
```

The CLI flag updates every wired client at once. Restart your MCP host
(Claude Code, Cursor, Kiro, etc.) for the change to take effect.

---

## Tools

| Tool | What it does |
|---|---|
| `emfirge_setup_help` | Returns a clickable CloudFormation deploy link |
| `emfirge_scan` | Scan an AWS account, returns score + analysis_id |
| `emfirge_get_findings` | Get findings list for a scan, filterable by severity |
| `emfirge_attack_paths` | Get attack paths from internet to internal resources |
| `emfirge_verify_fix` | Simulate fixing a finding, see the score delta (no AWS changes) |
| `emfirge_check_compliance` | CIS AWS Foundations / SOC 2 compliance status |
| `emfirge_simulate_breach` | Full kill-chain walkthrough — attack stages, blast radius, follow-up moves |

All tools are deterministic on the backend side — no LLM calls inside the
MCP path. Your host LLM (Claude / Cursor / etc.) is the only AI in the
loop.

---

## Manual config

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

- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac), `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Cursor**: `~/.cursor/mcp.json`
- **Kiro**: `~/.config/kiro/mcp.json`
- **Cline**: `~/Library/Application Support/Cline/cline_mcp_settings.json`
- **Continue**: `~/.continue/config.json`

---

## CLI

```
npx @emfirge/mcp install                      # auto-wire to all detected clients (asks for privacy mode on first run)
npx @emfirge/mcp install --privacy=balanced   # non-interactive: skip the prompt
npx @emfirge/mcp uninstall                    # remove from all clients
npx @emfirge/mcp status                       # show what's wired up
npx @emfirge/mcp privacy <strict|balanced|off> # change privacy mode across every wired client
npx @emfirge/mcp privacy                      # show current mode per client
npx @emfirge/mcp tokens                       # list local token mappings
npx @emfirge/mcp purge --role-arn <ARN>       # delete all your scan data
```

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `EMFIRGE_BASE_URL` | `https://emfirge.cloud/api` | Backend URL — override for self-host |
| `EMFIRGE_PRIVACY` | `strict` | `strict`, `balanced`, or `off` |
| `EMFIRGE_TRUSTED_ACCOUNT_ID` | `282027772803` | AWS account ID to trust in the IAM role (for setup_help) |
| `EMFIRGE_EXTERNAL_ID` | `aws-risk-agent` | ExternalId for STS assume-role |

---

## Privacy & data deletion

See [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md)
in the source repo for the full data-handling story.

To delete all your data anytime:

```bash
npx @emfirge/mcp purge --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnly
```

---

## License

[BUSL 1.1](https://github.com/theanshsonkar/emfirge/blob/main/LICENSE) —
free for non-production and small production use. Auto-converts to Apache
2.0 in 2030.

## Source

https://github.com/theanshsonkar/emfirge
