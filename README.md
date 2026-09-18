<div align="center">

# 🛡️ Emfirge

## Git branch for your cloud.

**Give your AI a read-only map of AWS. Trace attack paths, model security changes on an isolated branch, and inspect the result before touching production.**

[Get started][quickstart] · [Read the docs][docs] · [npm][npm]

**MCP version: 0.2.3**

</div>

Emfirge scans through a read-only role, builds an infrastructure graph, and computes security evidence from that snapshot. It can fork the graph, model a proposed change, and report a diff and advisory verdict. Branch changes never mutate AWS. Emfirge computes a security delta; it never guarantees a deployment is safe.

| Capability | What it provides |
|---|---|
| Graph analysis | Connected resource context rather than isolated checks. |
| Attack paths | Routes from public-facing resources toward internal resources and chokepoints. |
| Modeled branches | Isolated add, modify, and delete changes with diff, verdict, rollback, and comparison. |
| Privacy modes | Local `strict`, `balanced`, and `off` tokenization controls for MCP results. |

## Install

```bash
npx @emfirge/mcp install
```

Then ask your assistant to scan using a read-only role and region. Example placeholder only:

```text
Scan with arn:aws:iam::123456789012:role/EmfirgeReadOnly in us-east-1
```

The account ID above is intentionally non-existent example data. Use your own role when running a real scan.

## The 15 MCP tools

### Analyze

| Tool | Purpose |
|---|---|
| `emfirge_scan` | Scan an AWS account and return risk score, finding counts, and `analysis_id`. |
| `emfirge_get_findings` | Return findings for a scan, optionally filtered by severity. |
| `emfirge_attack_paths` | Return internet-to-resource paths, chokepoints, and orphaned resources. |
| `emfirge_simulate_breach` | Walk a natural-language scenario through entry, pivot, impact, and blast radius. |
| `emfirge_verify_fix` | Simulate a supported finding fix and return score and finding deltas. |
| `emfirge_check_compliance` | Return CIS AWS Foundations 1.5 or SOC 2 per-control status. |

### Branch

| Tool | Purpose |
|---|---|
| `emfirge_create_branch` | Create an isolated branch from a completed analysis. |
| `emfirge_apply_change` | Apply an add, modify, or delete change to the branch model, not AWS. |
| `emfirge_branch_diff` | Compare the branch model with its base analysis. |
| `emfirge_branch_verdict` | Return advisory `block`, `warn`, or `pass` results and coverage details. |
| `emfirge_rollback_branch` | Remove the most recent modeled change. |
| `emfirge_discard_branch` | Discard an isolated branch. |
| `emfirge_list_branches` | List branches, optionally by base analysis. |
| `emfirge_compare_branches` | Compare branches and rank modeled outcomes safest-first. |

### Setup

| Tool | Purpose |
|---|---|
| `emfirge_setup_help` | Return a CloudFormation deploy URL for a read-only IAM role. |

## Privacy

The MCP supports `strict` (default), `balanced`, and `off` modes. In `strict`, recognized AWS identifiers are tokenized locally before results reach the LLM; the mapping stays on the local machine. The backend receives the data needed to perform the requested analysis. Credentials in presigned report URLs are scrubbed before URLs are returned. Review outputs under your own data-handling policy.

```bash
npx @emfirge/mcp privacy
npx @emfirge/mcp privacy strict|balanced|off
```

## Typical flow

```text
read-only scan → fork graph → apply modeled change → diff → re-run lenses → advisory verdict
```

A non-empty `coverage_warnings` field means the verdict is degraded and must not be described as complete coverage. A `pass` is not a guarantee of safety or application connectivity.

## Manual MCP configuration

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

See the [MCP README][mcp-readme] and [documentation][docs] for usage details.

## License

The MCP package is licensed under Apache-2.0. The engine is licensed under AGPL-3.0.

[docs]: https://emfirge.cloud/docs
[quickstart]: https://emfirge.cloud/docs/quickstart
[npm]: https://www.npmjs.com/package/@emfirge/mcp
[mcp-readme]: https://github.com/theanshsonkar/emfirge/tree/main/mcp
