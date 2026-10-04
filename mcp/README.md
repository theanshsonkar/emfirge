<div align="center">

# 🛡️ Emfirge MCP

**Privacy-first AWS security inside your AI.**

Version **0.2.3** · Apache-2.0

</div>

The Emfirge MCP server connects an AI client to read-only AWS security analysis. It exposes graph analysis and isolated branch modeling over stdio. Modeled branch changes do not mutate AWS; results compute a security delta and never guarantee safe deployment.

## Install

```bash
npx @emfirge/mcp install
```

The installer can wire supported desktop MCP clients. Manual configuration:

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

Ask your assistant to scan with a read-only role. This is an example placeholder, not a real account:

```text
Scan arn:aws:iam::123456789012:role/EmfirgeReadOnly in us-east-1
```

## Tools (15)

### Analyze

- `emfirge_scan` — scan an AWS account and return risk score, finding counts, and `analysis_id`.
- `emfirge_get_findings` — return findings for a scan, optionally filtered by severity.
- `emfirge_attack_paths` — return internet-to-resource paths, chokepoints, and orphaned resources.
- `emfirge_simulate_breach` — walk a natural-language scenario through entry, pivot, impact, and blast radius.
- `emfirge_verify_fix` — simulate a supported finding fix and return score and finding deltas.
- `emfirge_check_compliance` — return CIS AWS Foundations 1.5 or SOC 2 per-control status.

### Branch

- `emfirge_create_branch` — create an isolated infrastructure branch from a completed analysis.
- `emfirge_apply_change` — apply an add, modify, or delete change to the branch model, not AWS.
- `emfirge_branch_diff` — show the infrastructure diff against the base analysis.
- `emfirge_branch_verdict` — evaluate an advisory `block`, `warn`, or `pass` verdict with coverage details.
- `emfirge_rollback_branch` — remove the most recent modeled change.
- `emfirge_discard_branch` — discard an isolated branch; optionally pass `expected_change_count` to reject a stale discard with HTTP 409.
- `emfirge_list_branches` — list branches, optionally filtered by base analysis ID.
- `emfirge_get_branch` — read branch metadata and its ordered normalized change log without returning the base infrastructure snapshot.
- `emfirge_fork_branch` — create an independent open branch from an open branch's current base and ordered changes.
- `emfirge_fork_branch` — fork an open branch into an independent branch with the same base and ordered changes.
- `emfirge_compare_branches` — compare branch models and rank outcomes safest-first.

### Setup

- `emfirge_setup_help` — return a CloudFormation deploy URL for a read-only IAM role.

## Privacy

Set `EMFIRGE_PRIVACY` to `strict`, `balanced`, or `off`; `strict` is the default. Strict tokenizes recognized AWS identifiers locally before MCP results reach the LLM. The token mapping remains on the local machine. The backend receives the data needed for the requested analysis. Credentials in presigned report URLs are scrubbed before URLs are returned.

For concurrent branch edits, pass the `branch_revision` returned by `emfirge_get_branch` to `emfirge_apply_change`. The backend rejects a stale revision with HTTP 409, including when another agent replaced history without changing its length. `expected_change_count` remains supported as a lighter count-only check.

```bash
npx @emfirge/mcp privacy
npx @emfirge/mcp privacy strict|balanced|off
```

## CLI

```text
npx @emfirge/mcp install                         # install for detected clients
npx @emfirge/mcp uninstall                       # remove from clients
npx @emfirge/mcp status                          # show installation and privacy mode
npx @emfirge/mcp privacy <strict|balanced|off>   # set privacy mode
npx @emfirge/mcp tokens                          # list local token mappings
npx @emfirge/mcp purge --role-arn <ARN>          # request deletion of scan data
```

## Advisory boundaries

The typical workflow is:

```text
read-only scan → fork graph → apply modeled change → diff → re-run lenses → verdict
```

A branch is an analysis model. `emfirge_branch_verdict` reports `scanner_status` and `coverage_warnings`; non-empty warnings mean degraded coverage and must not be presented as complete. `pass` is advisory evidence from the available lenses, not a guarantee of safety or application connectivity.

## License

The MCP package is licensed under [Apache-2.0](../LICENSE). The repository engine is separately licensed under AGPL-3.0.
