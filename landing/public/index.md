# emfirge

emfirge is building the harness for AI agents that work on your cloud.

Available through our CLI, any agent's shell, and MCP.

- Site: https://emfirge.cloud
- Docs: https://emfirge.cloud/docs
- Quickstart: https://emfirge.cloud/docs/quickstart
- Source: https://github.com/theanshsonkar/emfirge
- Contact: ansh@emfirge.cloud

Works with: Claude Code, Codex, Cursor, Gemini CLI, MCP.

## Mission

The path to agents that run infrastructure isn't a smarter model. It's a true world for them to work in: what exists, what's live, what depends on what, and a safe copy to try a change on before it's real.

Intelligence is no longer the constraint. Trust is.

Agents can already write the Terraform and run the CLI. What they can't do is see what a change will break, and owners can't let them near production without that.

We built the hard parts: a branch engine for your live AWS, six checks that say what a change does to your data, exposure, money, availability, control and the outside world, and a record of what was applied, verified against CloudTrail.

Emfirge supplies the truth. Your agent supplies the intelligence. Emfirge has no AI inside: the same branch always gets the same answer, and it never writes to your cloud.

Figure 1. A change enters emfirge in any format and runs on a branch of your live cloud. Six checks answer with facts; a block goes back to the agent, which changes its plan. Only a passing change reaches your agent's context to apply.

## What we do

- **A true model of your cloud.** What exists, what's live, what depends on what, and what each identity can reach, read through a role you can revoke any time.
- **A branch for every change.** Your agent tries AWS CLI commands, Terraform plans and CloudFormation change sets on a copy of live, never on production.
- **Six checks, no AI inside.** Data, exposure, money, availability, control, outside world. Deterministic, and unknown never passes.

Every check comes from public data: AWS's own API models and Price List, pathfinding.cloud, Prowler and policy_sentry. Not hand-written lists.

## In production

Our promise is a world your agent can trust: true facts, unknowns marked honestly, and nothing that ever writes to your cloud.

Numbers, counted from the repository:

| What | Count | How it was counted |
|---|---|---|
| Engine tests (backend) | 2,432 | `pytest --collect-only` in backend/ |
| MCP + CLI tests | 102 | `npm test` in mcp/ |
| Laws | 48 | README, "Built to be trusted" |
| Modeled resource types | 14 | `SUPPORTED_RESOURCE_TYPES` in backend/app/mutations.py |
| pathfinding.cloud escalation paths | 92 | backend/app/data/pathfinding_paths.json |
| Scanner check reads | 55 | backend/app/data/scanner_check_reads.json |
| Native reason codes | 30 | distinct codes in backend/app/verdict.py |
| Prowler check metadata files | 21 | backend/app/data/third_party/prowler/checks |
| Severity crosswalk entries | 21 | backend/app/data/scanner_severity_crosswalk.json |

Same change, same answer: one rule that opens port 22 to the world gives the same verdict as a typed change, an AWS CLI command, an AWS API call, a Terraform plan or a CloudFormation change set. Law L21 pins Terraform and the AWS API to the same verdict.

> A change Emfirge can't model can't pass. A missing check is reported, not hidden. (Emfirge README)

## Where it runs

emfirge runs wherever your agent runs. The CLI is a thin client; the engine is hosted. Your cloud only ever sees a read-only role.

1. In your terminal
2. In CI
3. In your agent's sandbox

## Trust

Emfirge is read-only by design. Your account IDs are tokenized on your machine before any model sees them. The engine is open source, so you can read every check.

- Read-only role
- Tokenized IDs
- Open source (AGPL-3.0, Apache-2.0)

Security policy: https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md
Privacy: https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md

## Writing (coming soon)

- Field notes: an AI agent working on real AWS
- Why a cloud agent needs a harness
- Six questions instead of 15,000 rules

---

## How to use emfirge (for agents)

### Install

```
npx @emfirge/cli connect
```

This connects the CLI to your AWS account through a read-only IAM role (one CloudFormation click; delete the stack to revoke). The MCP server is configured for Claude Code, Cursor, Codex and others by the installer.

### The six verbs

1. `branch`: fork a copy of the live cloud model. Live never moves.
2. `try`: put a change on the branch (AWS CLI command, AWS API call, Terraform plan, CloudFormation change set, or a typed change).
3. `check`: six checks answer with facts: data, exposure, money, availability, control, outside world.
4. `block`: a failing check is a fact about the change, not an error.
5. `retry`: change your plan, put the new change on a new branch, and check again.
6. `pass`: only a change that passed reaches your context to apply.

### Rules

- Never apply a change that did not pass.
- A block is a fact. Change your plan and retry; do not argue with it or route around it.
- Read emfirge.md in the project for the facts about this cloud before proposing changes.
- Emfirge never writes to the cloud. Applying a passing change is your job, with your own credentials.
- Unknown never passes. If a check could not run, the verdict says so.
