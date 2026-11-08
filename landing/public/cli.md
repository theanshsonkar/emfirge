# One command, six verbs. The CLI, in one page.

`emfirge` is a thin client for the hosted engine. It signs in, tokenizes identifiers on your machine, sends one verb, and prints the answer for a person or, with `--json`, for an agent. The six verbs follow an agent's workflow: context, branch, try, check, request, report.

Human version: https://emfirge.cloud/cli/

*Figure 1. The six verbs follow an agent's loop: ask what is true, open a branch, try a change, check it, ask the owner if needed, report what was applied. The highlighted verb is the section you are reading.*

## Install and sign in

**Run it with npx, or install it once.**

Terminal:

```
npx @emfirge/cli@latest connect   # sign in and create the read-only role
npm install -g @emfirge/cli       # optional: put `emfirge` on your PATH
```

Node.js 20 or later.

| Command | What it does |
|---|---|
| `emfirge connect` | Sign in, then walk through the read-only role and the first scan. The one command a person needs. |
| `emfirge login` | Open the browser to sign in with GitHub or Google. Stores the session on this machine. |
| `emfirge logout` | Sign out of this device. |
| `emfirge status` | Show the signed-in account, the connected role, the privacy mode and the backend in use. |
| `emfirge privacy [strict\|balanced\|off]` | Show or set the privacy mode. |
| `emfirge tokens` | List the local identifier-to-token mappings. |
| `emfirge purge --role-arn ARN` | Ask the backend to delete the scan data it holds for that account. Read what it removes first, on [Security & privacy](https://emfirge.cloud/security.md#retention). |

## Global options

**Same flags on every verb. Machine-readable output is one flag away.**

| Flag or variable | Meaning |
|---|---|
| `--json` | Print one stable, key-sorted JSON document on stdout. Errors go to stderr. This is the mode agents should use. |
| `--branch NAME` | The branch a verb acts on. Defaults to the branch you opened last. |
| `--region REGION` | The AWS region to read or act on. Required where a scan has several. |
| `--revision TOKEN` | A branch revision token from `branch show`. A stale token is rejected with HTTP 409. |
| `--no-color` | Plain output for logs. |
| `EMFIRGE_PRIVACY` | `strict` (default), `balanced` or `off`. Strict tokenizes every recognized AWS identifier before a model sees it. |
| `EMFIRGE_BASE_URL` | Backend API URL. Defaults to `https://emfirge.cloud/api`. |
| `EMFIRGE_API_KEY` | An API key, for CI where no browser can open. |

Local state lives in `~/.emfirge/`: your session and the token map. The token map never leaves your machine.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Pass. Nothing to tell or ask. |
| `1` | Warn or ask. There are facts the agent should read, or a request is waiting for the owner. |
| `2` | Block. The change must not be applied as it stands. |
| `3` | Error. The command could not run (network, auth, bad input). This is not a verdict. |

> [TODO Ansh: confirm the exit codes 0 pass, 1 warn or ask, 2 block, 3 error. The existing branch script exits 2 on any error, so this changes.]

## context

**Ask what is true before you change anything.**

Synopsis:

```
emfirge context [--about ID] [--paths] [--findings [--severity LEVEL]]
                [--compliance cis-1.5|soc2] [--usage ID --approve] [--refresh]
```

| Flag | Meaning |
|---|---|
| `--about ID` | What depends on a resource, what it depends on, who can reach it, and your marks from `emfirge.md`. |
| `--paths` | Internet-to-resource paths, chokepoints and orphaned resources. |
| `--findings` | The findings of the current snapshot. Add `--severity` to filter. |
| `--compliance` | Per-control status for CIS AWS Foundations 1.5 or SOC 2. Controls emfirge does not evaluate are `not_evaluated`, never `pass`. |
| `--usage ID` | Opt-in evidence that a resource is in use (CloudTrail and CloudWatch reads). Prints the estimate first and reads only with `--approve`. |
| `--refresh` | Read your live account again and take a new snapshot. Without it, context uses the latest one and says how old it is. |

Example:

```
$ emfirge context --about DB_001
  DB_001  rds_instance  us-east-1   snapshot 2026-11-08 09:14 (2h old)
  holds data     yes, no recovery point on record
  used by        EC2_003, LAMBDA_002
  reachable from  nothing outside the VPC
  marks          "orders-* is production. Never delete without me."  (emfirge.md)
```

### For agents

- Run `context` first; do not infer from names. Facts here come from your account, with their source.
- `context` is the only verb that can touch your live account, and only through the read-only role.
- The snapshot's age is part of the answer. Re-read with `--refresh` before a change that depends on fresh state.

## branch

**A workspace for a change. Open, fork, compare, roll back, discard.**

Synopsis:

```
emfirge branch new [NAME] [--from SCAN]
emfirge branch fork [BRANCH] [NAME]
emfirge branch list
emfirge branch show [BRANCH]
emfirge branch compare BRANCH BRANCH [BRANCH…]
emfirge branch rollback [BRANCH] [--to COUNT]
emfirge branch discard [BRANCH]
```

| Subcommand | What it does |
|---|---|
| `new` | Open a branch from the latest scan (or `--from SCAN`). With no changes it equals live. |
| `fork` | Copy a branch, base and full change log, into an independent child. |
| `list` | List branches, newest first, with their change counts. |
| `show` | The branch's metadata, ordered change log and revision token. Never the base snapshot. |
| `compare` | Compare two or more branches and rank them safest first. |
| `rollback` | Remove the most recent change, or keep only the first `--to COUNT` changes. `--to 0` returns to base. |
| `discard` | Close the branch so it takes no more changes. Nothing in your cloud changes. |

Example:

```
$ emfirge branch new private-db
  branch private-db  #1   base: us-east-1 scan 2026-11-08   0 changes
$ emfirge branch fork private-db private-db-v2
  branch private-db-v2  #1   copied 0 changes from private-db
$ emfirge branch compare private-db private-db-v2
  1  private-db-v2   pass   0 blocks  0 warns
  2  private-db      pass   0 blocks  0 warns
```

### For agents

- One idea per branch. To try a different plan after a block, `fork` or open a new branch; do not stack a contradicting change on the old one.
- Several agents on one base: pass `--revision` from `show` to `try`, `rollback` and `discard`. HTTP 409 means someone else changed the branch; run `show` again.
- Rolling back an empty branch does nothing. Only open branches take changes.

## try

**Put a change on a branch, in whatever form you already have it.**

Synopsis:

```
emfirge try [--branch NAME] --aws-cli "aws …" [--aws-cli "aws …"]
emfirge try [--branch NAME] --terraform plan.json
emfirge try [--branch NAME] --cfn changeset.json
emfirge try [--branch NAME] --aws-api calls.json
emfirge try [--branch NAME] --op add|modify --type TYPE --id ID --fields '{…}' [--fields-file F|-]
emfirge try [--branch NAME] --delete TYPE ID
```

| Flag | Meaning |
|---|---|
| `--aws-cli CMD` | An AWS CLI command, written out in full. Repeat for several. Shorthand is refused. |
| `--terraform FILE` | The JSON from `terraform show -json`. Emfirge never runs the plan. |
| `--cfn FILE` | A CloudFormation change set as JSON. |
| `--aws-api FILE` | AWS API calls as JSON. |
| `--op`, `--type`, `--id`, `--fields` | A typed change. `--fields-file -` reads the fields from stdin. A tag change replaces the whole user tag set. |
| `--delete TYPE ID` | Shorthand for a typed delete. |

Example:

```
$ emfirge try --branch private-db --op modify --type rds_instance --id DB_001 --fields '{"publicly_accessible": false}'
  applied 1 of 1   unmodeled 0   rejected 0   unknown fields 0   branch #2
```

Every response says which changes were **applied**, **rejected** (impossible input, such as `from_port` greater than `to_port`, or a value AWS would reject), **unmodeled** (read but not modeled, which makes the verdict stricter) and which had **unknown values** (a required value you left out is flagged, never guessed). The resource types you can change are on [Coverage](https://emfirge.cloud/coverage.md#resources).

### For agents

- Send the change you were already going to run. Do not translate it into emfirge's typed form.
- If the response lists an unmodeled change, the next `check` cannot pass. Do not retry the same change.
- `emfirge context --about ID` first when you are unsure of an ID; use the exact ID or token you were given.

## check

**Ask what the branch would do. Six answers, with reasons, evidence and unknowns.**

Synopsis:

```
emfirge check [--branch NAME] [--diff] [--only data,exposure,money,availability,control,outside-world]
              [--policy-checks --approve]
```

| Flag | Meaning |
|---|---|
| `--diff` | Add the two-sided diff: resources added and removed, relationships changed, what became reachable from the internet, cost before and after. |
| `--only LIST` | Run a subset of the six checks. |
| `--policy-checks` | Opt in to asking AWS IAM Access Analyzer whether changed S3 bucket and role trust policies are public. Prints the cost estimate (about $0.002 a policy, billed to your AWS account) and runs only with `--approve`. It can make a verdict stricter, never looser. |

Example:

```
$ emfirge check --branch orders-cleanup
  verdict  BLOCK   branch orders-cleanup #1   1 change

  data           block  data_store_deleted_no_recovery_point
                 DB_001 holds data and has no recovery point after this change
  availability   block  recently_used
                 CloudWatch shows DB_001 was used in the last 90 days
  exposure       pass
  money          pass   -$58.40/month (provisioned only; usage not priced)
  control        pass
  outside world  pass

  coverage  full for the six checks; scanner findings advisory
  exit 2
```

> Example output; the reason codes are real, the numbers are illustrative.

### For agents

- A block is a fact about your change. Change the plan and retry on a new branch. Do not argue with it, split it to hide it, or route around it.
- Read `coverage` and `unknowns` as well as the verdict. A check that did not run did not find nothing.
- Never apply a change that did not pass. A pass is evidence, not a guarantee.

## request

**Ask the owner. The agent waits only if it has nothing else to do.**

Synopsis:

```
emfirge request [--branch NAME] --check CHECK --why "…" [--wait [--timeout DURATION]]
emfirge request status [ID]
```

| Flag | Meaning |
|---|---|
| `--check CHECK` | Which check needs the owner: data, exposure, money, availability, control or outside-world. |
| `--why TEXT` | One plain sentence for the owner. Emfirge adds the facts: the branch, the change and the reason code. |
| `--wait` | Block this command until the owner answers. Without it, `request` returns an ID at once and the agent carries on. |
| `--timeout` | Give up waiting after this long (for example `10m`). The request stays open. |

Example:

```
$ emfirge request --branch orders-cleanup-2 --check data --why "Delete legacy-reports-db; I have a manual snapshot from today."
  request rq_7  open   asked: you@example.com   branch orders-cleanup-2 #1
$ emfirge request status rq_7
  rq_7  approved by you@example.com   exit 0
```

Which facts ask and which only tell is your call, in `emfirge.md`; see [Tell vs ask](https://emfirge.cloud/how-it-works.md#tell-vs-ask). An approval covers exactly the branch revision that was asked about, so changing the branch afterwards needs a new request.

### For agents

- Ask when `check` says to, not before. Put the sentence you would want to read at 3 a.m. in `--why`.
- Do not wait idle: start the next task and poll `request status`.
- A denial is final for that branch revision. Change the plan.

## report

**Say what you applied. Emfirge records it and checks it against CloudTrail.**

Synopsis:

```
emfirge report --branch NAME --calls FILE [--verify]
emfirge report show [BRANCH]
```

| Flag | Meaning |
|---|---|
| `--calls FILE` | The exact calls you applied, as JSON. Emfirge records them as submitted and never applies them itself. |
| `--verify` | Compare the calls and the live trail with what was judged. Reports the first mismatch by name. |
| `report show` | Print the record for a branch: the verdict, the calls, and predicted versus actual. |

Example:

```
$ emfirge report --branch orders-cleanup-2 --calls applied-calls.json --verify
  recorded   1 call   input_sha256 4be2…c90d
  verdict    PASS     branch orders-cleanup-2 #1
  cloudtrail 1 of 1 calls found, 0 not in the verdict
  record     predicted vs actual: match
```

A record binds the calls to the verdict by the input hash, the base snapshot, the branch revision and the verdict ID. On a mismatch, `--verify` returns `input_hash_mismatch`, `base_snapshot_changed`, `branch_revision_changed` or `verdict_changed` and exits 1.

### For agents

- Report after you apply, every time, with the calls exactly as run.
- If `--verify` finds a mismatch, tell the owner. Do not edit the calls file to make it match.

## MCP adapter

**The same six verbs, for agents that speak MCP.**

`@emfirge/mcp` is an adapter over the same client. It exposes the capabilities behind the verbs as MCP tools over stdio, so a client that cannot run a shell can still use emfirge. Both paths share one engine and one privacy layer.

| Verb | MCP tools behind it |
|---|---|
| `context` | `emfirge_scan`, `emfirge_get_findings`, `emfirge_attack_paths`, `emfirge_check_compliance`, `emfirge_in_use_evidence` |
| `branch` | `emfirge_create_branch`, `emfirge_list_branches`, `emfirge_get_branch`, `emfirge_fork_branch`, `emfirge_discard_branch`, `emfirge_rollback_branch`, `emfirge_rollback_branch_to_count`, `emfirge_compare_branches` |
| `try` | `emfirge_apply_change`, `emfirge_plan_verdict` |
| `check` | `emfirge_branch_verdict`, `emfirge_branch_diff`, `emfirge_policy_checks`, `emfirge_verify_fix` |
| `request` | none yet |
| `report` | `emfirge_branch_handback` |
| `connect`, `login`, `logout` | `emfirge_setup_help`, `emfirge_login`, `emfirge_logout`, `emfirge_link_project` |

Install it into the clients it detects, or add it by hand. Restart the client afterwards.

Terminal:

```
npx @emfirge/mcp install
```

Manual MCP config (JSON):

```
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

Codex (~/.codex/config.toml):

```
[mcp_servers.emfirge]
command = "npx"
args = ["-y", "@emfirge/mcp"]

[mcp_servers.emfirge.env]
EMFIRGE_PRIVACY = "strict"
```

> The 24 MCP tool names above are the ones the adapter ships today, and they keep working. [TODO Ansh: decide whether the adapter's tool names change to the six verbs.]

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
