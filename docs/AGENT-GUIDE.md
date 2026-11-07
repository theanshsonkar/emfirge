# Emfirge agent guide

Emfirge tells you what is true about the cloud. You bring the thinking.
Run it from the shell: `emfirge <verb>`. Output is JSON on stdout.

## Rules

- Emfirge never writes to the cloud. You apply your own change, with your own access.
- Facts, not fixes. Emfirge will not tell you what to do. You decide.
- Unknown means not checked. It never means safe. Read every `unknown` entry.
- Names and ids come back as tokens (`S3_001`, `NAME_003`, `TAG_001`). Pass them back as they are. Emfirge turns them into real ids on your machine.
- Emfirge keeps no plan text. Apply your own original plan. The hand-back is tied to it by sha256.

## The loop

1. `emfirge context inventory` - ask what is true.
2. `emfirge branch open --analysis ID --name NAME` - make a safe copy.
3. `emfirge try BRANCH ...` - put your change on the branch.
4. `emfirge check BRANCH` - read the facts and the unknowns.
5. Not what you wanted? Fix your own plan and go back to step 3. `emfirge branch rollback BRANCH` clears the branch.
6. (Later, v2) `emfirge request` - ask the owner. Not built yet.
7. Apply it yourself, with your own access.
8. `emfirge report BRANCH` - the hand-back for what you applied.

## Verbs

| Verb | What it does | Example |
|---|---|---|
| context | Ask what is true: what exists, what depends on what, what is reachable, who has access, data, cost, recent use, owner tags | `emfirge context reachable --branch B` |
| branch | Open, fork, list, get, roll back, discard, compare branches | `emfirge branch open --analysis A --name fix` |
| try | Put a change on a branch: typed JSON, AWS CLI, AWS API calls, Terraform plan, CloudFormation | `emfirge try B --aws-cli "aws ec2 ..."` |
| check | Diff, six damage answers (data, exposure, money, availability, control, outside world), evidence, unknowns | `emfirge check B` |
| request | Ask the owner. Not built yet (v2): exits 1 | `emfirge request B` |
| report | "I applied it": returns the hand-back for the branch or plan | `emfirge report B` |
| connect, login, logout | Set up and sign in | `emfirge login` |
| guide | Print this page | `emfirge guide` |

Add `--human` for short readable output. Add `--help` to any verb.
Inputs for `try` can be a file path, inline JSON, or `-` for stdin.
`emfirge check` answers come in the order data, exposure, money, availability, control, outside_world, then the baseline.

## Old MCP tool to verb option

| MCP tool | Now |
|---|---|
| `emfirge_login` | `emfirge login` |
| `emfirge_logout` | `emfirge logout` |
| `emfirge_link_project` | `emfirge connect --link` |
| `emfirge_setup_help` | `emfirge connect` |
| `emfirge_scan` | `emfirge context --refresh --role-arn ARN --region R` |
| `emfirge_context` | `emfirge context QUESTION` |
| `emfirge_get_findings` | `emfirge context --findings --analysis A` |
| `emfirge_attack_paths` | `emfirge context --attack-paths --analysis A` |
| `emfirge_check_compliance` | `emfirge context --compliance --analysis A` |
| `emfirge_simulate_breach` | `emfirge context --simulate "what if ..." --analysis A` |
| `emfirge_verify_fix` | `emfirge try --verify-fix --rule R --resource ID --analysis A` |
| `emfirge_create_branch` | `emfirge branch open --analysis A --name N` |
| `emfirge_fork_branch` | `emfirge branch fork B --name N` |
| `emfirge_list_branches` | `emfirge branch list` |
| `emfirge_get_branch` | `emfirge branch get B` |
| `emfirge_compare_branches` | `emfirge branch compare B1 B2` |
| `emfirge_rollback_branch` | `emfirge branch rollback B` |
| `emfirge_rollback_branch_to_count` | `emfirge branch rollback-to B --count N` |
| `emfirge_discard_branch` | `emfirge branch discard B` |
| `emfirge_apply_change` | `emfirge try B --typed JSON` |
| `emfirge_plan_verdict` | `emfirge try B --aws-cli / --aws-api / --terraform / --cloudformation` |
| `emfirge_check` | `emfirge check B` |
| `emfirge_branch_diff` | `emfirge check B --diff` |
| `emfirge_branch_verdict` | `emfirge check B --verdict` |
| `emfirge_in_use_evidence` | `emfirge check B --evidence` |
| `emfirge_policy_checks` | `emfirge check B --policy` |
| `emfirge_branch_handback` | `emfirge report B [--verify]` |

## Costs and consent

`check --evidence` and `check --policy` show an estimate first and send nothing.
Run them with `--accept-estimate ID` (and `--approve` for policy) only after the owner agrees.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | usage error (bad verb or option), or `request` (not built) |
| 2 | not signed in, or forbidden. Run `emfirge login`. |
| 3 | not found (branch, analysis) |
| 4 | server or network error. Try again later. |

Errors are JSON on stderr: `{"error":{"code","message","exit"}}`. Stdout is empty on error.

## Setup

`emfirge login`, then `emfirge connect` for the read-only AWS role link, then `emfirge context --refresh`.
Set `EMFIRGE_API_KEY` to skip browser sign-in.
