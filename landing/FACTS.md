# Fact sheet for site v9 (v8 facts plus section 13, who does what)

Counted and read from the merged code on 2026-11-08 (branch `claude/hopeful-shannon-f6t6mf`, HEAD = `origin/main` merged in, 62 commits after the v7 site commit `1c10452`).
Rule: **the code wins**. Where a README or doc disagrees, the code is used and the disagreement is listed in section 12.
Every fact has a source: `file:line` (repo-relative), or a command and its output. Everything on the site must match this file.

Paths: `be/` = `backend/app/`, `mcp/` = `mcp/src/`.

---

## 1. The CLI

### 1.1 Package, command, install, run

| Fact | Source |
|---|---|
| The npm package is `emfirge` and it gives one command, `emfirge`. There is no `@emfirge/cli` package. | `cli/package.json:2` (name), `cli/package.json:6-8` (bin `emfirge` -> `./dist/emfirge.js`); `mcp/src/cli/package-name.test.ts:16-19`; `npm view @emfirge/cli` returns E404 |
| Repo version of the CLI package is `0.2.9`, the same as `@emfirge/mcp`. The npm registry's `latest` of `emfirge` is `0.1.1` (published 2026-11-08), which already contains the manifest-driven CLI (it ships `bundled-manifest.json` and the exit code 6 text). | `cli/package.json:3`, `mcp/package.json:3`; `mcp/src/cli/package-name.test.ts:28-31` (versions equal); `npm view emfirge versions time` -> `0.0.0-stage, 0.0.1, 0.1.0, 0.1.1`; `npm pack emfirge@0.1.1` and grep of `dist/emfirge.js` |
| Node.js 20 or later. | `cli/package.json:23-25` (`engines.node >=20.0.0`) |
| Install and first run: `npx emfirge login`, then `npx emfirge connect`. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`. Run `npx emfirge@latest` only when emfirge says so (exit code 6). | `cli/README.md:5-18` |
| A global install (`npm install -g emfirge`) puts `emfirge` on PATH. This follows from the `bin` field; no doc states it. | `cli/package.json:6-8` |
| The package is one self-contained file with no runtime dependencies, bundled with esbuild from `mcp/src/cli/index.ts` (target node20, ESM). `dist/` also holds `AGENT-GUIDE.md`, `bundled-manifest.json` and `THIRD_PARTY_NOTICES.txt` (zod, MIT). It must not depend on `@emfirge/mcp`. | `cli/scripts/build.mjs:1-5,30-60`; `cli/README.md:20-22`; `mcp/src/cli/package-name.test.ts:21-26`; commit `e9425c7` |
| `@emfirge/mcp` no longer installs an `emfirge` command (its bins are `emfirge-mcp` and `mcp`). | `mcp/package.json:9-12`; `mcp/src/cli/package-name.test.ts:36-38` |
| The CLI is a thin client: sign in, send the command, tokenize/redact, print the answer. All logic is on the hosted engine. | `mcp/src/cli/run.ts:1-6` |
| `emfirge --version` / `-v` prints the package version (`0.2.9` from source). | `mcp/src/cli/run.ts:94-98`; command output: `node --import tsx src/cli/index.ts --version` -> `0.2.9` |
| Default backend is `https://emfirge.cloud/api`, overridable with `EMFIRGE_BASE_URL`. | `mcp/src/client.ts:93` |

### 1.2 Commands come from the server (`GET /cli/manifest`)

| Fact | Source |
|---|---|
| The server serves the list of commands at `GET /cli/manifest`. It is public (works before sign-in), static, and holds no customer data. | `be/main.py:395-399`; `be/cli_manifest.py:1-8`; law L88d, L88e (`backend/tests/laws/test_L88_cli_manifest_laws.py:1-12`) |
| The CLI fetches it with a 3 second timeout. If the server cannot be reached (offline, timeout, old server, bad body), it uses the copy bundled in the package. | `mcp/src/cli/manifest.ts:143-170` (`MANIFEST_TIMEOUT_MS = 3000`, `fetchManifest`, `loadManifest`) |
| The bundled copy equals what the server returns (law L88g). It is written by `backend/scripts/export_cli_manifest.py` to `mcp/src/cli/bundled-manifest.json`. Checked: `build_manifest() == bundled-manifest.json` is `True`. | `backend/scripts/export_cli_manifest.py:1-24`; `backend/tests/laws/test_L88_cli_manifest_laws.py:10`; python check run on 2026-11-08 |
| The manifest has `protocol: 1`, 12 commands and one group summary (`branch`). The CLI reads protocol up to 1; a higher server protocol, an unknown argument type, an unknown feature or an unknown built-in key gives "needs a newer emfirge" (exit 6). | `be/cli_manifest.py:37`; `mcp/src/cli/manifest.ts:14,17,19-21,103-122`; `mcp/src/cli/run.ts:104-112` |
| A new command that needs only a request is added on the server and works in an installed CLI without a new npm version. | `be/cli_manifest.py:3-6`; `cli/README.md:12-18` |
| `GET /branches/capabilities` and `GET /branches/field-catalog` also exist on the server (the capabilities list is the authoritative resource list; the field catalog lists every settable field with its AWS API member). | `be/main.py:1627,1634` |

### 1.3 All commands (what `emfirge --help` prints)

Command output (`node --import tsx src/cli/index.ts --help`, offline so it uses the bundled manifest):

```
Commands:
  context   Ask what is true about the cloud. Facts only, with what was checked and what is unknown.
  branch    Open and manage a branch: a safe copy of the cloud model. Never touches the cloud.
  try       Put a change on a branch. Emfirge models it; it never runs it.
  check     Check a branch: what changed, six damage answers, evidence, and unknowns.
  report    Say what you applied. For now: returns the hand-back for the branch or plan.
  request   Ask the owner for approval. NOT BUILT YET (v2): exits 1 with a JSON error.
  connect   Set up the read-only AWS role: prints the deploy link. --link joins an API-key project to your sign-in.
  login     Sign in with GitHub or Google in your browser.
  logout    Sign out on this device.
  guide     Print the agent guide: the loop, the rules, the tool map and exit codes.
Global: --human (readable output), --version.
```

So there are **ten commands**: five manifest verbs (`context`, `branch`, `try`, `check`, `report`), and five built in (`request` as a stub, `connect`, `login`, `logout`, `guide`). The agent guide names six verbs: context, branch, try, check, request, report (`docs/AGENT-GUIDE.md:25-36`). **`request` is not built**: it exits 1 with code `not_built` and sends no network call (`mcp/src/cli/run.ts:153-158`, `mcp/src/cli/verbs.ts:30-35`, test `mcp/src/cli/run.test.ts:327`).

### 1.4 Real flags (from the manifest, `be/cli_manifest.py`; same text in `--help`)

**`context`** (`be/cli_manifest.py:66-108`)

- Usage: `emfirge context <question> [--analysis ID | --branch ID] [--resource ID]`; `--refresh --role-arn ARN --region REGION`; `--findings|--attack-paths|--compliance --analysis ID`; `--simulate "what if ..." --analysis ID`.
- `question` is one of 11: `inventory, resource, depends_on, dependents, reachable, access, data, cost, live, marks, baseline` (`be/cli_manifest.py:39-40`, `be/context_query.py:29-32`). `resource`, `depends_on`, `dependents` need `--resource` (`be/context_query.py:33,59-69`); `baseline` takes no resource.
- Flags: `--analysis` (default: your latest), `--branch` (ask about a branch instead of a scan; exclusive with `--analysis`, `be/context_query.py:60-62`), `--resource`, `--refresh` (needs `--role-arn` and `--region`), `--role-arn`, `--region`, `--findings` (+ `--severity Critical|Moderate|Low`), `--attack-paths`, `--compliance` (+ `--framework cis-aws-1.5|soc2`), `--simulate`. Only one of the five modes may be given (`variants_exclusive`, `be/cli_manifest.py:107`). `--findings`, `--attack-paths`, `--compliance` and `--simulate` require `--analysis` (`be/cli_manifest.py:101-105`).
- What each question answers (`mcp/src/tools/context.ts:17-20`): inventory what exists; resource/depends_on/dependents one resource and what it depends on or what depends on it; reachable what the internet can reach; access who can access what; data data stores and their backups; cost monthly list price; live recent use; marks owner tags; baseline counts for the whole snapshot.
- The old site flags `--about`, `--paths`, `--usage`, `--compliance cis-1.5|soc2` as a value do **not** exist.

**`branch`** (`be/cli_manifest.py:109-168`, eight commands)

| Command | Flags | Request |
|---|---|---|
| `branch open` | `--analysis` (required), `--name` (required) | `POST /branches` |
| `branch fork BRANCH` | `--name` (required), `--revision` | `POST /branches/{id}/fork` |
| `branch list` | `--analysis` | `GET /branches` |
| `branch get BRANCH` | | `GET /branches/{id}` |
| `branch rollback BRANCH` | `--revision`, `--expected-count` | `POST /branches/{id}/rollback` (removes the most recent change, `be/branches.py:447-452`) |
| `branch rollback-to BRANCH` | `--count` (required), `--revision` | `POST /branches/{id}/rollback-to-count` |
| `branch discard BRANCH` | `--revision`, `--expected-count` | `POST /branches/{id}/discard` (deletes the branch and every linked row, `be/branches.py:561-566`, law L71b) |
| `branch compare BRANCH...` | two or more branch ids | `POST /branches/compare` |

`--revision` is the `branch_revision` (SHA-256 hex, 64 chars) you last saw; a stale one is rejected (HTTP 409). `--expected-count` is the change count you last saw. Branch `new`, `show` and `rollback --to` from the old site do **not** exist (they are `open`, `get`, `rollback-to --count`). Open-branch limit: 10 per base analysis (`be/branches.py:92`, env `EMFIRGE_MAX_OPEN_BRANCHES`); hitting it answers HTTP 429, so the CLI exits 4 with code `rate_limited` (`be/main.py:1615-1616,1688-1689`).

**`try`** (`be/cli_manifest.py:169-199`, client code `mcp/src/cli/overrides.ts:17-61`)

- Usage: `emfirge try BRANCH --typed JSON`; `--aws-cli "aws ec2 ..."` (repeat, or a JSON list); `--aws-api FILE|JSON|-`; `--terraform FILE|JSON|-`; `--cloudformation FILE|JSON|-`; `emfirge try --verify-fix --rule RULE --resource ID --analysis ID`.
- Exactly one of `--typed`, `--aws-cli`, `--aws-api`, `--terraform`, `--cloudformation` (`mcp/src/cli/overrides.ts:21-24`). A JSON input is a file path, inline JSON, or `-` for stdin (`mcp/src/cli/support.ts:74-82`).
- `--typed` is one JSON object `{op, resource_type, resource_id, fields}` (`be/cli_manifest.py` help; `mcp/src/tools/branches.ts:34-47`). `--aws-api` is `{format:"aws-api-calls/1", calls:[...]}`. `--terraform` is the output of `terraform show -json PLAN`. `--cloudformation` is the output of `aws cloudformation describe-change-set`.
- AWS CLI shorthand syntax (`--target Arn=...,RoleArn=...`) is refused before any request with exit 1; pass the value as JSON (`mcp/src/cli/overrides.ts:45-53`, `mcp/src/cli/extra.ts`, commit `71a7b47`).
- `--verify-fix` models the fix for one finding on a copy of a scan, with no branch.
- The old site flags `--terraform` as a typed file path only, `--cfn`, `--delete TYPE ID`, `--op/--type/--id/--fields` do **not** exist as flags; a delete is a typed change with `"op":"delete"`.
- What `try` returns for the four plan formats: `plan_id`, `input_sha256`, `applied`, `rejected`, `unmodeled`, `unknown_fields`, `verdict {decision, reasons}`, `verdict_id`, `branch_revision`, `handback`, `next_step` (`mcp/src/tools/plan-verdict.ts:66-96`). `decision` is `pass`, `warn` or `block`.
- Emfirge keeps only the sha256 of a plan, never its text (`mcp/src/tools/plan-verdict.ts:46-48`, law L71c, `PRIVACY.md:112-114`).

**`check`** (`be/cli_manifest.py:200-228`)

- `emfirge check BRANCH` returns the six damage answers (below). `--verdict` returns the old pass / warn / block verdict. `--diff` returns the diff against the base scan. `--policy` asks IAM Access Analyzer about changed policies (costs money; shows an estimate first; `--approve` and `--accept-estimate ID` to run it). `--evidence` reads CloudTrail / CloudWatch use of deleted resources (estimate first; `--source cloudtrail_events|cloudwatch_metrics`, repeatable; `--accept-estimate ID --role-arn ARN` to run it).
- `--only`, `--policy-checks`, `--human` as site v7 described them: `--only` and `--policy-checks` do **not** exist. `--human` exists (global).

**`report`** (`be/cli_manifest.py:229-243`, `mcp/src/tools/branch-handback.ts`)

- `emfirge report BRANCH [--plan PLAN] [--verify]`. Without `--plan` it returns the hand-back of the branch (`GET /branches/{id}/handback`): the exact AWS API calls of its typed changes, their `input_sha256`, `base_analysis_id`, `branch_revision`, `verdict` and `verdict_id` (`be/main.py:2111-2140`). With `--plan` it returns the hand-back of one plan from `emfirge try` (`be/main.py:2048-2076`). `--verify` posts the hand-back back to the server, which checks the binding and answers `{ok: true, ...}` or 409 with a `reason_code` of `unknown_plan`, `input_hash_mismatch`, `branch_revision_changed`, `base_snapshot_changed` or `verdict_changed` (`be/main.py:2078-2108,2142-2175`).
- It does **not** read CloudTrail. The old site's CloudTrail after-check, `--calls FILE` and `report show` do not exist. Summary text in the manifest: "For now: returns the hand-back for the branch or plan."
- A branch built from a submitted plan cannot use the typed hand-back (409 `branch_has_plan_receipts`); a branch with no changes gives 409 `no_changes`; changes with no AWS API equivalent give 422 `unmappable_changes` (`be/main.py:2111-2140`).

**Built-in commands** (`mcp/src/cli/verbs.ts:29-60`, `mcp/src/cli/run.ts:38-58`)

- `emfirge login`: sign in with GitHub or Google in your browser (PKCE, a one-time local server on `127.0.0.1`, 5 minute timeout; `EMFIRGE_NO_BROWSER=1` does not open the browser). Stores the refresh token in `~/.emfirge/credentials.json` (dir mode 0700, file 0600). If `EMFIRGE_API_KEY` is set it says so and uses the key. `mcp/src/auth/login.ts:29-138`, `mcp/src/auth/credentials.ts:6-31`.
- `emfirge logout`: sign out on this device (removes the stored sign-in).
- `emfirge connect`: prints the CloudFormation deploy link for the read-only role (`deploy_url` plus the setup text: ExternalId, trusted account, steps). `emfirge connect --link` links your saved sign-in to an existing API-key project (needs `EMFIRGE_API_KEY`). It does not detect the role; you paste back the RoleArn from the stack outputs. `mcp/src/tools/setup.ts:45-78`, `mcp/src/cli/run.ts:38-43`.
- `emfirge guide`: prints the agent guide (`docs/AGENT-GUIDE.md`).
- `emfirge help [command]`, `emfirge <command> --help` / `-h`, `--version`.
- **There is no `emfirge status`, `emfirge privacy`, `emfirge tokens` or `emfirge purge`.** Those are subcommands of `npx @emfirge/mcp` (`install`, `uninstall`, `status`, `privacy [mode]`, `tokens`, `purge --role-arn ARN [--region R]`): `mcp/src/index.ts:38,49-72`.

### 1.5 Global options, environment, output

| Fact | Source |
|---|---|
| Output is one JSON document on stdout. `--human` prints a short readable form instead. Errors are JSON on stderr, `{"error":{"code","message","exit"}}`, stdout empty; with `--human` an error is `Error: <message>`. | `docs/AGENT-GUIDE.md:94-96`; `mcp/src/cli/output.ts` (`formatOk`, `formatError`); `mcp/src/cli/verbs.ts:143-146` |
| There is no `--json`, `--no-color`, global `--branch`, `--region` or `--revision` flag. (`--region`, `--branch`, `--revision` are per-command flags listed above.) | `mcp/src/cli/args.ts:26-92`; `be/cli_manifest.py` |
| `EMFIRGE_API_KEY`: an API key; skips browser sign-in. `EMFIRGE_BASE_URL`: backend URL, default `https://emfirge.cloud/api`. `EMFIRGE_PRIVACY`: `strict` (default), `balanced`, `off`. `EMFIRGE_NO_BROWSER=1`: do not open the browser on login. | `mcp/src/client.ts:55-60,93`; `mcp/src/tokenize.ts:12-16`; `mcp/src/auth/login.ts:131` |
| Local state in `~/.emfirge/`: `credentials.json` (sign-in refresh token) and `tokens.json` (token map). Folder mode 0700, files 0600; older open files are tightened. | `mcp/src/auth/credentials.ts:6-31`; `mcp/src/tokenize.ts:18-19`; `PRIVACY.md:221-226` (law L71f) |
| Not signed in: the CLI fails fast with exit 2 (it never waits for a browser). | `mcp/src/client.ts:62-67`; test `mcp/src/cli/run.test.ts:375` |
| A `check`/`try` result never changes the exit code: a block verdict still exits 0. The exit codes are about the command, not about the finding. | `mcp/src/cli/run.ts:147-150` (a successful command always `return 0`) |

### 1.6 Exit codes, the full real table

| Code | Error code in JSON | Meaning | Source |
|---|---|---|---|
| 0 | | ok | `mcp/src/cli/run.ts:7-8` |
| 1 | `usage` | usage error (bad command or option, missing argument); also HTTP 400 and 422 (input the server rejected); also AWS CLI shorthand; also `request` (`not_built`) | `run.ts:59,73,155`, `docs/AGENT-GUIDE.md:87`, commit `71a7b47` |
| 2 | `not_signed_in` (HTTP 401), `forbidden` (HTTP 403) | not signed in, or forbidden; login that did not finish | `run.ts:71`, `run.ts:54` |
| 3 | `not_found` (HTTP 404) | branch, analysis or resource not found | `run.ts:72` |
| 4 | `server_error` (5xx, network, timeout), `rate_limited` (HTTP 429) | server or network error, or rate limited | `run.ts:75-76` |
| 5 | `conflict` (HTTP 409) | the branch changed since you read it (stale `--revision` / `--expected-count`) | `run.ts:74`, `docs/AGENT-GUIDE.md:91` |
| 6 | `update_needed` | the server's command is newer than this install: run `npx emfirge@latest` | `manifest.ts:19-21`, `run.ts:104-112` |

All of 1-6 are tested in `mcp/src/cli/exit-codes.test.ts` (400/422 -> 1, 409 -> 5 with code `conflict`, 429 -> 4 with code `rate_limited`, the agent guide documents every code).
**The site's old table (0 pass, 1 warn or ask, 2 block, 3 error) was wrong.**

---

## 2. Check output (what `emfirge check BRANCH` returns)

| Fact | Source |
|---|---|
| `GET /branches/{id}/check` returns `CheckResult`: `branch_id`, `base_analysis_id`, `branch_revision`, `changes` (added / removed / modified resource ids), `answers` (always six, always in the order data, exposure, money, availability, control, outside_world), `changed_settings`, and `baseline` (only when the branch changes nothing). | `be/check_facts.py:35,159-181,652-682`; `be/main.py:2229-2241` |
| **There is no pass / warn / block in the default check.** "An answer is never a verdict. There is no pass/warn/block, no score, no severity, no rule or reason id and no advice." Each answer has `facts`, `checked` (what was checked) and `unknown` (what was not, and why). Unknown means not checked, never safe. | `be/check_facts.py:1-19`; `mcp/src/tools/check.ts:9-13`; `docs/AGENT-GUIDE.md` (Rules) |
| The verdict (`pass` / `warn` / `block` + reasons) still exists in two places: `emfirge check BRANCH --verdict` and the `verdict` field that `emfirge try` returns for plan formats. The level is the worst reason level, `pass` if there are none. | `be/main.py:2221-2227`; `be/verdict.py:41,830`; `mcp/src/tools/plan-verdict.ts:66-96` |
| Fact kinds per answer: data (`deleted` / `recovery_removed`, with `has_recovery_point` true / false / null); exposure (`newly_exposed`, `no_longer_exposed`, `became_internet_reachable`, `no_longer_internet_reachable`, `became_public`, `no_longer_public`, `newly_trusts_external_account`, `no_longer_trusts_external_account`); money (`added`, `removed`, `modified`, `total` with before / after monthly USD); availability (`dependency_removed`, `internal_path_removed`, `dependent_of_deleted`, `deleted_along_with`, `internet_path_removed`, `schedule_disabled`, `schedule_deleted`, `permission_removed`, `origin_receives_host_header`); control (admin access added / removed, logging enabled / disabled, `account_setting_changed`, `privilege_escalation_path_added`, `permission_added`); outside world (an action in the service table, or a schedule that starts running: `schedule_enabled`, `schedule_added_enabled`, `schedule_changed`). | `be/check_facts.py:49-156`; `be/aws_check.py:65-190` |
| **`changed_settings`** sits outside the six answers: one entry per (resource, setting) that differs between base and branch, by **name only, never a value**. `judged: true` + `judged_by` (the damage answers) means a check reads that setting; `judged: false` means it changed and no check reads it. It is named there and nowhere else, never dropped. "Judged" does not mean it produced a fact. "Not judged" is not safe. Human form: `changed settings: N (J judged by a check, K not judged)` then `Changed, not judged:`. | `be/check_facts.py:159-171`; `be/aws_check_fields.py:1-14`; `docs/AGENT-GUIDE.md:43`; `mcp/src/cli/output.ts:53-60`; law L87 (`backend/tests/laws/test_L87_changed_settings_laws.py:1-17`); commits `d0a9456`, `ceb0850` |
| Judged settings are declared per resource type in `JUDGED_FIELDS` (13 resource types; for example `security_group.rules` -> exposure, `ebs_volume.size_gb` -> money, `iam_role.has_admin` -> control, `scheduler_schedule.state` -> availability and outside_world). Law L87h greps each reading module for each declared field so a declaration cannot name code that does not use it. Computed settings and counts are dropped when something else changed on the resource. | `be/aws_check_fields.py:36-107,110-132`; `backend/tests/laws/test_L87_changed_settings_laws.py:15` |
| Unknowns (real topics, by answer). data: `data_contents`, `data_store_types`, `table_backups`, `recovery_unknown`, `recovery_not_assessed`; exposure: `observed_traffic`; money: `cost`, `cost_total`, `usage_charges`; availability: `recent_use`, `app_code_references`, `action_catalog`, never-granted permission (law L84), `other_policy_layers`; control: `account_settings`, `other_policy_layers`; outside_world: `unclassified_action`, `service_table`, schedule state / target unknowns. Every answer also lists the collection sources it needs and whether each was collected ok. A plan item that could not be modeled is an `unmodeled_item`, `plan_change_not_applied` or `plan_values_unknown` unknown in the five diff answers and outside_world. | `be/check_facts.py:355-576`; `be/aws_check.py:40-47` (`DAMAGE_SOURCES`) |
| `changes` + `baseline`: with zero changes the answer carries the baseline counts of the whole snapshot (law L74g). | `be/check_facts.py:652-682` |
| Real example output (abridged; engine output on the synthetic test account `load_synthetic_base("delete")`, ids tokenized as the CLI does in strict mode): an SSH rule opened on a web security group gives, in `exposure`, a `newly_exposed` fact on `EC2_001` (tcp, ports 22-22, source `0.0.0.0/0`, via `SG_002`), and `changed_settings` lists `SG_002.rules` as judged by exposure and `SG_001.attached_instances` / `attached_to` as not judged. Deleting the RDS instance `db-dl-prod` gives a `data` fact `deleted` with `has_recovery_point: false`, an `availability` fact `internet_path_removed`, and a `money` fact `removed` with the unknown `cost: RDS instance class is absent from the current model`. | command output, run 2026-11-08: `check_for_branch(...)` on the synthetic base, then `formatOk(redactDeep(...))` from `mcp/src/tokenize.ts` and `mcp/src/cli/output.ts` |

### 2.1 Verdict reason codes (real, `emfirge check --verdict` and `emfirge try`)

32 distinct codes passed to `_reason(...)` in `be/verdict.py` (counted with Python `ast` over the file on 2026-11-08; the site said 30). Level in brackets:

- Data and recovery: `data_store_deleted_no_recovery_point` [block], `data_store_deleted_recovery_unknown` [warn], `data_store_deleted_with_recovery_point` [warn], `recovery_point_removed` [warn]
- Exposure and findings: `introduced_critical_exposure` [block], `introduced_critical_finding` [block], `new_exposure` [warn], `latent_exposure` [warn], `newly_internet_reachable` [warn], `internet_to_broad_data_access` [block or warn by finding severity], `introduced_finding` [warn], `new_scanner_finding` [warn]
- Access: `privilege_escalation` [block], `tag_change_access_unmodeled` [warn]
- Use and dependencies: `recently_used` [block], `usage_unknown` [block], `recent_activity` [warn], `lost_ingress` [warn], `lost_dependency` [warn], `lost_connectivity` [warn], `deletion_impact` [warn]
- Limits: `capacity` [warn]
- Coverage, what could not be modeled: `unmodeled_change` [warn], `unmodeled_delete` [block], `unmodeled_risky_change` [block], `unseen_change` [block], `outside_view` [warn], `plan_change_rejected` [warn], `plan_delete_rejected` [block], `unknown_plan_values` [warn], `unspecified_values` [warn], `stateless_replace` [warn]

Sources: `be/verdict.py:421-446,667-824`. The verdict has **no reason code for money, control or outside world**; those live only in the six answers. The verdict also carries `coverage_warnings`, `scanner_status` (`checkov`, `trivy`, `cloudsplaining`), `scanner_loss` and `scanner_skipped` (`be/verdict.py:39-90`).
Scanners: the code default is off (`EMFIRGE_RUN_SCANNERS` defaults to `0`, `be/main.py:2206`), but the production deploy turns Checkov on (`.github/workflows/deploy.yml:76`, `backend/deploy/docker-compose.scanner.yml:30`). Trivy is `disabled (memory)` (`be/scanners.py:547`). Scanner findings are advisory.

### 2.2 How "outside world" is decided (per service, per action)

| Fact | Source |
|---|---|
| Decided per **service** and per **action**, never by adding single actions one by one. The one split inside a table service is reads: an operation starting with `Get`, `List` or `Describe` is not outside-world. Anything not in the table is reported as an `unclassified_action` unknown, never as fine. | `be/aws_outside_world.py:1-28,46,100-125`; commits `c67e0eb`, `b9ea793`; law L83a-b |
| The table has **7 entries covering 9 botocore service names**: `support`; `servicequotas` and `service-quotas`; `ses`; `sesv2`; `route53domains`; `marketplace-catalog` and `marketplace-entitlement`; `savingsplans`. Each cites an AWS documentation URL. (Terraform resource-type prefixes: `aws_servicequotas_`, `aws_ses_`, `aws_sesv2_`, `aws_route53domains_`.) | `be/aws_outside_world.py:49-85`; counted with Python on 2026-11-08 |
| What they mean (the entry reasons): support = opens or changes a case with AWS Support staff; service quotas = asks AWS to raise an account limit; ses / sesv2 = sends or configures email to recipients outside the account; route53domains = registers, transfers or renews a domain (billed); marketplace = subscribes to or changes third-party software; savings plans = buys a one- or three-year commitment. | `be/aws_outside_world.py:50-84` |
| Separately, a **schedule** (EventBridge Scheduler) that starts running on the branch, or whose timing changes while enabled, is an outside_world fact: "Runs its target on a timer without anyone starting it." What the target does outside is not visible (an unknown). Law L77, L85. | `be/aws_outside_world.py:87-93`; `be/aws_check.py:221-277`; commit `e76a325` |
| Services where only some actions leave the cloud (SNS, Organizations, RAM, Pinpoint, Connect, EventBridge API destinations, Marketplace metering and agreements) are **not** in the table and stay unclassified. Typed changes are not claimed to stay inside the account: the answer only says how many typed changes were compared. | `be/aws_outside_world.py:12-17`; `be/check_facts.py:536-576`; law L83e |
| Source status: the SES, Service Quotas, Route 53 domains, Savings Plans and Marketplace reasons "were not re-verified" in the L83 review. | `HAND-WRITTEN-FACTS-INVENTORY.md` (rows for those entries) |

---

## 3. The context query

| Fact | Source |
|---|---|
| `emfirge context <question>` -> `POST /context` with `{question, analysis_id, branch_id, resource_id}` (nulls explicit). The answer is `ContextResponse`: `question`, `source {kind scan|branch, analysis_id, branch_id, collected_at, region}`, `facts`, `known` (what was checked), `unknown` (what was not, and why). Read-only, "facts only, never advice", deterministic: no AI, no clock, no randomness. | `be/context_query.py:1-20,53-91,183-191`; `be/cli_manifest.py:96-99`; `be/main.py:596`; law L73 |
| 11 questions (see 1.4). The `baseline` answer counts the whole snapshot (resources, relationships, per type, internet reachable, identities with escalation paths, data stores with and without recovery point, priced and unpriced resources, tags, last-used inside / outside the window). | `be/context_query.py:497-535` |
| `marks` returns resource tags and has the fixed unknown `owner_intent`: "emfirge.md is not built yet; only resource tags are shown". **`emfirge.md` is not built.** | `be/context_query.py:40,448-460` |
| Resource ids are tokens (`S3_001`) on output and are expanded back on your machine before sending. In `strict` mode tag values become `TAG_` tokens. | `mcp/src/cli/generic.ts:128,134` (`expandTokens`, `redactDeep`); `docs/AGENT-GUIDE.md` (Rules) |
| `context --refresh --role-arn ARN --region R` runs a fresh scan (the scan stream waits up to 240 s and ends with "Scans remaining today: n/limit (resets midnight UTC)"). `--findings`, `--attack-paths`, `--compliance`, `--simulate` read an existing scan. | `mcp/src/tools/scan.ts:46-71`; `mcp/src/cli/overrides.ts:63-70` |
| Compliance frameworks: CIS AWS Foundations 1.5 (63 requirements) and SOC 2 (27 requirements, a subset of the Trust Services Criteria) from Prowler's published files. Controls Emfirge does not evaluate are `not_evaluated`, never `pass`; statuses are `fail`, `pass`, `partial`, `not_applicable`, `not_evaluated`. | `be/compliance.py:1-21`; `backend/app/data/third_party/prowler/compliance/SOURCE.json`; python count of `Requirements` |

---

## 4. Coverage: resource types a branch can change

`len(app.mutations.SUPPORTED_RESOURCE_TYPES)` = **18** (was 14). Source: `be/mutations.py:392-496`, `python3 -c "from app import mutations; print(sorted(mutations.SUPPORTED_RESOURCE_TYPES))"` on 2026-11-08.

| Resource type | add | modify | delete | Notes (from the constraints in `be/mutations.py`) |
|---|---|---|---|---|
| `ec2_instance` | yes | yes | yes | |
| `security_group` | yes | yes | yes | `attached_to` is derived from instance `sg_ids` |
| `rds_instance` | yes | yes | yes | |
| `s3_bucket` | yes | yes | yes | `policy_public` is derived from `policy` |
| `lambda_function` | yes | yes | yes | |
| `network_acl` | yes | yes | yes | modify replaces the complete `entries` and/or `associated_subnet_ids` |
| `iam_role` | yes | yes | yes | modify covers the trust policy |
| `iam_role_policy` | | yes | | replaces the complete `access_statements` list of one existing role (by role ARN) |
| `iam_user` | yes | **yes** (new) | | modify: `has_console_access`, `access_statements` + `policy_documents` together, `has_access_keys` |
| `iam_instance_profile` | **yes** (new) | | | resource id is the instance profile ARN; one field, `role_arn` |
| `nat_gateway` | yes | | | needs `subnet_id` (and an Elastic IP for a public one) |
| `route_table` | yes | yes | | modify replaces the complete `routes` list; new internet-gateway routes need attachment evidence |
| `rds_snapshot` | yes | | yes | |
| `ebs_volume` | yes | | yes | `size_gb` etc.; availability zone needed |
| `ebs_snapshot` | | | yes | |
| `dynamodb_table` | | **yes** (new) | **yes** (new) | modify: `pitr_enabled`, `deletion_protection_enabled`; adding a table is not modeled |
| `cloudfront_distribution` | | **yes** (new) | | modify: `enabled`, `aliases`, `price_class`, `web_acl_id`, `default_cache_behavior`, `cache_behaviors`, `origins`; add and delete not modeled |
| `scheduler_schedule` | **yes** (new) | **yes** (new) | **yes** (new) | EventBridge Scheduler schedules |

Not modeled and so unmodeled on a branch: everything else (for example queues, caches, KMS keys, Secrets Manager, EventBridge rules, load balancers as a type). Old site "Not modeled yet: CloudFront, DynamoDB, EventBridge Scheduler" is **now wrong**: all three are modeled (commits `fd18613`, `f4218fc`, `139aa02`; laws L75, L78, L80).
Most types also carry `tags` (a tag change replaces the complete user tag set, `aws:` tags are kept; law L50).

### 4.1 Numbers

| Number | Value | Source (command or file) |
|---|---|---|
| Backend test cases | **3,247** | `cd backend && python3 -m pytest --collect-only -q -p no:warnings \| tail -3` -> `3247 tests collected` (old site: 2,432) |
| MCP + CLI tests | **206** | `cd mcp && npm test` -> `# tests 206`, `# pass 206`, `# fail 0` (old site: 102) |
| Laws | **88** (L1 to L88, none missing) | distinct `L<n>` ids in `backend/tests/**/*.py` (87; L81 lives in `mcp/src/tokenize-leaks.test.ts:1`) plus the MCP tests = 88. `L99` in `test_privacy_doc_law.py:220` is a test of the marker checker, not a law. README says 48, see section 12. |
| Resource types | **18** | section 4 |
| Privilege-escalation paths (pathfinding.cloud) | **92** | `len(backend/app/data/pathfinding_paths.json["paths"])`; source `https://github.com/DataDog/pathfinding.cloud`, commit `ecc3d092...`, Apache-2.0 |
| Scanner check reads | **55** | `len(backend/app/data/scanner_check_reads.json)` |
| Native reason codes | **32** | section 2.1 (old site: 30) |
| Prowler check metadata files | **21** | `ls backend/app/data/third_party/prowler/checks/*.metadata.json \| wc -l` |
| Scanner severity crosswalk entries | **21** | `len(backend/app/data/scanner_severity_crosswalk.json)` |
| MCP tools | **27** (README says 24) | `grep -c 'name: "emfirge_' mcp/src/tools-registry.ts` = 27; new vs README: `emfirge_check`, `emfirge_context` |
| Manifest commands | 12 (10 CLI top-level commands) | `be/cli_manifest.py`; `emfirge --help` |
| Outside-world service table | 7 entries, 9 botocore service names | section 2.2 |
| Backend full test run | 3243 passed, 3 skipped, 1 xfailed | section 11 |

### 4.2 Lens and sources facts (for "What each check is built from")

Derived from the code, not from docs. Lenses are internal groupings named in the README: Security, Dependencies, Compliance, Cost, Limits, Yours (planned).

| Check | Engine parts | Data sources | Source in code |
|---|---|---|---|
| Data | Dependencies lens: the delete lens (`delete_lens.py`) and `recovery_removals` in `verdict.py`: deleted data stores compared with surviving snapshots and backups; versioning, backup retention and point-in-time recovery turned off | Collected EBS volumes and snapshots, RDS snapshots and backup settings, S3 versioning, DynamoDB table settings (collection keys `ebs_snapshots`, `ebs_volumes`, `rds_snapshots`, `dynamodb`) | `be/aws_check.py:40-46`; `be/check_facts.py:355-387`; `be/verdict.py` `recovery_removals` |
| Exposure | Security lens: ingress-rule diff (`exposure.py`), internet-reachability graph over security groups, network ACLs, route tables and gateways (`egraph.py`), S3 public-access evaluation (`s3_public.py`), role trust to external accounts, RDS default ports (`rds_ports.py`); opt-in IAM Access Analyzer policy checks (can only make the verdict stricter) | Collected network configuration, S3 policies and role trust; AWS documentation ("meaning of public" for S3, default RDS ports); AWS IAM Access Analyzer (opt-in, your role) | `be/check_facts.py:389-414`; `be/aws_check.py:61-86,156-174`; `be/s3_public.py:1-8`; `be/rds_ports.py:1-6`; `be/policy_checks.py:1-8` |
| Money | Cost lens (`cost.py`): provisioned list-price cost before and after, per resource and total | AWS Price List (Bulk API values, us-east-1 on-demand, vendored in `backend/app/data/aws_prices.json`, generated by `scripts/generate_prices.py`) | `be/cost.py:1-30`; `be/aws_check.py:326`; `be/check_facts.py:416-440` |
| Availability | Dependencies lens: the dependency graph walked up to 10 levels, lost dependencies and internal paths, lost internet paths, action-level permission facts for roles (`aws_permissions.py`, `permission_facts.py`), the CloudFront Host-header fact (`cloudfront_check.py`), schedules disabled or deleted, recent use over a 90-day window | Collected network interfaces and IAM role last-used; policy_sentry IAM action data; AWS CloudFront documentation; opt-in CloudTrail and CloudWatch evidence | `be/check_facts.py:467-521`; `be/aws_check.py:40-47,109-147`; `be/aws_permissions.py:1-11`; `be/delete_lens.py:14`; `be/cloudfront_check.py:1-25` |
| Control | Security lens: admin access added or removed (roles and users), privilege-escalation paths added (`iam_escalation.py`), S3 access logging, account-level settings (CloudTrail, GuardDuty, KMS, Config), permissions added | pathfinding.cloud escalation paths (92); policy_sentry IAM data; collected IAM roles and users, S3 logging, CloudTrail, GuardDuty, KMS and Config settings | `be/aws_check.py:50,65-86,150-190`; `be/iam_escalation.py:1-2,12`; `be/check_facts.py:523-534` |
| Outside world | The per-service table (`aws_outside_world.py`, hand-written, each entry cites AWS docs), EventBridge Scheduler schedule changes, unmodeled plan actions | AWS documentation URLs per entry; collected EventBridge Scheduler schedules (collection key `scheduler`) | `be/aws_outside_world.py:49-93`; `be/aws_check.py:221-277`; `be/check_facts.py:536-576` |

Not part of the six checks: the Compliance lens (`context --compliance`, CIS 1.5 and SOC 2 from Prowler) and the Limits lens (`capacity` reason in the verdict; AWS default quotas as of 2026-09-15, `be/limits.py:14`).
Lens status (README table, `README.md:57-66`): Security live, Dependencies live, Compliance live, Cost early (us-east-1 only), Limits early, Yours planned.
Sources table: pathfinding.cloud (IAM escalation paths), policy_sentry (IAM access levels / action catalog: `be/aws_actions.py:28`, `be/iam_classifier.py:51`), Prowler (CIS 1.5 and SOC 2 control lists, scanner severities), AWS API models via botocore (field catalog: `be/field_catalog.py:1-12`) and the AWS Price List, Checkov (advisory scanner; Trivy off).

---

## 5. Escalation paths, scanners, other engine numbers

See 4.1. Also: recent-use window 90 days (`be/delete_lens.py:14`); dependency walk depth 10 (`be/check_facts.py:38`); evidence and policy-check caps: 50 resources / 50 policies (`be/evidence_models.py:10`, `be/policy_checks.py:21`); policy checks about $0.002 a policy (`be/policy_checks.py:22`); in-use evidence sources `cloudtrail_events`, `cloudwatch_metrics` (`be/evidence_models.py:9`).

Limits in the engine (code defaults, overridable by server environment; the production values are not in the repo): 5 scans per AWS account per day (`DAILY_SCAN_LIMIT`, `be/main.py:343`; whitelisted accounts exempt, `be/main.py:77-79`); 30 branch requests per minute (`be/main.py:160-182`, env `EMFIRGE_BRANCH_RATE_LIMIT`); 10 open branches per base analysis (`be/branches.py:92`); 3 breach simulations a day per account (`be/main.py:903`).

---

## 6. Privacy and security: what is true now

`PRIVACY.md` was rewritten on 2026-11-08 and now matches the code (law L71h checks it against the database tables, `backend/tests/test_privacy_doc_law.py`).

| Claim | True now? | Source |
|---|---|---|
| Retention: "There is **no automatic expiry yet**. Nothing is deleted because of its age. There are no sweeps and no S3 expiry rules in the code." No retention period is promised. | The old site said "PRIVACY.md describes a 90-day retention period": **false**, PRIVACY.md no longer says that. | `PRIVACY.md:72-75` |
| `purge` (`POST /privacy/purge`, run with `npx @emfirge/mcp purge --role-arn ARN`) re-assumes your role to prove you control the account, then deletes in one transaction every table keyed to the account: `analysis_logs`, `drift_events`, `simulation_logs`, `feedback`, `llm_usage`, `account_bindings`, `account_binding_events`, plus branches and their children (`branch_logs`, `branch_owners`, `plan_logs`, `branch_evidence_logs`, `branch_policy_check_logs`) and the S3 scan reports; it returns counts per table plus `s3_objects`. Not purged (keyed to your login, not the account): `projects`, `api_keys`, `supabase_identities`, and the legacy GitHub tables `tf_resources`, `ci_api_keys`; email to remove. A test fails if a table is added without a purge-or-keep choice. The MCP command then deletes `~/.emfirge/tokens.json` but not `credentials.json`. It stops without sending anything if you are not signed in. **Old site: purge "does not yet remove branches, submitted plans, evidence or policy checks" is now false.** `purge` is not an `emfirge` command. | `be/privacy.py:36-70`, `be/main.py:4962-4985`, `PRIVACY.md:77-98,230-257`, `mcp/src/installer.ts:538-610`, `mcp/src/purge.test.ts`; laws L71a, L71i |
| Discarding a branch **deletes** the branch and its plans, evidence and policy checks. **Old site: "marks it closed, does not delete its data" is now false.** | `be/branches.py:561-566,594`; `PRIVACY.md:118-121`; law L71b (`backend/tests/test_privacy_discard_laws.py`) |
| The server keeps only the **sha256** of an uploaded plan, never its text (older stored text is blanked at startup). **Old site: "text of a Terraform plan ... is kept as submitted" is now false.** | `PRIVACY.md:112-114`; `mcp/src/tools/plan-verdict.ts:46-48`; law L71c |
| API keys and CI keys are stored as hashes. | `PRIVACY.md:110-111`; law L71d |
| Server logs carry no account IDs, resource IDs, ARNs, bucket / role / repo names; errors are logged as the error type. | `PRIVACY.md:157-159`; law L71g (`backend/tests/test_privacy_logs.py`) |
| For the MCP and CLI the backend never calls an LLM (`X-MCP` header or raw flag); `/simulate/component` honors it. The web dashboard and plain `curl` do send real resource IDs to Gemini or Claude. | `PRIVACY.md:163-186`; law L71e |
| What a scan keeps for newer resource types: CloudFront origin custom header values are **withheld** (only the fact that they exist); EventBridge Scheduler target `Input` payload is **withheld** (only a has-input flag); DynamoDB table items are never read; Lambda keeps names of secret-looking environment variables, never values; EC2 user data is one yes/no flag. | `PRIVACY.md:35-61` |
| Tokenization modes (CLI default `strict`): strict replaces every recognized identifier (ARNs incl. DynamoDB, SQS, SNS, Scheduler, CloudFront, WAF; instance, security group, EIP, volume, subnet, VPC, ENI, route table, gateway and ACL IDs; IPs; account IDs; bucket, role, user, function and secret names; CloudFront aliases, origin domains, path patterns; Scheduler target ARNs, also before / after values in a branch diff). balanced keeps generic network topology ids (volume, subnet, VPC, network interface, route table, internet gateway, NAT gateway, ACL) raw. off replaces nothing; presigned URLs still lose their credentials. **Resource tag values are hidden in strict and balanced** (tag keys stay readable). | `PRIVACY.md:188-215`; `mcp/src/tokenize.ts:101-129`; law L81 (`mcp/src/tokenize-leaks.test.ts`), commits `eb22425`, `9f072a1` |
| Every CLI answer goes through the same redaction (`redactDeep`) and token expansion as the MCP tools, so branch and check output are tokenized in strict mode too (tests: "branch output is masked", "check ... masks the answer", L81a-c). | `mcp/src/cli/generic.ts:128,134`, `mcp/src/cli/run.test.ts:174,253,292`; `mcp/src/tokenize-leaks.test.ts:46,92,103` |
| The token map is `~/.emfirge/tokens.json` on your machine, never uploaded; dir 0700, files 0600 (tightened on load). | `PRIVACY.md:217-226`; `mcp/src/tokenize.ts:18-19`; law L71f |
| The read-only role: AWS-managed `SecurityAudit` plus extra reads: CloudWatch `GetMetricStatistics` / `GetMetricData` (usage evidence), Access Analyzer `CheckNoPublicAccess` / `ValidatePolicy` (opt-in), and a list of List / Describe / Get actions for Budgets, GuardDuty, Secrets Manager (`ListSecrets` only: names), Lambda, IAM role policies, ECS task definitions, WAFv2, SNS, KMS (incl. key rotation status), AWS Config, CloudFront (distribution config, tags, cache policies, origin request policies, origin access controls), API Gateway v2, SQS, **EventBridge Scheduler (`ListSchedules`, `GetSchedule`)**. Trust: the Emfirge account with your ExternalId (min 32 chars). No write action. Role name `EmfirgeReadOnlyRole`; the connect link names the stack `EmfirgeReadOnlyStack`. | `iam-role.yaml:15-92` (Scheduler at `:80-81`), `mcp/src/tools/setup.ts:45-50`, commit `e19ba20` |
| The template does not list `cloudtrail:LookupEvents`; PRIVACY.md says the opt-in evidence read uses it and marks evidence `denied` if the role lacks it. Whether `SecurityAudit` includes it was not checked here. | `iam-role.yaml:46-90`; `PRIVACY.md:123-132` |
| Credentials: temporary STS credentials, 1 hour, held in memory, never stored; presigned report links expire after 1 hour. | `PRIVACY.md:19-23`; `SECURITY.md:31-32,35` |
| Certifications: none claimed in code or docs. Licenses: engine AGPL-3.0, MCP adapter and CLI Apache-2.0. Vulnerability reports: ansh@emfirge.cloud, acknowledge within 48 hours, initial assessment within 7 days. | `SECURITY.md:5-17`; `cli/package.json:20`; `mcp/package.json` license; `README.md` |
| Emfirge is advisory today: a branch is a model; a pass is evidence, not a guarantee; nothing in the code blocks a live apply. | `README.md:101-103`; `mcp/README.md` (Advisory boundaries) |

---

## 7. Not built (the code says so, so the site must too)

| Thing the v7 site described | Code reality | Source |
|---|---|---|
| `emfirge request` (ask the owner, `--wait`, `request status`) | Not built (v2). Exits 1, code `not_built`, no network. | `mcp/src/cli/run.ts:153-158`; `docs/AGENT-GUIDE.md:21,33` |
| `emfirge.md` (intent file, read as context, enforced as boundaries) | Not built. `context marks` says "emfirge.md is not built yet; only resource tags are shown". | `be/context_query.py:40` |
| Owner thresholds and "tell vs ask" defaults ($5 a month etc.) | No such code exists. Nothing asks an owner anything. | repo-wide grep: no code for thresholds; `be/check_facts.py` has no verdict or ask |
| `report` verifies against CloudTrail | `report --verify` checks the hash binding on the server only (input hash, base snapshot, branch revision, verdict id). No CloudTrail read. | `be/main.py:2078-2175` |
| `emfirge status`, `privacy`, `tokens`, `purge` | Subcommands of `npx @emfirge/mcp`, not of `emfirge`. | `mcp/src/index.ts:38` |
| `connect` prints a link, detects the role, "reading us-east-1 ... 214 resources" | `connect` prints the deploy link and steps; you paste the RoleArn back; the first scan is `context --refresh --role-arn ARN --region R`. | `mcp/src/tools/setup.ts:58-78`; `docs/AGENT-GUIDE.md:96-98` |
| Control and Outside-world checks have no reason codes | Still true for the verdict (no codes); they are real answers in `check` with their own fact kinds. | section 2 |

---

## 8. MCP adapter (for the CLI page)

`@emfirge/mcp` (0.2.9 in the repo; npm latest 0.2.3) exposes **27 tools** over stdio: `emfirge_login`, `emfirge_link_project`, `emfirge_logout`, `emfirge_setup_help`, `emfirge_scan`, `emfirge_get_findings`, `emfirge_attack_paths`, `emfirge_verify_fix`, `emfirge_check_compliance`, `emfirge_simulate_breach`, `emfirge_create_branch`, `emfirge_compare_branches`, `emfirge_apply_change`, `emfirge_get_branch`, `emfirge_fork_branch`, `emfirge_branch_diff`, `emfirge_branch_verdict`, `emfirge_check`, `emfirge_plan_verdict`, `emfirge_branch_handback`, `emfirge_rollback_branch`, `emfirge_rollback_branch_to_count`, `emfirge_discard_branch`, `emfirge_list_branches`, `emfirge_in_use_evidence`, `emfirge_policy_checks`, `emfirge_context` (`mcp/src/tools-registry.ts:69-300`, `grep -c` = 27). The tool names stay; the CLI is built on the same handlers (`mcp/src/cli/support.ts:25-32`). The old-tool -> command map is in `docs/AGENT-GUIDE.md:48-78`. Install: `npx @emfirge/mcp install`, or the manual config with `"args": ["-y", "@emfirge/mcp"]` and `EMFIRGE_PRIVACY` (`mcp/README.md:13-33`).

---

## 9. Real changelog (merged PRs and notable commits)

Merged PR titles and dates (GitHub REST `gh api repos/theanshsonkar/emfirge/pulls?state=closed`, 2026-11-08; the local merge commits are all "Merge pull request #N from .../dev", so the titles come from the API):

| Date | PR | Title |
|---|---|---|
| 2026-11-08 | #85 | Harness v1: context, check facts, the emfirge CLI, and audit fixes |
| 2026-11-07 | #84 | Priority 0 privacy, collector scan fix, and real-world ingest work (dev -> main) |
| 2026-10-26 | #83 | Scanner: skip checks that read unmodeled attributes (L66) |
| 2026-10-25 | #82 | Scanner coverage: IAM, KMS, CloudTrail, Lambda, VPC; fix skipped SG checks (L65) |
| 2026-10-25 | #81 | Scanner input: send collected settings, skip checks on unknown input (L64) |
| 2026-10-25 | #80 | Scanner severities from Prowler check metadata (L63) |
| 2026-10-24 | #76-#79 | Scanner worker and opt-in AWS policy checks (L61, L62); deploy scanners on; docs |
| 2026-10-23 | #75 | Sourced facts and scanner groundwork (L56-L60) |

Notable commits since Oct 26 (`git log --date=short 1c10452..HEAD --no-merges`), in plain English:

- 2026-11-08: the `emfirge` command became its own npm package, bundled into one file (`e9425c7`); its commands run from the server's manifest (`2c153f6`, `8dff40d`, L88); exit codes 400/422 -> 1, 409 -> 5, 429 `rate_limited`, and AWS CLI shorthand is refused with a clear message (`71a7b47`); the package was named `emfirge` (`08f186c`).
- 2026-11-08: check lists every changed setting, judged or named as not judged (`d0a9456`, `ceb0850`, L87).
- 2026-11-08: outside world stays per service (`c67e0eb`, `b9ea793`, L83); a never-granted permission is unknown, not a fact (`86a8c6c`, L84); schedule gaps closed (`3902a8e`, L85); DynamoDB item count 0 is unknown, never a recovery point (`2344fa8`, `988e6a3`, L80m, L86); CloudFormation property removal is a reset or a named unknown (`4112873`, L82); CloudFormation security group egress diffed like ingress (`4361d9e`); CloudFront Host fact, IAM case matching, endpoint-prefix fallback (`616bd6b`).
- 2026-11-08: four privacy leaks in MCP/CLI output closed (`eb22425`, L81); PRIVACY.md covers CloudFront, Scheduler, DynamoDB (`87fa691`).
- 2026-11-07: read-only context query, `POST /context` (`c4a77a9`, L73); check facts, `GET /branches/{id}/check` (`2214c05`, L74); the CLI with six verbs and the agent guide (`8011e3c`); MCP `emfirge_check` and `emfirge_context`.
- 2026-11-07: branches model EventBridge Scheduler schedules (`fd18613`, L75), a schedule that starts running is an outside-world fact (`e76a325`, L77), CloudFront distributions with the Host-header availability fact (`f4218fc`, L78), DynamoDB tables in the data answer and delete safety (`139aa02`, L80), role permission facts (`8c9c4de`), an offline rehearsal of four real incidents (`161cfc7`, L79).
- 2026-11-07: privacy: purge covers every table (`7c8399f`, L71a); discard deletes (`5bfc4c1`, L71b); plans keep only a sha256 (`36e262e`, L71c); CI keys hashed (`a083d10`, L71d); no LLM for `/simulate/component` from the MCP (`d3e0997`, L71e); private token files (`da1db3f`, L71f); no customer identifiers in server logs (`c1f6e55`, `896855c`, L71g); PRIVACY.md checked against the code (`b66857a`, L71h); MCP purge needs sign-in (`d5c5fb7`, L71i); a real scan finishes (`969c8f2`, L72).
- 2026-10-26: Terraform ingest for IAM role identity, IAM permissions, S3 settings, Lambda and EC2 settings (`c8235c7`, `baf2429`, `128fba7`, `5638414`; L67-L70); real-world evaluation corpus and graders (`ab10378`, `33d6d14`, `fed3c98`, `a88b1de`).

---

## 10. Real-world scorecard (NOT for the site; Ansh's decision)

Two scorecards exist. Same corpus (78 entries: 77 misconfiguration / attack-path entries and 1 negative), same locked answer keys (sha256 `e4a1a829fb0e2ca471b594b30c2b88567ccb9afb87272afc30c30f3a6bca0b29`), terraform 1.15.9, scanners on.

| Run | caught | missed_ingest (could not read the resource) | missed_logic (read, no matching evidence) | negatives correct | Source |
|---|---|---|---|---|---|
| First scoring, branch `origin/eval/realworld` (tip `fed3c98`, 2026-10-26) | **11 / 77** | 36 | 30 | 1 of 1 | `git show origin/eval/realworld:backend/tests/data/realworld/SCORECARD.md` |
| After the four ingest fixes (L67-L70), in `main` (`a88b1de`, 2026-10-26) | **14 / 77** | 15 | 48 | 1 of 1 | `backend/tests/data/realworld/SCORECARD-after-ingest-fixes.md:7-12` |

Notes recorded in the scorecards: (a) after the fixes, role entries stay `missed_logic` although Emfirge reports the escalation, because the harness records a created role by ARN while the engine names it by name: "an id-bookkeeping gap in the harness/grader, not an ingest gap"; (b) all 10 TerraGoat S3 entries are `missed_logic` in both runs because Terraform leaves unconfigured computed S3 blocks unknown at plan time; (c) the clean set: `terraform-aws-vpc` warn, `terraform-aws-s3-bucket` warn, `terraform-aws-rds` block (1 Critical, backups disabled, which the example sets itself: arguably a true finding), `terraform-aws-ec2-instance` warn with 12 Checkov IMDSv1 false alarms in the first run and 0 after. The HEAD tree also has the older `SCORECARD.md` unchanged. The catch rate is low (14 of 77, 18 %); not on the site.

---

## 11. Verification of the counts

- `cd backend && python3 -m pytest --collect-only -q | tail -3` -> `3247 tests collected`.
- `cd mcp && npm test` -> `# tests 206`, `# pass 206`, `# fail 0`.
- policy_sentry IAM action count (how-it-works says "more than 20,000"): `from policy_sentry.querying.all import get_all_actions; len(get_all_actions())` in the backend venv = 20455 (the code comment in `be/aws_outside_world.py:8` says about 15k).
- Full backend test run, `cd backend && python3 -m pytest -q -p no:warnings -p no:cacheprovider` on 2026-11-08: `3243 passed, 3 skipped, 1 xfailed in 524.27s` (3,247 collected).
- The L88g law (bundled manifest == server manifest) was re-checked directly: `True`.

---

## 12. Contradictions: code vs README and docs

| Where | Says | Code says |
|---|---|---|
| `README.md:96` | "There are 48 [laws] so far" | L1 to L88 are all present in the tests: 88 laws (87 in `backend/tests`, L81 in `mcp/src`). |
| `README.md:79` and the install text | install with `npx @emfirge/mcp install`; no mention of the CLI | the CLI is `npx emfirge login` / `npx emfirge connect`; the MCP install still works. |
| `README.md:109-125` (resource table) | 14 types; IAM user add only; no CloudFront, DynamoDB, Scheduler, instance profile | 18 types; IAM user add + modify; CloudFront modify; DynamoDB modify + delete; Scheduler add / modify / delete; instance profile add. |
| `mcp/README.md:39` | heading "Tools (24)" (the body lists 25 names) | the registry has 27 tools; the README lacks `emfirge_check` and `emfirge_context` (`comm` of registry names against README names). |
| `mcp/README.md:76-83` and `README.md` | the CLI section lists `status`, `privacy`, `tokens`, `purge` as the CLI | they are `@emfirge/mcp` subcommands, not `emfirge`. |
| `be/cli_manifest.py` (`branch rollback` summary) | "Clear the changes on a branch." | `rollback_last` removes the **most recent** change only (`be/branches.py:447-452`); `rollback-to --count 0` clears. The site follows the code. |
| `mcp/src/cli/verbs.ts` summary of `request` | "NOT BUILT YET (v2)" | consistent; the site says so (v7 site described it as built). |
| `docs/AGENT-GUIDE.md:91` | exit 5 conflict is "the branch changed since you read it, or a limit was hit" | only stale-revision conflicts are HTTP 409. Hitting the open-branch limit is HTTP 429, so exit 4 `rate_limited` (`be/main.py:1615,1688`). The site follows the code. |
| `be/main.py:2204-2206` comment says scanners are off | code default `EMFIRGE_RUN_SCANNERS=0` | production sets `EMFIRGE_RUN_SCANNERS=1` (`.github/workflows/deploy.yml:76`), so "Checkov runs on every verdict" is true on the hosted engine, false for a default self-hosted run. |
| `landing` v7 site | exit codes 0/1/2/3 = pass/warn/block/error | 0-6 as in 1.6; a verdict never changes the exit code. |
| `landing` v7 site | `@emfirge/cli` package | the package is `emfirge`; `@emfirge/cli` does not exist on npm. |
| `landing` v7 site | check prints a BLOCK / PASS verdict line | `check` prints six answers and no verdict; the verdict is `check --verdict` and `try`. |
| `landing` v7 site | 14 types, 24 tools, 2,432 / 102 tests, 48 laws, 30 reason codes | 18, 27, 3,247 / 206, 88, 32. |
| `landing` v7 site `/security` | 90-day retention in PRIVACY.md, purge incomplete, discard only closes, plan text kept | all four are false now (section 6). |
| `PRIVACY.md` vs `iam-role.yaml` | evidence uses `cloudtrail:LookupEvents` | the template does not list it (it may come from `SecurityAudit`; not checked). |
| `backend/BRANCH-CLI.md` | a separate Python client `backend/scripts/emfirge-branch.py`, errors exit 2 | unrelated to the npm `emfirge` command; not mentioned on the site. |


---

## 13. Who does what (added for site v9, 2026-11-08)

Question: Ansh's product insight is that people do not use the CLI, their agent does. Which steps need a human, and what can the agent do alone?
Everything here was read from the code; line numbers are in the repo as of this commit. "Agent" means an AI agent that can run shell commands on the machine where `npx` runs.

### 13.1 The four questions

| Question | Answer | Source |
|---|---|---|
| Does `npx emfirge login` need a human? | **Yes, a browser approval. It is not a device code.** `login` starts a one-time web server on `127.0.0.1` (random port) and opens the machine's default browser to it (`open`, `xdg-open` or `cmd start`). The page offers "Continue with GitHub" and "Continue with Google"; the human signs in there (PKCE through Supabase) and is redirected back to the local server, which stores the refresh token. It waits up to 5 minutes (300 000 ms), then fails with exit 2 (`not_signed_in`, "Sign-in did not finish. Run: emfirge login"). The agent can start it and can print the address (the CLI prints `Sign in with GitHub or Google. Opening your browser; if it does not open, go to http://127.0.0.1:PORT/` on stderr), but it cannot complete it: only the person who owns the GitHub or Google account can. There is no device-code flow and no `--code` option in the code. | `mcp/src/auth/login.ts:29-138` (server on 127.0.0.1, `/start/github`, `/start/google`, callback, 300 000 ms timeout, `EMFIRGE_NO_BROWSER`); `mcp/src/cli/run.ts:45-58` (message and exit 2); `cli/README.md:5-9` |
| What does the agent get after the human approves? | A refresh token saved in `~/.emfirge/credentials.json` (folder 0700, file 0600) on that machine. Every later command reuses it silently and refreshes the access token itself. The human is needed again only if the sign-in expires (refresh answers 400 or 401: "Your sign-in has expired. Please sign in again.") or the file is removed (`emfirge logout`). | `mcp/src/auth/credentials.ts:11-31`; `mcp/src/auth/session.ts:25-62`; `mcp/src/cli/run.ts:144` (`setInteractiveLogin(false)`) |
| What if nobody has signed in? | Every other command fails fast with exit 2 and `Not signed in. Run: emfirge login (or set EMFIRGE_API_KEY).` The CLI never opens a browser by itself and never waits for one. The agent must run `emfirge login` and wait for the human. | `mcp/src/client.ts:62-67`; `mcp/src/cli/run.test.ts:375` |
| Is there a way around the browser? | `EMFIRGE_API_KEY` skips browser sign-in (the key is the bearer token). **No command or endpoint in the code issues an API key to a user**: `create_api_key()` exists in `backend/app/auth.py:29` but nothing in `main.py` or the CLI calls it. So today a key is something the operator hands out; a person cannot get one themselves. Treat the key as a CI and self-host route, not the normal setup. | `docs/AGENT-GUIDE.md:99`; `mcp/src/client.ts:55-60`; `backend/app/auth.py:19-44`; `grep create_api_key backend/app` finds only the definition |
| Does the browser have to be on the agent's machine? | **Yes, in practice.** The sign-in page lives at `127.0.0.1` on the machine running the CLI, and the redirect returns to the same address. If the agent runs in a remote or cloud sandbox and the human's browser is on another computer, the address cannot be reached and the code has no other flow. `EMFIRGE_NO_BROWSER=1` only stops the CLI from opening a browser; it still waits for the callback. | `mcp/src/auth/login.ts:37,40,131` |
| What does signing in create? | On the first authenticated call the backend creates a project for the signed-in identity with its own random `ExternalId` (`secrets.token_urlsafe(32)`). `connect` reads it from `GET /project`. So `connect` only works after `login`. | `backend/app/auth.py:112-130`; `backend/app/main.py:495-506`; `mcp/src/tools/setup.ts:45-52` |
| Who creates the read-only role (the CloudFormation one-click link)? | **The human, in their own AWS console.** `emfirge connect` only prints the link (`deploy_url`) with the template, `stackName=EmfirgeReadOnlyStack`, the trusted account and the person's ExternalId pre-filled. A person who is signed in to AWS opens it, ticks "I acknowledge that AWS CloudFormation might create IAM resources", clicks **Create stack** (about 30 seconds), and waits for `CREATE_COMPLETE`. Nothing in emfirge creates the stack, and emfirge has no access to the account until the role exists. The tool text that `connect` returns tells the assistant to "Tell the user these next steps" and to "paste the URL above verbatim in your reply". (An agent that happens to hold its own AWS write access could in principle deploy `iam-role.yaml` itself; no emfirge command or document does or describes this, so the site does not claim it.) | `mcp/src/tools/setup.ts:45-78`; `mcp/src/cli/run.ts:38-43`; `iam-role.yaml:1-30,89-92` |
| How does the role ARN reach `connect`? | **It does not.** `connect` takes no ARN and does not detect the role. The human copies `RoleArn` from the stack's **Outputs** tab and pastes it to the agent (setup text step 4: "Paste the RoleArn back here and the scan will run"). The agent then passes it to the scan: `emfirge context --refresh --role-arn ARN --region REGION`. `--region` is required, there is no default, and the tool says: "If the user gave a role ARN but no region, ASK them which region to scan ... Do not guess." The ARN must match `arn:aws:iam::<12 digits>:role/<name>`. The CLI does not save the ARN (local state is `credentials.json` and `tokens.json` only), so the agent keeps it; `check --evidence --accept-estimate ID --role-arn ARN` needs it again. | `mcp/src/tools/setup.ts:70`; `mcp/src/cli/overrides.ts:64`; `be/cli_manifest.py:71,85-87,101`; `mcp/src/tools/scan.ts:14-31`; `be/cli_manifest.py:206,218`; `mcp/src/auth/credentials.ts`, `mcp/src/tokenize.ts:18-19` |
| After that, can the agent do everything? | **Yes, for emfirge itself.** `context` (including `--refresh`), `branch`, `try`, `check`, `report` need only the saved sign-in and the role ARN. No other human approval is built. The agent opens a branch, tries a change in any of five formats, reads `check`, fixes its own plan and tries again, rolls back or discards, and gets the hand-back, all with no person in the loop. It also applies the real change itself, with its own AWS access: emfirge never writes to the account. | `mcp/src/cli/run.ts:144-175`; `docs/AGENT-GUIDE.md:14-27,96-99`; `README.md:101-103` |

### 13.2 What stays with the human (and what is only a convention)

| Item | Who | What the code says | Source |
|---|---|---|---|
| Give the agent emfirge (the prompt) | human, once | Nothing installs itself: the agent runs `npx -y emfirge ...` (Node.js 20 or later). | `cli/README.md:14-16`; `cli/package.json:23-25` |
| Approve sign-in | human, once (again only if it expires) | See 13.1. | `mcp/src/auth/login.ts` |
| Create the role, give the agent the ARN and the region | human, once | See 13.1. Revoke by deleting the stack. | `mcp/src/tools/setup.ts:62-76` |
| Agree to a cost before `check --policy` or `check --evidence` | **human, by convention** | The CLI prints an estimate and sends nothing until it is run again with `--accept-estimate ID` (and `--approve` for policy). The guide says to do that "only after the owner agrees". Nothing in the code can tell whether a person agreed; an agent can pass the flags alone. The setup prompt therefore tells the agent to ask. | `docs/AGENT-GUIDE.md:77-80`; `mcp/src/cli/overrides.ts:72-80`; `be/cli_manifest.py:206-218` |
| Decide to apply a change | **human, by convention** | `emfirge request` (ask the owner) is not built. Emfirge is advisory: a `block` or a failed check stops nothing for an agent that has its own AWS credentials. The only guard is the instruction to the agent ("never apply a change that did not pass") and whatever permissions the agent's own tool gives it. | `mcp/src/cli/run.ts:153-158`; `README.md:101-103`; `landing` FACTS section 7 |
| Read the hand-back | human | `report` returns the hand-back (exact calls, `input_sha256`, branch revision, verdict, `verdict_id`); `report --verify` checks the binding. The agent summarizes it for the person. | `be/main.py:2111-2175`; `mcp/src/cli/overrides.ts:81` |
| Get the real names back from tokens | human, optional | In the default `strict` mode the agent sees tokens (`SG_001`) and never the real identifier; the map is `~/.emfirge/tokens.json` on the machine, and `npx @emfirge/mcp tokens` lists it. | `mcp/src/tokenize.ts:18-19`; `landing` FACTS section 6 |

### 13.3 Other paths, for completeness

- MCP: `npx @emfirge/mcp install` is a human command. It detects clients, may prompt for a privacy mode on first install, patches their config and says "Restart your MCP client(s)". After that the agent calls `emfirge_login` (same browser approval, URL returned in the tool text), `emfirge_setup_help` (the same deploy link), `emfirge_scan` and the rest. `mcp/src/installer.ts:402-470`; `mcp/src/tools/login.ts:11-32`.
- Self-host: with `EMFIRGE_REQUIRE_AUTH` off the server accepts every caller as `self-host` and no sign-in is needed. `backend/app/auth.py:99-103`; `README.md` (self-host).
- CI: `EMFIRGE_API_KEY`, see above.
- `cli/README.md:7-9` says "You run two commands, once: `npx emfirge login`, `npx emfirge connect`". That is a person typing them. Site v9 says instead that the agent runs both and the person approves the browser sign-in and the CloudFormation click; the CLI behaves the same either way.

### 13.4 Not verified here

- Whether every agent's shell tool can keep `emfirge login` running for up to 5 minutes (the CLI waits that long; an agent whose tool call times out sooner has to start it in the background or run it again). The site tells the agent to wait for the person, nothing more.
- How an operator issues an API key today (no code path). Written on the site as `[TODO Ansh]`.
- Whether a person's sign-in ever expires in practice (the refresh token's lifetime is set at the sign-in provider, not in this repo).
