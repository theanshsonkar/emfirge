# Emfirge marketing site: design spec

Status: draft, not live. A separate marketing site, not the docs (`site/`).
Copy is written **as if the CLI and the harness v1 are fully built** (Ansh's call, 2026-11-07).
Before it goes live, every claim must be checked against the code (roadmap guardrail 11:
"Promise only what the code does"). Claims that are aspirational today are listed at the end.

## Positioning

- Headline: **The harness for cloud agents.**
- One-liner: Claude Code gave agents a place to write code. Emfirge gives them a place to work on your cloud.
- Core line: **Emfirge supplies the truth. Your agent supplies the intelligence.**
- Audience: solo developers and small teams with one AWS account who already use coding agents
  (Claude Code, Codex, Cursor, Gemini CLI, Kiro, Cline...).
- Product shape: a CLI (`npx @emfirge/cli@latest`) that any agent can run from a shell. MCP is an extra adapter.
- Never: "we scan your cloud", "AI-powered", "guarantee". Emfirge has no AI inside; it is deterministic.

## Visual direction: "Forge at night"

A completely new look, unrelated to the docs site. Editorial and confident, dark-first, terminal-native.

- Background: ink `#0B0B0C`; raised surface `#141416`; hairline borders `#26262A`.
- Text: paper `#EDEBE6`; muted `#8E8C86`.
- Accent (brand): forge orange `#FF5A1F` (hover `#FF7A47`). Used sparingly: CTAs, active step, one word in a headline.
- Signal colors (only inside terminal and signal UI): pass `#3DDC84`, warn `#F5B83D`, block `#FF4D4D`.
- One light "paper" section for contrast (the comparison table): bg `#EDEBE6`, text `#0B0B0C`.
- Type:
  - Display: **Instrument Serif** (Google Fonts), large, tight leading, italics for emphasis words.
  - Body/UI: **Inter**.
  - Code/terminal: **JetBrains Mono**.
- Texture: faint dot grid (radial-gradient, 24px) on the hero, fading out at the bottom; a slow orange glow behind the terminal.
- Motion: the hero terminal types itself out line by line (respect `prefers-reduced-motion`: show the final state).
  Sections fade/slide up 12px on scroll (IntersectionObserver). Nothing else moves.
- Layout: max width 1200px, 24px gutters (16px on phones), generous vertical rhythm (120px between sections desktop, 72px mobile).
  No horizontal scroll at 360px width.
- Logo: the "e" mark from `site/public/emfirge-logo.svg`, rendered in paper color, plus the wordmark "emfirge" in Inter semibold.

## Page sections (in order)

### 1. Nav (sticky, blurred ink background)
Logo · How it works · Verbs · Safety · Docs · GitHub (icon) · button **Get started** (orange).
Mobile: logo + Get started + menu toggle.

### 2. Hero
- Eyebrow pill: `● emfirge cli v1 · AWS`
- H1 (serif, ~88px desktop / 48px mobile): "The harness for *cloud* agents." ("cloud" in italic orange)
- Sub: "Your coding agent has files, a branch, tests and a log. Emfirge gives it the same when it touches your cloud: a true model of your AWS, a branch to try changes on, and facts about what would break, before anything reaches production."
- CTAs: copyable command box `npx @emfirge/cli@latest connect` (copy button) + secondary link "Read the docs →".
- Small line under CTAs: "Read-only. Works with any agent that can run a shell."
- Right/below: **animated terminal** (the signature visual), titled `~/infra — claude`. Script:

```
you    › Clean up the unused databases in us-east-1.

agent  › $ emfirge context --type rds
         4 databases · orders-db, legacy-reports-db, analytics-db, staging-db
agent  › $ emfirge branch new cleanup-dbs
         branch #1 forked from live · 0 changes
agent  › $ emfirge try --delete rds:orders-db rds:legacy-reports-db
         2 changes on branch #1
agent  › $ emfirge check
         BLOCK
         ✗ data          orders-db has no recovery point
         ✗ availability  orders-db served 1,240 queries/day (last 30d)
         ✓ exposure · money · control · outside world
agent  › Keeping orders-db. Retrying with legacy-reports-db only.
agent  › $ emfirge check --branch 2
         PASS  · saves $41.20/mo · nothing live depends on it
agent  › $ emfirge report --applied
         recorded · verified in CloudTrail 14s later ✓
```
Color: `BLOCK` red, `PASS` green, ✗ red, ✓ green, `$ emfirge` lines in paper with the command in orange.

### 3. Works-with strip
"Works with any agent that runs a shell" then plain text names (no logos): Claude Code · Codex · Cursor · Gemini CLI · Kiro · Cline · Aider · your own.

### 4. The problem
Eyebrow "The problem". H2: "Nobody trusts an agent with their cloud. For good reason."
Three cards:
1. **It can't see what's live.** An agent reading your AWS sees resources, not that `orders-db` takes 1,200 queries a day or that the schedule was paused on purpose.
2. **It can't try before it does.** Code has branches and tests. The cloud has prod. Every `aws` command is the real thing.
3. **You can't see what it did.** A wall of API calls, no record of what it meant to do, no check that it did what it said.

### 5. The comparison (light paper section)
H2: "Coding agents got a harness. Cloud agents didn't. Until now."
Two-column table, "Coding harness" vs "Emfirge":
| Files | **Context**: a queryable model of your cloud: what exists, what's live, what depends on what |
| A git branch | **Branch**: a copy of your live AWS to try changes on |
| Tests | **Signals**: the diff, six damage answers, evidence, unknowns |
| Permissions | **Boundaries**: what needs you, what's never allowed |
| Commit log | **Record**: what happened, predicted vs actual |

### 6. The loop (How it works)
H2: "The loop is the product."
A horizontal (desktop) / vertical (mobile) step diagram, built with HTML/CSS (no images):
context → branch → try → check → signals ↺ agent fixes and retries → boundaries → agent applies → record.
The "retry" arc loops back from signals to try, drawn in orange.
Caption: "Your agent fails on a branch, reads the signal, fixes its own plan and tries again, like reading a failed test. Only what's left reaches you."

### 7. Six verbs
H2: "Six verbs. Every agent already knows how to use them."
Sub: "No SDK, no plugin. If your agent can run a shell command, it can work on your cloud."
Grid of 6 cards (3×2 desktop, 1 column mobile), each: verb in mono, one line, example command.
- `context`: Ask what's true. `emfirge context --live --deps orders-db`
- `branch`: Open, fork, compare, discard workspaces. `emfirge branch fork 1`
- `try`: Put a change on a branch: typed, AWS CLI, API, Terraform or CloudFormation. `emfirge try --terraform plan.json`
- `check`: The diff, six damage answers, evidence and unknowns. `emfirge check --json`
- `request`: Ask the owner, keep working on something else. `emfirge request "delete orders-db?"`
- `report`: "I applied it." Exact calls, bound to the verdict, verified in CloudTrail. `emfirge report --applied`

### 8. Six damage questions
H2: "Six questions about the result. Not 15,000 rules about actions."
Sub: "Emfirge doesn't judge what an agent says it's doing. It judges what the change does on the branch."
Six tiles with an icon (lucide) each:
- **Data**: Did something holding data disappear with no recovery point?
- **Exposure**: Is anything newly reachable from the internet or another account?
- **Money**: Did the monthly cost go above your limit?
- **Availability**: Did something live traffic depends on break?
- **Control**: Was access or logging lost: an admin role, a KMS key, CloudTrail?
- **Outside world**: Does it leave the cloud: support cases, quota requests, emails, domains?
Below: "Each answer either **tells** you (a line in the record, nobody waits) or **asks** you (your agent keeps working on something else)."

### 9. Facts, never fixes
Split layout. Left: H2 "Signals are facts. Your agent does the thinking." + text: "Emfirge has no AI inside. It's deterministic: the same branch always gives the same answer, and it can't be talked into a pass. A change it can't model never passes; it says what it couldn't check."
Right: a signal card (mono):
```
FAIL  availability
feed.xml → S3 (OAC) now receives the Host header
predicted: origin 404
live traffic: 1,240 req/day
source: CloudFront config · CloudWatch metrics
```

### 10. emfirge.md
H2: "Write your intent once. Every agent reads it."
Code card titled `emfirge.md`:
```
# my cloud
- prod-* is production. Never delete without me.
- The nightly-sync schedule is paused on purpose.
- Tell me about any support case or quota request.
- Budget: $30/month.
```
Text: "Plain English. Agents read it as context; Emfirge enforces the hard lines as boundaries."

### 11. Use cases ("Your agent invents the uses")
Small grid of 6 chips with one line each: Guard ("is this safe?"), Explore (two designs on two branches, compare), Clean up, Cost, Incident response, Attack (play attacker against your own IAM, then test the fix on a branch).

### 12. Built to be trusted (Safety)
H2: "Built to be trusted."
Grid of 6:
- **Read-only, always.** Emfirge never writes to your cloud. Your agent applies with its own access.
- **Private by default.** AWS identifiers are tokenized on your machine before any model sees them.
- **No silent passes.** Anything it can't model is reported, never passed.
- **Deterministic.** No AI inside. Same snapshot, same changes, same verdict.
- **Built from public data.** Checks come from AWS's own API models and price list, pathfinding.cloud, Prowler and policy_sentry, not hand-written lists.
- **Pinned by laws.** Every behavior is a property test that must always hold, e.g. *L7: the same snapshot and changes always give the same verdict.*

### 13. Get started (3 steps)
H2: "Two minutes to a safe cloud agent."
1. `npx @emfirge/cli@latest connect`: sign in.
2. One-click CloudFormation link creates a read-only role. Delete the stack any time to revoke.
3. Tell your agent: "Use emfirge before you change anything in AWS."
CTA buttons: Get started (orange) · Read the docs.

### 14. FAQ (accordion, `<details>`)
- Does Emfirge change my AWS? No. It's read-only. Your agent applies with its own credentials; Emfirge records and verifies.
- Which agents work? Any agent that can run a shell command. An MCP adapter is also available.
- Which clouds? AWS today. The core is cloud-neutral; more clouds come as adapters.
- Does my data go to an LLM? Emfirge has no LLM. Identifiers are tokenized on your machine before your agent's model sees them.
- Is a PASS a guarantee? No. A branch is a model of your cloud. A pass is evidence, and every verdict says what was checked and what wasn't.
- Is it open source? Yes. Engine AGPL-3.0, CLI Apache-2.0.

### 15. Final CTA + footer
Big serif line: "Let your agents own the cloud. *Safely.*" + command box + Get started.
Footer: logo, "The harness for cloud agents.", links (Docs, GitHub, Privacy, Security, ansh@emfirge.cloud), "Built by Ansh Sonkar".

## Links
- Docs: https://emfirge.cloud/docs
- GitHub: https://github.com/theanshsonkar/emfirge
- Privacy/Security: GitHub blob links to PRIVACY.md / SECURITY.md

## Aspirational today (verify before launch)
- The CLI, `@emfirge/cli` package name, and verb flags (CLI not built; name open).
- `request`, `report`, CloudTrail verification, `emfirge.md` boundaries (roadmap v2/PROPOSED).
- Six damage questions as signals (LEANING), consequence-fact `check` output.
- "Private by default" while PRIVACY.md audit findings (roadmap §5) are open.
- Coverage of CloudFront, DynamoDB, EventBridge Scheduler (not modeled yet).
- The numbers in the terminal demo are illustrative.
- v4: FAQ answer "there will always be a free tier for one account" (post-beta pricing) is a commitment not yet decided; the hero and tab terminal transcripts, resource names and numbers are illustrative.
- v7 (the website is the docs), written "as if built", none of it exists yet:
  - the whole `emfirge` CLI and the `@emfirge/cli` package: `connect`, `login`, `logout`, `status`, `privacy`, `tokens`, `purge`, global flags (`--json`, `--branch`, `--region`, `--revision`, `--no-color`) and the exit codes 0/1/2/3 (marked [TODO Ansh: confirm] on /cli);
  - the six verbs' flags: `context` (`--about`, `--paths`, `--findings`, `--compliance`, `--usage --approve`, `--refresh`), `branch` (`new`, `fork`, `list`, `show`, `compare`, `rollback --to`, `discard`), `try` (`--aws-cli`, `--terraform`, `--cfn`, `--aws-api`, typed `--op/--type/--id/--fields`, `--delete`), `check` (`--diff`, `--only`, `--policy-checks --approve`);
  - `request` (ask the owner, `--wait`, `request status`) and `report` (`--calls`, `--verify`, `report show`), including the CloudTrail after-check, which may need `cloudtrail:LookupEvents` added to iam-role.yaml;
  - owner thresholds and the tell/ask defaults ("Tell vs ask" on /how-it-works), and `emfirge.md` read as context and enforced as boundaries;
  - the Control and Outside-world checks (no reason codes exist in verdict.py yet) and a Money reason code;
  - `emfirge connect` printing a one-click CloudFormation link and detecting the role; "reading us-east-1 ... 214 resources" and every other terminal transcript on the new pages are illustrative;
  - the MCP adapter exposing the same verbs: today it ships the 24 tools listed on /cli;
  - the token form `acct_7f3a…` shown in the tokenization figure is illustrative (the engine's real tokens look like `SG_001`);
  - "Free while in beta": confirm it is the actual commercial position (nothing is decided about after beta).
- v7 truth notes: /security states that the 90-day retention sweep, full purge, and branch deletion are not built (roadmap §5 audit), so PRIVACY.md should be corrected to match; remove that sentence from the page when they ship.
