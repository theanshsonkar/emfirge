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
- Product shape: a CLI (`npx emfirge`) that any agent can run from a shell. MCP is an extra adapter.
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
- Logo: the fork mark (an ink trunk with a green branch curving off it) plus the wordmark "emfirge" in Geist semibold; `site/public/emfirge-logo.svg` has both. Favicon and app icons: ink tile, white trunk, green branch (`src/app/icon.svg`, `favicon.ico`, `icon.png`, `apple-icon.png`).

## Page sections (in order)

### 1. Nav (sticky, blurred ink background)
Logo · How it works · Verbs · Safety · Docs · GitHub (icon) · button **Get started** (orange).
Mobile: logo + Get started + menu toggle.

### 2. Hero
- Eyebrow pill: `● emfirge cli v1 · AWS`
- H1 (serif, ~88px desktop / 48px mobile): "The harness for *cloud* agents." ("cloud" in italic orange)
- Sub: "Your coding agent has files, a branch, tests and a log. Emfirge gives it the same when it touches your cloud: a true model of your AWS, a branch to try changes on, and facts about what would break, before anything reaches production."
- CTAs: copyable command box `npx emfirge connect` (copy button) + secondary link "Read the docs →".
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
1. `npx emfirge connect`: sign in.
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

## As-if-built list (v8, 2026-11-08)

Sections above are the original v1 spec and are superseded by DESIGN-v6.md (look) and DESIGN-v7.md (pages). Site v8 checked
every statement on every page against the merged code; the sources are in `FACTS.md`. Built and now true on the site, so
removed from this list: the CLI and its package name (`emfirge`), the verbs' flags, exit codes 0 to 6, the six damage answers
in `check` with `changed_settings`, the server-served command list, the `context` query, coverage of CloudFront, DynamoDB
and EventBridge Scheduler (18 resource types), purge and branch deletion, and the 27 MCP tools.

Still not built or not decided (the site says "not built yet" or carries a visible `[TODO Ansh]`):
- `emfirge request` (listed, exits 1 with `not_built`), the owner side of it (Tell vs ask, owner thresholds) and `emfirge.md`
  (`context marks` says it is not built). The v7 "Tell vs ask" and "emfirge.md" sections were reduced to a "Not built yet"
  section on /how-it-works; the v7 wording is in git history (commit 1c10452).
- CloudTrail verification of what was applied: `report --verify` checks the hash binding on the server only.
- Retention periods and sweeps (none exist; /security says so).
- "Free while in beta" and everything about pricing after beta; beta usage limits on the production server (code defaults only).
- Publishing: npm shows `emfirge` 0.1.1 as latest while the repo's CLI is 0.2.9.
- A law that compares a typed change with the AWS API call (L18, L19, L21 cover the CLI, CloudFormation and Terraform).
- Home placeholders: the "Writing" posts, the X handle, the status page (the footer text "All systems operational" has no source), the CLI announcement post.
- The real-world scorecard numbers are recorded in `FACTS.md` section 10 and are deliberately not on the site.

## v9 reframe (2026-11-08): the agent uses the CLI; the human gives it to their agent

Ansh's insight: people don't use the CLI, their agent does. Look, layout and graphics are unchanged; the words, the nav and one figure's
labels changed. Who does what, with sources, is `FACTS.md` section 13.

- Home: hero sub "You set it up once. Your agent does the rest."; the primary button **Give emfirge to your agent** copies the setup
  prompt (the same text as the copy bar below it, whose Claude / ChatGPT / Cursor links stay). The secondary button goes to Set up.
  The setup prompt is `SETUP_PROMPT` in `src/content/site.ts`; it is also on /quickstart/, in index.md and in every deep link.
- /quickstart/ is now **Set up** (route kept so links and `/quickstart.md` still work): only what the person does (paste, approve sign-in,
  create the role and give the agent the ARN, ask as usual), "What you'll see", and the raw commands in a collapsed "Prefer to set it up
  yourself?" block. The 4-step figure's labels follow those steps.
- /cli/ is the **Agent reference** ("CLI reference" in the rail): opening line for the human, a new "Setup, loop and rules" section from
  `docs/AGENT-GUIDE.md`, the full reference unchanged.
- Rail and mobile Menu: two mono labels, FOR YOU and FOR YOUR AGENT (CLI reference, /llms.txt, /cli.md, GitHub).
- FAQ: "Do I need to learn the CLI?" and "What do I actually do?". How it works: the loop table says what the agent does and where the person comes in.

Aspirational or unverified after v9 (also listed in `FACTS.md` 13.4):
- Sign-in needs the person's browser on the machine where the agent runs (the page is on 127.0.0.1); there is no flow for remote or cloud
  agents, and no command or endpoint issues an `EMFIRGE_API_KEY`. The Set up page shows a visible `[TODO Ansh]` about it.
- "Ask me before `check --policy` or `check --evidence`" and "never apply a change that did not pass" are instructions in the prompt.
  Nothing in the code enforces either; emfirge is advisory.
- The setup prompt has not been run end to end with each named agent. The Claude and ChatGPT deep links open a chat, which cannot run
  `npx` unless that client has a shell; the Set up page says so.
- "What you'll see" is an abridged, real-shaped example: the wording is an agent's, the reason codes, fields and hashes are from the
  engine's synthetic test account.
- Whether an agent's shell tool can keep `emfirge login` waiting for the full 5 minutes.
