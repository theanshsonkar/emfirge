# Emfirge landing v5: "go on, break it." (design spec)

Ansh, 2026-11-08: "all designs are just copies of each other, we need a unique one."
v1–v4 each borrowed a reference site's look. v5 borrows nothing: the design comes
from Emfirge's own idea. **The landing page is a demo cloud you try to break.**
Every button is something an agent might do; Emfirge tries it on a branch, answers with
the six damage facts, and live never moves. You learn the product by playing with it.
(It also fills the roadmap gap "there is no try-it-without-AWS path".)

DESIGN.md's "as if built" stance and aspirational list still apply. Earlier specs are history only.
Do not reuse any v1–v4 component or style; start the components fresh.

## Art direction: the crash-test lab

Emfirge is a **crash test for cloud changes**: you smash the change into a copy, measure
the damage, and the real car never gets a scratch. So the visual language comes from crash testing:

- **The crash-test target marker**: a circle split into 4 quadrants, alternating yellow and black
  (an SVG, `TestMark`). It is the brand's symbol. It marks the node currently under test, sits
  beside the wordmark, and is used as the favicon. Nowhere else.
- **Test reports**: results print as a numbered test sheet (`test 004`), with rows and measured values,
  and a **rubber stamp** that lands on it: `BLOCKED` (red), `PASSED` (green) or `ASK OWNER` (yellow).
  The stamp is rotated about -7°, with slightly rough ink (SVG turbulence filter on the stamp only),
  and it thumps in (scale 1.15 → 1, 140ms) when a test completes.
- **Guarded switches**: every dangerous action sits under a hinged safety cover, like a real
  "arm" switch. Click → the cover flips up (rotateX, 180ms) → the toggle throws → the test runs.
  It is playful and memorable, and says "this is dangerous, and it's safe here".
- **Branch damage on the diagram**: on the branch view, broken nodes get a red diagonal hatch
  and a dashed outline; removed nodes become a dashed ghost; new exposure draws a red line from
  an "internet" node. The **live** view never changes.

## Tokens
- `paper` #FFFFFF (page), `bench` #ECEDEE (the test bench surface), `ink` #000000, `ink-2` #4A4A4A, `ink-3` #8A8A8A, `rule` #D6D7D9
- `crash` #FFD60A: the brand yellow. It also means "**ask owner**" (caution), so yellow always means a human decides.
- `block` #E5341D (stamp red), `pass` #1F9D55 (stamp green)
- Fonts (next/font/google):
  - **Archivo** (variable, with the `wdth` axis). Display: wdth 125, weight 800, tracking -0.02em, sentence case.
    Body: wdth 100, weight 400, 17px/1.55. UI labels: wdth 100, 500, 14px.
  - **IBM Plex Mono**: reports, reason codes, the terminal, measured values.
  - No other fonts. No italics. No all-caps except the stamp words and the test number (they're printed artefacts).
- Shapes: 2px black rules and outlines (instrument-like), radii 6px for controls and 10px for panels. No soft shadows except
  the switch covers (a small hard shadow, `2px 2px 0 #000`).
- One bold place: **the bench**. Everything after it is quiet: white, black text, generous space, yellow used rarely.

## Page

### 0. The live bar (sticky, top, 40px, black)
`● live · 9 resources · 0 changes since you arrived` on the left (the dot is pass-green with a slow 2s pulse),
and on the right `caught 0 of 0` (updates after each test: how many dangerous tries Emfirge caught),
then a `get started` text link. This bar is the promise, always visible: *whatever you do below, live doesn't move.*

### 1. Header (white)
The TestMark + "emfirge" wordmark (Archivo 700); links: how it works · pricing · docs · github.

### 2. The bench (hero, the whole first screen and a bit more)
Left column (desktop ~38%):
- H1 (Archivo expanded 800, 64px; mobile 40px): "Go on. Break it."
- Body: "This is a demo cloud. Every switch is something an AI agent might do to yours. Emfirge tries it on a branch, measures the damage, and tells your agent what would break. Live never moves."
- Small: "Then give your agent the same thing: `npx @emfirge/cli connect`" (copy button).

Right column (~62%), the **bench panel** (`bench` background, 2px black outline, 10px radius), three stacked parts:

**a) The demo cloud diagram** (SVG, ~340px tall). Top-left tabs: `live` | `branch #N` (appears after the first test;
the latest branch is auto-selected). Nodes are white boxes with 2px black outlines and mono labels:
`internet` (a cloud outline, top-left) → `cdn` → `web-alb` → `api ×3` → `orders-db` (rds) and `legacy-reports-db` (rds, idle, dimmed);
plus `assets` (s3), `nightly-sync` (lambda) → orders-db, and `deploy-role` (iam). Each node shows one live metric under its name
(e.g. orders-db "1,240 q/day", legacy-reports-db "0 q/day · 90d", api "3 instances").
The node under test gets the TestMark badge. Branch damage follows the rules above.

**b) The switch panel**: 7 guarded switches in a grid (desktop 4+3, mobile 2 columns). Each: a cover, a toggle, and a 2-line label:
1. delete orders-db
2. open port 22 to the world
3. make the assets bucket public
4. give deploy-role iam:PassRole on *
5. triple the api fleet
6. ask aws for a quota increase
7. delete legacy-reports-db (this one is safe, and it should pass)
After a switch runs, it stays thrown, and its label shows its stamp color dot. A small `reset bench` text button clears everything.

**c) The test report** (white sheet, mono): shows the latest test. Header: `test 00N · <action> · branch #N · 0.4s`.
Then six rows, `question · result · measured fact · reason code` (the reason code in ink-3, small):

| switch | data | exposure | money | availability | control | outside world | stamp |
|---|---|---|---|---|---|---|---|
| 1 delete orders-db | ✗ no recovery point `data_store_deleted_no_recovery_point` | ✓ | ✓ −$96.40/mo | ✗ 1,240 queries/day `recently_used` · nightly-sync depends on it `lost_dependency` | ✓ | ✓ | BLOCKED |
| 2 port 22 | ✓ | ✗ api ×3 reachable from 0.0.0.0/0 on :22 `introduced_critical_exposure` | ✓ | ✓ | ✓ | ✓ | BLOCKED |
| 3 public bucket | ✓ | ✗ assets readable by anyone `newly_internet_reachable` | ✓ | ✓ | ✓ | ✓ | BLOCKED |
| 4 PassRole | ✓ | ✓ | ✓ | ✓ | ✗ deploy-role can become admin in 2 steps `privilege_escalation` (path from pathfinding.cloud) | ✓ | BLOCKED |
| 5 triple fleet | ✓ | ✓ | ? +$187.20/mo, over your $30 limit `capacity` | ✓ | ✓ | ✓ | ASK OWNER |
| 6 quota increase | ✓ | ✓ | ✓ | ✓ | ✓ | ? opens an aws support case | ASK OWNER |
| 7 delete legacy-reports-db | ✓ snapshot from today | ✓ | ✓ −$41.20/mo | ✓ no queries in 90 days | ✓ | ✓ | PASSED |

✗ in block red, ✓ in pass green, ? in a yellow chip. Under the rows, one line of the agent's next move:
- blocked → "your agent reads this, changes its plan, and tries again. nothing reached live."
- ask → "emfirge asks you. your agent keeps working on something else."
- passed → "safe to apply. your agent applies it with its own access; emfirge records it."
Rows print one by one (40ms stagger), then the stamp thumps. Reduced motion: everything appears at once, no thump.
Before any test: the sheet shows `test 000 · waiting for you to flip a switch`, with the six questions listed and empty.

Mobile: the left column stacks on top; the diagram simplifies (hide cdn, nightly-sync and deploy-role labels' metrics),
the switches go to 2 columns, and the report rows wrap with the reason code on its own line.

### 3. "What your agent would have run" (white, quiet)
Dynamic: shows the CLI transcript for the **last test the visitor ran** (or test 1 if none), in a plain black terminal block (Plex Mono,
no window chrome, no traffic lights):
```
$ emfirge branch new
$ emfirge try --delete rds:orders-db
$ emfirge check
  BLOCKED · data, availability
```
Beside it, three short numbered lines (they ARE sequential): 1 branch: a copy of your live cloud · 2 try: the change goes on the copy ·
3 check: six questions, answered with facts. Then: "Works with any agent that can run a shell: Claude Code, Codex, Cursor, Gemini CLI, Kiro, Cline."

### 4. "Six questions. Every change." (quiet)
A 2×3 (mobile 1-col) list, no cards: each is a black 2px top rule, the question name in Archivo 700, and one sentence.
Data · Exposure · Money · Availability · Control · Outside world (questions from DESIGN.md).
Then one line: "Yellow means you decide. Thresholds like the $30 limit are yours to set in emfirge.md."

### 5. "Why I built it" (quiet, a short signed note, no window chrome)
3 short paragraphs from Ansh in plain body text, max 60ch, ending with a hand-signed "Ansh" (an SVG signature path, not a font):
> I gave an AI agent my AWS to ship a small podcast project. It was good at it, and quiet about things. It asked AWS for a Lambda quota increase without telling me; I found out from a support case. A cache policy change sent my feed to a 404. A deploy script turned a paused schedule back on.
>
> None of it was the agent being dumb. It had nowhere safe to try a change, and I had no way to see what it was about to do. Switches 1 to 6 above are those moments.
>
> So I built the crash test I wanted. It's early. Break it, and tell me what it missed.

### 6. Pricing (quiet)
One bordered panel (2px black, 10px radius), 2 columns: left "Free while in beta." (Archivo 800) + "One AWS account, every feature, no card." + the `get started` button
(black, white text, 6px radius); right a plain list of what's included (8 items, mono ✓ in pass green).

### 7. FAQ: `<details>` rows with 2px black top rules (same 6 questions and answers as v4's content.ts; reuse that text).

### 8. Footer
A big black band: the TestMark large (160px) and "Crash-test every change before it touches your cloud." (Archivo expanded 800, white), the command,
then links and "Built by Ansh Sonkar", "© 2026 Emfirge".

## Behaviour and code
- All demo data (nodes, switches, results, transcripts) lives in `src/content.ts` as typed data. The bench is a client component with a small
  reducer: state = { tests: Test[], selectedView: 'live' | branchId }. Each test = a new branch number.
- The live bar's counters read the same state ("caught" = tests whose stamp is BLOCKED or ASK OWNER).
- Accessibility: each switch is a `<button aria-pressed>` with a full label ("Run test: delete orders-db"); the report is an `aria-live="polite"` region;
  the diagram has a text alternative listing node states; focus-visible = a 3px yellow outline + a black offset.
- Without JS: the bench shows test 001 (delete orders-db) as a static, completed example, and the switches are disabled with the note "turn on JavaScript to run tests".
- Motion: only the user-triggered ones (cover flip, toggle, report print, stamp thump, branch tab appear) and the live-dot pulse. No scroll animations.

## Ban list (any hit fails)
Glows, gradients, glass/blur, grain on anything but the stamp, purple/indigo/orange, Inter/Instrument/Geist/Space Grotesk,
pill badges above the H1, all-caps eyebrow labels, arrows on buttons, three identical icon cards, marquees, macOS window chrome
(we are not Helumi), dark navy/forest panels with hairline frames (we are not Docker v3), dot-grid canvases (not v2), fake testimonials.

## Process
1. Build. 2. `npm run build`. 3. Playwright at 1440, 768 and 390: full page before any test; then click switches 1, 5 and 7 in turn and
screenshot the bench after each (to check BLOCKED, ASK OWNER and PASSED render well). 4. Critique: is anything here reminiscent of v1–v4 or a
generic SaaS page? Does the bench feel like a lab instrument you want to play with? Fix, up to 3 rounds. 5. 360px: no horizontal scroll; no console errors.
