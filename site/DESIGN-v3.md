# Emfirge landing v3: design spec

Supersedes DESIGN-v2.md. DESIGN.md still holds the "as if built" stance and the
aspirational-claims list. Ansh's verdict on v2: "still looks AI generated."
Reference: **docker.com** (Ansh's pick). Screenshots and extracted tokens are in
`/tmp/claude-0/-home-user/20b78b6d-8b7e-552f-9e6e-b28300b8c523/scratchpad/ref/`
(docker-d-full.png, dk0..dk2.png, docker-m-full.png).

We take Docker's **taste**, not its look. Never copy its colors, font, wording, whale or
falling-letter effect. Emfirge must pass the "hide the logo" test: nobody should mistake it for Docker.

## Docker's taste, and why it works

| Decision | Why |
|---|---|
| Light page (#F9FAFB / white), dark panels only for "the serious system" | Dark means control/console. Contrast carries meaning, not mood |
| One saturated brand color, used for CTAs, links and gradient washes only | Recognizable without decoration |
| One grotesk family for display at weight 500, tracking about -3% | Confident without shouting; no serif/italic tricks |
| A visible frame: content between vertical hairlines, full-bleed rules between sections | Feels engineered, like a spec sheet |
| Product UI (terminals, a console log with status pills and timestamps) is the imagery | Shows the product is real; no stock illustrations |
| Small, quiet buttons (4px radius, 12–14px text) | The headline sells, not the button |
| Short declarative copy in pairs: "Your laptop. One command." | Plain and confident |
| One signature moment in the hero, derived from the brand | Memorable once; everything else stays calm |

## Emfirge v3 decisions

### Palette (5 named values + signals)
- `paper` #F7F8F7: page background
- `white` #FFFFFF: cards and surfaces
- `ink` #15201C: headings and primary text; body text `ink-2` #3A4641; muted `ink-3` #6B7671
- `line` #DDE2DF: hairlines and borders
- `forest` #0C2A22: the dark "console" panels and the hero band. Text on it: #E8EFEC; muted: #8FA39B
- `brand` **#0A8754 "branch green"**: CTAs, links, active states, gradient washes.
  The brand color *is* the pass color: green means "safe to apply". That is our meaning, not decoration.
- Signals: pass = brand, block #D93F3F, warn #D98A0B. Pills: tinted bg (12%) + solid text.

No orange. No near-black page. No purple. No glow. No grain. No glass.

### Type
- **Instrument Sans** (Google Fonts) for everything: display 500 with letter-spacing -0.035em;
  body 400 at 16px/1.6 on marketing, 14px inside UI mocks.
- **Geist Mono** (npm `geist`, or Google "Geist Mono") only inside terminals and console panels.
- Scale: H1 72/1.02 (mobile 44), H2 56/1.05 (mobile 36), H3 22/1.3, body 16, small 14, UI 13.
- Sentence case everywhere. No accented word in a headline. No italics. No all-caps labels.

### Frame
- A container at 1200px with **1px vertical hairlines (`line`) on both sides running the full page**
  (desktop only), like a blueprint. Sections are separated by full-bleed 1px horizontal rules.
- Radii: buttons 4px, panels/cards 12px, pills 999px. Shadows: none, except product mocks
  get `0 30px 60px -20px rgba(12,42,34,.25)`.

### Signature moment (the one bold thing): "the fork"
The hero band (forest) has a thin horizontal trunk line running across it at about 70% height,
with commit dots. On load, **one orchestrated sequence (about 1.6s total)**:
the trunk draws left to right, then at about 40% a branch curves off downward-right and runs
parallel (dashed). A small mono label rides on it, `branch #1`, and the branch ends in a red ✗
dot, then a second branch forks off and ends in a green ✓ dot that merges back into the trunk.
It is drawn in SVG with hairline strokes (`#2E5A4B` trunk, brand green and red at the ends).
It runs once, never loops. Reduced motion: show the final drawing.
This is Emfirge's own mark: git branching applied to the cloud. Nothing else on the page animates
on load except the split-panel log (below), which plays once when scrolled into view.

## Page (8 blocks)

ASCII wireframes are desktop; on mobile everything stacks, with 16px gutters.

### 0. Announcement bar (forest, 36px)
"New: the emfirge CLI. Six verbs, any agent. Read the docs" (the last part is a link, no arrow). Close ×.

### 1. Nav (white, 64px, bottom hairline)
```
[e emfirge]  Product  Docs  GitHub  Changelog            [Sign in] [Get started]
```
Sign in = 1px ink border, white. Get started = brand green, white text. Both 4px radius, 14px, 8×14 padding.

### 2. Hero (forest band, full frame width, ~560px tall)
```
|                                                                      |
|  The harness for cloud agents                                       |
|  Your agent gets a true model of your AWS, a branch to try          |
|  changes on, and facts about what would break. Production           |
|  never sees a guess.                                                |
|  [Get started]  [Read the docs]                                     |
|  $ npx @emfirge/cli connect                         (copy)          |
|  ───●────●────●──────────●─────────●──────── trunk (live)           |
|              ╲__ branch #1 ____ ✗                                    |
|               ╲__ branch #2 ________ ✓ ╱ (merges)                    |
```
Left-aligned, not centered. The command is a quiet mono line with a small copy icon (no box).

### 3. Works with (white, a row of bordered cells like a logo wall)
Six equal cells with hairline dividers, each holding a plain-text wordmark in ink-3, 18px, weight 500:
Claude Code, Codex, Cursor, Gemini CLI, Kiro, Cline. Above, a small ink-3 line: "Works with the agent you already use."
Mobile: a 2-column grid of cells.

### 4. The split panel (the product moment)
H2: "Your agent tries it on a branch. You read one result."
Body (max 60ch): "Before anything touches production, the change runs against a copy of your live AWS.
Six questions about the result come back as facts. Your agent fixes its own plan."
Then a 2-column panel (12px radius, the left half white, the right half forest), each half with a small
icon + label and an H3, then a mock:
- Left, "Agent view" / H3 "Your terminal. One command.": a dark terminal mock:
  ```
  $ emfirge try --delete rds:orders-db rds:legacy-reports-db
    2 changes on branch #1
  $ emfirge check
    block · 2 of 6 checks failed
  ```
- Right, "The branch" / H3 "Six checks. Every change.": a log of rows, each
  `time · pill · text`, in mono 13px:
  ```
  14:02:36.04  [Block]  data          orders-db has no recovery point
  14:02:36.05  [Block]  availability  orders-db served 1,240 queries/day
  14:02:36.05  [Pass]   exposure      nothing newly reachable
  14:02:36.06  [Pass]   money         −$41.20/mo
  14:02:36.06  [Pass]   control       no access or logging lost
  14:02:36.07  [Pass]   outside world no external side effects
  ```
  When scrolled into view, rows appear one by one (60ms stagger), once.
- Mobile: the halves stack, and the log text wraps under the pill.

### 5. "The world your agent works in" (2×2 cards, Docker-style)
H2 "The world your agent works in." Sub: "Coding agents got files, branches, tests and a log. Cloud agents get the same."
Four white cards (12px radius, hairline border). Each has an H3 + 2 lines, and the bottom ~45% of the card
holds a cropped product mock sitting on a **brand-green wash fading up from the bottom** (12% → 0):
- **Context. Ask what's true.**: "What exists, what's live, what depends on what." Mock: a mini table
  `orders-db · rds · live · 1,240 q/day · 3 dependents`, 3 rows.
- **Branch. Try anything.**: "A copy of your live AWS. Fork it, compare it, throw it away." Mock: branch list
  `#1 cleanup-dbs · block`, `#2 cleanup-dbs · pass`, `live`.
- **Boundaries. Write your intent once.**: "Plain English in emfirge.md. Hard lines are enforced." Mock: the emfirge.md 4 lines.
- **Record. Know what happened.**: "Every applied change, checked against CloudTrail." Mock: a 3-line timeline.

### 6. Principles (3 plain columns, no cards, top hairline)
H2 "Built so you can trust it." Three columns, each an H3 + 2–3 sentences:
- **Read-only. Always.** "Emfirge never writes to your cloud. Your agent applies with its own access, and Emfirge records it."
- **No AI inside.** "The same branch always gives the same answer. Nothing can talk it into a pass."
- **Unknown never passes.** "If a change can't be modeled, the result says so. A missing check is reported, not hidden."

### 7. Numbers (3 big figures, centered row)
`48` laws every release must pass · `2,428` engine tests · `92` IAM escalation paths, from pathfinding.cloud.
Figure: 64px, weight 500, ink. Label: 16px ink-2, two lines max. These are real numbers from the repo; keep them exact.

### 8. Get started + footer
A forest panel inside the frame: H2 (light) "Give your agent a branch of your cloud." + [Get started] [Read the docs]
+ the command line. Then a footer on paper: logo + one line, 4 link columns (Product: CLI, Docs, Changelog ·
Open source: GitHub, Engine (AGPL-3.0), CLI (Apache-2.0) · Trust: Privacy, Security · Contact: ansh@emfirge.cloud),
and a bottom row "© 2026 Emfirge · Built by Ansh Sonkar".

## Ban list (grep before you commit; any hit fails)
- Fonts: Inter, Space Grotesk, Instrument Serif, any serif, italics in headlines.
- Colors: #FF5A1F or any orange accent, purple/indigo/violet, near-black page backgrounds, cream.
- Decoration: glows, `backdrop-blur`, glassmorphism, grain/noise, gradient borders, radial spotlights, the dot-grid canvas.
- Patterns: a pill badge above the H1, all-caps or letter-spaced eyebrow labels, " · " meta strings in marketing
  copy (allowed only inside product mocks), arrows (→ ›) on buttons or links, emoji, a single accented headline word,
  three identical icon cards, fade-in on every section, hover-lift on cards, a marquee.
- Icons: at most 4 small lucide icons in the whole page (the split-panel labels and the copy icon only).
- Copy: "empower", "unlock", "seamless", "supercharge", "revolutionize".

## Process (required)
1. Build. All copy lives in `src/content.ts`. Delete unused v2 components.
2. `npm run build`. Serve `out/`. Screenshot at 1440, 768 and 390 (full page, reduced motion), plus a
   1440×900 hero shot after 2s without reduced motion.
3. Put each screenshot next to the Docker reference and critique it: Does it feel as calm, engineered and real?
   Does it pass the hide-the-logo test? Any ban-list hit? Fix, re-shoot. Up to 3 rounds.
4. At 360px, scrollWidth <= 360. No console errors.
