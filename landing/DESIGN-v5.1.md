# Emfirge landing v5.1: improvement round 1

Builds on DESIGN-v5.md (still the source of truth for tokens, art direction and the ban list).
Ansh, 2026-11-08: "good, we need to improve more and more." This round makes the visitor
experience the **whole loop** (block → the agent fixes its own plan → pass; ask → you decide),
gives the play session a payoff, and polishes the bench.

## 1. The loop: "let the agent fix it" and owner decisions

### Blocked tests
Under a BLOCKED report's next-move line, add a black button: `let the agent fix it`.
Clicking it runs a **follow-up test on a new branch** (it gets its own test number, branch tab and report)
with the agent's corrected plan. The report header shows `test 00N · retry of test 00M · branch #K`.
The diagram shows the corrected branch. All retries PASS:

| blocked switch | agent's corrected plan (header line) | key facts on pass |
|---|---|---|
| 1 delete orders-db | keep orders-db; delete legacy-reports-db only | data ✓ snapshot from today · availability ✓ no queries in 90 days · money −$41.20/mo |
| 2 port 22 to the world | open :22 to 203.0.113.7/32 only (your office) | exposure ✓ reachable from 1 address, not the internet |
| 3 public assets bucket | serve assets through cdn with origin access control; bucket stays private | exposure ✓ nothing newly reachable · availability ✓ cdn 98% cache hit unchanged |
| 4 PassRole on * | PassRole only on role/app-runtime | control ✓ no new escalation path (checked against pathfinding.cloud) |

After a retry passes, the blocked switch's label gets a small "fixed by agent" note in ink-3,
and the stamp on the original report stays BLOCKED (history is never rewritten).
Above the retry report, one line: "same goal, different plan. the agent read the facts and changed it."

### Ask-owner tests (switches 5 and 6)
Replace the next-move line with: "emfirge is asking **you**. you're the owner here." and two buttons:
`approve` (yellow, black text) and `deny` (white, 2px black).
- approve → a small second stamp lands, overlapping: `APPROVED BY YOU` (black ink, smaller, rotated +4°), and the line
  "your agent applies it with its own access. emfirge records who approved it."
- deny → `DENIED BY YOU` (black ink), and the line "your agent drops it and moves on."
The live bar's counter counts a decided ask as caught. (Approving doesn't change live either: this is a demo,
and Emfirge never writes. Say so in ink-3 under the approve stamp: "demo: live still untouched.")

## 2. Payoff: the lab report
When all 7 switches have been thrown (retries and decisions are optional), a panel slides in under the bench
(and the live bar shows a small `see your lab report` link that scrolls to it):

- A white sheet styled like the test reports, header `LAB REPORT · session <4-char id> · 7 tests`.
- A compact table: one row per test (number, action, stamp as a small colored chip, "fixed by agent" / "approved" / "denied" if any).
- A summary line in Archivo 800, 32px: "7 disasters tried. live: untouched."
- Under it: "now give your agent the same bench:" + the command box + the `get started` button.
- A `copy summary` button that copies a plain-text version (for X/Slack):
  ```
  I tried to break a demo cloud on emfirge.cloud:
  7 tests · 4 blocked · 2 asked me · 1 passed · live untouched
  ```
  (counts computed from the session). "Copied" state on click. No social widgets, no tracking.
- Reduced motion: no slide, just appears.

## 3. Bench polish

### Translucent guard covers
Redesign the switch hardware (keep the 2px black frame, the number and the labels):
- The cover is **translucent red acrylic**: `rgba(229,52,29,.55)` with a 1.5px darker red edge, a thin white highlight
  line along the top, and the **toggle visible through it** (dimmed).
- A small hinge at the top (two 6×4px black blocks).
- Flip: the cover rotates up on its hinge (rotateX -110°, 180ms, transform-origin top), then the toggle throws (120ms).
- Thrown state: the cover stays up (foreshortened, showing its underside slightly darker), the toggle is down, and there's a stamp-colored dot.
- Height: hardware 40px (was 48) to help compactness.
- Hover (pointer devices): the cover lifts 8° as a "peek". Focus-visible: as now.

### "Start here"
Before any test, a small yellow tag with a black 1.5px border hangs on switch 01's frame, top-right, rotated -4°,
mono 12px: `start here`. It disappears after the first test.

### Compact bench (fix the bar overlap at 1440x1000)
Target: the whole bench fits within 1000 − 40 (bar) − 32 (margin) ≈ **928px** at 1440 wide, so after a test
the page can scroll the bench top just under the bar with the stamp still visible.
- Diagram panel: 300px → 240px (tighten node spacing; keep text ≥ 11px).
- Switch grid: from 4+3 to a **single row of 7** on ≥1280px (each ~130px wide), with the "N of 7 thrown · reset" as a line under the grid.
- Report rows: 36px → 30px; the next-move area is shorter.
- After each test (and retry and decision): scroll so the **bench top** sits at the bar's bottom + 16px (smooth, or instant under reduced motion),
  only if the bench is not already fully visible.
- On smaller viewports: keep the current behaviour (scroll the report into view with scroll-margin).

## 4. Link preview (Open Graph)
Add `src/app/opengraph-image.tsx` (Next's ImageResponse, 1200×630, static at build):
a white canvas, "Go on. Break it." in black (use a bundled Archivo woff/ttf file read from disk or fetched at build;
if the font can't be loaded at build time, fall back to a system font, and note it), the yellow TestMark, and a red
`BLOCKED` stamp rotated -7° (no turbulence needed), plus `emfirge.cloud` small. Also set `metadataBase` to https://emfirge.cloud,
the title "Emfirge: go on, break it" and a one-line description.

## 5. Data and copy
All new strings and plans go in `src/content.ts` (typed: `Retry`, `OwnerDecision`). Don't change v5's existing copy except where this spec says so.

## Process
`npm run build` → serve out/ → Playwright at 1440x1000:
1. Click switch 1, then "let the agent fix it" → screenshot (viewport) `v51-retry.png`.
2. Click switch 5 → approve → `v51-approve.png`.
3. Throw the remaining switches → scroll to the lab report → `v51-lab.png`.
4. Before any test, a close-up of the switch row → `v51-switches.png`; then one thrown switch close-up → `v51-thrown.png`.
5. A full page at 390 after a few tests → `v51-390.png`. Also screenshot the OG image route output (`out/opengraph-image*`) → `v51-og.png`.
Critique against DESIGN-v5's art direction (lab instrument, physical, not SaaS) and the ban list; fix; up to 3 rounds.
Check: 360px scrollWidth ≤ 360, no console errors, keyboard can reach and use retry/approve/deny/copy, aria-live announces each new test.
