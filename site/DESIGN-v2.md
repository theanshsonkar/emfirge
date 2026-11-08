# Emfirge landing v2: design spec

v1 base (DESIGN.md) is kept: palette (ink #0B0B0C, paper #EDEBE6, forge orange #FF5A1F,
pass #3DDC84, warn #F5B83D, block #FF4D4D), Instrument Serif display + Inter + JetBrains Mono,
copy voice, "as if built" stance, and the aspirational-claims list in DESIGN.md.

Ansh's feedback on v1: hero doesn't wow, too long / repetitive, not premium enough.
Reference feel: **Railway / Fly.io**: an infrastructure *canvas* as the hero product shot,
illustrated and characterful, warm, polished motion. Not a wall of cards.

## What changes

1. **15 sections → 7.** Problem + comparison merge; loop + verbs merge; use cases, emfirge.md
   and "facts not fixes" fold into other sections; FAQ shrinks to 4.
2. **Signature hero: the cloud canvas** (see below). This is the whole point of v2.
3. **Premium layer:** subtle film grain (SVG feTurbulence overlay, ~4% opacity, fixed),
   soft radial glows (orange + a deep plum `#2A1630` for depth), 1px gradient borders on
   key panels (`linear-gradient` border via background-clip), glass panels
   (`backdrop-blur`, `bg-white/[0.03]`), and tighter type (display letter-spacing -0.02em,
   H1 up to 104px desktop).
4. **Motion with intent** (motion/react): scroll-linked sticky sections, a scripted canvas
   story, a marquee. Everything respects `useReducedMotion` (show final states, no loops).

## Sections

### 1. Nav
As v1 but floating: a centered pill-shaped glass bar (max-w ~880px, rounded-full, blur,
gradient border), 16px from top. Mobile: logo + Get started + menu.

### 2. Hero (full viewport height, centered)
- Eyebrow pill, H1 "The harness for *cloud* agents." centered, sub (shortened):
  "A true model of your AWS, a branch to try changes on, and facts about what would break.
  Your agent gets all three before it touches production."
- CTAs centered: CommandBox `npx @emfirge/cli@latest connect` + "Read the docs".
- Below, the **Cloud Canvas** product shot, full container width (~1200×620 desktop),
  framed like an app window with a gradient border and an orange/plum glow underneath,
  slightly tilted in 3D on load (rotateX 12deg → 0 as it scrolls into view, useScroll).

**Cloud Canvas** (SVG + HTML, built from a typed `canvasScript` in content.ts):
- Dotted canvas background (Railway style). Top bar: tabs `live` | `branch #1` | `branch #2`,
  a status chip on the right.
- Nodes = rounded cards with an icon (lucide), a service label and a name, colored per kind
  with a soft tint: CloudFront `cdn`, ALB `web-alb`, EC2 `api-1`, `api-2`,
  RDS `orders-db`, RDS `legacy-reports-db`, S3 `assets`, Lambda `nightly-sync`, IAM `deploy-role`.
  Edges: curved SVG paths, with small animated dots flowing along the live-traffic edges
  (CloudFront→ALB→EC2→orders-db) to show traffic. legacy-reports-db has no traffic edge (idle).
- Docked right panel (desktop; below on mobile): a compact agent terminal, the same story
  as v1's terminal but shortened.
- **The story, looping every ~14s** (each step synced between the canvas and the panel):
  1. `live` tab. Traffic dots flow. Panel: `you › Clean up the unused databases.`
  2. `$ emfirge branch new`: the tab `branch #1` appears and becomes active; the canvas
     border shifts to orange dashed ("you are on a branch"); a small "forked from live" toast.
  3. `$ emfirge try --delete orders-db legacy-reports-db`: both DB nodes fade to a red
     ghost outline with a strike, and the edges into orders-db turn red and dashed.
  4. `$ emfirge check`: a red BLOCK chip; two signal callouts pop next to orders-db
     ("✗ data: no recovery point", "✗ availability: 1,240 queries/day"); the api nodes shake once.
  5. `agent › Keeping orders-db.`: `branch #2` tab; orders-db restored, only legacy-reports-db ghosted.
  6. `$ emfirge check`: a green PASS chip, callout "saves $41.20/mo · nothing live depends on it".
  7. `$ emfirge report --applied`: tab back to `live`, legacy-reports-db gone, toast
     "verified in CloudTrail ✓". Pause, then reset.
- Mobile: the canvas scales down (viewBox) with fewer nodes (hide api-2, assets, deploy-role),
  and the panel stacks below. Must not overflow at 360px.
- Reduced motion: show step 4 (BLOCK with callouts) statically; no loop.

### 3. Works-with marquee
A thin band with an infinite horizontal marquee of agent names (Claude Code, Codex, Cursor,
Gemini CLI, Kiro, Cline, Aider, "your own agent"), separated by small orange diamonds,
and an edge fade mask. Label above: "Works with any agent that runs a shell".

### 4. "Coding agents got a harness. Cloud agents didn't." (problem + comparison, bento)
- One short lead line: "Nobody trusts an agent with their cloud: it can't see what's live,
  can't try before it does, and you can't see what it did. So we built it the harness coding agents already have."
- **Bento grid** (desktop: 6 columns, mixed spans; mobile: 1 column), five tiles, each
  pairing "coding harness → Emfirge" with a mini illustration:
  - **Files → Context** (span 4, tall): a mini graph of nodes with one node selected and a
    tooltip "orders-db · live · 1,240 q/day · 3 dependents".
  - **Git branch → Branch** (span 2): a branch-fork illustration (main line + forked line, nodes).
  - **Tests → Signals** (span 2): the v1 signal card (FAIL availability...).
  - **Permissions → Boundaries** (span 2): the emfirge.md card (4 lines).
  - **Commit log → Record** (span 2): a small vertical timeline: "14:02 branch #2 PASS",
    "14:03 applied by agent", "14:03 verified in CloudTrail ✓".
  Tiles: glass, gradient border on hover, a subtle spotlight that follows the cursor
  (radial-gradient at mouse position, desktop only).

### 5. How it works: the loop, scroll-driven (merges loop + verbs)
- H2 "Six verbs. The loop is the product."
- Desktop: a sticky two-column layout ~300vh tall. Left: the six verbs as a vertical list
  (context, branch, try, check, request, report) with one line each; the active verb is
  highlighted with an orange bar, driven by scroll progress. Right (sticky): a terminal
  card showing that verb's example command and output (content.ts), crossfading on change.
  Under the list, a small circular loop diagram (context→branch→try→check→↺) whose arc
  fills with scroll.
- Mobile: no sticky; six stacked compact cards with their command and output.
- Footer line: "Your agent fails on a branch, reads the signal, fixes its own plan and
  tries again. Only what's left reaches you."

### 6. Six damage questions + trust (merged)
- H2 "Six questions about the result. Not 15,000 rules about actions."
- Left: a **hexagon radar** illustration (SVG). Six segments labeled Data, Exposure, Money,
  Availability, Control, Outside world. On view, the segments light up one by one green,
  except Data and Availability, which pulse red, echoing the hero story.
- Right: the six questions as a compact list (icon, name, question).
- Below, a "Built to be trusted" strip: 6 short items in a 3×2 / 2×3 grid of inline
  icon + bold phrase + 1 line: Read-only, always · Private by default · No silent passes ·
  No AI inside · Built from public data · Pinned by laws (with the L7 quote).

### 7. Get started + FAQ + final CTA + footer
- "Two minutes to a safe cloud agent." Three steps in a horizontal row joined by a dashed
  connector line (vertical on mobile), each with a big mono number and a mini code/visual.
- FAQ: 4 items (Does it change my AWS? · Which agents? · Is a PASS a guarantee? · Open source?).
- Final CTA: big glow, "Let your agents own the cloud. *Safely.*", CommandBox + Get started.
  Behind it, a faint, slowly drifting version of the canvas nodes (decorative, aria-hidden).
- Footer as v1.

## Rules
- All copy and data in `src/content.ts`, typed. Reuse the v1 components where they still fit;
  delete the ones no longer used.
- No new claims beyond DESIGN.md and this file.
- Performance: the canvas is SVG/HTML only (no canvas/WebGL libs, no three.js). Animate
  transform and opacity. Pause the hero loop when it is offscreen (useInView).
- Accessibility: the canvas has role="img" and an aria-label summarizing the story, plus a
  visually hidden text version of the steps.
