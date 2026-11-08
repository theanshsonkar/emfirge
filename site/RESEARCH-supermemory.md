# What makes supermemory.ai good (research, 2026-11-08)

Studied: home, /product, /pricing, /research, /changelog, /blog, /index.md, the page scripts
(`Loop.astro`, `Paper.astro`, `arrive.js`), the CSS keyframes, Figure 1 frame by frame, and the hero video.
Ansh's rule: learn the principles, **do not copy the layout** (left rail, document column,
Human/Agent pill), the blue, or the dithered-nature video.

## How it is built
- **Astro**, static, with view transitions between pages. Almost no JS libraries: a small `arrive.js`
  reveal helper, one script per animated component. No canvas/WebGL. SVG + CSS keyframes + a few videos.
- Fonts: Geist + Geist Mono only. One brand blue (#0562EF), ink #0B1015, white, #F4F4F6. Radius 1px.
- ~15 named keyframes, each with one job: `logo-draw`/`logo-redraw` (logo strokes draw in), `draw-across`
  (lines draw), `rise-in`/`fade-in`/`float-in` (arrivals), `drift` (slow path motion), `ring`,
  `pixel-on`/`pixel-off` (dot-matrix cells), `status-pulse` (live dots), `shimmer-text` (the active word),
  `bar-grow` (charts), `col-live`/`col-out`. All gated on `prefers-reduced-motion` and on fonts loading.

## The principles (what to learn)

1. **The animation IS the explanation.** Figure 1 is a living diagram of the product's real loop, run by
   a script with state. Data sources light up ("hot"/"warm"), a "comet" travels each edge, the engine cycles
   its verbs (update → infer → forget, the active verb shimmers), and the database version visibly rolls
   v12 → v13 before the result travels to "your agent's context". Nothing moves for decoration.
2. **Written like a lab, not a SaaS.** Prose arguments with linked claims, "Figure 1." captions, worked
   examples ("one message in → four memories out"), comparison tables, a research page with public
   benchmarks and methodology. Confidence comes from specifics, not adjectives.
3. **Proof is designed, not listed.** Latency table, a pixel heatmap of tokens/month, a bar chart where only
   their bar is brand-colored, a log-scale line chart vs. the alternative, a benchmark table with their column
   tinted. Every number has a unit, a scope ("per query, on production traffic") and a date.
4. **One warm, human counterweight.** Rigorous technical UI is balanced by organic media: dithered duotone
   nature video (field, butterfly, meadow), blurred nature photos on pricing cards, a dusk sky in the CTA.
   Warmth comes from imagery, never from cute copy.
5. **A pixel motif ties it together.** Dot-matrix illustrations (data center, cloud, laptop), pixel heatmaps,
   pixel-on/off animations, the logo drawing itself. One visual language at every scale.
6. **Built for agents too.** `/index.md` is the page as markdown; a Human/Agent switch swaps the page for
   it; "Copy setup prompt" deep-links straight into ChatGPT, Claude, Cursor and Grok with the setup
   instruction prefilled. The product's users are agents, so the site speaks to them.
7. **Extreme restraint.** One color, two fonts, hairlines, 1px radius, mono micro-labels for metadata
   only. That restraint is why the few colored things (the active verb, their bar, the CTA) land.
8. **A real multi-page site.** Home = manifesto + figure + proof. Product = "the engine, in one page".
   Pricing, Research, Changelog, Blog: each dense and specific. Not one long landing page.

## How Emfirge should use them (without copying)

| Principle | Emfirge's own version |
|---|---|
| Living figure | **The loop, live**: a full-width hero diagram of the real Emfirge loop. Agent → `branch` forks a copy of live → `try` (the change rides an edge) → `check` (six cells light one by one) → **block** goes back to the agent (red comet returns) → the agent edits its plan → branch #2 → six green → `report` crosses to live, and the record counter ticks. Live itself never moves. |
| Written like a lab | Short argued paragraphs + worked example: "one agent command in → six facts out" (the real reason codes). |
| Designed proof | Only true numbers: 48 laws, 2,428 engine tests, 92 escalation paths, 14 modeled resource types, a coverage table per type. Optional, Ansh's call: publish the real-world scorecard openly ("measured in public"). |
| Warm counterweight | Not nature video. Our metaphor is the **fork**: a generative **river-delta** line field (vector, animated slowly): one channel tries a path, is blocked, reroutes, rejoins the main river. Nature's own branching, drawn in our lines. |
| One motif | **The fork line**: every illustration, divider, icon and the logo built from trunk + branch strokes that draw in. |
| Built for agents | Not a toggle copy: every section is **two columns, always visible**: left = for you (prose), right = for your agent (the exact command and its output). Plus `/index.md`, `/llms.txt`, and setup-prompt deep links. |
| Restraint | White, ink, one brand color (ours, not blue), one alert red used only for block. One family + its mono. |
| Multi-page | Home · How it works (the engine in one page) · Coverage (what a branch can model) · Pricing · Changelog · Docs. |
