# Emfirge landing v4: design spec (Helumi-style)

Supersedes v3 for the look (v3 is saved in git history at 11d52ef). DESIGN.md's
"as if built" stance and the aspirational-claims list still apply.
Reference: **helumi.app** (Ansh's pick). Screenshots are in
`/tmp/claude-0/-home-user/20b78b6d-8b7e-552f-9e6e-b28300b8c523/scratchpad/ref/`
(hx-how-it-works.png = hero, hx-pricing.png = pricing, hl0.png, hl2.png, hl5.png).
Take Helumi's **taste**. Never copy its logo, mascot, wording, diya pattern or images.

Ansh's decisions (2026-11-07): full Helumi-style; pricing "free while in beta";
testimonial slots are **clearly marked placeholders** (never fake people); founder
note drafted from his real field notes (below), which he edits before launch.

## Helumi's taste, and why it works
| Decision | Why |
|---|---|
| Light gray page `#F4F4F4`, white surfaces, almost monochrome | Calm. The product UI carries all the color |
| The OS's own system font (`-apple-system`), lowercase headings, tight tracking | Feels native and personal, like a Mac app, not a SaaS template |
| One black pill CTA with an icon | One action, impossible to miss |
| **Faithful OS UI recreations** (Finder, System Settings) as the imagery | You see it working in *your* world; realism builds trust |
| A founder letter in a Notes-app window, with highlighted lines and a handwritten signature | A real person, a real reason |
| Little human touches: a handwritten note with an arrow, a faint seasonal pattern, a floating toast | Warmth and craft; nothing here is "default" |
| Pricing is one card with a short icon checklist | No decision paralysis |
| Centered, narrow column (~720px for text, ~780px for windows) with huge vertical space | Reads like a letter, not a dashboard |

## Tokens
- `bg` #F4F4F4 · `surface` #FFFFFF · `ink` #000000 · `ink-2` rgba(0,0,0,.64) · `ink-3` rgba(0,0,0,.48)
- `hairline`: box-shadow `0 0 0 .5px rgba(0,0,0,.12)` (instead of borders, like macOS)
- Window chrome: traffic lights #FF5F57 #FEBC2E #28C840, titlebar #F6F6F6, sidebar #EFEFF0
- `pass` #0A8754 (only for "safe / pass" facts, like Helumi's green "0 KB on this Mac"), `block` #D93F3F, `warn` #D98A0B
- Highlighter yellow for the founder note: #FFF3B0
- Fonts:
  - UI/body: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Geist", system-ui, sans-serif`
    (load Geist via next/font as the non-Apple fallback; Inter is banned).
  - Mono: `ui-monospace, "SF Mono", "Geist Mono", monospace`.
  - Handwriting: **Caveat** (Google), used only for the hand note and the signature.
- Type: H1 48/600 tracking -0.045em; H2 32/600 tracking -0.03em; body 16/24; small 14/21; meta 12/18.
  All headings lowercase. One italic word per heading is allowed (Helumi does it: "one plan. *free* while in beta.").
- Radii: pills 999px; cards 16px; windows 12px; small chips 6–8px. No heavy shadows: windows get
  `0 0 0 .5px rgba(0,0,0,.12), 0 20px 50px -20px rgba(0,0,0,.18)`.
- Background pattern: faint tiny **branch-fork glyphs** (a custom 14px SVG: one trunk with one fork),
  scattered at ~6% opacity in the hero area only, fading out downward. It's our own "seasonal" touch.

## Page (centered column; every section's H2 sits centered above its content)

### 1. Nav: a floating centered pill (white, hairline), sticky top 12px
Items: **emfirge** (bold) · how it works · why · pricing · faq · docs. The active section gets a
light-gray pill (scroll-spy). Mobile: horizontally scrollable pill, no hamburger.

### 2. Hero
- H1: "meet [e-mark] emfirge." (the logo mark inline at text height, black).
- Sub (2 lines, ink-2 with bold words): "**let your agent** touch your aws, / **without** losing sleep over it."
- Black pill button: [terminal icon] "get started" → docs quickstart.
- Meta lines, 12px ink-3: "free while in beta · works with any agent · read-only access"; then a lock icon + "your ids are tokenized before any model sees them".
- Small line: "built in public by **ansh**", with a tiny avatar circle showing the initial "a" (no photo).
- **The hero window** (~780px wide): a faithful **light macOS Terminal** window (titlebar "~/infra — zsh", white
  background, SF Mono 13px). It runs one orchestrated story once on load (typing ~25ms/char, then lines appearing):
  ```
  ~/infra % claude
  > clean up the unused databases in ap-south-1

  ● I'll try it on a branch first.
    $ emfirge branch new cleanup-dbs
      branch #1 forked from live · 0 changes
    $ emfirge try --delete rds:orders-db rds:legacy-reports-db
      2 changes on branch #1
    $ emfirge check
      block · 2 of 6 checks failed
      ✗ data          orders-db has no recovery point
      ✗ availability  orders-db served 1,240 queries/day
  ● orders-db is live. Keeping it and retrying with legacy-reports-db only.
    $ emfirge check --branch 2
      pass · 6 of 6 · saves $41.20/mo
  ● Safe to apply. Want me to delete legacy-reports-db?
  ```
  `block` and ✗ in red, `pass` in pass-green, `●` agent bullets in ink, commands in ink, output in ink-2.
  Reduced motion / no JS: show the final state.
- Floating around the window (desktop ≥1100px only):
  - Left: a white toast card (like Helumi's testimonial toast) with a dashed hairline and a small "placeholder" chip:
    "“your tweet here. try emfirge and tell us what it caught.”" / "— you, @yourhandle". Close × (dismisses).
  - Right: the Caveat hand note "watch it catch a mistake" with a hand-drawn SVG arrow curving down to the window.

### 3. "built for every kind of cloud work." (how it works)
A row of pill tabs: everyone · cleanup · cost · security · incidents · what-if. Clicking a tab swaps the
terminal transcript below (the same light Terminal component, shorter scripts, ~6 lines each, in content.ts):
- cleanup: the delete story (short).
- cost: "> make staging cheaper" → try a smaller instance class → check → "money: −$62.10/mo · availability: nothing live depends on it · pass".
- security: "> is anything public that shouldn't be?" → `emfirge context --exposure` → lists 1 security group open on 22 → try a fix on a branch → pass.
- incidents: "> the feed is 404ing, fix it" → try the cache-policy change on a branch → check → "availability: feed.xml → S3 (OAC) receives Host header · predicted 404 · block" → retry with a managed policy → pass.
- what-if: "> rds public vs private?" → two branches → compare → private passes, public blocks on exposure.
- everyone: the hero story, condensed.
Motion only on tab change (crossfade 150ms).

### 4. "your cloud on a branch. *zero* risk to prod."
A faithful **macOS System Settings-style window** (sidebar + content, like Helumi's Storage panel, but ours):
the sidebar shows a list of branches (live, #1 cleanup-dbs, #2 cleanup-dbs (selected)); the content shows
- A card: "branch #2 · cleanup-dbs" / "1 change · forked from live 2 min ago", with a segmented bar of the six
  checks (six equal segments, all green) and the legend data · exposure · money · availability · control · outside world.
- A list card, row per check, each with a small colored rounded-square icon (like System Settings icons) + name +
  a right-aligned value: data "recovery point exists" · exposure "nothing newly reachable" · money "−$41.20/mo" ·
  availability "nothing live depends on it" · control "no access lost" · outside world "no side effects".
  Top row, highlighted: "emfirge · safe to apply" with "pass" in green on the right (the "0 KB on this Mac" moment).
Below the window, 3 short centered lines of explanation.

### 5. "sound familiar?"
A stack of **macOS notification banners** (rounded 16px, translucent white, app icon square, title, body, "now"),
slightly overlapping and fanned, each a REAL thing from Ansh's field notes (no ids):
- "aws support · case opened: lambda concurrency quota increase. you didn't ask for this."
- "feed.xml · returned 404 after a cache policy change"
- "eventbridge scheduler · nightly-sync is ENABLED again after a redeploy"
- "budget · your agent's test run counted the whole account"
Then one line: "every one of these happened to me in one week. the agent wasn't dumb. it just had nowhere safe to try."

### 6. "why emfirge?"
Two side-by-side white cards: "without emfirge" (5 rows, a gray ✗ each) and "with emfirge" (5 rows, a green ✓ each):
- every aws command is the real thing → every change is tried on a branch first
- you find out from a support email → nothing leaves the cloud without asking you
- "trust me, it's safe" → six checks, as facts, with evidence
- a wall of api calls → one record, checked against cloudtrail
- you watch over its shoulder → you write your rules once in emfirge.md

### 7. "loved by early builders." (placeholders, clearly marked)
A horizontally scrolling wall (2 rows, edge fades) of 6 tweet-style cards with a **dashed** hairline,
gray avatar circles, and the text "your tweet here", handle "@yourhandle", an X-style mark, and a small
"placeholder" chip on each. Above the wall: "emfirge is brand new. try it and be the first one here." (link to docs).
Never invent names or quotes.

### 8. "why i built emfirge."
A **macOS Notes window** (titlebar with a yellow note icon and "notes", white page, 17px body, ink-2), the letter
below, with the highlighted sentence in highlighter yellow, a footer with an avatar circle "a", "ansh, founder", and the
signature "emfirge" in Caveat on the right. A few emoji are allowed **only in this note**.

> hey, i'm ansh 👋. i build things with ai agents every day.
>
> a few weeks ago i gave claude code my aws to ship a small podcast project. it was good at it. it was also quiet about things. 🤐
>
> it asked aws for a lambda quota increase without telling me. i found out from a support case email. a cache policy change sent my feed to a 404. a deploy script turned a paused schedule back on.
>
> none of it was the agent being dumb. it just had no safe place to try a change, and i had no way to see what it was about to do.
>
> so i built what i wanted: ==emfirge. your agent tries every change on a branch of your cloud, sees what would break, and fixes its own plan before production ever sees it.==
>
> it's early. try it, and tell me what breaks. ✌️

### 9. "one plan. *free* while in beta." (#pricing)
One white card (~360px wide, 16px radius), like Helumi's:
- Header: the e-mark + "beta" (italic) / "everything, for one aws account"; a soft gray gradient band behind the header
  (light, no color).
- Price row: "$0" big + "/month while in beta" + a muted line "no card needed. we'll tell you before anything changes."
- Checklist (icon + text, 14px, 12 rows max): works with any agent that runs a shell · branches of your live aws ·
  six checks on every change · terraform, cloudformation, cli and api changes · read-only role, revoke any time ·
  ids tokenized on your machine · emfirge.md boundaries · record checked against cloudtrail · open source engine.
- Black full-width pill: "get started" (no arrow).

### 10. "questions, *answered*." (#faq)
Accordion, `<details>`, white rounded rows: does emfirge change my aws? · which agents work? · which clouds? ·
is a pass a guarantee? · what does it cost after beta? ("we'll tell you well before beta ends. there will always be a free tier for one account." Flag this answer in DESIGN.md's aspirational list) · is it open source?

### 11. Final CTA + footer
H2 "stop babysitting your agent in the cloud." + the black pill. Footer, centered, 12px with underlined links:
privacy · security · docs · github · changelog · © 2026 emfirge / "built by ansh ❤️" (link to github.com/theanshsonkar).
A big faint e-mark silhouette at the very bottom, cropped (like Helumi's mascot peeking).

## Rules
- All copy in `src/content.ts`. Reusable pieces: `MacWindow` (chrome variants terminal | settings | notes),
  `TerminalScript`, `NotificationBanner`, `TweetPlaceholder`, `PricingCard`.
- Motion: the hero typing (once), tab crossfades, the toast dismiss, and the notification stack fanning in once on view.
  No section fade-ins, no hover lifts. Respect reduced motion (hydration-safe `useReduced`). Content visible without JS.
- Never fake social proof: every placeholder shows the word "placeholder".
- No AWS or Claude logos or brand marks; product names in plain text only.
- The founder note text above is a draft for Ansh to edit; keep it verbatim for now.
- Mobile 390: windows scale down (terminal lines may wrap with a hanging indent); floating toast and hand note hidden;
  the notification stack becomes a vertical list. Never overflow at 360px.

## Process (required)
Build → `npm run build` → serve out/ → screenshots at 1440, 768 and 390 (full page, reduced motion) + the hero after 4s with motion →
compare each next to the Helumi references (taste: calm, native, personal, crafted) → fix → up to 3 rounds.
