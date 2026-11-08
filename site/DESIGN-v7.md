# Emfirge site v7: the website is the docs

Ansh, 2026-11-08: loves v6 (graphics, design, everything). "What if we make this site good enough that we
don't need a docs site at all? Now we have fewer tools, since we're going CLI."
So v7 turns the v6 site into the whole product site + documentation. Same layout, tokens, rail, graphics
and motion as v6 (DESIGN-v6.md stays the source of truth for the look). Supermemory's own subpages
(`sm/product0-2.png`, `sm/pricing0-1.png`, `sm/research0.png` in the scratchpad) show how their inner pages
keep the same rail + column: follow that.

## Information architecture (rail nav, in this order)
1. **Home** (`/`): v6 home, unchanged except nav links now point to real pages.
2. **Quickstart** (`/quickstart`): 4 numbered steps: install (`npx @emfirge/cli@latest connect`),
   sign in, create the read-only role (one-click CloudFormation link, what it can and cannot do, delete
   the stack to revoke), first check (a tiny example: `emfirge branch new` → `try` → `check` with real-looking
   output). Then "Tell your agent" (the setup prompt + Claude/ChatGPT/Cursor deep links) and "Next steps".
3. **How it works** (`/how-it-works`): "The engine, in one page." (like their /product). Sections: The loop
   (reuse Figure 1) · A branch of live (what a branch is: base snapshot + ordered changes; fork, roll back,
   compare, discard; empty branch = live, law L1) · Many ways in (typed, AWS CLI, API, Terraform,
   CloudFormation; same change, same answer, L21) · The six checks (a table: question, what it looks at,
   example real reason code) · Tell vs ask (owner thresholds) · emfirge.md (example file) · The record
   (report, CloudTrail verification) · What emfirge never does (writes, AI inside, silent passes).
4. **CLI** (`/cli`): one page. Global: install, `connect`/`login`/`logout`, config, `--json`, exit codes
   (0 pass, 1 warn/ask, 2 block, 3 error; mark as [TODO Ansh: confirm]). Then one section per verb, each with
   synopsis, flags table, example + output, and "for agents" notes: `context`, `branch` (new, fork, list,
   compare, rollback, discard), `try` (`--delete`, `--terraform plan.json`, `--cfn changeset.json`,
   `--aws-cli "…"`, typed), `check`, `request`, `report`. A short "MCP adapter" section at the end mapping
   verbs to MCP tools (one table) and how to add it to an MCP client. Sticky "on this page" in the rail lists
   the verbs.
5. **Coverage** (`/coverage`): the resource table from the root README (add/modify/delete), "anything not modeled
   degrades the verdict", the lenses with status (security, dependencies, compliance, cost (us-east-1 only),
   limits (early)), and "Where the checks come from" (reuse the v6 chart + sources with links).
6. **Security & privacy** (`/security`): read-only role (exact permissions summary from `iam-role.yaml`),
   tokenization (identifiers tokenized on the user's machine before a model sees them), what the hosted engine
   stores. **Only claims true today.** The notes repo's roadmap §5 audit says retention/deletion and full purge
   are not built yet: say plainly "Retention and deletion controls are being built; until then email
   ansh@emfirge.cloud to delete your data", and link SECURITY.md / PRIVACY.md. No certifications.
7. **Pricing** (`/pricing`): their pricing-page layout, one plan: "Free while in beta" card + what's included +
   "What happens after beta" ([TODO Ansh]) + FAQ about cost.
8. **Changelog** (`/changelog`): their changelog layout (date, title, Improvements/Fixes). Seed from real git
   history of this repo (`git log --merges` titles, recent first, ~8 entries, real dates), rewritten in plain
   English. No invented entries.
9. **FAQ** (`/faq`): merge the old docs' FAQ, Troubleshooting and Glossary (rewritten for the CLI).
Footer + rail external links: GitHub ↗. Remove "Docs ↗" (the site is the docs).

## Content source
Move useful content from the old docs site: `/home/user/emfirge/site/src/components/docs/content.ts`
(415 lines: quickstart, concepts, branches, changes, diffs, plans, lenses, safety, configuration,
troubleshooting, glossary, mcp) and `/home/user/emfirge/README.md`, `/home/user/emfirge/backend/BRANCH-CLI.md`,
`/home/user/emfirge/mcp/README.md`, `/home/user/emfirge/iam-role.yaml`. Rewrite for CLI-first and the six
verbs (the roadmap's verb table: context, branch, try, check, request, report). Drop the 24 MCP tool pages.
Keep the voice of v6: plain, specific, lab-like, figures with captions, mono labels, margin of honesty.
Mark anything that is design-not-yet-built (CLI flags, request/report) the same "as if built" way, and
list it in DESIGN.md's aspirational list.

## Agents
- Every page also served as markdown: `public/<page>.md` (and `public/index.md` for home), generated at build
  from the same content (a small script or a route that writes them), plus `public/llms.txt` listing all pages.
- Every page has a `.md` version at a relative URL; an old `?agent=1` link redirects to it. (There is no Human/Agent switch.)
- A "Copy page as markdown" button at the top of each docs page (like modern docs).

## Build rules
- Same stack. Static export with one folder per route. Shared `Shell` (rail + column) for every page.
  Page content in typed files under `src/content/` (one per page). Reuse v6 graphics components.
- Code blocks: their style (light surface, mono, copy button). Tables: their hairline style.
- The rail's "On this page" works on every page (scroll-spy over that page's H2s).
- Search is optional; skip it unless cheap.

## Process
Build; serve; screenshot every page at 1440 (fold + full) and 390; compare inner pages with
`sm/product0.png` / `sm/pricing0.png` at the same scale; fix mismatches (up to 3 rounds); check links
(no 404s between pages), no console errors, 360px no horizontal scroll, "Copy page as markdown" and "View .md" work on each docs page, and `?agent=1` lands on the `.md`.
