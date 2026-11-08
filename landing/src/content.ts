// All copy and numbers for the v6 landing page. See DESIGN-v6.md.
//
// REAL NUMBERS (counted from the repo on 2026-11-08, never estimated):
//  - Engine tests 2,432: `cd backend && python -m pytest --collect-only -q` (parametrized cases included).
//    The roadmap said 2,428; the collected count today is 2,432. (Plain `def test_` count is 1,497.)
//  - MCP + CLI tests 102: `cd mcp && npm test` -> "# tests 102, pass 102".
//  - Laws 48: README "Built to be trusted" says "There are 48 so far". The backend tests only tag 30
//    distinct ids (L1..L66 with gaps) in docstrings/names, so the tagged count is a lower bound.
//  - Resource types 14: len(app.mutations.SUPPORTED_RESOURCE_TYPES).
//  - Escalation paths 92: len(app/data/pathfinding_paths.json["paths"]).
//  - Scanner check reads 55: len(app/data/scanner_check_reads.json).
//  - Native reason codes 30: distinct codes passed to _reason(...) in app/verdict.py.
//  - Prowler check metadata files 21: app/data/third_party/prowler/checks/*.metadata.json.
//  - Severity crosswalk entries 21: len(app/data/scanner_severity_crosswalk.json).

export const LINKS = {
  site: "https://emfirge.cloud",
  docs: "https://emfirge.cloud/docs",
  quickstart: "https://emfirge.cloud/docs/quickstart",
  github: "https://github.com/theanshsonkar/emfirge",
  ansh: "https://github.com/theanshsonkar",
  mail: "mailto:ansh@emfirge.cloud",
  security: "https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md",
  privacy: "https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md",
};

export const SITE = {
  title: "Emfirge: the harness for AI agents that work on your cloud",
  description:
    "Emfirge gives AI agents a true model of your AWS, a branch for every change, and six checks with no AI inside.",
};

export const SETUP_PROMPT = "Set up emfirge in this project. Read https://emfirge.cloud/index.md and follow it.";
export const COMMAND = "npx @emfirge/cli connect";

export const RAIL_NAV = [
  { label: "Home", href: "/", active: true },
  { label: "How it works", href: LINKS.docs },
  { label: "Changelog", href: LINKS.docs },
  { label: "Pricing", href: LINKS.docs },
  { label: "Coverage", href: LINKS.docs },
  { label: "Docs", href: LINKS.docs, ext: true },
  { label: "GitHub", href: LINKS.github, ext: true },
];

export const ON_THIS_PAGE = [
  { id: "mission", label: "Mission" },
  { id: "what-we-do", label: "What we do" },
  { id: "in-production", label: "In production" },
  { id: "runs", label: "Where it runs" },
  { id: "trust", label: "Trust" },
  { id: "writing", label: "Writing" },
];

export const HERO = {
  pill: "Introducing the emfirge CLI",
  pillLink: "Read the post",
  h1: "emfirge is building the harness for AI agents that work on your cloud.",
  sub: "Available through our CLI, any agent's shell, and MCP.",
  primary: "Get started with emfirge",
  secondary: "Talk to Ansh",
  copy: "Copy setup prompt",
  worksWith: ["Claude Code", "Codex", "Cursor", "Gemini CLI", "MCP"],
};

export const NOTES = {
  world: "Read-only IAM role, one CloudFormation click, delete the stack to revoke.",
  trust: "A change Emfirge cannot model can't pass. A missing check is reported, not hidden.",
};

export const FIGURE = {
  caption:
    "Figure 1. A change enters emfirge in any format and runs on a branch of your live cloud. Six checks answer with facts; a block goes back to the agent, which changes its plan. Only a passing change reaches your agent's context to apply.",
};

export const WHAT = {
  title: "What we do",
  rows: [
    {
      tile: "rings",
      title: "A true model of your cloud.",
      text: "What exists, what's live, what depends on what, and what each identity can reach, read through a role you can revoke any time.",
    },
    {
      tile: "fork",
      title: "A branch for every change.",
      text: "Your agent tries AWS CLI commands, Terraform plans and CloudFormation change sets on a copy of live, never on production.",
    },
    {
      tile: "six",
      title: "Six checks, no AI inside.",
      text: "Data, exposure, money, availability, control, outside world. Deterministic, and unknown never passes.",
    },
  ],
  note: "Every check comes from public data: AWS's own API models and Price List, pathfinding.cloud, Prowler and policy_sentry. Not hand-written lists.",
  more: "Read more about the engine",
};

export const PRODUCTION = {
  label: "In production",
};

export const METRICS = {
  tests: {
    title: "Tests",
    sub: "Backend pytest, MCP + CLI node",
    cols: ["Test cases"],
    // 2,432 from pytest --collect-only; 102 from `npm test` in mcp/.
    rows: [
      { name: "Engine (backend)", value: 2432 },
      { name: "MCP + CLI", value: 102 },
    ],
  },
  laws: { title: "Laws", sub: "Properties that must always hold", value: 48 },
  types: { title: "Resource types", sub: "AWS types a branch can add, modify or delete", value: 14 },
  sources: {
    title: "Where the checks come from",
    sub: "Counts from the repo, not hand-written lists",
    headline: 92,
    headlineLabel: "privilege-escalation paths, from pathfinding.cloud",
    bars: [
      { label: "PATHS", name: "pathfinding.cloud escalation paths", value: 92 },
      { label: "READS", name: "scanner check reads", value: 55 },
      { label: "NATIVE", name: "native reason codes in verdict.py", value: 30, own: true },
      { label: "PROWLER", name: "Prowler check metadata files", value: 21 },
      { label: "CROSSWALK", name: "scanner severity crosswalk entries", value: 21 },
    ],
    link: "See the sources",
  },
  same: {
    title: "Same change, same answer",
    sub: "One rule, opening port 22 to the world, in five input formats",
    law: "L21",
    cols: ["Format", "Verdict"],
    rows: ["Typed change", "AWS CLI", "AWS API", "Terraform", "CloudFormation"],
    foot: "Law L21 pins Terraform and the AWS API to the same verdict, and L20 pins ::/0 to 0.0.0.0/0.",
    link: "Read the laws",
  },
  quote: "A change Emfirge can't model can't pass. A missing check is reported, not hidden.",
  quoteBy: "Emfirge README",
};

export const RUNS = {
  title: "emfirge runs wherever your agent runs.",
  text: "The CLI is a thin client; the engine is hosted. Your cloud only ever sees a read-only role.",
  link: "How setup works",
  cards: [
    { n: "001", title: "In your terminal", art: "laptop" },
    { n: "002", title: "In CI", art: "pipeline" },
    { n: "003", title: "In your agent's sandbox", art: "container" },
  ],
};

export const TRUST = {
  title: "Trust, by design.",
  text: "Emfirge is read-only by design. Your account IDs are tokenized on your machine before any model sees them. The engine is open source, so you can read every check.",
  tiles: [
    { mark: "key", label: "Read-only role" },
    { mark: "token", label: "Tokenized IDs" },
    { mark: "open", label: "Open source", sub: "AGPL-3.0 · Apache-2.0" },
  ],
  links: [
    { label: "Security policy", href: LINKS.security },
    { label: "Privacy", href: LINKS.privacy },
  ],
};

export const CTA = {
  title: "Letting agents touch production?",
  text: "If your agents already change your cloud, they should try every change on a branch first. Any agent, through the CLI or MCP.",
  button: "Get started with emfirge",
};

export const WRITING = {
  title: "Writing",
  rows: [
    "Field notes: an AI agent working on real AWS",
    "Why a cloud agent needs a harness",
    "Six questions instead of 15,000 rules",
  ],
  tag: "coming soon",
};

export const FOOTER = {
  tagline: "The harness for AI agents that work on your cloud.",
  cols: [
    { h: "Product", links: [["How it works", LINKS.docs], ["Pricing", LINKS.docs], ["Changelog", LINKS.docs], ["Coverage", LINKS.docs], ["Docs ↗", LINKS.docs]] },
    { h: "Company", links: [["Writing", "#writing"], ["GitHub ↗", LINKS.github], ["Contact", LINKS.mail]] },
    { h: "Connect", links: [["X", ""], ["GitHub", LINKS.ansh], ["ansh@emfirge.cloud", LINKS.mail]] },
  ],
  legal: "© 2026 emfirge",
  status: "All systems operational",
};

// Unknowns, written for Ansh. Not rendered on the page.
export const TODOS = [
  "[TODO Ansh: the CLI announcement post URL; the pill links to the docs until then]",
  "[TODO Ansh: real pages for How it works, Changelog, Pricing and Coverage; the nav links to docs until they exist]",
  "[TODO Ansh: X handle for the footer Connect column; shown as plain text without a link]",
  "[TODO Ansh: status page URL; the status dot links to docs]",
  "[TODO Ansh: confirm the law count: README says 48 but tests tag ids up to L66 (30 distinct)]",
  "[TODO Ansh: cite law numbers for typed, CLI and CloudFormation equivalence, only L20 and L21 are verified]",
  "[TODO Ansh: Writing posts, titles are placeholders with no dates or links]",
];
