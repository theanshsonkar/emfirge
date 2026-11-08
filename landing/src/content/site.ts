// Home-page copy and numbers (v6 look, v7 links). Inner pages live in the other files of this folder. See DESIGN-v7.md.
//
// REAL NUMBERS (counted from the repo on 2026-11-08, never estimated; sources in landing/FACTS.md, section 4.1):
//  - Engine tests 3,247: `cd backend && python3 -m pytest --collect-only -q` ("3247 tests collected"; parametrized cases
//    included). A full run on 2026-11-08: 3243 passed, 3 skipped, 1 xfailed.
//  - MCP + CLI tests 206: `cd mcp && npm test` -> "# tests 206, pass 206".
//  - Laws 88: distinct L1..L88 ids in backend/tests (87) plus mcp/src/tokenize-leaks.test.ts (L81). README still says 48.
//  - Resource types 18: len(app.mutations.SUPPORTED_RESOURCE_TYPES).
//  - Escalation paths 92: len(app/data/pathfinding_paths.json["paths"]).
//  - Scanner check reads 55: len(app/data/scanner_check_reads.json).
//  - Native reason codes 32: distinct codes passed to _reason(...) in app/verdict.py.
//  - Prowler check metadata files 21: app/data/third_party/prowler/checks/*.metadata.json.
//  - Severity crosswalk entries 21: len(app/data/scanner_severity_crosswalk.json).
//  - MCP tools 27: count of `name: "emfirge_` in mcp/src/tools-registry.ts.

export const LINKS = {
  site: "https://emfirge.cloud",
  quickstart: "/quickstart/",
  how: "/how-it-works/",
  cli: "/cli/",
  coverage: "/coverage/",
  security: "/security/",
  pricing: "/pricing/",
  changelog: "/changelog/",
  faq: "/faq/",
  github: "https://github.com/theanshsonkar/emfirge",
  ansh: "https://github.com/theanshsonkar",
  mail: "mailto:ansh@emfirge.cloud",
  securityPolicy: "https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md",
  privacy: "https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md",
  iamRole: "https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml",
};

export const SITE = {
  title: "Emfirge: the harness for AI agents that work on your cloud",
  description:
    "Emfirge gives AI agents a true model of your AWS, a branch for every change, and six checks with no AI inside.",
};

export const SETUP_PROMPT = "Set up emfirge in this project. Read https://emfirge.cloud/index.md and follow it.";
export const COMMAND = "npx emfirge connect";

export const RAIL_NAV = [
  { label: "Home", href: "/" },
  { label: "Quickstart", href: "/quickstart/" },
  { label: "How it works", href: "/how-it-works/" },
  { label: "CLI", href: "/cli/" },
  { label: "Coverage", href: "/coverage/" },
  { label: "Security & privacy", href: "/security/" },
  { label: "Pricing", href: "/pricing/" },
  { label: "Changelog", href: "/changelog/" },
  { label: "FAQ", href: "/faq/" },
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
  pillLink: "See the CLI",
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
    "Figure 1. A change enters emfirge in any format and runs on a branch of your live cloud. Six checks answer with facts, and the verdict reads pass, warn or block. The agent reads them, changes its plan and tries again. The change that is left comes back as a hand-back, bound by hash to its verdict.",
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
      text: "Data, exposure, money, availability, control, outside world. Deterministic, and what it cannot check is listed as unknown, never as safe.",
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
    // 3,247 from pytest --collect-only; 206 from `npm test` in mcp/.
    rows: [
      { name: "Engine (backend)", value: 3247 },
      { name: "MCP + CLI", value: 206 },
    ],
  },
  laws: { title: "Laws", sub: "Properties that must always hold", value: 88 },
  types: { title: "Resource types", sub: "AWS types a branch can add, modify or delete", value: 18 },
  sources: {
    title: "Where the checks come from",
    sub: "Counts from the repo, not hand-written lists",
    headline: 92,
    headlineLabel: "privilege-escalation paths, from pathfinding.cloud",
    bars: [
      { label: "PATHS", name: "pathfinding.cloud escalation paths", value: 92 },
      { label: "READS", name: "scanner check reads", value: 55 },
      { label: "NATIVE", name: "native reason codes in verdict.py", value: 32, own: true },
      { label: "PROWLER", name: "Prowler check metadata files", value: 21 },
      { label: "CROSSWALK", name: "scanner severity crosswalk entries", value: 21 },
    ],
    link: "See the sources",
  },
  same: {
    title: "Same change, same answer",
    sub: "The same change, in five input formats",
    cols: ["Format", "Verdict"],
    // law: the law that pins this format to the AWS API call; note: why there is none.
    rows: [
      { name: "Typed change", note: "the form the others become" },
      { name: "AWS CLI", law: "L18" },
      { name: "AWS API", note: "the reference" },
      { name: "Terraform", law: "L21" },
      { name: "CloudFormation", law: "L19" },
    ] as { name: string; law?: string; note?: string }[],
    foot: "L18 pins an AWS CLI command, L19 a CloudFormation change set and L21 a Terraform ingress rule to the same verdict as the equivalent AWS API call, and L20 pins ::/0 to 0.0.0.0/0.",
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
    { label: "Security policy", href: LINKS.securityPolicy },
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
    { h: "Product", links: [["Quickstart", "/quickstart/"], ["How it works", "/how-it-works/"], ["CLI", "/cli/"], ["Coverage", "/coverage/"], ["Pricing", "/pricing/"], ["Changelog", "/changelog/"], ["FAQ", "/faq/"]] },
    { h: "Company", links: [["Security & privacy", "/security/"], ["GitHub ↗", LINKS.github], ["Contact", LINKS.mail]] },
    { h: "Connect", links: [["X", ""], ["GitHub", LINKS.ansh], ["ansh@emfirge.cloud", LINKS.mail]] },
  ],
  legal: "© 2026 emfirge",
  status: "All systems operational",
};

// Unknowns, written for Ansh. Not rendered on the home page. (Inner-page TODOs are written in place in each page file
// as [TODO Ansh: ...] and rendered visibly.)
export const TODOS = [
  "[TODO Ansh: the CLI announcement post URL; the home pill links to /cli/ until then]",
  "[TODO Ansh: X handle for the footer Connect column; shown as plain text without a link]",
  "[TODO Ansh: status page URL; the footer status dot is not linked]",
  "[TODO Ansh: the typed-change row of \"Same change, same answer\" has no law that compares it with the AWS API call (L18, L19 and L21 cover the CLI, CloudFormation and Terraform); add one or keep the note]",
  "[TODO Ansh: npm shows emfirge 0.1.1 as latest, while the repo's CLI is 0.2.9; publish the current CLI before the site goes live]",
  "[TODO Ansh: Writing posts, titles are placeholders with no dates or links]",
];
