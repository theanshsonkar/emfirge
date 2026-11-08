// All copy and demo data for the v5 landing page. See DESIGN-v5.md and DESIGN-v5.1.md.
export const LINKS = {
  docs: "https://emfirge.cloud/docs",
  quickstart: "https://emfirge.cloud/docs/quickstart",
  github: "https://github.com/theanshsonkar/emfirge",
  ansh: "https://github.com/theanshsonkar",
};

export const SITE = {
  url: "https://emfirge.cloud",
  title: "Emfirge: go on, break it",
  description:
    "A demo cloud you try to break. Every switch is something an AI agent might do. Emfirge tries it on a branch, measures the damage, and live never moves.",
  ogAlt: "Go on. Break it. A red BLOCKED stamp beside the Emfirge crash-test mark.",
};

export const COMMAND = "npx @emfirge/cli connect";

export const NAV = {
  skip: "skip to content",
  links: [
    { label: "how it works", href: "#how", hideOnMobile: true },
    { label: "pricing", href: "#pricing" },
    { label: "docs", href: LINKS.docs },
    { label: "github", href: LINKS.github },
  ],
};

export const LIVE_BAR = {
  resources: 9,
  cta: { label: "get started", href: LINKS.quickstart },
};

export const HERO = {
  h1: "Go on. Break it.",
  body:
    "This is a demo cloud. Every switch is something an AI agent might do to yours. Emfirge tries it on a branch, measures the damage, and tells your agent what would break. Live never moves.",
  then: "Then give your agent the same thing:",
};

/* ---------- the demo cloud ---------- */
export type NodeId =
  | "internet"
  | "cdn"
  | "web-alb"
  | "api"
  | "orders-db"
  | "legacy-reports-db"
  | "assets"
  | "nightly-sync"
  | "deploy-role";

export type CloudNode = {
  id: NodeId;
  kind: string;
  metric: string;
  dim?: boolean;
};

export const NODES: CloudNode[] = [
  { id: "internet", kind: "", metric: "" },
  { id: "cdn", kind: "cloudfront", metric: "98% cache hit" },
  { id: "web-alb", kind: "alb", metric: "41 req/s" },
  { id: "api", kind: "ecs service", metric: "3 instances" },
  { id: "orders-db", kind: "rds", metric: "1,240 q/day" },
  { id: "legacy-reports-db", kind: "rds · idle", metric: "0 q/day · 90d", dim: true },
  { id: "assets", kind: "s3", metric: "212 GB · private" },
  { id: "nightly-sync", kind: "lambda", metric: "1 run/night" },
  { id: "deploy-role", kind: "iam role", metric: "12 deploys/wk" },
];

export const EDGES: [NodeId, NodeId][] = [
  ["internet", "cdn"],
  ["cdn", "web-alb"],
  ["web-alb", "api"],
  ["api", "orders-db"],
  ["cdn", "assets"],
  ["nightly-sync", "orders-db"],
];

export type Pos = { x: number; y: number };
export type RouteSpec = { d: string; label: Pos };
export type Layout = {
  w: number;
  h: number;
  nodeW: number;
  nodeH: number;
  pos: Partial<Record<NodeId, Pos>>;
  /** edge paths, keyed "from>to"; an edge missing here is not drawn in this layout */
  edges: Record<string, string>;
  /** red exposure routes from the internet node, by target */
  routes: Partial<Record<NodeId, RouteSpec>>;
};

export const LAYOUTS: { wide: Layout; narrow: Layout } = {
  wide: {
    w: 764,
    h: 218,
    nodeW: 124,
    nodeH: 58,
    pos: {
      internet: { x: 6, y: 40 },
      cdn: { x: 160, y: 40 },
      "web-alb": { x: 314, y: 40 },
      api: { x: 468, y: 40 },
      "orders-db": { x: 622, y: 40 },
      assets: { x: 160, y: 140 },
      "deploy-role": { x: 314, y: 140 },
      "legacy-reports-db": { x: 468, y: 140 },
      "nightly-sync": { x: 622, y: 140 },
    },
    edges: {
      "internet>cdn": "M130 69 H160",
      "cdn>web-alb": "M284 69 H314",
      "web-alb>api": "M438 69 H468",
      "api>orders-db": "M592 69 H622",
      "cdn>assets": "M222 98 V140",
      "nightly-sync>orders-db": "M684 140 V98",
    },
    routes: {
      api: { d: "M68 40 V14 H530 V40", label: { x: 299, y: 14 } },
      assets: { d: "M68 96 V119 H222 V140", label: { x: 145, y: 119 } },
    },
  },
  narrow: {
    w: 372,
    h: 356,
    nodeW: 156,
    nodeH: 58,
    pos: {
      internet: { x: 10, y: 24 },
      "web-alb": { x: 194, y: 24 },
      api: { x: 10, y: 112 },
      "orders-db": { x: 194, y: 112 },
      assets: { x: 10, y: 200 },
      "nightly-sync": { x: 194, y: 200 },
      "deploy-role": { x: 10, y: 288 },
      "legacy-reports-db": { x: 194, y: 288 },
    },
    edges: {
      "internet>web-alb": "M166 53 H194",
      "web-alb>api": "M272 82 V97 H88 V112",
      "api>orders-db": "M166 141 H194",
      "nightly-sync>orders-db": "M272 200 V170",
    },
    routes: {
      api: { d: "M40 82 V112", label: { x: 128, y: 97 } },
      assets: { d: "M10 53 H3 V229 H10", label: { x: 98, y: 186 } },
    },
  },
};

/* ---------- the six questions ---------- */
export type QuestionId = "data" | "exposure" | "money" | "availability" | "control" | "outside";

export const QUESTIONS: { id: QuestionId; name: string; short: string; sentence: string }[] = [
  { id: "data", name: "Data", short: "data", sentence: "Did something holding data disappear with no recovery point?" },
  { id: "exposure", name: "Exposure", short: "exposure", sentence: "Is anything newly reachable from the internet or another account?" },
  { id: "money", name: "Money", short: "money", sentence: "Did the monthly cost go above your limit?" },
  { id: "availability", name: "Availability", short: "availability", sentence: "Did something live traffic depends on break?" },
  { id: "control", name: "Control", short: "control", sentence: "Was access or logging lost: an admin role, a KMS key, CloudTrail?" },
  { id: "outside", name: "Outside world", short: "outside world", sentence: "Does it leave the cloud: support cases, quota requests, emails, domains?" },
];

/* ---------- the seven switches and their results ---------- */
export type Mark = "ok" | "fail" | "ask";
export type Verdict = "blocked" | "ask" | "passed";
export type Fact = { text: string; code?: string; note?: string };
export type Row = { mark: Mark; facts: Fact[] };

export type Damage = {
  removed?: NodeId[];
  broken?: NodeId[];
  flagged?: NodeId[];
  /** changed on the branch and checked clean (a retry's corrected plan) */
  fixed?: NodeId[];
  /** replaces a node's metric line on the branch */
  metrics?: Partial<Record<NodeId, string>>;
  exposure?: { to: NodeId; label: string };
};

export type SwitchDef = {
  id: number;
  line1: string;
  line2: string;
  action: string;
  target: NodeId;
  verdict: Verdict;
  rows: Record<QuestionId, Row>;
  damage: Damage;
  commands: string[];
  summary: string;
};

const ok = (...facts: Fact[]): Row => ({ mark: "ok", facts });
const fail = (...facts: Fact[]): Row => ({ mark: "fail", facts });
const ask = (...facts: Fact[]): Row => ({ mark: "ask", facts });

export const SWITCHES: SwitchDef[] = [
  {
    id: 1,
    line1: "delete",
    line2: "orders-db",
    action: "delete orders-db",
    target: "orders-db",
    verdict: "blocked",
    rows: {
      data: fail({ text: "no recovery point", code: "data_store_deleted_no_recovery_point" }),
      exposure: ok(),
      money: ok({ text: "−$96.40/mo" }),
      availability: fail(
        { text: "1,240 queries/day", code: "recently_used" },
        { text: "nightly-sync depends on it", code: "lost_dependency" },
      ),
      control: ok(),
      outside: ok(),
    },
    damage: {
      removed: ["orders-db"],
      broken: ["api", "nightly-sync"],
      metrics: { "orders-db": "deleted", api: "queries failing", "nightly-sync": "lost orders-db" },
    },
    commands: ["$ emfirge branch new", "$ emfirge try --delete rds:orders-db", "$ emfirge check", "  BLOCKED · data, availability"],
    summary: "orders-db is removed; api and nightly-sync are broken",
  },
  {
    id: 2,
    line1: "open port 22",
    line2: "to the world",
    action: "open port 22 to the world",
    target: "api",
    verdict: "blocked",
    rows: {
      data: ok(),
      exposure: fail({ text: "api ×3 reachable from 0.0.0.0/0 on :22", code: "introduced_critical_exposure" }),
      money: ok(),
      availability: ok(),
      control: ok(),
      outside: ok(),
    },
    damage: {
      broken: ["api"],
      metrics: { api: "ssh open to world" },
      exposure: { to: "api", label: "0.0.0.0/0 :22" },
    },
    commands: ["$ emfirge branch new", "$ emfirge try --open sg:api 22 0.0.0.0/0", "$ emfirge check", "  BLOCKED · exposure"],
    summary: "api is reachable from the internet on port 22",
  },
  {
    id: 3,
    line1: "make the assets",
    line2: "bucket public",
    action: "make the assets bucket public",
    target: "assets",
    verdict: "blocked",
    rows: {
      data: ok(),
      exposure: fail({ text: "assets readable by anyone", code: "newly_internet_reachable" }),
      money: ok(),
      availability: ok(),
      control: ok(),
      outside: ok(),
    },
    damage: {
      broken: ["assets"],
      metrics: { assets: "public read" },
      exposure: { to: "assets", label: "public read" },
    },
    commands: ["$ emfirge branch new", "$ emfirge try --set s3:assets public-read", "$ emfirge check", "  BLOCKED · exposure"],
    summary: "assets is readable by anyone on the internet",
  },
  {
    id: 4,
    line1: "give deploy-role",
    line2: "iam:PassRole on *",
    action: "give deploy-role iam:PassRole on *",
    target: "deploy-role",
    verdict: "blocked",
    rows: {
      data: ok(),
      exposure: ok(),
      money: ok(),
      availability: ok(),
      control: fail({
        text: "deploy-role can become admin in 2 steps",
        code: "privilege_escalation",
        note: "path from pathfinding.cloud",
      }),
      outside: ok(),
    },
    damage: { broken: ["deploy-role"], metrics: { "deploy-role": "admin in 2 steps" } },
    commands: ["$ emfirge branch new", "$ emfirge try --grant iam:deploy-role PassRole '*'", "$ emfirge check", "  BLOCKED · control"],
    summary: "deploy-role can become admin in two steps",
  },
  {
    id: 5,
    line1: "triple",
    line2: "the api fleet",
    action: "triple the api fleet",
    target: "api",
    verdict: "ask",
    rows: {
      data: ok(),
      exposure: ok(),
      money: ask({ text: "+$187.20/mo, over your $30 limit", code: "capacity" }),
      availability: ok(),
      control: ok(),
      outside: ok(),
    },
    damage: { flagged: ["api"], metrics: { api: "9 instances" } },
    commands: ["$ emfirge branch new", "$ emfirge try --scale ecs:api 9", "$ emfirge check", "  ASK OWNER · money"],
    summary: "api grows to 9 instances and needs your sign-off",
  },
  {
    id: 6,
    line1: "ask aws for a",
    line2: "quota increase",
    action: "ask aws for a quota increase",
    target: "nightly-sync",
    verdict: "ask",
    rows: {
      data: ok(),
      exposure: ok(),
      money: ok(),
      availability: ok(),
      control: ok(),
      outside: ask({ text: "opens an aws support case" }),
    },
    damage: { flagged: ["nightly-sync"], metrics: { "nightly-sync": "quota 1,000 → 3,000" } },
    commands: ["$ emfirge branch new", "$ emfirge try --request-quota lambda 3000", "$ emfirge check", "  ASK OWNER · outside world"],
    summary: "a lambda quota request would open an aws support case",
  },
  {
    id: 7,
    line1: "delete",
    line2: "legacy-reports-db",
    action: "delete legacy-reports-db",
    target: "legacy-reports-db",
    verdict: "passed",
    rows: {
      data: ok({ text: "snapshot from today" }),
      exposure: ok(),
      money: ok({ text: "−$41.20/mo" }),
      availability: ok({ text: "no queries in 90 days" }),
      control: ok(),
      outside: ok(),
    },
    damage: { removed: ["legacy-reports-db"], metrics: { "legacy-reports-db": "deleted · snapshot" } },
    commands: ["$ emfirge branch new", "$ emfirge try --delete rds:legacy-reports-db", "$ emfirge check", "  PASSED · all six clear"],
    summary: "legacy-reports-db is removed; nothing depended on it",
  },
];

export const VERDICT = {
  blocked: {
    stamp: "BLOCKED",
    next: "your agent reads this, changes its plan, and tries again. nothing reached live.",
  },
  ask: {
    stamp: "ASK OWNER",
    next: "emfirge asks you. your agent keeps working on something else.",
  },
  passed: {
    stamp: "PASSED",
    next: "safe to apply. your agent applies it with its own access; emfirge records it.",
  },
} as const;

export const BENCH = {
  idleHeader: "test 000 · waiting for you to flip a switch",
  noJs: "turn on JavaScript to run tests",
  reset: "reset bench",
  liveNote: "live · read-only. nothing you flip here touches it.",
  branchNote: "a private copy of live. nothing here reached live.",
  tryAgain: "already tried. showing its branch.",
  duration: "0.4s",
  thrown: (n: number, total: number) => `${n} of ${total} thrown`,
  startHere: "start here",
};

/* ---------- what your agent would have run ---------- */
export const TRANSCRIPT = {
  title: "What your agent would have run",
  steps: [
    { n: "1", name: "branch", text: "a copy of your live cloud" },
    { n: "2", name: "try", text: "the change goes on the copy" },
    { n: "3", name: "check", text: "six questions, answered with facts" },
  ],
  agents: "Works with any agent that can run a shell: Claude Code, Codex, Cursor, Gemini CLI, Kiro, Cline.",
  captionTest: "the last test you ran",
  captionExample: "test 1, as an example",
};

/* ---------- six questions ---------- */
export const SIX = {
  title: "Six questions. Every change.",
  note: "Yellow means you decide. Thresholds like the $30 limit are yours to set in emfirge.md.",
};

/* ---------- why i built it ---------- */
export const NOTE = {
  title: "Why I built it",
  paragraphs: [
    "I gave an AI agent my AWS to ship a small podcast project. It was good at it, and quiet about things. It asked AWS for a Lambda quota increase without telling me; I found out from a support case. A cache policy change sent my feed to a 404. A deploy script turned a paused schedule back on.",
    "None of it was the agent being dumb. It had nowhere safe to try a change, and I had no way to see what it was about to do. Switches 1 to 6 above are those moments.",
    "So I built the crash test I wanted. It's early. Break it, and tell me what it missed.",
  ],
  signedAs: "Ansh",
};

/* ---------- pricing ---------- */
export const PRICING = {
  title: "Free while in beta.",
  sub: "One AWS account, every feature, no card.",
  cta: { label: "get started", href: LINKS.quickstart },
  features: [
    "works with any agent that runs a shell",
    "branches of your live aws",
    "six checks on every change",
    "terraform, cloudformation, cli and api changes",
    "read-only role, revoke any time",
    "ids tokenized on your machine",
    "emfirge.md boundaries",
    "record checked against cloudtrail",
  ],
};

/* ---------- faq (text carried over from v4) ---------- */
export const FAQ = {
  title: "Questions, answered.",
  items: [
    {
      q: "does emfirge change my aws?",
      a: "no. it connects with a read-only role, so it can look but not touch. every change is tried on a branch, a private copy that never reaches your real account. you apply a plan yourself, when you decide to.",
    },
    {
      q: "which agents work?",
      a: "any agent that can run a shell command. emfirge is a command line tool, so there is nothing to plug in. if your agent can type `emfirge check`, it works.",
    },
    {
      q: "which clouds?",
      a: "aws, for now. it's what i use every day, so it's the one i'm making solid first.",
    },
    {
      q: "is a pass a guarantee?",
      a: "no. a pass means that on the six checks, nothing on the branch predicts damage, and you can see the evidence. it's a fact about the plan, not a promise about the world. you still decide whether to apply it.",
    },
    {
      q: "what does it cost after beta?",
      a: "we'll tell you well before beta ends. there will always be a free tier for one account.",
    },
    {
      q: "is it open source?",
      a: "the engine is open source (AGPL-3.0) and the cli is Apache-2.0. the code is on github.",
    },
  ],
};

export const FOOTER = {
  line: "Crash-test every change before it touches your cloud.",
  links: [
    { label: "docs", href: LINKS.docs },
    { label: "github", href: LINKS.github },
  ],
  built: "Built by Ansh Sonkar",
  copy: "© 2026 Emfirge",
};


/* ---------- v5.1: the loop ---------- */
/** The agent's corrected plan for a blocked switch. Always passes. */
export type Retry = {
  switchId: number;
  /** the plan, as one header line */
  plan: string;
  action: string;
  target: NodeId;
  rows: Record<QuestionId, Row>;
  damage: Damage;
  commands: string[];
  summary: string;
};

export const RETRIES: Retry[] = [
  {
    switchId: 1,
    plan: "keep orders-db; delete legacy-reports-db only",
    action: "delete legacy-reports-db only",
    target: "legacy-reports-db",
    rows: {
      data: ok({ text: "snapshot from today" }),
      exposure: ok(),
      money: ok({ text: "−$41.20/mo" }),
      availability: ok({ text: "no queries in 90 days" }),
      control: ok(),
      outside: ok(),
    },
    damage: {
      removed: ["legacy-reports-db"],
      fixed: ["orders-db"],
      metrics: { "legacy-reports-db": "deleted · snapshot", "orders-db": "kept · 1,240 q/day" },
    },
    commands: ["$ emfirge branch new", "$ emfirge try --delete rds:legacy-reports-db", "$ emfirge check", "  PASSED · all six clear"],
    summary: "orders-db is kept; only legacy-reports-db is removed",
  },
  {
    switchId: 2,
    plan: "open :22 to 203.0.113.7/32 only (your office)",
    action: "open port 22 to 203.0.113.7/32 only",
    target: "api",
    rows: {
      data: ok(),
      exposure: ok({ text: "reachable from 1 address, not the internet" }),
      money: ok(),
      availability: ok(),
      control: ok(),
      outside: ok(),
    },
    damage: { fixed: ["api"], metrics: { api: "ssh from 1 address" } },
    commands: ["$ emfirge branch new", "$ emfirge try --open sg:api 22 203.0.113.7/32", "$ emfirge check", "  PASSED · all six clear"],
    summary: "api accepts ssh from one office address only",
  },
  {
    switchId: 3,
    plan: "serve assets through cdn with origin access control; bucket stays private",
    action: "serve assets through cdn, bucket stays private",
    target: "assets",
    rows: {
      data: ok(),
      exposure: ok({ text: "nothing newly reachable" }),
      money: ok(),
      availability: ok({ text: "cdn 98% cache hit unchanged" }),
      control: ok(),
      outside: ok(),
    },
    damage: {
      fixed: ["assets", "cdn"],
      metrics: { assets: "private · cdn only", cdn: "98% cache hit, oac" },
    },
    commands: ["$ emfirge branch new", "$ emfirge try --set cloudfront:cdn origin-access-control s3:assets", "$ emfirge check", "  PASSED · all six clear"],
    summary: "assets stays private and is served through the cdn",
  },
  {
    switchId: 4,
    plan: "PassRole only on role/app-runtime",
    action: "PassRole only on role/app-runtime",
    target: "deploy-role",
    rows: {
      data: ok(),
      exposure: ok(),
      money: ok(),
      availability: ok(),
      control: ok({ text: "no new escalation path", note: "checked against pathfinding.cloud" }),
      outside: ok(),
    },
    damage: { fixed: ["deploy-role"], metrics: { "deploy-role": "PassRole: app-runtime" } },
    commands: ["$ emfirge branch new", "$ emfirge try --grant iam:deploy-role PassRole role/app-runtime", "$ emfirge check", "  PASSED · all six clear"],
    summary: "deploy-role can pass only the app-runtime role",
  },
];

export const LOOP = {
  retryButton: "let the agent fix it",
  retryAbove: "same goal, different plan. the agent read the facts and changed it.",
  retryOf: "retry of test",
  planLabel: "plan",
  fixedNote: "fixed by agent",
  seeRetry: (n: number) => `see the retry · branch #${n}`,
  seeOriginal: (n: number) => `see the blocked try · branch #${n}`,
};

export type OwnerDecision = "approved" | "denied";

export const OWNER = {
  prompt: ["emfirge is asking ", "you", ". you're the owner here."],
  approve: {
    label: "approve",
    stamp: "APPROVED BY YOU",
    line: "your agent applies it with its own access. emfirge records who approved it.",
    note: "demo: live still untouched.",
  },
  deny: {
    label: "deny",
    stamp: "DENIED BY YOU",
    line: "your agent drops it and moves on.",
    note: "",
  },
} as const;

/* ---------- v5.1: the lab report ---------- */
export const LAB = {
  title: "LAB REPORT",
  seeLink: "see your lab report",
  seeLinkShort: "lab report",
  summaryLine: (n: number) => `${n} disasters tried. live: untouched.`,
  give: "now give your agent the same bench:",
  copy: "copy summary",
  copied: "copied",
  chips: { blocked: "BLOCKED", ask: "ASK OWNER", passed: "PASSED" },
  notes: { fixed: "fixed by agent", approved: "approved", denied: "denied" },
  /** the plain-text summary, for X or Slack */
  text: (c: { total: number; blocked: number; asked: number; passed: number }) =>
    `I tried to break a demo cloud on emfirge.cloud:\n${c.total} tests · ${c.blocked} blocked · ${c.asked} asked me · ${c.passed} passed · live untouched`,
};
