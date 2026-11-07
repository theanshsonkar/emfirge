/* All page copy lives here. Components only lay it out. */

export const LINKS = {
  home: "https://emfirge.cloud",
  docs: "https://emfirge.cloud/docs",
  github: "https://github.com/theanshsonkar/emfirge",
  changelog: "https://github.com/theanshsonkar/emfirge/releases",
  privacy: "https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md",
  security: "https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md",
  email: "mailto:ansh@emfirge.cloud",
} as const;

export const CONNECT_CMD = "npx @emfirge/cli connect";

export interface LinkItem {
  label: string;
  href: string;
}

export const SITE = {
  title: "Emfirge: the harness for cloud agents",
  description:
    "Emfirge gives your coding agent a true model of your AWS, a branch to try changes on, and facts about what would break, before anything reaches production.",
};

export const ANNOUNCE = {
  text: "New: the emfirge CLI. Six verbs, any agent.",
  link: { label: "Read the docs", href: LINKS.docs },
  dismiss: "Dismiss announcement",
};

export const NAV = {
  home: "Emfirge home",
  items: [
    { label: "Product", href: "#product" },
    { label: "Docs", href: LINKS.docs },
    { label: "GitHub", href: LINKS.github },
    { label: "Changelog", href: LINKS.changelog },
  ] satisfies LinkItem[],
  signIn: { label: "Sign in", href: LINKS.home },
  start: { label: "Get started", href: "#get-started" },
  skip: "Skip to content",
};

export const HERO = {
  title: "The harness for cloud agents",
  body: "Your agent gets a true model of your AWS, a branch to try changes on, and facts about what would break. Production never sees a guess.",
  primary: { label: "Get started", href: "#get-started" },
  secondary: { label: "Read the docs", href: LINKS.docs },
  copy: "Copy command",
  copied: "Copied",
};

export const FORK = {
  alt: "A trunk line labelled live runs left to right with commit dots. Branch number 1 forks off, is tried, and ends in a red cross. Branch number 2 forks off, ends in a green check, and merges back into the trunk.",
  trunk: "live",
  branch1: "branch #1",
  branch2: "branch #2",
};

export const WORKS_WITH = {
  heading: "Works with the agent you already use.",
  agents: ["Claude Code", "Codex", "Cursor", "Gemini CLI", "Kiro", "Cline"],
};

export type LineTone = "cmd" | "out" | "block" | "pass";
export interface TermLine {
  tone: LineTone;
  text: string;
}
export type Signal = "block" | "pass";
export interface LogRow {
  time: string;
  signal: Signal;
  area: string;
  text: string;
}

export const SPLIT = {
  id: "product",
  title: "Your agent tries it on a branch. You read one result.",
  body: "Before anything touches production, the change runs against a copy of your live AWS. Six questions about the result come back as facts. Your agent fixes its own plan.",
  agent: {
    label: "Agent view",
    title: "Your terminal. One command.",
    mockLabel: "Terminal mock: an agent runs emfirge try, then emfirge check",
    path: "~/cloud-cleanup",
    lines: [
      { tone: "cmd", text: "emfirge try --delete rds:orders-db rds:legacy-reports-db" },
      { tone: "out", text: "2 changes on branch #1" },
      { tone: "cmd", text: "emfirge check" },
      { tone: "block", text: "block · 2 of 6 checks failed" },
    ] satisfies TermLine[],
  },
  branch: {
    label: "The branch",
    title: "Six checks. Every change.",
    mockLabel: "Console mock: the six checks on branch number 1, two block and four pass",
    pills: { block: "Block", pass: "Pass" } satisfies Record<Signal, string>,
    rows: [
      { time: "14:02:36.04", signal: "block", area: "data", text: "orders-db has no recovery point" },
      { time: "14:02:36.05", signal: "block", area: "availability", text: "orders-db served 1,240 queries/day" },
      { time: "14:02:36.05", signal: "pass", area: "exposure", text: "nothing newly reachable" },
      { time: "14:02:36.06", signal: "pass", area: "money", text: "−$41.20/mo" },
      { time: "14:02:36.06", signal: "pass", area: "control", text: "no access or logging lost" },
      { time: "14:02:36.07", signal: "pass", area: "outside world", text: "no external side effects" },
    ] satisfies LogRow[],
  },
};

export type WorldMock =
  | { kind: "table"; head: string[]; rows: string[][] }
  | { kind: "branches"; rows: { name: string; branch: string; state: "block" | "pass" | "live" }[] }
  | { kind: "doc"; lines: { text: string; hard?: boolean }[] }
  | { kind: "timeline"; rows: { time: string; text: string }[] };

export interface WorldCard {
  title: string;
  body: string;
  tone: "dark" | "light";
  mockLabel: string;
  mock: WorldMock;
}

export const WORLD = {
  title: "The world your agent works in.",
  body: "Coding agents got files, branches, tests and a log. Cloud agents get the same.",
  cards: [
    {
      title: "Context. Ask what's true.",
      body: "What exists, what's live, what depends on what.",
      tone: "dark",
      mockLabel: "Mock: a table of three resources with state, load and dependents",
      mock: {
        kind: "table",
        head: ["resource", "type", "state", "load", "dependents"],
        rows: [
          ["orders-db", "rds", "live", "1,240 q/day", "3"],
          ["checkout-api", "lambda", "live", "8,900 req/day", "5"],
          ["legacy-reports-db", "rds", "idle", "0 q/day", "0"],
        ],
      },
    },
    {
      title: "Branch. Try anything.",
      body: "A copy of your live AWS. Fork it, compare it, throw it away.",
      tone: "dark",
      mockLabel: "Mock: a list of branches with their result, next to live",
      mock: {
        kind: "branches",
        rows: [
          { name: "#1", branch: "cleanup-dbs", state: "block" },
          { name: "#2", branch: "cleanup-dbs", state: "pass" },
          { name: "live", branch: "", state: "live" },
        ],
      },
    },
    {
      title: "Boundaries. Write your intent once.",
      body: "Plain English in emfirge.md. Hard lines are enforced.",
      tone: "light",
      mockLabel: "Mock: an emfirge.md file with four lines",
      mock: {
        kind: "doc",
        lines: [
          { text: "# emfirge.md" },
          { text: "Keep spend under $4,000 a month." },
          { text: "Ask me before touching IAM." },
          { text: "hard: nothing becomes publicly reachable", hard: true },
        ],
      },
    },
    {
      title: "Record. Know what happened.",
      body: "Every applied change, checked against CloudTrail.",
      tone: "light",
      mockLabel: "Mock: a three-line timeline of an applied change",
      mock: {
        kind: "timeline",
        rows: [
          { time: "14:09", text: "applied cleanup-dbs #2 by claude-code" },
          { time: "14:09", text: "CloudTrail matched, 2 events, 0 unexpected" },
          { time: "14:10", text: "recorded, spend −$41.20/mo" },
        ],
      },
    },
  ] satisfies WorldCard[],
};

export const PRINCIPLES = {
  title: "Built so you can trust it.",
  items: [
    {
      title: "Read-only. Always.",
      body: "Emfirge never writes to your cloud. Your agent applies with its own access, and Emfirge records it.",
    },
    {
      title: "No AI inside.",
      body: "The same branch always gives the same answer. Nothing can talk it into a pass.",
    },
    {
      title: "Unknown never passes.",
      body: "If a change can't be modeled, the result says so. A missing check is reported, not hidden.",
    },
  ],
};

export const NUMBERS = {
  label: "Numbers from the repository",
  items: [
    { figure: "48", label: "laws every release must pass" },
    { figure: "2,428", label: "engine tests" },
    { figure: "92", label: "IAM escalation paths, from pathfinding.cloud" },
  ],
};

export const CTA = {
  id: "get-started",
  title: "Give your agent a branch of your cloud.",
  primary: { label: "Get started", href: LINKS.docs },
  secondary: { label: "Read the docs", href: LINKS.docs },
};

export const FOOTER = {
  tagline: "The harness for cloud agents.",
  columns: [
    {
      title: "Product",
      links: [
        { label: "CLI", href: LINKS.docs },
        { label: "Docs", href: LINKS.docs },
        { label: "Changelog", href: LINKS.changelog },
      ],
    },
    {
      title: "Open source",
      links: [
        { label: "GitHub", href: LINKS.github },
        { label: "Engine (AGPL-3.0)", href: LINKS.github },
        { label: "CLI (Apache-2.0)", href: LINKS.github },
      ],
    },
    {
      title: "Trust",
      links: [
        { label: "Privacy", href: LINKS.privacy },
        { label: "Security", href: LINKS.security },
      ],
    },
    {
      title: "Contact",
      links: [{ label: "ansh@emfirge.cloud", href: LINKS.email }],
    },
  ] satisfies { title: string; links: LinkItem[] }[],
  legal: "© 2026 Emfirge · Built by Ansh Sonkar",
};
