import {
  Activity,
  BookOpenCheck,
  Cloud,
  Cpu,
  Database,
  EyeOff,
  Globe,
  HardDrive,
  KeyRound,
  LifeBuoy,
  type LucideIcon,
  Network,
  Scale,
  Server,
  ShieldAlert,
  ShieldCheck,
  Wallet,
  Zap,
} from "lucide-react";

export const LINKS = {
  docs: "https://emfirge.cloud/docs",
  github: "https://github.com/theanshsonkar/emfirge",
  privacy: "https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md",
  security: "https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md",
  email: "mailto:ansh@emfirge.cloud",
} as const;

export const CONNECT_CMD = "npx @emfirge/cli@latest connect";

export const NAV_ITEMS = [
  { label: "Harness", href: "#harness" },
  { label: "How it works", href: "#how-it-works" },
  { label: "Safety", href: "#safety" },
  { label: "Docs", href: LINKS.docs },
] as const;

export const HERO = {
  eyebrow: "emfirge cli v1 · AWS",
  sub: "A true model of your AWS, a branch to try changes on, and facts about what would break. Your agent gets all three before it touches production.",
  note: "Read-only. Works with any agent that can run a shell.",
};

/* ------------------------------------------------------------------ */
/* Terminal vocabulary (shared by the canvas panel and How it works)   */
/* ------------------------------------------------------------------ */

export type Tone = "paper" | "muted" | "forge" | "pass" | "block";
export interface TermSeg {
  text: string;
  tone?: Tone;
  bold?: boolean;
}
export interface TermLine {
  who?: "you" | "agent";
  segs: TermSeg[];
  /** type the line out character by character */
  type?: boolean;
}

export const cmd = (verb: string, args = ""): TermSeg[] => [
  { text: "$ emfirge " },
  { text: verb, tone: "forge" },
  ...(args ? [{ text: ` ${args}` }] : []),
];
export const out = (text: string): TermLine => ({ segs: [{ text, tone: "muted" }] });

/* ------------------------------------------------------------------ */
/* Cloud canvas: nodes, edges and the scripted 7-step story            */
/* ------------------------------------------------------------------ */

export type NodeKind = "cdn" | "alb" | "ec2" | "rds" | "s3" | "lambda" | "iam";
export type NodeId =
  | "cdn"
  | "web-alb"
  | "api-1"
  | "api-2"
  | "orders-db"
  | "legacy-reports-db"
  | "assets"
  | "nightly-sync"
  | "deploy-role";
export type LayoutId = "desktop" | "compact";
export interface Pos {
  x: number;
  y: number;
}

export interface KindStyle {
  icon: LucideIcon;
  service: string;
  /** tint color (hex) */
  color: string;
}
export const KIND: Record<NodeKind, KindStyle> = {
  cdn: { icon: Cloud, service: "CloudFront", color: "#B79CFF" },
  alb: { icon: Network, service: "ALB", color: "#5AA9FF" },
  ec2: { icon: Server, service: "EC2", color: "#FF9A5C" },
  rds: { icon: Database, service: "RDS", color: "#3BD6E0" },
  s3: { icon: HardDrive, service: "S3", color: "#9BE564" },
  lambda: { icon: Zap, service: "Lambda", color: "#F5B83D" },
  iam: { icon: KeyRound, service: "IAM", color: "#F58AC2" },
};

export interface CanvasNode {
  id: NodeId;
  kind: NodeKind;
  /** position per layout; a missing layout hides the node there */
  pos: Partial<Record<LayoutId, Pos>>;
}
export interface CanvasEdge {
  from: NodeId;
  to: NodeId;
  /** live traffic: animated dots flow along it */
  traffic?: boolean;
  /** drawn dotted and quiet */
  idle?: boolean;
}

export const LAYOUT: Record<LayoutId, { w: number; h: number; nodeW: number; nodeH: number }> = {
  desktop: { w: 860, h: 500, nodeW: 172, nodeH: 58 },
  compact: { w: 400, h: 470, nodeW: 164, nodeH: 54 },
};

export const CANVAS_NODES: CanvasNode[] = [
  { id: "cdn", kind: "cdn", pos: { desktop: { x: 14, y: 196 }, compact: { x: 14, y: 18 } } },
  { id: "web-alb", kind: "alb", pos: { desktop: { x: 236, y: 196 }, compact: { x: 222, y: 18 } } },
  { id: "api-1", kind: "ec2", pos: { desktop: { x: 458, y: 124 }, compact: { x: 222, y: 120 } } },
  { id: "api-2", kind: "ec2", pos: { desktop: { x: 458, y: 268 } } },
  { id: "orders-db", kind: "rds", pos: { desktop: { x: 680, y: 150 }, compact: { x: 222, y: 222 } } },
  { id: "legacy-reports-db", kind: "rds", pos: { desktop: { x: 680, y: 330 }, compact: { x: 222, y: 330 } } },
  { id: "assets", kind: "s3", pos: { desktop: { x: 14, y: 346 } } },
  { id: "nightly-sync", kind: "lambda", pos: { desktop: { x: 458, y: 28 }, compact: { x: 14, y: 330 } } },
  { id: "deploy-role", kind: "iam", pos: { desktop: { x: 236, y: 390 } } },
];

export const CANVAS_EDGES: CanvasEdge[] = [
  { from: "cdn", to: "web-alb", traffic: true },
  { from: "web-alb", to: "api-1", traffic: true },
  { from: "web-alb", to: "api-2", traffic: true },
  { from: "api-1", to: "orders-db", traffic: true },
  { from: "api-2", to: "orders-db", traffic: true },
  { from: "cdn", to: "assets", idle: true },
  { from: "nightly-sync", to: "orders-db", idle: true },
  { from: "deploy-role", to: "api-2", idle: true },
];

export type ChipTone = "live" | "branch" | "block" | "pass";
export interface Callout {
  node: NodeId;
  tone: "block" | "pass";
  head: string;
  text: string;
  pos: Record<LayoutId, Pos & { w: number }>;
  /** seconds, relative to the step starting */
  delay?: number;
}
export interface CanvasStep {
  /** active tab */
  tab: string;
  /** tabs that exist at this step */
  tabs: string[];
  branch: boolean;
  chip: { label: string; tone: ChipTone };
  ghost?: NodeId[];
  gone?: NodeId[];
  /** edges ("from>to") drawn red and dashed */
  dead?: string[];
  shake?: NodeId[];
  callouts?: Callout[];
  toast?: { text: string; tone: "branch" | "pass" };
  /** terminal lines added at this step */
  lines: TermLine[];
  /** how long the step holds, ms */
  ms: number;
}

const DB_DEAD = ["api-1>orders-db", "api-2>orders-db", "nightly-sync>orders-db"];

export const CANVAS_TABS = ["live", "branch #1", "branch #2"];

export const CANVAS_SCRIPT: CanvasStep[] = [
  {
    tab: "live",
    tabs: ["live"],
    branch: false,
    chip: { label: "live · 9 resources", tone: "live" },
    lines: [{ who: "you", segs: [{ text: "Clean up the unused databases." }] }],
    ms: 1300,
  },
  {
    tab: "branch #1",
    tabs: ["live", "branch #1"],
    branch: true,
    chip: { label: "0 changes", tone: "branch" },
    toast: { text: "forked from live", tone: "branch" },
    lines: [
      { who: "agent", segs: cmd("branch", "new"), type: true },
      out("branch #1 forked from live"),
    ],
    ms: 1500,
  },
  {
    tab: "branch #1",
    tabs: ["live", "branch #1"],
    branch: true,
    chip: { label: "2 changes", tone: "branch" },
    ghost: ["orders-db", "legacy-reports-db"],
    dead: DB_DEAD,
    lines: [
      { who: "agent", segs: cmd("try", "--delete orders-db legacy-reports-db"), type: true },
      out("2 changes on branch #1"),
    ],
    ms: 1500,
  },
  {
    tab: "branch #1",
    tabs: ["live", "branch #1"],
    branch: true,
    chip: { label: "BLOCK", tone: "block" },
    ghost: ["orders-db", "legacy-reports-db"],
    dead: DB_DEAD,
    shake: ["api-1", "api-2"],
    callouts: [
      {
        node: "orders-db",
        tone: "block",
        head: "data",
        text: "no recovery point",
        pos: { desktop: { x: 690, y: 222, w: 164 }, compact: { x: 20, y: 206, w: 196 } },
        delay: 0.45,
      },
      {
        node: "orders-db",
        tone: "block",
        head: "availability",
        text: "1,240 queries/day",
        pos: { desktop: { x: 690, y: 270, w: 164 }, compact: { x: 20, y: 256, w: 196 } },
        delay: 0.7,
      },
    ],
    lines: [
      { who: "agent", segs: cmd("check"), type: true },
      { segs: [{ text: "BLOCK", tone: "block", bold: true }] },
      { segs: [{ text: "✗ ", tone: "block" }, { text: "data  orders-db has no recovery point" }] },
      { segs: [{ text: "✗ ", tone: "block" }, { text: "availability  1,240 queries/day" }] },
    ],
    ms: 2200,
  },
  {
    tab: "branch #2",
    tabs: ["live", "branch #1", "branch #2"],
    branch: true,
    chip: { label: "1 change", tone: "branch" },
    ghost: ["legacy-reports-db"],
    lines: [
      { who: "agent", segs: [{ text: "Keeping orders-db." }], type: true },
      out("branch #2 · 1 change"),
    ],
    ms: 1500,
  },
  {
    tab: "branch #2",
    tabs: ["live", "branch #1", "branch #2"],
    branch: true,
    chip: { label: "PASS", tone: "pass" },
    ghost: ["legacy-reports-db"],
    callouts: [
      {
        node: "legacy-reports-db",
        tone: "pass",
        head: "saves $41.20/mo",
        text: "nothing live depends on it",
        pos: { desktop: { x: 640, y: 410, w: 214 }, compact: { x: 172, y: 396, w: 212 } },
        delay: 0.4,
      },
    ],
    lines: [
      { who: "agent", segs: cmd("check", "--branch 2"), type: true },
      { segs: [{ text: "PASS", tone: "pass", bold: true }, { text: "  saves $41.20/mo" }] },
    ],
    ms: 2300,
  },
  {
    tab: "live",
    tabs: ["live", "branch #1", "branch #2"],
    branch: false,
    chip: { label: "applied", tone: "pass" },
    gone: ["legacy-reports-db"],
    toast: { text: "verified in CloudTrail ✓", tone: "pass" },
    lines: [
      { who: "agent", segs: cmd("report", "--applied"), type: true },
      { segs: [{ text: "recorded · verified in CloudTrail ", tone: "muted" }, { text: "✓", tone: "pass" }] },
    ],
    ms: 2300,
  },
];
/** held after the last step before the loop restarts */
export const CANVAS_RESET_PAUSE_MS = 1300;
/** step shown (statically) under reduced motion: BLOCK with callouts */
export const CANVAS_REDUCED_STEP = 3;

export const CANVAS_ARIA =
  "Cloud canvas: an agent is asked to clean up unused databases. It opens a branch of your live AWS, tries deleting orders-db and legacy-reports-db, and Emfirge blocks it: orders-db has no recovery point and serves 1,240 queries a day. The agent keeps orders-db, tries again deleting only legacy-reports-db, gets a pass that saves $41.20 a month, applies it, and the change is verified in CloudTrail.";
export const CANVAS_STORY_TEXT = [
  "1. On the live canvas, traffic flows from CloudFront to the load balancer, the API servers and orders-db. You ask the agent to clean up the unused databases.",
  "2. The agent runs emfirge branch new. Branch 1 forks from live.",
  "3. It tries deleting orders-db and legacy-reports-db on the branch. Both fade out and the edges into orders-db break.",
  "4. emfirge check blocks it: data has no recovery point and availability, 1,240 queries a day.",
  "5. The agent keeps orders-db and opens branch 2 with only legacy-reports-db removed.",
  "6. emfirge check passes: saves $41.20 a month and nothing live depends on it.",
  "7. The agent applies it. Back on live, legacy-reports-db is gone and the change is verified in CloudTrail.",
];

/* ------------------------------------------------------------------ */
/* Works with                                                          */
/* ------------------------------------------------------------------ */

export const AGENTS = ["Claude Code", "Codex", "Cursor", "Gemini CLI", "Kiro", "Cline", "Aider", "your own agent"];

/* ------------------------------------------------------------------ */
/* Harness (problem + comparison, bento)                               */
/* ------------------------------------------------------------------ */

export const HARNESS = {
  eyebrow: "The problem",
  h2: "Coding agents got a harness. *Cloud* agents didn't.",
  lead: "Nobody trusts an agent with their cloud: it can't see what's live, can't try before it does, and you can't see what it did. So we built it the harness coding agents already have.",
};

export const BENTO = {
  context: {
    coding: "Files",
    name: "Context",
    body: "A queryable model of your cloud: what exists, what's live, what depends on what.",
    tooltip: ["orders-db · live", "1,240 q/day · 3 dependents"],
  },
  branch: {
    coding: "Git branch",
    name: "Branch",
    body: "A copy of your live AWS to try changes on.",
  },
  signals: {
    coding: "Tests",
    name: "Signals",
    body: "The diff, six damage answers, evidence, unknowns.",
  },
  boundaries: {
    coding: "Permissions",
    name: "Boundaries",
    body: "Plain English. Agents read it as context; Emfirge enforces the hard lines as boundaries.",
  },
  record: {
    coding: "Commit log",
    name: "Record",
    body: "What happened, predicted vs actual.",
    events: [
      { time: "14:02", text: "branch #2", tag: "PASS", tone: "pass" as const },
      { time: "14:03", text: "applied by agent", tone: "muted" as const },
      { time: "14:03", text: "verified in CloudTrail", tag: "✓", tone: "pass" as const },
    ],
  },
};

export const SIGNAL = {
  status: "FAIL",
  title: "availability",
  lines: [
    "feed.xml → S3 (OAC) now receives the Host header",
    "predicted: origin 404",
    "live traffic: 1,240 req/day",
    "source: CloudFront config · CloudWatch metrics",
  ],
};

export const EMFIRGE_MD = [
  "# my cloud",
  "- prod-* is production. Never delete without me.",
  "- The nightly-sync schedule is paused on purpose.",
  "- Tell me about any support case or quota request.",
  "- Budget: $30/month.",
];

/* ------------------------------------------------------------------ */
/* How it works (six verbs, scroll-driven)                             */
/* ------------------------------------------------------------------ */

export interface Verb {
  name: string;
  line: string;
  example: string;
  output: TermLine[];
}
export const VERBS: Verb[] = [
  {
    name: "context",
    line: "Ask what's true.",
    example: "emfirge context --live --deps orders-db",
    output: [
      { segs: [{ text: "orders-db  ", bold: true }, { text: "rds · live", tone: "muted" }] },
      out("1,240 queries/day (30d) · 3 dependents"),
      out("api-1 · api-2 · nightly-sync"),
    ],
  },
  {
    name: "branch",
    line: "Open, fork, compare, discard workspaces.",
    example: "emfirge branch fork 1",
    output: [out("branch #2 forked from branch #1"), out("2 changes carried over · live untouched")],
  },
  {
    name: "try",
    line: "Put a change on a branch: typed, AWS CLI, API, Terraform or CloudFormation.",
    example: "emfirge try --terraform plan.json",
    output: [out("read plan.json · 1 resource to destroy"), out("1 change on branch #2")],
  },
  {
    name: "check",
    line: "The diff, six damage answers, evidence and unknowns.",
    example: "emfirge check --json",
    output: [
      { segs: [{ text: "BLOCK", tone: "block", bold: true }] },
      { segs: [{ text: "✗ ", tone: "block" }, { text: "data          no recovery point" }] },
      { segs: [{ text: "✗ ", tone: "block" }, { text: "availability  1,240 queries/day" }] },
      { segs: [{ text: "✓ ", tone: "pass" }, { text: "exposure · money · control · outside world", tone: "muted" }] },
    ],
  },
  {
    name: "request",
    line: "Ask the owner, keep working on something else.",
    example: 'emfirge request "delete orders-db?"',
    output: [out("sent to owner · request #4"), out("agent continues on other work")],
  },
  {
    name: "report",
    line: "\"I applied it.\" Exact calls, bound to the verdict, verified in CloudTrail.",
    example: "emfirge report --applied",
    output: [{ segs: [{ text: "recorded · verified in CloudTrail 14s later ", tone: "muted" }, { text: "✓", tone: "pass" }] }],
  },
];

export const HOW = {
  eyebrow: "How it works",
  h2: "Six verbs. The loop is *the product.*",
  footer:
    "Your agent fails on a branch, reads the signal, fixes its own plan and tries again. Only what's left reaches you.",
  loop: ["context", "branch", "try", "check"],
};

/* ------------------------------------------------------------------ */
/* Damage questions + trust                                            */
/* ------------------------------------------------------------------ */

export interface DamageQuestion {
  icon: LucideIcon;
  name: string;
  question: string;
  /** shown red in the radar, echoing the hero story */
  fails?: boolean;
}
export const DAMAGE_QUESTIONS: DamageQuestion[] = [
  { icon: Database, name: "Data", question: "Did something holding data disappear with no recovery point?", fails: true },
  { icon: Globe, name: "Exposure", question: "Is anything newly reachable from the internet or another account?" },
  { icon: Wallet, name: "Money", question: "Did the monthly cost go above your limit?" },
  { icon: Activity, name: "Availability", question: "Did something live traffic depends on break?", fails: true },
  { icon: KeyRound, name: "Control", question: "Was access or logging lost: an admin role, a KMS key, CloudTrail?" },
  { icon: LifeBuoy, name: "Outside world", question: "Does it leave the cloud: support cases, quota requests, emails, domains?" },
];

export const QUESTIONS = {
  eyebrow: "Six questions",
  h2: "Six questions about the result. Not 15,000 rules about *actions.*",
  sub: "Emfirge doesn't judge what an agent says it's doing. It judges what the change does on the branch.",
  foot: "Each answer either tells you (a line in the record, nobody waits) or asks you (your agent keeps working on something else).",
};

export interface SafetyItem {
  icon: LucideIcon;
  title: string;
  body: string;
}
export const SAFETY: SafetyItem[] = [
  { icon: ShieldCheck, title: "Read-only, always.", body: "Emfirge never writes to your cloud. Your agent applies with its own access." },
  { icon: EyeOff, title: "Private by default.", body: "AWS identifiers are tokenized on your machine before any model sees them." },
  { icon: ShieldAlert, title: "No silent passes.", body: "Anything it can't model is reported, never passed." },
  { icon: Cpu, title: "No AI inside.", body: "Deterministic: same snapshot, same changes, same verdict." },
  {
    icon: BookOpenCheck,
    title: "Built from public data.",
    body: "AWS's own API models and price list, pathfinding.cloud, Prowler and policy_sentry.",
  },
  {
    icon: Scale,
    title: "Pinned by laws.",
    body: "Every behavior is a property test that must always hold, e.g. *L7: the same snapshot and changes always give the same verdict.*",
  },
];

/* ------------------------------------------------------------------ */
/* Get started, FAQ, final CTA                                         */
/* ------------------------------------------------------------------ */

export const START = {
  h2: "Two minutes to a *safe* cloud agent.",
  steps: [
    { title: "Sign in", text: "Connect the CLI to your Emfirge account." },
    { title: "Create a read-only role", text: "One click in CloudFormation. Delete the stack any time to revoke." },
    { title: "Tell your agent", text: "One line, and it works on your cloud with a harness." },
  ],
  prompt: "Use emfirge before you change anything in AWS.",
};

export const FAQ: { q: string; a: string }[] = [
  {
    q: "Does Emfirge change my AWS?",
    a: "No. It's read-only. Your agent applies with its own credentials; Emfirge records and verifies.",
  },
  { q: "Which agents work?", a: "Any agent that can run a shell command. An MCP adapter is also available." },
  {
    q: "Is a PASS a guarantee?",
    a: "No. A branch is a model of your cloud. A pass is evidence, and every verdict says what was checked and what wasn't.",
  },
  { q: "Is it open source?", a: "Yes. Engine AGPL-3.0, CLI Apache-2.0." },
];

export const FOOTER_LINKS = [
  { label: "Docs", href: LINKS.docs },
  { label: "GitHub", href: LINKS.github },
  { label: "Privacy", href: LINKS.privacy },
  { label: "Security", href: LINKS.security },
  { label: "ansh@emfirge.cloud", href: LINKS.email },
];
