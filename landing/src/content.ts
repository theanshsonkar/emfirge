import {
  Activity,
  Eye,
  FlaskConical,
  ScrollText,
  Database,
  Globe,
  KeyRound,
  LifeBuoy,
  type LucideIcon,
  Wallet,
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
  { label: "How it works", href: "#how-it-works" },
  { label: "Verbs", href: "#verbs" },
  { label: "Safety", href: "#safety" },
  { label: "Docs", href: LINKS.docs },
] as const;

/* ---- Hero terminal ---- */

export type Tone = "paper" | "muted" | "forge" | "pass" | "block";
export interface TermSeg {
  text: string;
  tone?: Tone;
  bold?: boolean;
}
export interface TermLine {
  who?: "you" | "agent";
  segs: TermSeg[];
}

const cmd = (verb: string, args = ""): TermSeg[] => [
  { text: "$ emfirge " },
  { text: verb, tone: "forge" },
  ...(args ? [{ text: ` ${args}` }] : []),
];
const out = (text: string): TermLine => ({ segs: [{ text, tone: "muted" }] });

export const TERMINAL_TITLE = "~/infra — claude";
export const TERMINAL_SCRIPT: TermLine[] = [
  { who: "you", segs: [{ text: "Clean up the unused databases in us-east-1." }] },
  { segs: [] },
  { who: "agent", segs: cmd("context", "--type rds") },
  out("4 databases · orders-db, legacy-reports-db, analytics-db, staging-db"),
  { who: "agent", segs: cmd("branch", "new cleanup-dbs") },
  out("branch #1 forked from live · 0 changes"),
  { who: "agent", segs: cmd("try", "--delete rds:orders-db rds:legacy-reports-db") },
  out("2 changes on branch #1"),
  { who: "agent", segs: cmd("check") },
  { segs: [{ text: "BLOCK", tone: "block", bold: true }] },
  { segs: [{ text: "✗ ", tone: "block" }, { text: "data          orders-db has no recovery point" }] },
  {
    segs: [
      { text: "✗ ", tone: "block" },
      { text: "availability  orders-db served 1,240 queries/day (last 30d)" },
    ],
  },
  { segs: [{ text: "✓ ", tone: "pass" }, { text: "exposure · money · control · outside world", tone: "muted" }] },
  { who: "agent", segs: [{ text: "Keeping orders-db. Retrying with legacy-reports-db only." }] },
  { who: "agent", segs: cmd("check", "--branch 2") },
  {
    segs: [
      { text: "PASS", tone: "pass", bold: true },
      { text: "  · saves $41.20/mo · nothing live depends on it" },
    ],
  },
  { who: "agent", segs: cmd("report", "--applied") },
  { segs: [{ text: "recorded · verified in CloudTrail 14s later ", tone: "muted" }, { text: "✓", tone: "pass" }] },
];

/* ---- Works with ---- */

export const AGENTS = ["Claude Code", "Codex", "Cursor", "Gemini CLI", "Kiro", "Cline", "Aider", "your own"];

/* ---- Problem ---- */

export interface ProblemItem {
  icon: LucideIcon;
  title: string;
  /** `backticks` render as inline code */
  body: string;
}
export const PROBLEMS: ProblemItem[] = [
  {
    icon: Eye,
    title: "It can't see what's live.",
    body: "An agent reading your AWS sees resources, not that `orders-db` takes 1,200 queries a day or that the schedule was paused on purpose.",
  },
  {
    icon: FlaskConical,
    title: "It can't try before it does.",
    body: "Code has branches and tests. The cloud has prod. Every `aws` command is the real thing.",
  },
  {
    icon: ScrollText,
    title: "You can't see what it did.",
    body: "A wall of API calls, no record of what it meant to do, no check that it did what it said.",
  },
];

/* ---- Comparison ---- */

export interface CompareRow {
  coding: string;
  name: string;
  body: string;
}
export const COMPARISON: CompareRow[] = [
  { coding: "Files", name: "Context", body: "a queryable model of your cloud: what exists, what's live, what depends on what" },
  { coding: "A git branch", name: "Branch", body: "a copy of your live AWS to try changes on" },
  { coding: "Tests", name: "Signals", body: "the diff, six damage answers, evidence, unknowns" },
  { coding: "Permissions", name: "Boundaries", body: "what needs you, what's never allowed" },
  { coding: "Commit log", name: "Record", body: "what happened, predicted vs actual" },
];

/* ---- Loop ---- */

export interface LoopStep {
  name: string;
  /** part of the retry arc (try -> check -> signals -> try) */
  inRetry?: boolean;
}
export const LOOP_STEPS: LoopStep[] = [
  { name: "context" },
  { name: "branch" },
  { name: "try", inRetry: true },
  { name: "check", inRetry: true },
  { name: "signals", inRetry: true },
  { name: "boundaries" },
  { name: "agent applies" },
  { name: "record" },
];

/* ---- Verbs ---- */

export interface Verb {
  name: string;
  line: string;
  example: string;
}
export const VERBS: Verb[] = [
  { name: "context", line: "Ask what's true.", example: "emfirge context --live --deps orders-db" },
  { name: "branch", line: "Open, fork, compare, discard workspaces.", example: "emfirge branch fork 1" },
  {
    name: "try",
    line: "Put a change on a branch: typed, AWS CLI, API, Terraform or CloudFormation.",
    example: "emfirge try --terraform plan.json",
  },
  { name: "check", line: "The diff, six damage answers, evidence and unknowns.", example: "emfirge check --json" },
  { name: "request", line: "Ask the owner, keep working on something else.", example: 'emfirge request "delete orders-db?"' },
  {
    name: "report",
    line: "\"I applied it.\" Exact calls, bound to the verdict, verified in CloudTrail.",
    example: "emfirge report --applied",
  },
];

/* ---- Damage questions ---- */

export interface DamageQuestion {
  icon: LucideIcon;
  name: string;
  question: string;
}
export const DAMAGE_QUESTIONS: DamageQuestion[] = [
  { icon: Database, name: "Data", question: "Did something holding data disappear with no recovery point?" },
  { icon: Globe, name: "Exposure", question: "Is anything newly reachable from the internet or another account?" },
  { icon: Wallet, name: "Money", question: "Did the monthly cost go above your limit?" },
  { icon: Activity, name: "Availability", question: "Did something live traffic depends on break?" },
  { icon: KeyRound, name: "Control", question: "Was access or logging lost: an admin role, a KMS key, CloudTrail?" },
  {
    icon: LifeBuoy,
    name: "Outside world",
    question: "Does it leave the cloud: support cases, quota requests, emails, domains?",
  },
];

/* ---- Signal card + emfirge.md ---- */

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

/* ---- Use cases ---- */

export interface UseCase {
  name: string;
  line: string;
}
export const USE_CASES: UseCase[] = [
  { name: "Guard", line: "Is this safe?" },
  { name: "Explore", line: "Two designs on two branches, compare." },
  { name: "Clean up", line: "Remove what's unused, on a branch first." },
  { name: "Cost", line: "Try a change and see the monthly cost." },
  { name: "Incident response", line: "Try the fix on a branch before prod." },
  { name: "Attack", line: "Play attacker against your own IAM, then test the fix on a branch." },
];

/* ---- Safety ---- */

export interface SafetyItem {
  title: string;
  body: string;
}
export const SAFETY: SafetyItem[] = [
  { title: "Read-only, always.", body: "Emfirge never writes to your cloud. Your agent applies with its own access." },
  { title: "Private by default.", body: "AWS identifiers are tokenized on your machine before any model sees them." },
  { title: "No silent passes.", body: "Anything it can't model is reported, never passed." },
  { title: "Deterministic.", body: "No AI inside. Same snapshot, same changes, same verdict." },
  {
    title: "Built from public data.",
    body: "Checks come from AWS's own API models and price list, pathfinding.cloud, Prowler and policy_sentry, not hand-written lists.",
  },
  {
    title: "Pinned by laws.",
    body: "Every behavior is a property test that must always hold, e.g. *L7: the same snapshot and changes always give the same verdict.*",
  },
];

/* ---- Get started ---- */

export const STEPS: { cmd?: string; text: string }[] = [
  { cmd: CONNECT_CMD, text: "sign in." },
  { text: "One-click CloudFormation link creates a read-only role. Delete the stack any time to revoke." },
  { text: "Tell your agent: \"Use emfirge before you change anything in AWS.\"" },
];

/* ---- FAQ ---- */

export const FAQ: { q: string; a: string }[] = [
  {
    q: "Does Emfirge change my AWS?",
    a: "No. It's read-only. Your agent applies with its own credentials; Emfirge records and verifies.",
  },
  { q: "Which agents work?", a: "Any agent that can run a shell command. An MCP adapter is also available." },
  { q: "Which clouds?", a: "AWS today. The core is cloud-neutral; more clouds come as adapters." },
  {
    q: "Does my data go to an LLM?",
    a: "Emfirge has no LLM. Identifiers are tokenized on your machine before your agent's model sees them.",
  },
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
