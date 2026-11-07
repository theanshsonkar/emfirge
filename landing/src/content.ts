// All copy for the v4 landing page. See DESIGN-v4.md.
export const LINKS = {
  docs: "https://emfirge.cloud/docs",
  quickstart: "https://emfirge.cloud/docs/quickstart",
  github: "https://github.com/theanshsonkar/emfirge",
  ansh: "https://github.com/theanshsonkar",
  changelog: "https://github.com/theanshsonkar/emfirge/releases",
  privacy: "https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md",
  security: "https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md",
};

export const SITE = {
  title: "emfirge. let your agent touch your aws",
  description:
    "Your agent tries every change on a branch of your cloud, sees what would break, and fixes its own plan before production ever sees it.",
};

export const NAV = {
  skip: "skip to content",
  items: [
    { id: "top", label: "emfirge", href: "#top", strong: true },
    { id: "how", label: "how it works", href: "#how" },
    { id: "why", label: "why", href: "#why" },
    { id: "pricing", label: "pricing", href: "#pricing" },
    { id: "faq", label: "faq", href: "#faq" },
    { id: "docs", label: "docs", href: LINKS.docs, external: true },
  ],
};

/* ---------- terminal scripts ---------- */
export type TKind = "prompt" | "user" | "agent" | "cmd" | "out" | "fail" | "blank";
export type TLine = { k: TKind; t: string };

export const HERO_SCRIPT: TLine[] = [
  { k: "prompt", t: "~/infra % claude" },
  { k: "user", t: "clean up the unused databases in ap-south-1" },
  { k: "blank", t: "" },
  { k: "agent", t: "I'll try it on a branch first." },
  { k: "cmd", t: "emfirge branch new cleanup-dbs" },
  { k: "out", t: "branch #1 forked from live · 0 changes" },
  { k: "cmd", t: "emfirge try --delete rds:orders-db rds:legacy-reports-db" },
  { k: "out", t: "2 changes on branch #1" },
  { k: "cmd", t: "emfirge check" },
  { k: "out", t: "block · 2 of 6 checks failed" },
  { k: "fail", t: "data          orders-db has no recovery point" },
  { k: "fail", t: "availability  orders-db served 1,240 queries/day" },
  { k: "agent", t: "orders-db is live. Keeping it and retrying with legacy-reports-db only." },
  { k: "cmd", t: "emfirge check --branch 2" },
  { k: "out", t: "pass · 6 of 6 · saves $41.20/mo" },
  { k: "agent", t: "Safe to apply. Want me to delete legacy-reports-db?" },
];

export const TABS: { id: string; label: string; lines: TLine[] }[] = [
  {
    id: "everyone",
    label: "everyone",
    lines: [
      { k: "prompt", t: "~/infra % claude" },
      { k: "user", t: "clean up the unused databases in ap-south-1" },
      { k: "agent", t: "I'll try it on a branch first." },
      { k: "cmd", t: "emfirge try --delete rds:orders-db rds:legacy-reports-db" },
      { k: "out", t: "block · orders-db has no recovery point and serves 1,240 queries/day" },
      { k: "agent", t: "orders-db is live. Retrying with legacy-reports-db only." },
      { k: "cmd", t: "emfirge check --branch 2" },
      { k: "out", t: "pass · 6 of 6 · saves $41.20/mo" },
    ],
  },
  {
    id: "cleanup",
    label: "cleanup",
    lines: [
      { k: "user", t: "delete legacy-reports-db, nobody uses it" },
      { k: "agent", t: "Trying the delete on a branch." },
      { k: "cmd", t: "emfirge try --delete rds:legacy-reports-db" },
      { k: "cmd", t: "emfirge check" },
      { k: "out", t: "pass · 6 of 6" },
      { k: "out", t: "data           recovery point exists" },
      { k: "out", t: "availability   nothing live depends on it" },
    ],
  },
  {
    id: "cost",
    label: "cost",
    lines: [
      { k: "user", t: "make staging cheaper" },
      { k: "agent", t: "I'll try a smaller instance class on a branch." },
      { k: "cmd", t: "emfirge try --modify rds:staging-db --class db.t4g.small" },
      { k: "cmd", t: "emfirge check" },
      { k: "out", t: "money         −$62.10/mo" },
      { k: "out", t: "availability  nothing live depends on it" },
      { k: "out", t: "pass · 6 of 6" },
    ],
  },
  {
    id: "security",
    label: "security",
    lines: [
      { k: "user", t: "is anything public that shouldn't be?" },
      { k: "cmd", t: "emfirge context --exposure" },
      { k: "out", t: "1 security group is open to the internet on port 22" },
      { k: "agent", t: "I'll close it on a branch and check." },
      { k: "cmd", t: "emfirge try --revoke sg:ssh-open 0.0.0.0/0:22" },
      { k: "cmd", t: "emfirge check" },
      { k: "out", t: "pass · 6 of 6 · nothing newly reachable" },
    ],
  },
  {
    id: "incidents",
    label: "incidents",
    lines: [
      { k: "user", t: "the feed is 404ing, fix it" },
      { k: "agent", t: "Trying the cache-policy change on a branch." },
      { k: "cmd", t: "emfirge try --modify cloudfront:feed-cdn --cache-policy forward-all" },
      { k: "cmd", t: "emfirge check" },
      { k: "out", t: "block · availability: feed.xml → S3 (OAC) receives Host header · predicted 404" },
      { k: "agent", t: "That would break it. Retrying with a managed policy." },
      { k: "cmd", t: "emfirge try --modify cloudfront:feed-cdn --cache-policy managed:caching-optimized" },
      { k: "out", t: "pass · 6 of 6" },
    ],
  },
  {
    id: "what-if",
    label: "what-if",
    lines: [
      { k: "user", t: "rds public vs private?" },
      { k: "agent", t: "Forking two branches to compare." },
      { k: "cmd", t: "emfirge branch new public --modify rds:app-db --public" },
      { k: "cmd", t: "emfirge branch new private --modify rds:app-db --private" },
      { k: "cmd", t: "emfirge compare 1 2" },
      { k: "out", t: "#2 private   pass · 6 of 6" },
      { k: "out", t: "#1 public    block · exposure: database newly reachable from the internet" },
    ],
  },
];

export const HOW = {
  title: "built for *every* kind of cloud work.",
  sub: "pick a kind of work. watch the agent try it on a branch first.",
};

/* ---------- hero ---------- */
export const HERO = {
  lead: "meet",
  name: "emfirge",
  subA: ["let your agent", " touch your aws,"],
  subB: ["without", " losing sleep over it."],
  cta: { label: "get started", href: LINKS.quickstart },
  meta: "free while in beta · works with any agent · read-only access",
  lock: "your ids are tokenized before any model sees them",
  built: { pre: "built in public by ", name: "ansh", href: LINKS.ansh },
  toast: {
    chip: "placeholder",
    text: "“your tweet here. try emfirge and tell us what it caught.”",
    handle: "— you, @yourhandle",
  },
  hand: "watch it catch a mistake",
};

/* ---------- branch window ---------- */
export const BRANCH = {
  title: "your cloud on a branch. *zero* risk to prod.",
  sidebar: ["live", "#1 cleanup-dbs", "#2 cleanup-dbs"],
  selected: 2,
  card: { title: "branch #2 · cleanup-dbs", sub: "1 change · forked from live 2 min ago", right: "6 of 6 checks passed" },
  legend: ["data", "exposure", "money", "availability", "control", "outside world"],
  top: { title: "emfirge · safe to apply", sub: "checked against your live account", value: "pass" },
  rows: [
    { key: "data", name: "data", value: "recovery point exists" },
    { key: "exposure", name: "exposure", value: "nothing newly reachable" },
    { key: "money", name: "money", value: "−$41.20/mo" },
    { key: "availability", name: "availability", value: "nothing live depends on it" },
    { key: "control", name: "control", value: "no access lost" },
    { key: "world", name: "outside world", value: "no side effects" },
  ],
  lines: [
    "a branch is a private copy of your cloud as it is right now. nothing on it touches production.",
    "your agent tries the change there, and six checks say what would break, with the evidence.",
    "when a plan passes, you apply it. when it blocks, the agent fixes its own plan first.",
  ],
};

/* ---------- notifications ---------- */
export const FAMILIAR = {
  title: "sound *familiar*?",
  items: [
    { icon: "support", app: "aws support", body: "case opened: lambda concurrency quota increase. you didn't ask for this." },
    { icon: "feed", app: "feed.xml", body: "returned 404 after a cache policy change" },
    { icon: "schedule", app: "eventbridge scheduler", body: "nightly-sync is ENABLED again after a redeploy" },
    { icon: "budget", app: "budget", body: "your agent's test run counted the whole account" },
  ],
  line: "every one of these happened to me in one week. the agent wasn't dumb. it just had nowhere safe to try.",
};

/* ---------- why ---------- */
export const WHY = {
  title: "why *emfirge*?",
  without: "without emfirge",
  with: "with emfirge",
  rows: [
    ["every aws command is the real thing", "every change is tried on a branch first"],
    ["you find out from a support email", "nothing leaves the cloud without asking you"],
    ["“trust me, it's safe”", "six checks, as facts, with evidence"],
    ["a wall of api calls", "one record, checked against cloudtrail"],
    ["you watch over its shoulder", "you write your rules once in emfirge.md"],
  ],
};

/* ---------- placeholder wall ---------- */
export const WALL = {
  title: "loved by *early* builders.",
  lead: "emfirge is brand new. try it and be the first one here.",
  link: { label: "read the docs", href: LINKS.docs },
  card: { chip: "placeholder", text: "your tweet here", name: "your name", handle: "@yourhandle" },
  count: 6,
};

/* ---------- founder note (draft for Ansh to edit; keep verbatim) ---------- */
export const NOTE = {
  title: "why i built emfirge.",
  app: "notes",
  paragraphs: [
    "hey, i'm ansh 👋. i build things with ai agents every day.",
    "a few weeks ago i gave claude code my aws to ship a small podcast project. it was good at it. it was also quiet about things. 🤐",
    "it asked aws for a lambda quota increase without telling me. i found out from a support case email. a cache policy change sent my feed to a 404. a deploy script turned a paused schedule back on.",
    "none of it was the agent being dumb. it just had no safe place to try a change, and i had no way to see what it was about to do.",
    "so i built what i wanted: ==emfirge. your agent tries every change on a branch of your cloud, sees what would break, and fixes its own plan before production ever sees it.==",
    "it's early. try it, and tell me what breaks. ✌️",
  ],
  author: { initial: "a", name: "ansh,", role: "founder" },
  signature: "emfirge",
};

/* ---------- pricing ---------- */
export const PRICING = {
  title: "one plan. *free* while in beta.",
  badge: "beta",
  sub: "everything, for one aws account",
  price: "$0",
  per: "/month while in beta",
  note: "no card needed. we'll tell you before anything changes.",
  features: [
    { icon: "terminal", t: "works with any agent that runs a shell" },
    { icon: "branch", t: "branches of your live aws" },
    { icon: "checks", t: "six checks on every change" },
    { icon: "code", t: "terraform, cloudformation, cli and api changes" },
    { icon: "key", t: "read-only role, revoke any time" },
    { icon: "lock", t: "ids tokenized on your machine" },
    { icon: "file", t: "emfirge.md boundaries" },
    { icon: "record", t: "record checked against cloudtrail" },
    { icon: "open", t: "open source engine" },
  ],
  cta: { label: "get started", href: LINKS.quickstart },
};

/* ---------- faq ---------- */
export const FAQ = {
  title: "questions, *answered*.",
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

/* ---------- final cta + footer ---------- */
export const CTA = {
  title: "stop *babysitting* your agent in the cloud.",
  button: { label: "get started", href: LINKS.quickstart },
};

export const FOOTER = {
  links: [
    { label: "privacy", href: LINKS.privacy },
    { label: "security", href: LINKS.security },
    { label: "docs", href: LINKS.docs },
    { label: "github", href: LINKS.github },
    { label: "changelog", href: LINKS.changelog },
  ],
  copy: "© 2026 emfirge",
  built: { pre: "built by ansh ", heart: "❤️", href: LINKS.ansh },
};
