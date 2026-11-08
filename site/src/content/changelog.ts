import type { Page, Entry } from "./types.ts";

// Seeded from the real git history of this repository (commit dates, rewritten in plain English).
// Law numbers (L..) are the ones named in the commit messages. Nothing here is invented.
export const entries: Entry[] = [
  {
    date: "November 8, 2026", iso: "2026-11-08", tag: "CLI",
    title: "API keys from the CLI (key create / list / revoke), CLI 0.1.x line and spinner",
    summary: "An agent that cannot open a browser, such as a cloud session or CI, can now use an API key you make once. The CLI also has its own version numbers.",
    improvements: [
      "`emfirge key create` makes an API key for your own project. It is shown once. `emfirge key list` shows your keys, never the key itself, and `emfirge key revoke KEY_ID` stops one at once. A project can hold 10 active keys, and the server keeps only a hash of each key (laws L89a to L89f).",
      "Set the key as `EMFIRGE_API_KEY` in the secret settings of the place your agent runs. The agent then skips the browser sign-in. You still create the read-only role yourself and give your agent its ARN.",
      "A key can use emfirge for your project, but it cannot make more keys: `key create` works only after a browser sign-in. `key list` and `key revoke` still work with a key, so a leaked key can be revoked (law L89g).",
      "The `emfirge` CLI now has its own version line, starting at 0.1.0, no longer tied to the MCP adapter's version.",
      "While it waits for the server, the CLI shows a small spinner on stderr. It appears only when stderr is a terminal and is off in CI, with `TERM=dumb` or with `EMFIRGE_NO_SPINNER=1`, so an agent reading the JSON on stdout never sees it (emfirge 0.1.1).",
    ],
  },
  {
    date: "November 8, 2026", iso: "2026-11-08", tag: "CLI",
    title: "The emfirge command is its own npm package, and its commands come from the server",
    summary: "`npx emfirge` runs the CLI. The engine serves the list of commands, so a new command works without a new install.",
    improvements: [
      "The npm package `emfirge` gives the `emfirge` command, bundled into one file with no dependencies.",
      "The CLI reads its commands from `GET /cli/manifest` and keeps a copy built in for when the server cannot be reached. A test pins the two together (law L88).",
      "Exit codes now say what failed: input the server rejected (400, 422) exits 1, a conflict (409) exits 5, a rate limit (429) exits 4 as `rate_limited`, and a command that needs a newer emfirge exits 6.",
    ],
    fixes: ["AWS CLI shorthand such as `--target Arn=…` is refused with a clear message instead of being guessed."],
  },
  {
    date: "November 8, 2026", iso: "2026-11-08", tag: "Engine",
    title: "Check lists every changed setting, judged or named as not judged",
    summary: "A setting that changed and that no check reads is no longer silent.",
    improvements: [
      "`check` returns `changed_settings`: every setting that differs on a resource, by name and never by value, with the answers that read it. A setting no check reads is named as not judged (law L87).",
      "The MCP check tool, the CLI's `--human` output and the agent guide show it.",
    ],
  },
  {
    date: "November 8, 2026", iso: "2026-11-08", tag: "Engine",
    title: "Outside world is decided per service, and unknowns are named",
    summary: "Fewer hand-made guesses, and more things said to be unknown.",
    improvements: [
      "An action that leaves the cloud is classified per service and per action, never by single actions added by hand. A read by name (Get, List, Describe) is not outside world, and every table entry cites AWS's documentation (law L83).",
      "A permission that was never granted is reported as unknown, not as a fact (law L84). Schedule gaps are closed: a change to a schedule's run settings is a fact, deleting an enabled schedule is an availability fact, and outside world carries plan gaps as unknowns (law L85).",
      "A DynamoDB item count of 0 is unknown emptiness, never a recovery point (laws L80, L86).",
      "A CloudFormation change set that removes a property is a reset or a named unknown, never dropped (law L82); security group egress is diffed like ingress.",
    ],
  },
  {
    date: "November 8, 2026", iso: "2026-11-08", tag: "Privacy",
    title: "Four privacy leaks in CLI and MCP output closed",
    summary: "An audit of what the CLI and MCP print found four places where an identifier could get through.",
    improvements: [
      "The before and after values in a branch diff, the check's path pattern, bare account IDs and the ARNs of DynamoDB, SQS, SNS, Scheduler, CloudFront and WAF in text are masked, and so is what you typed when a usage error echoes it (law L81).",
      "PRIVACY.md covers CloudFront, Scheduler and DynamoDB data and what is withheld.",
    ],
  },
  {
    date: "November 7, 2026", iso: "2026-11-07", tag: "Engine",
    title: "Context and check answer with facts, and the CLI arrives",
    summary: "Two read-only questions about your cloud, and a command that asks them.",
    improvements: [
      "`context` returns what is true, what was checked and what is unknown, for 11 questions, from a scan or a branch (law L73).",
      "`check` returns facts about six damages (data, exposure, money, availability, control, outside world) with what was checked and what is unknown. It never returns a rule ID (law L74).",
      "The `emfirge` CLI with its verbs and an agent guide; the MCP adapter gained `emfirge_context` and `emfirge_check`.",
    ],
  },
  {
    date: "November 7, 2026", iso: "2026-11-07", tag: "Branches",
    title: "Branches model EventBridge Scheduler, CloudFront and DynamoDB",
    summary: "Four more resource types can be tried on a branch, each with its own facts.",
    improvements: [
      "EventBridge Scheduler schedules can be added, modified and deleted on a branch (law L75). A schedule that starts running is an outside-world fact (law L77).",
      "CloudFront distributions can be modified, and a cache behavior that forwards the Host header to an S3 origin is an availability fact (law L78).",
      "DynamoDB tables are first-class in the data answer and in delete safety (law L80).",
      "A role's permissions are compared action by action in `check` and `context access`.",
    ],
  },
  {
    date: "November 7, 2026", iso: "2026-11-07", tag: "Privacy",
    title: "Purge, discard and plan storage now do what they say",
    summary: "The first privacy audit's findings, fixed and pinned by tests.",
    improvements: [
      "Purge covers every table that is keyed to an AWS account, including branches, plans, evidence and policy checks. A test fails if a table is added without a purge-or-keep decision (law L71a).",
      "Discarding a branch deletes it and every row linked to it (law L71b).",
      "The server keeps only a SHA-256 of an uploaded plan, never its text (law L71c). API and CI keys are stored as hashes (law L71d).",
      "Server logs carry no customer identifiers (law L71g), and PRIVACY.md is checked against the code (law L71h).",
      "Token and sign-in files on your machine are private to your user (law L71f), and `purge` in the MCP adapter needs you to be signed in (law L71i).",
    ],
    fixes: ["A real scan now finishes instead of failing on its collection time (law L72)."],
  },
  {
    date: "October 26, 2026", iso: "2026-10-26", tag: "Inputs",
    title: "Terraform plans carry IAM, S3, Lambda and EC2 settings",
    summary: "More of what a Terraform plan says now reaches the branch.",
    improvements: [
      "A created IAM role is identified by account, path and name (law L67), and roles, users and instance profiles get the permissions Terraform grants them (law L68).",
      "S3 bucket ACL, versioning, encryption, logging, policy and Block Public Access are read from a plan (law L69).",
      "A Lambda's role, environment secrets and VPC, and an instance's metadata settings and user-data secrets, are read from a plan (law L70).",
    ],
  },
  {
    date: "October 26, 2026", iso: "2026-10-26", tag: "Scanners",
    title: "Scanner checks that need unmodeled data are skipped",
    summary: "Checks from the borrowed scanners that read attributes emfirge does not model are now skipped instead of judged on missing data.",
    improvements: ["A scanner check that reads an attribute the engine does not model is skipped, so it cannot raise a finding from nothing (law L66)."],
  },
  {
    date: "October 25, 2026", iso: "2026-10-25", tag: "Scanners",
    title: "Scanners see IAM, KMS, CloudTrail, Lambda and the network",
    summary: "More of your account is passed to the scanners, and they are skipped when the input is unknown.",
    improvements: [
      "IAM roles and policies, KMS keys, CloudTrail, Lambda, VPCs, subnets and security group peers are now sent to the scanners, with crosswalks for KMS, CloudTrail, flow-log and Lambda-in-VPC checks (law L65).",
      "Database and instance settings are collected and sent to the scanners (law L64).",
    ],
    fixes: ["Absent log exports now mean none, and a check is skipped on both sides when its input is unknown on either side."],
  },
  {
    date: "October 24, 2026", iso: "2026-10-24", tag: "Scanners",
    title: "Checkov runs on every verdict, with severities from Prowler",
    summary: "The Checkov scanner is switched on in the hosted engine; Trivy stays off.",
    improvements: [
      "Checkov runs through a separate worker next to the engine and reports as advisory.",
      "Scanner severities come from Prowler's published check metadata (law L63).",
    ],
  },
  {
    date: "October 23, 2026", iso: "2026-10-23", tag: "Engine",
    title: "Prices, compliance and port ranges come from public data",
    summary: "Three checks now read published sources instead of hand-written values.",
    improvements: [
      "Provisioned cost comes from AWS's published Price List (law L59).",
      "CIS 1.5 and SOC 2 control lists come from Prowler's published data (law L57).",
      "SSH and RDP count as open when a port range or an all-traffic rule includes them (law L58).",
      "The scanner input reports what it left out, as a loss report in the verdict (law L60).",
    ],
  },
  {
    date: "October 23, 2026", iso: "2026-10-23", tag: "Engine",
    title: "Opt-in AWS policy checks and a faster scanner",
    summary: "Ask AWS itself whether a policy is public, and re-scan only what changed.",
    improvements: [
      "Opt-in IAM Access Analyzer checks for S3 bucket policies and role trust policies, run with your own role after you accept a cost estimate (law L62). They can only make a verdict stricter.",
      "The Checkov worker stays warm, caches the base scan and scans only changed resources and their neighbors (law L61).",
    ],
  },
  {
    date: "October 22, 2026", iso: "2026-10-22", tag: "Branches",
    title: "Branches can add volumes, route tables and NAT gateways",
    summary: "More of what an agent builds can now be tried on a branch.",
    improvements: [
      "Add EBS volumes (law L51), route tables (law L52) and NAT gateways on a branch.",
      "Resource tags are modeled (law L50), and a field catalog built from AWS's API models lists every settable field (law L54).",
      "Buckets made public by a bucket policy are detected (law L49), and RDS internet ingress shows in the graph (law L55).",
    ],
  },
  {
    date: "October 20, 2026", iso: "2026-10-20", tag: "Branches",
    title: "IAM role trust, IAM users and RDS snapshots on a branch",
    summary: "More IAM and database changes can be tried before they are real.",
    improvements: [
      "Add or modify an IAM role's trust policy, add an IAM user, and add an RDS manual snapshot.",
      "The two-sided diff now covers changeable types that have no graph node.",
    ],
  },
  {
    date: "October 14, 2026", iso: "2026-10-14", tag: "Inputs",
    title: "AWS CLI commands and CloudFormation change sets go straight onto a branch",
    summary: "Hand emfirge the change you already have; it returns the exact calls it judged.",
    improvements: [
      "AWS CLI commands go into a branch, with an exact hand-back of the calls.",
      "CloudFormation change sets go into a branch the same way.",
    ],
  },
];

export const changelog: Page = {
  slug: "changelog",
  href: "/changelog/",
  nav: "Changelog",
  title: "Changelog",
  h1: "Changelog.",
  lead: "What changed in emfirge, taken from the public git history. Dates are commit dates.",
  description: "Recent emfirge changes, in plain English, from the repository's git history.",
  sections: [{ id: "entries", title: "Recent changes", blocks: [{ t: "entries", items: entries }] }],
};
