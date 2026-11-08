// The verbs, their options and their --help text.

export type OptKind = "string" | "bool" | "multi";
export interface Opt { name: string; kind: OptKind; help: string }
export interface VerbSpec {
  summary: string;
  usage: string[];
  options: Opt[];
  examples: string[];
}

export const BRANCH_SUBS = ["open", "fork", "list", "get", "rollback", "rollback-to", "discard", "compare"] as const;

const s = (name: string, help: string): Opt => ({ name, kind: "string", help });
const b = (name: string, help: string): Opt => ({ name, kind: "bool", help });
const m = (name: string, help: string): Opt => ({ name, kind: "multi", help });

export const VERBS: Record<string, VerbSpec> = {
  context: {
    summary: "Ask what is true about the cloud. Facts only, with what was checked and what is unknown.",
    usage: [
      "emfirge context <question> [--analysis ID | --branch ID] [--resource ID]",
      "emfirge context --refresh --role-arn ARN --region REGION",
      "emfirge context --findings|--attack-paths|--compliance --analysis ID",
      "emfirge context --simulate \"what if ...\" --analysis ID",
    ],
    options: [
      s("analysis", "Analysis id from a scan (default: your latest)."),
      s("branch", "Ask about a branch instead of a scan."),
      s("resource", "Resource id or token (S3_001); needed for resource, depends_on, dependents."),
      b("refresh", "Run a fresh scan (needs --role-arn and --region)."),
      s("role-arn", "IAM role ARN to scan with."),
      s("region", "AWS region to scan."),
      b("findings", "List scan findings (use --severity to filter)."),
      s("severity", "Critical, Moderate or Low."),
      b("attack-paths", "Paths from the internet to inside resources."),
      b("compliance", "CIS AWS 1.5 / SOC 2 status (use --framework to filter)."),
      s("framework", "cis-aws-1.5 or soc2."),
      s("simulate", "Walk a what-if kill chain; the value is the question."),
    ],
    examples: [
      "emfirge context inventory",
      "emfirge context reachable --branch BRANCH_ID",
      "emfirge context resource --resource S3_001",
    ],
  },
  branch: {
    summary: "Open and manage a branch: a safe copy of the cloud model. Never touches the cloud.",
    usage: [
      "emfirge branch open --analysis ID --name NAME",
      "emfirge branch fork BRANCH --name NAME [--revision R]",
      "emfirge branch list [--analysis ID]",
      "emfirge branch get BRANCH",
      "emfirge branch rollback BRANCH [--revision R] [--expected-count N]",
      "emfirge branch rollback-to BRANCH --count N [--revision R]",
      "emfirge branch discard BRANCH [--revision R] [--expected-count N]",
      "emfirge branch compare BRANCH BRANCH [BRANCH ...]",
    ],
    options: [
      s("analysis", "Base analysis id (open) or filter (list)."),
      s("name", "Branch name (open, fork)."),
      s("revision", "branch_revision you last saw; a stale one is rejected."),
      s("expected-count", "Change count you last saw; a stale one is rejected."),
      s("count", "Number of leading changes to keep (rollback-to)."),
    ],
    examples: ["emfirge branch open --analysis ANALYSIS_ID --name close-ssh", "emfirge branch list"],
  },
  try: {
    summary: "Put a change on a branch. Emfirge models it; it never runs it.",
    usage: [
      "emfirge try BRANCH --typed JSON",
      "emfirge try BRANCH --aws-cli \"aws ec2 ...\" [--aws-cli \"...\"]",
      "emfirge try BRANCH --aws-api FILE|JSON|-",
      "emfirge try BRANCH --terraform FILE|JSON|-",
      "emfirge try BRANCH --cloudformation FILE|JSON|-",
      "emfirge try --verify-fix --rule RULE --resource ID --analysis ID",
    ],
    options: [
      s("typed", "One typed change as JSON: {op, resource_type, resource_id, fields}."),
      m("aws-cli", "An AWS CLI command (repeat for several), or a JSON list."),
      s("aws-api", "AWS API calls JSON: {format:\"aws-api-calls/1\", calls:[...]}."),
      s("terraform", "Output of `terraform show -json PLAN`."),
      s("cloudformation", "Output of `aws cloudformation describe-change-set`."),
      b("verify-fix", "Model the fix for one finding on a copy of a scan (no branch)."),
      s("rule", "Rule id such as EC2-002 (verify-fix)."),
      s("resource", "Resource id or token (verify-fix)."),
      s("analysis", "Analysis id (verify-fix)."),
    ],
    examples: [
      "emfirge try BRANCH_ID --aws-cli \"aws ec2 revoke-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0\"",
      "emfirge try BRANCH_ID --terraform plan.json",
    ],
  },
  check: {
    summary: "Check a branch: what changed, six damage answers, evidence, and unknowns.",
    usage: [
      "emfirge check BRANCH",
      "emfirge check BRANCH --verdict | --diff",
      "emfirge check BRANCH --policy [--approve --accept-estimate ID]",
      "emfirge check BRANCH --evidence [--source S] [--accept-estimate ID --role-arn ARN]",
    ],
    options: [
      b("verdict", "Old pass / warn / block verdict."),
      b("diff", "Diff against the base scan."),
      b("policy", "Ask IAM Access Analyzer about changed policies (costs money; shows an estimate first)."),
      b("evidence", "Read CloudTrail / CloudWatch use of deleted resources (shows an estimate first)."),
      b("approve", "With --policy: the owner agreed to the estimate."),
      s("accept-estimate", "Estimate id the owner agreed to."),
      m("source", "With --evidence: cloudtrail_events or cloudwatch_metrics (repeatable)."),
      s("role-arn", "Same role ARN used for the scan (needed when accepting an estimate)."),
    ],
    examples: ["emfirge check BRANCH_ID", "emfirge check BRANCH_ID --human"],
  },
  request: {
    summary: "Ask the owner for approval. NOT BUILT YET (v2): exits 1 with a JSON error.",
    usage: ["emfirge request BRANCH [--reason TEXT]"],
    options: [s("reason", "Why you are asking.")],
    examples: ["emfirge request BRANCH_ID --reason \"needs prod approval\""],
  },
  report: {
    summary: "Say what you applied. For now: returns the hand-back for the branch or plan.",
    usage: ["emfirge report BRANCH [--plan PLAN_ID] [--verify]"],
    options: [
      s("plan", "Hand-back for one plan from `emfirge try`."),
      b("verify", "Verify the hand-back with the server."),
    ],
    examples: ["emfirge report BRANCH_ID --verify"],
  },
  connect: {
    summary: "Set up the read-only AWS role: prints the deploy link. --link joins an API-key project to your sign-in.",
    usage: ["emfirge connect", "emfirge connect --link"],
    options: [b("link", "Link your saved sign-in to an existing API-key project (needs EMFIRGE_API_KEY).")],
    examples: ["emfirge connect"],
  },
  login: {
    summary: "Sign in with GitHub or Google in your browser.",
    usage: ["emfirge login"],
    options: [],
    examples: ["emfirge login"],
  },
  logout: {
    summary: "Sign out on this device.",
    usage: ["emfirge logout"],
    options: [],
    examples: ["emfirge logout"],
  },
  guide: {
    summary: "Print the agent guide: the loop, the rules, the tool map and exit codes.",
    usage: ["emfirge guide"],
    options: [],
    examples: ["emfirge guide"],
  },
};

export const VERB_NAMES = Object.keys(VERBS);

export function verbHelp(verb: string): string {
  const v = VERBS[verb];
  const lines = [`emfirge ${verb} - ${v.summary}`, "", "Usage:", ...v.usage.map((u) => `  ${u}`)];
  const opts = [...v.options, { name: "human", kind: "bool" as OptKind, help: "Short readable output instead of JSON." }];
  lines.push("", "Options:");
  for (const o of opts) lines.push(`  --${(o.name + (o.kind === "bool" ? "" : " VALUE")).padEnd(22)} ${o.help}`);
  lines.push("  -h, --help".padEnd(25) + " Show this help.");
  if (v.examples.length) lines.push("", "Examples:", ...v.examples.map((e) => `  ${e}`));
  lines.push("", "Output is JSON on stdout. Errors are JSON on stderr. Exit: 0 ok, 1 usage, 2 not signed in, 3 not found, 4 server.");
  return lines.join("\n") + "\n";
}

export function topUsage(): string {
  const lines = [
    "Usage: emfirge <command> [options]",
    "",
    "Emfirge tells you what is true about the cloud. It never changes it, and it gives facts, not fixes.",
    "",
    "Commands:",
  ];
  for (const name of VERB_NAMES) lines.push(`  ${name.padEnd(9)} ${VERBS[name].summary}`);
  lines.push(
    "",
    "Run `emfirge <command> --help` for options, or `emfirge guide` for the full agent guide.",
    "Global: --human (readable output), --version.",
    "Exit codes: 0 ok, 1 usage or rejected input, 2 not signed in, 3 not found, 4 server or rate limit, 5 conflict.",
  );
  return lines.join("\n") + "\n";
}
