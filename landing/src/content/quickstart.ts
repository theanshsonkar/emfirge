import type { Page } from "./types.ts";

// Commands and output are real: see landing/FACTS.md sections 1 and 2.
export const quickstart: Page = {
  slug: "quickstart",
  href: "/quickstart/",
  nav: "Quickstart",
  title: "Quickstart",
  h1: "Quickstart.\nFrom install to your first check.",
  lead: "Four steps. You run the CLI, sign in, give emfirge a read-only role in your AWS account, and try one change on a branch. Nothing you do here can change your cloud.",
  description: "Install the emfirge CLI, create the read-only role and run your first check on a branch of your live AWS.",
  intro: [
    { t: "fig", id: "steps", caption: "Figure 1. The four steps. Only the last one touches a branch; the role in step 3 is the only thing that can reach your AWS, and it is read-only." },
  ],
  sections: [
    {
      id: "install",
      title: "1. Install",
      blocks: [
        { t: "lede", x: "One command. There is nothing to install globally." },
        { t: "code", title: "Terminal", x: "npx emfirge --help" },
        { t: "p", x: "You need Node.js 20 or later. The npm package is `emfirge` and the command is `emfirge`. The list of commands comes from the server, so the help is always current. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`." },
        { t: "p", x: "Prefer a permanent command? `npm install -g emfirge` puts `emfirge` on your PATH. The CLI is a thin client: the engine is hosted, and the CLI only signs in, tokenizes identifiers on your machine, sends the command and prints the answer." },
      ],
    },
    {
      id: "sign-in",
      title: "2. Sign in",
      blocks: [
        { t: "lede", x: "Your browser opens, you sign in with GitHub or Google, and the CLI keeps the session on your machine." },
        { t: "code", title: "Terminal", x: "npx emfirge login\nnpx emfirge logout   # to sign out of this device" },
        { t: "p", x: "Emfirge never asks for your AWS access keys. The only thing it holds that can reach your account is the role in step 3. In CI, where no browser can open, set `EMFIRGE_API_KEY` instead." },
      ],
    },
    {
      id: "role",
      title: "3. Create the read-only role",
      blocks: [
        { t: "lede", x: "One CloudFormation click. The role can read your account's configuration and nothing else." },
        { t: "p", x: "`connect` prints a link that opens the CloudFormation console with the template already filled in, including an ExternalId that is unique to you. Read the template, tick the IAM acknowledgement, click **Create stack**, and copy the `RoleArn` from the stack's Outputs. Then take the first scan with that ARN." },
        { t: "code", title: "Terminal", x: "npx emfirge connect\n# open the link, create the stack, copy the RoleArn from its Outputs\nemfirge context --refresh --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole --region us-east-1\nemfirge context inventory" },
        { t: "note", x: "The account ID is a placeholder. A scan can take 30 to 60 seconds on a real account, and the CLI waits up to 240 seconds. Scans are limited per AWS account per day; the reply says how many remain." },
        { t: "h3", x: "What the role can do" },
        { t: "p", x: "It carries AWS's managed `SecurityAudit` policy plus a short list of extra read actions: CloudWatch metrics (for usage evidence), IAM Access Analyzer policy checks, and a handful of List, Describe and Get calls. It lists secret names; it has no permission to read their values. The full list is [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml), and a summary is on [Security & privacy](/security/#role)." },
        { t: "h3", x: "What it cannot do" },
        { t: "p", x: "It has no write permission of any kind. It cannot create, change or delete a resource, read S3 object contents, or read a secret's value." },
        { t: "h3", x: "Revoking it" },
        { t: "p", x: "Delete the CloudFormation stack. The role disappears and access ends immediately. Removing the CLI from your machine does not remove the role, so delete the stack too." },
      ],
    },
    {
      id: "first-check",
      title: "4. Your first check",
      blocks: [
        { t: "lede", x: "Open a branch, put a change on it, and ask what it did. Production is never touched." },
        { t: "p", x: "Here an agent is about to open SSH to the world on a security group. It tries that on a branch first." },
        { t: "code", title: "Terminal", x: "emfirge branch open --analysis ANALYSIS_ID --name first-try\nemfirge try BRANCH_ID --aws-cli \"aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0\"\nemfirge check BRANCH_ID --human" },
        { t: "p", x: "`try` answers with what it applied and a verdict, because the change came in as an AWS CLI command:" },
        { t: "code", title: "emfirge try (abridged output from the engine's synthetic test account)", x: "{\n  \"applied\": [ \"calls[0] ec2.AuthorizeSecurityGroupIngress\" ],\n  \"rejected\": [], \"unmodeled\": [], \"unknown_fields\": [],\n  \"verdict\": {\n    \"decision\": \"block\",\n    \"reasons\": [\n      { \"level\": \"block\", \"code\": \"introduced_critical_finding\", \"resources\": [\"SG_001\"] },\n      { \"level\": \"block\", \"code\": \"introduced_critical_exposure\", \"resources\": [\"EC2_001\"] },\n      { \"level\": \"warn\", \"code\": \"new_exposure\", \"resources\": [\"EC2_001\"] }\n    ]\n  }\n}" },
        { t: "p", x: "`check` lists the facts, and what it could not check:" },
        { t: "code", title: "emfirge check --human (abridged output from the same account)", x: "Branch check: BRANCH_ID (2 change(s))\n- data: 0 fact(s), 4 unknown\n- exposure: 1 fact(s), 1 unknown\n    fact: {\"resource_id\":\"EC2_001\",\"resource_type\":\"ec2_instance\",\"change\":\"newly_exposed\",\"protocol\":\"tcp\",\"ports\":[22,22],\"so...\n    unknown (not checked, not safe): {\"topic\":\"observed_traffic\",\"reason\":\"observed traffic, host firewalls and application-level controls are not collect...\n- money: 0 fact(s), 1 unknown\n- availability: 0 fact(s), 3 unknown\n- control: 0 fact(s), 2 unknown\n- outside_world: 0 fact(s), 2 unknown\nchanged settings: 3 (1 judged by a check, 2 not judged)\nChanged, not judged:\n    security_group SG_002: attached_instances\n    security_group SG_002: attached_to" },
        { t: "note", x: "Identifiers are tokens (SG_001, EC2_001) because privacy defaults to strict: your agent's model never sees the real IDs. The reason codes and fact kinds are the engine's real ones; the account is synthetic. Exit code is 0 for both: a finding is not an error." },
        { t: "p", x: "A fact is about the change, not an error. The agent reads it, changes its plan (say, a narrower CIDR or Session Manager instead of SSH), opens a new branch and checks again. See [the CLI reference](/cli/#check) for every flag." },
      ],
    },
    {
      id: "tell-your-agent",
      title: "Tell your agent",
      blocks: [
        { t: "lede", x: "Skip the typing. Give your agent this prompt and it reads the page written for it." },
        { t: "code", title: "Setup prompt", x: "Set up emfirge in this project. Read https://emfirge.cloud/index.md and follow it." },
        { t: "setup" },
        { t: "p", x: "The deep links open Claude, ChatGPT or Cursor with the prompt filled in. Any agent that can run a shell command works: Claude Code, Codex, Cursor, Gemini CLI. If your client prefers MCP, see the [MCP adapter](/cli/#mcp-adapter)." },
      ],
    },
    {
      id: "next",
      title: "Next steps",
      blocks: [
        { t: "list", items: [
          "[How it works](/how-it-works/): branches, the six checks, and the record.",
          "[CLI reference](/cli/): every verb, flag and exit code.",
          "[Coverage](/coverage/): which resources a branch can change today.",
          "[Security & privacy](/security/): exactly what the role, the engine and your machine hold.",
        ] },
      ],
    },
  ],
};
