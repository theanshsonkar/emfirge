import type { Page } from "./types.ts";
import { SETUP_PROMPT } from "./site.ts";

// The Set up page (the route keeps its v8 name, /quickstart/). It lists only what a person does; the agent's side is on /cli/.
// Who does what, with sources: site/FACTS.md section 13. Commands and output are real: sections 1 and 2.
export const quickstart: Page = {
  slug: "quickstart",
  href: "/quickstart/",
  nav: "Set up",
  title: "Set up",
  h1: "Set up.\nWhat you do, once.",
  lead: "Give emfirge to your agent, approve two things only you can approve, and you are done. Your agent does the rest: it branches, tries a change, checks it, fixes its plan and hands back. Nothing you do here can change your cloud.",
  description: "What you do to set up emfirge: give your agent the setup prompt, approve sign-in, create the read-only role with one click and give your agent its ARN. Then ask your agent to change your AWS as usual.",
  intro: [
    { t: "fig", id: "steps", caption: "Figure 1. Your four steps. Your agent runs every command; you paste one prompt, approve a sign-in, click once in AWS and then ask as usual. The role in step 3 is the only thing that can reach your AWS, and it is read-only." },
  ],
  sections: [
    {
      id: "prompt",
      title: "1. Paste the prompt",
      blocks: [
        { t: "lede", x: "Give this to your agent. It runs every command and reads the reference written for it." },
        { t: "code", title: "Setup prompt", x: SETUP_PROMPT },
        { t: "setup" },
        { t: "p", x: "Copy it, or open it in Claude, ChatGPT or Cursor with the arrow. Your agent needs to be able to run commands on your machine (Claude Code, Codex, Cursor's agent, Gemini CLI): a plain chat window cannot run `npx`. It needs Node.js 20 or later. If your client prefers MCP, see the [MCP adapter](/cli/#mcp-adapter)." },
        { t: "p", x: "The prompt points your agent to the full reference at [/cli.md](/cli.md), the same page as [CLI reference](/cli/). You do not need to read it." },
      ],
    },
    {
      id: "sign-in",
      title: "2. Approve sign-in",
      blocks: [
        { t: "lede", x: "Your agent shows you a link. You sign in with GitHub or Google." },
        { t: "p", x: "Your agent runs `emfirge login`. That opens your browser to a sign-in page served on your own machine, where you choose GitHub or Google. If the browser does not open, your agent shows you the address to open. You have 5 minutes. The session is kept in `~/.emfirge/credentials.json` on your machine, so your agent does not need you again unless the sign-in expires." },
        { t: "note", x: "The sign-in page lives on the machine where the command runs, so your browser and your agent must be on the same machine. If your agent runs in a remote sandbox, you cannot reach it." },
        { t: "p", x: "Emfirge never asks for your AWS access keys. The only thing it holds that can reach your account is the role in step 3." },
      ],
    },
    {
      id: "role",
      title: "3. Create the read-only role",
      blocks: [
        { t: "lede", x: "One click in AWS, then give your agent the role ARN. The role can read your account's configuration and nothing else." },
        { t: "p", x: "Your agent runs `emfirge connect` and shows you a link. It opens the CloudFormation console with the template already filled in, including an ExternalId that is unique to you. You do this part because it is your AWS account: emfirge has no access to it until the role exists." },
        { t: "list", items: [
          "Open the link. Read the template if you like.",
          "Tick the IAM acknowledgement and click **Create stack**. It takes about 30 seconds.",
          "When the stack says `CREATE_COMPLETE`, open its **Outputs** tab and copy the `RoleArn`.",
          "Paste the `RoleArn` to your agent and tell it which AWS region to look at. Your agent asks if you forget.",
        ] },
        { t: "p", x: "`connect` does not find the role by itself, so your agent needs the ARN from you. It then takes the first scan with it. A scan can take 30 to 60 seconds on a real account. Scans are limited per AWS account per day; your agent sees how many remain." },
        { t: "h3", x: "What the role can do" },
        { t: "p", x: "It carries AWS's managed `SecurityAudit` policy plus a short list of extra read actions: CloudWatch metrics (for usage evidence), IAM Access Analyzer policy checks, and a handful of List, Describe and Get calls. It lists secret names; it has no permission to read their values. The full list is [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml), and a summary is on [Security & privacy](/security/#role)." },
        { t: "h3", x: "What it cannot do" },
        { t: "p", x: "It has no write permission of any kind. It cannot create, change or delete a resource, read S3 object contents, or read a secret's value." },
        { t: "h3", x: "Revoking it" },
        { t: "p", x: "Delete the CloudFormation stack. The role disappears and access ends immediately. Removing emfirge from your machine does not remove the role, so delete the stack too." },
      ],
    },
    {
      id: "done",
      title: "4. Done: ask as usual",
      blocks: [
        { t: "lede", x: "Ask your agent to change your AWS the way you always do. It handles the rest." },
        { t: "p", x: "Before it touches anything real, your agent opens a branch, tries the change on it, checks it and fixes its own plan until the check is clean. Then it applies the change with its own AWS access and tells you what it did. Emfirge never applies anything." },
        { t: "p", x: "From here you do two things. You read what your agent hands back, and you decide. Your agent should also ask you before a check that costs money (IAM Access Analyzer policy checks, and reads of CloudTrail and CloudWatch use): those show an estimate first and run only after you agree." },
        { t: "note", x: "Emfirge is advisory today. It does not stop an agent that has its own AWS credentials, so the prompt tells your agent never to apply a change that did not pass." },
      ],
    },
    {
      id: "see",
      title: "What you'll see",
      blocks: [
        { t: "lede", x: "A short message from your agent, with the facts emfirge gave it." },
        { t: "p", x: "Here your agent was asked to open SSH to the world on a security group. It tried that on a branch first." },
        { t: "code", title: "Your agent's message (abridged and real-shaped; the wording is your agent's)", x: "I tried opening SSH (port 22) to 0.0.0.0/0 on SG_001 on a branch first.\nemfirge says: block.\n  introduced_critical_finding    SG_001\n  introduced_critical_exposure   EC2_001\n  exposure: EC2_001 newly exposed on tcp 22 from 0.0.0.0/0\n  not checked (so not safe): observed traffic, host firewalls\nI did not apply it. I changed my plan, opened a new branch and checked again." },
        { t: "p", x: "When a change passes, your agent applies it and runs `emfirge report`. The hand-back ties the exact calls it applied to the verdict they were judged with:" },
        { t: "code", title: "The hand-back, from emfirge report --verify (abridged output from the engine's synthetic test account)", x: "{\n  \"kind\": \"aws-api-calls\",\n  \"calls\": [ { \"change_index\": 0, \"service\": \"ec2\", \"operation\": \"AuthorizeSecurityGroupIngress\", … }, … ],\n  \"input_sha256\": \"3c467190…\",\n  \"verdict\": \"warn\",\n  \"verdict_id\": \"f7dc5a85…\",\n  \"verification\": { \"ok\": true, \"verdict\": \"warn\", \"verdict_id\": \"f7dc5a85…\" }\n}" },
        { t: "note", x: "Names appear as tokens such as SG_001 and EC2_001, because privacy defaults to strict: your agent's model never sees the real identifiers. The map from token to name stays in `~/.emfirge/tokens.json` on your machine. A finding is not an error: a block still exits 0, and your agent reads it as a fact about its plan." },
        { t: "link", label: "How the loop works", href: "/how-it-works/#loop" },
      ],
    },
    {
      id: "yourself",
      title: "Without an agent",
      blocks: [
        { t: "details", summary: "Prefer to set it up yourself?", blocks: [
          { t: "p", x: "The commands your agent runs are the same ones you can run. You need Node.js 20 or later. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`." },
          { t: "code", title: "Terminal", x: "npx emfirge --help\nnpx emfirge login      # sign in with GitHub or Google in your browser\nnpx emfirge connect    # print the link that creates the read-only role" },
          { t: "p", x: "Open the link, create the stack, copy the `RoleArn` from its Outputs, then take the first scan with it. The account ID below is a placeholder." },
          { t: "code", title: "Terminal", x: "emfirge context --refresh --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole --region us-east-1\nemfirge context inventory" },
          { t: "p", x: "Then try a change on a branch and ask what it did. Production is never touched." },
          { t: "code", title: "Terminal", x: "emfirge branch open --analysis ANALYSIS_ID --name first-try\nemfirge try BRANCH_ID --aws-cli \"aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0\"\nemfirge check BRANCH_ID --human" },
          { t: "p", x: "`npm install -g emfirge` puts `emfirge` on your PATH. In CI, where no browser can open, set `EMFIRGE_API_KEY` instead of running `login`. Every verb, flag and exit code is in the [CLI reference](/cli/)." },
        ] },
      ],
    },
    {
      id: "next",
      title: "Next steps",
      blocks: [
        { t: "list", items: [
          "[How it works](/how-it-works/): the loop your agent runs, the six checks and the record.",
          "[Coverage](/coverage/): which resources a branch can change today.",
          "[Security & privacy](/security/): exactly what the role, the engine and your machine hold.",
          "[FAQ](/faq/): do I need to learn the CLI, and what do I actually do.",
          "[CLI reference](/cli/): the reference your agent reads.",
        ] },
      ],
    },
  ],
};
