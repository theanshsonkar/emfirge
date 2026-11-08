import type { Page } from "./types.ts";

// Everything here is from PRIVACY.md (updated 2026-11-08 and checked against the code by law L71h), iam-role.yaml, SECURITY.md and
// the code. See site/FACTS.md, section 6.
export const security: Page = {
  slug: "security",
  href: "/security/",
  nav: "Security & privacy",
  title: "Security & privacy",
  h1: "Security & privacy.\nOnly what is true today.",
  lead: "What emfirge can reach, what your agent's model sees, what the hosted engine stores, and how to delete it. Where the code and an older document disagree, this page follows the code.",
  description: "The read-only role, identifier tokenization, what the hosted emfirge engine stores, and how retention and deletion work today.",
  sections: [
    {
      id: "role",
      title: "The read-only role",
      blocks: [
        { t: "lede", x: "Emfirge reaches your account through one IAM role that can read and cannot write." },
        { t: "fig", id: "role", caption: "Figure 1. Read flows out of your account through the role; nothing flows in. The role holds no write permission, so there is no path for emfirge to change a resource." },
        { t: "table", head: ["Part of the role", "What it grants"], rows: [
          ["Managed policy", "AWS `SecurityAudit`: configuration reads across services."],
          ["Usage evidence", "`cloudwatch:GetMetricStatistics` and `GetMetricData`."],
          ["Policy checks", "`access-analyzer:CheckNoPublicAccess` and `ValidatePolicy`, used only for opt-in checks."],
          ["Extra reads", "A short list of List/Describe/Get actions for IAM role policies, Lambda, ECS task definitions, SNS, KMS (including key rotation status), AWS Config, CloudFront (distribution config, tags, cache and origin request policies, origin access controls), API Gateway v2, SQS, GuardDuty, Budgets, WAFv2, EventBridge Scheduler (`ListSchedules`, `GetSchedule`) and Secrets Manager (names only)."],
          ["Trust", "Assumable only from emfirge's AWS account and only with an ExternalId unique to you."],
          ["Writes", "None."],
        ] },
        { t: "p", x: "Emfirge calls AWS STS for temporary credentials (one hour, held in memory, never stored). It never asks for your access keys. Read the template yourself: [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml)." },
        { t: "p", x: "**Revoke it:** delete the CloudFormation stack. Access ends at once." },
      ],
    },
    {
      id: "tokenization",
      title: "Tokenization",
      blocks: [
        { t: "lede", x: "Identifiers are replaced with tokens on your machine before a model sees them." },
        { t: "fig", id: "token", caption: "Figure 2. An account ID becomes a token on your machine, before the text reaches the model. The map from token back to ID stays on your disk." },
        { t: "table", head: ["Mode", "What is tokenized"], mono: [0], rows: [
          ["`strict` (default)", "Everything recognized: ARNs (including DynamoDB, SQS, SNS, Scheduler, CloudFront and WAF), instance, security group, Elastic IP, volume, subnet, VPC, network interface, route table, gateway and ACL IDs, IPs, account IDs, and bucket, role, user, function and secret names. CloudFront aliases, origin domains and path patterns, and Scheduler targets are masked too, also in a branch diff."],
          ["`balanced`", "The same, except generic network topology IDs (volume, subnet, VPC, network interface, route table, internet gateway, NAT gateway and ACL IDs), which stay as they are."],
          ["`off`", "Nothing. Best output for a personal or demo account. Presigned download links still have their credentials removed."],
        ] },
        { t: "p", x: "Resource tag values are hidden in `strict` and `balanced`: tag keys such as `owner` stay readable, and each value becomes a `TAG_` token. The token map (`~/.emfirge/tokens.json`) lives only on your machine, in a folder only your user can read. It is never sent to emfirge or to a model provider. Set the mode with `EMFIRGE_PRIVACY`, or for the MCP adapter with `npx @emfirge/mcp privacy`." },
        { t: "p", x: "Every `emfirge` answer goes through the same redaction as the MCP tools, so branch and check output are tokenized in `strict` too. Tokenization protects what **your agent's model** sees. It does not hide anything from the hosted engine, which needs the real identifiers to answer." },
      ],
    },
    {
      id: "stored",
      title: "What the hosted engine stores",
      blocks: [
        { t: "lede", x: "Your account's configuration, your branches, and a fingerprint of what your agent sends to `try`. Not your data." },
        { t: "table", head: ["Stored", "Contents"], rows: [
          ["Scans", "A summary and findings with real AWS resource IDs, your account ID and region, plus the infrastructure snapshot. Newer resource types are kept without their secrets: CloudFront origin custom header values and the Scheduler target `Input` payload are withheld, and DynamoDB table items are never read."],
          ["Branches", "A full copy of your account's modeled state as the base, and the ordered changes on it."],
          ["What your agent sends to `try`", "Only a SHA-256 of a Terraform plan, CloudFormation change set or CLI command, never its text. Your agent applies its own original plan."],
          ["API keys", "A SHA-256 of each key, never the key. The optional label you gave it and its first 8 characters after `emf_`, to tell keys apart, plus when it was made and last used."],
          ["Usage evidence (opt-in)", "Per resource: status, used and holds-data flags, metric peaks, last event time and event name. Never CloudTrail user names, IP addresses, access keys or raw events."],
          ["Policy checks (opt-in)", "Which resource was checked and the answers, never the policy text."],
          ["Server logs", "No account IDs, resource IDs, ARNs, bucket, role or repo names. Errors are logged as the error type."],
        ] },
        { t: "h3", x: "Never stored" },
        { t: "p", x: "Your AWS access keys; the contents of your resources (S3 objects, database rows, DynamoDB items, secret values, EC2 user data text); plan text; and anything about accounts you did not scan." },
        { t: "p", x: "On the CLI and MCP path the engine never calls an AI model: every request carries the header that tells the backend to skip its AI summaries, and your own agent's model sees only what the CLI prints. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) also covers the web dashboard, which does not carry that header and does send real IDs to LLM providers; the CLI path does not use it." },
      ],
    },
    {
      id: "keys",
      title: "API keys",
      blocks: [
        { t: "lede", x: "A key is a password for your emfirge project, for an agent that cannot open a browser. You make it, you can list it, and you can end it at once." },
        { t: "list", items: [
          "**Made from a browser sign-in only.** `emfirge key create` works only when you are signed in with GitHub or Google. A call made with a key is refused (HTTP 403), so a leaked key cannot make more keys.",
          "**Shown once.** The server keeps only a SHA-256 of the key, so it cannot show it again. It also stores the optional label you gave it and the key's first 8 characters after `emf_`, to tell keys apart.",
          "**Yours alone.** A key belongs to your own project. Another project cannot list or revoke it. A project can hold 10 active keys.",
          "**Revoked at once.** `emfirge key revoke KEY_ID` ends a key immediately. `emfirge key list` shows each key's label, first characters, when it was made and last used, and whether it is active, but never the key.",
          "**No expiry.** A key does not expire by itself. Revoke it when you no longer need it.",
          "**Store it as a secret.** Set it as `EMFIRGE_API_KEY` in the secret settings of the place your agent runs. Never paste it into a chat or commit it.",
        ] },
        { t: "p", x: "A key can use emfirge for your project the way your sign-in does, except it cannot make keys. `key list` and `key revoke` also work with a key, so a leaked key could revoke your other keys. If that happens, make a new key from a browser sign-in. The key is not an AWS credential: your AWS account is reached only through the read-only role." },
      ],
    },
    {
      id: "retention",
      title: "Retention and deletion",
      blocks: [
        { t: "lede", x: "Nothing expires by itself. You can delete everything linked to an AWS account." },
        { t: "list", items: [
          "There is no automatic expiry. Nothing is deleted because of its age, there are no retention sweeps, and no retention period is promised. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) says the same.",
          "`npx @emfirge/mcp purge --role-arn ARN` first proves you control the account by assuming your role. It then deletes, in one transaction, the scans, drift records, simulation logs, feedback, usage records and account bindings for that account, the branches linked to it with their plans, evidence and policy checks, and the stored scan reports in S3. It returns a count per table, then removes your local token map. A test fails if a table is added without a purge-or-keep decision.",
          "`emfirge branch discard` deletes the branch and its plans, evidence and policy checks.",
          "Purge does not remove your login (workspace, API keys as hashes with their labels, sign-in identity) or the legacy GitHub integration tables. Email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) to delete those, or anything else.",
        ] },
        { t: "note", x: "Retention periods and sweeps are not designed yet." },
      ],
    },
    {
      id: "open",
      title: "Open source, reporting and certifications",
      blocks: [
        { t: "table", head: ["Part", "License"], rows: [
          ["Engine (`backend/`) and the CloudFormation template", "AGPL-3.0"],
          ["MCP adapter (`mcp/`) and the `emfirge` CLI (`cli/`)", "Apache-2.0"],
        ] },
        { t: "p", x: "You can read every check. Self-hosting the engine is possible under the license but is not supported." },
        { t: "p", x: "**Certifications:** emfirge holds none today. Its CIS and SOC 2 mapping reports which controls its checks cover; it is not an audit." },
        { t: "p", x: "**Reporting a vulnerability:** email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) rather than opening a public issue. The aim is to acknowledge within 48 hours and give an initial assessment within 7 days. Read [SECURITY.md](https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md) and [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md)." },
        { t: "p", x: "**Advisory, not a gate:** a `block` is a verdict. Emfirge does not stop an agent, person or pipeline with its own AWS credentials from applying a change." },
      ],
    },
  ],
};
