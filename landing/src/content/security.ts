import type { Page } from "./types.ts";

export const security: Page = {
  slug: "security",
  href: "/security/",
  nav: "Security & privacy",
  title: "Security & privacy",
  h1: "Security & privacy.\nOnly what is true today.",
  lead: "What emfirge can reach, what your agent's model sees, what the hosted engine stores, and what is still being built. Where the code and an older document disagree, this page follows the code.",
  description: "The read-only role, identifier tokenization, what the hosted emfirge engine stores, and the retention controls still being built.",
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
          ["Extra reads", "A short list of List/Describe/Get actions for IAM role policies, Lambda, ECS task definitions, SNS, KMS (including key rotation status), AWS Config, CloudFront, API Gateway v2, SQS, GuardDuty, Budgets, WAFv2 and Secrets Manager (names only)."],
          ["Trust", "Assumable only from emfirge's AWS account and only with an ExternalId unique to you."],
          ["Writes", "None."],
        ] },
        { t: "p", x: "Emfirge calls AWS STS for temporary credentials (one hour, never stored). It never asks for your access keys. Read the template yourself: [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml)." },
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
          ["`strict` (default)", "Everything recognized: ARNs, IDs, IPs, account IDs, bucket and role names."],
          ["`balanced`", "ARNs, EC2, security group, EIP and IAM IDs, IPs and account IDs. Subnet, VPC and volume IDs stay raw."],
          ["`off`", "Nothing. Best output for a personal or demo account."],
        ] },
        { t: "p", x: "The token map (`~/.emfirge/tokens.json`) lives only on your machine. It is never sent to emfirge or to a model provider. Set the mode with `emfirge privacy`." },
        { t: "p", x: "Tokenization protects what **your agent's model** sees. It does not hide anything from the hosted engine, which needs the real identifiers to answer. [TODO Ansh: confirm that every verb's output is tokenized in strict mode, including branch and check output; older docs said branch responses were not.]" },
      ],
    },
    {
      id: "stored",
      title: "What the hosted engine stores",
      blocks: [
        { t: "lede", x: "Your account's configuration, your branches, and what you send to `try`. Not your data." },
        { t: "table", head: ["Stored", "Contents"], rows: [
          ["Scans", "A summary and findings with real AWS resource IDs, your account ID and region, plus the infrastructure snapshot."],
          ["Branches", "A full copy of your account's modeled state as the base, and the ordered changes on it."],
          ["What you send to `try`", "The text of a Terraform plan, CloudFormation change set or CLI command is kept as submitted. It can contain values such as Lambda environment variables, so do not put secrets in a plan you submit."],
          ["Usage evidence (opt-in)", "Per resource: status, used and holds-data flags, metric peaks, last event time and event name. Never CloudTrail user names, IP addresses, access keys or raw events."],
          ["Policy checks (opt-in)", "Which resource was checked and the answers, never the policy text."],
        ] },
        { t: "h3", x: "Never stored" },
        { t: "p", x: "Your AWS access keys; the contents of your resources (S3 objects, database rows, secret values); and anything about accounts you did not scan." },
        { t: "p", x: "Emfirge has no AI inside, so no model provider sees your data from the engine. Your own agent's model sees only what the CLI prints. [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md) also covers the web dashboard, which does send real IDs to LLM providers; the CLI path does not use it." },
      ],
    },
    {
      id: "retention",
      title: "Retention and deletion",
      blocks: [
        { t: "lede", x: "Retention and deletion controls are being built." },
        { t: "p", x: "Until then, email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) to delete your data." },
        { t: "list", items: [
          "PRIVACY.md describes a 90-day retention period. That automatic sweep is not built yet, so data is kept until you ask for deletion.",
          "`emfirge purge` removes scan records, drift records, simulation logs and the matching stored reports for your account. It does not yet remove branches, submitted plans, evidence or policy checks.",
          "Discarding a branch marks it closed. It does not delete its data.",
        ] },
        { t: "note", x: "[TODO Ansh: update PRIVACY.md to match this page, and tell us when sweeps, full purge and branch deletion ship so this section can change.]" },
      ],
    },
    {
      id: "open",
      title: "Open source, reporting and certifications",
      blocks: [
        { t: "table", head: ["Part", "License"], rows: [
          ["Engine (`backend/`) and the CloudFormation template", "AGPL-3.0"],
          ["MCP adapter (`mcp/`)", "Apache-2.0"],
        ] },
        { t: "p", x: "You can read every check. Self-hosting the engine is possible under the license but is not supported." },
        { t: "p", x: "**Certifications:** emfirge holds none today. Its CIS and SOC 2 mapping reports which controls its checks cover; it is not an audit." },
        { t: "p", x: "**Reporting a vulnerability:** email [ansh@emfirge.cloud](mailto:ansh@emfirge.cloud) rather than opening a public issue. The aim is to acknowledge within 48 hours and give an initial assessment within 7 days. Read [SECURITY.md](https://github.com/theanshsonkar/emfirge/blob/main/SECURITY.md) and [PRIVACY.md](https://github.com/theanshsonkar/emfirge/blob/main/PRIVACY.md)." },
        { t: "p", x: "**Advisory, not a gate:** a `block` is a verdict. Emfirge does not stop an agent, person or pipeline with its own AWS credentials from applying a change." },
      ],
    },
  ],
};
