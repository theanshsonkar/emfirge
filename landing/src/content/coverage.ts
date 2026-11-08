import type { Page } from "./types.ts";

const T = (type: string, add: string, mod: string, del: string, note: string) => [`\`${type}\``, add, mod, del, note];

export const coverage: Page = {
  slug: "coverage",
  href: "/coverage/",
  nav: "Coverage",
  title: "Coverage",
  h1: "What a branch can change,\nand what it can judge.",
  lead: "Emfirge reads far more of your account than it can change on a branch. This page is the honest line between the two. Anything on the wrong side of it degrades the verdict instead of passing.",
  description: "The AWS resource types a branch can add, modify or delete, the status of each lens, and where the checks come from.",
  intro: [
    { t: "fig", id: "coverage", caption: "Figure 1. The 14 resource types a branch can change today. Each pip is an operation it supports: green for add, outlined for modify, red for delete." },
  ],
  sections: [
    {
      id: "resources",
      title: "Resources a branch can change",
      blocks: [
        { t: "lede", x: "Fourteen resource types today." },
        { t: "table", head: ["Resource type", "Add", "Modify", "Delete", "Notes"], mono: [0], rows: [
          T("ec2_instance", "yes", "yes", "yes", ""),
          T("security_group", "yes", "yes", "yes", "Attachments derive from instance `sg_ids`."),
          T("rds_instance", "yes", "yes", "yes", ""),
          T("s3_bucket", "yes", "yes", "yes", "Public-by-bucket-policy is detected."),
          T("lambda_function", "yes", "yes", "yes", ""),
          T("network_acl", "yes", "yes", "yes", "Modify replaces the complete `entries` and/or `associated_subnet_ids`."),
          T("iam_role", "yes", "yes", "yes", "Modify covers the trust policy."),
          T("iam_role_policy", "", "yes", "", "Replaces the complete `access_statements` list of an existing role."),
          T("iam_user", "yes", "", "", ""),
          T("nat_gateway", "yes", "", "", "AWS assigns the ID; `subnet_id` and `connectivity_type` are needed."),
          T("route_table", "yes", "yes", "", "Modify replaces the complete `routes` list. New internet-gateway routes need attachment evidence."),
          T("rds_snapshot", "yes", "", "yes", "Add is a manual snapshot of an existing database."),
          T("ebs_volume", "yes", "", "yes", "`size_gb` is required for an add."),
          T("ebs_snapshot", "", "", "yes", ""),
        ] },
        { t: "p", x: "Most types also carry `tags`; a tag change replaces the complete user tag set, and `aws:` tags are kept. The live endpoint `GET /branches/capabilities` is the authoritative list, and `GET /branches/field-catalog` lists every settable field with the AWS API member it stands for, taken from AWS's own API models. A value AWS would reject is rejected." },
        { t: "h3", x: "Not modeled yet." },
        { t: "p", x: "CloudFront, DynamoDB and EventBridge Scheduler. A change to them is read but not modeled, so it cannot pass." },
      ],
    },
    {
      id: "degrades",
      title: "When emfirge can't model it",
      blocks: [
        { t: "lede", x: "Anything not modeled degrades the verdict. It never passes quietly." },
        { t: "list", items: [
          "A change to an unmodeled type or operation is listed as unmodeled and makes the verdict stricter (`unmodeled_change`; `unmodeled_delete` blocks).",
          "A missing value AWS requires is flagged `unspecified_values`, never filled with a guess.",
          "A collection gap is shown in the diff, not hidden.",
          "A scanner that did not run is reported as not run; `coverage_warnings` says the result is not full coverage.",
        ] },
      ],
    },
    {
      id: "lenses",
      title: "Lenses and their status",
      blocks: [
        { t: "lede", x: "Each lens looks at the branch from one angle. Together they feed the six checks." },
        { t: "table", head: ["Lens", "Asks", "Status"], rows: [
          ["Security", "Does this expose something, or open a privilege-escalation path?", "Live"],
          ["Dependencies", "What breaks if this is removed? Is it still in use? Can it be recovered?", "Live"],
          ["Compliance", "Which CIS AWS Foundations 1.5 and SOC 2 controls flip? Uncovered controls are never `pass`. These are mapped checks, not an audit.", "Live"],
          ["Cost", "What does it cost before and after? AWS Price List, **us-east-1 only**, provisioned charges only, no load-balancer capacity units.", "Early"],
          ["Limits", "Will it hit an AWS quota? AWS default quotas only, not your approved increases, and no forecasting.", "Early"],
          ["Yours", "Bring your own evaluator against the same branch.", "Planned"],
        ] },
        { t: "p", x: "Usage-based cost (data transfer, requests, invocations) is excluded and labelled unknown. Application latency, throughput and runtime correctness need a real run and are not modeled." },
      ],
    },
    {
      id: "sources",
      title: "Where the checks come from",
      blocks: [
        { t: "lede", x: "Public data, with the source kept next to every fact. Not hand-written lists." },
        { t: "sources" },
        { t: "table", head: ["Source", "Used for"], rows: [
          ["[pathfinding.cloud](https://pathfinding.cloud)", "IAM privilege-escalation paths (92)"],
          ["[policy_sentry](https://github.com/salesforce/policy_sentry)", "IAM access levels for every action pattern"],
          ["[Prowler](https://github.com/prowler-cloud/prowler)", "CIS 1.5 and SOC 2 control lists, and scanner severities"],
          ["AWS API models and Price List", "The field catalog, and provisioned cost"],
          ["[Checkov](https://github.com/bridgecrewio/checkov)", "An advisory configuration scanner on each verdict. It warns; it does not block on its own. Trivy is off."],
        ] },
        { t: "p", x: "The numbers in the chart are counted from the repository, not estimated. Every behavior is pinned by a numbered law, a property test that must always hold. [Read the laws](https://github.com/theanshsonkar/emfirge/tree/main/backend/tests/laws)." },
      ],
    },
  ],
};
