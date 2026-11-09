import type { Page } from "./types.ts";

const T = (type: string, add: string, mod: string, del: string, note: string) => [`\`${type}\``, add, mod, del, note];

// Read from backend/app/mutations.py (_MUTATION_CAPABILITIES, 18 types) on 2026-11-08. See site/FACTS.md, sections 2 and 4.
export const coverage: Page = {
  slug: "coverage",
  href: "/coverage/",
  nav: "Coverage",
  title: "Coverage",
  h1: "What a branch can change,\nand what it can judge.",
  lead: "Emfirge reads far more of your account than it can change on a branch. This page is the honest line between the two. Anything on the wrong side of it is listed as unmodeled or unknown instead of passing.",
  description: "The AWS resource types a branch can add, modify or delete, what each of the six checks is built from, the status of each lens, and where the checks come from.",
  intro: [
    { t: "fig", id: "coverage", caption: "Figure 1. The 18 resource types a branch can change today. Each pip is an operation it supports: green for add, outlined for modify, red for delete." },
  ],
  sections: [
    {
      id: "resources",
      title: "Resources a branch can change",
      blocks: [
        { t: "lede", x: "Eighteen resource types today." },
        { t: "table", head: ["Resource type", "Add", "Modify", "Delete", "Notes"], mono: [0], ops: [1, 2, 3], rows: [
          T("ec2_instance", "yes", "yes", "yes", ""),
          T("security_group", "yes", "yes", "yes", "Attachments derive from instance `sg_ids`."),
          T("rds_instance", "yes", "yes", "yes", ""),
          T("s3_bucket", "yes", "yes", "yes", "Public-by-bucket-policy is detected. `policy_public` is derived from `policy`."),
          T("lambda_function", "yes", "yes", "yes", ""),
          T("network_acl", "yes", "yes", "yes", "Modify replaces the complete `entries` and/or `associated_subnet_ids`."),
          T("iam_role", "yes", "yes", "yes", "Modify covers the trust policy."),
          T("iam_role_policy", "", "yes", "", "Replaces the complete `access_statements` list of an existing role, by role ARN."),
          T("iam_user", "yes", "yes", "", "Modify sets the console and access-key flags, or replaces the complete statement list."),
          T("iam_instance_profile", "yes", "", "", "The ID is the instance profile ARN; the one field is `role_arn`."),
          T("nat_gateway", "yes", "", "", "AWS assigns the ID; `subnet_id` and `connectivity_type` are needed."),
          T("route_table", "yes", "yes", "", "Modify replaces the complete `routes` list. New internet-gateway routes need attachment evidence."),
          T("rds_snapshot", "yes", "", "yes", "Add is a manual snapshot of an existing database."),
          T("ebs_volume", "yes", "", "yes", "`size_gb` is required for an add."),
          T("ebs_snapshot", "", "", "yes", ""),
          T("dynamodb_table", "", "yes", "yes", "Modify sets point-in-time recovery or deletion protection. Adding a table is not modeled."),
          T("cloudfront_distribution", "", "yes", "", "Modify changes `enabled`, aliases, price class, web ACL, origins and cache behaviors. Adding or deleting a distribution is not modeled."),
          T("scheduler_schedule", "yes", "yes", "yes", "EventBridge Scheduler schedules."),
        ] },
        { t: "p", x: "Most types also carry `tags`; a tag change replaces the complete user tag set, and `aws:` tags are kept. The live endpoint `GET /branches/capabilities` is the authoritative list, and `GET /branches/field-catalog` lists every settable field with the AWS API member it stands for, taken from AWS's own API models. A value AWS would reject is rejected." },
        { t: "h3", x: "Not modeled." },
        { t: "p", x: "Every resource type that is not in the table, and every operation left empty in it. A change to one of them is read but not modeled: it is listed as unmodeled and cannot pass." },
      ],
    },
    {
      id: "degrades",
      title: "When emfirge can't model it",
      blocks: [
        { t: "lede", x: "Anything not modeled is listed. It never passes quietly." },
        { t: "list", items: [
          "A change to an unmodeled type or operation is listed as unmodeled and makes the verdict stricter (`unmodeled_change` warns; `unmodeled_delete` blocks).",
          "A missing value AWS requires is flagged `unspecified_values`, never filled with a guess.",
          "A source that was not collected is an unknown in the answer, not a silent \"nothing found\".",
          "A scanner that did not run is reported as not run; `coverage_warnings` says the result is not full coverage.",
        ] },
      ],
    },
    {
      id: "lenses",
      title: "Lenses and their status",
      blocks: [
        { t: "lede", x: "Each lens looks at the branch from one angle. Together they feed the checks." },
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
      id: "built-from",
      title: "What each check is built from",
      blocks: [
        { t: "lede", x: "The engine parts and the data behind each of the six checks." },
        { t: "table", head: ["Check", "Engine parts", "Data sources"], key: true, rows: [
          ["Data", "Dependencies lens: a deleted data store against the snapshots and backups that survive. Recovery points the branch removes: deleted snapshots, backups, versioning or point-in-time recovery turned off.", "Your read-only scan: EBS volumes and snapshots, RDS snapshots and backup settings, S3 versioning, DynamoDB tables."],
          ["Exposure", "Security lens: the ingress-rule diff, internet reachability over security groups, network ACLs, route tables and gateways, S3 public access, role trust, RDS default ports. Opt-in IAM Access Analyzer checks, which can only make the verdict stricter.", "Your scan. AWS documentation for S3 public access and RDS ports. IAM Access Analyzer, with your role, only after you accept an estimate."],
          ["Money", "Cost lens: provisioned cost before and after, per resource and in total.", "The AWS Price List (us-east-1 on-demand prices, vendored)."],
          ["Availability", "Dependencies lens: the dependency graph walked up to 10 levels, and lost internal and internet paths. Role permission facts, the CloudFront Host-header fact, schedules turned off or deleted, recent use.", "Your scan: network interfaces, IAM role last-used. policy_sentry IAM action data. AWS CloudFront documentation. CloudTrail and CloudWatch evidence over 90 days, opt-in."],
          ["Control", "Security lens: admin access added or removed, privilege-escalation paths added, permissions added, S3 access logging.", "pathfinding.cloud (92 escalation paths). policy_sentry IAM action data. Your scan: IAM roles and users, S3 logging."],
          ["Outside world", "A per-service table written by hand (AWS Support, Service Quotas, SES, Route 53 Domains, Marketplace, Savings Plans), and schedule changes.", "AWS documentation, one page cited per table entry. Your scan: EventBridge Scheduler schedules."],
        ] },
        { t: "p", x: "The Compliance lens (CIS 1.5 and SOC 2, from Prowler) feeds `emfirge context --compliance`, and the Limits lens feeds the `capacity` reason in the verdict. Neither is part of the six checks. Lenses are internals; they are named here so you can see where each answer comes from." },
      ],
    },
    {
      id: "sources",
      title: "Where the checks come from",
      blocks: [
        { t: "lede", x: "Public data where a source exists, kept next to every fact. The few facts with no public source are written by hand, cite the AWS docs, and are tested." },
        { t: "sources" },
        { t: "table", head: ["Source", "Used for"], rows: [
          ["[pathfinding.cloud](https://pathfinding.cloud)", "IAM privilege-escalation paths (92)"],
          ["[policy_sentry](https://github.com/salesforce/policy_sentry)", "IAM access levels and the catalog of actions per service"],
          ["[Prowler](https://github.com/prowler-cloud/prowler)", "CIS 1.5 and SOC 2 control lists, and scanner severities"],
          ["AWS API models and Price List", "The field catalog, and provisioned cost"],
          ["[Checkov](https://github.com/bridgecrewio/checkov)", "An advisory configuration scanner on each verdict. It warns; it does not block on its own. Trivy is off."],
        ] },
        { t: "p", x: "The numbers in the chart are counted from the repository, not estimated. Every behavior is pinned by a numbered law, a property test that must always hold; there are 89, numbered L1 to L92 (L37 to L39 are not used). [Read the laws](https://github.com/theanshsonkar/emfirge/tree/main/backend/tests/laws)." },
      ],
    },
  ],
};
