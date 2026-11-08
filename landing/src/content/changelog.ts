import type { Page, Entry } from "./types.ts";

// Seeded from the real git history of this repository (commit dates, rewritten in plain English).
// Law numbers (L..) are the ones named in the commit messages. Nothing here is invented.
export const entries: Entry[] = [
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
  lead: "What changed in the emfirge engine, taken from the public git history. Dates are commit dates.",
  description: "Recent emfirge engine changes, in plain English, from the repository's git history.",
  sections: [{ id: "entries", title: "Recent changes", blocks: [{ t: "entries", items: entries }] }],
};
