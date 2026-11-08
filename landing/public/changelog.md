# Changelog.

What changed in emfirge, taken from the public git history. Dates are commit dates.

Human version: https://emfirge.cloud/changelog/

## Recent changes

### November 8, 2026: The emfirge command is its own npm package, and its commands come from the server [CLI]

`npx emfirge` runs the CLI. The engine serves the list of commands, so a new command works without a new install.

Improvements:
- The npm package `emfirge` gives the `emfirge` command, bundled into one file with no dependencies.
- The CLI reads its commands from `GET /cli/manifest` and keeps a copy built in for when the server cannot be reached. A test pins the two together (law L88).
- Exit codes now say what failed: input the server rejected (400, 422) exits 1, a conflict (409) exits 5, a rate limit (429) exits 4 as `rate_limited`, and a command that needs a newer emfirge exits 6.

Fixes:
- AWS CLI shorthand such as `--target Arn=…` is refused with a clear message instead of being guessed.

### November 8, 2026: Check lists every changed setting, judged or named as not judged [Engine]

A setting that changed and that no check reads is no longer silent.

Improvements:
- `check` returns `changed_settings`: every setting that differs on a resource, by name and never by value, with the answers that read it. A setting no check reads is named as not judged (law L87).
- The MCP check tool, the CLI's `--human` output and the agent guide show it.

### November 8, 2026: Outside world is decided per service, and unknowns are named [Engine]

Fewer hand-made guesses, and more things said to be unknown.

Improvements:
- An action that leaves the cloud is classified per service and per action, never by single actions added by hand. A read by name (Get, List, Describe) is not outside world, and every table entry cites AWS's documentation (law L83).
- A permission that was never granted is reported as unknown, not as a fact (law L84). Schedule gaps are closed: a change to a schedule's run settings is a fact, deleting an enabled schedule is an availability fact, and outside world carries plan gaps as unknowns (law L85).
- A DynamoDB item count of 0 is unknown emptiness, never a recovery point (laws L80, L86).
- A CloudFormation change set that removes a property is a reset or a named unknown, never dropped (law L82); security group egress is diffed like ingress.

### November 8, 2026: Four privacy leaks in CLI and MCP output closed [Privacy]

An audit of what the CLI and MCP print found four places where an identifier could get through.

Improvements:
- The before and after values in a branch diff, the check's path pattern, bare account IDs and the ARNs of DynamoDB, SQS, SNS, Scheduler, CloudFront and WAF in text are masked, and so is what you typed when a usage error echoes it (law L81).
- PRIVACY.md covers CloudFront, Scheduler and DynamoDB data and what is withheld.

### November 7, 2026: Context and check answer with facts, and the CLI arrives [Engine]

Two read-only questions about your cloud, and a command that asks them.

Improvements:
- `context` returns what is true, what was checked and what is unknown, for 11 questions, from a scan or a branch (law L73).
- `check` returns facts about six damages (data, exposure, money, availability, control, outside world) with what was checked and what is unknown. It never returns a rule ID (law L74).
- The `emfirge` CLI with its verbs and an agent guide; the MCP adapter gained `emfirge_context` and `emfirge_check`.

### November 7, 2026: Branches model EventBridge Scheduler, CloudFront and DynamoDB [Branches]

Four more resource types can be tried on a branch, each with its own facts.

Improvements:
- EventBridge Scheduler schedules can be added, modified and deleted on a branch (law L75). A schedule that starts running is an outside-world fact (law L77).
- CloudFront distributions can be modified, and a cache behavior that forwards the Host header to an S3 origin is an availability fact (law L78).
- DynamoDB tables are first-class in the data answer and in delete safety (law L80).
- A role's permissions are compared action by action in `check` and `context access`.

### November 7, 2026: Purge, discard and plan storage now do what they say [Privacy]

The first privacy audit's findings, fixed and pinned by tests.

Improvements:
- Purge covers every table that is keyed to an AWS account, including branches, plans, evidence and policy checks. A test fails if a table is added without a purge-or-keep decision (law L71a).
- Discarding a branch deletes it and every row linked to it (law L71b).
- The server keeps only a SHA-256 of an uploaded plan, never its text (law L71c). API and CI keys are stored as hashes (law L71d).
- Server logs carry no customer identifiers (law L71g), and PRIVACY.md is checked against the code (law L71h).
- Token and sign-in files on your machine are private to your user (law L71f), and `purge` in the MCP adapter needs you to be signed in (law L71i).

Fixes:
- A real scan now finishes instead of failing on its collection time (law L72).

### October 26, 2026: Terraform plans carry IAM, S3, Lambda and EC2 settings [Inputs]

More of what a Terraform plan says now reaches the branch.

Improvements:
- A created IAM role is identified by account, path and name (law L67), and roles, users and instance profiles get the permissions Terraform grants them (law L68).
- S3 bucket ACL, versioning, encryption, logging, policy and Block Public Access are read from a plan (law L69).
- A Lambda's role, environment secrets and VPC, and an instance's metadata settings and user-data secrets, are read from a plan (law L70).

### October 26, 2026: Scanner checks that need unmodeled data are skipped [Scanners]

Checks from the borrowed scanners that read attributes emfirge does not model are now skipped instead of judged on missing data.

Improvements:
- A scanner check that reads an attribute the engine does not model is skipped, so it cannot raise a finding from nothing (law L66).

### October 25, 2026: Scanners see IAM, KMS, CloudTrail, Lambda and the network [Scanners]

More of your account is passed to the scanners, and they are skipped when the input is unknown.

Improvements:
- IAM roles and policies, KMS keys, CloudTrail, Lambda, VPCs, subnets and security group peers are now sent to the scanners, with crosswalks for KMS, CloudTrail, flow-log and Lambda-in-VPC checks (law L65).
- Database and instance settings are collected and sent to the scanners (law L64).

Fixes:
- Absent log exports now mean none, and a check is skipped on both sides when its input is unknown on either side.

### October 24, 2026: Checkov runs on every verdict, with severities from Prowler [Scanners]

The Checkov scanner is switched on in the hosted engine; Trivy stays off.

Improvements:
- Checkov runs through a separate worker next to the engine and reports as advisory.
- Scanner severities come from Prowler's published check metadata (law L63).

### October 23, 2026: Prices, compliance and port ranges come from public data [Engine]

Three checks now read published sources instead of hand-written values.

Improvements:
- Provisioned cost comes from AWS's published Price List (law L59).
- CIS 1.5 and SOC 2 control lists come from Prowler's published data (law L57).
- SSH and RDP count as open when a port range or an all-traffic rule includes them (law L58).
- The scanner input reports what it left out, as a loss report in the verdict (law L60).

### October 23, 2026: Opt-in AWS policy checks and a faster scanner [Engine]

Ask AWS itself whether a policy is public, and re-scan only what changed.

Improvements:
- Opt-in IAM Access Analyzer checks for S3 bucket policies and role trust policies, run with your own role after you accept a cost estimate (law L62). They can only make a verdict stricter.
- The Checkov worker stays warm, caches the base scan and scans only changed resources and their neighbors (law L61).

### October 22, 2026: Branches can add volumes, route tables and NAT gateways [Branches]

More of what an agent builds can now be tried on a branch.

Improvements:
- Add EBS volumes (law L51), route tables (law L52) and NAT gateways on a branch.
- Resource tags are modeled (law L50), and a field catalog built from AWS's API models lists every settable field (law L54).
- Buckets made public by a bucket policy are detected (law L49), and RDS internet ingress shows in the graph (law L55).

### October 20, 2026: IAM role trust, IAM users and RDS snapshots on a branch [Branches]

More IAM and database changes can be tried before they are real.

Improvements:
- Add or modify an IAM role's trust policy, add an IAM user, and add an RDS manual snapshot.
- The two-sided diff now covers changeable types that have no graph node.

### October 14, 2026: AWS CLI commands and CloudFormation change sets go straight onto a branch [Inputs]

Hand emfirge the change you already have; it returns the exact calls it judged.

Improvements:
- AWS CLI commands go into a branch, with an exact hand-back of the calls.
- CloudFormation change sets go into a branch the same way.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
