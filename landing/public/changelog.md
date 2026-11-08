# Changelog.

What changed in the emfirge engine, taken from the public git history. Dates are commit dates.

Human version: https://emfirge.cloud/changelog/

## Recent changes

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
