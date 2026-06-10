"""
Compliance framework evaluation engine.

Maps EMFIRGE rule IDs to CIS AWS Foundations Benchmark 1.5 and SOC 2 Type II controls.
Evaluates pass/fail per control based on which rules fired during a scan.

Logic:
- If a control's mapped rule_id is found in the scan findings → FAIL
- If a control's mapped rule_id is NOT found → PASS
- If mapped_rule_id is None → PASS (no automated check available, assumed compliant)
- "not_applicable" is determined by checking if the relevant service has resources
"""

from typing import Optional


# --- FRAMEWORK DEFINITIONS ----------------------------------------------------

CIS_SECTIONS = [
    {"id": "1", "title": "Identity and Access Management"},
    {"id": "2", "title": "Storage"},
    {"id": "3", "title": "Logging"},
    {"id": "4", "title": "Monitoring"},
    {"id": "5", "title": "Networking"},
    {"id": "6", "title": "Compute"},
    {"id": "7", "title": "Database"},
]

SOC2_SECTIONS = [
    {"id": "cc6", "title": "Logical & Physical Access"},
    {"id": "cc7", "title": "System Operations"},
    {"id": "cc8", "title": "Change Management"},
]

# Each control: (id, title, section, mapped_rule_id, description_pass, description_fail, na_service)
# na_service: if set, control is "not_applicable" when that service has 0 resources

CIS_CONTROLS = [
    # Section 1: IAM
    ("1.1", "Ensure no root access keys exist", "1", "EMFIRGE-IAM-001",
     "No root access keys found", "Root account has active access keys",
     None),
    ("1.2", "Ensure MFA enabled for all IAM users", "1", "EMFIRGE-IAM-003",
     "All IAM users have MFA enabled", "Users without MFA detected",
     None),
    ("1.3", "Avoid use of root account", "1", "EMFIRGE-IAM-005",
     "Root account not used in last 90 days", "Root account used recently",
     None),
    ("1.4", "Rotate access keys within 90 days", "1", "EMFIRGE-IAM-004",
     "All access keys rotated within 90 days", "Stale access keys detected (>90 days old)",
     None),
    ("1.5", "Ensure no wildcard IAM policies", "1", "EMFIRGE-IAM-006",
     "No wildcard admin policies detected", "Users/roles with wildcard admin policies found",
     None),

    # Section 2: Storage
    ("2.1", "Ensure S3 buckets are not public", "2", "EMFIRGE-S3-001",
     "No public S3 buckets", "Public S3 bucket(s) detected",
     "s3"),
    ("2.2", "Ensure S3 bucket encryption", "2", "EMFIRGE-S3-002",
     "All buckets encrypted", "Unencrypted S3 bucket(s) detected",
     "s3"),
    ("2.3", "Ensure S3 versioning enabled", "2", "EMFIRGE-S3-003",
     "Versioning enabled on all buckets", "Bucket(s) without versioning detected",
     "s3"),
    ("2.4", "Ensure S3 access logging", "2", "EMFIRGE-S3-004",
     "Access logging configured on all buckets", "Bucket(s) without access logging detected",
     "s3"),

    # Section 3: Logging
    ("3.1", "Ensure CloudTrail is enabled", "3", "EMFIRGE-CT-001",
     "CloudTrail enabled", "CloudTrail is disabled",
     None),
    ("3.2", "Ensure CloudTrail multi-region", "3", "EMFIRGE-CT-002",
     "Multi-region trail configured", "CloudTrail not configured for multi-region",
     None),
    ("3.3", "Ensure CloudTrail log file validation", "3", "EMFIRGE-CT-003",
     "Log file validation enabled", "CloudTrail log file validation disabled",
     None),
    ("3.4", "Ensure VPC flow logs enabled", "3", "EMFIRGE-VPC-001",
     "Flow logs enabled on all VPCs", "VPC(s) without flow logs detected",
     "vpc"),

    # Section 4: Monitoring
    ("4.1", "Ensure GuardDuty is enabled", "4", "EMFIRGE-GD-001",
     "GuardDuty active", "GuardDuty is disabled",
     None),
    ("4.2", "Ensure CloudWatch alarms exist", "4", "EMFIRGE-CW-001",
     "CloudWatch alarms configured", "No CloudWatch alarms configured",
     None),
    ("4.3", "Ensure AWS Config is enabled", "4", "EMFIRGE-CFG-001",
     "AWS Config recording active", "AWS Config is disabled",
     None),
    ("4.4", "Ensure KMS key rotation", "4", "EMFIRGE-KMS-001",
     "All CMKs have rotation enabled", "CMK(s) without rotation detected",
     "kms"),

    # Section 5: Networking
    ("5.1", "Restrict SSH access (port 22)", "5", "EMFIRGE-EC2-002",
     "SSH not exposed to 0.0.0.0/0", "SSH open to 0.0.0.0/0 detected",
     None),
    ("5.2", "Restrict RDP access (port 3389)", "5", "EMFIRGE-EC2-003",
     "RDP not exposed to internet", "RDP open to internet detected",
     None),
    ("5.3", "Ensure no default VPC in use", "5", "EMFIRGE-VPC-002",
     "Default VPC not in use", "Resources deployed in default VPC",
     None),
    ("5.4", "Ensure WAF on public ALBs", "5", "EMFIRGE-WAF-001",
     "All public ALBs have WAF attached", "ALB(s) without WAF detected",
     "waf"),

    # Section 6: Compute
    ("6.1", "Ensure IMDSv2 required on EC2", "6", "EMFIRGE-EC2-016",
     "All instances use IMDSv2", "Instance(s) using IMDSv1 detected",
     "ec2"),
    ("6.2", "Ensure no stopped instances (waste)", "6", "EMFIRGE-EC2-006",
     "No stopped instances", "Stopped instance(s) detected (cost waste)",
     "ec2"),
    ("6.3", "Ensure Lambda functions in VPC", "6", "EMFIRGE-LAMBDA-004",
     "All Lambda functions deployed in VPC", "Lambda function(s) not in VPC",
     "lambda"),
    ("6.4", "Ensure ECS no privileged containers", "6", "EMFIRGE-ECS-001",
     "No privileged ECS containers", "Privileged ECS container(s) detected",
     "ecs"),

    # Section 7: Database
    ("7.1", "Ensure RDS not publicly accessible", "7", "EMFIRGE-RDS-002",
     "No public RDS instances", "Publicly accessible RDS instance(s) detected",
     "rds"),
    ("7.2", "Ensure RDS encryption enabled", "7", "EMFIRGE-RDS-003",
     "All RDS instances encrypted", "Unencrypted RDS instance(s) detected",
     "rds"),
    ("7.3", "Ensure RDS Multi-AZ enabled", "7", "EMFIRGE-RDS-006",
     "Multi-AZ enabled on all RDS instances", "RDS instance(s) without Multi-AZ",
     "rds"),
    ("7.4", "Ensure RDS backup retention >= 7 days", "7", "EMFIRGE-RDS-007",
     "Backup retention adequate (>= 7 days)", "RDS backup retention below 7 days",
     "rds"),
]

SOC2_CONTROLS = [
    # CC6: Logical & Physical Access
    ("CC6.1", "Logical access security", "cc6", "EMFIRGE-IAM-003",
     "MFA enforced for all users", "MFA not enforced for all users",
     None),
    ("CC6.2", "Access key management", "cc6", "EMFIRGE-IAM-004",
     "Access keys rotated within policy", "Stale access keys detected",
     None),
    ("CC6.3", "Network access restrictions", "cc6", "EMFIRGE-EC2-002",
     "Network access properly restricted", "SSH open to internet",
     None),
    ("CC6.4", "Encryption at rest", "cc6", "EMFIRGE-S3-002",
     "All storage encrypted at rest", "Unencrypted storage detected",
     None),
    ("CC6.5", "Encryption in transit", "cc6", None,
     "HTTPS enforced", "HTTPS not enforced",
     None),

    # CC7: System Operations
    ("CC7.1", "Intrusion detection", "cc7", "EMFIRGE-GD-001",
     "GuardDuty active for threat detection", "No intrusion detection system active",
     None),
    ("CC7.2", "Audit logging", "cc7", "EMFIRGE-CT-001",
     "CloudTrail enabled for audit logging", "Audit logging disabled",
     None),
    ("CC7.3", "Monitoring & alerting", "cc7", "EMFIRGE-CW-001",
     "CloudWatch alarms configured", "No monitoring alarms configured",
     None),
    ("CC7.4", "Backup & recovery", "cc7", "EMFIRGE-RDS-001",
     "Backups enabled for data stores", "Backup not enabled for data stores",
     "rds"),

    # CC8: Change Management
    ("CC8.1", "Change detection", "cc8", "EMFIRGE-CFG-001",
     "AWS Config recording changes", "Change detection not active",
     None),
    ("CC8.2", "Vulnerability management", "cc8", None,
     "Regular scanning active (Emfirge)", "No vulnerability scanning",
     None),
    ("CC8.3", "Configuration management", "cc8", "EMFIRGE-VPC-001",
     "VPC flow logs enabled for network visibility", "Network visibility gaps detected",
     None),
]


def _check_service_has_resources(service_key: str, infrastructure: Optional[dict]) -> bool:
    """Check if a service has any resources deployed. Used for N/A determination."""
    if not infrastructure:
        return True  # If no infra data, assume resources exist (don't mark N/A)

    checks = {
        "ec2": lambda i: i.get("ec2", {}).get("instance_count", 0) > 0,
        "s3": lambda i: i.get("s3", {}).get("total_buckets", 0) > 0,
        "rds": lambda i: len(i.get("rds", {}).get("instances", [])) > 0,
        "lambda": lambda i: i.get("lambda_data", {}).get("function_count", 0) > 0,
        "ecs": lambda i: i.get("ecs", {}).get("total_task_definitions", 0) > 0,
        "vpc": lambda i: i.get("vpc", {}).get("total_vpcs", 0) > 0,
        "kms": lambda i: i.get("kms", {}).get("total_cmks", 0) > 0,
        "waf": lambda i: i.get("waf", {}).get("total_albs", 0) > 0,
    }

    check_fn = checks.get(service_key)
    if not check_fn:
        return True  # Unknown service key → assume resources exist
    return check_fn(infrastructure)


def evaluate_framework(
    framework_id: str,
    fired_rule_ids: set,
    infrastructure: Optional[dict] = None,
) -> dict:
    """
    Evaluate a compliance framework against fired rule IDs.

    Args:
        framework_id: "cis-aws-1.5" or "soc2"
        fired_rule_ids: set of rule_id strings that fired during the scan
        infrastructure: optional infrastructure dict for N/A determination

    Returns:
        dict with framework metadata, sections, controls with pass/fail/not_applicable status
    """
    if framework_id == "cis-aws-1.5":
        controls_def = CIS_CONTROLS
        sections = CIS_SECTIONS
        name = "CIS AWS Foundations Benchmark"
        version = "1.5"
    elif framework_id == "soc2":
        controls_def = SOC2_CONTROLS
        sections = SOC2_SECTIONS
        name = "SOC 2 Type II"
        version = "2024"
    else:
        return {"error": f"Unknown framework: {framework_id}"}

    controls = []
    passed = 0
    failed = 0
    na = 0

    for (ctrl_id, title, section, mapped_rule_id, desc_pass, desc_fail, na_service) in controls_def:
        # Determine status
        if na_service and not _check_service_has_resources(na_service, infrastructure):
            status = "not_applicable"
            description = f"No {na_service.upper()} resources deployed"
            na += 1
        elif mapped_rule_id is None:
            # No automated check - assumed pass
            status = "pass"
            description = desc_pass
            passed += 1
        elif mapped_rule_id in fired_rule_ids:
            status = "fail"
            description = desc_fail
            failed += 1
        else:
            status = "pass"
            description = desc_pass
            passed += 1

        controls.append({
            "id": ctrl_id,
            "title": title,
            "section": section,
            "status": status,
            "mappedRuleId": mapped_rule_id,
            "description": description,
        })

    total = len(controls_def)

    return {
        "id": framework_id,
        "name": name,
        "version": version,
        "totalControls": total,
        "passedControls": passed,
        "failedControls": failed,
        "naControls": na,
        "sections": sections,
        "controls": controls,
    }


def evaluate_all_frameworks(fired_rule_ids: set, infrastructure: Optional[dict] = None) -> list:
    """Evaluate all supported frameworks and return results."""
    return [
        evaluate_framework("cis-aws-1.5", fired_rule_ids, infrastructure),
        evaluate_framework("soc2", fired_rule_ids, infrastructure),
    ]
