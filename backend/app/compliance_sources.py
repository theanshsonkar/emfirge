"""
Published compliance data and Emfirge's mapping onto it.

The framework requirements (ids, descriptions, which checks belong to which
requirement) come from Prowler's compliance files, vendored unmodified under
data/third_party/prowler/compliance/ (Apache-2.0, see SOURCE.json there).

EMFIRGE_TO_PROWLER is Emfirge's own statement of which Emfirge rule tests the
same condition as which Prowler check. An entry is only added when the two test
the same thing; anything uncertain is left out, so the requirement stays
unevaluated rather than claiming a pass.
"""

import json
import os
from functools import lru_cache

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "third_party", "prowler", "compliance")

# framework id -> (file, display name, Prowler framework version fallback)
FRAMEWORK_FILES = {
    "cis-aws-1.5": ("cis_1.5_aws.json", "CIS AWS Foundations Benchmark"),
    "soc2": ("soc2_aws.json", "SOC 2"),
}

_P = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_"

EMFIRGE_TO_PROWLER = {
    "EMFIRGE-EC2-002": [_P + "22"],
    "EMFIRGE-EC2-003": [_P + "3389"],
    "EMFIRGE-EC2-016": ["ec2_instance_imdsv2_enabled"],
    "EMFIRGE-S3-001": ["s3_bucket_public_access"],
    "EMFIRGE-S3-002": ["s3_bucket_default_encryption"],
    "EMFIRGE-S3-003": ["s3_bucket_object_versioning"],
    "EMFIRGE-S3-004": ["s3_bucket_server_access_logging_enabled"],
    "EMFIRGE-RDS-002": ["rds_instance_no_public_access"],
    "EMFIRGE-RDS-003": ["rds_instance_storage_encrypted"],
    "EMFIRGE-RDS-004": ["rds_instance_deletion_protection"],
    "EMFIRGE-RDS-005": ["rds_instance_integration_cloudwatch_logs"],
    "EMFIRGE-IAM-001": ["iam_no_root_access_key"],
    "EMFIRGE-IAM-004": ["iam_rotate_access_key_90_days"],
    # CT-001 (no logging trail) and CT-002 (trail not multi-region) together are
    # the condition "no multi-region trail is logging".
    "EMFIRGE-CT-001": ["cloudtrail_multi_region_enabled"],
    "EMFIRGE-CT-002": ["cloudtrail_multi_region_enabled"],
    "EMFIRGE-GD-001": ["guardduty_is_enabled"],
    "EMFIRGE-VPC-001": ["vpc_flow_logs_enabled"],
    "EMFIRGE-KMS-001": ["kms_cmk_rotation_enabled"],
}

# Service whose absence makes the rule not applicable (matches the keys used by
# compliance._check_service_has_resources).
RULE_SERVICE = {
    "EMFIRGE-EC2-016": "ec2",
    "EMFIRGE-S3-001": "s3",
    "EMFIRGE-S3-002": "s3",
    "EMFIRGE-S3-003": "s3",
    "EMFIRGE-S3-004": "s3",
    "EMFIRGE-RDS-002": "rds",
    "EMFIRGE-RDS-003": "rds",
    "EMFIRGE-RDS-004": "rds",
    "EMFIRGE-RDS-005": "rds",
    "EMFIRGE-VPC-001": "vpc",
    "EMFIRGE-KMS-001": "kms",
}


@lru_cache(maxsize=None)
def load_source_metadata() -> dict:
    with open(os.path.join(DATA_DIR, "SOURCE.json"), encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=None)
def load_framework(framework_id: str):
    """Return the parsed Prowler framework JSON, or None for an unknown id."""
    entry = FRAMEWORK_FILES.get(framework_id)
    if not entry:
        return None
    with open(os.path.join(DATA_DIR, entry[0]), encoding="utf-8") as f:
        return json.load(f)


def prowler_check_to_rules() -> dict:
    """Inverse of EMFIRGE_TO_PROWLER: Prowler check id -> sorted Emfirge rule ids."""
    inv = {}
    for rule_id, checks in EMFIRGE_TO_PROWLER.items():
        for check in checks:
            inv.setdefault(check, set()).add(rule_id)
    return {k: sorted(v) for k, v in inv.items()}
