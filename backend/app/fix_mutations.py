"""
Fix Mutations Map
=================
Maps rule_id → a function that returns the mutation config to apply
to the infrastructure dict in order to simulate fixing that finding.

Each function receives (infra_dict, resource_id) and mutates infra_dict in-place.
Returns True if mutation was applied, False if resource not found.
"""


def _fix_ssh_open(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-EC2-002: Remove SSH (port 22) open to 0.0.0.0/0 from the security group."""
    for sg in infra_dict.get('ec2', {}).get('security_groups', []):
        if sg['id'] == resource_id:
            sg['rules'] = [
                r for r in sg.get('rules', [])
                if not (
                    r.get('from_port') == 22 and
                    '0.0.0.0/0' in r.get('ip_ranges', [])
                )
            ]
            # Also update the ssh_open_to_internet flag
            infra_dict['ec2']['ssh_open_to_internet'] = False
            infra_dict['ec2']['ssh_security_group_id'] = None
            return True
    return False


def _fix_rdp_open(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-EC2-003: Remove RDP (port 3389) open to 0.0.0.0/0 from the security group."""
    for sg in infra_dict.get('ec2', {}).get('security_groups', []):
        if sg['id'] == resource_id:
            sg['rules'] = [
                r for r in sg.get('rules', [])
                if not (
                    r.get('from_port') == 3389 and
                    '0.0.0.0/0' in r.get('ip_ranges', [])
                )
            ]
            infra_dict['ec2']['rdp_open_to_internet'] = False
            infra_dict['ec2']['rdp_security_group_id'] = None
            return True
    return False


def _fix_s3_public(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-S3-001: Make S3 bucket non-public."""
    for bucket in infra_dict.get('s3', {}).get('buckets', []):
        if bucket['name'] == resource_id:
            bucket['is_public'] = False
            bucket['policy'] = None
            # Remove from public_buckets list
            pub = infra_dict['s3'].get('public_buckets', [])
            if resource_id in pub:
                pub.remove(resource_id)
            return True
    return False


def _fix_s3_encryption(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-S3-002: Enable encryption on S3 bucket."""
    # Remove from unencrypted_buckets list
    unenc = infra_dict.get('s3', {}).get('unencrypted_buckets', [])
    if resource_id in unenc:
        unenc.remove(resource_id)
        return True
    return False


def _fix_s3_versioning(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-S3-003: Enable versioning on S3 bucket."""
    no_ver = infra_dict.get('s3', {}).get('buckets_without_versioning', [])
    if resource_id in no_ver:
        no_ver.remove(resource_id)
        return True
    return False


def _fix_rds_public(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-RDS-002: Make RDS instance non-publicly-accessible."""
    for rds in infra_dict.get('rds', {}).get('rds_instances', []):
        if rds['id'] == resource_id:
            rds['publicly_accessible'] = False
            pub = infra_dict['rds'].get('publicly_accessible', [])
            if resource_id in pub:
                pub.remove(resource_id)
            return True
    return False


def _fix_rds_encryption(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-RDS-003: Enable encryption on RDS instance."""
    for rds in infra_dict.get('rds', {}).get('rds_instances', []):
        if rds['id'] == resource_id:
            rds['encrypted'] = True
            unenc = infra_dict['rds'].get('unencrypted_instances', [])
            if resource_id in unenc:
                unenc.remove(resource_id)
            return True
    return False


def _fix_rds_multi_az(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-RDS-006: Enable Multi-AZ on RDS."""
    infra_dict['rds']['multi_az_enabled'] = True
    return True


def _fix_ec2_imdsv2(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-EC2-009: Require IMDSv2 on EC2 instance."""
    for inst in infra_dict.get('ec2', {}).get('instances', []):
        if inst['id'] == resource_id:
            inst['imdsv2_required'] = True
            return True
    return False


def _fix_waf_not_enabled(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-WAF-001: Attach WAF to ALB."""
    albs_without = infra_dict.get('waf', {}).get('albs_without_waf', [])
    if resource_id in albs_without:
        albs_without.remove(resource_id)
        return True
    return False


def _fix_rds_deletion_protection(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-RDS-004: Enable deletion protection on RDS."""
    no_dp = infra_dict.get('rds', {}).get('instances_without_deletion_protection', [])
    if resource_id in no_dp:
        no_dp.remove(resource_id)
        return True
    return False


def _fix_guardduty_disabled(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-GUARD-001: Enable GuardDuty."""
    infra_dict['guardduty']['is_enabled'] = True
    infra_dict['guardduty']['detector_id'] = 'simulated-detector'
    return True


def _fix_cloudwatch_disabled(infra_dict: dict, resource_id: str) -> bool:
    """EMFIRGE-CW-001: Enable CloudWatch alarms."""
    infra_dict['cloudwatch']['has_alarms'] = True
    infra_dict['cloudwatch']['has_billing_alarm'] = True
    return True


# -- MASTER MAP ----------------------------------------------------
# rule_id → mutation function
FIX_MUTATIONS: dict = {
    "EMFIRGE-EC2-002": _fix_ssh_open,
    "EMFIRGE-EC2-003": _fix_rdp_open,
    "EMFIRGE-S3-001": _fix_s3_public,
    "EMFIRGE-S3-002": _fix_s3_encryption,
    "EMFIRGE-S3-003": _fix_s3_versioning,
    "EMFIRGE-RDS-002": _fix_rds_public,
    "EMFIRGE-RDS-003": _fix_rds_encryption,
    "EMFIRGE-RDS-004": _fix_rds_deletion_protection,
    "EMFIRGE-RDS-006": _fix_rds_multi_az,
    "EMFIRGE-EC2-009": _fix_ec2_imdsv2,
    "EMFIRGE-WAF-001": _fix_waf_not_enabled,
    "EMFIRGE-GUARD-001": _fix_guardduty_disabled,
    "EMFIRGE-CW-001": _fix_cloudwatch_disabled,
}
