import math

# ── MATURITY CHECK CONSTANTS ──────────────────────────────────────
MATURITY_CHECKS = [
    ("cloudtrail_multiregion",    10),
    ("guardduty_enabled",         10),
    ("no_root_access_keys",       10),
    ("all_iam_users_mfa",         10),
    ("vpc_flow_logs_enabled",     10),
    ("kms_rotation_enabled",      10),
    ("config_recording_enabled",   5),
    ("cloudwatch_alarms_exist",    5),
]

MATURITY_FIELD_MAP = {
    "cloudtrail_multiregion":   lambda i: i.cloudtrail.is_multi_region,
    "guardduty_enabled":        lambda i: i.guardduty.is_enabled,
    "no_root_access_keys":      lambda i: not i.iam.root_has_access_keys,
    "all_iam_users_mfa":        lambda i: len(i.iam.users_without_mfa) == 0,
    "vpc_flow_logs_enabled":    lambda i: len(i.vpc.vpcs_without_flow_logs) == 0 and i.vpc.total_vpcs > 0,
    "kms_rotation_enabled":     lambda i: i.kms.total_cmks > 0 and len(i.kms.cmks_without_rotation) == 0,
    "config_recording_enabled": lambda i: i.config.is_enabled and i.config.is_recording,
    "cloudwatch_alarms_exist":  lambda i: i.cloudwatch.has_alarms,
}

# ── SEVERITY × CONFIDENCE WEIGHT TABLE ───────────────────────────
# Each finding contributes a base weight determined by its severity and
# how confident the rule is that this is a real risk (not a false positive).
# Context-aware rules that downgrade findings set confidence='LOW'.
# Hardcoded Critical rules with no ambiguity set confidence='HIGH'.
# Everything else defaults to 'MEDIUM'.
SEVERITY_WEIGHTS = {
    'Critical': {'HIGH': 20, 'MEDIUM': 12, 'LOW': 6},
    'Moderate': {'HIGH': 8,  'MEDIUM': 5,  'LOW': 2},
    'Low':      {'HIGH': 2,  'MEDIUM': 1,  'LOW': 0.5},
}

# ── CRITICAL FLOOR PENALTY ────────────────────────────────────────
# Each Critical/HIGH finding imposes a flat penalty on the overall score
# regardless of account size. This prevents large accounts from hiding
# critical vulnerabilities behind a high resource count.
CRITICAL_FLOOR_PENALTY = 5   # points deducted per Critical/HIGH finding


def _weighted_risk(findings: list) -> float:
    """
    Sum weighted risk across a list of findings.

    For each finding:
      weight           = SEVERITY_WEIGHTS[severity][confidence]
      blast_multiplier = 1 + log10(1 + blast_radius)
      contribution     = weight * blast_multiplier

    blast_radius=0  → multiplier = 1.0  (no amplification)
    blast_radius=9  → multiplier ≈ 2.0
    blast_radius=99 → multiplier ≈ 3.0
    """
    total = 0.0
    for f in findings:
        severity = f.severity if f.severity in SEVERITY_WEIGHTS else 'Low'
        confidence = f.confidence if f.confidence in ('HIGH', 'MEDIUM', 'LOW') else 'MEDIUM'
        blast = f.blast_radius or 0
        weight = SEVERITY_WEIGHTS[severity][confidence]
        blast_multiplier = 1 + math.log10(1 + blast)
        total += weight * blast_multiplier
    return total


def _critical_floor_penalty(findings: list) -> int:
    """
    Count Critical/HIGH findings and return a flat penalty.
    This ensures large accounts can't dilute critical issues.
    """
    count = sum(
        1 for f in findings
        if (f.severity if f.severity in SEVERITY_WEIGHTS else 'Low') == 'Critical'
        and (f.confidence if f.confidence in ('HIGH', 'MEDIUM', 'LOW') else 'MEDIUM') == 'HIGH'
    )
    return count * CRITICAL_FLOOR_PENALTY


def _score_from_risk(weighted_risk: float, total_resources: int) -> int:
    """
    Convert accumulated weighted risk into a 0–100 score.

    Normalise by max(total_resources, 10) * 20 so that the same number of
    findings on a larger account produces a proportionally smaller penalty.
    Score is inverted: higher = safer.
    """
    normaliser = max(total_resources, 10) * 20
    raw = weighted_risk / normaliser          # 0.0 → ∞, typically 0.0–1.0+
    score = 100 * max(0.0, 1.0 - raw)        # invert: 0 risk → 100, high risk → 0
    return max(0, min(100, int(score)))


def _category_resource_count(category: str, infrastructure) -> int:
    """
    Return the number of resources relevant to a specific category.
    This makes category scores responsive to actual posture instead of
    being diluted by the total resource count.

    Falls back to 10 (the global minimum) if infrastructure is None
    or the category has no specific resource mapping.
    """
    if infrastructure is None:
        return 10

    if category == 'Availability':
        # Compute + DB resources — the things that need redundancy
        count = (
            infrastructure.ec2.instance_count +
            len(infrastructure.rds.instances) +
            infrastructure.lambda_data.function_count +
            infrastructure.ecs.total_task_definitions
        )
        return max(count, 3)   # floor of 3 so a single-instance account isn't over-penalised

    if category == 'Disaster Recovery':
        # Stateful resources — the things that need backups
        count = (
            len(infrastructure.rds.instances) +
            infrastructure.s3.total_buckets +
            len(infrastructure.ec2.ebs_volumes)
        )
        return max(count, 3)

    if category == 'Cost':
        # All resources contribute to cost
        return max(_total_resource_count(infrastructure), 10)

    # Security — uses total resources (covers everything)
    return max(_total_resource_count(infrastructure), 10)


def _total_resource_count(infrastructure) -> int:
    """Sum all resource counts from infrastructure. Safe if infrastructure is None."""
    if infrastructure is None:
        return 10
    return max(10, (
        infrastructure.ec2.instance_count +
        infrastructure.s3.total_buckets +
        len(infrastructure.rds.instances) +
        infrastructure.lambda_data.function_count +
        infrastructure.secrets_manager.total_secrets +
        infrastructure.vpc.total_vpcs +
        infrastructure.kms.total_cmks +
        infrastructure.sns.total_topics +
        infrastructure.ecs.total_task_definitions +
        infrastructure.waf.total_albs +
        infrastructure.api_gateway.total_apis +
        infrastructure.elasticache.total_clusters +
        infrastructure.sqs.total_queues +
        infrastructure.dynamodb.total_tables
    ))


def calculate_score(findings_dict: dict, total_resources: int = 10, infrastructure=None) -> dict:
    """
    Calculate weighted, blast-radius-aware risk scores.

    Parameters
    ----------
    findings_dict   : dict returned by run_all_checks()
    total_resources : total number of resources scanned — used for normalisation.
                      Defaults to 10 so the function is safe to call without it.

    Returns the same keys as the old scoring function so no callers break:
      overall_risk_score, overall_risk_level,
      security_score, availability_score, disaster_recovery_score,
      cost_score, cost_level
    """
    critical = findings_dict.get('critical_risks', [])
    moderate = findings_dict.get('moderate_risks', [])
    low      = findings_dict.get('low_risks', [])
    cost     = findings_dict.get('cost_findings', [])

    all_risk_findings = critical + moderate + low

    # ── OVERALL SCORE ─────────────────────────────────────────────
    overall_risk  = _weighted_risk(all_risk_findings)
    overall_score = _score_from_risk(overall_risk, total_resources)

    # Apply critical floor penalty — flat deduction per Critical/HIGH finding
    floor_penalty = _critical_floor_penalty(all_risk_findings)
    overall_score = max(0, overall_score - floor_penalty)

    # ── MATURITY BONUS ────────────────────────────────────────────
    maturity_score = 0
    maturity_bonus = 0.0
    maturity_checks_passed = []
    if infrastructure is not None:
        maturity_checks_passed = [
            check for check, pts in MATURITY_CHECKS
            if MATURITY_FIELD_MAP[check](infrastructure)
        ]
        maturity_score = sum(
            pts for check, pts in MATURITY_CHECKS
            if check in maturity_checks_passed
        )
        raw_bonus = round((maturity_score / 80) * 15, 1)
        # Cap maturity bonus at +5 when critical findings exist
        has_criticals = len(critical) > 0
        maturity_bonus = min(raw_bonus, 5.0) if has_criticals else raw_bonus
        overall_score = min(100, overall_score + int(maturity_bonus))

    if overall_score >= 85:
        risk_level = 'LOW'
    elif overall_score >= 70:
        risk_level = 'MODERATE'
    elif overall_score >= 50:
        risk_level = 'HIGH'
    else:
        risk_level = 'CRITICAL'

    # ── CATEGORY SCORES ───────────────────────────────────────────
    # Each category normalises against its own relevant resource count
    # so that thin categories (Availability, DR) produce meaningful scores.

    security_findings     = [f for f in all_risk_findings if f.category == 'Security']
    security_resources    = _category_resource_count('Security', infrastructure) if infrastructure else total_resources
    security_score        = _score_from_risk(_weighted_risk(security_findings), security_resources)

    availability_findings = [f for f in all_risk_findings if f.category == 'Availability']
    availability_resources = _category_resource_count('Availability', infrastructure) if infrastructure else total_resources
    availability_score    = _score_from_risk(_weighted_risk(availability_findings), availability_resources)

    dr_findings           = [f for f in all_risk_findings if f.category == 'Disaster Recovery']
    dr_resources          = _category_resource_count('Disaster Recovery', infrastructure) if infrastructure else total_resources
    dr_score              = _score_from_risk(_weighted_risk(dr_findings), dr_resources)

    # ── COST SCORE ────────────────────────────────────────────────
    cost_risk  = _weighted_risk(cost)
    cost_score = _score_from_risk(cost_risk, total_resources)

    if cost_score >= 80:
        cost_level = 'OPTIMIZED'
    elif cost_score >= 50:
        cost_level = 'REVIEW NEEDED'
    else:
        cost_level = 'ACTION REQUIRED'

    return {
        'overall_risk_score':        overall_score,
        'overall_risk_level':        risk_level,
        'security_score':            security_score,
        'availability_score':        availability_score,
        'disaster_recovery_score':   dr_score,
        'cost_score':                cost_score,
        'cost_level':                cost_level,
        'maturity_score':            maturity_score,
        'maturity_bonus':            maturity_bonus,
        'maturity_checks_passed':    maturity_checks_passed,
    }
