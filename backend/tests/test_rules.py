"""
Tests for rules.py — zero AWS calls, zero LLM calls.
Uses synthetic AWSInfrastructure objects from conftest.py
"""
import pytest
from app.rules import (
    run_all_checks, find_toxic_combos,
    check_ssh_open, check_rdp_open, check_dangerous_open_ports,
    check_default_sg_open, check_imdsv1_enabled,
    check_public_s3_context_aware, check_s3_encryption, check_s3_versioning,
    check_s3_no_logging,
    check_rds_no_backup, check_rds_public, check_rds_encryption,
    check_rds_deletion_protection, check_rds_log_exports,
    check_root_access_keys, check_users_without_mfa, check_iam_wildcard_policy,
    check_old_access_keys, check_root_used_recently,
    check_cloudtrail_disabled, check_cloudtrail_not_multiregion,
    check_guardduty_disabled, check_no_cloudwatch,
    check_lambda_admin_role, check_lambda_outdated_runtime,
    check_vpc_no_flow_logs, check_default_vpc_in_use,
    check_kms_pending_deletion, check_kms_no_rotation,
    check_ecs_privileged_mode, check_sns_public_access,
    check_waf_not_enabled,
    # New rules
    check_rds_no_multi_az, check_multi_instance_no_alb,
    check_lambda_no_vpc, check_single_az_instances,
    check_rds_low_backup_retention, check_cloudtrail_no_log_validation,
)
from app.egraph import build_graph
from app.models import (
    AWSInfrastructure, EC2Data, S3Data, RDSData, IAMData, IAMUser,
    CloudTrailData, GuardDutyData, LambdaData, VPCData, KMSData,
    ECSData, SNSData, WAFData, SecurityGroup, EC2Instance, S3Bucket,
    RDSInstance,
)


# -- EC2 RULES -----------------------------------------------------

class TestSSHOpen:
    def test_ssh_open_is_critical(self, nightmare_infra):
        result = check_ssh_open(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-EC2-002"
        assert result.resource_id == "sg-ssh"

    def test_ssh_closed_no_finding(self, clean_infra):
        result = check_ssh_open(clean_infra)
        assert result is None

    def test_ssh_open_behind_lb_downgrades_to_low(self):
        """SSH open but instances are behind a load balancer — should downgrade."""
        from app.models import LoadBalancer
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instance_count=1,
                instance_ids=["i-001"],
                ssh_open_to_internet=True,
                ssh_security_group_id="sg-ssh",
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-ssh"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(
                    id="sg-ssh", name="web",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
                load_balancers=[LoadBalancer(arn="arn:aws:elb:us-east-1:123:loadbalancer/app/my-lb/abc", type="application", target_instances=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = check_ssh_open(infra, graph)
        assert result is not None
        assert result.severity == "Low"
        assert result.confidence == "LOW"

    def test_ssh_open_no_graph_stays_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(ssh_open_to_internet=True, ssh_security_group_id="sg-001"),
        )
        result = check_ssh_open(infra, graph=None)
        assert result is not None
        assert result.severity == "Critical"


class TestRDPOpen:
    def test_rdp_open_is_critical(self, nightmare_infra):
        result = check_rdp_open(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-EC2-003"

    def test_rdp_closed_no_finding(self, clean_infra):
        assert check_rdp_open(clean_infra) is None


class TestDangerousOpenPorts:
    def test_database_port_open_is_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-db", name="db-sg",
                    rules=[{"from_port": 3306, "to_port": 3306, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        findings = check_dangerous_open_ports(infra)
        assert len(findings) == 1
        assert findings[0].severity == "Critical"
        assert findings[0].rule_id == "EMFIRGE-EC2-012"
        assert "3306" in findings[0].issue

    def test_web_ports_not_flagged(self):
        """Ports 80 and 443 open to internet should NOT produce findings."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-web", name="web-sg",
                    rules=[
                        {"from_port": 80, "to_port": 80, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]},
                        {"from_port": 443, "to_port": 443, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]},
                    ],
                    attached_to=["i-001"],
                )],
            ),
        )
        findings = check_dangerous_open_ports(infra)
        assert len(findings) == 0

    def test_all_ports_open_is_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-all", name="open-all",
                    rules=[{"from_port": 0, "to_port": 65535, "protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        findings = check_dangerous_open_ports(infra)
        assert any(f.rule_id == "EMFIRGE-EC2-010" for f in findings)

    def test_internal_port_open_is_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-int", name="internal",
                    rules=[{"from_port": 8080, "to_port": 8080, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        findings = check_dangerous_open_ports(infra)
        assert len(findings) == 1
        assert findings[0].rule_id == "EMFIRGE-EC2-013"

    def test_no_findings_when_no_sgs(self, clean_infra):
        clean_infra.ec2.security_groups = []
        assert check_dangerous_open_ports(clean_infra) == []

    def test_private_cidr_not_flagged(self):
        """Rules restricted to private CIDR should not produce findings."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-priv", name="private",
                    rules=[{"from_port": 3306, "to_port": 3306, "protocol": "tcp", "ip_ranges": ["10.0.0.0/8"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        assert check_dangerous_open_ports(infra) == []


class TestDefaultSGOpen:
    def test_default_sg_with_open_rule_is_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-default", name="default",
                    rules=[{"from_port": 0, "to_port": 65535, "protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=[],
                )],
            ),
        )
        findings = check_default_sg_open(infra)
        assert len(findings) == 1
        assert findings[0].rule_id == "EMFIRGE-EC2-015"

    def test_non_default_sg_not_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-custom", name="my-custom-sg",
                    rules=[{"from_port": 0, "to_port": 65535, "protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=[],
                )],
            ),
        )
        assert check_default_sg_open(infra) == []


class TestIMDSv1:
    def test_imdsv1_enabled_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=False)],
            ),
        )
        findings = check_imdsv1_enabled(infra)
        assert len(findings) == 1
        assert findings[0].rule_id == "EMFIRGE-EC2-016"
        assert "i-001" in findings[0].issue

    def test_imdsv2_required_no_finding(self, clean_infra):
        assert check_imdsv1_enabled(clean_infra) == []

    def test_multiple_instances_each_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=False),
                    EC2Instance(id="i-002", type="t3.micro", state="running", imdsv2_required=False),
                    EC2Instance(id="i-003", type="t3.micro", state="running", imdsv2_required=True),
                ],
            ),
        )
        findings = check_imdsv1_enabled(infra)
        assert len(findings) == 2
        ids = [f.resource_id for f in findings]
        assert "i-001" in ids
        assert "i-002" in ids
        assert "i-003" not in ids


# -- S3 RULES -----------------------------------------------------

class TestPublicS3:
    def test_prod_bucket_public_is_critical(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                public_buckets=["prod-data-bucket"],
                buckets=[S3Bucket(name="prod-data-bucket", is_public=True, is_empty=False)],
            ),
        )
        findings = check_public_s3_context_aware(infra)
        assert len(findings) == 1
        assert findings[0].severity == "Critical"

    def test_cloudfront_bucket_public_is_low(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                public_buckets=["my-website-assets"],
                buckets=[S3Bucket(name="my-website-assets", is_public=True, has_cloudfront=True, is_empty=False)],
            ),
        )
        graph = build_graph(infra)
        findings = check_public_s3_context_aware(infra, graph)
        assert len(findings) == 1
        assert findings[0].severity == "Low"

    def test_dev_bucket_public_downgrades_to_moderate(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                public_buckets=["dev-test-bucket"],
                buckets=[S3Bucket(name="dev-test-bucket", is_public=True, is_empty=False)],
            ),
        )
        findings = check_public_s3_context_aware(infra)
        assert len(findings) == 1
        assert findings[0].severity == "Moderate"

    def test_no_public_buckets_no_findings(self, clean_infra):
        assert check_public_s3_context_aware(clean_infra) == []

    def test_website_bucket_without_cloudfront_is_moderate(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                public_buckets=["my-website-static"],
                buckets=[S3Bucket(name="my-website-static", is_public=True, has_cloudfront=False, is_empty=False)],
            ),
        )
        findings = check_public_s3_context_aware(infra)
        assert findings[0].severity == "Moderate"


class TestS3Encryption:
    def test_unencrypted_buckets_flagged(self, nightmare_infra):
        result = check_s3_encryption(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-S3-002"

    def test_all_encrypted_no_finding(self, clean_infra):
        assert check_s3_encryption(clean_infra) is None


class TestS3NoLogging:
    def test_buckets_without_logging_flagged(self, nightmare_infra):
        result = check_s3_no_logging(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-S3-004"
        assert result.severity == "Moderate"
        assert result.confidence == "HIGH"
        assert result.aws_service == "S3"
        assert "prod-data-bucket" in result.issue

    def test_all_logging_enabled_no_finding(self, clean_infra):
        assert check_s3_no_logging(clean_infra) is None

    def test_single_bucket_without_logging(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                total_buckets=2,
                buckets_without_logging=["my-app-data"],
                buckets=[
                    S3Bucket(name="my-app-data", is_public=False, is_empty=False),
                    S3Bucket(name="my-logs", is_public=False, is_empty=False),
                ],
            ),
        )
        result = check_s3_no_logging(infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-S3-004"
        assert result.resource_id == "my-app-data"

    def test_empty_account_no_finding(self, empty_infra):
        assert check_s3_no_logging(empty_infra) is None


# -- RDS RULES -----------------------------------------------------

class TestRDSRules:
    def test_no_backup_is_critical(self, nightmare_infra):
        result = check_rds_no_backup(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-RDS-001"

    def test_backup_enabled_no_finding(self, clean_infra):
        assert check_rds_no_backup(clean_infra) is None

    def test_no_rds_no_finding(self, empty_infra):
        assert check_rds_no_backup(empty_infra) is None

    def test_public_rds_is_critical(self, nightmare_infra):
        result = check_rds_public(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-RDS-002"

    def test_private_rds_no_finding(self, clean_infra):
        assert check_rds_public(clean_infra) is None

    def test_deletion_protection_missing_is_critical(self, nightmare_infra):
        result = check_rds_deletion_protection(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-RDS-004"

    def test_log_exports_missing_flagged(self, nightmare_infra):
        result = check_rds_log_exports(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-RDS-005"


# -- IAM RULES -----------------------------------------------------

class TestIAMRules:
    def test_root_access_keys_critical(self, nightmare_infra):
        result = check_root_access_keys(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-IAM-001"

    def test_no_root_keys_no_finding(self, clean_infra):
        assert check_root_access_keys(clean_infra) is None

    def test_console_user_without_mfa_is_critical(self, nightmare_infra):
        findings = check_users_without_mfa(nightmare_infra)
        console_findings = [f for f in findings if "has console access" in f.issue]
        assert len(console_findings) > 0
        assert all(f.severity == "Critical" for f in console_findings)

    def test_programmatic_user_without_mfa_is_low(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(
                users_without_mfa=["svc-account"],
                iam_users=[IAMUser(username="svc-account", has_console_access=False)],
            ),
        )
        findings = check_users_without_mfa(infra)
        assert len(findings) == 1
        assert findings[0].severity == "Low"

    def test_no_users_without_mfa_no_finding(self, clean_infra):
        assert check_users_without_mfa(clean_infra) == []

    def test_wildcard_policy_is_critical(self, nightmare_infra):
        findings = check_iam_wildcard_policy(nightmare_infra)
        assert len(findings) >= 1
        assert all(f.severity == "Critical" for f in findings)
        assert all(f.rule_id == "EMFIRGE-IAM-006" for f in findings)

    def test_root_used_recently_is_moderate(self, nightmare_infra):
        result = check_root_used_recently(nightmare_infra)
        assert result is not None
        assert result.severity == "Moderate"
        assert result.rule_id == "EMFIRGE-IAM-005"

    def test_root_not_used_recently_no_finding(self, clean_infra):
        assert check_root_used_recently(clean_infra) is None


# -- CLOUDTRAIL / GUARDDUTY ----------------------------------------

class TestCloudTrailGuardDuty:
    def test_cloudtrail_disabled_flagged(self, nightmare_infra):
        result = check_cloudtrail_disabled(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-CT-001"

    def test_cloudtrail_enabled_no_finding(self, clean_infra):
        assert check_cloudtrail_disabled(clean_infra) is None

    def test_single_region_trail_flagged(self, partial_permissions_infra):
        result = check_cloudtrail_not_multiregion(partial_permissions_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-CT-002"

    def test_multi_region_trail_no_finding(self, clean_infra):
        assert check_cloudtrail_not_multiregion(clean_infra) is None

    def test_guardduty_disabled_flagged(self, nightmare_infra):
        result = check_guardduty_disabled(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-GD-001"

    def test_guardduty_enabled_no_finding(self, clean_infra):
        assert check_guardduty_disabled(clean_infra) is None


# -- VPC / KMS / ECS / SNS / WAF ----------------------------------

class TestVPCKMSECSSNSWAF:
    def test_vpc_no_flow_logs_flagged(self, nightmare_infra):
        result = check_vpc_no_flow_logs(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-VPC-001"

    def test_vpc_flow_logs_ok_no_finding(self, clean_infra):
        assert check_vpc_no_flow_logs(clean_infra) is None

    def test_default_vpc_in_use_flagged(self, nightmare_infra):
        result = check_default_vpc_in_use(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-VPC-002"

    def test_kms_pending_deletion_is_critical(self, nightmare_infra):
        result = check_kms_pending_deletion(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-KMS-002"

    def test_kms_no_rotation_flagged(self, nightmare_infra):
        result = check_kms_no_rotation(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-KMS-001"

    def test_ecs_privileged_is_critical(self, nightmare_infra):
        result = check_ecs_privileged_mode(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-ECS-001"

    def test_sns_public_access_is_critical(self, nightmare_infra):
        result = check_sns_public_access(nightmare_infra)
        assert result is not None
        assert result.severity == "Critical"
        assert result.rule_id == "EMFIRGE-SNS-002"

    def test_waf_missing_flagged(self, nightmare_infra):
        result = check_waf_not_enabled(nightmare_infra)
        assert result is not None
        assert result.rule_id == "EMFIRGE-WAF-001"

    def test_waf_present_no_finding(self, clean_infra):
        assert check_waf_not_enabled(clean_infra) is None


# -- RUN ALL CHECKS ------------------------------------------------

class TestRunAllChecks:
    def test_clean_account_has_no_critical_risks(self, clean_infra):
        results = run_all_checks(clean_infra)
        assert results["critical_risks"] == []

    def test_nightmare_account_has_many_criticals(self, nightmare_infra):
        results = run_all_checks(nightmare_infra)
        assert len(results["critical_risks"]) >= 5

    def test_empty_account_no_crash(self, empty_infra):
        results = run_all_checks(empty_infra)
        assert "critical_risks" in results
        assert "moderate_risks" in results
        assert "cost_findings" in results

    def test_all_findings_have_rule_id_or_category(self, nightmare_infra):
        results = run_all_checks(nightmare_infra)
        all_findings = (
            results["critical_risks"]
            + results["moderate_risks"]
            + results["cost_findings"]
        )
        for f in all_findings:
            assert f.category is not None
            assert f.severity in ("Critical", "Moderate", "Low")

    def test_no_duplicate_rule_ids_per_resource(self, nightmare_infra):
        """Same rule_id should not fire twice for the same resource_id."""
        results = run_all_checks(nightmare_infra)
        all_findings = results["critical_risks"] + results["moderate_risks"]
        seen = set()
        for f in all_findings:
            key = (f.rule_id, f.resource_id)
            assert key not in seen, f"Duplicate finding: {f.rule_id} on {f.resource_id}"
            seen.add(key)

    def test_partial_permissions_no_crash(self, partial_permissions_infra):
        results = run_all_checks(partial_permissions_infra)
        assert isinstance(results, dict)

    def test_with_graph_enriches_findings(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        results = run_all_checks(nightmare_infra, graph)
        assert len(results["critical_risks"]) >= 5


# -- TOXIC COMBOS -------------------------------------------------

class TestToxicCombos:
    def test_ssh_open_no_guardduty_detected(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        findings = run_all_checks(nightmare_infra, graph)
        combos = find_toxic_combos(findings, graph, nightmare_infra)
        combo_ids = [c.combo_id for c in combos]
        assert "SSH_OPEN_NO_GUARDDUTY" in combo_ids

    def test_public_rds_no_cloudtrail_detected(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        findings = run_all_checks(nightmare_infra, graph)
        combos = find_toxic_combos(findings, graph, nightmare_infra)
        combo_ids = [c.combo_id for c in combos]
        assert "PUBLIC_RDS_NO_CLOUDTRAIL" in combo_ids

    def test_rds_no_backup_no_deletion_protection(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        findings = run_all_checks(nightmare_infra, graph)
        combos = find_toxic_combos(findings, graph, nightmare_infra)
        combo_ids = [c.combo_id for c in combos]
        assert "RDS_NO_BACKUP_NO_DELETION_PROTECTION" in combo_ids

    def test_clean_account_no_combos(self, clean_infra):
        graph = build_graph(clean_infra)
        findings = run_all_checks(clean_infra, graph)
        combos = find_toxic_combos(findings, graph, clean_infra)
        assert combos == []

    def test_all_combos_have_required_fields(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        findings = run_all_checks(nightmare_infra, graph)
        combos = find_toxic_combos(findings, graph, nightmare_infra)
        for c in combos:
            assert c.combo_id
            assert c.title
            assert c.severity in ("CRITICAL", "HIGH")
            assert isinstance(c.resource_ids, list)

# -- NEW AVAILABILITY RULES ----------------------------------------

class TestRDSNoMultiAZ:
    def test_no_multi_az_flagged(self, nightmare_infra):
        result = check_rds_no_multi_az(nightmare_infra)
        assert result is not None
        assert result.severity == "Moderate"
        assert result.category == "Availability"
        assert result.rule_id == "EMFIRGE-RDS-006"

    def test_multi_az_enabled_no_finding(self, clean_infra):
        assert check_rds_no_multi_az(clean_infra) is None

    def test_no_rds_no_finding(self, empty_infra):
        assert check_rds_no_multi_az(empty_infra) is None


class TestMultiInstanceNoALB:
    def test_multi_instance_no_alb_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(instance_count=3, has_load_balancer=False),
        )
        result = check_multi_instance_no_alb(infra)
        assert result is not None
        assert result.severity == "Moderate"
        assert result.category == "Availability"
        assert result.rule_id == "EMFIRGE-EC2-017"

    def test_multi_instance_with_alb_no_finding(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(instance_count=3, has_load_balancer=True),
        )
        assert check_multi_instance_no_alb(infra) is None

    def test_single_instance_no_finding(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(instance_count=1, has_load_balancer=False),
        )
        assert check_multi_instance_no_alb(infra) is None


class TestLambdaNoVPC:
    def test_lambda_no_vpc_flagged(self):
        from app.models import LambdaFunction
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=2,
                functions=[
                    LambdaFunction(name="fn-a", vpc_id=None),
                    LambdaFunction(name="fn-b", vpc_id="vpc-001"),
                ],
            ),
        )
        results = check_lambda_no_vpc(infra)
        assert len(results) == 1
        assert results[0].resource_id == "fn-a"
        assert results[0].category == "Availability"

    def test_all_in_vpc_no_finding(self):
        from app.models import LambdaFunction
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions=[LambdaFunction(name="fn-a", vpc_id="vpc-001")],
            ),
        )
        assert check_lambda_no_vpc(infra) == []

    def test_no_functions_no_finding(self, empty_infra):
        assert check_lambda_no_vpc(empty_infra) == []


class TestSingleAZInstances:
    def test_all_same_subnet_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instance_count=3,
                instances=[
                    EC2Instance(id="i-1", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-a"),
                    EC2Instance(id="i-2", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-a"),
                    EC2Instance(id="i-3", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-a"),
                ],
            ),
        )
        result = check_single_az_instances(infra)
        assert result is not None
        assert result.severity == "Moderate"
        assert result.category == "Availability"

    def test_different_subnets_no_finding(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instance_count=2,
                instances=[
                    EC2Instance(id="i-1", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-a"),
                    EC2Instance(id="i-2", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-b"),
                ],
            ),
        )
        assert check_single_az_instances(infra) is None

    def test_single_instance_no_finding(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instance_count=1,
                instances=[EC2Instance(id="i-1", type="t3.micro", sg_ids=[], state="running", subnet_id="subnet-a")],
            ),
        )
        assert check_single_az_instances(infra) is None


# -- NEW DISASTER RECOVERY RULES ----------------------------------

class TestRDSLowBackupRetention:
    def test_low_retention_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(instances=["db-1"], backup_enabled=True, backup_retention_days=3),
        )
        result = check_rds_low_backup_retention(infra)
        assert result is not None
        assert result.severity == "Moderate"
        assert result.category == "Disaster Recovery"
        assert result.rule_id == "EMFIRGE-RDS-007"

    def test_good_retention_no_finding(self, clean_infra):
        assert check_rds_low_backup_retention(clean_infra) is None

    def test_no_backup_no_finding(self):
        """If backups are disabled entirely, check_rds_no_backup handles it — not this rule."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(instances=["db-1"], backup_enabled=False, backup_retention_days=0),
        )
        assert check_rds_low_backup_retention(infra) is None

    def test_no_rds_no_finding(self, empty_infra):
        assert check_rds_low_backup_retention(empty_infra) is None


class TestCloudTrailNoLogValidation:
    def test_no_validation_flagged(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            cloudtrail=CloudTrailData(is_enabled=True, has_log_file_validation=False),
        )
        result = check_cloudtrail_no_log_validation(infra)
        assert result is not None
        assert result.severity == "Low"
        assert result.category == "Disaster Recovery"
        assert result.rule_id == "EMFIRGE-CT-003"

    def test_validation_enabled_no_finding(self, clean_infra):
        assert check_cloudtrail_no_log_validation(clean_infra) is None

    def test_cloudtrail_disabled_no_finding(self):
        """If CloudTrail is off, check_cloudtrail_disabled handles it — not this rule."""
        infra = AWSInfrastructure(
            region="us-east-1",
            cloudtrail=CloudTrailData(is_enabled=False, has_log_file_validation=False),
        )
        assert check_cloudtrail_no_log_validation(infra) is None
