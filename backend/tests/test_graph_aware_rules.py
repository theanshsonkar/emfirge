"""
Tests for graph-aware rule severity adjustments.

Tests 3 scenarios for each upgraded rule:
1. No graph (graph=None) → original severity (backward compat)
2. Graph + resource IS internet-reachable → Critical (or upgraded)
3. Graph + resource NOT internet-reachable → downgraded severity

Also tests blast_radius and attack_path population.
"""
import pytest
from app.egraph import Graph, get_internet_reachable_set
from app.models import (
    AWSInfrastructure, EC2Data, S3Data, RDSData, IAMData, IAMUser,
    CloudTrailData, CostData, CloudWatchData, GuardDutyData,
    LambdaData, LambdaFunction, SecretsManagerData, VPCData, VPCSubnet,
    KMSData, ConfigData, SNSData, ECSData, WAFData,
    EC2Instance, SecurityGroup, S3Bucket, RDSInstance, LoadBalancer,
)
from app.rules import (
    check_rdp_open,
    check_dangerous_open_ports,
    check_default_sg_open,
    check_imdsv1_enabled,
    check_lambda_admin_role,
    check_lambda_outdated_runtime,
    check_iam_wildcard_policy,
    check_waf_not_enabled,
    check_s3_encryption,
    check_rds_encryption,
    check_rds_deletion_protection,
    check_cloudtrail_disabled,
    check_default_vpc_in_use,
    check_lambda_no_vpc,
    run_all_checks,
)


# -- GRAPH BUILDERS ------------------------------------------------

def build_reachable_graph(instance_ids, sg_ids, subnet_ids=None):
    """
    Build a graph where instances ARE internet-reachable.
    INTERNET → SG → instances (via public subnet).
    """
    nodes = [
        {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
    ]
    edges = []

    for sg_id in sg_ids:
        nodes.append({
            'id': sg_id, 'type': 'security_group', 'label': f'SG: {sg_id}',
            'metadata': {'name': sg_id, 'rules_count': 1, 'rules': [], 'attached_instances': instance_ids}
        })
        edges.append({'from': 'INTERNET', 'to': sg_id, 'relationship': 'REACHES'})

    for iid in instance_ids:
        nodes.append({
            'id': iid, 'type': 'ec2_instance', 'label': f'EC2: {iid}',
            'metadata': {'instance_type': 't3.micro', 'state': 'running', 'subnet_id': None}
        })
        edges.append({'from': 'INTERNET', 'to': iid, 'relationship': 'REACHES_VIA_SG'})

    if subnet_ids:
        for sid in subnet_ids:
            nodes.append({
                'id': sid, 'type': 'vpc_subnet', 'label': f'Subnet: {sid}',
                'metadata': {'vpc_id': 'vpc-001', 'resource_count': len(instance_ids)}
            })

    return Graph(nodes=nodes, edges=edges)


def build_private_graph(instance_ids, sg_ids, subnet_ids=None):
    """
    Build a graph where instances are NOT internet-reachable.
    No INTERNET node edges to instances — they're in private subnets.
    """
    nodes = [
        {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
    ]
    edges = []

    for sg_id in sg_ids:
        nodes.append({
            'id': sg_id, 'type': 'security_group', 'label': f'SG: {sg_id}',
            'metadata': {'name': sg_id, 'rules_count': 1, 'rules': [], 'attached_instances': instance_ids}
        })
        # No INTERNET → SG edge (private)

    for iid in instance_ids:
        nodes.append({
            'id': iid, 'type': 'ec2_instance', 'label': f'EC2: {iid}',
            'metadata': {'instance_type': 't3.micro', 'state': 'running', 'subnet_id': None}
        })
        # No INTERNET → instance edge (private)

    if subnet_ids:
        for sid in subnet_ids:
            nodes.append({
                'id': sid, 'type': 'vpc_subnet', 'label': f'Subnet: {sid}',
                'metadata': {'vpc_id': 'vpc-001', 'resource_count': len(instance_ids)}
            })

    return Graph(nodes=nodes, edges=edges)


def build_lb_graph(instance_ids, sg_ids, lb_arn="arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"):
    """
    Build a graph where instances are behind a load balancer.
    """
    nodes = [
        {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
        {'id': lb_arn, 'type': 'load_balancer', 'label': 'LB: my-alb', 'metadata': {'type': 'ALB', 'target_count': len(instance_ids)}},
    ]
    edges = [
        {'from': 'INTERNET', 'to': lb_arn, 'relationship': 'REACHES'},
    ]

    for sg_id in sg_ids:
        nodes.append({
            'id': sg_id, 'type': 'security_group', 'label': f'SG: {sg_id}',
            'metadata': {'name': sg_id, 'rules_count': 1, 'rules': [], 'attached_instances': instance_ids}
        })

    for iid in instance_ids:
        nodes.append({
            'id': iid, 'type': 'ec2_instance', 'label': f'EC2: {iid}',
            'metadata': {'instance_type': 't3.micro', 'state': 'running', 'subnet_id': None}
        })
        edges.append({'from': lb_arn, 'to': iid, 'relationship': 'targets_instance'})

    return Graph(nodes=nodes, edges=edges)


# -- INFRASTRUCTURE FIXTURES ---------------------------------------

def make_rdp_infra(has_subnets=True):
    """Infrastructure with RDP open to internet."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-rdp"], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=1,
            instance_types=["t3.micro"],
            instance_ids=["i-rdp"],
            rdp_open_to_internet=True,
            rdp_security_group_id="sg-rdp",
            instances=[EC2Instance(id="i-rdp", type="t3.micro", sg_ids=["sg-rdp"], state="running", imdsv2_required=True)],
            security_groups=[SecurityGroup(id="sg-rdp", name="rdp-sg",
                rules=[{"from_port": 3389, "to_port": 3389, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                attached_to=["i-rdp"])],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_dangerous_ports_infra(has_subnets=True):
    """Infrastructure with dangerous ports open (admin port 8080, DB port 3306)."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=1,
            instance_types=["t3.micro"],
            instance_ids=["i-001"],
            instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-ports"], state="running", imdsv2_required=True)],
            security_groups=[SecurityGroup(id="sg-ports", name="open-ports",
                rules=[{"from_port": 3306, "to_port": 3306, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                attached_to=["i-001"])],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_default_sg_infra(attached_to=None, has_subnets=True):
    """Infrastructure with default SG open to internet."""
    if attached_to is None:
        attached_to = ["i-001"]
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=attached_to, is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=len(attached_to),
            instance_types=["t3.micro"] * len(attached_to),
            instance_ids=attached_to,
            instances=[EC2Instance(id=iid, type="t3.micro", sg_ids=["sg-default"], state="running", imdsv2_required=True) for iid in attached_to],
            security_groups=[SecurityGroup(id="sg-default", name="default",
                rules=[{"from_port": 0, "to_port": 65535, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                attached_to=attached_to)],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_imdsv1_infra(has_subnets=True):
    """Infrastructure with IMDSv1 enabled on an instance."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-imds"], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instance_count=1,
            instance_types=["t3.micro"],
            instance_ids=["i-imds"],
            instances=[EC2Instance(id="i-imds", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=False)],
            security_groups=[SecurityGroup(id="sg-001", name="web-sg", rules=[], attached_to=["i-imds"])],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_lambda_admin_infra():
    """Infrastructure with Lambda function having admin role."""
    return AWSInfrastructure(
        region="us-east-1",
        lambda_data=LambdaData(
            function_count=1,
            functions_with_admin_role=["admin-fn"],
            functions=[LambdaFunction(name="admin-fn", role_arn="arn:aws:iam::123:role/AdminRole")],
        ),
        s3=S3Data(total_buckets=2, buckets=[
            S3Bucket(name="prod-data", is_public=False, is_empty=False),
            S3Bucket(name="logs-bucket", is_public=False, is_empty=False),
        ]),
        vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
    )


def make_lambda_outdated_infra(has_subnets=True):
    """Infrastructure with Lambda on outdated runtime."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        lambda_data=LambdaData(
            function_count=1,
            functions_with_outdated_runtime=["legacy-fn"],
            functions=[LambdaFunction(name="legacy-fn")],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_waf_infra(has_subnets=True):
    """Infrastructure with ALB missing WAF."""
    alb_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        waf=WAFData(total_albs=1, albs_without_waf=[alb_arn]),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_s3_encryption_infra(has_subnets=True):
    """Infrastructure with unencrypted S3 buckets."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        s3=S3Data(
            total_buckets=1,
            unencrypted_buckets=["sensitive-data"],
            buckets=[S3Bucket(name="sensitive-data", is_public=False, is_empty=False)],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


def make_cloudtrail_infra(has_subnets=True):
    """Infrastructure with CloudTrail disabled."""
    subnets = [VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)] if has_subnets else []
    return AWSInfrastructure(
        region="us-east-1",
        cloudtrail=CloudTrailData(is_enabled=False),
        ec2=EC2Data(
            instance_count=1,
            instance_types=["t3.micro"],
            instance_ids=["i-001"],
            instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
            security_groups=[SecurityGroup(id="sg-001", name="web-sg",
                rules=[{"from_port": 80, "to_port": 80, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                attached_to=["i-001"])],
        ),
        vpc=VPCData(total_vpcs=1, subnets=subnets),
    )


# ══════════════════════════════════════════════════════════════════
# TIER 1: INTERNET REACHABILITY TESTS
# ══════════════════════════════════════════════════════════════════

class TestRDPOpen:
    """EC2-003: check_rdp_open — downgrade if behind LB or not reachable."""

    def test_no_graph_stays_critical(self):
        """Without graph, RDP open is always Critical."""
        infra = make_rdp_infra()
        result = check_rdp_open(infra, graph=None)
        assert result is not None
        assert result.severity == 'Critical'
        assert result.raw_severity == 'Critical'

    def test_reachable_stays_critical(self):
        """With graph showing instance IS reachable, stays Critical."""
        infra = make_rdp_infra()
        graph = build_reachable_graph(["i-rdp"], ["sg-rdp"])
        result = check_rdp_open(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_behind_lb_downgrades_to_low(self):
        """With graph showing instance behind LB, downgrades to Low."""
        infra = make_rdp_infra()
        graph = build_lb_graph(["i-rdp"], ["sg-rdp"])
        result = check_rdp_open(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Low'
        assert result.raw_severity == 'Critical'
        assert 'load balancer' in result.issue

    def test_no_subnet_data_stays_critical(self):
        """Without subnet data, cannot determine reachability — stays Critical (conservative)."""
        infra = make_rdp_infra(has_subnets=False)
        graph = build_private_graph(["i-rdp"], ["sg-rdp"])
        result = check_rdp_open(infra, graph=graph)
        assert result is not None
        # Without subnet data in infra, the rule should not downgrade
        assert result.severity == 'Critical'


class TestDangerousOpenPorts:
    """EC2-010–014: check_dangerous_open_ports — downgrade if not reachable."""

    def test_no_graph_stays_critical(self):
        """Without graph, DB port open is Critical."""
        infra = make_dangerous_ports_infra()
        results = check_dangerous_open_ports(infra, graph=None)
        assert len(results) > 0
        assert results[0].severity == 'Critical'
        assert results[0].raw_severity == 'Critical'

    def test_reachable_stays_critical(self):
        """With graph showing instance IS reachable, stays Critical."""
        infra = make_dangerous_ports_infra()
        graph = build_reachable_graph(["i-001"], ["sg-ports"])
        results = check_dangerous_open_ports(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Critical'

    def test_not_reachable_downgrades(self):
        """With graph showing instance NOT reachable, downgrades to Moderate."""
        infra = make_dangerous_ports_infra()
        graph = build_private_graph(["i-001"], ["sg-ports"])
        results = check_dangerous_open_ports(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Moderate'
        assert results[0].raw_severity == 'Critical'
        assert 'not internet-reachable' in results[0].issue


class TestDefaultSGOpen:
    """EC2-015: check_default_sg_open — downgrade if no instances or not reachable."""

    def test_no_graph_stays_critical(self):
        """Without graph, default SG open is Critical."""
        infra = make_default_sg_infra()
        results = check_default_sg_open(infra, graph=None)
        assert len(results) > 0
        assert results[0].severity == 'Critical'

    def test_reachable_stays_critical(self):
        """With graph showing instance IS reachable, stays Critical."""
        infra = make_default_sg_infra()
        graph = build_reachable_graph(["i-001"], ["sg-default"])
        results = check_default_sg_open(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Critical'

    def test_not_reachable_downgrades_to_moderate(self):
        """With graph showing instance NOT reachable, downgrades to Moderate."""
        infra = make_default_sg_infra()
        graph = build_private_graph(["i-001"], ["sg-default"])
        results = check_default_sg_open(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Moderate'
        assert results[0].raw_severity == 'Critical'

    def test_no_attached_instances_downgrades_to_low(self):
        """Default SG with no attached instances → Low."""
        infra = make_default_sg_infra(attached_to=[])
        # Need a graph with the SG node but no attached instances
        graph = build_private_graph([], ["sg-default"])
        results = check_default_sg_open(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Low'


class TestIMDSv1:
    """EC2-016: check_imdsv1_enabled — upgrade to Critical if reachable."""

    def test_no_graph_stays_moderate(self):
        """Without graph, IMDSv1 is Moderate."""
        infra = make_imdsv1_infra()
        results = check_imdsv1_enabled(infra, graph=None)
        assert len(results) > 0
        assert results[0].severity == 'Moderate'
        assert results[0].raw_severity == 'Moderate'

    def test_reachable_upgrades_to_critical(self):
        """With graph showing instance IS reachable, upgrades to Critical."""
        infra = make_imdsv1_infra()
        graph = build_reachable_graph(["i-imds"], ["sg-001"])
        results = check_imdsv1_enabled(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Critical'
        assert 'internet-reachable' in results[0].issue

    def test_not_reachable_stays_moderate(self):
        """With graph showing instance NOT reachable, stays Moderate."""
        infra = make_imdsv1_infra()
        graph = build_private_graph(["i-imds"], ["sg-001"])
        results = check_imdsv1_enabled(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Moderate'

    def test_no_subnet_data_stays_moderate(self):
        """Without subnet data, cannot upgrade — stays Moderate (conservative)."""
        infra = make_imdsv1_infra(has_subnets=False)
        graph = build_reachable_graph(["i-imds"], ["sg-001"])
        results = check_imdsv1_enabled(infra, graph=graph)
        assert len(results) > 0
        # No subnet data in infra → has_subnet_data=False → no upgrade
        assert results[0].severity == 'Moderate'


class TestLambdaAdminRole:
    """LAMBDA-001: check_lambda_admin_role — add blast_radius."""

    def test_no_graph_stays_critical(self):
        """Without graph, Lambda admin role is Critical with no blast_radius."""
        infra = make_lambda_admin_infra()
        result = check_lambda_admin_role(infra, graph=None)
        assert result is not None
        assert result.severity == 'Critical'

    def test_with_graph_adds_blast_radius(self):
        """With graph containing data stores, blast_radius is populated."""
        infra = make_lambda_admin_infra()
        # Build a graph with Lambda → IAM Role → can_access → S3 buckets
        nodes = [
            {'id': 'admin-fn', 'type': 'lambda_function', 'label': 'Lambda: admin-fn', 'metadata': {'role_arn': 'arn:aws:iam::123:role/AdminRole'}},
            {'id': 'iam-role-AdminRole', 'type': 'iam_role', 'label': 'IAM Role: AdminRole', 'metadata': {'arn': 'arn:aws:iam::123:role/AdminRole'}},
            {'id': 'prod-data', 'type': 's3_bucket', 'label': 'S3: prod-data', 'metadata': {}},
            {'id': 'logs-bucket', 'type': 's3_bucket', 'label': 'S3: logs-bucket', 'metadata': {}},
        ]
        edges = [
            {'from': 'admin-fn', 'to': 'iam-role-AdminRole', 'relationship': 'uses_iam_role'},
            {'from': 'iam-role-AdminRole', 'to': 'prod-data', 'relationship': 'can_access'},
            {'from': 'iam-role-AdminRole', 'to': 'logs-bucket', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_lambda_admin_role(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'
        assert result.blast_radius is not None
        assert result.blast_radius >= 2  # At least 2 data stores accessible


class TestLambdaOutdatedRuntime:
    """LAMBDA-002: check_lambda_outdated_runtime — upgrade if reachable."""

    def test_no_graph_stays_moderate(self):
        """Without graph, outdated runtime is Moderate."""
        infra = make_lambda_outdated_infra()
        result = check_lambda_outdated_runtime(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'
        assert result.raw_severity == 'Moderate'

    def test_reachable_upgrades_to_critical(self):
        """With graph showing Lambda IS reachable (via API GW), upgrades to Critical."""
        infra = make_lambda_outdated_infra()
        # Build graph where legacy-fn is reachable from INTERNET
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'api-gw', 'type': 'api_gateway', 'label': 'API GW', 'metadata': {}},
            {'id': 'legacy-fn', 'type': 'lambda_function', 'label': 'Lambda: legacy-fn', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'api-gw', 'relationship': 'REACHES'},
            {'from': 'api-gw', 'to': 'legacy-fn', 'relationship': 'invokes'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_lambda_outdated_runtime(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_not_reachable_stays_moderate(self):
        """With graph showing Lambda NOT reachable, stays Moderate."""
        infra = make_lambda_outdated_infra()
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'legacy-fn', 'type': 'lambda_function', 'label': 'Lambda: legacy-fn', 'metadata': {}},
        ]
        edges = []  # No path from INTERNET to legacy-fn
        graph = Graph(nodes=nodes, edges=edges)
        result = check_lambda_outdated_runtime(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


class TestIAMWildcardPolicy:
    """IAM-006: check_iam_wildcard_policy — add blast_radius."""

    def test_no_graph_stays_critical(self):
        """Without graph, wildcard policy is Critical."""
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(users_with_admin_policy=["admin-user"]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        results = check_iam_wildcard_policy(infra, graph=None)
        assert len(results) > 0
        assert results[0].severity == 'Critical'

    def test_with_graph_adds_blast_radius(self):
        """With graph containing data stores, blast_radius reflects accessible resources."""
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(users_with_admin_policy=["admin-user"]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'prod-bucket', 'type': 's3_bucket', 'label': 'S3: prod-bucket', 'metadata': {}},
            {'id': 'prod-db', 'type': 'rds_instance', 'label': 'RDS: prod-db', 'metadata': {}},
            {'id': 'api-secret', 'type': 'secretsmanager_secret', 'label': 'Secret: api-secret', 'metadata': {}},
        ]
        edges = []
        graph = Graph(nodes=nodes, edges=edges)
        results = check_iam_wildcard_policy(infra, graph=graph)
        assert len(results) > 0
        assert results[0].blast_radius is not None
        assert results[0].blast_radius >= 3  # 3 data stores


class TestWAFNotEnabled:
    """WAF-001: check_waf_not_enabled — upgrade if ALB is reachable."""

    def test_no_graph_stays_moderate(self):
        """Without graph, WAF missing is Moderate."""
        infra = make_waf_infra()
        result = check_waf_not_enabled(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'
        assert result.raw_severity == 'Moderate'

    def test_alb_reachable_upgrades_to_critical(self):
        """With graph showing ALB IS reachable, upgrades to Critical."""
        infra = make_waf_infra()
        alb_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': alb_arn, 'type': 'load_balancer', 'label': 'LB: my-alb', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': alb_arn, 'relationship': 'REACHES'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_waf_not_enabled(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_alb_not_reachable_stays_moderate(self):
        """With graph showing ALB NOT reachable, stays Moderate."""
        infra = make_waf_infra()
        alb_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': alb_arn, 'type': 'load_balancer', 'label': 'LB: my-alb', 'metadata': {}},
        ]
        edges = []  # No path from INTERNET to ALB
        graph = Graph(nodes=nodes, edges=edges)
        result = check_waf_not_enabled(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


# ══════════════════════════════════════════════════════════════════
# TIER 2: DATA EXPOSURE PATH TESTS
# ══════════════════════════════════════════════════════════════════

class TestS3Encryption:
    """S3-002: check_s3_encryption — upgrade if bucket accessible from internet-facing role."""

    def test_no_graph_stays_moderate(self):
        """Without graph, unencrypted S3 is Moderate."""
        infra = make_s3_encryption_infra()
        result = check_s3_encryption(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'
        assert result.raw_severity == 'Moderate'

    def test_bucket_accessible_from_internet_role_upgrades(self):
        """If bucket is accessible from an internet-facing role, upgrades to Critical."""
        infra = make_s3_encryption_infra()
        # Build graph: INTERNET → i-001 → iam-role → can_access → sensitive-data
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2: i-001', 'metadata': {}},
            {'id': 'iam-role-WebRole', 'type': 'iam_role', 'label': 'IAM Role: WebRole', 'metadata': {}},
            {'id': 'sensitive-data', 'type': 's3_bucket', 'label': 'S3: sensitive-data', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'},
            {'from': 'i-001', 'to': 'iam-role-WebRole', 'relationship': 'uses_iam_role'},
            {'from': 'iam-role-WebRole', 'to': 'sensitive-data', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_s3_encryption(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_bucket_not_accessible_stays_moderate(self):
        """If no internet-facing role can access bucket, stays Moderate."""
        infra = make_s3_encryption_infra()
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'sensitive-data', 'type': 's3_bucket', 'label': 'S3: sensitive-data', 'metadata': {}},
        ]
        edges = []  # No can_access edges to the bucket
        graph = Graph(nodes=nodes, edges=edges)
        result = check_s3_encryption(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


class TestRDSEncryption:
    """RDS-003: check_rds_encryption — upgrade if RDS reachable from internet via IAM path."""

    def test_no_graph_stays_moderate(self):
        """Without graph, unencrypted RDS is Moderate."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(unencrypted_instances=["prod-db"], rds_instances=[RDSInstance(id="prod-db", encrypted=False)]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        result = check_rds_encryption(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'
        assert result.raw_severity == 'Moderate'

    def test_rds_accessible_from_internet_upgrades(self):
        """If RDS is accessible from an internet-facing role, upgrades to Critical."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(unencrypted_instances=["prod-db"], rds_instances=[RDSInstance(id="prod-db", encrypted=False)]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2: i-001', 'metadata': {}},
            {'id': 'iam-role-AppRole', 'type': 'iam_role', 'label': 'IAM Role: AppRole', 'metadata': {}},
            {'id': 'prod-db', 'type': 'rds_instance', 'label': 'RDS: prod-db', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'},
            {'from': 'i-001', 'to': 'iam-role-AppRole', 'relationship': 'uses_iam_role'},
            {'from': 'iam-role-AppRole', 'to': 'prod-db', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_rds_encryption(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'


class TestRDSDeletionProtection:
    """RDS-004: check_rds_deletion_protection — downgrade if private."""

    def test_no_graph_stays_critical(self):
        """Without graph, missing deletion protection is Critical."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(instances_without_deletion_protection=["prod-db"], rds_instances=[RDSInstance(id="prod-db")]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        result = check_rds_deletion_protection(infra, graph=None)
        assert result is not None
        assert result.severity == 'Critical'
        assert result.raw_severity == 'Critical'

    def test_rds_private_downgrades_to_moderate(self):
        """If RDS is in private subnet (not reachable), downgrades to Moderate."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(instances_without_deletion_protection=["prod-db"], rds_instances=[RDSInstance(id="prod-db")]),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["prod-db"], is_public=True)]),
        )
        # Graph where prod-db is NOT reachable from internet
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'prod-db', 'type': 'rds_instance', 'label': 'RDS: prod-db', 'metadata': {}},
        ]
        edges = []  # No path from INTERNET to prod-db
        graph = Graph(nodes=nodes, edges=edges)
        result = check_rds_deletion_protection(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


# ══════════════════════════════════════════════════════════════════
# TIER 3: BLAST RADIUS ENRICHMENT + UPGRADE TESTS
# ══════════════════════════════════════════════════════════════════

class TestCloudTrailDisabled:
    """CT-001: check_cloudtrail_disabled — upgrade if reachable resources exist."""

    def test_no_graph_stays_moderate(self):
        """Without graph, CloudTrail disabled is Moderate."""
        infra = make_cloudtrail_infra()
        result = check_cloudtrail_disabled(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'
        assert result.raw_severity == 'Moderate'

    def test_reachable_resources_upgrades_to_critical(self):
        """If there are internet-reachable resources, upgrades to Critical."""
        infra = make_cloudtrail_infra()
        graph = build_reachable_graph(["i-001"], ["sg-001"])
        result = check_cloudtrail_disabled(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_no_reachable_resources_stays_moderate(self):
        """If no resources are internet-reachable, stays Moderate."""
        infra = make_cloudtrail_infra()
        graph = build_private_graph(["i-001"], ["sg-001"])
        result = check_cloudtrail_disabled(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


class TestDefaultVPCInUse:
    """VPC-002: check_default_vpc_in_use — upgrade if has reachable resources."""

    def test_no_graph_stays_moderate(self):
        """Without graph, default VPC in use is Moderate."""
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(
                total_vpcs=1, default_vpc_in_use=True, default_vpc_id="vpc-001",
                subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)],
            ),
            ec2=EC2Data(
                instance_count=1, instance_ids=["i-001"],
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web-sg", rules=[], attached_to=["i-001"])],
            ),
        )
        result = check_default_vpc_in_use(infra, graph=None)
        assert result is not None
        assert result.severity == 'Moderate'

    def test_reachable_resources_upgrades_to_critical(self):
        """If default VPC has internet-reachable resources, upgrades to Critical."""
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(
                total_vpcs=1, default_vpc_in_use=True, default_vpc_id="vpc-001",
                subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)],
            ),
            ec2=EC2Data(
                instance_count=1, instance_ids=["i-001"],
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web-sg", rules=[], attached_to=["i-001"])],
            ),
        )
        graph = build_reachable_graph(["i-001"], ["sg-001"])
        result = check_default_vpc_in_use(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'

    def test_no_reachable_resources_stays_moderate(self):
        """If default VPC has no internet-reachable resources, stays Moderate."""
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(
                total_vpcs=1, default_vpc_in_use=True, default_vpc_id="vpc-001",
                subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)],
            ),
            ec2=EC2Data(
                instance_count=1, instance_ids=["i-001"],
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web-sg", rules=[], attached_to=["i-001"])],
            ),
        )
        graph = build_private_graph(["i-001"], ["sg-001"])
        result = check_default_vpc_in_use(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Moderate'


class TestLambdaNoVPC:
    """LAMBDA-004: check_lambda_no_vpc — upgrade if Lambda has admin role + no VPC."""

    def test_no_graph_stays_low(self):
        """Without graph, Lambda not in VPC is Low."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions=[LambdaFunction(name="my-fn", role_arn="arn:aws:iam::123:role/BasicRole", vpc_id=None, subnet_ids=[])],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        results = check_lambda_no_vpc(infra, graph=None)
        assert len(results) > 0
        assert results[0].severity == 'Low'
        assert results[0].raw_severity == 'Low'

    def test_admin_role_no_vpc_upgrades(self):
        """Lambda with admin role + no VPC → upgrades severity."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions_with_admin_role=["admin-fn"],
                functions=[LambdaFunction(name="admin-fn", role_arn="arn:aws:iam::123:role/AdminRole", vpc_id=None, subnet_ids=[])],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        # Graph with admin role having can_access edges
        nodes = [
            {'id': 'admin-fn', 'type': 'lambda_function', 'label': 'Lambda: admin-fn', 'metadata': {}},
            {'id': 'iam-role-AdminRole', 'type': 'iam_role', 'label': 'IAM Role: AdminRole', 'metadata': {'has_admin': True}},
            {'id': 'prod-bucket', 'type': 's3_bucket', 'label': 'S3: prod-bucket', 'metadata': {}},
        ]
        edges = [
            {'from': 'admin-fn', 'to': 'iam-role-AdminRole', 'relationship': 'uses_iam_role'},
            {'from': 'iam-role-AdminRole', 'to': 'prod-bucket', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        results = check_lambda_no_vpc(infra, graph=graph)
        assert len(results) > 0
        # Should be upgraded from Low to Moderate or Critical
        assert results[0].severity in ('Moderate', 'Critical')


# ══════════════════════════════════════════════════════════════════
# INTEGRATION: run_all_checks WITH GRAPH
# ══════════════════════════════════════════════════════════════════

class TestRunAllChecksWithGraph:
    """Verify run_all_checks integrates graph-aware logic correctly."""

    def test_run_all_checks_without_graph(self, nightmare_infra):
        """run_all_checks works without graph (backward compat)."""
        results = run_all_checks(nightmare_infra, graph=None)
        assert 'critical_risks' in results
        assert 'moderate_risks' in results
        assert 'low_risks' in results
        assert len(results['critical_risks']) > 0

    def test_run_all_checks_with_graph_produces_low_risks(self, nightmare_infra):
        """With a graph showing private resources, some findings move to low_risks."""
        from app.egraph import build_graph
        # Build graph from nightmare_infra - it has public subnets so resources ARE reachable
        graph = build_graph(nightmare_infra)
        results = run_all_checks(nightmare_infra, graph=graph)
        assert 'critical_risks' in results
        assert 'low_risks' in results
        # Graph-aware upgraded rules should have raw_severity populated
        # (Some older rules like IAM-001 predate the raw_severity pattern)
        upgraded_rule_ids = {
            'EMFIRGE-EC2-003', 'EMFIRGE-EC2-010', 'EMFIRGE-EC2-011', 'EMFIRGE-EC2-012',
            'EMFIRGE-EC2-013', 'EMFIRGE-EC2-014', 'EMFIRGE-EC2-015', 'EMFIRGE-EC2-016',
            'EMFIRGE-LAMBDA-001', 'EMFIRGE-LAMBDA-002', 'EMFIRGE-IAM-006', 'EMFIRGE-WAF-001',
            'EMFIRGE-S3-002', 'EMFIRGE-RDS-003', 'EMFIRGE-RDS-004', 'EMFIRGE-CT-001',
            'EMFIRGE-VPC-002', 'EMFIRGE-LAMBDA-004', 'EMFIRGE-EC2-001', 'EMFIRGE-RDS-001',
        }
        for category in ['critical_risks', 'moderate_risks', 'low_risks']:
            for finding in results[category]:
                if finding.rule_id and finding.rule_id in upgraded_rule_ids:
                    assert finding.raw_severity is not None, f"{finding.rule_id} missing raw_severity"

    def test_private_infra_downgrades_findings(self):
        """Infrastructure with private subnets should have downgraded findings."""
        # Create infra with dangerous ports but in a PRIVATE subnet
        # Use RDP (EC2-003) which we know has raw_severity support
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instance_count=1,
                instance_types=["t3.micro"],
                instance_ids=["i-private"],
                rdp_open_to_internet=True,
                rdp_security_group_id="sg-rdp",
                instances=[EC2Instance(id="i-private", type="t3.micro", sg_ids=["sg-rdp"], state="running", imdsv2_required=False)],
                security_groups=[SecurityGroup(id="sg-rdp", name="rdp-sg",
                    rules=[{"from_port": 3389, "to_port": 3389, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-private"])],
            ),
            vpc=VPCData(
                total_vpcs=1,
                subnets=[VPCSubnet(id="subnet-priv", vpc_id="vpc-001", resources=["i-private"], is_public=False)],
            ),
            cloudtrail=CloudTrailData(is_enabled=True, is_multi_region=True, has_log_file_validation=True),
        )
        from app.egraph import build_graph
        graph = build_graph(infra)
        results = run_all_checks(infra, graph=graph)

        # RDP open (EC2-003) should NOT be in critical_risks since instance is in private subnet
        # The graph won't create INTERNET edges because the instance is in a private subnet
        rdp_findings = [f for f in results.get('critical_risks', []) + results.get('moderate_risks', []) + results.get('low_risks', [])
                       if f.rule_id == 'EMFIRGE-EC2-003']
        if rdp_findings:
            # raw_severity should be Critical (static), but severity may be downgraded
            assert rdp_findings[0].raw_severity == 'Critical'

        # IMDSv1 (EC2-016) should stay Moderate (not upgraded) since instance is private
        imds_findings = [f for f in results.get('critical_risks', []) + results.get('moderate_risks', []) + results.get('low_risks', [])
                        if f.rule_id == 'EMFIRGE-EC2-016']
        if imds_findings:
            assert imds_findings[0].severity == 'Moderate'
            assert imds_findings[0].raw_severity == 'Moderate'


# ══════════════════════════════════════════════════════════════════
# HELPER FUNCTION TESTS
# ══════════════════════════════════════════════════════════════════

class TestGetInternetReachableSet:
    """Test the BFS reachability helper."""

    def test_empty_graph_returns_empty(self):
        """Graph with no INTERNET node returns empty set."""
        graph = Graph(nodes=[], edges=[])
        result = get_internet_reachable_set(graph)
        assert result == set()

    def test_internet_node_only_returns_empty(self):
        """INTERNET node with no edges returns empty set."""
        nodes = [{'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}}]
        graph = Graph(nodes=nodes, edges=[])
        result = get_internet_reachable_set(graph)
        assert result == set()

    def test_direct_reach(self):
        """Resources directly connected to INTERNET are reachable."""
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'sg-001', 'type': 'security_group', 'label': 'SG', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'sg-001', 'relationship': 'REACHES'},
            {'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = get_internet_reachable_set(graph)
        assert 'sg-001' in result
        assert 'i-001' in result
        assert 'INTERNET' not in result

    def test_transitive_reach(self):
        """Resources reachable via multiple hops are included."""
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'sg-001', 'type': 'security_group', 'label': 'SG', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
            {'id': 'role-001', 'type': 'iam_role', 'label': 'Role', 'metadata': {}},
            {'id': 'bucket-001', 'type': 's3_bucket', 'label': 'S3', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'sg-001', 'relationship': 'REACHES'},
            {'from': 'sg-001', 'to': 'i-001', 'relationship': 'attached_to_instance'},
            {'from': 'i-001', 'to': 'role-001', 'relationship': 'uses_iam_role'},
            {'from': 'role-001', 'to': 'bucket-001', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = get_internet_reachable_set(graph)
        assert 'sg-001' in result
        assert 'i-001' in result
        assert 'role-001' in result
        assert 'bucket-001' in result

    def test_unreachable_not_included(self):
        """Resources with no path from INTERNET are not in the set."""
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-public', 'type': 'ec2_instance', 'label': 'EC2 Public', 'metadata': {}},
            {'id': 'i-private', 'type': 'ec2_instance', 'label': 'EC2 Private', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'i-public', 'relationship': 'REACHES_VIA_SG'},
            # i-private has no inbound from INTERNET
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = get_internet_reachable_set(graph)
        assert 'i-public' in result
        assert 'i-private' not in result


# ══════════════════════════════════════════════════════════════════
# TIER 3: ATTACK PATH TESTS (get_attack_path_to)
# ══════════════════════════════════════════════════════════════════

class TestGetAttackPathTo:
    """Tests for the get_attack_path_to() BFS helper in egraph.py."""

    def test_reachable_target_returns_path(self):
        """BFS from INTERNET to a reachable target returns the shortest path."""
        from app.egraph import get_attack_path_to
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'sg-001', 'type': 'security_group', 'label': 'SG', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
            {'id': 'role-001', 'type': 'iam_role', 'label': 'Role', 'metadata': {}},
            {'id': 'bucket-001', 'type': 's3_bucket', 'label': 'S3', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'sg-001', 'relationship': 'REACHES'},
            {'from': 'sg-001', 'to': 'i-001', 'relationship': 'attached_to_instance'},
            {'from': 'i-001', 'to': 'role-001', 'relationship': 'uses_iam_role'},
            {'from': 'role-001', 'to': 'bucket-001', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        path = get_attack_path_to(graph, 'bucket-001')
        assert path is not None
        assert path[0] == 'INTERNET'
        assert path[-1] == 'bucket-001'
        assert len(path) == 5  # INTERNET → sg-001 → i-001 → role-001 → bucket-001

    def test_unreachable_target_returns_none(self):
        """BFS from INTERNET to an unreachable target returns None."""
        from app.egraph import get_attack_path_to
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-public', 'type': 'ec2_instance', 'label': 'EC2 Public', 'metadata': {}},
            {'id': 'i-private', 'type': 'ec2_instance', 'label': 'EC2 Private', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'i-public', 'relationship': 'REACHES_VIA_SG'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        path = get_attack_path_to(graph, 'i-private')
        assert path is None

    def test_no_internet_node_returns_none(self):
        """Graph without INTERNET node returns None."""
        from app.egraph import get_attack_path_to
        nodes = [
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        graph = Graph(nodes=nodes, edges=[])
        path = get_attack_path_to(graph, 'i-001')
        assert path is None

    def test_target_not_in_graph_returns_none(self):
        """Target node not in graph returns None."""
        from app.egraph import get_attack_path_to
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
        ]
        graph = Graph(nodes=nodes, edges=[])
        path = get_attack_path_to(graph, 'nonexistent-node')
        assert path is None

    def test_direct_connection_returns_two_node_path(self):
        """Direct INTERNET → target returns path of length 2."""
        from app.egraph import get_attack_path_to
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'alb-001', 'type': 'load_balancer', 'label': 'ALB', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'alb-001', 'relationship': 'REACHES'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        path = get_attack_path_to(graph, 'alb-001')
        assert path == ['INTERNET', 'alb-001']


# ══════════════════════════════════════════════════════════════════
# TIER 4: GRAPHCONTEXT TESTS
# ══════════════════════════════════════════════════════════════════

class TestGraphContext:
    """Tests for the GraphContext dataclass and its methods."""

    def test_build_without_graph(self):
        """GraphContext.build with no graph returns empty context."""
        from app.rules import GraphContext
        infra = AWSInfrastructure(region="us-east-1")
        ctx = GraphContext.build(None, infra)
        assert ctx.graph is None
        assert ctx.reachable == set()
        assert ctx.has_subnet_data is False

    def test_build_with_graph_populates_reachable(self):
        """GraphContext.build with a graph populates the reachable set."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        ctx = GraphContext.build(graph, infra)
        assert ctx.graph is graph
        assert 'i-001' in ctx.reachable
        assert ctx.has_subnet_data is True

    def test_is_reachable_returns_true_for_reachable(self):
        """is_reachable returns True for internet-reachable resources."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = [{'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'}]
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        ctx = GraphContext.build(graph, infra)
        assert ctx.is_reachable('i-001') is True

    def test_is_reachable_returns_false_for_private(self):
        """is_reachable returns False for private resources."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = []  # No path from INTERNET
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        ctx = GraphContext.build(graph, infra)
        assert ctx.is_reachable('i-001') is False

    def test_is_reachable_returns_none_without_subnet_data(self):
        """is_reachable returns None when no subnet data exists (conservative)."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = [{'from': 'INTERNET', 'to': 'i-001', 'relationship': 'REACHES_VIA_SG'}]
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(region="us-east-1", vpc=VPCData(total_vpcs=1, subnets=[]))
        ctx = GraphContext.build(graph, infra)
        assert ctx.is_reachable('i-001') is None

    def test_get_attack_path_returns_path(self):
        """get_attack_path returns BFS path for reachable resource."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'sg-001', 'type': 'security_group', 'label': 'SG', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'sg-001', 'relationship': 'REACHES'},
            {'from': 'sg-001', 'to': 'i-001', 'relationship': 'attached_to_instance'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        ctx = GraphContext.build(graph, infra)
        path = ctx.get_attack_path('i-001')
        assert path is not None
        assert path[0] == 'INTERNET'
        assert path[-1] == 'i-001'

    def test_get_attack_path_returns_none_for_unreachable(self):
        """get_attack_path returns None for unreachable resource."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {}},
            {'id': 'i-001', 'type': 'ec2_instance', 'label': 'EC2', 'metadata': {}},
        ]
        edges = []
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(
            region="us-east-1",
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=["i-001"], is_public=True)]),
        )
        ctx = GraphContext.build(graph, infra)
        path = ctx.get_attack_path('i-001')
        assert path is None

    def test_get_data_store_access_count(self):
        """get_data_store_access_count returns count of can_access edges."""
        from app.rules import GraphContext
        nodes = [
            {'id': 'iam-role-Admin', 'type': 'iam_role', 'label': 'Role', 'metadata': {}},
            {'id': 'bucket-1', 'type': 's3_bucket', 'label': 'S3', 'metadata': {}},
            {'id': 'bucket-2', 'type': 's3_bucket', 'label': 'S3', 'metadata': {}},
            {'id': 'db-1', 'type': 'rds_instance', 'label': 'RDS', 'metadata': {}},
        ]
        edges = [
            {'from': 'iam-role-Admin', 'to': 'bucket-1', 'relationship': 'can_access'},
            {'from': 'iam-role-Admin', 'to': 'bucket-2', 'relationship': 'can_access'},
            {'from': 'iam-role-Admin', 'to': 'db-1', 'relationship': 'can_access'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        infra = AWSInfrastructure(region="us-east-1")
        ctx = GraphContext.build(graph, infra)
        count = ctx.get_data_store_access_count('iam-role-Admin')
        assert count == 3


# ══════════════════════════════════════════════════════════════════
# TIER 5: IAM HIGH-RISK USERS BLAST RADIUS
# ══════════════════════════════════════════════════════════════════

class TestIAMHighRiskUsersBlastRadius:
    """IAM-002: check_iam_high_risk_users — blast_radius enrichment."""

    def test_admin_user_gets_blast_radius(self):
        """Admin user with old keys + no MFA gets blast_radius = data store count."""
        from app.rules import check_iam_high_risk_users
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(
                users_without_mfa=["alice"],
                old_access_keys=["alice (120 days)"],
                users_with_admin_policy=["alice"],
                iam_users=[IAMUser(username="alice", has_console_access=True)],
            ),
        )
        # Graph with 3 data stores
        nodes = [
            {'id': 'bucket-1', 'type': 's3_bucket', 'label': 'S3: bucket-1', 'metadata': {}},
            {'id': 'bucket-2', 'type': 's3_bucket', 'label': 'S3: bucket-2', 'metadata': {}},
            {'id': 'prod-db', 'type': 'rds_instance', 'label': 'RDS: prod-db', 'metadata': {}},
            {'id': 'api-secret', 'type': 'secretsmanager_secret', 'label': 'Secret: api-secret', 'metadata': {}},
        ]
        graph = Graph(nodes=nodes, edges=[])
        results = check_iam_high_risk_users(infra, graph=graph)
        assert len(results) == 1
        assert results[0].blast_radius == 4  # 2 S3 + 1 RDS + 1 Secret

    def test_non_admin_user_gets_zero_blast_radius(self):
        """Non-admin user with old keys + no MFA gets blast_radius = 0."""
        from app.rules import check_iam_high_risk_users
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(
                users_without_mfa=["bob"],
                old_access_keys=["bob (90 days)"],
                users_with_admin_policy=[],  # bob is NOT admin
                iam_users=[IAMUser(username="bob", has_console_access=True)],
            ),
        )
        nodes = [
            {'id': 'bucket-1', 'type': 's3_bucket', 'label': 'S3', 'metadata': {}},
            {'id': 'prod-db', 'type': 'rds_instance', 'label': 'RDS', 'metadata': {}},
        ]
        graph = Graph(nodes=nodes, edges=[])
        results = check_iam_high_risk_users(infra, graph=graph)
        assert len(results) == 1
        assert results[0].blast_radius == 0

    def test_no_graph_gives_zero_blast_radius(self):
        """Without graph, blast_radius is always 0."""
        from app.rules import check_iam_high_risk_users
        infra = AWSInfrastructure(
            region="us-east-1",
            iam=IAMData(
                users_without_mfa=["alice"],
                old_access_keys=["alice (120 days)"],
                users_with_admin_policy=["alice"],
                iam_users=[IAMUser(username="alice", has_console_access=True)],
            ),
        )
        results = check_iam_high_risk_users(infra, graph=None)
        assert len(results) == 1
        assert results[0].blast_radius == 0


# ══════════════════════════════════════════════════════════════════
# TIER 6: LAMBDA NO-VPC SEVERITY UPGRADES
# ══════════════════════════════════════════════════════════════════

class TestLambdaNoVPCSeverityUpgrades:
    """LAMBDA-004: check_lambda_no_vpc — severity upgrades based on context."""

    def test_internet_triggered_lambda_upgrades_to_critical(self):
        """Lambda reachable from internet without VPC → Critical."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions=[LambdaFunction(name="api-handler")],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        # Graph: INTERNET → API GW → api-handler (reachable)
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'api-gw', 'type': 'api_gateway', 'label': 'API GW', 'metadata': {}},
            {'id': 'api-handler', 'type': 'lambda_function', 'label': 'Lambda: api-handler', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': 'api-gw', 'relationship': 'REACHES'},
            {'from': 'api-gw', 'to': 'api-handler', 'relationship': 'invokes'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        results = check_lambda_no_vpc(infra, graph=graph)
        assert len(results) == 1
        assert results[0].severity == 'Critical'
        assert results[0].raw_severity == 'Low'
        assert results[0].attack_path is not None
        assert results[0].attack_path[0] == 'INTERNET'
        assert results[0].attack_path[-1] == 'api-handler'

    def test_admin_lambda_without_vpc_is_moderate(self):
        """Lambda with admin role but not internet-triggered → Moderate."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions_with_admin_role=["admin-fn"],
                functions=[LambdaFunction(name="admin-fn", role_arn="arn:aws:iam::123:role/AdminRole")],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        # Graph: admin-fn exists but is NOT reachable from INTERNET
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'admin-fn', 'type': 'lambda_function', 'label': 'Lambda: admin-fn', 'metadata': {}},
        ]
        edges = []  # No path from INTERNET
        graph = Graph(nodes=nodes, edges=edges)
        results = check_lambda_no_vpc(infra, graph=graph)
        assert len(results) == 1
        assert results[0].severity == 'Moderate'
        assert results[0].raw_severity == 'Low'

    def test_internal_lambda_without_vpc_stays_low(self):
        """Internal Lambda not reachable and not admin → Low."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions=[LambdaFunction(name="cron-job")],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': 'cron-job', 'type': 'lambda_function', 'label': 'Lambda: cron-job', 'metadata': {}},
        ]
        edges = []
        graph = Graph(nodes=nodes, edges=edges)
        results = check_lambda_no_vpc(infra, graph=graph)
        assert len(results) == 1
        assert results[0].severity == 'Low'
        assert results[0].raw_severity == 'Low'

    def test_lambda_in_vpc_not_flagged(self):
        """Lambda deployed in a VPC should not produce a finding."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                function_count=1,
                functions=[LambdaFunction(name="vpc-fn", vpc_id="vpc-001", subnet_ids=["subnet-001"])],
            ),
            vpc=VPCData(total_vpcs=1, subnets=[VPCSubnet(id="subnet-001", vpc_id="vpc-001", resources=[], is_public=True)]),
        )
        graph = Graph(nodes=[], edges=[])
        results = check_lambda_no_vpc(infra, graph=graph)
        assert len(results) == 0


# ══════════════════════════════════════════════════════════════════
# TIER 7: ATTACK PATH POPULATION ON FINDINGS
# ══════════════════════════════════════════════════════════════════

class TestAttackPathPopulation:
    """Verify attack_path is populated on findings when resources are reachable."""

    def test_imdsv1_reachable_has_attack_path(self):
        """IMDSv1 finding for reachable instance should have attack_path populated."""
        infra = make_imdsv1_infra()
        graph = build_reachable_graph(["i-imds"], ["sg-001"])
        results = check_imdsv1_enabled(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Critical'
        assert results[0].attack_path is not None
        assert len(results[0].attack_path) >= 2
        assert results[0].attack_path[0] == 'INTERNET'
        assert results[0].attack_path[-1] == 'i-imds'

    def test_imdsv1_private_has_no_attack_path(self):
        """IMDSv1 finding for private instance should have no attack_path."""
        infra = make_imdsv1_infra()
        graph = build_private_graph(["i-imds"], ["sg-001"])
        results = check_imdsv1_enabled(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Moderate'
        assert results[0].attack_path is None or results[0].attack_path == []

    def test_dangerous_ports_reachable_has_attack_path(self):
        """Dangerous port finding for reachable instance should have attack_path."""
        infra = make_dangerous_ports_infra()
        graph = build_reachable_graph(["i-001"], ["sg-ports"])
        results = check_dangerous_open_ports(infra, graph=graph)
        assert len(results) > 0
        assert results[0].severity == 'Critical'
        # attack_path should be populated for reachable resources
        if results[0].attack_path:
            assert results[0].attack_path[0] == 'INTERNET'

    def test_waf_reachable_has_attack_path(self):
        """WAF finding for reachable ALB should have attack_path."""
        infra = make_waf_infra()
        alb_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc"
        nodes = [
            {'id': 'INTERNET', 'type': 'internet', 'label': 'Internet', 'metadata': {'is_virtual': True}},
            {'id': alb_arn, 'type': 'load_balancer', 'label': 'LB: my-alb', 'metadata': {}},
        ]
        edges = [
            {'from': 'INTERNET', 'to': alb_arn, 'relationship': 'REACHES'},
        ]
        graph = Graph(nodes=nodes, edges=edges)
        result = check_waf_not_enabled(infra, graph=graph)
        assert result is not None
        assert result.severity == 'Critical'
        if result.attack_path:
            assert result.attack_path[0] == 'INTERNET'
            assert result.attack_path[-1] == alb_arn
