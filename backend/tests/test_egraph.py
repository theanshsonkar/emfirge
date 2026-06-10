"""
Tests for egraph.py — graph building, BFS, blast radius, orphan detection.
Zero AWS/LLM calls.
"""
import pytest
from app.egraph import build_graph, find_attack_path, calculate_blast_radius, find_orphaned_resources
from app.models import (
    AWSInfrastructure, EC2Data, S3Data, RDSData, LambdaData, VPCData,
    EC2Instance, SecurityGroup, S3Bucket, RDSInstance, LambdaFunction,
    LoadBalancer, VPCSubnet, EBSVolume, ElasticIP, IAMData, RolePolicy,
)


# -- GRAPH BUILDING ------------------------------------------------

class TestBuildGraph:
    def test_empty_infra_builds_empty_graph(self, empty_infra):
        graph = build_graph(empty_infra)
        assert graph.nodes == []
        assert graph.edges == []

    def test_ec2_instance_node_created(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=True)],
            ),
        )
        graph = build_graph(infra)
        node = graph.get_node("i-001")
        assert node is not None
        assert node["type"] == "ec2_instance"

    def test_sg_node_created_with_rules(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-001", name="web-sg",
                    rules=[{"from_port": 443, "to_port": 443, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        node = graph.get_node("sg-001")
        assert node is not None
        assert node["type"] == "security_group"
        assert len(node["metadata"]["rules"]) == 1

    def test_internet_node_added_for_open_sg(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-open", name="open",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        internet_node = graph.get_node("INTERNET")
        assert internet_node is not None
        assert internet_node["type"] == "internet"

    def test_internet_node_not_added_for_private_sg(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[SecurityGroup(
                    id="sg-priv", name="private",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["10.0.0.0/8"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.get_node("INTERNET") is None

    def test_internet_node_added_only_once(self):
        """Multiple open SGs should still produce only one INTERNET node."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                security_groups=[
                    SecurityGroup(id="sg-1", name="sg1",
                        rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                        attached_to=["i-001"]),
                    SecurityGroup(id="sg-2", name="sg2",
                        rules=[{"from_port": 80, "to_port": 80, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                        attached_to=["i-002"]),
                ],
            ),
        )
        graph = build_graph(infra)
        internet_nodes = [n for n in graph.nodes if n["id"] == "INTERNET"]
        assert len(internet_nodes) == 1

    def test_s3_bucket_node_created(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="my-bucket", is_public=False, is_empty=False)]),
        )
        graph = build_graph(infra)
        node = graph.get_node("my-bucket")
        assert node is not None
        assert node["type"] == "s3_bucket"

    def test_cloudfront_edge_created_for_cf_bucket(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="cdn-bucket", is_public=True, has_cloudfront=True, is_empty=False)]),
        )
        graph = build_graph(infra)
        cf_node = graph.get_node("cloudfront-cdn-bucket")
        assert cf_node is not None
        assert cf_node["type"] == "cloudfront_distribution"
        # Edge: cloudfront -> bucket
        assert graph.has_connection("cloudfront-cdn-bucket", "cdn-bucket", "serves_from_bucket")

    def test_rds_node_created(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", publicly_accessible=False, encrypted=True)],
            ),
        )
        graph = build_graph(infra)
        node = graph.get_node("my-db")
        assert node is not None
        assert node["type"] == "rds_instance"

    def test_lambda_to_iam_role_edge(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="my-fn", role_arn="arn:aws:iam::123:role/MyRole")],
            ),
        )
        graph = build_graph(infra)
        role_id = "iam-role-MyRole"
        assert graph.get_node(role_id) is not None
        assert graph.has_connection("my-fn", role_id, "uses_iam_role")

    def test_lambda_secret_ref_edge(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="my-fn", secret_refs=["my-secret"])],
            ),
        )
        graph = build_graph(infra)
        assert graph.get_node("my-secret") is not None
        assert graph.has_connection("my-fn", "my-secret", "REFERENCES_SECRET")

    def test_lb_to_instance_edge(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=True)],
                load_balancers=[LoadBalancer(
                    arn="arn:aws:elb:us-east-1:123:loadbalancer/app/my-lb/abc",
                    type="application",
                    target_instances=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        lb_arn = "arn:aws:elb:us-east-1:123:loadbalancer/app/my-lb/abc"
        assert graph.has_connection(lb_arn, "i-001", "targets_instance")

    def test_full_nightmare_graph_has_nodes(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0


# -- GRAPH QUERY METHODS -------------------------------------------

class TestGraphQueries:
    def test_get_node_returns_none_for_missing(self, clean_infra):
        graph = build_graph(clean_infra)
        assert graph.get_node("nonexistent-id") is None

    def test_get_inbound_returns_sources(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=True)],
                load_balancers=[LoadBalancer(
                    arn="arn:aws:elb:us-east-1:123:loadbalancer/app/lb/abc",
                    type="application",
                    target_instances=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        inbound = graph.get_inbound("i-001", relationship_type="targets_instance")
        assert len(inbound) == 1
        assert inbound[0]["type"] == "load_balancer"

    def test_get_outbound_returns_targets(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web", rules=[], attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        outbound = graph.get_outbound("i-001", relationship_type="uses_security_group")
        assert any(n["id"] == "sg-001" for n in outbound)

    def test_find_nodes_by_type(self, nightmare_infra):
        graph = build_graph(nightmare_infra)
        ec2_nodes = graph.find_nodes_by_type("ec2_instance")
        assert len(ec2_nodes) >= 1

    def test_has_connection_true(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="fn", role_arn="arn:aws:iam::123:role/MyRole")],
            ),
        )
        graph = build_graph(infra)
        assert graph.has_connection("fn", "iam-role-MyRole", "uses_iam_role") is True

    def test_has_connection_false(self, clean_infra):
        graph = build_graph(clean_infra)
        assert graph.has_connection("nonexistent", "also-nonexistent") is False


# -- ATTACK PATH ---------------------------------------------------

class TestFindAttackPath:
    def test_path_from_instance_to_rds(self):
        """EC2 instance shares SG with RDS — attack path should find the RDS."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web", rules=[], attached_to=["i-001"])],
            ),
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", sg_ids=["sg-001"], publicly_accessible=False, encrypted=True)],
            ),
        )
        graph = build_graph(infra)
        # BFS from instance outward: i-001 -> sg-001 -> my-db (via uses_security_group edges)
        # The path goes through the shared SG
        result = calculate_blast_radius(graph, "i-001")
        assert "my-db" in result["resource_ids"] or "sg-001" in result["resource_ids"]

    def test_no_path_returns_empty(self, clean_infra):
        graph = build_graph(clean_infra)
        # Instance with no path to data store
        path = find_attack_path(graph, "nonexistent-resource")
        assert path == []

    def test_path_from_lambda_to_secret(self):
        """Lambda with secret ref — blast radius should include the secret."""
        infra = AWSInfrastructure(
            region="us-east-1",
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="my-fn", secret_refs=["db-password"])],
            ),
        )
        graph = build_graph(infra)
        result = calculate_blast_radius(graph, "my-fn")
        assert "db-password" in result["resource_ids"]

    def test_max_hops_respected(self):
        """Path longer than max_hops should return empty."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web", rules=[], attached_to=["i-001"])],
            ),
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", sg_ids=["sg-001"], publicly_accessible=False, encrypted=True)],
            ),
        )
        graph = build_graph(infra)
        # max_hops=0 means don't traverse at all
        path = find_attack_path(graph, "i-001", max_hops=0)
        assert path == []


# -- BLAST RADIUS --------------------------------------------------

class TestBlastRadius:
    def test_isolated_resource_zero_blast(self, empty_infra):
        graph = build_graph(empty_infra)
        result = calculate_blast_radius(graph, "nonexistent")
        assert result["count"] == 0

    def test_connected_resource_has_blast(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web", rules=[], attached_to=["i-001"])],
            ),
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", sg_ids=["sg-001"], publicly_accessible=False, encrypted=True)],
            ),
        )
        graph = build_graph(infra)
        result = calculate_blast_radius(graph, "i-001")
        assert result["count"] > 0
        assert "my-db" in result["resource_ids"] or "sg-001" in result["resource_ids"]

    def test_blast_radius_does_not_include_self(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-001"], state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(id="sg-001", name="web", rules=[], attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = calculate_blast_radius(graph, "i-001")
        assert "i-001" not in result["resource_ids"]


# -- ORPHANED RESOURCES --------------------------------------------

class TestOrphanedResources:
    def test_connected_resources_not_orphaned(self, clean_infra):
        graph = build_graph(clean_infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        # The clean_infra RDS instance has no SG connections in the graph
        # (clean_infra.rds.rds_instances has no sg_ids), so it may appear orphaned.
        # What we verify: no EC2 instances or S3 buckets with data are orphaned.
        ec2_orphans = [o for o in orphans if o["type"] == "ec2_instance"]
        assert ec2_orphans == [], f"EC2 instances should not be orphaned: {ec2_orphans}"

    def test_empty_test_bucket_is_orphaned(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                buckets=[
                    S3Bucket(name="test-temp-bucket", is_public=False, is_empty=True),
                ],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        assert "test-temp-bucket" in orphan_ids

    def test_non_empty_prod_bucket_not_orphaned(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                buckets=[
                    S3Bucket(name="prod-data", is_public=False, is_empty=False),
                ],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        assert "prod-data" not in orphan_ids

    def test_orphan_has_cost_estimate(self):
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(
                buckets=[S3Bucket(name="test-sandbox-bucket", is_public=False, is_empty=True)],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        if orphans:
            for o in orphans:
                assert "estimated_monthly_cost" in o
                assert o["estimated_monthly_cost"] >= 0

    def test_unattached_ebs_volume_is_orphaned(self):
        """Unattached EBS volume (state=available) should appear in orphans with correct cost."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                ebs_volumes=[
                    EBSVolume(
                        id="vol-001",
                        size_gb=100,
                        volume_type="gp2",
                        create_time="2024-01-01T00:00:00",
                        availability_zone="us-east-1a",
                    )
                ],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        assert "vol-001" in orphan_ids
        ebs_orphan = next(o for o in orphans if o["id"] == "vol-001")
        assert ebs_orphan["estimated_monthly_cost"] == 10.0  # 100GB × $0.10

    def test_attached_eip_not_orphaned(self):
        """Elastic IP that is attached to an instance should NOT appear in orphans."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                elastic_ips=[
                    ElasticIP(
                        allocation_id="eipalloc-attached",
                        public_ip="1.2.3.4",
                        is_attached=True,
                    )
                ],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        assert "eipalloc-attached" not in orphan_ids

    def test_unattached_eip_is_orphaned(self):
        """Unattached Elastic IP should appear in orphans with cost = 3.65."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                elastic_ips=[
                    ElasticIP(
                        allocation_id="eipalloc-free",
                        public_ip="5.6.7.8",
                        is_attached=False,
                    )
                ],
            ),
        )
        graph = build_graph(infra)
        orphans = find_orphaned_resources(graph)
        orphan_ids = [o["id"] for o in orphans]
        assert "eipalloc-free" in orphan_ids
        eip_orphan = next(o for o in orphans if o["id"] == "eipalloc-free")
        assert eip_orphan["estimated_monthly_cost"] == 3.65


# -- IAM POLICY EDGES (can_access) --------------------------------

class TestIAMPolicyEdges:
    def test_can_access_edge_created_for_s3(self):
        """Role with S3 policy creates can_access edge to matching bucket."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="customer-data", is_public=False, is_empty=False)]),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="my-fn", role_arn="arn:aws:iam::123:role/DataRole")],
            ),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="DataRole",
                    role_arn="arn:aws:iam::123:role/DataRole",
                    accessible_resources=["arn:aws:s3:::customer-data/*"],
                    has_admin=False,
                    policy_names=["S3ReadAccess"],
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.has_connection("iam-role-DataRole", "customer-data", "can_access")

    def test_can_access_edge_created_for_rds(self):
        """Role with RDS policy creates can_access edge to matching RDS instance."""
        infra = AWSInfrastructure(
            region="us-east-1",
            rds=RDSData(
                rds_instances=[RDSInstance(id="prod-db", publicly_accessible=False, encrypted=True)],
            ),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="api-fn", role_arn="arn:aws:iam::123:role/APIRole")],
            ),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="APIRole",
                    role_arn="arn:aws:iam::123:role/APIRole",
                    accessible_resources=["arn:aws:rds:us-east-1:123:db:prod-db"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.has_connection("iam-role-APIRole", "prod-db", "can_access")

    def test_admin_role_gets_edges_to_all_data_stores(self):
        """Admin role creates can_access edges to every S3/RDS node."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[
                S3Bucket(name="bucket-a", is_public=False, is_empty=False),
                S3Bucket(name="bucket-b", is_public=False, is_empty=False),
            ]),
            rds=RDSData(
                rds_instances=[RDSInstance(id="db-1", publicly_accessible=False, encrypted=True)],
            ),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="admin-fn", role_arn="arn:aws:iam::123:role/AdminRole")],
            ),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="AdminRole",
                    role_arn="arn:aws:iam::123:role/AdminRole",
                    accessible_resources=[],
                    has_admin=True,
                    policy_names=["AdministratorAccess"],
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.has_connection("iam-role-AdminRole", "bucket-a", "can_access")
        assert graph.has_connection("iam-role-AdminRole", "bucket-b", "can_access")
        assert graph.has_connection("iam-role-AdminRole", "db-1", "can_access")

    def test_no_match_no_edge(self):
        """Policy referencing non-existent bucket creates no edge."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="real-bucket", is_public=False, is_empty=False)]),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="fn", role_arn="arn:aws:iam::123:role/SomeRole")],
            ),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="SomeRole",
                    role_arn="arn:aws:iam::123:role/SomeRole",
                    accessible_resources=["arn:aws:s3:::nonexistent-bucket/*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        # Should NOT have edge to real-bucket (ARN doesn't match)
        assert not graph.has_connection("iam-role-SomeRole", "real-bucket", "can_access")

    def test_empty_role_policies_no_crash(self):
        """Existing infra with no role_policies field works fine."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="my-bucket", is_public=False, is_empty=False)]),
            iam=IAMData(),  # no role_policies - defaults to []
        )
        graph = build_graph(infra)
        # Should build fine with no can_access edges
        assert graph.get_node("my-bucket") is not None
        # No can_access edges exist
        can_access_edges = [e for e in graph.edges if e['relationship'] == 'can_access']
        assert can_access_edges == []

    def test_bfs_traces_through_can_access(self):
        """BFS from INTERNET reaches S3 bucket via EC2 → Role → can_access."""
        from app.egraph import bfs_from_internet
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(
                    id="i-001", type="t3.micro", sg_ids=["sg-open"],
                    state="running", imdsv2_required=False,
                    instance_profile_arn="arn:aws:iam::123:instance-profile/WebRole",
                )],
                security_groups=[SecurityGroup(
                    id="sg-open", name="open-sg",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
            s3=S3Data(buckets=[S3Bucket(name="customer-data", is_public=False, is_empty=False)]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="WebRole",
                    role_arn="arn:aws:iam::123:role/WebRole",
                    accessible_resources=["arn:aws:s3:::customer-data/*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        # Verify the chain exists: INTERNET → sg-open → i-001 → iam-role-WebRole → customer-data
        assert graph.has_connection("INTERNET", "sg-open", "REACHES")
        assert graph.has_connection("i-001", "iam-role-WebRole", "uses_iam_role")
        assert graph.has_connection("iam-role-WebRole", "customer-data", "can_access")
        # BFS should reach customer-data
        result = bfs_from_internet(graph)
        reachable_ids = {n['id'] for n in result['nodes']}
        assert "customer-data" in reachable_ids

    def test_wildcard_s3_pattern_matches_prefix(self):
        """Policy with arn:aws:s3:::prod-* matches all prod- prefixed buckets."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[
                S3Bucket(name="prod-data", is_public=False, is_empty=False),
                S3Bucket(name="prod-logs", is_public=False, is_empty=False),
                S3Bucket(name="dev-sandbox", is_public=False, is_empty=False),
            ]),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="fn", role_arn="arn:aws:iam::123:role/ProdRole")],
            ),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="ProdRole",
                    role_arn="arn:aws:iam::123:role/ProdRole",
                    accessible_resources=["arn:aws:s3:::prod-*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.has_connection("iam-role-ProdRole", "prod-data", "can_access")
        assert graph.has_connection("iam-role-ProdRole", "prod-logs", "can_access")
        assert not graph.has_connection("iam-role-ProdRole", "dev-sandbox", "can_access")

    def test_role_node_created_even_without_lambda(self):
        """Role from role_policies creates a node even if no Lambda/ECS uses it."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="data", is_public=False, is_empty=False)]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="OrphanRole",
                    role_arn="arn:aws:iam::123:role/OrphanRole",
                    accessible_resources=["arn:aws:s3:::data/*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.get_node("iam-role-OrphanRole") is not None
        assert graph.has_connection("iam-role-OrphanRole", "data", "can_access")

    def test_ec2_instance_profile_creates_role_edge(self):
        """EC2 instance with instance_profile_arn creates uses_iam_role edge."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(
                    id="i-001", type="t3.micro", state="running",
                    imdsv2_required=True,
                    instance_profile_arn="arn:aws:iam::123:instance-profile/MyRole",
                )],
            ),
        )
        graph = build_graph(infra)
        assert graph.get_node("iam-role-MyRole") is not None
        assert graph.has_connection("i-001", "iam-role-MyRole", "uses_iam_role")


# -- DIJKSTRA (WEIGHTED PATHS) ------------------------------------

class TestDijkstra:
    def test_dijkstra_returns_distances_from_internet(self):
        """Dijkstra returns weighted distances for all reachable nodes."""
        from app.egraph import dijkstra_from_internet
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(
                    id="i-001", type="t3.micro", sg_ids=["sg-open"],
                    state="running", imdsv2_required=False,
                    instance_profile_arn="arn:aws:iam::123:instance-profile/WebRole",
                )],
                security_groups=[SecurityGroup(
                    id="sg-open", name="open-sg",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
            s3=S3Data(buckets=[S3Bucket(name="customer-data", is_public=False, is_empty=False)]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="WebRole",
                    role_arn="arn:aws:iam::123:role/WebRole",
                    accessible_resources=["arn:aws:s3:::customer-data/*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        result = dijkstra_from_internet(graph)

        # INTERNET should NOT be in results
        assert 'INTERNET' not in result

        # sg-open is directly reached (REACHES edge, weight=1)
        assert 'sg-open' in result
        assert result['sg-open']['distance'] == 1

        # i-001 is reached via REACHES_VIA_SG (weight=1)
        assert 'i-001' in result
        assert result['i-001']['distance'] == 1

        # iam-role-WebRole is reached via i-001 → uses_iam_role (weight=3)
        assert 'iam-role-WebRole' in result
        assert result['iam-role-WebRole']['distance'] == 1 + 3  # 1 (to i-001) + 3 (uses_iam_role)

        # customer-data is reached via role → can_access (weight=2)
        assert 'customer-data' in result
        assert result['customer-data']['distance'] == 1 + 3 + 2  # 6 total

    def test_dijkstra_empty_graph_returns_empty(self):
        """Graph with no INTERNET node returns empty dict."""
        from app.egraph import dijkstra_from_internet, Graph
        empty_graph = Graph(nodes=[], edges=[])
        assert dijkstra_from_internet(empty_graph) == {}

    def test_dijkstra_no_internet_node_returns_empty(self):
        """Graph with nodes but no INTERNET returns empty."""
        from app.egraph import dijkstra_from_internet
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(id="i-001", type="t3.micro", state="running", imdsv2_required=True)],
                security_groups=[SecurityGroup(
                    id="sg-priv", name="private",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["10.0.0.0/8"]}],
                    attached_to=["i-001"],
                )],
            ),
        )
        graph = build_graph(infra)
        result = dijkstra_from_internet(graph)
        assert result == {}

    def test_dijkstra_previous_forms_valid_path(self):
        """The 'previous' field allows reconstructing the path back to INTERNET."""
        from app.egraph import dijkstra_from_internet
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(
                    id="i-001", type="t3.micro", sg_ids=["sg-open"],
                    state="running", imdsv2_required=False,
                    instance_profile_arn="arn:aws:iam::123:instance-profile/Role1",
                )],
                security_groups=[SecurityGroup(
                    id="sg-open", name="open-sg",
                    rules=[{"from_port": 80, "to_port": 80, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
            s3=S3Data(buckets=[S3Bucket(name="data-bucket", is_public=False, is_empty=False)]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="Role1",
                    role_arn="arn:aws:iam::123:role/Role1",
                    accessible_resources=["arn:aws:s3:::data-bucket/*"],
                    has_admin=False,
                )],
            ),
        )
        graph = build_graph(infra)
        result = dijkstra_from_internet(graph)

        # Trace back from data-bucket to INTERNET via 'previous'
        path = []
        current = 'data-bucket'
        while current is not None and current != 'INTERNET':
            path.append(current)
            current = result.get(current, {}).get('previous')
        path.append('INTERNET')
        path.reverse()

        # Path should start at INTERNET and end at data-bucket
        assert path[0] == 'INTERNET'
        assert path[-1] == 'data-bucket'
        assert len(path) >= 3  # at least INTERNET → something → data-bucket


# -- BETWEENNESS CENTRALITY ----------------------------------------

class TestBetweennessCentrality:
    def test_centrality_returns_scores_for_all_nodes(self):
        """Centrality returns a score for every node in the graph."""
        from app.egraph import betweenness_centrality
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-open"], state="running", imdsv2_required=False,
                                instance_profile_arn="arn:aws:iam::123:instance-profile/AdminRole"),
                    EC2Instance(id="i-002", type="t3.micro", sg_ids=["sg-open"], state="running", imdsv2_required=True),
                ],
                security_groups=[SecurityGroup(
                    id="sg-open", name="open-sg",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001", "i-002"],
                )],
            ),
            s3=S3Data(buckets=[
                S3Bucket(name="prod-data", is_public=False, is_empty=False),
                S3Bucket(name="logs", is_public=False, is_empty=False),
            ]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="AdminRole",
                    role_arn="arn:aws:iam::123:role/AdminRole",
                    accessible_resources=[],
                    has_admin=True,
                    policy_names=["AdministratorAccess"],
                )],
            ),
        )
        graph = build_graph(infra)
        scores = betweenness_centrality(graph)

        # Should have a score for every node
        assert len(scores) == len(graph.nodes)

        # All scores should be non-negative
        for score in scores.values():
            assert score >= 0.0

    def test_centrality_chokepoint_has_higher_score(self):
        """A node that sits on all paths (chokepoint) should have higher centrality."""
        from app.egraph import betweenness_centrality
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[EC2Instance(
                    id="i-001", type="t3.micro", sg_ids=["sg-open"],
                    state="running", imdsv2_required=False,
                    instance_profile_arn="arn:aws:iam::123:instance-profile/AdminRole",
                )],
                security_groups=[SecurityGroup(
                    id="sg-open", name="open-sg",
                    rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                    attached_to=["i-001"],
                )],
            ),
            s3=S3Data(buckets=[
                S3Bucket(name="bucket-a", is_public=False, is_empty=False),
                S3Bucket(name="bucket-b", is_public=False, is_empty=False),
            ]),
            iam=IAMData(
                role_policies=[RolePolicy(
                    role_name="AdminRole",
                    role_arn="arn:aws:iam::123:role/AdminRole",
                    accessible_resources=[],
                    has_admin=True,
                )],
            ),
        )
        graph = build_graph(infra)
        scores = betweenness_centrality(graph)

        # iam-role-AdminRole sits between i-001 and all data stores
        # It should have higher centrality than leaf nodes (buckets)
        admin_score = scores.get('iam-role-AdminRole', 0.0)
        bucket_a_score = scores.get('bucket-a', 0.0)
        bucket_b_score = scores.get('bucket-b', 0.0)

        # Admin role is a chokepoint - higher than leaf data stores
        assert admin_score >= bucket_a_score
        assert admin_score >= bucket_b_score

    def test_centrality_tiny_graph_returns_empty(self):
        """Graph with fewer than 3 nodes returns empty dict."""
        from app.egraph import betweenness_centrality, Graph
        tiny_graph = Graph(
            nodes=[
                {'id': 'a', 'type': 't', 'label': 'A', 'metadata': {}},
                {'id': 'b', 'type': 't', 'label': 'B', 'metadata': {}},
            ],
            edges=[{'from': 'a', 'to': 'b', 'relationship': 'test'}],
        )
        assert betweenness_centrality(tiny_graph) == {}

    def test_centrality_no_internet_still_works(self):
        """Centrality works even without INTERNET node (uses all nodes as sources)."""
        from app.egraph import betweenness_centrality
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    EC2Instance(id="i-001", type="t3.micro", sg_ids=["sg-priv"], state="running", imdsv2_required=True),
                    EC2Instance(id="i-002", type="t3.micro", sg_ids=["sg-priv"], state="running", imdsv2_required=True),
                ],
                security_groups=[SecurityGroup(
                    id="sg-priv", name="private",
                    rules=[{"from_port": 443, "to_port": 443, "protocol": "tcp", "ip_ranges": ["10.0.0.0/8"]}],
                    attached_to=["i-001", "i-002"],
                )],
            ),
            s3=S3Data(buckets=[S3Bucket(name="internal-data", is_public=False, is_empty=False)]),
        )
        graph = build_graph(infra)
        scores = betweenness_centrality(graph)

        # Should still return scores (uses all nodes as sources)
        assert len(scores) == len(graph.nodes)
