"""Focused coverage for the provider-neutral typed graph models."""
from app.egraph import Edge, Graph, Node, NodeCategory, RelationshipType, build_graph, internet_ingress
from app.models import (
    AWSInfrastructure,
    EC2Data,
    EC2Instance,
    NACLEntry,
    NetworkACL,
    Route,
    RouteTable,
    SecurityGroup,
    VPCData,
    VPCPeeringConnection,
    VPCSubnet,
    VPNGateway,
    InterfaceEndpoint,
)
from app.rules import run_all_checks


def test_internet_ingress_public_ip_gate_is_ec2_only_for_non_ec2_resources():
    resource = Node(
        id="lb-public-ingress",
        resource_type="load_balancer",
        label="Public load balancer",
        base={"subnet_id": "subnet-public"},
    )
    security_group = Node(
        id="sg-public-ingress",
        resource_type="security_group",
        label="Open security group",
        base={"rules": [{
            "from_port": 443,
            "to_port": 443,
            "protocol": "tcp",
            "ip_ranges": ["0.0.0.0/0"],
        }]},
    )
    graph = Graph(nodes=[resource, security_group], edges=[])

    evidence = internet_ingress(resource, "subnet-public", [security_group], graph)

    assert "has_public_ip" not in resource.base
    assert evidence
    assert evidence[0]["ports"] == [443, 443]



def test_collect_vpc_skips_malformed_peering_record_and_keeps_later_valid_one(monkeypatch):
    from app import aws_collector

    class FakeEC2:
        def describe_vpc_peering_connections(self):
            return {
                "VpcPeeringConnections": [
                    {"RequesterVpcInfo": []},
                    {
                        "VpcPeeringConnectionId": "pcx-valid",
                        "RequesterVpcInfo": {"VpcId": "vpc-requester"},
                        "AccepterVpcInfo": {"VpcId": "vpc-accepter"},
                        "Status": {"Code": "active"},
                    },
                ]
            }

        def describe_vpcs(self):
            return {"Vpcs": []}

        def describe_internet_gateways(self):
            return {"InternetGateways": []}

        def describe_nat_gateways(self, **kwargs):
            return {"NatGateways": []}

        def describe_route_tables(self):
            return {"RouteTables": []}

        def describe_subnets(self):
            return {"Subnets": []}

        def describe_network_acls(self):
            return {"NetworkAcls": []}

        def describe_vpc_endpoints(self):
            return {"VpcEndpoints": []}

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeEC2())

    result = aws_collector.collect_vpc("key", "secret", "token", "us-east-1", [])

    assert [connection.id for connection in result.vpc_peering_connections] == ["pcx-valid"]
    assert result.vpc_peering_connections[0].status == "active"




def test_collect_vpc_populates_network_service_relationships(monkeypatch):
    from app import aws_collector

    class FakeEC2:
        def describe_vpc_peering_connections(self):
            return {"VpcPeeringConnections": []}

        def describe_vpcs(self):
            return {"Vpcs": []}

        def describe_transit_gateway_vpc_attachments(self):
            return {"TransitGatewayVpcAttachments": [{
                "TransitGatewayAttachmentId": "tgw-attach-1",
                "TransitGatewayId": "tgw-1",
                "VpcId": "vpc-1",
                "State": "available",
            }]}

        def describe_vpn_gateways(self):
            return {"VpnGateways": [{
                "VpnGatewayId": "vgw-1",
                "State": "available",
                "VpcAttachments": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}],
            }]}

        def describe_vpc_endpoints(self):
            return {"VpcEndpoints": [
                {"VpcEndpointId": "vpce-s3", "VpcId": "vpc-1",
                 "VpcEndpointType": "Gateway", "ServiceName": "com.amazonaws.us-east-1.s3"},
                {"VpcEndpointId": "vpce-ssm", "VpcId": "vpc-1",
                 "VpcEndpointType": "Interface", "ServiceName": "com.amazonaws.us-east-1.ssm"},
                {"VpcEndpointId": "vpce-dynamodb", "VpcId": "vpc-1",
                 "VpcEndpointType": "Gateway", "ServiceName": "com.amazonaws.us-east-1.dynamodb"},
            ]}

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeEC2())
    result = aws_collector.collect_vpc("key", "secret", "token", "us-east-1", [])

    assert result.transit_gateway_attachments[0].id == "tgw-attach-1"
    assert [(gateway.id, gateway.vpc_id) for gateway in result.vpn_gateways] == [
        ("vgw-1", "vpc-1"), ("vgw-1", "vpc-2")
    ]
    assert result.interface_endpoints[0].service_name.endswith("ssm")
    assert result.missing_s3_endpoint is False
    assert result.missing_dynamodb_endpoint is False


def test_collect_vpc_new_network_calls_fail_safe(monkeypatch):
    from app import aws_collector
    from botocore.exceptions import ClientError

    class FakeEC2:
        def describe_vpcs(self):
            return {"Vpcs": []}

        def _denied(self):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "Describe",
            )

        describe_transit_gateway_vpc_attachments = _denied
        describe_vpn_gateways = _denied
        describe_vpc_endpoints = _denied

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeEC2())
    result = aws_collector.collect_vpc("key", "secret", "token", "us-east-1", [])

    assert result.transit_gateway_attachments == []
    assert result.vpn_gateways == []
    assert result.interface_endpoints == []
    assert result.missing_s3_endpoint is False
    assert result.missing_dynamodb_endpoint is False
def test_build_graph_is_deterministic_and_typed(nightmare_infra):
    first = build_graph(nightmare_infra)
    second = build_graph(nightmare_infra)

    assert first.to_dict() == second.to_dict()
    assert all(isinstance(node, Node) for node in first.nodes)
    assert all(isinstance(edge, Edge) for edge in first.edges)

    legacy = first.to_dict()
    assert all({"id", "type", "label", "metadata"}.issubset(node) for node in legacy["nodes"])
    assert all({"from", "to", "relationship"}.issubset(edge) for edge in legacy["edges"])



class _FakeEC2CollectorClient:
    def __init__(self, instance, security_groups=None):
        self.instance = instance
        self.security_groups = security_groups or []

    def describe_instances(self):
        return {"Reservations": [{"Instances": [self.instance]}]}

    def describe_security_groups(self):
        return {"SecurityGroups": self.security_groups}

    def describe_load_balancers(self):
        return {"LoadBalancers": []}

    def describe_auto_scaling_groups(self):
        return {"AutoScalingGroups": []}

    def describe_volumes(self, **kwargs):
        return {"Volumes": []}

    def describe_addresses(self):
        return {"Addresses": []}


def _collect_instance_with_public_ip_signal(monkeypatch, instance):
    from app import aws_collector

    monkeypatch.setattr(
        aws_collector.boto3,
        "client",
        lambda *args, **kwargs: _FakeEC2CollectorClient(instance),
    )
    return aws_collector.collect_ec2("key", "secret", "token", "us-east-1", []).instances[0]


def _base_instance(**fields):
    instance = {
        "InstanceId": "i-public-ip-test",
        "State": {"Name": "running"},
        "InstanceType": "t3.micro",
        "SecurityGroups": [],
    }
    instance.update(fields)
    return instance


def test_collect_ec2_public_ip_from_top_level_field(monkeypatch):
    instance = _collect_instance_with_public_ip_signal(
        monkeypatch,
        _base_instance(PublicIpAddress="198.51.100.10"),
    )

    assert instance.has_public_ip is True


def test_collect_ec2_public_ip_from_network_interface_association(monkeypatch):
    instance = _collect_instance_with_public_ip_signal(
        monkeypatch,
        _base_instance(
            NetworkInterfaces=[{"Association": {"PublicIp": "198.51.100.11"}}],
        ),
    )

    assert instance.has_public_ip is True


def test_collect_ec2_public_ip_absent_is_false(monkeypatch):
    instance = _collect_instance_with_public_ip_signal(
        monkeypatch,
        _base_instance(NetworkInterfaces=[{"NetworkInterfaceId": "eni-private"}]),
    )

    assert instance.has_public_ip is False


def test_collect_ec2_malformed_public_ip_signal_is_unknown(monkeypatch):
    instance = _collect_instance_with_public_ip_signal(
        monkeypatch,
        _base_instance(NetworkInterfaces=["malformed-interface"]),
    )

    assert instance.has_public_ip is None




def test_collect_ec2_security_group_rule_references(monkeypatch):
    from app import aws_collector

    instance = _base_instance(SecurityGroups=[{"GroupId": "sg-app"}])
    security_groups = [{
        "GroupId": "sg-app",
        "GroupName": "app",
        "IpPermissions": [
            {
                "FromPort": 443,
                "ToPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [],
                "UserIdGroupPairs": [{"GroupId": "sg-source"}],
            },
            {
                "FromPort": 80,
                "ToPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            },
        ],
        "IpPermissionsEgress": [
            {
                "FromPort": 5432,
                "ToPort": 5432,
                "IpProtocol": "tcp",
                "IpRanges": [],
                "UserIdGroupPairs": [{"GroupId": "sg-destination"}],
            },
            {
                "FromPort": 443,
                "ToPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            },
        ],
    }]
    monkeypatch.setattr(
        aws_collector.boto3,
        "client",
        lambda *args, **kwargs: _FakeEC2CollectorClient(instance, security_groups),
    )

    result = aws_collector.collect_ec2("key", "secret", "token", "us-east-1", [])

    assert [rule["source_sg_ids"] for rule in result.security_groups[0].rules] == [
        ["sg-source"],
        [],
    ]
    assert [rule["dest_sg_ids"] for rule in result.security_groups[0].egress_rules] == [
        ["sg-destination"],
        [],
    ]
def test_node_and_edge_legacy_shims_and_metadata_copy():

    metadata = {"state": "running", "nested": {"source": "fixture"}}
    node = Node(id="i-1", type="ec2_instance", label="EC2", metadata=metadata)
    metadata["state"] = "mutated"

    assert node["id"] == "i-1"
    assert node["type"] == "ec2_instance"
    assert node.category is NodeCategory.COMPUTE
    assert node["metadata"].get("state") == "running"
    assert node.get("missing", "fallback") == "fallback"
    assert "metadata" in node

    edge = Edge(**{"from": "a", "to": "b", "relationship": "REACHES"})
    assert edge["from"] == edge.src == "a"
    assert edge["to"] == edge.dst == "b"
    assert edge["relationship"] == RelationshipType.REACHES.value
    assert edge.weight == 1
    assert "relationship" in edge


def test_network_truth_graph_preserves_routes_and_avoids_missing_targets():
    routes = [
        Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id="igw-test"),
        Route(destination_cidr="10.0.0.0/16", target_type="local", target_id="local"),
        Route(destination_cidr="10.0.0.0/8", target_type="nat_gateway", target_id="nat-test"),
        Route(destination_cidr="172.16.0.0/16", target_type="vpc_peering", target_id="pcx-missing"),
    ]
    route_table = RouteTable(
        id="rtb-test",
        vpc_id="vpc-test",
        is_main=True,
        associated_subnet_ids=["subnet-test"],
        routes=routes,
    )
    infrastructure = AWSInfrastructure(
        region="us-east-1",
        vpc=VPCData(
            subnets=[VPCSubnet(
                id="subnet-test",
                vpc_id="vpc-test",
                cidr="10.0.1.0/24",
            )],
            route_tables=[route_table],
            internet_gateways=["igw-test"],
            nat_gateways=["nat-test"],
        ),
    )

    first = build_graph(infrastructure)
    second = build_graph(infrastructure)

    expected_nodes = {
        "rtb-test": ("route_table", NodeCategory.NETWORK),
        "igw-test": ("internet_gateway", NodeCategory.NETWORK_BOUNDARY),
        "nat-test": ("nat_gateway", NodeCategory.NETWORK),
        "subnet-test": ("vpc_subnet", NodeCategory.NETWORK),
    }
    for node_id, (resource_type, category) in expected_nodes.items():
        node = first.get_node(node_id)
        assert node is not None
        assert node.resource_type == resource_type
        assert node.category is category

    route_table_node = first.get_node("rtb-test")
    assert route_table_node.base == {
        "vpc_id": "vpc-test",
        "is_main": True,
        "routes": [route.model_dump() for route in routes],
    }
    assert first.get_node("subnet-test").base["cidr"] == "10.0.1.0/24"

    edge_tuples = {(edge.src, edge.dst, edge.relationship.value) for edge in first.edges}
    assert ("subnet-test", "rtb-test", "associated_with") in edge_tuples
    assert ("rtb-test", "igw-test", "routes_to") in edge_tuples
    assert ("rtb-test", "nat-test", "routes_to") in edge_tuples
    assert not any("pcx-missing" in (edge.src, edge.dst) for edge in first.edges)

    node_ids = {node.id for node in first.nodes}
    routing_edges = [
        edge for edge in first.edges
        if edge.relationship.value in {"associated_with", "routes_to"}
    ]
    assert all(edge.src in node_ids and edge.dst in node_ids for edge in routing_edges)

    assert [node.id for node in first.nodes] == [node.id for node in second.nodes]
    assert [
        (edge.src, edge.dst, edge.relationship.value) for edge in first.edges
    ] == [
        (edge.src, edge.dst, edge.relationship.value) for edge in second.edges

    ]
    assert [
        (node.id, node.base) for node in first.nodes
    ] == [
        (node.id, node.base) for node in second.nodes
    ]

    assert RouteTable(id="rtb-default", vpc_id="vpc-test").associated_subnet_ids == []
    assert RouteTable(id="rtb-default", vpc_id="vpc-test").routes == []
    assert routes[0].destination_cidr == "0.0.0.0/0"
    assert routes[0].target_type == "internet_gateway"
    assert routes[0].target_id == "igw-test"


def test_empty_metadata_and_unknown_relationship_are_safe():
    node = Node(id="x", resource_type="vendor_resource", label="X")
    edge = Edge(src="x", dst="y", relationship="provider-specific-link")

    assert node.metadata == {}
    assert node.category is NodeCategory.OTHER
    assert edge.relationship is RelationshipType.UNKNOWN
    assert edge["relationship"] == "UNKNOWN"
    assert edge.weight == 3


def test_rules_regression_with_typed_graph():
    infrastructure = AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instances=[EC2Instance(id="i-001", type="t3.micro", state="running")],
            security_groups=[SecurityGroup(
                id="sg-open",
                name="open",
                rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
                attached_to=["i-001"],
            )],
        ),
    )
    graph = build_graph(infrastructure)
    expected = run_all_checks(infrastructure)
    actual = run_all_checks(infrastructure, graph)

    finding_fields = ("rule_id", "resource_id", "severity", "category", "issue")
    for key in ("critical_risks", "moderate_risks", "low_risks", "cost_findings"):
        assert [
            tuple(getattr(finding, field, getattr(finding, "message", None)) for field in finding_fields)
            for finding in actual[key]
        ] == [
            tuple(getattr(finding, field, getattr(finding, "message", None)) for field in finding_fields)
            for finding in expected[key]
        ]
    assert graph.get_node("sg-open")["metadata"].get("rules_count") == 1


def test_network_truth_graph_includes_egress_and_nacl_protection():
    allow_entry = NACLEntry(
        rule_number=100,
        protocol="6",
        rule_action="allow",
        egress=False,
        cidr_block="10.0.0.0/16",
        port_from=443,
        port_to=443,
    )
    deny_entry = NACLEntry(
        rule_number=200,
        protocol="-1",
        rule_action="deny",
        egress=True,
        cidr_block="0.0.0.0/0",
    )
    infrastructure = AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instances=[EC2Instance(
                id="i-network-truth",
                type="t3.micro",
                state="running",
                subnet_id="subnet-existing",
                sg_ids=["sg-network-truth"],
            )],
            security_groups=[SecurityGroup(
                id="sg-network-truth",
                name="network-truth",
                rules=[],
                egress_rules=[{
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "ip_ranges": ["10.0.0.0/16"],
                }],
            )],
        ),
        vpc=VPCData(
            subnets=[VPCSubnet(
                id="subnet-existing",
                vpc_id="vpc-network-truth",
                cidr="10.0.1.0/24",
            )],
            nacls=[
                NetworkACL(
                    id="acl-network-truth",
                    vpc_id="vpc-network-truth",
                    associated_subnet_ids=["subnet-existing"],
                    entries=[allow_entry, deny_entry],
                ),
                NetworkACL(
                    id="acl-missing-subnet",
                    vpc_id="vpc-network-truth",
                    associated_subnet_ids=["subnet-does-not-exist"],
                ),
            ],
        ),
    )

    first = build_graph(infrastructure)
    second = build_graph(infrastructure)

    sg_node = first.get_node("sg-network-truth")
    assert sg_node is not None
    assert sg_node.base["egress_rules"] == [{
        "from_port": 443,
        "to_port": 443,
        "protocol": "tcp",
        "ip_ranges": ["10.0.0.0/16"],
    }]

    nacl_node = first.get_node("acl-network-truth")
    assert nacl_node is not None
    assert nacl_node.resource_type == "network_acl"
    assert nacl_node.category is NodeCategory.NETWORK_BOUNDARY
    assert nacl_node.base == {
        "entries": [allow_entry.model_dump(), deny_entry.model_dump()],
        "is_default": False,
        "vpc_id": "vpc-network-truth",
    }

    edge_tuples = {(edge.src, edge.dst, edge.relationship.value) for edge in first.edges}
    assert ("subnet-existing", "acl-network-truth", "protected_by") in edge_tuples
    assert not any(
        edge.dst == "acl-missing-subnet" and edge.relationship is RelationshipType.PROTECTED_BY
        for edge in first.edges
    )
    assert first.to_dict() == second.to_dict()


def test_network_truth_graph_includes_vpc_peering_connections_without_dangling_edges():
    route_table = RouteTable(
        id="rtb-peering",
        vpc_id="vpc-local",
        associated_subnet_ids=["subnet-local"],
        routes=[
            Route(destination_cidr="10.1.0.0/16", target_type="vpc_peering", target_id="pcx-active"),
            Route(destination_cidr="10.2.0.0/16", target_type="vpc_peering", target_id="pcx-unknown"),
        ],
    )
    infrastructure = AWSInfrastructure(
        region="us-east-1",
        vpc=VPCData(
            subnets=[VPCSubnet(id="subnet-local", vpc_id="vpc-local")],
            route_tables=[route_table],
            vpc_peering_connections=[VPCPeeringConnection(
                id="pcx-active",
                requester_vpc_id="vpc-local",
                accepter_vpc_id="vpc-remote",
                status="active",
            )],
        ),
    )

    first = build_graph(infrastructure)
    second = build_graph(infrastructure)

    peering_node = first.get_node("pcx-active")
    assert peering_node is not None
    assert peering_node.resource_type == "vpc_peering_connection"
    assert peering_node.category is NodeCategory.NETWORK
    assert peering_node.base["status"] == "active"

    local_vpc = first.get_node("vpc-local")
    remote_vpc = first.get_node("vpc-remote")
    assert local_vpc is not None
    assert remote_vpc is not None
    assert local_vpc.base.get("collected") is not False
    assert remote_vpc.base == {"collected": False}

    edge_tuples = {(edge.src, edge.dst, edge.relationship.value) for edge in first.edges}
    assert ("pcx-active", "vpc-local", "peered_with") in edge_tuples
    assert ("pcx-active", "vpc-remote", "peered_with") in edge_tuples
    assert ("rtb-peering", "pcx-active", "routes_to") in edge_tuples
    assert not any("pcx-unknown" in (edge.src, edge.dst) for edge in first.edges)

    node_ids = {node.id for node in first.nodes}
    assert all(edge.src in node_ids and edge.dst in node_ids for edge in first.edges)
    assert first.to_dict() == second.to_dict()


# ── INTERNET REACHABILITY ADVERSARIAL CASES ───────────────────────

def _network_truth_infra(*, route_table=None, nacls=None, has_public_ip=None):
    """Build a minimal real-model EC2/VPC fixture for public build_graph tests."""
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instances=[EC2Instance(
                id="i-adversarial",
                type="t3.micro",
                state="running",
                subnet_id="subnet-adversarial",
                sg_ids=["sg-adversarial"],
                has_public_ip=has_public_ip,
            )],
            security_groups=[SecurityGroup(
                id="sg-adversarial",
                name="adversarial-open-ssh",
                rules=[{
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "ip_ranges": ["0.0.0.0/0"],
                }],
                attached_to=["i-adversarial"],
            )],
        ),
        vpc=VPCData(
            subnets=[VPCSubnet(id="subnet-adversarial", vpc_id="vpc-adversarial")],
            route_tables=[] if route_table is None else [route_table],
            nacls=nacls or [],
        ),
    )


def _instance_reach_edge(graph):
    return next(
        (
            edge for edge in graph.edges
            if edge.src == "INTERNET" and edge.dst == "i-adversarial"
        ),
        None,
    )


def test_igw_route_nacl_allow_open_ssh_with_no_public_ip_has_no_instance_edge():
    graph = build_graph(_network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(NACLEntry(
            rule_number=100, protocol="6", rule_action="allow", egress=False,
            cidr_block="0.0.0.0/0", port_from=22, port_to=22,
        )),
        has_public_ip=False,
    ))

    assert _instance_reach_edge(graph) is None


def test_igw_route_nacl_allow_open_ssh_with_public_ip_is_high_confidence():
    graph = build_graph(_network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(NACLEntry(
            rule_number=100, protocol="6", rule_action="allow", egress=False,
            cidr_block="0.0.0.0/0", port_from=22, port_to=22,
        )),
        has_public_ip=True,
    ))
    edge = _instance_reach_edge(graph)

    assert edge is not None
    assert edge.attrs["confidence"] == "high"
    assert "public IP" in edge.attrs["reason"]


def test_igw_route_nacl_allow_open_ssh_with_unknown_public_ip_is_assumed():
    graph = build_graph(_network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(NACLEntry(
            rule_number=100, protocol="6", rule_action="allow", egress=False,
            cidr_block="0.0.0.0/0", port_from=22, port_to=22,
        )),
        has_public_ip=None,
    ))
    edge = _instance_reach_edge(graph)

    assert edge is not None
    assert edge.attrs["confidence"] == "assumed"
    assert "public IP assumed" in edge.attrs["reason"]


def _route_table(target_type):
    return RouteTable(
        id="rtb-adversarial",
        vpc_id="vpc-adversarial",
        associated_subnet_ids=["subnet-adversarial"],
        routes=[Route(
            destination_cidr="0.0.0.0/0",
            target_type=target_type,
            target_id=f"{target_type}-adversarial",
        )],
    )


def _allow_ssh_nacl(*entries):
    return [NetworkACL(
        id="acl-adversarial",
        vpc_id="vpc-adversarial",
        associated_subnet_ids=["subnet-adversarial"],
        entries=list(entries),
    )]


def test_nat_only_default_route_and_open_ssh_have_no_internet_edge():
    graph = build_graph(_network_truth_infra(route_table=_route_table("nat_gateway")))

    assert _instance_reach_edge(graph) is None


def test_igw_route_nacl_allow_open_ssh_has_high_confidence_evidence():
    graph = build_graph(_network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(NACLEntry(
            rule_number=100,
            protocol="6",
            rule_action="allow",
            egress=False,
            cidr_block="0.0.0.0/0",
            port_from=22,
            port_to=22,
        )),
        has_public_ip=True,
    ))
    edge = _instance_reach_edge(graph)

    assert edge is not None
    assert edge.attrs["confidence"] == "high"
    assert all(term in edge.attrs["reason"] for term in ("IGW", "SG", "NACL"))


def test_lower_number_nacl_deny_blocks_igw_route_open_ssh():
    graph = build_graph(_network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(
            NACLEntry(
                rule_number=100,
                protocol="6",
                rule_action="deny",
                egress=False,
                cidr_block="0.0.0.0/0",
                port_from=22,
                port_to=22,
            ),
            NACLEntry(
                rule_number=200,
                protocol="6",
                rule_action="allow",
                egress=False,
                cidr_block="0.0.0.0/0",
                port_from=22,
                port_to=22,
            ),
        ),
    ))

    assert _instance_reach_edge(graph) is None


def test_igw_route_without_nacl_assumes_open_ingress():
    graph = build_graph(_network_truth_infra(route_table=_route_table("internet_gateway")))
    edge = _instance_reach_edge(graph)

    assert edge is not None
    assert edge.attrs["confidence"] == "assumed"


def test_missing_route_table_assumes_public_ingress():
    graph = build_graph(_network_truth_infra())
    edge = _instance_reach_edge(graph)

    assert edge is not None
    assert edge.attrs["confidence"] == "assumed"


def test_repeated_build_graph_is_deterministic_including_edge_attrs():
    infrastructure = _network_truth_infra(
        route_table=_route_table("internet_gateway"),
        nacls=_allow_ssh_nacl(NACLEntry(
            rule_number=100,
            protocol="6",
            rule_action="allow",
            egress=False,
            cidr_block="0.0.0.0/0",
            port_from=22,
            port_to=22,
        )),
        has_public_ip=True,
    )
    first = build_graph(infrastructure)
    second = build_graph(infrastructure)

    assert [edge.model_dump() for edge in first.edges] == [edge.model_dump() for edge in second.edges]
    assert _instance_reach_edge(first).attrs == _instance_reach_edge(second).attrs


def test_non_ec2_security_group_remains_internet_reachable_without_public_ip_gate():
    infrastructure = AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            security_groups=[SecurityGroup(
                id="sg-api-style",
                name="api-style",
                rules=[{
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "ip_ranges": ["0.0.0.0/0"],
                }],
                attached_to=["api-gateway-1"],
            )],
        ),
    )

    graph = build_graph(infrastructure)

    assert any(
        edge.src == "INTERNET"
        and edge.dst == "sg-api-style"
        and edge.relationship is RelationshipType.REACHES
        for edge in graph.edges
    )



def _internal_pair_infra(*, same_vpc=True, egress=True, ingress_source="sg-a",
                         route_tables=None, nacls=None, tgw=False,
                         peering=None, extra_ingress=False, vpn=False,
                         interface_endpoint=False):
    """Build a minimal real-model topology for internal reachability tests."""
    vpc_a, vpc_b = "vpc-a", "vpc-a" if same_vpc else "vpc-b"
    subnet_a, subnet_b = "subnet-a", "subnet-b"
    sg_a, sg_b = "sg-a", "sg-b"
    ingress_rules = [{
        "from_port": 5432, "to_port": 5432, "protocol": "tcp",
        "source_sg_ids": [ingress_source], "ip_ranges": [],
    }]
    if extra_ingress:
        ingress_rules.append({
            "from_port": 5432, "to_port": 5432, "protocol": "tcp",
            "source_sg_ids": [], "ip_ranges": ["10.0.0.0/16"],
        })
    egress_rules = [{
        "from_port": 5432, "to_port": 5432, "protocol": "tcp",
        "dest_sg_ids": [sg_b], "ip_ranges": [],
    }] if egress else []
    default_nacls = [
        NetworkACL(id="acl-a", vpc_id=vpc_a, associated_subnet_ids=[subnet_a],
                   entries=[NACLEntry(rule_number=100, protocol="tcp", rule_action="allow",
                                      egress=True, cidr_block="0.0.0.0/0",
                                      port_from=5432, port_to=5432),
                            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow",
                                      egress=False, cidr_block="0.0.0.0/0",
                                      port_from=5432, port_to=5432)]),
        NetworkACL(id="acl-b", vpc_id=vpc_b, associated_subnet_ids=[subnet_b],
                   entries=[NACLEntry(rule_number=100, protocol="tcp", rule_action="allow",
                                      egress=True, cidr_block="0.0.0.0/0",
                                      port_from=5432, port_to=5432),
                            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow",
                                      egress=False, cidr_block="0.0.0.0/0",
                                      port_from=5432, port_to=5432)]),
    ]
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(
            instances=[
                EC2Instance(id="i-a", type="t3.micro", sg_ids=[sg_a],
                            subnet_id=subnet_a, state="running"),
                EC2Instance(id="i-b", type="t3.micro", sg_ids=[sg_b],
                            subnet_id=subnet_b, state="running"),
            ],
            security_groups=[
                SecurityGroup(id=sg_a, name="a", egress_rules=egress_rules,
                              attached_to=["i-a"]),
                SecurityGroup(id=sg_b, name="b", rules=ingress_rules,
                              attached_to=["i-b"]),
            ],
        ),
        vpc=VPCData(
            subnets=[
                VPCSubnet(id=subnet_a, vpc_id=vpc_a, cidr="10.0.1.0/24"),
                VPCSubnet(id=subnet_b, vpc_id=vpc_b, cidr="10.0.2.0/24"),
            ],
            route_tables=route_tables or [],
            nacls=nacls if nacls is not None else default_nacls,
            transit_gateway_attachments=([
                {"id": "tgw-attachment-a", "transit_gateway_id": "tgw-1",
                 "vpc_id": vpc_a, "state": "available"},
            ] if tgw else []),
            vpn_gateways=([VPNGateway(id="vgw-a", vpc_id=vpc_a, state="available")]
                          if vpn else []),
            interface_endpoints=([InterfaceEndpoint(id="vpce-a", vpc_id=vpc_a,
                                                     service_name="com.amazonaws.us-east-1.ssm")]
                                 if interface_endpoint else []),
            vpc_peering_connections=([peering] if peering else []),
        ),
    )


def _can_reach_edges(graph):
    return [edge for edge in graph.edges if edge.relationship.value == "can_reach"]


def test_internal_reachability_same_vpc_sg_allow_high_5432():
    edges = _can_reach_edges(build_graph(_internal_pair_infra()))
    edge = next(edge for edge in edges if (edge.src, edge.dst) == ("i-a", "i-b"))
    assert edge.attrs["ports"] == [5432, 5432]
    assert edge.attrs["confidence"] == "high"
    assert edge.attrs["flagged"] is False




def test_internal_reachability_cross_vpc_vpn_only_has_no_path():
    edges = _can_reach_edges(build_graph(_internal_pair_infra(same_vpc=False, vpn=True)))
    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_cross_vpc_interface_endpoint_only_has_no_path():
    edges = _can_reach_edges(build_graph(
        _internal_pair_infra(same_vpc=False, interface_endpoint=True)))
    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_ingress_mismatch_has_no_edge():
    edges = _can_reach_edges(build_graph(_internal_pair_infra(ingress_source="sg-other")))
    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_cross_vpc_without_path_has_no_edge():
    edges = _can_reach_edges(build_graph(_internal_pair_infra(same_vpc=False)))
    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_cross_vpc_tgw_is_flagged_assumed():
    edge = next(edge for edge in _can_reach_edges(
        build_graph(_internal_pair_infra(same_vpc=False, tgw=True)))
        if (edge.src, edge.dst) == ("i-a", "i-b"))
    assert edge.attrs["confidence"] == "assumed"
    assert edge.attrs["flagged"] is True
    assert "Transit Gateway" in edge.attrs["reason"]


def test_internal_reachability_active_peering_matching_routes_is_high():
    peering = VPCPeeringConnection(id="pcx-1", requester_vpc_id="vpc-a",
                                   accepter_vpc_id="vpc-b", status="active")
    route_tables = [
        RouteTable(id="rt-a", vpc_id="vpc-a", associated_subnet_ids=["subnet-a"],
                   routes=[Route(destination_cidr="10.0.2.0/24",
                                 target_type="vpc_peering", target_id="pcx-1")]),
        RouteTable(id="rt-b", vpc_id="vpc-b", associated_subnet_ids=["subnet-b"],
                   routes=[Route(destination_cidr="10.0.1.0/24",
                                 target_type="vpc_peering", target_id="pcx-1")]),
    ]
    edge = next(edge for edge in _can_reach_edges(build_graph(_internal_pair_infra(
        same_vpc=False, route_tables=route_tables, peering=peering)))
        if (edge.src, edge.dst) == ("i-a", "i-b"))
    assert edge.attrs["confidence"] == "high"
    assert edge.attrs["flagged"] is False


def test_internal_reachability_lower_number_nacl_deny_blocks():
    acl = NetworkACL(
        id="acl-b", vpc_id="vpc-a", associated_subnet_ids=["subnet-b"],
        entries=[
            NACLEntry(rule_number=90, protocol="tcp", rule_action="deny", egress=False,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
        ],
    )
    edges = _can_reach_edges(build_graph(_internal_pair_infra(nacls=[acl])))
    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_outbound_nacl_deny_on_source_subnet_blocks():
    acl_a = NetworkACL(
        id="acl-a", vpc_id="vpc-a", associated_subnet_ids=["subnet-a"],
        entries=[
            NACLEntry(rule_number=100, protocol="tcp", rule_action="deny", egress=True,
                      cidr_block="10.0.2.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=110, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.2.0/24", port_from=5432, port_to=5432),
        ],
    )
    acl_b = NetworkACL(
        id="acl-b", vpc_id="vpc-a", associated_subnet_ids=["subnet-b"],
        entries=[
            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=110, protocol="tcp", rule_action="allow", egress=True,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
        ],
    )

    edges = _can_reach_edges(build_graph(_internal_pair_infra(nacls=[acl_a, acl_b])))

    assert not any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_earlier_nacl_allow_wins_over_later_deny():
    acl_a = NetworkACL(
        id="acl-a", vpc_id="vpc-a", associated_subnet_ids=["subnet-a"],
        entries=[
            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=True,
                      cidr_block="10.0.2.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=200, protocol="tcp", rule_action="deny", egress=True,
                      cidr_block="10.0.2.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=300, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.2.0/24", port_from=5432, port_to=5432),
        ],
    )
    acl_b = NetworkACL(
        id="acl-b", vpc_id="vpc-a", associated_subnet_ids=["subnet-b"],
        entries=[
            NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
            NACLEntry(rule_number=110, protocol="tcp", rule_action="allow", egress=True,
                      cidr_block="10.0.1.0/24", port_from=5432, port_to=5432),
        ],
    )

    edges = _can_reach_edges(build_graph(_internal_pair_infra(nacls=[acl_a, acl_b])))

    assert any((edge.src, edge.dst) == ("i-a", "i-b") for edge in edges)


def test_internal_reachability_can_reach_edges_are_deterministic_and_exact():
    infra = _internal_pair_infra(extra_ingress=True)
    first = _can_reach_edges(build_graph(infra))
    second = _can_reach_edges(build_graph(infra))
    first_pair = [edge for edge in first if (edge.src, edge.dst) == ("i-a", "i-b")]
    second_pair = [edge for edge in second if (edge.src, edge.dst) == ("i-a", "i-b")]
    assert len(first_pair) == len(second_pair) == 1
    assert first_pair[0].attrs == second_pair[0].attrs
    assert set(first_pair[0].attrs) == {"ports", "reason", "confidence", "flagged"}



def test_collect_iam_maps_only_unambiguous_profiles_across_pages(monkeypatch):
    from app import aws_collector

    class FakePaginator:
        def __init__(self, pages):
            self.pages = pages

        def paginate(self):
            return iter(self.pages)

    class FakeIAM:
        def get_account_summary(self):
            return {"SummaryMap": {}}

        def get_paginator(self, operation):
            if operation == "list_instance_profiles":
                return FakePaginator([
                    {"InstanceProfiles": [{
                        "InstanceProfileName": "SingleProfile",
                        "Arn": "arn:aws:iam::123:instance-profile/SingleProfile",
                        "Roles": [{
                            "RoleName": "SingleRole",
                            "Arn": "arn:aws:iam::123:role/SingleRole",
                        }],
                    }]},
                    {"InstanceProfiles": [{
                        "InstanceProfileName": "AmbiguousProfile",
                        "Arn": "arn:aws:iam::123:instance-profile/AmbiguousProfile",
                        "Roles": [
                            {"RoleName": "RoleA", "Arn": "arn:aws:iam::123:role/RoleA"},
                            {"RoleName": "RoleB", "Arn": "arn:aws:iam::123:role/RoleB"},
                        ],
                    }, {"not": "a profile"}]},
                    "malformed page",
                ])
            if operation == "list_roles":
                return FakePaginator([])
            raise AssertionError(f"unexpected paginator: {operation}")

        def list_users(self):
            return {"Users": []}

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeIAM())

    result = aws_collector.collect_iam("key", "secret", "token", "us-east-1", [])

    assert result.instance_profile_roles == {
        "SingleProfile": {"role_name": "SingleRole", "role_arn": "arn:aws:iam::123:role/SingleRole"},
        "arn:aws:iam::123:instance-profile/SingleProfile": {
            "role_name": "SingleRole", "role_arn": "arn:aws:iam::123:role/SingleRole",
        },
    }




def test_collect_iam_invalidates_profile_keys_after_bad_duplicate_observations(monkeypatch):
    from app import aws_collector

    class FakePaginator:
        def __init__(self, pages):
            self.pages = pages

        def paginate(self):
            return iter(self.pages)

    role_a = {"RoleName": "RoleA", "Arn": "arn:aws:iam::123:role/RoleA"}
    role_b = {"RoleName": "RoleB", "Arn": "arn:aws:iam::123:role/RoleB"}
    profile_arn = "arn:aws:iam::123:instance-profile/Profile"
    profile = lambda roles: {
        "InstanceProfileName": "Profile", "Arn": profile_arn, "Roles": roles,
    }

    class FakeIAM:
        def get_account_summary(self):
            return {"SummaryMap": {}}

        def get_paginator(self, operation):
            if operation == "list_instance_profiles":
                return FakePaginator([{
                    "InstanceProfiles": [
                        profile([role_a]),
                        profile([{"RoleName": "RoleA"}]),
                        profile([role_b]),
                        profile([role_a]),
                    ],
                }])
            if operation == "list_roles":
                return FakePaginator([])
            raise AssertionError(f"unexpected paginator: {operation}")

        def list_users(self):
            return {"Users": []}

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeIAM())

    result = aws_collector.collect_iam("key", "secret", "token", "us-east-1", [])

    assert result.instance_profile_roles == {}
def test_collect_iam_skips_instance_profiles_on_permission_error(monkeypatch):
    from app import aws_collector
    from botocore.exceptions import ClientError

    class FakePaginator:
        def paginate(self):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "ListInstanceProfiles",
            )

    class FakeIAM:
        def get_account_summary(self):
            return {"SummaryMap": {}}

        def get_paginator(self, operation):
            if operation == "list_instance_profiles":
                return FakePaginator()
            if operation == "list_roles":
                return type("RolesPaginator", (), {"paginate": lambda self: iter(())})()
            raise AssertionError(f"unexpected paginator: {operation}")

        def list_users(self):
            return {"Users": []}

    monkeypatch.setattr(aws_collector.boto3, "client", lambda *args, **kwargs: FakeIAM())

    result = aws_collector.collect_iam("key", "secret", "token", "us-east-1", [])

    assert result.instance_profile_roles == {}
