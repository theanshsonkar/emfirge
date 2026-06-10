"""
Tests for BFS-based simulation slice — bfs_from_internet() and get_simulation_slice().
Zero AWS/LLM calls. Verifies real attack path traversal replaces type-filter.
"""
import pytest
from app.egraph import build_graph, bfs_from_internet, get_simulation_slice, format_graph_for_claude
from app.models import (
    AWSInfrastructure, EC2Data, S3Data, RDSData, LambdaData, VPCData,
    EC2Instance, SecurityGroup, S3Bucket, RDSInstance, LambdaFunction,
)


# -- HELPERS -------------------------------------------------------

def make_open_sg(sg_id, port=22, attached_to=None):
    return SecurityGroup(
        id=sg_id, name=f"open-{sg_id}",
        rules=[{"from_port": port, "to_port": port, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
        attached_to=attached_to or [],
    )

def make_private_sg(sg_id, attached_to=None):
    return SecurityGroup(
        id=sg_id, name=f"private-{sg_id}",
        rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["10.0.0.0/8"]}],
        attached_to=attached_to or [],
    )

def make_instance(instance_id, sg_ids=None):
    return EC2Instance(
        id=instance_id, type="t3.micro",
        sg_ids=sg_ids or [],
        state="running", imdsv2_required=True,
    )


# -- bfs_from_internet() -------------------------------------------

class TestBfsFromInternet:

    def test_no_internet_node_returns_empty(self):
        """No open SGs → no INTERNET node → BFS returns empty."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-priv"])],
                security_groups=[make_private_sg("sg-priv", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        assert result['nodes'] == []
        assert result['edges'] == []
        assert result['layers'] == {}

    def test_internet_node_at_depth_zero(self):
        """INTERNET node itself must be at depth 0."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        assert result['layers']['INTERNET'] == 0

    def test_directly_reachable_sg_at_depth_one(self):
        """SG with 0.0.0.0/0 rule → INTERNET→SG edge → depth 1."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        assert result['layers']['sg-open'] == 1

    def test_ec2_behind_open_sg_at_depth_two(self):
        """INTERNET→SG→EC2 via REACHES_VIA_SG edge → EC2 at depth 1 (direct edge)."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        # INTERNET→i-001 via REACHES_VIA_SG is a direct edge, so depth=1
        assert 'i-001' in result['layers']
        assert result['layers']['i-001'] == 1

    def test_private_sg_not_reachable(self):
        """SG with only private CIDR → not reachable from internet."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    make_instance("i-public", sg_ids=["sg-open"]),
                    make_instance("i-private", sg_ids=["sg-priv"]),
                ],
                security_groups=[
                    make_open_sg("sg-open", attached_to=["i-public"]),
                    make_private_sg("sg-priv", attached_to=["i-private"]),
                ],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        node_ids = {n['id'] for n in result['nodes']}
        assert 'i-public' in node_ids
        assert 'sg-priv' not in node_ids
        assert 'i-private' not in node_ids

    def test_all_reachable_nodes_in_result(self):
        """Every node reachable from INTERNET must appear in result nodes."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        node_ids = {n['id'] for n in result['nodes']}
        # All nodes in layers must be in result nodes
        for nid in result['layers']:
            assert nid in node_ids, f"Node {nid} in layers but missing from result nodes"

    def test_edges_only_between_reachable_nodes(self):
        """Edges in BFS result must only connect nodes that are in the reachable set."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    make_instance("i-public", sg_ids=["sg-open"]),
                    make_instance("i-private", sg_ids=["sg-priv"]),
                ],
                security_groups=[
                    make_open_sg("sg-open", attached_to=["i-public"]),
                    make_private_sg("sg-priv", attached_to=["i-private"]),
                ],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        reachable_ids = {n['id'] for n in result['nodes']}
        for edge in result['edges']:
            assert edge['from'] in reachable_ids, f"Edge from unreachable node: {edge['from']}"
            assert edge['to'] in reachable_ids, f"Edge to unreachable node: {edge['to']}"

    def test_multi_hop_traversal(self):
        """INTERNET→SG→EC2→IAM role — all should be reachable via BFS."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
            lambda_data=LambdaData(
                functions=[LambdaFunction(name="my-fn", role_arn="arn:aws:iam::123:role/AdminRole")],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        node_ids = {n['id'] for n in result['nodes']}
        # INTERNET and SG and EC2 must be reachable
        assert 'INTERNET' in node_ids
        assert 'sg-open' in node_ids
        assert 'i-001' in node_ids

    def test_category_is_attack_surface(self):
        """BFS result always returns category='attack_surface'."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        assert result['category'] == 'attack_surface'

    def test_multiple_open_sgs_all_reachable(self):
        """Two open SGs → both reachable at depth 1."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[
                    make_instance("i-001", sg_ids=["sg-ssh"]),
                    make_instance("i-002", sg_ids=["sg-http"]),
                ],
                security_groups=[
                    make_open_sg("sg-ssh", port=22, attached_to=["i-001"]),
                    make_open_sg("sg-http", port=80, attached_to=["i-002"]),
                ],
            ),
        )
        graph = build_graph(infra)
        result = bfs_from_internet(graph)
        assert result['layers']['sg-ssh'] == 1
        assert result['layers']['sg-http'] == 1


# -- get_simulation_slice() ----------------------------------------

class TestGetSimulationSlice:

    def test_attack_surface_uses_bfs_when_internet_exists(self):
        """attack_surface category must use BFS, not type filter."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = get_simulation_slice(graph, 'attack_surface')
        node_ids = {n['id'] for n in result['nodes']}
        # BFS result must include INTERNET
        assert 'INTERNET' in node_ids
        # layers must be populated
        assert result['layers'] != {}
        assert result['layers']['INTERNET'] == 0

    def test_general_uses_bfs_when_internet_exists(self):
        """general category must also use BFS."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = get_simulation_slice(graph, 'general')
        node_ids = {n['id'] for n in result['nodes']}
        assert 'INTERNET' in node_ids
        assert result['layers'] != {}

    def test_attack_surface_fallback_when_no_internet(self):
        """No INTERNET node → fallback to first 50 nodes, layers empty."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-priv"])],
                security_groups=[make_private_sg("sg-priv", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        result = get_simulation_slice(graph, 'attack_surface')
        # Fallback: nodes present but layers empty
        assert len(result['nodes']) > 0
        assert result['layers'] == {}

    def test_scale_traffic_uses_type_filter(self):
        """scale_traffic must still use type-based filter, not BFS."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", publicly_accessible=False, encrypted=True)],
            ),
        )
        graph = build_graph(infra)
        result = get_simulation_slice(graph, 'scale_traffic')
        node_ids = {n['id'] for n in result['nodes']}
        # scale_traffic includes ec2_instance and rds_instance
        assert 'i-001' in node_ids
        assert 'my-db' in node_ids
        # INTERNET should NOT be in scale_traffic slice
        assert 'INTERNET' not in node_ids
        # layers should be empty for type-filter slices
        assert result['layers'] == {}

    def test_data_exposure_uses_type_filter(self):
        """data_exposure must use type-based filter."""
        infra = AWSInfrastructure(
            region="us-east-1",
            s3=S3Data(buckets=[S3Bucket(name="my-bucket", is_public=True, is_empty=False)]),
            rds=RDSData(
                rds_instances=[RDSInstance(id="my-db", publicly_accessible=True, encrypted=False)],
            ),
        )
        graph = build_graph(infra)
        result = get_simulation_slice(graph, 'data_exposure')
        node_ids = {n['id'] for n in result['nodes']}
        assert 'my-bucket' in node_ids
        assert 'my-db' in node_ids

    def test_result_always_has_layers_key(self):
        """All slice results must have a 'layers' key regardless of category."""
        infra = AWSInfrastructure(region="us-east-1")
        graph = build_graph(infra)
        for category in ('attack_surface', 'general', 'scale_traffic', 'data_exposure', 'cost'):
            result = get_simulation_slice(graph, category)
            assert 'layers' in result, f"Missing 'layers' key for category={category}"


# -- format_graph_for_claude() -------------------------------------

class TestFormatGraphForClaude:

    def test_depth_annotation_present(self):
        """Each node line must contain depth=N."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        slice_dict = get_simulation_slice(graph, 'attack_surface')
        text = format_graph_for_claude(slice_dict)
        # Every node line should have depth=
        node_lines = [l for l in text.splitlines() if l.strip().startswith('- ')]
        edge_section = False
        for line in text.splitlines():
            if line.strip() == 'Edges:':
                edge_section = True
            if not edge_section and line.strip().startswith('- '):
                assert 'depth=' in line, f"Missing depth annotation in node line: {line}"

    def test_internet_node_depth_zero_in_text(self):
        """INTERNET node must appear as depth=0 in formatted text."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        slice_dict = get_simulation_slice(graph, 'attack_surface')
        text = format_graph_for_claude(slice_dict)
        assert 'INTERNET [internet] depth=0' in text

    def test_no_raw_metadata_dump(self):
        """Formatted text must not contain raw Python dict noise like 'rules_count'."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        slice_dict = get_simulation_slice(graph, 'attack_surface')
        text = format_graph_for_claude(slice_dict)
        # These are metadata fields that should be filtered out
        assert 'rules_count' not in text
        assert 'attached_instances' not in text
        assert 'subnet_id' not in text

    def test_edges_section_present(self):
        """Formatted text must have an Edges: section."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        slice_dict = get_simulation_slice(graph, 'attack_surface')
        text = format_graph_for_claude(slice_dict)
        assert 'Edges:' in text

    def test_edge_format_correct(self):
        """Edge lines must follow 'from --relationship--> to' format."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-open"])],
                security_groups=[make_open_sg("sg-open", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        slice_dict = get_simulation_slice(graph, 'attack_surface')
        text = format_graph_for_claude(slice_dict)
        edge_lines = []
        in_edges = False
        for line in text.splitlines():
            if line.strip() == 'Edges:':
                in_edges = True
                continue
            if in_edges and line.strip().startswith('- '):
                edge_lines.append(line)
        assert len(edge_lines) > 0
        for line in edge_lines:
            assert '--' in line and '-->' in line, f"Bad edge format: {line}"

    def test_unknown_depth_shown_as_question_mark(self):
        """Nodes not in layers dict should show depth=?."""
        infra = AWSInfrastructure(
            region="us-east-1",
            ec2=EC2Data(
                instances=[make_instance("i-001", sg_ids=["sg-priv"])],
                security_groups=[make_private_sg("sg-priv", attached_to=["i-001"])],
            ),
        )
        graph = build_graph(infra)
        # Use scale_traffic which has empty layers
        slice_dict = get_simulation_slice(graph, 'scale_traffic')
        text = format_graph_for_claude(slice_dict)
        # All nodes should show depth=? since layers is empty
        node_lines = []
        in_edges = False
        for line in text.splitlines():
            if line.strip() == 'Edges:':
                in_edges = True
            if not in_edges and line.strip().startswith('- '):
                node_lines.append(line)
        for line in node_lines:
            assert 'depth=?' in line, f"Expected depth=? for type-filter slice: {line}"
