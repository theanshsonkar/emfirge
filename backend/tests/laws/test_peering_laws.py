from __future__ import annotations

import ipaddress
import random

from app.egraph import Graph, Node, RelationshipType, route_between


def _graph(routes_a=None, routes_b=None, *, status="active", cidr_a="10.0.0.0/16", cidr_b="10.1.0.0/16", explicit=True):
    routes_a = routes_a or []
    routes_b = routes_b or []
    nodes = [
        Node(id="i-a", resource_type="ec2_instance", label="A", base={"subnet_id": "subnet-a"}),
        Node(id="i-b", resource_type="ec2_instance", label="B", base={"subnet_id": "subnet-b"}),
        Node(id="subnet-a", resource_type="vpc_subnet", label="A subnet", base={"vpc_id": "vpc-a", "cidr": cidr_a}),
        Node(id="subnet-b", resource_type="vpc_subnet", label="B subnet", base={"vpc_id": "vpc-b", "cidr": cidr_b}),
        Node(id="pcx-1", resource_type="vpc_peering_connection", label="peering", base={
            "requester_vpc_id": "vpc-a", "accepter_vpc_id": "vpc-b", "status": status,
        }),
        Node(id="rt-a", resource_type="route_table", label="A routes", base={
            "vpc_id": "vpc-a", "is_main": not explicit, "routes": routes_a,
        }),
        Node(id="rt-b", resource_type="route_table", label="B routes", base={
            "vpc_id": "vpc-b", "is_main": not explicit, "routes": routes_b,
        }),
    ]
    edges = [
        {"src": "i-a", "dst": "subnet-a", "relationship": RelationshipType.in_subnet},
        {"src": "i-b", "dst": "subnet-b", "relationship": RelationshipType.in_subnet},
    ]
    if explicit:
        edges += [
            {"src": "subnet-a", "dst": "rt-a", "relationship": RelationshipType.ASSOCIATED_WITH},
            {"src": "subnet-b", "dst": "rt-b", "relationship": RelationshipType.ASSOCIATED_WITH},
        ]
    return Graph(nodes=nodes, edges=edges)


def _route(destination, target="pcx-1"):
    return {"destination_cidr": destination, "target_type": "vpc_peering" if target == "pcx-1" else "nat_gateway", "target_id": target}


def test_l37a_routes_cover_peer_subnets_in_both_directions():
    graph = _graph([_route("10.1.0.0/16")], [_route("10.0.0.0/16")])
    assert route_between(graph.nodes[0], graph.nodes[1], graph) == ("routed_high", "active peering")


def test_l37b_nonmatching_destination_does_not_route():
    graph = _graph([_route("192.168.0.0/16")], [_route("10.0.0.0/16")])
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "blocked"


def test_l37c_return_path_is_required():
    graph = _graph([_route("10.1.0.0/16")], [])
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "blocked"
    assert route_between(graph.nodes[1], graph.nodes[0], graph)[0] == "blocked"


def test_l37d_more_specific_route_wins():
    graph = _graph([_route("10.0.0.0/8"), _route("10.1.0.0/16", "nat-1")], [_route("10.0.0.0/16")])
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "blocked"


def test_l37e_inactive_peering_does_not_route():
    graph = _graph([_route("10.1.0.0/16")], [_route("10.0.0.0/16")], status="pending")
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "blocked"


def test_l37f_unassociated_subnets_use_main_route_table():
    graph = _graph([_route("10.1.0.0/16")], [_route("10.0.0.0/16")], explicit=False)
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "routed_high"


def test_l37g_missing_cidr_is_assumed_flagged():
    graph = _graph([_route("10.1.0.0/16")], [_route("10.0.0.0/16")], cidr_b=None)
    assert route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "assumed_flagged"


def test_l37h_longest_prefix_property():
    destinations = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "0.0.0.0/0", "192.168.0.0/16"]
    targets = ["pcx-1", "nat-1", "igw-1", "local"]
    for seed in range(200):
        rnd = random.Random(seed)
        left = [_route(destination, target) for destination, target in ((rnd.choice(destinations), rnd.choice(targets)) for _ in range(rnd.randrange(5)))]
        right = [_route(destination, target) for destination, target in ((rnd.choice(destinations), rnd.choice(targets)) for _ in range(rnd.randrange(5)))]
        graph = _graph(left, right)
        expected = []
        for routes, address in ((left, "10.1.0.0"), (right, "10.0.0.0")):
            matching = [(ipaddress.ip_network(route["destination_cidr"]), route) for route in routes
                        if ipaddress.ip_address(address) in ipaddress.ip_network(route["destination_cidr"])]
            expected.append(bool(matching) and max(matching, key=lambda item: item[0].prefixlen)[1]["target_id"] == "pcx-1")
        actual = route_between(graph.nodes[0], graph.nodes[1], graph)[0] == "routed_high"
        assert actual == (expected[0] and expected[1]), (seed, left, right)
