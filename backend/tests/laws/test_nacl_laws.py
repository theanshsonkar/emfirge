"""Law 33 synthetic NACL semantics tests."""
import random

from app.egraph import _nacl_allowed_intervals, build_graph, get_internet_reachable_set
from app.models import AWSInfrastructure, EC2Data, EC2Instance, NetworkACL, NACLEntry, Route, RouteTable, SecurityGroup, VPCData, VPCSubnet, InternetGatewayAttachment

VPC = "vpc-l33"
SUBNET = "subnet-l33"
INSTANCE = "i-l33"

def infra(inbound, egress=None, sg_ports=(0, 65535), *, ipv6=False, default=False, no_acl=False, cidr="10.33.0.0/24"):
    sg_rule = {"from_port": sg_ports[0], "to_port": sg_ports[1], "protocol": "tcp", "ip_ranges": ["::/0" if ipv6 else "0.0.0.0/0"]}
    acl = [] if no_acl else [NetworkACL(id="acl-l33", vpc_id=VPC, is_default=default, associated_subnet_ids=[] if default else [SUBNET], entries=(inbound or []) + (egress or []))]
    return AWSInfrastructure(region="us-east-1", ec2=EC2Data(instances=[EC2Instance(id=INSTANCE, type="t3.micro", state="running", subnet_id=SUBNET, sg_ids=["sg-l33"], has_public_ip=True)], security_groups=[SecurityGroup(id="sg-l33", name="open", attached_to=[INSTANCE], rules=[sg_rule], egress_rules=[{"from_port": 0, "to_port": 65535, "protocol": "tcp", "ip_ranges":["0.0.0.0/0"]}])]), vpc=VPCData(subnets=[VPCSubnet(id=SUBNET, vpc_id=VPC, cidr=cidr)], route_tables=[RouteTable(id="rt-l33", vpc_id=VPC, is_main=True, associated_subnet_ids=[SUBNET], routes=[Route(destination_cidr="0.0.0.0/0", target_type="internet_gateway", target_id="igw-l33")])], internet_gateways=["igw-l33"], internet_gateway_attachments=[InternetGatewayAttachment(internet_gateway_id="igw-l33", vpc_id=VPC, state="available")], internet_gateway_attachments_complete=True, nacls=acl))

def e(rule, *, out=False, cidr="0.0.0.0/0", protocol="6", lo=0, hi=65535, ipv6=None):
    return NACLEntry(rule_number=rule, protocol=protocol, rule_action="allow", egress=out, cidr_block=cidr, ipv6_cidr_block=ipv6, port_from=lo, port_to=hi)

def d(rule, *, out=False, cidr="0.0.0.0/0", protocol="6", lo=0, hi=65535):
    return NACLEntry(rule_number=rule, protocol=protocol, rule_action="deny", egress=out, cidr_block=cidr, port_from=lo, port_to=hi)

def reachable(g): return INSTANCE in get_internet_reachable_set(build_graph(g))

def test_L33a_first_match_is_per_interval():
    assert reachable(infra([d(100, lo=22, hi=22), e(200)], [e(100, out=True)]))

def test_L33b_security_group_and_nacl_intersect():
    assert not reachable(infra([e(100, lo=443, hi=443), d(200)], [e(100, out=True)], sg_ports=(22,22)))
    assert reachable(infra([e(100, lo=443, hi=443), d(200)], [e(100, out=True)], sg_ports=(443,443)))

def test_L33c_rule_order_wins_not_input_order():
    assert not reachable(infra([e(200), d(100)], [e(100, out=True)]))
    assert reachable(infra([d(200), e(100)], [e(100, out=True)]))

def test_L33d_return_path_is_required():
    assert not reachable(infra([e(100)], [d(100, out=True)]))
    assert reachable(infra([e(100)], [e(100, out=True, lo=1024, hi=65535)]))

def test_L33e_implicit_deny():
    assert not reachable(infra([e(100, cidr="10.0.0.0/8")], [e(100, out=True)]))

def test_L33f_empty_direction_is_assumed():
    assert reachable(infra([e(100)], []))

def test_L33g_default_fallback_and_missing_acl():
    assert not reachable(infra([d(100)], [e(100, out=True)], default=True))
    assert reachable(infra([], [], no_acl=True))

def test_L33h_ipv6():
    assert reachable(infra([d(100), e(110, cidr=None, ipv6="::/0")], [e(100, out=True), e(110, out=True, cidr=None, ipv6="::/0")], ipv6=True))


def test_L33j_nacl_protocol_name_tcp_matches_security_group_tcp():
    assert reachable(infra(
        [NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=False,
                   cidr_block="0.0.0.0/0", port_from=443, port_to=443)],
        [e(100, out=True, lo=1024, hi=65535)],
        sg_ports=(443, 443),
    ))


def test_L33k_nacl_intervals_match_brute_force_first_match():
    import ipaddress

    protocols = ["-1", "6", "17", "tcp", "udp", "1"]
    cidrs = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "::/0"]
    peer = ipaddress.ip_network("10.1.2.0/24")

    def normalize(protocol):
        return {"tcp": "6", "udp": "17", "icmp": "1", "all": "-1"}.get(
            str(protocol).lower(), str(protocol).lower())

    def brute(entries, egress, protocol, lo, hi):
        wanted = normalize(protocol)
        allowed = set()
        direction = [entry for entry in entries if entry.egress == egress]
        if not direction:
            return set(range(lo, hi + 1))
        for port in range(lo, hi + 1):
            match = None
            for entry in sorted(direction, key=lambda item: item.rule_number):
                entry_protocol = normalize(entry.protocol)
                if entry_protocol not in {"-1", wanted}:
                    continue
                entry_cidr = entry.cidr_block or entry.ipv6_cidr_block
                if not entry_cidr:
                    continue
                network = ipaddress.ip_network(entry_cidr, strict=False)
                if network.version != peer.version or not peer.subnet_of(network):
                    continue
                if entry_protocol not in {"-1", "1", "58"}:
                    entry_lo = 0 if entry.port_from is None else entry.port_from
                    entry_hi = 65535 if entry.port_to is None else entry.port_to
                    if not entry_lo <= port <= entry_hi:
                        continue
                match = entry
                break
            if match is not None and match.rule_action == "allow":
                allowed.add(port)
        return allowed

    for seed in range(200):
        rnd = random.Random(seed)
        entries = []
        for rule_number in rnd.sample(range(1, 301), rnd.randint(1, 6)):
            protocol = rnd.choice(protocols)
            is_portless = normalize(protocol) in {"-1", "1"}
            lo = hi = None
            if not is_portless:
                lo, hi = sorted((rnd.randint(0, 1100), rnd.randint(0, 1100)))
            entries.append(NACLEntry(
                rule_number=rule_number,
                egress=rnd.choice([False, True]),
                protocol=protocol,
                rule_action=rnd.choice(["allow", "deny"]),
                cidr_block=rnd.choice(cidrs),
                port_from=lo,
                port_to=hi,
            ))
        request_protocol = rnd.choice(["6", "17", "-1"])
        lo, hi = sorted((rnd.randint(0, 1100), rnd.randint(0, 1100)))
        for egress in (False, True):
            expected = brute(entries, egress, request_protocol, lo, hi)
            intervals = _nacl_allowed_intervals(
                entries, egress, ["10.1.2.0/24"], request_protocol, lo, hi)
            actual = {port for start, end in intervals for port in range(start, end + 1)}
            assert actual == expected, (seed, egress, request_protocol, lo, hi, entries)
