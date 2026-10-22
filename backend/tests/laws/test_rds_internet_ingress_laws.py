"""L55 RDS internet ingress: a publicly accessible RDS in a public subnet whose SG admits its port from the internet is internet reachable."""
import json

import boto3
from moto import mock_aws

from app.aws_collector import collect_rds
from app.egraph import build_graph, get_internet_reachable_set
from app.exposure import compute_exposures
from app.models import NACLEntry, NetworkACL
from app.mutations import Change, apply_change
from app.typed_handback import build_api_calls
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

RDS = "db-dl-prod"
PUB, PRIV = "subnet-dl-pub", "subnet-dl-priv"


def world(*ports):
    return [{"protocol": "tcp", "from_port": p, "to_port": p, "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []} for p in ports]


def make(*, public=True, subnet=PUB, engine="postgres", port=None, ports=(5432,), nacl=None):
    """A base with no EC2 pivot and db-dl-prod configured as asked."""
    base = apply_change(load_synthetic_base("delete"), Change(op="delete", resource_type="ec2_instance", resource_id="i-dl-web"))
    base = type(base).model_validate(base.model_dump())
    for sg in base.ec2.security_groups:
        if sg.id == "sg-dl-db":
            sg.rules = world(*ports)
    for db in base.rds.rds_instances:
        if db.id == RDS:
            db.publicly_accessible, db.subnet_id, db.engine, db.port = public, subnet, engine, port
    if nacl is not None:
        base.vpc.nacls = [NetworkACL(id="acl-l55", vpc_id="vpc-dl0001", is_default=False, associated_subnet_ids=[PUB], entries=nacl)]
    return base


def rds_edges(base):
    return [e for e in build_graph(base).edges if e.src == "INTERNET" and e.dst == RDS]


def reachable(base):
    return RDS in get_internet_reachable_set(build_graph(base))


def nacl_rules(deny_port=None):
    rules = []
    if deny_port:
        rules.append(NACLEntry(rule_number=100, protocol="6", rule_action="deny", egress=False, cidr_block="0.0.0.0/0", port_from=deny_port, port_to=deny_port))
    rules.append(NACLEntry(rule_number=200, protocol="-1", rule_action="allow", egress=False, cidr_block="0.0.0.0/0"))
    rules.append(NACLEntry(rule_number=100, protocol="-1", rule_action="allow", egress=True, cidr_block="0.0.0.0/0"))
    return rules


def test_L55a_public_rds_is_reachable_and_flip_blocks():
    base = make()
    assert reachable(base)
    edges = rds_edges(base)
    assert len(edges) == 1
    assert str(edges[0].relationship.value) == "REACHES_VIA_SG"
    branch_base = make(public=False)
    branch_base.rds.rds_instances[0].subnet_id = PUB
    branch = apply_change(branch_base, Change(op="modify", resource_type="rds_instance", resource_id=RDS, fields={"publicly_accessible": True}))
    verdict = combined_verdict(branch_base, branch, run_scanners=False)
    data = verdict if isinstance(verdict, dict) else verdict.model_dump()
    assert RDS in data["newly_internet_reachable"]
    assert data["verdict"] == "block"
    assert any(x["resource_id"] == RDS and x["from_port"] == 5432 and x["severity"] == "Critical" for x in data["newly_exposed"])


def test_L55b_each_missing_condition_blocks_reachability():
    assert not reachable(make(public=False))
    assert not reachable(make(subnet=PRIV))
    assert not reachable(make(ports=(443,)))
    assert not rds_edges(make(public=False))
    assert not reachable(make(nacl=nacl_rules(deny_port=5432)))
    assert reachable(make(nacl=nacl_rules()))


def test_L55c_explicit_port_beats_engine_default():
    assert reachable(make(port=6000, ports=(6000,)))
    assert not reachable(make(port=6000, ports=(5432,)))


def test_L55d_fail_closed_on_unknown():
    base = make(subnet=None)
    assert reachable(base)
    assert rds_edges(base)[0].attrs["confidence"] == "assumed"
    assert reachable(make(engine=None, port=None, ports=(443,)))


def test_L55e_exposures_cover_only_the_db_port():
    base = make(ports=(443, 5432))
    graph = build_graph(base)
    mine = [x for x in compute_exposures(base, graph) if x.resource_id == RDS]
    assert {(x.from_port, x.to_port) for x in mine} == {(5432, 5432)}
    assert all(x.resource_type == "rds_instance" for x in mine)


@mock_aws
def test_L55f_collector_sets_subnet_and_port(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    region = "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    vpc = ec2.create_vpc(CidrBlock="10.55.0.0/16")["Vpc"]["VpcId"]
    a = ec2.create_subnet(VpcId=vpc, CidrBlock="10.55.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    b = ec2.create_subnet(VpcId=vpc, CidrBlock="10.55.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    rds = boto3.client("rds", region_name=region)
    rds.create_db_subnet_group(DBSubnetGroupName="g55", DBSubnetGroupDescription="d", SubnetIds=[a, b])
    rds.create_db_instance(DBInstanceIdentifier="db55", DBInstanceClass="db.t3.micro", Engine="postgres", MasterUsername="u", MasterUserPassword="password123",
                           AllocatedStorage=20, PubliclyAccessible=True, DBSubnetGroupName="g55", AvailabilityZone="us-east-1b")
    data = collect_rds(None, None, None, region, [])
    db = next(x for x in data.rds_instances if x.id == "db55")
    assert db.subnet_id == b
    assert db.port == 5432
    assert db.publicly_accessible is True


def test_L55g_handback_maps_port():
    base = make()
    calls = build_api_calls(base, [Change(op="modify", resource_type="rds_instance", resource_id=RDS, fields={"port": 6000})])
    text = json.dumps(calls, default=lambda o: getattr(o, "__dict__", str(o)))
    assert "ModifyDBInstance" in text and "DBPortNumber" in text and "6000" in text


def test_L55h_graph_is_deterministic():
    base = make(ports=(443, 5432))
    def dump(g):
        return json.dumps([[n.model_dump() if hasattr(n, "model_dump") else n for n in g.nodes], [e.model_dump() if hasattr(e, "model_dump") else e for e in g.edges]], sort_keys=False, default=str)
    assert dump(build_graph(base)) == dump(build_graph(base))
