"""Moto round-trips for typed hand-back calls.

These tests deliberately use the production service collectors rather than
constructing a synthetic AWS graph.
"""
import io
import json
import re
import zipfile

import boto3
import pytest
from moto import mock_aws

from app.aws_collector import collect_ec2, collect_lambda, collect_rds, collect_s3, collect_vpc
from app.models import AWSInfrastructure, NACLEntry
from app.mutations import Change, apply_changes
from app.typed_handback import build_api_calls

REGION = "ap-south-1"
CREDS = {"aws_access_key_id": "testing", "aws_secret_access_key": "testing", "aws_session_token": "testing"}
KNOWN_MOTO_GAPS = {}
VOLATILE_FIELDS = set()


def _client(service):
    return boto3.client(service, region_name=REGION, **CREDS)


def _method(client, operation):
    return next(method for method, name in client._PY_TO_OP_NAME.items() if name == operation)


def _collect(fn):
    warnings = []
    return fn("testing", "testing", "testing", REGION, warnings)


def _base(data, section):
    return AWSInfrastructure.model_validate({section: data, "region": REGION})


def _resource(state, typ, ident):
    groups = {
        "security_group": state.ec2.security_groups,
        "ec2_instance": state.ec2.instances,
        "ebs_volume": state.ec2.ebs_volumes,
        "ebs_snapshot": state.ec2.ebs_snapshots,
        "rds_instance": state.rds.rds_instances,
        "rds_snapshot": state.rds.rds_snapshots,
        "s3_bucket": state.s3.buckets,
        "lambda_function": state.lambda_data.functions,
        "route_table": state.vpc.route_tables,
        "network_acl": state.vpc.nacls,
    }
    key = "name" if typ in {"s3_bucket", "lambda_function"} else "id"
    return next((x for x in groups[typ] if getattr(x, key) == ident), None)


def _route_key(route):
    target_type = "igw" if route.target_type == "internet_gateway" else route.target_type
    return route.destination_cidr, target_type, route.target_id


def _assert_matches(recollected, modeled, change, typ, ident, touched):
    if change.op == "delete":
        assert _resource(recollected, typ, ident) is None
        assert _resource(modeled, typ, ident) is None
        return
    actual = _resource(recollected, typ, ident)
    expected = _resource(modeled, typ, ident)
    assert actual is not None and expected is not None
    fields = type(actual).model_fields.keys()
    for field in fields:
        if field in VOLATILE_FIELDS:
            continue
        actual_value = getattr(actual, field)
        expected_value = getattr(expected, field)
        if field == "rules":
            def rule_key(rule):
                value = dict(rule)
                value.setdefault("source_sg_ids", [])
                return value
            actual_value = [rule_key(x) for x in actual_value]
            expected_value = [rule_key(x) for x in expected_value]
        elif field == "routes":
            actual_value = [_route_key(x) for x in actual_value]
            expected_value = [_route_key(x) for x in expected_value]
        assert actual_value == expected_value, (field, actual, expected)


def _roundtrip(base, change, collector, typ, ident, touched):
    modeled = apply_changes(base, [change])
    calls = build_api_calls(base, [change])
    assert calls, f"no hand-back calls for {typ}"
    for item in calls:
        client = _client(item["service"])
        getattr(client, _method(client, item["operation"]))(**item["params"])
    recollected = collector()
    _assert_matches(recollected, modeled, change, typ, ident, touched)


def _vpc():
    return _client("ec2").create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]


def _sg(vpc):
    ec2 = _client("ec2")
    return ec2.create_security_group(GroupName="roundtrip-sg", Description="roundtrip", VpcId=vpc)["GroupId"]


def _instance(vpc, sg):
    ec2 = _client("ec2")
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    return ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[sg])["Instances"][0]["InstanceId"]


@pytest.fixture(autouse=True)
def fake_aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        yield


def test_security_group_delete_and_rule_modify_roundtrip():
    vpc = _vpc(); sg = _sg(vpc); ec2 = _client("ec2")
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    def collect(): return _base(_collect(collect_ec2), "ec2")
    base = collect()
    _roundtrip(base, Change(op="modify", resource_type="security_group", resource_id=sg, fields={"rules": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["10.0.0.0/8"]}]}), collect, "security_group", sg, ["rules"])
    base = collect()
    _roundtrip(base, Change(op="delete", resource_type="security_group", resource_id=sg, fields={}), collect, "security_group", sg, [])


def test_ec2_modify_roundtrip():
    vpc = _vpc(); sg = _sg(vpc); ident = _instance(vpc, sg)
    def collect(): return _base(_collect(collect_ec2), "ec2")
    _roundtrip(collect(), Change(op="modify", resource_type="ec2_instance", resource_id=ident, fields={"type": "t3.small"}), collect, "ec2_instance", ident, ["type"])


def test_rds_modify_and_snapshot_delete_roundtrip():
    rds = _client("rds")
    rds.create_db_instance(DBInstanceIdentifier="roundtrip-db", DBInstanceClass="db.t3.micro", Engine="postgres", MasterUsername="master", MasterUserPassword="password", AllocatedStorage=20)
    def collect(): return _base(_collect(collect_rds), "rds")
    _roundtrip(collect(), Change(op="modify", resource_type="rds_instance", resource_id="roundtrip-db", fields={"backup_retention_days": 7}), collect, "rds_instance", "roundtrip-db", ["backup_retention_days"])
    rds.create_db_snapshot(DBSnapshotIdentifier="roundtrip-snapshot", DBInstanceIdentifier="roundtrip-db")
    base = collect()
    _roundtrip(base, Change(op="delete", resource_type="rds_snapshot", resource_id="roundtrip-snapshot", fields={}), collect, "rds_snapshot", "roundtrip-snapshot", [])


def test_s3_policy_modify_and_delete_roundtrip():
    s3 = _client("s3"); name = "roundtrip-bucket"; s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}]})
    def collect(): return _base(_collect(collect_s3), "s3")
    _roundtrip(collect(), Change(op="modify", resource_type="s3_bucket", resource_id=name, fields={"policy": policy}), collect, "s3_bucket", name, ["policy"])
    _roundtrip(collect(), Change(op="delete", resource_type="s3_bucket", resource_id=name, fields={}), collect, "s3_bucket", name, [])


def test_lambda_configuration_modify_roundtrip():
    _client("iam").create_role(RoleName="roundtrip", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    lm = _client("lambda")
    code = io.BytesIO();
    with zipfile.ZipFile(code, "w") as archive: archive.writestr("lambda_function.py", "def lambda_handler(event, context): return event")
    name = "roundtrip-function"; role = "arn:aws:iam::123456789012:role/roundtrip"
    lm.create_function(FunctionName=name, Runtime="python3.11", Role=role, Handler="lambda_function.lambda_handler", Code={"ZipFile": code.getvalue()})
    def collect(): return _base(_collect(collect_lambda), "lambda_data")
    _roundtrip(collect(), Change(op="modify", resource_type="lambda_function", resource_id=name, fields={"role_arn": "arn:aws:iam::123456789012:role/changed"}), collect, "lambda_function", name, ["role_arn"])


def test_ebs_volume_and_snapshot_delete_roundtrip():
    ec2 = _client("ec2"); volume = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=1)["VolumeId"]; snapshot = ec2.create_snapshot(VolumeId=volume, Description="roundtrip")["SnapshotId"]
    def collect(): return _base(_collect(collect_ec2), "ec2")
    _roundtrip(collect(), Change(op="delete", resource_type="ebs_volume", resource_id=volume, fields={}), collect, "ebs_volume", volume, [])
    _roundtrip(collect(), Change(op="delete", resource_type="ebs_snapshot", resource_id=snapshot, fields={}), collect, "ebs_snapshot", snapshot, [])


def test_route_table_modify_roundtrip():
    ec2 = _client("ec2"); vpc = _vpc(); rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]; igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]; ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    def collect(): return _base(_collect(collect_vpc), "vpc")
    fields = {"routes": [{"destination_cidr": vpc.replace("vpc", "10.0.0.0/16"), "target_type": "local", "target_id": "local"}, {"destination_cidr": "0.0.0.0/0", "target_type": "igw", "target_id": igw}]}
    # The collector's local route is the modeled baseline; use its exact value.
    current = collect(); local = _resource(current, "route_table", rt).routes[0].destination_cidr
    fields["routes"][0]["destination_cidr"] = local
    _roundtrip(current, Change(op="modify", resource_type="route_table", resource_id=rt, fields=fields), collect, "route_table", rt, ["routes"])


def test_network_acl_entry_modify_roundtrip():
    ec2 = _client("ec2"); vpc = _vpc(); acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
    def collect(): return _base(_collect(collect_vpc), "vpc")
    base = collect(); current = _resource(base, "network_acl", acl)
    entry = NACLEntry(rule_number=100, protocol="tcp", rule_action="allow", egress=False,
                      cidr_block="10.0.0.0/8", port_from=443, port_to=443)
    _roundtrip(base, Change(op="modify", resource_type="network_acl", resource_id=acl,
                            fields={"entries": [x.model_dump() for x in current.entries] + [entry.model_dump()]}), collect, "network_acl", acl, ["entries"])


def test_tampered_handback_call_is_detected():
    vpc = _vpc(); sg = _sg(vpc); ec2 = _client("ec2")
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    def collect(): return _base(_collect(collect_ec2), "ec2")
    base = collect()
    change = Change(op="modify", resource_type="security_group", resource_id=sg, fields={"rules": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "ip_ranges": ["10.0.0.0/8"]}]})
    modeled = apply_changes(base, [change]); calls = build_api_calls(base, [change])
    for permission in calls[0]["params"]["IpPermissions"]:
        permission["FromPort"] = 444
        permission["ToPort"] = 444
    for item in calls:
        client = _client(item["service"])
        getattr(client, _method(client, item["operation"]))(**item["params"])
    recollected = collect()
    with pytest.raises(AssertionError):
        _assert_matches(recollected, modeled, change, "security_group", sg, ["rules"])


def test_known_moto_gaps_are_explicit():
    assert set(KNOWN_MOTO_GAPS) == set()
