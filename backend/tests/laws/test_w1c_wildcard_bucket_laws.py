import itertools
import itertools
import random
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import branches, database, diffing, main, verdict
from app.egraph import Graph
from app.models import (
    AccessStatement,
    AWSInfrastructure,
    EC2Data,
    EC2Instance,
    IAMData,
    RolePolicy,
    RiskFinding,
    S3Bucket,
    S3Data,
    SecurityGroup,
)
from app.rules import check_internet_to_broad_data_access


@pytest.fixture
def plan_client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'w1c.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(branches, "SessionLocal", factory)
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _ip: None)
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    client = TestClient(main.app)
    yield client
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


BUCKETS = ["cust-apps-a", "cust-apps-b", "payroll"]
ROLE_ARN = "arn:aws:iam::123:role/OrdersRole"


def _role(resource="*", *, condition=False):
    return RolePolicy(
        role_name="OrdersRole", role_arn=ROLE_ARN,
        access_statements=[AccessStatement(effect="Allow", actions=["s3:GetObject"], resources=[resource], has_condition=condition)],
    )


def _infra(*, public=False, role=None):
    instance = EC2Instance(id="i-orders", type="t3.micro", state="running", instance_profile_arn="arn:aws:iam::123:instance-profile/OrdersRole")
    if public:
        instance.sg_ids = ["sg-orders"]
    return AWSInfrastructure(
        region="us-east-1",
        ec2=EC2Data(instance_count=1, instance_ids=["i-orders"], instances=[instance], security_groups=[SecurityGroup(id="sg-orders", name="orders", rules=[{"ip_ranges": ["0.0.0.0/0"]}] if public else [])]),
        s3=S3Data(total_buckets=3, buckets=[S3Bucket(name=name) for name in BUCKETS]),
        iam=IAMData(role_policies=[role or _role()], instance_profile_roles={"OrdersRole": {"role_name": "OrdersRole", "role_arn": ROLE_ARN}}),
    )


def _graph(infra):
    public = bool(infra.ec2.security_groups and infra.ec2.security_groups[0].rules)
    nodes = [
        {"id": "INTERNET", "type": "internet", "label": "Internet"},
        {"id": "i-orders", "type": "ec2_instance", "label": "EC2: i-orders"},
        {"id": "iam-role-OrdersRole", "type": "iam_role", "label": "IAM Role: OrdersRole"},
        *[{"id": name, "type": "s3_bucket", "label": f"S3: {name}"} for name in BUCKETS],
    ]
    edges = [{"from": "i-orders", "to": "iam-role-OrdersRole", "relationship": "uses_iam_role"}]
    if public:
        edges.insert(0, {"from": "INTERNET", "to": "i-orders", "relationship": "REACHES"})
    return Graph(nodes=nodes, edges=edges)


def _verdict(base, branch, monkeypatch):
    monkeypatch.setattr(diffing, "build_graph_pair", lambda before, after: (_graph(before), _graph(after)))
    monkeypatch.setattr(verdict, "build_graph", _graph)
    return verdict.combined_verdict(base, branch, run_scanners=False)


def _finding(result):
    return next(item for item in result.native_added if item["rule_id"] == "EMFIRGE-IAM-008")


def _reason(result):
    return next(item for item in result.reasons if item["code"] == "internet_to_broad_data_access")


def test_W1c_glob_covers_bucket_table():
    from app.rules import _s3_glob_covers_bucket

    cases = [
        ("cust-apps-*", "cust-apps-a", True), ("cust-apps-*", "payroll", False),
        ("cust-apps-*/*", "cust-apps-b", True), ("cust-apps-?", "cust-apps-1", True),
        ("cust-apps-?", "cust-apps-12", False), ("cust-*/logs/*", "cust-x", True),
        ("Cust-apps-*", "cust-apps-a", False), ("cust-apps-a", "cust-apps-a", True),
        ("cust-apps-a/*", "cust-apps-ab", False),
    ]
    assert all(_s3_glob_covers_bucket(pattern, bucket) is expected for pattern, bucket, expected in cases)


def _glob_regex(pattern):
    return "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern)


def test_W1c_glob_brute_force():
    from app.rules import _s3_glob_covers_bucket

    rng = random.Random(43)
    alphabet = ["a", "b", "-", "/", "*", "?"]
    bucket_alphabet = ["a", "b", "-"]
    suffixes = ("".join(chars) for length in range(5) for chars in itertools.product(["a", "b", "-", "/"], repeat=length))
    suffixes = list(suffixes)
    for _ in range(400):
        pattern = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
        bucket = "".join(rng.choice(bucket_alphabet) for _ in range(rng.randint(1, 3)))
        regex = _glob_regex(pattern)
        oracle = bool(re.fullmatch(regex, bucket, flags=re.DOTALL)) or any(re.fullmatch(regex, bucket + "/" + suffix, flags=re.DOTALL) for suffix in suffixes)
        assert _s3_glob_covers_bucket(pattern, bucket) is oracle, (pattern, bucket)


@pytest.mark.parametrize("resource", ["arn:aws:s3:::cust-apps-*", "arn:aws:s3:::cust-apps-*/*"])
def test_W1c_typed_wildcard_blocks_and_names_path(resource, monkeypatch):
    result = _verdict(_infra(), _infra(public=True, role=_role(resource)), monkeypatch)
    assert result.verdict == "block"
    finding = _finding(result)
    assert finding["resource_id"] == "i-orders"
    assert finding["metadata"]["matched_buckets"] == ["cust-apps-a", "cust-apps-b"]
    reason = _reason(result)
    assert reason["resources"] == ["i-orders", "iam-role-OrdersRole", "cust-apps-a", "cust-apps-b"]
    assert "-> role -> 2 buckets" in reason["message"]
    assert not any(identifier in reason["message"] for identifier in ("i-orders", "iam-role-OrdersRole", "cust-apps-a", "cust-apps-b", "payroll"))


def test_W1c_wildcard_matching_no_bucket_no_finding(monkeypatch):
    result = _verdict(_infra(), _infra(public=True, role=_role("arn:aws:s3:::zzz-*")), monkeypatch)
    assert not any(item["rule_id"] == "EMFIRGE-IAM-008" for item in result.native_added)


def test_W1c_private_instance_no_finding():
    assert check_internet_to_broad_data_access(_infra(role=_role("arn:aws:s3:::cust-apps-*")), _graph(_infra())) == []


def test_W1c_service_wide_reason_unchanged(monkeypatch):
    result = _verdict(_infra(), _infra(public=True, role=_role("*")), monkeypatch)
    reason = _reason(result)
    assert reason["resources"] == ["i-orders", "iam-role-OrdersRole"]
    assert "matched_buckets" not in _finding(result)["metadata"]


def test_W1c_api_route_matches_typed(plan_client, monkeypatch):
    base = _infra(public=True, role=_role("arn:aws:s3:::payroll/*"))
    monkeypatch.setattr("app.main.get_infrastructure_for_analysis", lambda _id: base)
    monkeypatch.setattr("app.verdict.build_graph", _graph)
    monkeypatch.setattr("app.diffing.build_graph_pair", lambda before, after: (_graph(before), _graph(after)))
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "w1c-api"}).json()["branch_id"]
    typed_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "w1c-typed"}).json()["branch_id"]
    body = {"format": "aws-api-calls/1", "calls": [{"service": "iam", "operation": "PutRolePolicy", "parameters": {"RoleName": "OrdersRole", "PolicyName": "web-policy", "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::cust-apps-*"}}}}]}
    assert plan_client.post(f"/branches/{api_branch}/plans/aws-api", json=body).status_code == 200
    typed = {"op": "modify", "resource_type": "iam_role_policy", "resource_id": ROLE_ARN, "fields": {"access_statements": [
        {"effect": "allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::payroll/*"], "is_not_action": False, "is_not_resource": False, "has_condition": False},
        {"effect": "allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::cust-apps-*"], "is_not_action": False, "is_not_resource": False, "has_condition": False},
    ]}}
    assert plan_client.post(f"/branches/{typed_branch}/changes", json=typed).status_code == 200
    api_result = plan_client.get(f"/branches/{api_branch}/verdict").json()
    typed_result = plan_client.get(f"/branches/{typed_branch}/verdict").json()
    assert api_result["verdict"] == typed_result["verdict"] == "block"
    api_reason = next(item for item in api_result["reasons"] if item["code"] == "internet_to_broad_data_access")
    typed_reason = next(item for item in typed_result["reasons"] if item["code"] == "internet_to_broad_data_access")
    assert {key: api_reason[key] for key in ("code", "level", "message", "resources")} == {key: typed_reason[key] for key in ("code", "level", "message", "resources")}
    assert api_reason["resources"][-2:] == ["cust-apps-a", "cust-apps-b"]


def test_W1c_message_caps_bucket_list(monkeypatch):
    buckets = [f"cust-apps-{index:02d}" for index in range(15)]
    monkeypatch.setitem(globals(), "BUCKETS", buckets)
    base = _infra()
    branch = _infra(public=True, role=_role("arn:aws:s3:::cust-apps-*"))
    base.s3.buckets = [S3Bucket(name=name) for name in buckets]
    base.s3.total_buckets = len(buckets)
    branch.s3.buckets = [S3Bucket(name=name) for name in buckets]
    branch.s3.total_buckets = len(buckets)
    result = _verdict(base, branch, monkeypatch)
    reason = _reason(result)
    assert len(reason["resources"]) == 17
    assert "-> role -> 15 buckets" in reason["message"]
    assert "cust-apps-" not in reason["message"]


def test_W1c_native_findings_without_metadata_have_no_metadata_key(plan_client):
    finding = RiskFinding(
        rule_id="EMFIRGE-EC2-001", category="Security", severity="high",
        issue="issue", recommendation="recommendation", aws_service="EC2",
        resource_id="i-x",
    )
    assert "metadata" not in verdict._native_finding(finding)
    with_metadata = finding.model_copy(update={"metadata": {"role_id": "r"}})
    assert verdict._native_finding(with_metadata)["metadata"] == {"role_id": "r"}
