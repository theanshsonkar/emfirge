import pytest

from app import diffing, verdict
from app.egraph import Graph
from app.models import AccessStatement, AWSInfrastructure, EC2Data, EC2Instance, IAMData, RolePolicy, SecurityGroup
from app.rules import _broad_statement, _service_wide_resource, check_internet_to_broad_data_access


def _role(action="s3:GetObject", resource="*", *, condition=False, effect="Allow"):
    return RolePolicy(role_name="OrdersRole", role_arn="arn:aws:iam::123:role/OrdersRole", access_statements=[AccessStatement(effect=effect, actions=[action], resources=[resource], has_condition=condition)])


def _infra(*, public=False, role=None, action="s3:GetObject", resource="*", condition=False, effect="Allow"):
    role = role or _role(action, resource, condition=condition, effect=effect)
    instance = EC2Instance(id="i-orders", type="t3.micro", state="running", instance_profile_arn="arn:aws:iam::123:instance-profile/OrdersRole")
    if public:
        instance.sg_ids = ["sg-orders"]
    return AWSInfrastructure(region="us-east-1", ec2=EC2Data(instance_count=1, instance_ids=["i-orders"], instances=[instance], security_groups=[SecurityGroup(id="sg-orders", name="orders", rules=[{"ip_ranges":["0.0.0.0/0"]}] if public else [])]), iam=IAMData(role_policies=[role], instance_profile_roles={"OrdersRole": {"role_name": "OrdersRole", "role_arn": role.role_arn}}))


def _graph(infra):
    public = bool(infra.ec2.security_groups and infra.ec2.security_groups[0].rules)
    nodes = [{"id": "INTERNET", "type": "internet", "label": "Internet"}, {"id": "i-orders", "type": "ec2_instance", "label": "EC2: i-orders"}, {"id": "iam-role-OrdersRole", "type": "iam_role", "label": "IAM Role: OrdersRole"}]
    edges = [{"from": "i-orders", "to": "iam-role-OrdersRole", "relationship": "uses_iam_role"}]
    if public:
        edges.insert(0, {"from": "INTERNET", "to": "i-orders", "relationship": "REACHES"})
    return Graph(nodes=nodes, edges=edges)


def _verdict(base, branch, monkeypatch):
    monkeypatch.setattr(diffing, "build_graph_pair", lambda base, branch: (_graph(base), _graph(branch)))
    monkeypatch.setattr(verdict, "build_graph", _graph)
    return verdict.combined_verdict(base, branch, run_scanners=False)


def test_L43a_internet_ec2_gains_s3_star(monkeypatch):
    result = _verdict(_infra(public=False), _infra(public=True), monkeypatch)
    assert result.verdict == "block"
    finding = next(item for item in result.native_added if item["rule_id"] == "EMFIRGE-IAM-008")
    assert finding["resource_id"] == "i-orders"
    reason = next(item for item in result.reasons if item["code"] == "internet_to_broad_data_access")
    assert reason["resources"] == ["i-orders", "iam-role-OrdersRole"]


def test_L43b_private_ec2_no_finding():
    assert check_internet_to_broad_data_access(_infra(), _graph(_infra())) == []


def test_L43c_scoped_bucket_no_finding():
    statement = AccessStatement(effect="Allow", actions=["s3:GetObject"], resources=["arn:aws:s3:::one-bucket/*"])
    assert _broad_statement(statement) is None
    assert not _service_wide_resource("arn:aws:s3:::one-bucket/*")


def test_L43d_getobject_on_star():
    assert _broad_statement(AccessStatement(effect="Allow", actions=["s3:GetObject"], resources=["*"]))


def test_L43e_dynamodb_table_wildcard():
    assert _broad_statement(AccessStatement(effect="Allow", actions=["dynamodb:*"], resources=["arn:aws:dynamodb:*:*:table/*"]))


def test_L43f_not_action_allow():
    assert _broad_statement(AccessStatement(effect="Allow", is_not_action=True, resources=["*"]))


def test_L43g_condition_is_high_and_warn(monkeypatch):
    result = _verdict(_infra(public=False), _infra(public=True, condition=True), monkeypatch)
    finding = next(item for item in result.native_added if item["rule_id"] == "EMFIRGE-IAM-008")
    assert finding["severity"] == "high"
    reason = next(item for item in result.reasons if item["code"] == "internet_to_broad_data_access")
    assert reason["level"] == "warn"
    assert result.verdict != "block"


def test_L43h_preexisting_not_introduced(monkeypatch):
    result = _verdict(_infra(public=True), _infra(public=True), monkeypatch)
    assert not any(item["rule_id"] == "EMFIRGE-IAM-008" for item in result.native_added)


def test_L43i_sg_opened_makes_it_introduced(monkeypatch):
    result = _verdict(_infra(public=False), _infra(public=True), monkeypatch)
    assert result.verdict == "block"
    assert any(item["code"] == "internet_to_broad_data_access" for item in result.reasons)


@pytest.mark.xfail(strict=True, reason="The current graph builder has no modeled Lambda internet-reachability path")
def test_L43j_internet_lambda():
    pytest.xfail("No modeled Lambda internet-reachability path")


def test_L43k_deny_no_finding():
    assert _broad_statement(AccessStatement(effect="Deny", actions=["s3:GetObject"], resources=["*"])) is None
