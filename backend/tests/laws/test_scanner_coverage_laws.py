"""L65 scanner coverage: IAM roles and their policies, KMS keys, the CloudTrail trail, Lambda functions, VPCs and subnets, and security-group peers reach the scanners with exactly the values the model holds; what it cannot know (the trust document, a key's rotation state, a VPC's flow logs, a Condition) is reported, never guessed, and findings that read it are skipped."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import scanners
from app.models import (
    AWSInfrastructure, AccessStatement, CloudTrailData, EC2Data, IAMData, KMSData, LambdaData, LambdaFunction,
    PolicyDocumentRecord, RolePolicy, SecurityGroup, VPCData, VPCSubnet,
)
from app.serializer import (
    CLOUDTRAIL, FIELD_MAP, KMS_KEY, LAMBDA_FUNCTION, ROLE_POLICY, TF_TO_EMFIRGE, UNMODELED, VPC, VPC_SUBNET,
    attribute_fields, build_terraform, terraform_name,
)

ROLE_ARN = "arn:aws:iam::123456789012:role/app"
TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
GET = AccessStatement(effect="allow", actions=["s3:GetObject"], resources=["arn:aws:s3:::b/*"])


def _role(name="app", statements=(GET,), documents=True, names=("p",), **fields) -> RolePolicy:
    statements = [st.model_copy(deep=True) for st in statements]
    return RolePolicy(
        role_name=name, role_arn=f"arn:aws:iam::123456789012:role/{name}", access_statements=statements,
        policy_documents=[PolicyDocumentRecord(name="p", kind="inline", statements=statements)] if documents else None,
        policy_names=list(names), **fields,
    )


def _resources(out, tf_type):
    return out.tf["resource"].get(tf_type, {})


def _omitted(out, resource_type, rid=None):
    return [e for e in out.loss if e.get("kind") == "omitted_field" and e["resource_type"] == resource_type
            and (rid is None or e["id"] == rid)]


def _stub_finding(monkeypatch, infra, tf_type, resource_type, rid, check_id):
    scanners.clear_scan_cache()
    out = build_terraform(infra)
    name = next(n for n, (t, i) in out.names.items() if t == resource_type and i == rid and n in _resources(out, tf_type))
    stdout = json.dumps({"results": {"failed_checks": [{
        "check_id": check_id, "resource": f"resource.{name}", "check_name": "stub",
    }]}})
    monkeypatch.setattr("app.scanners.subprocess.run", lambda *a, **k: SimpleNamespace(stdout=stdout, returncode=1))


# --- IAM -------------------------------------------------------------------------------------------------------


def test_L65a_role_policy_carries_exactly_the_kept_statements():
    statements = [
        AccessStatement(effect="allow", actions=["s3:GetObject", "s3:ListBucket"], resources=["arn:aws:s3:::b", "arn:aws:s3:::b/*"]),
        AccessStatement(effect="deny", actions=["iam:*"], resources=["*"]),
        AccessStatement(effect="allow", actions=["ec2:*"], resources=["arn:aws:ec2:*:*:instance/i-1"], is_not_action=True),
        AccessStatement(effect="allow", actions=["s3:PutObject"], resources=["arn:aws:s3:::b/x"], is_not_resource=True),
    ]
    out = build_terraform(AWSInfrastructure(iam=IAMData(role_policies=[_role(statements=statements)])))
    (role,) = _resources(out, "aws_iam_role").items()
    (policy,) = _resources(out, "aws_iam_role_policy").values()
    assert role[1] == {"name": "app"}
    assert policy["role"] == f"${{aws_iam_role.{role[0]}.id}}"
    assert json.loads(policy["policy"]) == {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
        {"Effect": "Deny", "Action": ["iam:*"], "Resource": ["*"]},
        {"Effect": "Allow", "NotAction": ["ec2:*"], "Resource": ["arn:aws:ec2:*:*:instance/i-1"]},
        {"Effect": "Allow", "Action": ["s3:PutObject"], "NotResource": ["arn:aws:s3:::b/x"]},
    ]}  # no Version, Sid or Condition is invented
    assert not [e for e in _omitted(out, ROLE_POLICY) if e["field"] == "access_statements"]


def test_L65a_role_without_statements_has_no_policy_resource():
    out = build_terraform(AWSInfrastructure(iam=IAMData(role_policies=[_role(statements=[], names=[], trusted_services=["ec2.amazonaws.com"])])))
    assert "aws_iam_role_policy" not in out.tf["resource"] and "aws_iam_role" in out.tf["resource"]


def test_L65b_trust_policy_is_reported_lost_and_not_emitted():
    role = _role(trusted_services=["lambda.amazonaws.com"], trusted_role_arns=["arn:aws:iam::1:role/x"],
                 trust_allows_external=True, trust_has_conditions=True)
    out = build_terraform(AWSInfrastructure(iam=IAMData(role_policies=[role])))
    (args,) = _resources(out, "aws_iam_role").values()
    assert "assume_role_policy" not in args
    fields = {e["field"] for e in _omitted(out, ROLE_POLICY, "app")}
    assert {"assume_role_policy", "trusted_role_arns", "trusted_services", "trust_allows_external",
            "trust_has_conditions", "trust_external_unrestricted"} <= fields
    assert "assume_role_policy" in UNMODELED["aws_iam_role"]


@pytest.mark.parametrize("role, reason", [
    (_role(statements=[AccessStatement(effect="allow", actions=["*"], resources=["*"], has_condition=True)]), "Condition"),
    (_role(documents=False), "breakdown not recorded"),
    (_role(names=("p", "managed-x")), "managed-x"),
    (_role(has_admin=True), "administrator"),
])
def test_L65c_incomplete_policy_is_reported_against_access_statements(role, reason):
    out = build_terraform(AWSInfrastructure(iam=IAMData(role_policies=[role])))
    reasons = [e["reason"] for e in _omitted(out, ROLE_POLICY, role.role_name) if e["field"] == "access_statements"]
    assert any(reason in r for r in reasons), reasons
    assert "aws_iam_role_policy" in out.tf["resource"]  # still emitted from what is known


def test_L65c_policy_reading_findings_are_skipped_when_a_condition_was_not_kept(monkeypatch):
    # Read-attributes come from the crosswalk; stand in a policy-reading row.
    monkeypatch.setattr(scanners, "check_reads", lambda: {"CKV_AWS_STUB": ("aws_iam_role_policy", ("policy",))})
    assert "policy" in attribute_fields("aws_iam_role_policy")
    conditioned = AWSInfrastructure(iam=IAMData(role_policies=[_role(
        statements=[AccessStatement(effect="allow", actions=["*"], resources=["*"], has_condition=True)])]))
    _stub_finding(monkeypatch, conditioned, "aws_iam_role_policy", ROLE_POLICY, "app", "CKV_AWS_STUB")
    result = scanners.run_checkov(conditioned)
    assert result.findings == []
    assert result.skipped == [{"check_id": "CKV_AWS_STUB", "resource_type": ROLE_POLICY, "id": "app", "inputs": ["policy"]}]
    plain = AWSInfrastructure(iam=IAMData(role_policies=[_role(
        statements=[AccessStatement(effect="allow", actions=["*"], resources=["*"])])]))
    _stub_finding(monkeypatch, plain, "aws_iam_role_policy", ROLE_POLICY, "app", "CKV_AWS_STUB")
    result = scanners.run_checkov(plain)
    assert [f.check_id for f in result.findings] == ["CKV_AWS_STUB"] and result.skipped == []


# --- KMS and CloudTrail ----------------------------------------------------------------------------------------


def test_L65d_kms_emits_only_keys_known_without_rotation():
    infra = AWSInfrastructure(kms=KMSData(total_cmks=4, cmks_without_rotation=["key-a", "key-b"], cmks_pending_deletion=["key-p"]))
    out = build_terraform(infra)
    keys = _resources(out, "aws_kms_key")
    assert sorted(out.names[n][1] for n in keys) == ["key-a", "key-b"]
    assert all(args == {"enable_key_rotation": False} for args in keys.values())
    omitted = {(e["id"], e["reason"]) for e in out.loss if e.get("kind") == "omitted_resource" and e["resource_type"] == KMS_KEY}
    assert any(i == "key-p" and "rotation state unknown" in r for i, r in omitted)
    assert any(i == "unlisted" and r.startswith("1 customer-managed key") for i, r in omitted)  # 4 - 2 - 1
    assert "aws_kms_key" not in build_terraform(AWSInfrastructure(kms=KMSData(total_cmks=2))).tf["resource"]


def test_L65d_unknown_key_rotation_is_never_emitted_as_enabled():
    out = build_terraform(AWSInfrastructure(kms=KMSData(total_cmks=3, cmks_without_rotation=["k"])))
    assert [a.get("enable_key_rotation") for a in _resources(out, "aws_kms_key").values()] == [False]


def test_L65e_cloudtrail_emits_only_what_is_known():
    out = build_terraform(AWSInfrastructure(cloudtrail=CloudTrailData(is_enabled=True, trail_arn=TRAIL_ARN)))
    (args,) = _resources(out, "aws_cloudtrail").values()
    assert args == {"name": "main", "enable_logging": True, "is_multi_region_trail": False, "enable_log_file_validation": False}
    unmodeled = {e["field"] for e in _omitted(out, CLOUDTRAIL)}
    assert set(UNMODELED["aws_cloudtrail"]) <= unmodeled and not {"is_multi_region", "has_log_file_validation"} & unmodeled


def test_L65e_cloudtrail_true_flags_are_aggregates_and_not_attributed_to_the_trail():
    out = build_terraform(AWSInfrastructure(cloudtrail=CloudTrailData(
        is_enabled=True, is_multi_region=True, has_log_file_validation=True, trail_arn=TRAIL_ARN)))
    (args,) = _resources(out, "aws_cloudtrail").values()
    assert "is_multi_region_trail" not in args and "enable_log_file_validation" not in args
    assert {"is_multi_region", "has_log_file_validation"} <= {e["field"] for e in _omitted(out, CLOUDTRAIL)}


def test_L65e_no_trail_arn_means_no_trail_resource_but_state_is_reported():
    assert "aws_cloudtrail" not in build_terraform(AWSInfrastructure()).tf["resource"]
    out = build_terraform(AWSInfrastructure(cloudtrail=CloudTrailData(is_multi_region=True)))
    assert "aws_cloudtrail" not in out.tf["resource"]
    assert [e for e in out.loss if e.get("kind") == "omitted_resource" and e["resource_type"] == CLOUDTRAIL]


@pytest.mark.parametrize("flags, check_id, kept", [
    ({}, "CKV_AWS_36", True),
    ({"has_log_file_validation": True}, "CKV_AWS_36", False),
])
def test_L65e_log_validation_finding_is_skipped_when_the_flag_is_not_attributable(monkeypatch, flags, check_id, kept):
    infra = AWSInfrastructure(cloudtrail=CloudTrailData(is_enabled=True, trail_arn=TRAIL_ARN, **flags))
    _stub_finding(monkeypatch, infra, "aws_cloudtrail", CLOUDTRAIL, TRAIL_ARN, check_id)
    result = scanners.run_checkov(infra)
    assert bool(result.findings) is kept and bool(result.skipped) is not kept


# --- Lambda, VPC, subnets --------------------------------------------------------------------------------------


def _network(**lambda_fields) -> AWSInfrastructure:
    return AWSInfrastructure(
        iam=IAMData(role_policies=[_role()]),
        ec2=EC2Data(security_groups=[SecurityGroup(id="sg-1", name="n")]),
        vpc=VPCData(total_vpcs=1, vpcs_without_flow_logs=["vpc-1"], subnets=[
            VPCSubnet(id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/24", availability_zone="us-east-1a")]),
        lambda_data=LambdaData(functions=[LambdaFunction(name="fn", **lambda_fields)]),
    )


def test_L65f_lambda_links_role_subnets_and_groups_by_reference():
    out = build_terraform(_network(role_arn=ROLE_ARN, vpc_id="vpc-1", subnet_ids=["subnet-1"], sg_ids=["sg-1"]))
    (fn,) = _resources(out, "aws_lambda_function").values()
    (role,) = _resources(out, "aws_iam_role")
    (subnet,) = _resources(out, "aws_subnet")
    (sg,) = _resources(out, "aws_security_group")
    assert fn["function_name"] == "fn" and fn["role"] == f"${{aws_iam_role.{role}.arn}}"
    assert fn["vpc_config"] == [{
        "subnet_ids": [f"${{aws_subnet.{subnet}.id}}"], "security_group_ids": [f"${{aws_security_group.{sg}.id}}"],
    }]
    assert set(UNMODELED["aws_lambda_function"]) <= {e["field"] for e in _omitted(out, LAMBDA_FUNCTION, "fn")}
    assert "runtime" not in fn and "environment" not in fn


def test_L65f_lambda_outside_the_input_stays_literal_and_without_vpc_has_no_vpc_config():
    out = build_terraform(_network(role_arn="arn:aws:iam::1:role/other"))
    (fn,) = _resources(out, "aws_lambda_function").values()
    assert fn["role"] == "arn:aws:iam::1:role/other" and "vpc_config" not in fn
    out = build_terraform(_network(role_arn="", subnet_ids=["subnet-x"]))
    (fn,) = _resources(out, "aws_lambda_function").values()
    assert "role" not in fn and fn["vpc_config"] == [{"subnet_ids": ["subnet-x"]}]
    assert "role_arn" in {e["field"] for e in _omitted(out, LAMBDA_FUNCTION, "fn")}


def test_L65g_vpc_and_subnet_emit_known_values_only():
    out = build_terraform(_network())
    (vpc,) = [n for n, (t, i) in out.names.items() if t == VPC and i == "vpc-1"]
    assert _resources(out, "aws_vpc")[vpc] == {}  # nothing about the VPC beyond its id is known
    (subnet,) = _resources(out, "aws_subnet").values()
    assert subnet == {"vpc_id": f"${{aws_vpc.{vpc}.id}}", "cidr_block": "10.0.0.0/24", "availability_zone": "us-east-1a"}
    assert "map_public_ip_on_launch" not in subnet
    assert "map_public_ip_on_launch" in {e["field"] for e in _omitted(out, VPC_SUBNET, "subnet-1")}
    assert "cidr_block" in {e["field"] for e in _omitted(out, VPC, "vpc-1")}


def test_L65g_flow_log_state_is_known_only_for_vpcs_listed_without_flow_logs():
    infra = AWSInfrastructure(vpc=VPCData(total_vpcs=3, vpcs_without_flow_logs=["vpc-bad"], subnets=[
        VPCSubnet(id="s1", vpc_id="vpc-bad"), VPCSubnet(id="s2", vpc_id="vpc-other")]))
    out = build_terraform(infra)
    assert "aws_flow_log" not in out.tf["resource"]  # never emitted: no flow-log list exists
    unknown = {e["id"] for e in _omitted(out, VPC) if e["field"] == "flow_logs"}
    assert unknown == {"vpc-other"}  # absent from the without-list is not "has flow logs"
    assert [e for e in out.loss if e.get("kind") == "omitted_resource" and e["resource_type"] == VPC and "1 VPC" in e["reason"]]
    assert "aws_subnet" in out.tf["resource"] and len(_resources(out, "aws_subnet")) == 2
    assert VPC_SUBNET in {e["resource_type"] for e in out.loss if e["id"] == "s1"}  # AZ and CIDR not collected


@pytest.mark.parametrize("vpc_id, kept", [("vpc-bad", True), ("vpc-other", False)])
def test_L65g_flow_log_finding_is_kept_only_where_absence_is_known(monkeypatch, vpc_id, kept):
    infra = AWSInfrastructure(vpc=VPCData(total_vpcs=2, vpcs_without_flow_logs=["vpc-bad"], subnets=[
        VPCSubnet(id="s1", vpc_id="vpc-bad"), VPCSubnet(id="s2", vpc_id="vpc-other")]))
    _stub_finding(monkeypatch, infra, "aws_vpc", VPC, vpc_id, "CKV2_AWS_11")
    result = scanners.run_checkov(infra)
    assert bool(result.findings) is kept
    assert result.skipped == ([] if kept else [{"check_id": "CKV2_AWS_11", "resource_type": VPC, "id": vpc_id, "inputs": ["aws_flow_log"]}])


def test_L65h_new_crosswalk_rows_read_attributes_the_serializer_marks_unknown():
    rows = scanners._crosswalk_rows()
    wanted = {"CKV_AWS_7": "aws_kms_key", "CKV_AWS_36": "aws_cloudtrail", "CKV2_AWS_11": "aws_vpc", "CKV_AWS_117": "aws_lambda_function"}
    for check_id, tf_type in wanted.items():
        assert rows[check_id]["tf_type"] == tf_type and rows[check_id]["reads"]
        assert tf_type in TF_TO_EMFIRGE and FIELD_MAP[TF_TO_EMFIRGE[tf_type]]
    assert rows["CKV_AWS_7"]["severity"] == "high" and rows["CKV_AWS_117"]["severity"] == "low"


# --- Security groups -------------------------------------------------------------------------------------------


def _sg_infra(rules=(), egress=(), peers=("sg-b",)) -> AWSInfrastructure:
    groups = [SecurityGroup(id="sg-a", name="a", rules=list(rules), egress_rules=list(egress))]
    groups += [SecurityGroup(id=p, name=p) for p in peers]
    return AWSInfrastructure(ec2=EC2Data(security_groups=groups))


def test_L65i_peer_security_groups_are_references_self_or_literals():
    rule = {"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": [], "source_sg_ids": ["sg-b", "sg-a", "sg-zzz"]}
    out = build_terraform(_sg_infra([rule]))
    b = terraform_name("aws_security_group", "security_group", "sg-b")
    a = next(iter(k for k, v in out.names.items() if v == ("security_group", "sg-a")))
    (ingress,) = _resources(out, "aws_security_group")[a]["ingress"]
    assert ingress["security_groups"] == [f"${{aws_security_group.{b}.id}}", "sg-zzz"] and ingress["self"] is True
    assert not [e for e in out.loss if e.get("field") == "rules"]


def test_L65i_peers_beside_address_ranges_get_their_own_block():
    rule = {"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": ["sg-a"]}
    out = build_terraform(_sg_infra([rule]))
    (group,) = [v for k, v in _resources(out, "aws_security_group").items() if out.names[k][1] == "sg-a"]
    world = [b for b in group["ingress"] if b.get("cidr_blocks")]
    peer = [b for b in group["ingress"] if b.get("self")]
    assert world == [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
    assert peer == [{"from_port": 22, "to_port": 22, "protocol": "tcp", "self": True}]


def test_L65i_egress_peers_ipv6_and_all_protocol_ports():
    out = build_terraform(_sg_infra(
        rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["::/0", "10.0.0.0/8"], "source_sg_ids": []}],
        egress=[{"protocol": "-1", "ip_ranges": [], "dest_sg_ids": ["sg-b"]}],
    ))
    (group,) = [v for k, v in _resources(out, "aws_security_group").items() if out.names[k][1] == "sg-a"]
    assert group["ingress"][0]["ipv6_cidr_blocks"] == ["::/0"] and group["ingress"][0]["cidr_blocks"] == ["10.0.0.0/8"]
    b = terraform_name("aws_security_group", "security_group", "sg-b")
    assert group["egress"] == [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": [],
                                "security_groups": [f"${{aws_security_group.{b}.id}}"]}]


def test_L65i_ssh_findings_on_collector_shaped_rules_are_no_longer_skipped(monkeypatch):
    rule = {"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []}
    infra = _sg_infra([rule])
    _stub_finding(monkeypatch, infra, "aws_security_group", "security_group", "sg-a", "CKV_AWS_24")
    result = scanners.run_checkov(infra)
    assert [f.check_id for f in result.findings] == ["CKV_AWS_24"] and result.skipped == []


# --- Scan scope ------------------------------------------------------------------------------------------------


def _scope(base, branch):
    built = build_terraform(base)
    built.names.update(build_terraform(branch).names)
    return {built.names[n] for n in scanners.plan_scan_scope(base, branch).names}


def _tf(tf_type, resource_type, rid):
    return terraform_name(tf_type, resource_type, rid)


def test_L65j_changed_role_policy_brings_its_role_and_a_lambda_brings_role_policy_subnet_and_groups():
    base = _network(role_arn=ROLE_ARN, vpc_id="vpc-1", subnet_ids=["subnet-1"], sg_ids=["sg-1"])
    base.iam.role_policies.append(_role("other"))
    base.ec2.security_groups.append(SecurityGroup(id="sg-2", name="unrelated"))
    base.vpc.subnets.append(VPCSubnet(id="subnet-2", vpc_id="vpc-2"))
    role, policy = _tf("aws_iam_role", ROLE_POLICY, "app"), _tf("aws_iam_role_policy", ROLE_POLICY, "app")
    fn = _tf("aws_lambda_function", LAMBDA_FUNCTION, "fn")
    sg1, sg2 = (_tf("aws_security_group", "security_group", i) for i in ("sg-1", "sg-2"))
    subnet1, subnet2 = (_tf("aws_subnet", VPC_SUBNET, i) for i in ("subnet-1", "subnet-2"))
    other = {_tf("aws_iam_role", ROLE_POLICY, "other"), _tf("aws_iam_role_policy", ROLE_POLICY, "other")}

    branch = base.model_copy(deep=True)
    branch.iam.role_policies[0].access_statements[0].resources = ["arn:aws:s3:::b/new/*"]
    scope = scanners.plan_scan_scope(base, branch).names
    assert {policy, role} <= scope and not other & scope and sg2 not in scope

    branch = base.model_copy(deep=True)
    branch.lambda_data.functions[0].sg_ids = ["sg-1", "sg-2"]
    scope = scanners.plan_scan_scope(base, branch).names
    assert {fn, role, policy, sg1, sg2, subnet1} <= scope
    assert not other & scope and subnet2 not in scope


def test_L65j_changed_subnet_brings_its_vpc_and_a_changed_flow_log_its_vpc(monkeypatch):
    base = _network()
    branch = base.model_copy(deep=True)
    branch.vpc.subnets[0].cidr = "10.9.0.0/24"
    scope = _scope(base, branch)
    assert {(VPC_SUBNET, "subnet-1"), (VPC, "vpc-1")} <= scope

    vpc = terraform_name("aws_vpc", VPC, "vpc-1")
    other = terraform_name("aws_vpc", VPC, "vpc-2")
    flow = "flow_x"

    def fake_build(infra):
        resources = {"aws_vpc": {vpc: {}, other: {}}, "aws_flow_log": {flow: {"vpc_id": f"${{aws_vpc.{vpc}.id}}", "traffic_type": infra.region}}}
        return SimpleNamespace(tf={"resource": resources}, names={})

    monkeypatch.setattr(scanners, "build_terraform", fake_build)
    scope = scanners.plan_scan_scope(AWSInfrastructure(region="ACCEPT"), AWSInfrastructure(region="REJECT"))
    assert scope.names == {flow, vpc}


def test_L65j_security_group_peers_do_not_widen_the_scope():
    rule = {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": [], "source_sg_ids": ["sg-b"]}
    base = _sg_infra([rule], peers=("sg-b", "sg-c"))
    branch = base.model_copy(deep=True)
    branch.ec2.security_groups[1].name = "renamed"
    scope = _scope(base, branch)
    assert scope == {("security_group", "sg-b")}
