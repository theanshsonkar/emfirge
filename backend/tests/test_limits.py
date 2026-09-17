from app.limits import DEFAULT_QUOTAS, limit_checks, limits_delta
from app.models import (
    AWSInfrastructure,
    EC2Data,
    EC2Instance,
    ElasticIP,
    LambdaData,
    LambdaFunction,
    SecurityGroup,
    VPCData,
    VPCSubnet,
)


def _finding(items, check, scope):
    return next(item for item in items if item.check == check and item.scope == scope)


def _infra(**kwargs):
    return AWSInfrastructure(region="us-east-1", **kwargs)


def test_subnet_capacity_uses_reserved_five_and_unique_observed_ids():
    infra = _infra(
        ec2=EC2Data(instances=[EC2Instance(id="i-1", type="t3.micro", state="running", subnet_id="subnet-1")]),
        lambda_data=LambdaData(functions=[LambdaFunction(name="fn-1", subnet_ids=["subnet-1"])]),
        vpc=VPCData(subnets=[VPCSubnet(
            id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/28",
            resources=["i-1"]
        )]),
    )
    finding = _finding(limit_checks(infra), "subnet_ip_capacity", "subnet-1")
    assert (finding.current, finding.limit, finding.status) == (2, 11, "ok")
    assert "5 reserved" in finding.basis


def test_subnet_capacity_marks_equal_usable_capacity_exceeded_and_large_subnet_near():
    resources = [f"resource-{i}" for i in range(11)]
    small = _infra(vpc=VPCData(subnets=[VPCSubnet(
        id="small", vpc_id="vpc-1", cidr="10.0.0.0/28", resources=resources
    )]))
    assert _finding(limit_checks(small), "subnet_ip_capacity", "small").status == "exceeded"

    large = _infra(vpc=VPCData(subnets=[VPCSubnet(
        id="large", vpc_id="vpc-1", cidr="10.0.1.0/24",
        resources=[f"resource-{i}" for i in range(201)]
    )]))
    finding = _finding(limit_checks(large), "subnet_ip_capacity", "large")
    assert (finding.current, finding.limit, finding.status) == (201, 251, "near")


def test_requested_quota_checks_and_conservative_nat_basis():
    infra = _infra(
        ec2=EC2Data(
            elastic_ips=[ElasticIP(allocation_id=f"eip-{i}", public_ip=f"192.0.2.{i}", is_attached=False) for i in range(6)],
            security_groups=[SecurityGroup(
                id="sg-1", name="main", rules=[{}] * 61, egress_rules=[{}] * 48,
            )],
        ),
        vpc=VPCData(total_vpcs=5, nat_gateways=["nat-1", "nat-2"]),
    )
    findings = limit_checks(infra)
    assert _finding(findings, "eips_per_region", "region").status == "exceeded"
    assert _finding(findings, "rules_per_sg_inbound", "sg-1").status == "exceeded"
    assert _finding(findings, "rules_per_sg_outbound", "sg-1").status == "near"
    nat = _finding(findings, "nat_gateways_per_az", "region")
    assert "AZ unknown" in nat.basis or "availability zone is unknown" in nat.basis
    assert _finding(findings, "lambda_concurrent_executions", "region").status == "unknown"
    assert DEFAULT_QUOTAS["eips_per_region"] == 5


def test_missing_cidr_and_missing_vpc_id_are_unknown():
    infra = _infra(vpc=VPCData(subnets=[
        VPCSubnet(id="no-cidr", vpc_id="vpc-1"),
        VPCSubnet(id="no-vpc", vpc_id="", cidr="10.0.0.0/24"),
    ]))
    findings = limit_checks(infra)
    assert _finding(findings, "subnet_ip_capacity", "no-cidr").status == "unknown"
    assert _finding(findings, "subnets_per_vpc", "unknown-vpc").status == "unknown"


def test_subnets_group_by_vpc_and_sgs_per_eni_is_checked():
    infra = _infra(
        ec2=EC2Data(instances=[EC2Instance(
            id="i-1", type="t3.micro", state="running", sg_ids=[f"sg-{i}" for i in range(5)]
        )]),
        vpc=VPCData(subnets=[
            VPCSubnet(id="a", vpc_id="vpc-2"),
            VPCSubnet(id="b", vpc_id="vpc-1"),
            VPCSubnet(id="c", vpc_id="vpc-2"),
        ]),
    )
    findings = limit_checks(infra)
    assert _finding(findings, "subnets_per_vpc", "vpc-2").current == 2
    assert _finding(findings, "sgs_per_eni", "i-1").status == "near"


def test_sixth_eip_is_introduced_in_delta_and_unknown_is_not_resolution():
    base = _infra()
    branch = _infra(ec2=EC2Data(elastic_ips=[
        ElasticIP(allocation_id=f"eip-{i}", public_ip=f"192.0.2.{i}", is_attached=False)
        for i in range(6)
    ]))
    delta = limits_delta(base, branch)
    assert [(item.check, item.scope) for item in delta.introduced] == [("eips_per_region", "region")]
    assert delta.resolved == []
    assert any("Unknown check/scope" in note for note in delta.notes)


def test_unknown_base_to_exceeded_branch_is_not_introduced():
    base = _infra(vpc=VPCData(subnets=[VPCSubnet(id="subnet-1", vpc_id="vpc-1")]))
    branch = _infra(vpc=VPCData(subnets=[VPCSubnet(
        id="subnet-1", vpc_id="vpc-1", cidr="10.0.0.0/30", resources=["resource-1"]
    )]))

    delta = limits_delta(base, branch)

    assert delta.introduced == []
    assert any("Unknown check/scope: subnet_ip_capacity/subnet-1" in note for note in delta.notes)


def test_checks_are_deterministic_and_have_no_forecasting_vocabulary():
    infra = _infra(vpc=VPCData(subnets=[
        VPCSubnet(id="z", vpc_id="vpc-z"), VPCSubnet(id="a", vpc_id="vpc-a")
    ]))
    first = [item.model_dump() for item in limit_checks(infra)]
    second = [item.model_dump() for item in limit_checks(infra)]
    assert first == second
    output = str(first).lower()
    for forbidden in ("users", "latency", "requests", "throughput", "forecast"):
        assert forbidden not in output
