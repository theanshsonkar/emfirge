import copy

from app.cost import (
    ALB_HOURLY_USD,
    EC2_HOURLY_USD,
    EBS_GP3_GB_MONTH_USD,
    HOURS_PER_MONTH,
    NAT_GATEWAY_HOURLY_USD,
    cost_delta,
    estimate_monthly_cost,
)
from app.models import (
    AWSInfrastructure,
    EC2Data,
    EC2Instance,
    EBSVolume,
    ElasticIP,
    LambdaData,
    LambdaFunction,
    LoadBalancer,
    RDSData,
    RDSInstance,
    S3Bucket,
    S3Data,
    VPCData,
)


def _infra(**kwargs):
    return AWSInfrastructure(region="us-east-1", **kwargs)


def test_t3_micro_uses_curated_hourly_rate():
    estimate = estimate_monthly_cost(_infra(ec2=EC2Data(instances=[
        EC2Instance(id="i-1", type="t3.micro", state="running"),
    ])))
    assert estimate.total_monthly_usd == round(EC2_HOURLY_USD["t3.micro"] * HOURS_PER_MONTH, 2)
    assert estimate.resources[0].basis == "provisioned-estimate"


def test_s3_and_lambda_are_unknown_and_excluded_from_total():
    estimate = estimate_monthly_cost(_infra(
        s3=S3Data(buckets=[S3Bucket(name="bucket")]),
        lambda_data=LambdaData(functions=[LambdaFunction(name="handler")]),
    ))
    assert estimate.total_monthly_usd == 0
    assert estimate.unknown_count == 2
    assert all(item.monthly_usd is None for item in estimate.resources)
    assert {item.basis for item in estimate.resources} == {"usage-based-unknown"}


def test_exotic_ec2_and_rds_are_price_unavailable():
    estimate = estimate_monthly_cost(_infra(
        ec2=EC2Data(instances=[EC2Instance(id="i-exotic", type="u7i.24xlarge", state="running")]),
        rds=RDSData(rds_instances=[RDSInstance(id="db-1")]),
    ))
    assert estimate.total_monthly_usd == 0
    assert {item.basis for item in estimate.resources} == {"price-unavailable"}


def test_nat_and_gp3_ebs_are_priced():
    estimate = estimate_monthly_cost(_infra(
        vpc=VPCData(nat_gateways=["nat-1"]),
        ec2=EC2Data(ebs_volumes=[EBSVolume(
            id="vol-1", size_gb=100, volume_type="gp3",
            create_time="2026-01-01", availability_zone="us-east-1a",
        )]),
    ))
    assert estimate.total_monthly_usd == round(
        NAT_GATEWAY_HOURLY_USD * HOURS_PER_MONTH + 100 * EBS_GP3_GB_MONTH_USD, 2
    )
    assert estimate.unknown_count == 0


def test_alb_has_fixed_charge_only_and_other_lb_is_unavailable():
    estimate = estimate_monthly_cost(_infra(ec2=EC2Data(load_balancers=[
        LoadBalancer(arn="arn:alb", type="application"),
        LoadBalancer(arn="arn:nlb", type="network"),
    ])))
    assert estimate.total_monthly_usd == round(ALB_HOURLY_USD * HOURS_PER_MONTH, 2)
    assert next(item for item in estimate.resources if item.resource_id == "arn:alb").basis == "provisioned-estimate"
    assert next(item for item in estimate.resources if item.resource_id == "arn:nlb").basis == "price-unavailable"


def test_ec2_add_delete_delta_reports_stable_records():
    base = _infra(ec2=EC2Data(instances=[EC2Instance(id="i-old", type="t3.micro", state="running")]))
    branch = _infra(ec2=EC2Data(instances=[EC2Instance(id="i-new", type="t3.small", state="running")]))
    delta = cost_delta(base, branch)
    assert delta.monthly_delta_usd == round(
        (EC2_HOURLY_USD["t3.small"] - EC2_HOURLY_USD["t3.micro"]) * HOURS_PER_MONTH, 2
    )
    assert [(item.resource_type, item.resource_id) for item in delta.added_cost] == [("ec2_instance", "i-new")]
    assert [(item.resource_type, item.resource_id) for item in delta.removed_cost] == [("ec2_instance", "i-old")]


def test_s3_only_delta_is_zero_but_explicitly_incomplete():
    base = _infra(s3=S3Data(buckets=[S3Bucket(name="bucket")]))
    delta = cost_delta(base, _infra())
    assert delta.monthly_delta_usd == 0
    assert delta.base_total == delta.branch_total == 0
    assert delta.added_cost == []
    assert [(item.resource_type, item.resource_id) for item in delta.removed_cost] == [("s3_bucket", "bucket")]
    assert any("base: s3_bucket/bucket" in note and "incomplete/unknown" in note for note in delta.unknown_notes)


def test_estimate_is_deterministic_and_does_not_mutate_input():
    infra = _infra(
        ec2=EC2Data(
            instances=[EC2Instance(id="i-2", type="t3.micro", state="running"),
                       EC2Instance(id="i-1", type="t3.micro", state="running")],
        ),
        vpc=VPCData(nat_gateways=["nat-2", "nat-1"]),
    )
    before = copy.deepcopy(infra).model_dump()
    first = estimate_monthly_cost(infra)
    second = estimate_monthly_cost(infra)
    assert first.model_dump() == second.model_dump()
    assert infra.model_dump() == before
    assert [(item.resource_type, item.resource_id) for item in first.resources] == [
        ("ec2_instance", "i-1"), ("ec2_instance", "i-2"),
        ("nat_gateway", "nat-1"), ("nat_gateway", "nat-2"),
    ]


def test_unsupported_elastic_ip_is_counted_and_reported_in_delta():
    base = _infra()
    branch = _infra(ec2=EC2Data(elastic_ips=[ElasticIP(
        allocation_id="eipalloc-1", public_ip="203.0.113.10", is_attached=False,
    )]))

    estimate = estimate_monthly_cost(branch)
    assert estimate.unknown_count == 1
    assert [(item.resource_type, item.resource_id, item.basis) for item in estimate.resources] == [
        ("elastic_ip", "eipalloc-1", "price-unavailable"),
    ]

    delta = cost_delta(base, branch)
    assert any("branch: elastic_ip/eipalloc-1" in note for note in delta.unknown_notes)
