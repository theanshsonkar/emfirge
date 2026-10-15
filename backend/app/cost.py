"""Deterministic, embedded-price cost estimates for collected AWS infrastructure."""

from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel

from .models import AWSInfrastructure


PRICE_TABLE_REGION = "us-east-1"
PRICE_TABLE_AS_OF = "2026-09-15"
HOURS_PER_MONTH = 730
# Embedded list-price sources (all rates below are deliberately fixed snapshots):
# EC2: https://aws.amazon.com/ec2/pricing/on-demand/
# NAT Gateway: https://aws.amazon.com/vpc/pricing/
# EBS: https://aws.amazon.com/ebs/pricing/
# Application Load Balancer: https://aws.amazon.com/elasticloadbalancing/pricing/
NAT_GATEWAY_HOURLY_USD = 0.045
ALB_HOURLY_USD = 0.0225
EBS_GP3_GB_MONTH_USD = 0.08

# Curated Linux/Unix, shared-tenancy, us-east-1 on-demand rates. The table is
# intentionally small and transparent rather than a live pricing lookup.
EC2_HOURLY_USD = {
    "t3.nano": 0.0052,
    "t3.micro": 0.0104,
    "t3.small": 0.0208,
    "t3.medium": 0.0416,
    "t3.large": 0.0832,
    "t3.xlarge": 0.1664,
    "t3.2xlarge": 0.3328,
    "m5.large": 0.096,
    "m5.xlarge": 0.192,
    "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768,
    "m5.12xlarge": 2.304,
    "m5.24xlarge": 4.608,
    "c5.large": 0.085,
    "c5.xlarge": 0.17,
    "c5.2xlarge": 0.34,
    "c5.4xlarge": 0.68,
    "c5.9xlarge": 1.53,
    "c5.18xlarge": 3.06,
}

CostBasis = Literal[
    "provisioned-estimate", "usage-based-unknown", "price-unavailable", "free"
]


class ResourceCost(BaseModel):
    resource_id: str
    resource_type: str
    monthly_usd: Optional[float]
    basis: CostBasis


class CostEstimate(BaseModel):
    region_assumed: str
    as_of: str
    hours_per_month: int
    total_monthly_usd: float
    resources: List[ResourceCost]
    unknown_count: int


class CostDelta(BaseModel):
    value: Optional[float]
    status: Literal["estimated", "unknown", "n/a"]
    reason: str
    unknown_count: int
    known_provisioned_delta: Optional[float]
    currency: Literal["USD"] = "USD"


def _record(resource_id: str, resource_type: str, monthly_usd: Optional[float], basis: CostBasis) -> ResourceCost:
    return ResourceCost(
        resource_id=str(resource_id),
        resource_type=resource_type,
        monthly_usd=None if monthly_usd is None else round(monthly_usd, 2),
        basis=basis,
    )


def _resource_sort_key(resource: ResourceCost) -> Tuple[str, str]:
    return resource.resource_type, resource.resource_id


def estimate_monthly_cost(infra: AWSInfrastructure) -> CostEstimate:
    """Estimate known provisioned charges without changing ``infra``."""
    resources: List[ResourceCost] = []

    for instance in infra.ec2.instances:
        hourly = EC2_HOURLY_USD.get(instance.type)
        resources.append(_record(
            instance.id,
            "ec2_instance",
            hourly * HOURS_PER_MONTH if hourly is not None else None,
            "provisioned-estimate" if hourly is not None else "price-unavailable",
        ))

    for gateway_id in infra.vpc.nat_gateways:
        resources.append(_record(
            gateway_id, "nat_gateway", NAT_GATEWAY_HOURLY_USD * HOURS_PER_MONTH,
            "provisioned-estimate",
        ))

    for volume in infra.ec2.ebs_volumes:
        if volume.state != "available":
            continue
        monthly = None
        if volume.volume_type.lower() == "gp3" and volume.size_gb > 0:
            monthly = volume.size_gb * EBS_GP3_GB_MONTH_USD
        resources.append(_record(
            volume.id, "ebs_volume", monthly,
            "provisioned-estimate" if monthly is not None else "price-unavailable",
        ))

    for load_balancer in infra.ec2.load_balancers:
        lb_type = load_balancer.type.lower()
        is_alb = lb_type in {"application", "alb", "application/alb"}
        resources.append(_record(
            load_balancer.arn,
            "load_balancer",
            ALB_HOURLY_USD * HOURS_PER_MONTH if is_alb else None,
            "provisioned-estimate" if is_alb else "price-unavailable",
        ))

    for security_group in infra.ec2.security_groups:
        resources.append(_record(
            security_group.id, "security_group", None, "free",
        ))

    for elastic_ip in infra.ec2.elastic_ips:
        resources.append(_record(
            elastic_ip.allocation_id, "elastic_ip", None, "price-unavailable",
        ))

    for gateway_id in infra.vpc.internet_gateways:
        resources.append(_record(
            gateway_id, "internet_gateway", None, "free",
        ))

    for subnet in infra.vpc.subnets:
        resources.append(_record(
            subnet.id, "vpc_subnet", None, "free",
        ))

    for route_table in infra.vpc.route_tables:
        resources.append(_record(
            route_table.id, "route_table", None, "free",
        ))

    for peering in infra.vpc.vpc_peering_connections:
        resources.append(_record(
            peering.id, "vpc_peering_connection", None, "free",
        ))

    for nacl in infra.vpc.nacls:
        resources.append(_record(
            nacl.id, "network_acl", None, "free",
        ))

    for attachment in infra.vpc.transit_gateway_attachments:
        resources.append(_record(
            attachment.id, "transit_gateway_attachment", None, "price-unavailable",
        ))

    for gateway in infra.vpc.vpn_gateways:
        resources.append(_record(
            gateway.id, "vpn_gateway", None, "price-unavailable",
        ))

    for endpoint in infra.vpc.interface_endpoints:
        resources.append(_record(
            endpoint.id, "interface_endpoint", None, "price-unavailable",
        ))

    for bucket in infra.s3.buckets:
        resources.append(_record(
            bucket.name, "s3_bucket", None, "usage-based-unknown",
        ))

    for function in infra.lambda_data.functions:
        resources.append(_record(
            function.name, "lambda_function", None, "usage-based-unknown",
        ))

    for instance in infra.rds.rds_instances:
        # RDSInstance intentionally has no instance class, engine, or storage fields.
        resources.append(_record(
            instance.id, "rds_instance", None, "price-unavailable",
        ))

    for user in infra.iam.iam_users:
        resources.append(_record(
            user.username, "iam_user", None, "free",
        ))

    for policy in infra.iam.role_policies:
        resources.append(_record(
            policy.role_arn or policy.role_name, "iam_role_policy", None, "free",
        ))

    for api in infra.api_gateway.apis:
        resources.append(_record(
            api.id, "api_gateway", None, "usage-based-unknown",
        ))

    for cluster in infra.elasticache.clusters:
        resources.append(_record(
            cluster.id, "elasticache_cluster", None, "price-unavailable",
        ))

    for queue in infra.sqs.queues:
        resources.append(_record(
            queue.arn, "sqs_queue", None, "usage-based-unknown",
        ))

    for table in infra.dynamodb.tables:
        resources.append(_record(
            table.arn, "dynamodb_table", None, "usage-based-unknown",
        ))

    resources.sort(key=_resource_sort_key)
    total = round(sum(item.monthly_usd for item in resources if item.monthly_usd is not None), 2)
    return CostEstimate(
        region_assumed=PRICE_TABLE_REGION,
        as_of=PRICE_TABLE_AS_OF,
        hours_per_month=HOURS_PER_MONTH,
        total_monthly_usd=total,
        resources=resources,
        unknown_count=sum(item.monthly_usd is None for item in resources),
    )


def _unknown_reason(resource: ResourceCost) -> str:
    if resource.basis == "usage-based-unknown":
        return "usage-based pricing is not embedded"
    if resource.resource_type == "ec2_instance":
        return "EC2 instance type is not in the curated table"
    if resource.resource_type == "ebs_volume":
        return "only positive gp3 storage is priced"
    if resource.resource_type == "load_balancer":
        return "only the ALB fixed portion is embedded"
    if resource.resource_type == "rds_instance":
        return "RDS instance class is absent from the current model"
    return "price is not embedded"


def cost_delta(base: AWSInfrastructure, branch: AWSInfrastructure) -> CostDelta:
    """Return a typed delta for resources whose cost-relevant state changed."""
    base_estimate = estimate_monthly_cost(base)
    branch_estimate = estimate_monthly_cost(branch)
    base_by_key = {(item.resource_type, item.resource_id): item for item in base_estimate.resources}
    branch_by_key = {(item.resource_type, item.resource_id): item for item in branch_estimate.resources}
    changed: list[tuple[ResourceCost | None, ResourceCost | None]] = []
    for key in sorted(base_by_key.keys() | branch_by_key.keys()):
        before = base_by_key.get(key)
        after = branch_by_key.get(key)
        if before is None or after is None or (
            before.monthly_usd != after.monthly_usd or before.basis != after.basis
        ):
            changed.append((before, after))

    cost_bearing = [(before, after) for before, after in changed
                    if (before or after).basis != "free"]
    unknown = [(before, after) for before, after in cost_bearing
               if (before is not None and before.monthly_usd is None)
               or (after is not None and after.monthly_usd is None)]
    priced = [(before, after) for before, after in cost_bearing
              if (before is None or before.monthly_usd is not None)
              and (after is None or after.monthly_usd is not None)]
    known_delta = round(sum(
        (after.monthly_usd if after and after.monthly_usd is not None else 0.0)
        - (before.monthly_usd if before and before.monthly_usd is not None else 0.0)
        for before, after in priced
    ), 2)
    if not cost_bearing:
        return CostDelta(value=0.0, status="n/a", reason="no changed cost-bearing resources",
                         unknown_count=0, known_provisioned_delta=None)
    if unknown:
        return CostDelta(
            value=None, status="unknown",
            reason=f"{len(unknown)} changed resources have usage-based or unavailable prices",
            unknown_count=len(unknown),
            known_provisioned_delta=known_delta if priced else None,
        )
    return CostDelta(
        value=known_delta, status="estimated",
        reason="embedded AWS us-east-1 on-demand/list-price snapshot",
        unknown_count=0, known_provisioned_delta=known_delta,
    )
