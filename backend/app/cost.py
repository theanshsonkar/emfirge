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
    "provisioned-estimate", "usage-based-unknown", "price-unavailable"
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
    monthly_delta_usd: float
    base_total: float
    branch_total: float
    added_cost: List[ResourceCost]
    removed_cost: List[ResourceCost]
    unknown_notes: List[str]


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
            security_group.id, "security_group", None, "price-unavailable",
        ))

    for elastic_ip in infra.ec2.elastic_ips:
        resources.append(_record(
            elastic_ip.allocation_id, "elastic_ip", None, "price-unavailable",
        ))

    for gateway_id in infra.vpc.internet_gateways:
        resources.append(_record(
            gateway_id, "internet_gateway", None, "price-unavailable",
        ))

    for subnet in infra.vpc.subnets:
        resources.append(_record(
            subnet.id, "vpc_subnet", None, "price-unavailable",
        ))

    for route_table in infra.vpc.route_tables:
        resources.append(_record(
            route_table.id, "route_table", None, "price-unavailable",
        ))

    for peering in infra.vpc.vpc_peering_connections:
        resources.append(_record(
            peering.id, "vpc_peering_connection", None, "price-unavailable",
        ))

    for nacl in infra.vpc.nacls:
        resources.append(_record(
            nacl.id, "network_acl", None, "price-unavailable",
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
            user.username, "iam_user", None, "price-unavailable",
        ))

    for policy in infra.iam.role_policies:
        resources.append(_record(
            policy.role_arn or policy.role_name, "iam_role_policy", None, "price-unavailable",
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


def _unknown_notes(side: str, estimate: CostEstimate) -> List[str]:
    return [
        f"{side}: {resource.resource_type}/{resource.resource_id}: "
        f"incomplete/unknown ({resource.basis}; {_unknown_reason(resource)})"
        for resource in estimate.resources
        if resource.monthly_usd is None
    ]


def cost_delta(base: AWSInfrastructure, branch: AWSInfrastructure) -> CostDelta:
    """Compare deterministic estimates and identify resources by type and stable ID."""
    base_estimate = estimate_monthly_cost(base)
    branch_estimate = estimate_monthly_cost(branch)
    base_by_key = {(item.resource_type, item.resource_id): item for item in base_estimate.resources}
    branch_by_key = {(item.resource_type, item.resource_id): item for item in branch_estimate.resources}

    added = [branch_by_key[key] for key in sorted(branch_by_key.keys() - base_by_key.keys())]
    removed = [base_by_key[key] for key in sorted(base_by_key.keys() - branch_by_key.keys())]
    notes = _unknown_notes("base", base_estimate) + _unknown_notes("branch", branch_estimate)
    # ALB's known fixed charge intentionally excludes usage-dependent LCUs.
    if any(item.resource_type == "load_balancer" and item.monthly_usd is not None for item in base_estimate.resources + branch_estimate.resources):
        notes.append("incomplete/unknown: ALB estimates include fixed hourly charge only; LCU usage is excluded")

    return CostDelta(
        monthly_delta_usd=round(branch_estimate.total_monthly_usd - base_estimate.total_monthly_usd, 2),
        base_total=base_estimate.total_monthly_usd,
        branch_total=branch_estimate.total_monthly_usd,
        added_cost=added,
        removed_cost=removed,
        unknown_notes=notes,
    )
