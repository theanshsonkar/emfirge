"""Deterministic, vendored-price cost estimates for collected AWS infrastructure."""

import json
from pathlib import Path
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel

from .models import AWSInfrastructure


PRICE_TABLE_REGION = "us-east-1"
HOURS_PER_MONTH = 730
# Prices are AWS's published Price List Bulk API values, vendored by
# scripts/generate_prices.py into app/data/aws_prices.json (with source URLs and
# publication dates). Nothing here is hand-typed.
_PRICES_PATH = Path(__file__).resolve().parent / "data" / "aws_prices.json"


def _load_prices(region: str) -> dict:
    with open(_PRICES_PATH, encoding="utf-8") as handle:
        return json.load(handle)["regions"][region]


_PRICES = _load_prices(PRICE_TABLE_REGION)
# Publication date (YYYY-MM-DD) of the EC2 offer file the prices came from.
PRICE_TABLE_AS_OF = _PRICES["sources"]["AmazonEC2"]["publication_date"][:10]
NAT_GATEWAY_HOURLY_USD = _PRICES["nat_gateway_hourly_usd"]
ALB_HOURLY_USD = _PRICES["alb_hourly_usd"]
EBS_GB_MONTH_USD = _PRICES["ebs_gb_month_usd"]
EBS_GP3_GB_MONTH_USD = EBS_GB_MONTH_USD["gp3"]
# Linux, shared-tenancy, no pre-installed software, on-demand rates.
EC2_HOURLY_USD = _PRICES["ec2_hourly_usd"]

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


class CostSide(BaseModel):
    known_monthly_usd: float
    unknown_count: int
    status: Literal["estimated", "partial", "n/a"]
    currency: Literal["USD"] = "USD"


class CostChange(BaseModel):
    resource_id: str
    resource_type: str
    before_monthly_usd: Optional[float]
    after_monthly_usd: Optional[float]
    before_basis: Optional[str]
    after_basis: Optional[str]


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
        per_gb = EBS_GB_MONTH_USD.get(volume.volume_type.lower())
        if per_gb is not None and volume.size_gb > 0:
            monthly = volume.size_gb * per_gb
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

    for snapshot in infra.rds.rds_snapshots:
        resources.append(_record(
            snapshot.id, "rds_snapshot", None, "usage-based-unknown",
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
        return "EC2 instance type is not in the AWS price list data"
    if resource.resource_type == "ebs_volume":
        return "only positive-size volumes of types in the AWS price list data are priced"
    if resource.resource_type == "load_balancer":
        return "only the ALB fixed portion is embedded"
    if resource.resource_type == "rds_instance":
        return "RDS instance class is absent from the current model"
    return "price is not embedded"


def _changed_resource_pairs(base_estimate: CostEstimate, branch_estimate: CostEstimate) -> list[tuple[ResourceCost | None, ResourceCost | None]]:
    base_by_key = {(item.resource_type, item.resource_id): item for item in base_estimate.resources}
    branch_by_key = {(item.resource_type, item.resource_id): item for item in branch_estimate.resources}
    changed: list[tuple[ResourceCost | None, ResourceCost | None]] = []
    for key in sorted(base_by_key.keys() | branch_by_key.keys()):
        before = base_by_key.get(key)
        after = branch_by_key.get(key)
        if before is None or after is None or before.monthly_usd != after.monthly_usd or before.basis != after.basis:
            changed.append((before, after))
    return changed


def _delta_from_estimates(base_estimate: CostEstimate, branch_estimate: CostEstimate) -> CostDelta:
    changed = _changed_resource_pairs(base_estimate, branch_estimate)
    cost_bearing = [(before, after) for before, after in changed if (before or after).basis != "free"]
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
        return CostDelta(value=None, status="unknown",
                         reason=f"{len(unknown)} changed resources have usage-based or unavailable prices",
                         unknown_count=len(unknown), known_provisioned_delta=known_delta if priced else None)
    return CostDelta(value=known_delta, status="estimated",
                     reason="embedded AWS us-east-1 on-demand/list-price snapshot",
                     unknown_count=0, known_provisioned_delta=known_delta)


def _cost_side(estimate: CostEstimate) -> CostSide:
    known = round(sum(item.monthly_usd for item in estimate.resources if item.monthly_usd is not None), 2)
    unknown_count = sum(item.monthly_usd is None and item.basis != "free" for item in estimate.resources)
    has_cost_basis = any(item.basis != "free" for item in estimate.resources)
    status = "n/a" if not has_cost_basis else ("partial" if unknown_count > 0 else "estimated")
    return CostSide(known_monthly_usd=known, unknown_count=unknown_count, status=status)


def cost_delta(base: AWSInfrastructure, branch: AWSInfrastructure) -> CostDelta:
    """Return a typed delta for resources whose cost-relevant state changed."""
    return _delta_from_estimates(estimate_monthly_cost(base), estimate_monthly_cost(branch))


def cost_sides(base: AWSInfrastructure, branch: AWSInfrastructure) -> tuple[CostSide, CostSide, list[CostChange], CostDelta]:
    base_estimate = estimate_monthly_cost(base)
    branch_estimate = estimate_monthly_cost(branch)
    changes = []
    for before, after in _changed_resource_pairs(base_estimate, branch_estimate):
        if all(item.basis == "free" for item in (before, after) if item is not None):
            continue
        item = before or after
        changes.append(CostChange(
            resource_id=item.resource_id, resource_type=item.resource_type,
            before_monthly_usd=before.monthly_usd if before else None,
            after_monthly_usd=after.monthly_usd if after else None,
            before_basis=before.basis if before else None,
            after_basis=after.basis if after else None,
        ))
    changes.sort(key=lambda item: (item.resource_type, item.resource_id))
    return _cost_side(base_estimate), _cost_side(branch_estimate), changes, _delta_from_estimates(base_estimate, branch_estimate)
