"""Deterministic checks for known AWS resource limits."""

from __future__ import annotations

import ipaddress
from numbers import Real
from typing import Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from .models import AWSInfrastructure


QUOTAS_AS_OF = "2026-09-15"
# Curated AWS service-quota defaults. These are region-general AWS DEFAULTS,
# not account-specific quota lookups; accounts may have approved increases.
DEFAULT_QUOTAS: Dict[str, int] = {
    "eips_per_region": 5,
    "vpcs_per_region": 5,
    "subnets_per_vpc": 200,
    "nat_gateways_per_az": 5,
    "rules_per_sg_inbound": 60,
    "rules_per_sg_outbound": 60,
    "sgs_per_eni": 5,
    "lambda_concurrent_executions": 1000,
}

LimitStatus = Literal["ok", "near", "exceeded", "unknown"]


class LimitFinding(BaseModel):
    check: str
    scope: str
    current: Optional[int] = None
    limit: Optional[int] = None
    status: LimitStatus
    basis: str


class LimitsDelta(BaseModel):
    introduced: List[LimitFinding] = Field(default_factory=list)
    resolved: List[LimitFinding] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


def _status(current: Optional[int], limit: Optional[int], *, capacity: bool = False) -> LimitStatus:
    """Classify a value; capacities fail at equality, quotas fail only above it."""
    if current is None or limit is None or current < 0 or limit < 0:
        return "unknown"
    if capacity and current >= limit:
        return "exceeded"
    if not capacity and current > limit:
        return "exceeded"
    if limit == 0:
        return "near" if current < limit else "exceeded"
    if current >= limit * 0.8:
        return "near"
    return "ok"


def _finding(check: str, scope: str, current: Optional[int], limit: Optional[int], basis: str, *, capacity: bool = False) -> LimitFinding:
    return LimitFinding(
        check=check,
        scope=scope,
        current=current,
        limit=limit,
        status=_status(current, limit, capacity=capacity),
        basis=basis,
    )


def _subnet_ip_finding(infra: AWSInfrastructure, subnet) -> LimitFinding:
    basis = (
        "AWS DEFAULTS, region-general, as of " + QUOTAS_AS_OF
        + "; IPv4 subnet capacity uses AWS's 5 reserved addresses; "
        "current is observed unique subnet resources and concrete instances/functions"
    )
    if not subnet.cidr:
        return _finding("subnet_ip_capacity", subnet.id, None, None, basis)
    try:
        network = ipaddress.ip_network(subnet.cidr, strict=False)
    except ValueError:
        return _finding("subnet_ip_capacity", subnet.id, None, None, basis)
    if network.version != 4:
        return _finding("subnet_ip_capacity", subnet.id, None, None, basis)

    ids = set(str(resource_id) for resource_id in subnet.resources)
    ids.update(
        str(instance.id) for instance in infra.ec2.instances
        if instance.subnet_id == subnet.id
    )
    ids.update(
        str(function.name) for function in infra.lambda_data.functions
        if subnet.id in function.subnet_ids
    )
    usable = max(network.num_addresses - 5, 0)
    return _finding("subnet_ip_capacity", subnet.id, len(ids), usable, basis, capacity=True)


def _quota_basis(label: str) -> str:
    return f"AWS DEFAULTS, region-general, as of {QUOTAS_AS_OF}; {label}"


def limit_checks(infra: AWSInfrastructure) -> List[LimitFinding]:
    """Return deterministic, non-mutating checks supported by ``infra``."""
    findings: List[LimitFinding] = []
    findings.extend(_subnet_ip_finding(infra, subnet) for subnet in infra.vpc.subnets)

    findings.append(_finding(
        "eips_per_region", "region", len(infra.ec2.elastic_ips), DEFAULT_QUOTAS["eips_per_region"],
        _quota_basis("EIP count compared with the regional default quota"),
    ))

    total_vpcs = infra.vpc.total_vpcs
    vpc_current = total_vpcs if isinstance(total_vpcs, int) and not isinstance(total_vpcs, bool) and total_vpcs >= 0 else None
    findings.append(_finding(
        "vpcs_per_region", "region", vpc_current, DEFAULT_QUOTAS["vpcs_per_region"],
        _quota_basis("VPCData.total_vpcs compared with the regional default quota"),
    ))

    nat_basis = _quota_basis(
        "NAT gateway count compared conservatively per region; availability zone is unknown, so no per-AZ fabrication"
    )
    findings.append(_finding(
        "nat_gateways_per_az", "region", len(infra.vpc.nat_gateways),
        DEFAULT_QUOTAS["nat_gateways_per_az"], nat_basis,
    ))

    sg_basis = _quota_basis("actual security-group rule lists compared with the default quota")
    for security_group in infra.ec2.security_groups:
        findings.append(_finding(
            "rules_per_sg_inbound", str(security_group.id), len(security_group.rules),
            DEFAULT_QUOTAS["rules_per_sg_inbound"], sg_basis,
        ))
        findings.append(_finding(
            "rules_per_sg_outbound", str(security_group.id), len(security_group.egress_rules),
            DEFAULT_QUOTAS["rules_per_sg_outbound"], sg_basis,
        ))

    subnet_groups: Dict[str, int] = {}
    for subnet in infra.vpc.subnets:
        vpc_id = str(subnet.vpc_id) if subnet.vpc_id else ""
        if vpc_id:
            subnet_groups[vpc_id] = subnet_groups.get(vpc_id, 0) + 1
        else:
            findings.append(_finding(
                "subnets_per_vpc", "unknown-vpc", None, None,
                _quota_basis("missing VPC ID prevents per-VPC grouping"),
            ))
    for vpc_id, count in subnet_groups.items():
        findings.append(_finding(
            "subnets_per_vpc", vpc_id, count, DEFAULT_QUOTAS["subnets_per_vpc"],
            _quota_basis("subnets grouped by observed VPCSubnet.vpc_id"),
        ))

    eni_basis = _quota_basis("EC2Instance.sg_ids count compared with the default per-ENI quota")
    for instance in infra.ec2.instances:
        findings.append(_finding(
            "sgs_per_eni", str(instance.id), len(instance.sg_ids),
            DEFAULT_QUOTAS["sgs_per_eni"], eni_basis,
        ))

    functions = infra.lambda_data.functions
    concurrency_values: List[int] = []
    all_have_numeric_concurrency = bool(functions)
    for function in functions:
        value = getattr(function, "reserved_concurrency", None)
        if isinstance(value, bool) or not isinstance(value, Real) or value < 0:
            all_have_numeric_concurrency = False
            break
        concurrency_values.append(int(value))
    if all_have_numeric_concurrency:
        findings.append(_finding(
            "lambda_concurrent_executions", "region", sum(concurrency_values),
            DEFAULT_QUOTAS["lambda_concurrent_executions"],
            _quota_basis("sum of observed reserved_concurrency values"),
        ))
    else:
        findings.append(_finding(
            "lambda_concurrent_executions", "region", None,
            DEFAULT_QUOTAS["lambda_concurrent_executions"],
            _quota_basis("unknown: no reserved-concurrency data is present on LambdaFunction"),
        ))

    return sorted(findings, key=lambda finding: (finding.check, finding.scope))


def limits_delta(base: AWSInfrastructure, branch: AWSInfrastructure) -> LimitsDelta:
    """Compare two snapshots without treating unknown findings as transitions."""
    base_findings = {(item.check, item.scope): item for item in limit_checks(base)}
    branch_findings = {(item.check, item.scope): item for item in limit_checks(branch)}
    introduced: List[LimitFinding] = []
    resolved: List[LimitFinding] = []
    notes = ["Quota basis is AWS DEFAULTS, region-general, as of " + QUOTAS_AS_OF + "."]

    for key in sorted(set(base_findings) | set(branch_findings)):
        old = base_findings.get(key)
        new = branch_findings.get(key)
        old_status = old.status if old else "unknown"
        new_status = new.status if new else "unknown"
        old_bad = old_status in {"near", "exceeded"}
        new_bad = new_status in {"near", "exceeded"}
        if new is not None and new_bad and old is not None and old_status == "ok":
            introduced.append(new)
        if old is not None and old_bad and new is not None and new_status == "ok":
            resolved.append(old)
        for finding in (old, new):
            if finding is not None and finding.status == "unknown":
                notes.append(f"Unknown check/scope: {finding.check}/{finding.scope}; no transition inferred.")

    return LimitsDelta(introduced=introduced, resolved=resolved, notes=sorted(set(notes)))


# Singular spelling is a convenient compatibility alias for callers.
limit_delta = limits_delta

__all__ = [
    "DEFAULT_QUOTAS", "QUOTAS_AS_OF", "LimitFinding", "LimitsDelta",
    "limit_checks", "limits_delta", "limit_delta",
]
