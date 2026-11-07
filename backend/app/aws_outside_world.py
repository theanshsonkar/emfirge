"""AWS adapter: which services' actions leave the cloud.

A typed change (a security group, a bucket, a role) only touches resources inside
the account. Some AWS actions reach a person or a party outside it: a support
case, a quota request that AWS staff decide on, email to outside recipients, a
domain purchase, a third-party marketplace agreement, a billed spending
commitment. Whether an action does that is decided per SERVICE from the action
name, not from a diff.

The table is hand-written, so every entry cites AWS's own documentation. It is
deliberately small: a service belongs here only when its actions routinely
involve a party outside the account. Anything not in the table is reported as
unclassified by the check, never as fine.

Cloud-neutral core (``check_facts``) never sees a service name; it receives
``classify_action`` as data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.check_facts import OutsideEntry


@dataclass(frozen=True)
class OutsideService:
    """One entry: botocore service ids, Terraform resource-type prefixes, a plain reason, AWS's own doc URL."""
    services: tuple[str, ...]
    terraform_prefixes: tuple[str, ...]
    reason: str
    source_url: str


OUTSIDE_WORLD_SERVICES: tuple[OutsideService, ...] = (
    OutsideService(
        services=("support",), terraform_prefixes=(),
        reason="Opens or changes a case with AWS Support staff, who are people outside the account.",
        source_url="https://docs.aws.amazon.com/awssupport/latest/user/about-support.html",
    ),
    OutsideService(
        services=("servicequotas", "service-quotas"), terraform_prefixes=("aws_servicequotas_",),
        reason="Asks AWS to raise an account limit; AWS reviews the request and decides, and an approved limit changes what the account can launch and spend.",
        source_url="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html",
    ),
    OutsideService(
        services=("ses",), terraform_prefixes=("aws_ses_",),
        reason="Sends or configures email that reaches recipients outside the account.",
        source_url="https://docs.aws.amazon.com/ses/latest/dg/Welcome.html",
    ),
    OutsideService(
        services=("sesv2",), terraform_prefixes=("aws_sesv2_",),
        reason="Sends or configures email that reaches recipients outside the account.",
        source_url="https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html",
    ),
    OutsideService(
        services=("route53domains",), terraform_prefixes=("aws_route53domains_",),
        reason="Registers, transfers or renews a domain name with a registrar outside the account, which is billed.",
        source_url="https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html",
    ),
    OutsideService(
        services=("aws-marketplace", "marketplace-catalog", "marketplace-entitlement"), terraform_prefixes=(),
        reason="Subscribes to or changes software sold by a third-party seller, an agreement with a party outside the account.",
        source_url="https://docs.aws.amazon.com/marketplace/latest/buyerguide/what-is-marketplace.html",
    ),
    OutsideService(
        services=("savingsplans",), terraform_prefixes=(),
        reason="Buys a one- or three-year spending commitment that is billed whether or not it is used.",
        source_url="https://docs.aws.amazon.com/savingsplans/latest/userguide/what-is-savings-plans.html",
    ),
)

_BY_SERVICE = {service: entry for entry in OUTSIDE_WORLD_SERVICES for service in entry.services}
_BY_PREFIX = sorted(((prefix, entry) for entry in OUTSIDE_WORLD_SERVICES for prefix in entry.terraform_prefixes),
                    key=lambda pair: -len(pair[0]))


def classify_action(action: str) -> Optional[OutsideEntry]:
    """The table entry for an action, or None when its service is not in the table.

    ``action`` is ``service.Operation`` (API, CLI and CloudFormation plans keep
    that form) or a Terraform resource type such as ``aws_ses_email_identity``.
    """
    text = str(action or "").strip()
    if not text:
        return None
    if "." in text:
        service = text.split(".", 1)[0].lower()
        entry = _BY_SERVICE.get(service)
        return OutsideEntry(service=service, reason=entry.reason, source_url=entry.source_url) if entry else None
    lowered = text.lower()
    for prefix, entry in _BY_PREFIX:
        if lowered.startswith(prefix):
            return OutsideEntry(service=entry.services[0], reason=entry.reason, source_url=entry.source_url)
    return None
