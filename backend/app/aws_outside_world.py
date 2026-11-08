"""AWS adapter: which actions leave the cloud.

A typed change (a security group, a bucket, a role) only touches resources inside
the account. Some AWS actions reach a person or a party outside it: a support
case, a quota request that AWS staff decide on, email to outside recipients, a
domain purchase, a billed spending commitment. Whether an action does that is
decided per SERVICE (ARC-DISCUSSION "No rulebook: the branch decides"), never by
adding single actions one by one: that would be a rulebook of ~15k actions. The
one split inside a service is reads: a Get, List or Describe of a table service is
not treated as outside-world.

The table is hand-written, so every entry cites AWS's own documentation. It is
deliberately small. Anything not in the table is reported as unclassified by the
check, never as fine. Services where only some actions leave the cloud (SNS,
Organizations, RAM, Pinpoint, Connect, EventBridge API destinations, Marketplace
metering and agreements) are not in the table, so they stay unclassified.

Service names are botocore names (what an API plan carries), not IAM prefixes:
``aws-marketplace`` is an IAM prefix, the botocore services are ``marketplace-catalog``,
``marketplace-entitlement``, ``meteringmarketplace`` and so on.

The Get / List / Describe rule is a naming convention of AWS operations, not a
guarantee AWS documents; IAM groups actions into List / Read / Write access levels
(https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_understand-policy-summary-access-level-summaries.html).

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


READ_ONLY_PREFIXES = ("Get", "List", "Describe")


OUTSIDE_WORLD_SERVICES: tuple[OutsideService, ...] = (
    OutsideService(
        services=("support",), terraform_prefixes=(),
        reason="Opens or changes a case with AWS Support staff, who are people outside the account.",
        source_url="https://docs.aws.amazon.com/awssupport/latest/user/case-management.html",
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
        services=("marketplace-catalog", "marketplace-entitlement"), terraform_prefixes=(),
        reason="Subscribes to or changes software sold by a third-party seller, an agreement with a party outside the account.",
        source_url="https://docs.aws.amazon.com/marketplace/latest/buyerguide/what-is-marketplace.html",
    ),
    OutsideService(
        services=("savingsplans",), terraform_prefixes=(),
        reason="Buys a one- or three-year spending commitment that is billed whether or not it is used.",
        source_url="https://docs.aws.amazon.com/savingsplans/latest/userguide/what-is-savings-plans.html",
    ),
)

# Not an action to classify: a schedule starts its target on a timer, which can reach outside the account
# through whatever the target does. Used by the check for schedules that begin or keep running on a branch.
SCHEDULER_ENTRY = OutsideEntry(
    service="scheduler",
    reason="Runs its target on a timer without anyone starting it.",
    source_url="https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-state.html",
)

_BY_SERVICE = {service: entry for entry in OUTSIDE_WORLD_SERVICES for service in entry.services}
_BY_PREFIX = sorted(((prefix, entry) for entry in OUTSIDE_WORLD_SERVICES for prefix in entry.terraform_prefixes),
                    key=lambda pair: -len(pair[0]))


def classify_action(action: str) -> Optional[OutsideEntry]:
    """What the table says about one action, or None when it says nothing.

    ``action`` is ``service.Operation`` (API, CLI and CloudFormation plans keep
    that form) or a Terraform resource type such as ``aws_ses_email_identity``.
    A read (Get, List, Describe) of a table service gives an entry with
    ``outside`` False; None means unclassified, which the check reports as such.
    """
    text = str(action or "").strip()
    if not text:
        return None
    if "." in text:
        service, operation = text.split(".", 1)
        service = service.lower()
        entry = _BY_SERVICE.get(service)
        if entry is None:
            return None
        if operation.startswith(READ_ONLY_PREFIXES):
            return OutsideEntry(service=service, reason="A read by name (Get, List or Describe); not treated as leaving the cloud.",
                                source_url=entry.source_url, outside=False)
        return OutsideEntry(service=service, reason=entry.reason, source_url=entry.source_url)
    lowered = text.lower()
    for prefix, entry in _BY_PREFIX:
        if lowered.startswith(prefix):
            return OutsideEntry(service=entry.services[0], reason=entry.reason, source_url=entry.source_url)
    return None
