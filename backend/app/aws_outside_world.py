"""AWS adapter: which actions leave the cloud.

A typed change (a security group, a bucket, a role) only touches resources inside
the account. Some AWS actions reach a person or a party outside it: a support
case, a quota request that AWS staff decide on, email to outside recipients, a
domain purchase, a billed spending commitment, a message to subscribers. Whether
an action does that is decided per ACTION, not from a diff and not per service:
a read (Get, List, Describe) of a table service is known not to be outside-world,
and a service listed with ``only_actions`` is outside-world for exactly those
actions.

The table is hand-written, so every entry cites AWS's own documentation. It is
deliberately small. Anything not in the table is reported as unclassified by the
check, never as fine. Services whose effect AWS does not document in a page we
could cite (Pinpoint, Connect, EventBridge API destinations, Marketplace
agreements) are left unclassified on purpose.

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
    only_actions: Optional[tuple[str, ...]] = None  # None: every action that is not a read; else exactly these


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
    OutsideService(
        services=("sns",), terraform_prefixes=(), only_actions=("Publish", "PublishBatch"),
        reason="Publishing delivers the message to every endpoint subscribed to the topic, or to a phone number or mobile endpoint, which can be outside the account.",
        source_url="https://docs.aws.amazon.com/sns/latest/api/API_Publish.html",
    ),
    OutsideService(
        services=("organizations",), terraform_prefixes=(), only_actions=("InviteAccountToOrganization",),
        reason="Sends an invitation, by email on your behalf, to another account's owner to join the organization.",
        source_url="https://docs.aws.amazon.com/organizations/latest/APIReference/API_InviteAccountToOrganization.html",
    ),
    OutsideService(
        services=("ram",), terraform_prefixes=(), only_actions=("CreateResourceShare",),
        reason="Sharing a resource makes it available for use by principals outside of the account that created it.",
        source_url="https://docs.aws.amazon.com/ram/latest/APIReference/API_CreateResourceShare.html",
    ),
    OutsideService(
        services=("meteringmarketplace",), terraform_prefixes=(), only_actions=("MeterUsage",),
        reason="Emits metering records directly to AWS Marketplace.",
        source_url="https://docs.aws.amazon.com/marketplacemetering/latest/APIReference/API_MeterUsage.html",
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
        if entry.only_actions is not None:
            if operation not in entry.only_actions:
                return None
        elif operation.startswith(READ_ONLY_PREFIXES):
            return OutsideEntry(service=service, reason="A read by name (Get, List or Describe); not treated as leaving the cloud.",
                                source_url=entry.source_url, outside=False)
        return OutsideEntry(service=service, reason=entry.reason, source_url=entry.source_url)
    lowered = text.lower()
    for prefix, entry in _BY_PREFIX:
        if lowered.startswith(prefix):
            return OutsideEntry(service=entry.services[0], reason=entry.reason, source_url=entry.source_url)
    return None
