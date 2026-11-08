"""AWS adapter: the CloudFront availability fact of the check.

One fact, read off modeled fields of two snapshots (no provider call):

  origin_receives_host_header  a cache behavior that serves an S3 bucket through origin access control
                               now passes the viewer Host header to the bucket

What AWS documents (``SOURCE_URL``, the custom-origin behavior page): CloudFront sets Host to the domain name of the
origin, and you can't cache based on the Host header for Amazon S3 origins. The managed-policies page
(https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-origin-request-policies.html) says
API Gateway, Lambda function URL and Lambda web function origins expect Host to be the origin domain name and that
forwarding the viewer Host to them can prevent them working; it says nothing about S3.

What AWS does not document, and what is only observed: that an S3 bucket answers a forwarded viewer Host with an
error and the path goes down. That was seen in one incident, not read from an AWS page; the fact therefore cites
the documented part and the effect on S3 is incident-observed.

A fact only when the header rule of every policy that applies is known. A rule that was not collected, or is
not one this model reads, makes the answer unknown, never a fact and never a silent "fine".
"""
from __future__ import annotations

import json
from typing import Any, Optional

from app.aws_context import node_id_for
from app.check_facts import CheckInputs, EdgeOriginFact
from app.models import AWSInfrastructure, CloudFrontCacheBehavior, CloudFrontDistribution, CloudFrontOrigin

SOURCE_URL = "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html"
CHANGE = "origin_receives_host_header"


def _behaviors(dist: CloudFrontDistribution) -> list[CloudFrontCacheBehavior]:
    return ([dist.default_cache_behavior] if dist.default_cache_behavior else []) + list(dist.cache_behaviors)


def _origin(dist: CloudFrontDistribution, behavior: CloudFrontCacheBehavior) -> Optional[CloudFrontOrigin]:
    return next((o for o in dist.origins if o.id == behavior.target_origin_id), None)


def _host_to_protected_bucket(infra: AWSInfrastructure, dist: CloudFrontDistribution,
                              behavior: CloudFrontCacheBehavior) -> tuple[Optional[bool], Optional[CloudFrontOrigin]]:
    """(does the viewer Host reach an S3 bucket origin: True / False / None unknown, that origin).

    Whether the origin has access control is the caller's question (``origin_access_control_id``)."""
    origin = _origin(dist, behavior)
    if origin is None or origin.origin_type != "s3":
        return False, origin
    return infra.cloudfront.behavior_forwards_host(behavior), origin


def _signature(infra: AWSInfrastructure, dist: CloudFrontDistribution, behavior: CloudFrontCacheBehavior) -> str:
    origin = _origin(dist, behavior)
    return json.dumps([behavior.target_origin_id, behavior.cache_policy_id, behavior.origin_request_policy_id,
                       behavior.uses_legacy_forwarded_values, behavior.extra.get("ForwardedValues"),
                       origin.model_dump(exclude={"extra"}) if origin else None], sort_keys=True, default=str)


def compare(base: AWSInfrastructure, branch: AWSInfrastructure, branch_graph: Any
            ) -> tuple[list[EdgeOriginFact], list[tuple[str, str, Optional[str]]], int, int]:
    """(facts, unknown notes, behaviors compared, distributions changed) between the base and the branch."""
    before_by_id = {d.id: d for d in base.cloudfront.distributions}
    facts: list[EdgeOriginFact] = []
    doubts: list[tuple[str, str, Optional[str]]] = []
    compared = changed = 0
    for dist in branch.cloudfront.distributions:
        old = before_by_id.get(dist.id)
        if old is None:
            continue
        if old.model_dump() != dist.model_dump():
            changed += 1
        before = {b.path_pattern: b for b in _behaviors(old)}
        for behavior in _behaviors(dist):
            after_state, origin = _host_to_protected_bucket(branch, dist, behavior)
            previous = before.get(behavior.path_pattern)
            before_state = _host_to_protected_bucket(base, old, previous)[0] if previous is not None else False
            compared += 1
            if previous is not None and _signature(base, old, previous) == _signature(branch, dist, behavior):
                continue  # nothing about how this behavior reaches its origin changed
            if origin is not None and origin.origin_type == "s3" and not origin.origin_access_control_id:
                # An OAI or public S3 origin: the observed incident is with OAC only, so never a fact, and never silent.
                if after_state is not False and before_state is not True:
                    doubts.append(("origin_host_header_s3_without_oac",
                                   "a behavior serving an S3 bucket without origin access control (an origin access identity or a public bucket) "
                                   f"{'now passes' if after_state else 'may now pass'} the viewer Host header to it; whether that breaks the path is not observed "
                                   "(the observed incident is with origin access control), so it is not stated as a fact", dist.id))
                continue
            if after_state is True and before_state is not True:
                facts.append(EdgeOriginFact(
                    resource_id=dist.id, resource_type="cloudfront_distribution", change=CHANGE,
                    resource_ids=[node_id_for(branch_graph, "s3_bucket", origin.s3_bucket)] if origin and origin.s3_bucket else [],
                    path_pattern=behavior.path_pattern, cache_policy_id=behavior.cache_policy_id,
                    origin_request_policy_id=behavior.origin_request_policy_id, source_url=SOURCE_URL))
            elif after_state is None and before_state is not True:
                doubts.append(("origin_host_header",
                               "whether a behavior serving an S3 bucket through origin access control now passes the viewer Host header "
                               "to it is not known: the header rule of its cache policy or origin request policy was not collected", dist.id))
    return facts, doubts, compared, changed


def with_cloudfront(inputs: CheckInputs, base: AWSInfrastructure, branch: AWSInfrastructure, branch_graph: Any) -> CheckInputs:
    """``inputs`` plus the CloudFront availability fact and the notes that say what was and was not looked at."""
    facts, doubts, compared, changed = compare(base, branch, branch_graph)
    checked: list[tuple[str, str]] = []
    unknown: list[tuple[str, str]] = []
    status = base.collection.get("cloudfront")
    if status == "ok":
        checked.append(("cloudfront", "collected ok"))
    elif status is not None:
        unknown.append(("cloudfront", f"collection status is '{status}'; what it would show is not in the snapshot"))
    elif any(b.has_cloudfront for b in base.s3.buckets):
        unknown.append(("cloudfront", "a distribution serves from a bucket but CloudFront was not collected for this snapshot, "
                                      "so its behaviors and policies are not in it"))
    if base.cloudfront.distributions:
        checked.append(("cloudfront_origin_host", f"{compared} cache behaviors of {len(base.cloudfront.distributions)} distributions "
                                                  "compared for whether the viewer Host header now reaches an S3 origin behind origin access control"))
    if changed:
        unknown.append(("cloudfront_unmodeled_settings",
                        "settings of a changed distribution other than origins, cache behaviors, aliases, price class, web ACL and enabled "
                        "are carried unchanged and not interpreted"))
    availability_unknown = list(inputs.unknown_notes.get("availability", ())) + unknown
    availability_checked = list(inputs.checked_notes.get("availability", ())) + checked
    inputs.unknown_notes = {**inputs.unknown_notes, "availability": availability_unknown}
    inputs.checked_notes = {**inputs.checked_notes, "availability": availability_checked}
    inputs.availability_facts = list(inputs.availability_facts) + facts
    inputs.availability_doubts = list(inputs.availability_doubts) + doubts
    return inputs
