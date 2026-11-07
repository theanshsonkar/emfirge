"""L78 CloudFront distributions: collected, branchable, diffable, hand-back exact, and a true Availability fact.

The incident behind this law: a distribution serves a podcast feed (alias, behavior for `feed.xml`) from an S3
bucket behind origin access control. An agent moved that behavior to the AWS managed cache policy
UseOriginCacheControlHeaders, which puts the Host header in the cache key, so CloudFront forwarded the viewer
Host to S3. S3 answered NotFound and the feed was down. The fix was the managed CachingOptimized.

L78a  collector reads distributions, behaviors, origins, tags and the policy header rules (managed and custom,
      referenced or not); policy contents come from the provider's own listings
L78b  denied / error collection is recorded, shows up as unknown, and never becomes a fact
L78c  graph: real node, serves_from_bucket edge with path_pattern / oac / forwards_host, dependency direction
L78d  branch modify (cache policy by path pattern, default behavior, enabled) shows in the diff with before/after
L78e  API, CLI, Terraform and CloudFormation give the same branch for the incident
L78f  hand-back builds the exact UpdateDistribution (IfMatch), refuses to guess; moto round trip
L78g  the fact: the incident is origin_receives_host_header; CachingOptimized is not; unknown stays unknown
L78h  cost is usage based; add / delete are not modeled (said, not silent); catalog from botocore
L78i  the IAM read policy lists exactly the reads the collector makes; no hand-written policy table
L78j  old snapshots still load; the code lives in adapter modules
"""
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
import yaml
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from botocore.validate import ParamValidator
from moto import mock_aws

from app import cloudfront_distribution as cfd
from app.aws_api_ingest import translate_api_calls
from app.aws_check import check_for_branch
from app.aws_cli_ingest import parse_cli_commands
from app.aws_context import answer_for_infra
from app.cfn_ingest import convert_change_set
from app.cloudfront_check import SOURCE_URL
from app.cost import estimate_monthly_cost, unknown_reason
from app.delete_lens import analyze_deletions
from app.diffing import diff_infrastructure
from app.egraph import build_graph
from app.field_catalog import CATALOG, resolve
from app.graph_schema import validate_graph
from app.models import (
    AWSInfrastructure, CloudFrontData, CloudFrontDistribution, S3Bucket,
)
from app.mutations import Change, TargetNotFound, apply_change, apply_changes, mutation_capabilities
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls
from tests.incidents.synthetic_base import load_synthetic_base

REGION = "us-east-1"
BUCKET = "jarvis-podcast-feed"
DIST = "E2JARVISFEED01"
DIST_ARN = f"arn:aws:cloudfront::000000000000:distribution/{DIST}"
OAC = "E3OACJARVIS0001"
ETAG = "E1ETAGJARVIS001"
FEED = "feed.xml"
APP_DIR = Path(__file__).resolve().parents[2] / "app"
ROOT = Path(__file__).resolve().parents[3]

# Policy ids as AWS documents them (the DeveloperGuide pages for managed cache / origin request policies).
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
USE_ORIGIN_CACHE_CONTROL = "83da9c7e-98b4-4e11-a168-04f0df8e2c65"
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
ALL_VIEWER = "216adef6-5c7f-47e4-b989-5492eafa07d3"
ALL_VIEWER_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
CORS_S3 = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf"
CUSTOM_HOST_POLICY = "11111111-2222-3333-4444-555555555555"
UNCOLLECTED = "99999999-8888-7777-6666-555555555555"

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_METHODS = {"Quantity": 2, "Items": ["GET", "HEAD"], "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}


# ── provider listings as the API returns them ─────────────────────────────────

def _cache_policy_item(policy_id, name, behavior, headers=()):
    headers_config = {"HeaderBehavior": behavior}
    if headers:
        headers_config["Headers"] = {"Quantity": len(headers), "Items": list(headers)}
    return {"Type": "managed", "CachePolicy": {"Id": policy_id, "LastModifiedTime": _NOW, "CachePolicyConfig": {
        "Name": name, "MinTTL": 0,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True, "HeadersConfig": headers_config,
            "CookiesConfig": {"CookieBehavior": "none"}, "QueryStringsConfig": {"QueryStringBehavior": "none"}}}}}


def _origin_request_item(policy_id, name, behavior, headers=()):
    headers_config = {"HeaderBehavior": behavior}
    if headers:
        headers_config["Headers"] = {"Quantity": len(headers), "Items": list(headers)}
    return {"Type": "managed", "OriginRequestPolicy": {"Id": policy_id, "LastModifiedTime": _NOW, "OriginRequestPolicyConfig": {
        "Name": name, "HeadersConfig": headers_config, "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"}}}}


MANAGED_CACHE = [
    _cache_policy_item(CACHING_OPTIMIZED, "Managed-CachingOptimized", "none"),
    _cache_policy_item(CACHING_DISABLED, "Managed-CachingDisabled", "none"),
    _cache_policy_item(USE_ORIGIN_CACHE_CONTROL, "Managed-UseOriginCacheControlHeaders", "whitelist",
                       ["Host", "Origin", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]),
]
MANAGED_ORIGIN_REQUEST = [
    _origin_request_item(ALL_VIEWER, "Managed-AllViewer", "allViewer"),
    _origin_request_item(ALL_VIEWER_EXCEPT_HOST, "Managed-AllViewerExceptHostHeader", "allExcept", ["host"]),
    _origin_request_item(CORS_S3, "Managed-CORS-S3Origin", "whitelist", ["Origin", "Access-Control-Request-Headers"]),
]
CUSTOM_CACHE = [{**_cache_policy_item(CUSTOM_HOST_POLICY, "ours-with-host", "whitelist", ["host"]), "Type": "custom"}]


def _list_response(key, items, marker=None):
    page = {"MaxItems": 100, "Quantity": len(items), "Items": items}
    if marker:
        page["NextMarker"] = marker
    return {key: page}


def _validated(operation, response):
    """A canned response must be a valid response of the botocore operation (shape, required members, types)."""
    shape = boto3.client("cloudfront", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x").meta.service_model \
        .operation_model(operation).output_shape
    report = ParamValidator().validate({k: v for k, v in response.items() if k != "ResponseMetadata"}, shape)
    assert not report.has_errors(), report.generate_report()
    return response


def _stub_policy_reads(monkeypatch, *, cache=None, origin_request=None, custom_cache=None, fail=None):
    """moto does not implement cache / origin request policy reads: answer them (and only them) from canned listings."""
    original = BaseClient._make_api_call
    calls = []

    def patched(self, operation, params):
        if operation in {"ListCachePolicies", "ListOriginRequestPolicies"}:
            calls.append((operation, params.get("Type"), params.get("Marker")))
            if fail and operation in fail:
                raise ClientError({"Error": {"Code": fail[operation], "Message": "denied for arn:aws:cloudfront::123456789012:x"}}, operation)
            if operation == "ListCachePolicies":
                items = (cache if cache is not None else MANAGED_CACHE) if params["Type"] == "managed" else (custom_cache or [])
                return _validated(operation, _list_response("CachePolicyList", items))
            items = (origin_request if origin_request is not None else MANAGED_ORIGIN_REQUEST) if params["Type"] == "managed" else []
            return _validated(operation, _list_response("OriginRequestPolicyList", items))
        return original(self, operation, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)
    return calls


# ── distributions ─────────────────────────────────────────────────────────────

def api_config(policy=CACHING_OPTIMIZED, *, orp=None, origin_request_policy_id=None, enabled=True, feed_origin="s3-feed"):
    """A botocore DistributionConfig the way GetDistributionConfig returns it for the incident's distribution."""
    behavior = {"TargetOriginId": feed_origin, "ViewerProtocolPolicy": "redirect-to-https", "CachePolicyId": policy,
                "AllowedMethods": copy.deepcopy(_METHODS), "Compress": True}
    if origin_request_policy_id or orp:
        behavior["OriginRequestPolicyId"] = origin_request_policy_id or orp
    return {
        "CallerReference": "jarvis-feed-1", "Comment": "podcast feed", "Enabled": enabled,
        "Aliases": {"Quantity": 1, "Items": ["feed.jarvis.example"]},
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3-feed", "DomainName": f"{BUCKET}.s3.{REGION}.amazonaws.com", "OriginAccessControlId": OAC,
            "S3OriginConfig": {"OriginAccessIdentity": ""}}]},
        "DefaultCacheBehavior": {**copy.deepcopy(behavior), "CachePolicyId": CACHING_OPTIMIZED},
        "CacheBehaviors": {"Quantity": 1, "Items": [{"PathPattern": FEED, **copy.deepcopy(behavior)}]},
        "PriceClass": "PriceClass_All", "WebACLId": "",
    }


def distribution(config=None, **overrides):
    config = config or api_config()
    fields, problems = cfd.config_to_fields(config, replace=True)
    assert problems == []
    return CloudFrontDistribution(**{"id": DIST, "arn": DIST_ARN, "domain_name": "d1jarvis.cloudfront.net", "status": "Deployed",
                                     "etag": ETAG, "tags": {"app": "jarvis"}, **fields, **overrides})


def policies(*, cache=True, origin_request=True, custom=True):
    return CloudFrontData(
        cache_policies=[cfd.cache_policy_from(i, "managed") for i in MANAGED_CACHE] * cache
        + [cfd.cache_policy_from(i, "custom") for i in CUSTOM_CACHE] * (cache and custom),
        origin_request_policies=[cfd.origin_request_policy_from(i, "managed") for i in MANAGED_ORIGIN_REQUEST] * origin_request)


def base_with(*dists, data=None, with_bucket=True, collection="ok"):
    base = load_synthetic_base("delete")
    data = data or policies()
    data.distributions = list(dists or [distribution()])
    update = {"cloudfront": data, "collection": {**base.collection, "cloudfront": collection}}
    if with_bucket:
        update["s3"] = base.s3.model_copy(update={"buckets": [*base.s3.buckets, S3Bucket(name=BUCKET, has_cloudfront=True)]})
    return base.model_copy(update=update)


def find(infra, dist_id=DIST):
    return next(d for d in infra.cloudfront.distributions if d.id == dist_id)


def modeled(dist):
    """The distribution without the settings carried verbatim (they differ by input format, not by meaning)."""
    def strip(value):
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k not in {"extra", "etag"}}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    return strip(dist.model_dump(mode="json"))


def move_feed(policy, dist_id=DIST, **extra):
    return Change(op="modify", resource_type="cloudfront_distribution", resource_id=dist_id,
                  fields={"cache_behaviors": {FEED: {"cache_policy_id": policy, **extra}}})


def checked(base, branch, **kw):
    kw.setdefault("branch_id", "law-branch")
    kw.setdefault("base_analysis_id", "law-base")
    kw.setdefault("branch_revision", "rev")
    return check_for_branch(base, branch, **kw).model_dump(mode="json")


def availability(body):
    return next(a for a in body["answers"] if a["damage"] == "availability")


def host_facts(body):
    return [f for f in availability(body)["facts"] if f.get("change") == "origin_receives_host_header"]


EXPECTED_FACT = {
    "resource_id": DIST, "resource_type": "cloudfront_distribution", "change": "origin_receives_host_header",
    "resource_ids": [BUCKET], "path_pattern": FEED, "cache_policy_id": USE_ORIGIN_CACHE_CONTROL,
    "origin_request_policy_id": None, "source_url": SOURCE_URL,
}


# ── L78a collector ────────────────────────────────────────────────────────────

@pytest.fixture
def aws(monkeypatch):
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        yield boto3.client("cloudfront", region_name=REGION)


def _collect():
    warnings = []
    return cfd.collect_cloudfront("testing", "testing", "testing", REGION, warnings), warnings


def _create(client, config=None, tags=None):
    config = config or api_config()
    config["CallerReference"] = f"ref-{len(client.list_distributions().get('DistributionList', {}).get('Items', []))}"
    if tags:
        return client.create_distribution_with_tags(DistributionConfigWithTags={"DistributionConfig": config, "Tags": {
            "Items": [{"Key": k, "Value": v} for k, v in tags.items()]}})["Distribution"]
    return client.create_distribution(DistributionConfig=config)["Distribution"]


def test_L78a_collector_reads_behaviors_origins_tags_and_policy_rules(aws, monkeypatch):
    created = _create(aws, tags={"app": "jarvis"})
    _stub_policy_reads(monkeypatch, custom_cache=CUSTOM_CACHE)
    data, warnings = _collect()
    assert data.collection_status == {"cloudfront": "ok"} and warnings == []
    dist = next(d for d in data.distributions if d.id == created["Id"])
    assert dist.arn == created["ARN"] and dist.aliases == ["feed.jarvis.example"] and dist.enabled is True
    assert dist.etag and dist.tags == {"app": "jarvis"} and dist.status
    assert [(b.path_pattern, b.target_origin_id, b.cache_policy_id) for b in dist.cache_behaviors] == [(FEED, "s3-feed", CACHING_OPTIMIZED)]
    assert (dist.default_cache_behavior.path_pattern, dist.default_cache_behavior.cache_policy_id) == ("*", CACHING_OPTIMIZED)
    assert dist.cache_behaviors[0].allowed_methods == ["GET", "HEAD"] and dist.cache_behaviors[0].viewer_protocol_policy == "redirect-to-https"
    origin = dist.origins[0]
    assert (origin.id, origin.origin_type, origin.s3_bucket) == ("s3-feed", "s3", BUCKET)
    # settings that are not modeled are carried verbatim, so a full replace can be exact
    assert dist.extra["Comment"] == "podcast feed" and "ViewerCertificate" in dist.extra


def test_L78a_every_policy_is_read_from_the_provider_whether_or_not_a_distribution_uses_it(aws, monkeypatch):
    """The managed policy a branch moves to is usually not used by any distribution yet: its rule must still be known."""
    _create(aws)
    calls = _stub_policy_reads(monkeypatch, custom_cache=CUSTOM_CACHE)
    data, _ = _collect()
    by_id = {p.id: p for p in data.cache_policies}
    assert by_id[USE_ORIGIN_CACHE_CONTROL].type == "managed" and by_id[USE_ORIGIN_CACHE_CONTROL].forwards_host is True
    assert by_id[USE_ORIGIN_CACHE_CONTROL].headers_behavior == "whitelist" and "Host" in by_id[USE_ORIGIN_CACHE_CONTROL].headers
    assert by_id[CACHING_OPTIMIZED].forwards_host is False and by_id[CACHING_DISABLED].forwards_host is False
    assert by_id[CUSTOM_HOST_POLICY].type == "custom" and by_id[CUSTOM_HOST_POLICY].forwards_host is True
    orp = {p.id: p for p in data.origin_request_policies}
    assert (orp[ALL_VIEWER].forwards_host, orp[ALL_VIEWER_EXCEPT_HOST].forwards_host, orp[CORS_S3].forwards_host) == (True, False, False)
    assert {(op, kind) for op, kind, _ in calls} == {(op, kind) for op in ("ListCachePolicies", "ListOriginRequestPolicies") for kind in ("managed", "custom")}


def test_L78a_header_rules_follow_botocore_enums_and_never_guess():
    cases = [("none", [], False, False), ("whitelist", ["Origin"], False, False), ("whitelist", ["HOST"], True, True),
             ("allViewer", [], None, True), ("allViewerAndWhitelistCloudFront", [], None, True),
             ("allExcept", ["Host"], None, False), ("allExcept", ["Origin"], None, True), ("brand-new-rule", [], None, None)]
    for behavior, headers, cache_expected, orp_expected in cases:
        assert cfd.header_rule_forwards_host(behavior, headers, origin_request=False) == cache_expected, behavior
        assert cfd.header_rule_forwards_host(behavior, headers, origin_request=True) == orp_expected, behavior
    model = boto3.client("cloudfront", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x").meta.service_model
    assert set(model.shape_for("CachePolicyHeaderBehavior").enum) == {"none", "whitelist"}
    assert set(model.shape_for("OriginRequestPolicyHeaderBehavior").enum) == {"none", "whitelist", "allViewer", "allViewerAndWhitelistCloudFront", "allExcept"}


def test_L78a_a_policy_without_a_header_rule_is_unknown():
    item = {"Type": "managed", "CachePolicy": {"Id": "x", "LastModifiedTime": _NOW, "CachePolicyConfig": {"Name": "bare", "MinTTL": 0}}}
    assert cfd.cache_policy_from(item, "managed").forwards_host is None


def test_L78a_oac_custom_origins_and_secret_headers(aws, monkeypatch):
    """moto drops origin access control and custom origin details, so a full configuration is served for the read."""
    config = api_config()
    config["Origins"]["Items"].append({
        "Id": "api", "DomainName": "api.jarvis.example", "OriginAccessControlId": "",
        "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"},
        "CustomHeaders": {"Quantity": 1, "Items": [{"HeaderName": "X-Origin-Verify", "HeaderValue": "planted-secret-zq7"}]}})
    config["Origins"]["Quantity"] = 2
    _create(aws)
    _stub_policy_reads(monkeypatch)
    original = BaseClient._make_api_call
    monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (
        {"DistributionConfig": config, "ETag": ETAG} if op == "GetDistributionConfig" else original(self, op, params)))
    data, _ = _collect()
    dist = data.distributions[0]
    s3, custom = dist.origins
    assert (s3.origin_type, s3.origin_access_control_id, s3.s3_bucket) == ("s3", OAC, BUCKET)
    assert (custom.origin_type, custom.origin_access_control_id, custom.s3_bucket) == ("custom", None, None)
    assert dist.withheld_settings == ["Origins.CustomHeaders"]
    assert "planted-secret" not in dist.model_dump_json() and "X-Origin-Verify" not in dist.model_dump_json()
    assert dist.etag == ETAG


def test_L78a_an_s3_website_endpoint_is_a_custom_origin_not_a_bucket():
    assert cfd.origin_kind(f"{BUCKET}.s3-website-us-east-1.amazonaws.com", custom_config=True) == "custom"
    assert cfd.s3_bucket_of(f"{BUCKET}.s3.amazonaws.com") == BUCKET
    assert cfd.s3_bucket_of(f"{BUCKET}.s3.us-east-1.amazonaws.com") == BUCKET
    assert cfd.s3_bucket_of(f"{BUCKET}.s3.dualstack.us-east-1.amazonaws.com") == BUCKET
    assert cfd.s3_bucket_of("my.dotted.bucket.s3-eu-west-1.amazonaws.com") == "my.dotted.bucket"
    assert cfd.s3_bucket_of("api.example.com") is None


def test_L78a_listings_are_followed_across_pages(aws, monkeypatch):
    for _ in range(3):
        _create(aws)
    original = BaseClient._make_api_call
    pages = []

    def patched(self, operation, params):
        if operation == "ListCachePolicies" and params["Type"] == "custom":
            pages.append(params.get("Marker"))
            if not params.get("Marker"):
                return _validated(operation, _list_response("CachePolicyList", CUSTOM_CACHE, marker="page-2"))
            second = {**CUSTOM_CACHE[0], "CachePolicy": {**CUSTOM_CACHE[0]["CachePolicy"], "Id": "second"}}
            return _validated(operation, _list_response("CachePolicyList", [second]))
        if operation in {"ListCachePolicies", "ListOriginRequestPolicies"}:
            return _validated(operation, _list_response("CachePolicyList" if operation == "ListCachePolicies" else "OriginRequestPolicyList", []))
        return original(self, operation, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)
    data, _ = _collect()
    assert len(data.distributions) == 3 and pages == [None, "page-2"]
    assert {p.id for p in data.cache_policies} == {CUSTOM_HOST_POLICY, "second"}


def test_L78a_collector_only_makes_the_reads_the_role_grants(aws, monkeypatch):
    _create(aws)
    aws.create_origin_access_control(OriginAccessControlConfig={
        "Name": "oac", "SigningProtocol": "sigv4", "SigningBehavior": "always", "OriginAccessControlOriginType": "s3"})
    _stub_policy_reads(monkeypatch)
    seen = []
    original = BaseClient._make_api_call
    monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (seen.append(op), original(self, op, params))[1])
    data, _ = _collect()
    assert set(seen) == set(cfd.COLLECTOR_OPERATIONS)
    assert [c.name for c in data.origin_access_controls] == ["oac"] and data.origin_access_controls[0].origin_type == "s3"


# ── L78b denied / error ───────────────────────────────────────────────────────

def _fail(monkeypatch, code, operations):
    original = BaseClient._make_api_call

    def patched(self, operation, params):
        if operation in operations:
            raise ClientError({"Error": {"Code": code, "Message": f"arn:aws:cloudfront::123456789012:distribution/{DIST}"}}, operation)
        return original(self, operation, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)


@pytest.mark.parametrize("code, status", [("AccessDenied", "denied"), ("InternalFailure", "error")])
def test_L78b_failed_list_is_recorded_not_empty(aws, monkeypatch, code, status):
    _create(aws)
    _fail(monkeypatch, code, {"ListDistributions"})
    data, warnings = _collect()
    assert data.distributions == [] and data.collection_status == {"cloudfront": status}
    assert warnings and "arn:aws" not in " ".join(warnings) and DIST not in " ".join(warnings)


def test_L78b_denied_configuration_keeps_the_list_view_without_an_etag(aws, monkeypatch):
    _create(aws)
    _stub_policy_reads(monkeypatch)
    _fail(monkeypatch, "AccessDenied", {"GetDistributionConfig"})
    data, _ = _collect()
    dist = data.distributions[0]
    assert data.collection_status == {"cloudfront": "denied"}
    assert dist.etag is None and dist.extra == {} and dist.cache_behaviors[0].path_pattern == FEED
    assert dist.cache_behaviors[0].cache_policy_id == CACHING_OPTIMIZED


def test_L78b_denied_policy_reads_make_forwarding_unknown_never_false(aws, monkeypatch):
    _create(aws)
    _stub_policy_reads(monkeypatch, fail={"ListCachePolicies": "AccessDenied", "ListOriginRequestPolicies": "AccessDenied"})
    data, _ = _collect()
    assert data.collection_status == {"cloudfront": "denied"} and data.cache_policies == []
    assert data.behavior_forwards_host(data.distributions[0].cache_behaviors[0]) is None
    assert any(e.relationship.value == "serves_from_bucket" and e.attrs["forwards_host"] is None
               for e in build_graph(AWSInfrastructure(cloudfront=data, s3={"buckets": [{"name": BUCKET}]})).edges)


def test_L78b_denied_collection_is_unknown_in_context_and_ok_is_known():
    for status in ("denied", "error"):
        infra = base_with(collection=status)
        for question in ("inventory", "resource", "depends_on", "dependents"):
            body = answer_for_infra(question, infra, analysis_id="a", resource_id=DIST if question != "dependents" else BUCKET).model_dump(mode="json")
            reasons = {u["topic"]: u["reason"] for u in body["unknown"]}
            assert status in reasons.get("cloudfront", ""), (question, reasons)
            assert "cloudfront" not in {k["topic"] for k in body["known"]}
    body = answer_for_infra("inventory", base_with(), analysis_id="a").model_dump(mode="json")
    assert "cloudfront" in {k["topic"] for k in body["known"]} and "cloudfront" not in {u["topic"] for u in body["unknown"]}
    assert any(f["resource_id"] == DIST and f["resource_type"] == "cloudfront_distribution" for f in body["facts"])


def test_L78b_denied_collection_never_produces_the_fact_only_unknown():
    base = base_with(collection="denied", data=policies(cache=False, origin_request=False))
    branch = apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL))
    body = checked(base, branch)
    assert host_facts(body) == []
    topics = {u["topic"] for u in availability(body)["unknown"]}
    assert {"cloudfront", "origin_host_header"} <= topics


# ── L78c graph ────────────────────────────────────────────────────────────────

def _edges(graph, source):
    return [(e.dst, e.relationship.value, e.attrs) for e in graph.edges if e.src == source]


def test_L78c_real_node_edges_and_schema():
    graph = build_graph(base_with())
    assert validate_graph(graph) == []
    node = next(n for n in graph.nodes if n.id == DIST)
    assert node.resource_type == "cloudfront_distribution" and node.category.value == "edge"
    assert node.base["aliases"] == ["feed.jarvis.example"] and node.base["enabled"] is True
    assert [b["path_pattern"] for b in node.base["behaviors"]] == ["*", FEED]
    assert node.base["origins"][0]["origin_access_control_id"] == OAC and node.base["origins"][0]["s3_bucket"] == BUCKET
    attrs = sorted(_edges(graph, DIST), key=lambda e: e[2]["path_pattern"])
    assert attrs == [(BUCKET, "serves_from_bucket", {"path_pattern": "*", "oac": True, "forwards_host": False}),
                     (BUCKET, "serves_from_bucket", {"path_pattern": FEED, "oac": True, "forwards_host": False})]


def test_L78c_the_edge_carries_forwards_host_true_false_and_unknown():
    for policy, expected in ((CACHING_OPTIMIZED, False), (USE_ORIGIN_CACHE_CONTROL, True), (UNCOLLECTED, None)):
        graph = build_graph(base_with(distribution(api_config(policy))))
        feed = next(a for _, _, a in _edges(graph, DIST) if a["path_pattern"] == FEED)
        assert feed["forwards_host"] is expected, policy
    # an origin request policy that forwards Host counts even with a cache policy that does not
    graph = build_graph(base_with(distribution(api_config(CACHING_OPTIMIZED, orp=ALL_VIEWER))))
    assert next(a for _, _, a in _edges(graph, DIST) if a["path_pattern"] == FEED)["forwards_host"] is True
    graph = build_graph(base_with(distribution(api_config(CACHING_OPTIMIZED, orp=ALL_VIEWER_EXCEPT_HOST))))
    assert next(a for _, _, a in _edges(graph, DIST) if a["path_pattern"] == FEED)["forwards_host"] is False


def test_L78c_legacy_forwarded_headers_are_read_too():
    config = api_config()
    for behavior in (config["DefaultCacheBehavior"], config["CacheBehaviors"]["Items"][0]):
        behavior.pop("CachePolicyId")
        behavior["ForwardedValues"] = {"QueryString": False, "Cookies": {"Forward": "none"},
                                       "Headers": {"Quantity": 1, "Items": ["Host"]}}
        behavior.update(MinTTL=0, DefaultTTL=0, MaxTTL=0)
    dist = distribution(config)
    assert dist.cache_behaviors[0].uses_legacy_forwarded_values is True
    assert base_with(dist).cloudfront.behavior_forwards_host(dist.cache_behaviors[0]) is True
    config["CacheBehaviors"]["Items"][0]["ForwardedValues"]["Headers"] = {"Quantity": 0}
    assert base_with(distribution(config)).cloudfront.behavior_forwards_host(distribution(config).cache_behaviors[0]) is False


def test_L78c_no_duplicate_node_the_synthetic_one_only_without_collected_distributions():
    graph = build_graph(base_with())
    assert [n.id for n in graph.nodes if n.resource_type == "cloudfront_distribution"] == [DIST]
    legacy = load_synthetic_base("delete")
    legacy = legacy.model_copy(update={"s3": legacy.s3.model_copy(update={"buckets": [S3Bucket(name=BUCKET, has_cloudfront=True)]})})
    nodes = [n for n in build_graph(legacy).nodes if n.resource_type == "cloudfront_distribution"]
    assert [n.id for n in nodes] == [f"cloudfront-{BUCKET}"] and validate_graph(build_graph(legacy)) == []
    # a bucket flagged has_cloudfront that no collected distribution covers keeps its synthetic node
    other = base_with()
    other.s3.buckets.append(S3Bucket(name="other-bucket", has_cloudfront=True))
    ids = sorted(n.id for n in build_graph(other).nodes if n.resource_type == "cloudfront_distribution")
    assert ids == sorted([DIST, "cloudfront-other-bucket"])


def test_L78c_a_custom_origin_gets_no_bucket_edge_and_is_not_an_orphan():
    config = api_config()
    config["Origins"]["Items"] = [{"Id": "s3-feed", "DomainName": "api.jarvis.example", "CustomOriginConfig": {
        "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"}}]
    graph = build_graph(base_with(distribution(config)))
    assert _edges(graph, DIST) == []
    from app.egraph import find_orphaned_resources
    assert DIST not in {n["id"] for n in find_orphaned_resources(graph)}


def test_L78c_deleting_the_bucket_lists_the_distribution_as_dependent_with_the_dependency_direction():
    base = base_with()
    branch = apply_change(base, Change(op="delete", resource_type="s3_bucket", resource_id=BUCKET, fields={}))
    impact = next(i for i in analyze_deletions(base, branch).impacts if i.resource_id == DIST)
    assert (impact.resource_type, impact.relation, impact.depth) == ("cloudfront_distribution", "serves_from_bucket", 1)
    # the other direction: the distribution goes away, the bucket does not
    assert [i.resource_id for i in analyze_deletions(base, base).impacts] == []


def test_L78c_the_distribution_is_a_dependent_of_the_bucket_in_context():
    body = answer_for_infra("dependents", base_with(), analysis_id="a", resource_id=BUCKET).model_dump(mode="json")
    assert any(f["resource_id"] == DIST and f["relationship"] == "serves_from_bucket" for f in body["facts"])
    body = answer_for_infra("depends_on", base_with(), analysis_id="a", resource_id=DIST).model_dump(mode="json")
    assert BUCKET in {f["resource_id"] for f in body["facts"]}
    body = answer_for_infra("resource", base_with(), analysis_id="a", resource_id=DIST).model_dump(mode="json")
    assert body["facts"] and any(f["resource_id"] == DIST for f in body["facts"])


# ── L78d branch changes ───────────────────────────────────────────────────────

def test_L78d_moving_a_behavior_to_a_cache_policy_is_pure_and_changes_only_that_behavior():
    base = base_with()
    before = base.model_dump(mode="json")
    branch = apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL))
    assert base.model_dump(mode="json") == before
    assert find(branch).cache_behaviors[0].cache_policy_id == USE_ORIGIN_CACHE_CONTROL
    assert find(base).cache_behaviors[0].cache_policy_id == CACHING_OPTIMIZED
    assert find(branch).default_cache_behavior == find(base).default_cache_behavior
    assert find(branch).model_dump(exclude={"cache_behaviors"}) == find(base).model_dump(exclude={"cache_behaviors"})
    assert find(branch).cache_behaviors[0].extra == find(base).cache_behaviors[0].extra  # what the change did not state is kept


def test_L78d_the_policy_change_is_in_the_diff_with_before_and_after():
    base = base_with()
    branch = apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL))
    diff = diff_infrastructure(base, branch)
    entries = [i for i in diff.resources_modified if i["resource_type"] == "cloudfront_distribution"]
    assert [(e["id"], e["changed"]) for e in entries] == [(DIST, ["base.behaviors"])]
    values = entries[0]["values"]["base.behaviors"]
    feed = lambda rows: next(r for r in rows if r["path_pattern"] == FEED)
    assert (feed(values["before"])["cache_policy_id"], feed(values["before"])["forwards_host"]) == (CACHING_OPTIMIZED, False)
    assert (feed(values["after"])["cache_policy_id"], feed(values["after"])["forwards_host"]) == (USE_ORIGIN_CACHE_CONTROL, True)
    assert diff.resources_added == [] and diff.resources_removed == [] and diff.modeled_state_unchanged is False
    reverse = diff_infrastructure(branch, base)
    assert feed(next(i for i in reverse.resources_modified if i["resource_type"] == "cloudfront_distribution")["values"]["base.behaviors"]["after"])["cache_policy_id"] == CACHING_OPTIMIZED


def test_L78d_origin_request_policy_default_behavior_and_enabled():
    base = base_with()
    branch = apply_changes(base, [
        Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={
            "enabled": False, "default_cache_behavior": {"origin_request_policy_id": ALL_VIEWER},
            "cache_behaviors": {FEED: {"origin_request_policy_id": ALL_VIEWER_EXCEPT_HOST}}})])
    dist = find(branch)
    assert dist.enabled is False and dist.default_cache_behavior.origin_request_policy_id == ALL_VIEWER
    assert dist.cache_behaviors[0].origin_request_policy_id == ALL_VIEWER_EXCEPT_HOST
    entry = next(i for i in diff_infrastructure(base, branch).resources_modified if i["resource_type"] == "cloudfront_distribution")
    assert entry["changed"] == ["base.behaviors", "base.enabled"]
    assert entry["values"]["base.enabled"] == {"before": True, "after": False}


@pytest.mark.parametrize("fields", [
    {"cache_behaviors": {"nope/*": {"cache_policy_id": CACHING_OPTIMIZED}}},
    {"cache_behaviors": {FEED: {"path_pattern": "other"}}},
    {"cache_behaviors": {FEED: {"target_origin_id": "no-such-origin"}}},
    {"cache_behaviors": {FEED: {"viewer_protocol_policy": "plain-http"}}},
    {"cache_behaviors": {FEED: {"allowed_methods": ["GET", "TELEPORT"]}}},
    {"cache_behaviors": {FEED: {"unknown_field": 1}}},
    {"cache_behaviors": {FEED: {"cache_policy_id": 7}}},
    {"cache_behaviors": "all"}, {"default_cache_behavior": {"path_pattern": "images/*"}},
    {"enabled": "yes"}, {"price_class": "PriceClass_Everything"}, {"aliases": "a.example"},
    {"etag": "x"}, {"arn": "arn:aws:cloudfront::1:distribution/x"}, {"domain_name": "x"}, {"tags": {}}, {"unknown": 1}, {},
    {"origins": [{"id": "s3-feed", "domain_name": "x", "origin_type": "ftp"}]},
    {"origins": [{"domain_name": "x"}]},
    {"origins": [{"id": "other", "domain_name": f"{BUCKET}.s3.amazonaws.com"}]},  # removes the origin the behaviors target
])
def test_L78d_values_aws_would_reject_are_rejected(fields):
    with pytest.raises(ValueError):
        apply_change(base_with(), Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields=fields))


def test_L78d_a_behavior_cannot_lose_its_cache_policy_without_legacy_settings():
    with pytest.raises(ValueError):
        apply_change(base_with(), move_feed(None))


def test_L78d_moving_a_legacy_behavior_to_a_cache_policy_drops_the_settings_aws_rejects_beside_one():
    config = api_config()
    legacy = config["CacheBehaviors"]["Items"][0]
    legacy.pop("CachePolicyId")
    legacy.update(ForwardedValues={"QueryString": True, "Cookies": {"Forward": "all"}}, MinTTL=0, DefaultTTL=60, MaxTTL=600)
    base = base_with(distribution(config))
    assert find(base).cache_behaviors[0].uses_legacy_forwarded_values is True
    moved = find(apply_change(base, move_feed(CACHING_OPTIMIZED))).cache_behaviors[0]
    assert moved.uses_legacy_forwarded_values is False
    assert not set(moved.extra) & {"ForwardedValues", "MinTTL", "DefaultTTL", "MaxTTL"} and moved.extra["Compress"] is True
    call = build_api_calls(base, [move_feed(CACHING_OPTIMIZED)])[0]["params"]["DistributionConfig"]["CacheBehaviors"]["Items"][0]
    assert call["CachePolicyId"] == CACHING_OPTIMIZED and not set(call) & {"ForwardedValues", "MinTTL", "DefaultTTL", "MaxTTL"}


def test_L78d_a_complete_behavior_list_replaces_and_keeps_unstated_settings():
    base = base_with()
    kept = [{"path_pattern": FEED, "cache_policy_id": USE_ORIGIN_CACHE_CONTROL, "target_origin_id": "s3-feed"}]
    branch = apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"cache_behaviors": kept}))
    assert find(branch).cache_behaviors[0].extra == find(base).cache_behaviors[0].extra
    assert find(branch).cache_behaviors[0].allowed_methods == ["GET", "HEAD"]
    dropped = apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"cache_behaviors": []}))
    assert find(dropped).cache_behaviors == []
    with pytest.raises(ValueError):
        apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"cache_behaviors": kept + kept}))


def test_L78d_missing_distribution_names_no_resource_and_add_delete_are_not_modeled():
    with pytest.raises(TargetNotFound) as exc:
        apply_change(base_with(), Change(op="modify", resource_type="cloudfront_distribution", resource_id="EMISSING", fields={"enabled": False}))
    assert "EMISSING" not in str(exc.value)
    for op in ("add", "delete"):
        with pytest.raises(ValueError, match="modify only"):
            apply_change(base_with(), Change(op=op, resource_type="cloudfront_distribution", resource_id=DIST, fields={}))
    capability = next(c for c in mutation_capabilities().resources if c.resource_type == "cloudfront_distribution")
    assert capability.operations == ["modify"]
    message = capability.constraints[0].message
    assert "Adding or deleting a distribution is not modeled" in message and "not interpreted" in message
    assert {"cache_behaviors", "default_cache_behavior", "enabled"} <= set(capability.constraints[0].allowed_fields)


def test_L78d_api_branch_flow_shows_the_change_in_the_diff_and_the_check(monkeypatch):
    from app import main
    from tests.test_branch_api import client

    base = base_with()
    main._branch_request_log.clear()
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _id: base)
    created = client.post("/branches", json={"base_analysis_id": "l78-api", "name": "l78-api"})
    assert created.status_code == 200, created.text
    branch_id = created.json()["branch_id"]
    capabilities = client.get("/branches/capabilities").json()["resources"]
    assert next(c for c in capabilities if c["resource_type"] == "cloudfront_distribution")["operations"] == ["modify"]
    rejected = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "cloudfront_distribution", "resource_id": DIST, "fields": {"cache_behaviors": {"nope": {"cache_policy_id": "x"}}}})
    assert rejected.status_code == 422, rejected.text
    ok = client.post(f"/branches/{branch_id}/changes", json={
        "op": "modify", "resource_type": "cloudfront_distribution", "resource_id": DIST,
        "fields": {"cache_behaviors": {FEED: {"cache_policy_id": USE_ORIGIN_CACHE_CONTROL}}}})
    assert ok.status_code == 200, ok.text
    diff = client.get(f"/branches/{branch_id}/diff").json()
    assert [i["id"] for i in diff["resources_modified"] if i["resource_type"] == "cloudfront_distribution"] == [DIST]
    check = client.get(f"/branches/{branch_id}/check")
    assert check.status_code == 200, check.text
    assert host_facts(check.json()) == [EXPECTED_FACT]
    handback = client.get(f"/branches/{branch_id}/handback")
    assert handback.status_code == 200, handback.text
    assert [c["operation"] for c in handback.json()["calls"]] == ["UpdateDistribution"]


# ── L78e four formats ─────────────────────────────────────────────────────────

def _cli(command):
    return translate_api_calls(parse_cli_commands({"format": "aws-cli/1", "commands": [command]}))


def _api(parameters, **call):
    return translate_api_calls({"format": "aws-api-calls/1", "calls": [
        {"service": "cloudfront", "operation": "UpdateDistribution", "parameters": parameters, **call}]})


def _api_update(config):
    return _api({"Id": DIST, "IfMatch": ETAG, "DistributionConfig": config})


def _cfn_config(policy):
    return {
        "Comment": "podcast feed", "Enabled": True, "Aliases": ["feed.jarvis.example"], "PriceClass": "PriceClass_All", "WebACLId": "",
        "Origins": [{"Id": "s3-feed", "DomainName": f"{BUCKET}.s3.{REGION}.amazonaws.com", "OriginAccessControlId": OAC,
                     "S3OriginConfig": {"OriginAccessIdentity": ""}}],
        "DefaultCacheBehavior": {"TargetOriginId": "s3-feed", "ViewerProtocolPolicy": "redirect-to-https", "CachePolicyId": CACHING_OPTIMIZED,
                                 "AllowedMethods": ["GET", "HEAD"], "CachedMethods": ["GET", "HEAD"], "Compress": True},
        "CacheBehaviors": [{"PathPattern": FEED, "TargetOriginId": "s3-feed", "ViewerProtocolPolicy": "redirect-to-https", "CachePolicyId": policy,
                            "AllowedMethods": ["GET", "HEAD"], "CachedMethods": ["GET", "HEAD"], "Compress": True}],
    }


def _cfn(before_policy, after_policy, after_extra=None):
    after = {**_cfn_config(after_policy), **(after_extra or {})}
    change = {"Action": "Modify", "LogicalResourceId": "Feed", "ResourceType": "AWS::CloudFront::Distribution", "PhysicalResourceId": DIST,
              "Replacement": "False",
              "BeforeContext": json.dumps({"Properties": {"DistributionConfig": _cfn_config(before_policy)}}),
              "AfterContext": json.dumps({"Properties": {"DistributionConfig": after}})}
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": change}]})
    assert extras == []
    return translate_api_calls(doc)


def _tf_behavior(policy, **extra):
    return {"target_origin_id": "s3-feed", "viewer_protocol_policy": "redirect-to-https", "cache_policy_id": policy,
            "origin_request_policy_id": "", "allowed_methods": ["GET", "HEAD"], "cached_methods": ["GET", "HEAD"], "compress": True,
            "forwarded_values": [], "lambda_function_association": [], **extra}


def _tf_state(policy, **top):
    return {"id": DIST, "enabled": True, "aliases": ["feed.jarvis.example"], "price_class": "PriceClass_All", "web_acl_id": "",
            "comment": "podcast feed", "viewer_certificate": [{"cloudfront_default_certificate": True}],
            "default_cache_behavior": [_tf_behavior(CACHING_OPTIMIZED)],
            "ordered_cache_behavior": [{"path_pattern": FEED, **_tf_behavior(policy)}],
            "origin": [{"origin_id": "s3-feed", "domain_name": f"{BUCKET}.s3.{REGION}.amazonaws.com", "origin_access_control_id": OAC,
                        "s3_origin_config": [], "custom_origin_config": [], "origin_path": ""}], **top}


def _tf(before, after, unknown=None, actions=("update",)):
    return translate_plan({"format_version": "1.2", "resource_changes": [{
        "address": "aws_cloudfront_distribution.feed", "type": "aws_cloudfront_distribution", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": list(actions), "before": before, "after": after, "after_unknown": unknown or {}}}]})


def _incident_results():
    cli_config = json.dumps(api_config(USE_ORIGIN_CACHE_CONTROL), separators=(",", ":"))
    return {
        "api": _api_update(api_config(USE_ORIGIN_CACHE_CONTROL)),
        "cli": _cli(f"aws cloudfront update-distribution --id {DIST} --if-match {ETAG} --distribution-config '{cli_config}'"),
        "cfn": _cfn(CACHING_OPTIMIZED, USE_ORIGIN_CACHE_CONTROL),
        "terraform": _tf(_tf_state(CACHING_OPTIMIZED), _tf_state(USE_ORIGIN_CACHE_CONTROL)),
    }


def test_L78e_the_incident_gives_the_same_branch_and_the_same_fact_in_all_four_formats():
    base = base_with()
    results = _incident_results()
    states = {}
    for name, result in results.items():
        assert result["unknown_fields"] == [] and result["unmodeled"] == [], (name, result["unknown_fields"], result["unmodeled"])
        assert [(c.op, c.resource_type, c.resource_id) for c in result["changes"]] == [("modify", "cloudfront_distribution", DIST)], name
        branch = apply_changes(base, result["changes"])
        states[name] = modeled(find(branch))
        entry = next(i for i in diff_infrastructure(base, branch).resources_modified if i["resource_type"] == "cloudfront_distribution")
        assert entry["changed"] == ["base.behaviors"], name
        assert host_facts(checked(base, branch)) == [EXPECTED_FACT], name
    assert len({json.dumps(v, sort_keys=True) for v in states.values()}) == 1, states
    assert states["api"]["cache_behaviors"][0]["cache_policy_id"] == USE_ORIGIN_CACHE_CONTROL


def test_L78e_the_fix_is_no_fact_in_all_four_formats():
    base = base_with(distribution(api_config(USE_ORIGIN_CACHE_CONTROL)))
    cli_config = json.dumps(api_config(CACHING_OPTIMIZED), separators=(",", ":"))
    for name, result in {
        "api": _api_update(api_config(CACHING_OPTIMIZED)),
        "cli": _cli(f"aws cloudfront update-distribution --id {DIST} --if-match {ETAG} --distribution-config '{cli_config}'"),
        "cfn": _cfn(USE_ORIGIN_CACHE_CONTROL, CACHING_OPTIMIZED),
        "terraform": _tf(_tf_state(USE_ORIGIN_CACHE_CONTROL), _tf_state(CACHING_OPTIMIZED)),
    }.items():
        branch = apply_changes(base, result["changes"])
        assert find(branch).cache_behaviors[0].cache_policy_id == CACHING_OPTIMIZED, name
        assert host_facts(checked(base, branch)) == [], name


def test_L78e_a_full_api_replace_states_every_member_missing_required_ones_are_unknown_not_defaults():
    for missing in ("Origins", "DefaultCacheBehavior", "Enabled"):
        config = api_config()
        config.pop(missing)
        result = _api_update(config)
        assert [(u["field"], u["reason"]) for u in result["unknown_fields"]] == [(missing, "required_member_missing")]
    # a call that leaves aliases, price class and web ACL out clears them: the call states the whole distribution
    config = api_config()
    for member in ("Aliases", "PriceClass", "WebACLId"):
        config.pop(member)
    fields = _api_update(config)["changes"][0].fields
    assert (fields["aliases"], fields["price_class"], fields["web_acl_id"]) == ([], None, None)
    # unmodeled members are carried, not dropped and not flagged
    result = _api_update({**api_config(), "Logging": {"Enabled": True, "IncludeCookies": False, "Bucket": "logs.s3.amazonaws.com", "Prefix": ""}})
    assert result["unknown_fields"] == [] and result["changes"][0].fields["extra"]["Logging"]["Enabled"] is True


def test_L78e_api_call_with_other_parameters_or_no_config_is_visible():
    assert [u["field"] for u in _api({"Id": DIST, "DistributionConfig": api_config(), "Surprise": 1})["unknown_fields"]] == ["Surprise"]
    result = _api({"Id": DIST})
    assert result["changes"] == [] and len(result["unmodeled"]) == 1


def test_L78e_terraform_unmodeled_and_unknown_values_stay_visible():
    before, after = _tf_state(CACHING_OPTIMIZED), _tf_state(CACHING_OPTIMIZED, comment="why", viewer_certificate=[{"acm_certificate_arn": "arn:aws:acm:x"}])
    after["default_cache_behavior"] = [_tf_behavior(CACHING_OPTIMIZED, compress=False)]
    result = _tf(before, after)
    assert {u["field"] for u in result["unknown_fields"]} == {"comment", "viewer_certificate", "default_cache_behavior.compress"}
    assert all(u["reason"] == "unsupported_attribute" for u in result["unknown_fields"]) and result["changes"] == []
    unknown_after = _tf_state(None)
    result = _tf(_tf_state(CACHING_OPTIMIZED), unknown_after, {"ordered_cache_behavior": [{"cache_policy_id": True}]})
    assert [u["field"] for u in result["unknown_fields"]] == ["ordered_cache_behavior.cache_policy_id"]
    assert result["changes"] == []  # the unknown value is not applied as if it were the old one
    result = _tf(_tf_state(CACHING_OPTIMIZED), _tf_state(CACHING_OPTIMIZED), {"etag": True, "last_modified_time": True, "status": True})
    assert result["unknown_fields"] == [] and result["changes"] == []


def test_L78e_terraform_create_and_delete_of_a_distribution_are_unmodeled_not_silent():
    for actions, before, after in ((("create",), None, _tf_state(CACHING_OPTIMIZED)), (("delete",), _tf_state(CACHING_OPTIMIZED), None)):
        result = _tf(before, after, actions=actions)
        assert result["changes"] == [] and [u["type"] for u in result["unmodeled"]] == ["aws_cloudfront_distribution"]


def test_L78e_cloudformation_unmodeled_changes_are_named_replacement_is_an_extra():
    result = _cfn(CACHING_OPTIMIZED, USE_ORIGIN_CACHE_CONTROL, {"Comment": "new words", "Logging": {"Bucket": "logs"}})
    assert {u["field"] for u in result["unknown_fields"]} == {"DistributionConfig.Comment", "DistributionConfig.Logging"}
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Modify", "LogicalResourceId": "Feed", "ResourceType": "AWS::CloudFront::Distribution", "PhysicalResourceId": DIST,
        "Replacement": "True", "BeforeContext": json.dumps({"Properties": {}}), "AfterContext": json.dumps({"Properties": {}})}}]})
    assert doc["calls"] == [] or all(c["operation"] != "UpdateDistribution" for c in doc["calls"])
    assert extras
    doc, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Modify", "LogicalResourceId": "Feed", "ResourceType": "AWS::CloudFront::Distribution",
        "AfterContext": json.dumps({"Properties": {"DistributionConfig": {}}})}}]})
    assert doc["calls"] == [] and len(extras) == 1


# ── L78f hand-back ────────────────────────────────────────────────────────────

def test_L78f_the_incident_hands_back_one_exact_update_distribution():
    base = base_with()
    calls = build_api_calls(base, _incident_results()["api"]["changes"])
    assert calls == [{"change_index": 0, "service": "cloudfront", "operation": "UpdateDistribution", "params": {
        "Id": DIST, "IfMatch": ETAG, "DistributionConfig": api_config(USE_ORIGIN_CACHE_CONTROL)}}]
    # every input format hands back the same call
    for name, result in _incident_results().items():
        assert build_api_calls(base, result["changes"]) == calls, name


def test_L78f_the_call_is_valid_against_the_botocore_model():
    import botocore.session

    model = botocore.session.get_session().get_service_model("cloudfront")
    for change in (move_feed(USE_ORIGIN_CACHE_CONTROL), Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"enabled": False})):
        call = build_api_calls(base_with(), [change])[0]
        assert not ParamValidator().validate(call["params"], model.operation_model("UpdateDistribution").input_shape).has_errors()


def test_L78f_a_cache_policy_change_does_not_touch_anything_else_in_the_call():
    base = base_with()
    original = build_api_calls(base, [Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"enabled": True})])[0]["params"]
    changed = build_api_calls(base, [move_feed(USE_ORIGIN_CACHE_CONTROL)])[0]["params"]
    assert original["DistributionConfig"] == api_config(CACHING_OPTIMIZED)
    config = copy.deepcopy(changed["DistributionConfig"])
    config["CacheBehaviors"]["Items"][0]["CachePolicyId"] = CACHING_OPTIMIZED
    assert config == original["DistributionConfig"]


@pytest.mark.parametrize("override, reason", [
    ({"etag": None}, "ETag"),
    ({"withheld_settings": ["Origins.CustomHeaders"]}, "Origins.CustomHeaders"),
    ({"default_cache_behavior": None}, "DefaultCacheBehavior"),
])
def test_L78f_the_call_is_refused_when_it_would_drop_or_invent_settings(override, reason):
    base = base_with(distribution(**override))
    change = Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"enabled": False})
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [change])
    assert exc.value.changes[0]["resource_type"] == "cloudfront_distribution"
    assert exc.value.changes[0]["reason"].startswith("unspecified_values") and reason in exc.value.changes[0]["reason"]


def test_L78f_moto_round_trip_the_hand_back_changes_the_policy_in_aws(aws, monkeypatch):
    created = _create(aws)
    _stub_policy_reads(monkeypatch)
    data, _ = _collect()
    base = AWSInfrastructure.model_validate({"cloudfront": data.model_dump(), "region": REGION})
    change = move_feed(USE_ORIGIN_CACHE_CONTROL, created["Id"])
    branch = apply_change(base, change)
    assert host_facts(checked(base, branch)) == []  # moto keeps no origin access control: not the incident's configuration
    (call,) = build_api_calls(base, [change])
    assert (call["service"], call["operation"], call["params"]["Id"], call["params"]["IfMatch"]) == ("cloudfront", "UpdateDistribution", created["Id"], find(base, created["Id"]).etag)
    aws.update_distribution(**call["params"])
    after = aws.get_distribution_config(Id=created["Id"])["DistributionConfig"]
    assert after["CacheBehaviors"]["Items"][0]["CachePolicyId"] == USE_ORIGIN_CACHE_CONTROL
    assert after["DefaultCacheBehavior"]["CachePolicyId"] == CACHING_OPTIMIZED
    assert after["Aliases"]["Items"] == ["feed.jarvis.example"] and after["Comment"] == "podcast feed"
    # a second collect sees what the hand-back did
    again, _ = _collect()
    assert find(AWSInfrastructure(cloudfront=again), created["Id"]).cache_behaviors[0].cache_policy_id == USE_ORIGIN_CACHE_CONTROL


# ── L78g the fact ─────────────────────────────────────────────────────────────

def test_L78g_the_incident_is_a_true_availability_fact_with_the_exact_shape():
    base = base_with()
    body = checked(base, apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL)))
    assert host_facts(body) == [EXPECTED_FACT]
    assert list(host_facts(body)[0]) == list(EXPECTED_FACT)
    # nothing else claims the feed is down: no dependency was removed, nothing was deleted
    assert [f for f in availability(body)["facts"] if f.get("change") != "origin_receives_host_header"] == []
    topics = {c["topic"] for c in availability(body)["checked"]}
    assert {"cloudfront", "cloudfront_origin_host"} <= topics


def test_L78g_the_fix_and_a_policy_that_does_not_forward_host_are_not_facts():
    bad = base_with(distribution(api_config(USE_ORIGIN_CACHE_CONTROL)))
    for policy in (CACHING_OPTIMIZED, CACHING_DISABLED):
        assert host_facts(checked(bad, apply_change(bad, move_feed(policy)))) == []
    good = base_with()
    assert host_facts(checked(good, apply_change(good, move_feed(CACHING_DISABLED)))) == []
    assert host_facts(checked(good, apply_change(good, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=ALL_VIEWER_EXCEPT_HOST)))) == []
    assert host_facts(checked(good, apply_change(good, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=CORS_S3)))) == []


def test_L78g_an_origin_request_policy_that_forwards_host_is_the_same_fact():
    base = base_with()
    for orp in (ALL_VIEWER,):
        body = checked(base, apply_change(base, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=orp)))
        assert host_facts(body) == [{**EXPECTED_FACT, "cache_policy_id": CACHING_OPTIMIZED, "origin_request_policy_id": orp}]
    custom = checked(base, apply_change(base, move_feed(CUSTOM_HOST_POLICY)))
    assert host_facts(custom) == [{**EXPECTED_FACT, "cache_policy_id": CUSTOM_HOST_POLICY}]


def test_L78g_unknown_policy_contents_are_unknown_never_a_fact():
    base = base_with()
    branch = apply_change(base, move_feed(UNCOLLECTED))
    body = checked(base, branch)
    assert host_facts(body) == []
    unknown = {(u["topic"], u["resource_id"]) for u in availability(body)["unknown"]}
    assert ("origin_host_header", DIST) in unknown
    # a rule the model does not read is unknown too
    odd = base_with(data=CloudFrontData(cache_policies=[cfd.cache_policy_from(_cache_policy_item(USE_ORIGIN_CACHE_CONTROL, "x", "brand-new-rule"), "managed")],
                                        origin_request_policies=[]))
    body = checked(odd, apply_change(odd, move_feed(USE_ORIGIN_CACHE_CONTROL)))
    assert host_facts(body) == [] and ("origin_host_header", DIST) in {(u["topic"], u["resource_id"]) for u in availability(body)["unknown"]}
    # an origin request policy that was not collected makes a cache policy that says "no" insufficient
    partial = base_with(data=policies(origin_request=False))
    body = checked(partial, apply_change(partial, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=ALL_VIEWER)))
    assert host_facts(body) == [] and ("origin_host_header", DIST) in {(u["topic"], u["resource_id"]) for u in availability(body)["unknown"]}


def test_L78g_only_a_behavior_that_serves_an_s3_bucket_through_oac_counts():
    # a custom origin receives the viewer Host legitimately
    config = api_config()
    config["Origins"]["Items"] = [{"Id": "s3-feed", "DomainName": "api.jarvis.example", "CustomOriginConfig": {
        "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"}}]
    custom = base_with(distribution(config))
    assert host_facts(checked(custom, apply_change(custom, move_feed(USE_ORIGIN_CACHE_CONTROL)))) == []
    # an S3 origin without origin access control is not the incident's configuration
    config = api_config()
    config["Origins"]["Items"][0].pop("OriginAccessControlId")
    plain = base_with(distribution(config))
    assert host_facts(checked(plain, apply_change(plain, move_feed(USE_ORIGIN_CACHE_CONTROL)))) == []


def test_L78g_a_behavior_that_already_forwarded_host_is_not_news():
    base = base_with(distribution(api_config(USE_ORIGIN_CACHE_CONTROL)))
    assert host_facts(checked(base, apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"enabled": False})))) == []
    assert host_facts(checked(base, base.model_copy(deep=True))) == []


def test_L78g_a_behavior_pointed_at_the_protected_bucket_origin_is_the_same_fact():
    config = api_config()
    config["Origins"]["Items"].append({"Id": "api", "DomainName": "api.jarvis.example", "CustomOriginConfig": {
        "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"}})
    config["Origins"]["Quantity"] = 2
    config["CacheBehaviors"]["Items"][0].update(TargetOriginId="api", CachePolicyId=USE_ORIGIN_CACHE_CONTROL)
    base = base_with(distribution(config))
    assert host_facts(checked(base, base.model_copy(deep=True))) == []
    branch = apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST,
                                       fields={"cache_behaviors": {FEED: {"target_origin_id": "s3-feed"}}}))
    assert host_facts(checked(base, branch)) == [EXPECTED_FACT]


def test_L78g_the_default_behavior_is_covered_with_its_own_path_pattern():
    base = base_with()
    branch = apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST,
                                       fields={"default_cache_behavior": {"cache_policy_id": USE_ORIGIN_CACHE_CONTROL}}))
    assert [f["path_pattern"] for f in host_facts(checked(base, branch))] == ["*"]


def test_L78g_a_changed_distribution_says_its_other_settings_are_not_interpreted():
    base = base_with()
    body = checked(base, apply_change(base, Change(op="modify", resource_type="cloudfront_distribution", resource_id=DIST, fields={"enabled": False})))
    assert "cloudfront_unmodeled_settings" in {u["topic"] for u in availability(body)["unknown"]}
    quiet = checked(base, base.model_copy(deep=True))
    assert "cloudfront_unmodeled_settings" not in {u["topic"] for u in availability(quiet)["unknown"]}


def test_L78g_the_plan_values_a_format_could_not_apply_stay_unknown_in_the_check():
    base = base_with()
    result = _tf(_tf_state(CACHING_OPTIMIZED), _tf_state(CACHING_OPTIMIZED), {"ordered_cache_behavior": [{"cache_policy_id": True}]})
    branch = apply_changes(base, result["changes"]) if result["changes"] else base.model_copy(deep=True)
    body = checked(base, branch, plans=[{"unknown_fields": result["unknown_fields"], "unmodeled": result["unmodeled"], "rejected": []}])
    assert host_facts(body) == []
    assert any(u["topic"] == "plan_values_unknown" for a in body["answers"] for u in a["unknown"])


def test_L78g_the_fact_only_uses_tokenizer_masked_identifier_keys():
    from tests.laws.test_check_facts_laws import TOKENIZE_TS

    src = TOKENIZE_TS.read_text()
    masked = set()
    for name in ("SENSITIVE_KEYS", "IDENTIFIER_KEYS"):
        masked |= set(re.findall(r'"([^"]+)"', re.search(rf"const {name} = new Set\(\[(.*?)\]\)", src, re.S).group(1)))
    assert {"resource_id", "resource_ids"} <= masked
    # the distribution and bucket are the only customer identifiers in the fact; both sit under masked keys
    fact = EXPECTED_FACT
    for key, value in fact.items():
        text = json.dumps(value)
        if DIST in text or BUCKET in text:
            assert key in {"resource_id", "resource_ids"} and key in masked, key


# ── L78h cost, catalog ────────────────────────────────────────────────────────

def test_L78h_distributions_are_usage_priced_so_cost_is_unknown_with_a_reason_never_a_number():
    estimate = estimate_monthly_cost(base_with())
    record = next(r for r in estimate.resources if r.resource_type == "cloudfront_distribution")
    assert (record.resource_id, record.monthly_usd, record.basis) == (DIST, None, "usage-based-unknown")
    assert unknown_reason(record) == "usage-based pricing is not embedded"
    base = base_with()
    diff = diff_infrastructure(base, apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL)))
    assert diff.cost_delta_monthly_usd in (None, 0, 0.0)


def test_L78h_catalog_fields_trace_to_botocore_distribution_config_members():
    catalog = CATALOG["cloudfront_distribution"]
    assert resolve(catalog["price_class"]).enum == ["PriceClass_100", "PriceClass_200", "PriceClass_All", "None"]
    assert resolve(catalog["enabled"]).type_name == "boolean" and resolve(catalog["aliases"]).type_name == "list"
    assert {s.service for s in catalog.values() if hasattr(s, "service")} == {"cloudfront"}
    for field, source in {**cfd.BEHAVIOR_SOURCES, **cfd.ORIGIN_SOURCES}.items():
        assert resolve(source) is not None, field
    assert set(resolve(cfd.BEHAVIOR_SOURCES["viewer_protocol_policy"]).enum) == {"allow-all", "https-only", "redirect-to-https"}
    assert "GET" in resolve(cfd.BEHAVIOR_SOURCES["allowed_methods"]).member.enum
    # every settable field is a catalogued, non-derived field
    from app.field_catalog import Derived
    assert not [f for f in cfd.SETTABLE_FIELDS if isinstance(catalog[f], Derived)]


# ── L78i IAM and no hand-written policy tables ────────────────────────────────

@pytest.mark.parametrize("path", ["iam-role.yaml", "backend/cloudformation/iam-role.yaml"])
def test_L78i_iam_read_policy_lists_exactly_the_cloudfront_operations_the_collector_makes(path):
    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    document = yaml.load((ROOT / path).read_text(), Loader=Loader)
    actions = [a for statement in document["Resources"]["EmfirgeReadOnlyRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
               for a in statement["Action"]]
    assert {a for a in actions if a.startswith("cloudfront:")} == {f"cloudfront:{op}" for op in cfd.COLLECTOR_OPERATIONS}
    assert not [a for a in actions if a.startswith("cloudfront:") and a.split(":")[1].startswith(("Update", "Create", "Delete", "Tag", "Untag"))]


def test_L78i_the_two_role_files_are_identical():
    assert (ROOT / "iam-role.yaml").read_text() == (ROOT / "backend/cloudformation/iam-role.yaml").read_text()


def test_L78i_no_policy_contents_are_written_down_in_the_code():
    """Policy rules are provider facts read at scan time. A hand-written table would need a source URL per entry; there is none."""
    uuid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    for name in ("cloudfront_distribution.py", "cloudfront_check.py"):
        text = (APP_DIR / name).read_text()
        assert not uuid.findall(text), (name, uuid.findall(text))
        assert "UseOriginCacheControlHeaders" not in text and "CachingOptimized" not in text, name


def test_L78i_the_documentation_the_fact_cites_says_what_it_is_cited_for():
    assert SOURCE_URL.startswith("https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/")
    assert SOURCE_URL.endswith("RequestAndResponseBehaviorCustomOrigin.html")


# ── L78j compatibility and boundary ───────────────────────────────────────────

def test_L78j_old_snapshots_without_cloudfront_data_still_load():
    legacy = load_synthetic_base("delete").model_dump(mode="json")
    legacy.pop("cloudfront", None)
    old = AWSInfrastructure.model_validate(legacy)
    assert old.cloudfront.distributions == [] and old.collection.get("cloudfront") is None
    restored = AWSInfrastructure.model_validate(json.loads(base_with().model_dump_json()))
    assert find(restored) == find(base_with())
    assert restored.cloudfront.collection_status == {}


def test_L78j_cloudfront_logic_lives_in_adapter_modules_only():
    from tests.laws.test_core_adapter_boundary_laws import ADAPTER_MODULES, ALLOWED, CORE_MODULES, _imported_names

    for module in ("cloudfront_distribution", "cloudfront_check"):
        assert module in ADAPTER_MODULES and module not in CORE_MODULES
    for core in CORE_MODULES:
        assert not {"cloudfront_distribution", "cloudfront_check"} & _imported_names(core), core
    assert ALLOWED["egraph"] == {"models", "iam_classifier", "iam_escalation", "rds_ports"}
    assert ALLOWED.get("check_facts") == set()
