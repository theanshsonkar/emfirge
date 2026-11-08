"""AWS adapter helpers for CloudFront distributions.

One place for what every input shares: reading a botocore ``DistributionConfig``
(collector, ``UpdateDistribution`` calls, CloudFormation) into branch fields, applying
branch fields to a distribution, rebuilding the exact ``UpdateDistribution`` call for the
hand-back, and the collector itself (read only).

Modeled: aliases, enabled, price class, web ACL, origins (id, domain, kind, origin access
control, bucket) and cache behaviors (path pattern, origin, cache policy, origin request
policy, viewer protocol policy, methods). Every other member of the configuration is kept
verbatim in ``extra`` (never interpreted), so a full-replace hand-back is exact. Origin
custom header values can be secrets and are never stored; a distribution that has them
lists the setting in ``withheld_settings`` and cannot be handed back.

Policy contents (which headers a cache policy or origin request policy forwards) are read
from the provider at scan time (ListCachePolicies / ListOriginRequestPolicies, managed and
custom). Nothing about a policy is written down here.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Optional

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import ClientError

from app.field_catalog import Aws, _check, resolve
from app.models import (
    CloudFrontCacheBehavior, CloudFrontData, CloudFrontDistribution, CloudFrontOrigin,
    CloudFrontOriginAccessControl, CloudFrontPolicy, _says_something,
)

DEFAULT_PATH_PATTERN = "*"
_BOTO_CONFIG = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2, "mode": "standard"})
_DENIED_CODES = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")

# The read operations the collector makes (the IAM read policy lists exactly these; law L78).
COLLECTOR_OPERATIONS = (
    "ListDistributions", "GetDistributionConfig", "ListTagsForResource",
    "ListCachePolicies", "ListOriginRequestPolicies", "ListOriginAccessControls",
)

# Branch fields of a distribution a change may set.
SETTABLE_FIELDS = ("aliases", "enabled", "price_class", "web_acl_id", "default_cache_behavior", "cache_behaviors",
                   "origins", "extra", "withheld_settings")
BEHAVIOR_FIELDS = ("path_pattern", "target_origin_id", "cache_policy_id", "origin_request_policy_id", "viewer_protocol_policy",
                   "allowed_methods", "cached_methods", "uses_legacy_forwarded_values", "extra")
ORIGIN_FIELDS = ("id", "domain_name", "origin_type", "origin_access_control_id", "s3_bucket", "extra")

# Sub-fields traced to botocore (UpdateDistribution DistributionConfig); law L78 checks each one exists.
_CB = "DistributionConfig.DefaultCacheBehavior."
BEHAVIOR_SOURCES: dict[str, Aws] = {
    "path_pattern": Aws("cloudfront", "UpdateDistribution", "DistributionConfig.CacheBehaviors.Items.PathPattern"),
    "target_origin_id": Aws("cloudfront", "UpdateDistribution", _CB + "TargetOriginId"),
    "cache_policy_id": Aws("cloudfront", "UpdateDistribution", _CB + "CachePolicyId"),
    "origin_request_policy_id": Aws("cloudfront", "UpdateDistribution", _CB + "OriginRequestPolicyId"),
    "viewer_protocol_policy": Aws("cloudfront", "UpdateDistribution", _CB + "ViewerProtocolPolicy"),
    "allowed_methods": Aws("cloudfront", "UpdateDistribution", _CB + "AllowedMethods.Items"),
    "cached_methods": Aws("cloudfront", "UpdateDistribution", _CB + "AllowedMethods.CachedMethods.Items"),
}
ORIGIN_SOURCES: dict[str, Aws] = {
    "id": Aws("cloudfront", "UpdateDistribution", "DistributionConfig.Origins.Items.Id"),
    "domain_name": Aws("cloudfront", "UpdateDistribution", "DistributionConfig.Origins.Items.DomainName"),
    "origin_access_control_id": Aws("cloudfront", "UpdateDistribution", "DistributionConfig.Origins.Items.OriginAccessControlId"),
}

# Members of the call a legacy ForwardedValues behavior carries; AWS rejects them next to a cache policy.
_LEGACY_MEMBERS = ("ForwardedValues", "MinTTL", "DefaultTTL", "MaxTTL")
# DistributionConfig / behavior / origin members that are modeled (everything else stays in ``extra``).
_MODELED_TOP = {"Aliases", "Origins", "DefaultCacheBehavior", "CacheBehaviors", "Enabled", "PriceClass", "WebACLId"}
_MODELED_BEHAVIOR = {"PathPattern", "TargetOriginId", "CachePolicyId", "OriginRequestPolicyId", "ViewerProtocolPolicy", "AllowedMethods"}
_MODELED_ORIGIN = {"Id", "DomainName", "OriginAccessControlId"}
_REQUIRED_TOP = ("Origins", "DefaultCacheBehavior", "Enabled")
_S3_DOMAIN = re.compile(r"^(?P<bucket>.+)\.s3([.-][a-z0-9-]+)*\.amazonaws\.com(\.cn)?$")


# ── origins ──────────────────────────────────────────────────────────────────

def s3_bucket_of(domain_name: Optional[str]) -> Optional[str]:
    """The bucket named by an S3 REST endpoint domain (bucket.s3.amazonaws.com, bucket.s3.<region>.amazonaws.com, ...)."""
    match = _S3_DOMAIN.match(domain_name or "")
    return match.group("bucket") if match else None


def origin_kind(domain_name: Optional[str], *, s3_config: bool = False, custom_config: bool = False, vpc_config: bool = False) -> str:
    """s3 for an S3 bucket origin, custom for a custom or S3 website origin, other for anything else."""
    if s3_config:
        return "s3"
    if custom_config:
        return "custom"
    if vpc_config:
        return "other"
    return "s3" if s3_bucket_of(domain_name) else "other"


def origin_fields(raw: dict[str, Any], withheld: list[str], with_extra: bool = True) -> dict[str, Any]:
    """Branch fields of one botocore ``Origin``; custom header values are dropped and the setting is named."""
    extra = {k: copy.deepcopy(v) for k, v in raw.items() if k not in _MODELED_ORIGIN}
    headers = extra.pop("CustomHeaders", None)
    if isinstance(headers, dict) and headers.get("Items"):
        withheld.append("Origins.CustomHeaders")
    domain = raw.get("DomainName") or ""
    kind = origin_kind(domain, s3_config="S3OriginConfig" in raw, custom_config="CustomOriginConfig" in raw,
                       vpc_config="VpcOriginConfig" in raw)
    fields = {"id": raw.get("Id"), "domain_name": domain, "origin_type": kind,
              "origin_access_control_id": raw.get("OriginAccessControlId") or None,
              "s3_bucket": s3_bucket_of(domain) if kind == "s3" else None}
    return {**fields, "extra": extra} if with_extra else fields


# ── behaviors ────────────────────────────────────────────────────────────────

def _items(block: Any) -> list[Any]:
    return list(block.get("Items") or []) if isinstance(block, dict) else []


def behavior_fields(raw: dict[str, Any], path_pattern: str, with_extra: bool = True) -> dict[str, Any]:
    """Branch fields of one botocore ``CacheBehavior`` / ``DefaultCacheBehavior``."""
    methods = raw.get("AllowedMethods") if isinstance(raw.get("AllowedMethods"), dict) else {}
    # AWS rejects ForwardedValues and TTLs next to a cache policy, so a behavior with one carries none of them.
    skipped = _MODELED_BEHAVIOR | (set(_LEGACY_MEMBERS) if raw.get("CachePolicyId") else set())
    extra = {k: copy.deepcopy(v) for k, v in raw.items() if k not in skipped}
    fields = {"path_pattern": path_pattern, "target_origin_id": raw.get("TargetOriginId") or "",
              "cache_policy_id": raw.get("CachePolicyId") or None,
              "origin_request_policy_id": raw.get("OriginRequestPolicyId") or None,
              "viewer_protocol_policy": raw.get("ViewerProtocolPolicy"),
              "allowed_methods": _items(methods), "cached_methods": _items(methods.get("CachedMethods")),
              "uses_legacy_forwarded_values": "ForwardedValues" in raw and not raw.get("CachePolicyId")}
    return {**fields, "extra": extra} if with_extra else fields


def config_to_fields(config: dict[str, Any], *, replace: bool) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Branch fields from a botocore ``DistributionConfig``.

    ``replace`` is UpdateDistribution's meaning (the call states the whole distribution: members it
    leaves out are cleared and unmodeled members replace the stored ones). Without it only the members
    present are set (a partial view such as a CloudFormation change). Returns (fields, problems); a
    problem is (member, reason) for a required member a full replace lacks, never defaulted.
    """
    fields: dict[str, Any] = {}
    problems: list[tuple[str, str]] = []
    withheld: list[str] = []
    if "Aliases" in config or replace:
        fields["aliases"] = _items(config.get("Aliases"))
    for member, field in (("Enabled", "enabled"), ("PriceClass", "price_class"), ("WebACLId", "web_acl_id")):
        if member in config:
            value = config[member]
            fields[field] = (value or None) if field == "web_acl_id" else value
        elif replace:
            fields[field] = None
    if isinstance(config.get("Origins"), dict):
        fields["origins"] = [origin_fields(item, withheld, replace) for item in _items(config["Origins"]) if isinstance(item, dict)]
    if isinstance(config.get("DefaultCacheBehavior"), dict):
        fields["default_cache_behavior"] = behavior_fields(config["DefaultCacheBehavior"], DEFAULT_PATH_PATTERN, replace)
    if "CacheBehaviors" in config or replace:
        fields["cache_behaviors"] = [behavior_fields(item, item.get("PathPattern") or "", replace)
                                     for item in _items(config.get("CacheBehaviors")) if isinstance(item, dict)]
    if replace:
        for member in _REQUIRED_TOP:
            if member not in config:
                problems.append((member, "required_member_missing"))
        fields["extra"] = {k: copy.deepcopy(v) for k, v in config.items() if k not in _MODELED_TOP}
        fields["withheld_settings"] = sorted(set(withheld))
    return fields, problems


# ── cloudformation ───────────────────────────────────────────────────────────

def _quantity(items: list[Any]) -> dict[str, Any]:
    return {"Quantity": len(items), **({"Items": items} if items else {})}


def _cfn_bool(value: Any) -> Any:
    return {"true": True, "false": False}.get(value.strip().lower(), value) if isinstance(value, str) else value


def cfn_config_to_api(config: dict[str, Any]) -> dict[str, Any]:
    """The modeled members of a CloudFormation ``DistributionConfig`` in the API's shape (lists become Quantity / Items)."""
    result: dict[str, Any] = {}
    if isinstance(config.get("Aliases"), list):
        result["Aliases"] = _quantity(config["Aliases"])
    for member in ("Enabled",):
        if member in config:
            result[member] = _cfn_bool(config[member])
    for member in ("PriceClass", "WebACLId"):
        if member in config:
            result[member] = config[member]

    def behavior(raw: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in raw.items() if k in _MODELED_BEHAVIOR - {"AllowedMethods"}}
        methods = raw.get("AllowedMethods")
        if isinstance(methods, list):
            out["AllowedMethods"] = {**_quantity(methods), **(
                {"CachedMethods": _quantity(raw["CachedMethods"])} if isinstance(raw.get("CachedMethods"), list) else {})}
        if "ForwardedValues" in raw and not raw.get("CachePolicyId"):
            out["ForwardedValues"] = None  # presence only; its content is not converted
        return out

    if isinstance(config.get("DefaultCacheBehavior"), dict):
        result["DefaultCacheBehavior"] = behavior(config["DefaultCacheBehavior"])
    if isinstance(config.get("CacheBehaviors"), list):
        result["CacheBehaviors"] = _quantity([behavior(item) for item in config["CacheBehaviors"] if isinstance(item, dict)])
    if isinstance(config.get("Origins"), list):
        origins = []
        for raw in config["Origins"]:
            if not isinstance(raw, dict):
                continue
            origin = {k: v for k, v in raw.items() if k in _MODELED_ORIGIN}
            for member in ("S3OriginConfig", "CustomOriginConfig", "VpcOriginConfig"):
                if member in raw:
                    origin[member] = {}
            origins.append(origin)
        result["Origins"] = _quantity(origins)
    return result


def cfn_unmodeled(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """CloudFormation properties outside the model that differ between the two contexts."""
    names = []
    # A modeled property the change set removes is reset by CloudFormation to a default the resource page does not
    # state, so it is named (never dropped): https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html
    names += [f"DistributionConfig.{key}" for key in sorted(_MODELED_TOP)
              if key in before and key not in after and _says_something(before.get(key))]
    for key in sorted(set(before) | set(after)):
        if key in _MODELED_TOP or key == "CallerReference":
            continue
        if before.get(key) != after.get(key) and (_says_something(before.get(key)) or _says_something(after.get(key))):
            names.append(f"DistributionConfig.{key}")
    for label, key in (("DefaultCacheBehavior", None), ("CacheBehaviors", "PathPattern"), ("Origins", "Id")):
        def index(config):
            raw = config.get(label)
            items = [raw] if isinstance(raw, dict) else [i for i in raw or [] if isinstance(i, dict)]
            return {(i.get(key) if key else "*"): i for i in items}
        old, new = index(before), index(after)
        for ident, item in new.items():
            other = old.get(ident, {})
            modeled = _MODELED_ORIGIN if label == "Origins" else _MODELED_BEHAVIOR | {"CachedMethods"}
            names += [f"{label}.{k}" for k in sorted(modeled) if k in other and k not in item and _says_something(other.get(k))]
            names += [f"{label}.{k}" for k in sorted(set(item) | set(other))
                      if k not in _MODELED_BEHAVIOR | _MODELED_ORIGIN | {"CachedMethods"} and item.get(k) != other.get(k)
                      and (_says_something(item.get(k)) or _says_something(other.get(k)))]
    return sorted(set(names))


# ── terraform ────────────────────────────────────────────────────────────────

_TF_TOP_MODELED = {"enabled", "aliases", "price_class", "web_acl_id", "default_cache_behavior", "ordered_cache_behavior", "origin"}
_TF_TOP_IGNORED = {"arn", "id", "etag", "status", "domain_name", "hosted_zone_id", "caller_reference", "in_progress_validation_batches",
                   "last_modified_time", "trusted_key_groups", "trusted_signers", "tags_all", "wait_for_deployment", "retain_on_delete"}
_TF_BEHAVIOR_MODELED = {"path_pattern", "target_origin_id", "cache_policy_id", "origin_request_policy_id", "viewer_protocol_policy",
                        "allowed_methods", "cached_methods"}
_TF_ORIGIN_MODELED = {"origin_id", "domain_name", "origin_access_control_id"}
TF_FIELD_OF = {"enabled": "enabled", "aliases": "aliases", "price_class": "price_class", "web_acl_id": "web_acl_id",
               "default_cache_behavior": "default_cache_behavior", "ordered_cache_behavior": "cache_behaviors", "origin": "origins"}


def _tf_blocks(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    return [item for item in value or [] if isinstance(item, dict)] if isinstance(value, list) else []


def _tf_behavior(block: dict[str, Any], path_pattern: str) -> dict[str, Any]:
    policy = block.get("cache_policy_id") or None
    legacy = bool(_tf_blocks(block.get("forwarded_values"))) and not policy
    return {"path_pattern": path_pattern, "target_origin_id": block.get("target_origin_id") or "", "cache_policy_id": policy,
            "origin_request_policy_id": block.get("origin_request_policy_id") or None,
            "viewer_protocol_policy": block.get("viewer_protocol_policy") or None,
            "allowed_methods": list(block.get("allowed_methods") or []), "cached_methods": list(block.get("cached_methods") or []),
            "uses_legacy_forwarded_values": legacy}


def _tf_origin(block: dict[str, Any]) -> dict[str, Any]:
    domain = block.get("domain_name") or ""
    kind = origin_kind(domain, s3_config=bool(_tf_blocks(block.get("s3_origin_config"))),
                       custom_config=bool(_tf_blocks(block.get("custom_origin_config"))), vpc_config=bool(_tf_blocks(block.get("vpc_origin_config"))))
    return {"id": block.get("origin_id"), "domain_name": domain, "origin_type": kind,
            "origin_access_control_id": block.get("origin_access_control_id") or None,
            "s3_bucket": s3_bucket_of(domain) if kind == "s3" else None}


def _tf_state(attrs: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}
    for key in ("enabled", "price_class"):
        if key in attrs:
            state[key] = attrs[key]
    if "web_acl_id" in attrs:
        state["web_acl_id"] = attrs["web_acl_id"] or None
    if "aliases" in attrs:
        state["aliases"] = list(attrs["aliases"] or [])
    blocks = _tf_blocks(attrs.get("default_cache_behavior"))
    if blocks:
        state["default_cache_behavior"] = _tf_behavior(blocks[0], DEFAULT_PATH_PATTERN)
    if "ordered_cache_behavior" in attrs:
        state["cache_behaviors"] = [_tf_behavior(block, block.get("path_pattern") or "") for block in _tf_blocks(attrs["ordered_cache_behavior"])]
    if "origin" in attrs:
        state["origins"] = [_tf_origin(block) for block in _tf_blocks(attrs["origin"])]
    return state


def _tf_unmodeled(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    names = []
    for key in sorted(set(before) | set(after)):
        if key in _TF_TOP_MODELED or key in _TF_TOP_IGNORED:
            continue
        if before.get(key) != after.get(key) and not (_meaningless_tf(before.get(key)) and _meaningless_tf(after.get(key))):
            names.append(key)
    for label, key, modeled in (("default_cache_behavior", None, _TF_BEHAVIOR_MODELED), ("ordered_cache_behavior", "path_pattern", _TF_BEHAVIOR_MODELED),
                                ("origin", "origin_id", _TF_ORIGIN_MODELED)):
        def index(attrs):
            return {(b.get(key) if key else "*"): b for b in _tf_blocks(attrs.get(label))}
        old, new = index(before), index(after)
        for ident, block in new.items():
            other = old.get(ident, {})
            names += [f"{label}.{k}" for k in sorted(set(block) | set(other))
                      if k not in modeled and block.get(k) != other.get(k)
                      and not (_meaningless_tf(block.get(k)) and _meaningless_tf(other.get(k)))]
    return sorted(set(names))


def _meaningless_tf(value: Any) -> bool:
    if isinstance(value, list):
        return all(_meaningless_tf(v) for v in value)
    if isinstance(value, dict):
        return all(_meaningless_tf(v) for v in value.values())
    return value in (None, "", False, 0)


def tf_fields(before: dict[str, Any], after: dict[str, Any], unknown_paths: set[str]
              ) -> tuple[dict[str, Any], list[str], list[str]]:
    """Branch fields of an updated ``aws_cloudfront_distribution`` and the unknown fields the plan leaves.

    Only modeled attributes that differ between the plan's before and after state are set (a partial change:
    unmodeled members of the stored configuration are kept). Returns (fields, unknown Terraform names, unmodeled names).
    """
    old, new = _tf_state(before), _tf_state(after)
    unknown = sorted(path for path in unknown_paths if path.split(".")[0] in _TF_TOP_MODELED)
    blocked = {TF_FIELD_OF[path.split(".")[0]] for path in unknown}
    fields = {key: value for key, value in new.items() if key not in blocked and old.get(key) != value}
    return fields, unknown, _tf_unmodeled(before, after)


# ── applying fields ──────────────────────────────────────────────────────────

def _check_value(path: str, source: Aws, value: Any) -> None:
    _check(path, source, resolve(source), value)


def validate_behavior(entry: Any, label: str) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"cloudfront_distribution.{label}: expected an object")
    unknown = set(entry) - set(BEHAVIOR_FIELDS)
    if unknown:
        raise ValueError(f"cloudfront_distribution.{label}: unknown field (allowed: {', '.join(BEHAVIOR_FIELDS)})")
    for field, value in entry.items():
        if field in BEHAVIOR_SOURCES:
            _check_value(f"cloudfront_distribution.{label}.{field}", BEHAVIOR_SOURCES[field], value)
        elif field == "uses_legacy_forwarded_values" and not isinstance(value, bool):
            raise ValueError(f"cloudfront_distribution.{label}.{field}: expected a boolean")
        elif field == "extra" and not isinstance(value, dict):
            raise ValueError(f"cloudfront_distribution.{label}.extra: expected an object")


def validate_origin(entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ValueError("cloudfront_distribution.origins: expected objects")
    unknown = set(entry) - set(ORIGIN_FIELDS)
    if unknown:
        raise ValueError(f"cloudfront_distribution.origins: unknown field (allowed: {', '.join(ORIGIN_FIELDS)})")
    for field, value in entry.items():
        if field in ORIGIN_SOURCES:
            _check_value(f"cloudfront_distribution.origins.{field}", ORIGIN_SOURCES[field], value)
        elif field == "origin_type" and value not in {"s3", "custom", "other"}:
            raise ValueError("cloudfront_distribution.origins.origin_type: expected s3, custom or other")
        elif field == "extra" and not isinstance(value, dict):
            raise ValueError("cloudfront_distribution.origins.extra: expected an object")


def _settle_behavior(data: dict[str, Any]) -> CloudFrontCacheBehavior:
    """A behavior that has a cache policy no longer carries the legacy settings AWS rejects beside one."""
    extra = dict(data.get("extra") or {})
    if data.get("cache_policy_id"):
        for member in _LEGACY_MEMBERS:
            extra.pop(member, None)
        data = {**data, "uses_legacy_forwarded_values": False}
    elif not data.get("uses_legacy_forwarded_values") and "ForwardedValues" not in extra:
        raise ValueError("cloudfront_distribution: a cache behavior needs a cache policy (or legacy forwarded values)")
    return CloudFrontCacheBehavior.model_validate({**data, "extra": extra})


def _merge_behavior(old: Optional[CloudFrontCacheBehavior], patch: dict[str, Any], path_pattern: str) -> CloudFrontCacheBehavior:
    return _settle_behavior({**(old.model_dump() if old else {}), **patch, "path_pattern": path_pattern})


def _merge_origin(old: Optional[CloudFrontOrigin], entry: dict[str, Any]) -> CloudFrontOrigin:
    data = {**(old.model_dump() if old else {}), **entry}
    if "origin_type" not in entry:
        extra = data.get("extra") or {}
        data["origin_type"] = origin_kind(data.get("domain_name"), s3_config="S3OriginConfig" in extra,
                                          custom_config="CustomOriginConfig" in extra, vpc_config="VpcOriginConfig" in extra)
    if "s3_bucket" not in entry:
        data["s3_bucket"] = s3_bucket_of(data.get("domain_name")) if data["origin_type"] == "s3" else None
    return CloudFrontOrigin.model_validate(data)


def validate_change(fields: dict[str, Any]) -> None:
    """Reject fields the branch cannot set and values AWS's own model would reject."""
    from app.field_catalog import validate_fields

    unknown = set(fields) - set(SETTABLE_FIELDS)
    if unknown:
        raise ValueError(f"cloudfront_distribution fields: unknown or derived field (allowed: {', '.join(SETTABLE_FIELDS)})")
    if not fields:
        raise ValueError("modify needs at least one field")
    validate_fields("cloudfront_distribution", {k: v for k, v in fields.items() if k in {"aliases", "enabled", "price_class", "web_acl_id"}})
    if "default_cache_behavior" in fields:
        entry = fields["default_cache_behavior"]
        validate_behavior(entry, "default_cache_behavior")
        if isinstance(entry, dict) and entry.get("path_pattern") not in (None, DEFAULT_PATH_PATTERN):
            raise ValueError("cloudfront_distribution.default_cache_behavior.path_pattern: the default behavior's path pattern is *")
    if "cache_behaviors" in fields:
        value = fields["cache_behaviors"]
        if isinstance(value, dict):
            for path, patch in value.items():
                validate_behavior(patch, "cache_behaviors")
                if isinstance(patch, dict) and "path_pattern" in patch and patch["path_pattern"] != path:
                    raise ValueError("cloudfront_distribution.cache_behaviors: a change keyed by path pattern cannot rename it")
        elif isinstance(value, list):
            for entry in value:
                validate_behavior(entry, "cache_behaviors")
                if not isinstance(entry, dict) or not entry.get("path_pattern"):
                    raise ValueError("cloudfront_distribution.cache_behaviors: every behavior needs a path_pattern")
        else:
            raise ValueError("cloudfront_distribution.cache_behaviors: expected a list of behaviors or an object keyed by path pattern")
    if "origins" in fields:
        if not isinstance(fields["origins"], list):
            raise ValueError("cloudfront_distribution.origins: expected a list")
        for entry in fields["origins"]:
            validate_origin(entry)
            if not entry.get("id"):
                raise ValueError("cloudfront_distribution.origins: every origin needs an id")
    for field in ("extra",):
        if field in fields and not isinstance(fields[field], dict):
            raise ValueError("cloudfront_distribution.extra: expected an object")
    if "withheld_settings" in fields and not (isinstance(fields["withheld_settings"], list) and all(isinstance(i, str) for i in fields["withheld_settings"])):
        raise ValueError("cloudfront_distribution.withheld_settings: expected a list of names")


def apply_fields(dist: CloudFrontDistribution, fields: dict[str, Any]) -> CloudFrontDistribution:
    """The distribution after a modify. Pure: ``dist`` is not touched.

    A behavior list is the complete list (a behavior left out is removed; one that keeps its path pattern
    keeps the settings the entry does not state). An object keyed by path pattern changes those behaviors only.
    """
    validate_change(fields)
    data = dist.model_dump()
    for key in ("aliases", "enabled", "price_class", "web_acl_id", "extra", "withheld_settings"):
        if key in fields:
            data[key] = copy.deepcopy(fields[key])
    old_default = dist.default_cache_behavior
    if "default_cache_behavior" in fields:
        if old_default is None and not fields["default_cache_behavior"].get("target_origin_id"):
            raise ValueError("cloudfront_distribution.default_cache_behavior: the distribution's default behavior was not collected")
        data["default_cache_behavior"] = _merge_behavior(old_default, fields["default_cache_behavior"], DEFAULT_PATH_PATTERN).model_dump()
    if "cache_behaviors" in fields:
        by_path = {b.path_pattern: b for b in dist.cache_behaviors}
        value = fields["cache_behaviors"]
        if isinstance(value, dict):
            missing = [path for path in value if path not in by_path]
            if missing:
                raise ValueError("cloudfront_distribution.cache_behaviors: no behavior with that path pattern")
            data["cache_behaviors"] = [(_merge_behavior(b, value[b.path_pattern], b.path_pattern) if b.path_pattern in value else b).model_dump()
                                       for b in dist.cache_behaviors]
        else:
            data["cache_behaviors"] = [_merge_behavior(by_path.get(entry["path_pattern"]), entry, entry["path_pattern"]).model_dump() for entry in value]
    if "origins" in fields:
        by_id = {o.id: o for o in dist.origins}
        data["origins"] = [_merge_origin(by_id.get(entry["id"]), entry).model_dump() for entry in fields["origins"]]
    result = CloudFrontDistribution.model_validate(data)
    paths = [b.path_pattern for b in result.cache_behaviors]
    if len(paths) != len(set(paths)):
        raise ValueError("cloudfront_distribution.cache_behaviors: path patterns must be unique")
    ids = [o.id for o in result.origins]
    if len(ids) != len(set(ids)):
        raise ValueError("cloudfront_distribution.origins: origin ids must be unique")
    for behavior in ([result.default_cache_behavior] if result.default_cache_behavior else []) + result.cache_behaviors:
        if behavior.target_origin_id and result.origins and behavior.target_origin_id not in ids:
            raise ValueError("cloudfront_distribution: a cache behavior targets an origin the distribution does not have")
    return result


# ── hand-back ────────────────────────────────────────────────────────────────

def _behavior_config(behavior: CloudFrontCacheBehavior, *, default: bool) -> dict[str, Any]:
    config = copy.deepcopy(behavior.extra)
    if behavior.cache_policy_id:
        for member in _LEGACY_MEMBERS:
            config.pop(member, None)
    if not default:
        config["PathPattern"] = behavior.path_pattern
    config["TargetOriginId"] = behavior.target_origin_id
    if behavior.viewer_protocol_policy is not None:
        config["ViewerProtocolPolicy"] = behavior.viewer_protocol_policy
    if behavior.cache_policy_id:
        config["CachePolicyId"] = behavior.cache_policy_id
    if behavior.origin_request_policy_id:
        config["OriginRequestPolicyId"] = behavior.origin_request_policy_id
    if behavior.allowed_methods:
        methods: dict[str, Any] = _quantity(list(behavior.allowed_methods))
        if behavior.cached_methods:
            methods["CachedMethods"] = _quantity(list(behavior.cached_methods))
        config["AllowedMethods"] = methods
    return config


def build_update_call(dist: CloudFrontDistribution) -> tuple[Optional[dict[str, Any]], list[str]]:
    """(UpdateDistribution parameters, missing-or-unsafe reasons). The call replaces the whole distribution."""
    problems = []
    if dist.etag is None:
        problems.append("ETag (IfMatch): the distribution's full configuration was not collected")
    if dist.withheld_settings:
        problems.append(", ".join(dist.withheld_settings) + " (stored without values: the call would drop them or invent them)")
    if dist.default_cache_behavior is None or not dist.origins:
        problems.append("DefaultCacheBehavior / Origins")
    if problems:
        return None, problems
    config = copy.deepcopy(dist.extra)
    config["Aliases"] = _quantity(list(dist.aliases))
    origins = []
    for origin in dist.origins:
        item = copy.deepcopy(origin.extra)
        item["Id"], item["DomainName"] = origin.id, origin.domain_name
        if origin.origin_access_control_id:
            item["OriginAccessControlId"] = origin.origin_access_control_id
        origins.append(item)
    config["Origins"] = {"Quantity": len(origins), "Items": origins}
    config["DefaultCacheBehavior"] = _behavior_config(dist.default_cache_behavior, default=True)
    config["CacheBehaviors"] = _quantity([_behavior_config(b, default=False) for b in dist.cache_behaviors])
    if dist.enabled is not None:
        config["Enabled"] = dist.enabled
    if dist.price_class is not None:
        config["PriceClass"] = dist.price_class
    config["WebACLId"] = dist.web_acl_id or ""
    return {"Id": dist.id, "IfMatch": dist.etag, "DistributionConfig": config}, []


# ── collector (read only) ────────────────────────────────────────────────────

def _code(error: ClientError) -> str:
    return error.response.get("Error", {}).get("Code", "")


def _marker_pages(call, list_key: str, **kwargs):
    """Items of a Marker / NextMarker listing (the CloudFront operations without a paginator)."""
    marker = None
    while True:
        response = call(**kwargs, **({"Marker": marker} if marker else {}))
        page = response.get(list_key) or {}
        yield from page.get("Items") or []
        marker = page.get("NextMarker")
        if not marker:
            return


def policy_headers(config: dict[str, Any], key: str) -> tuple[Optional[str], list[str]]:
    headers = config.get(key) if isinstance(config.get(key), dict) else {}
    return headers.get("HeaderBehavior"), [str(h) for h in _items(headers.get("Headers"))]


def header_rule_forwards_host(behavior: Optional[str], headers: list[str], *, origin_request: bool) -> Optional[bool]:
    """Whether the viewer Host header reaches the origin under a header rule; None when the rule is not known."""
    host = any(h.lower() == "host" for h in headers)
    if behavior == "none":
        return False
    if behavior == "whitelist":
        return host
    if origin_request and behavior in {"allViewer", "allViewerAndWhitelistCloudFront"}:
        return True
    if origin_request and behavior == "allExcept":
        return not host
    return None


def cache_policy_from(item: dict[str, Any], kind: str) -> CloudFrontPolicy:
    policy = item.get("CachePolicy") or {}
    config = policy.get("CachePolicyConfig") or {}
    parameters = config.get("ParametersInCacheKeyAndForwardedToOrigin")
    behavior, headers = policy_headers(parameters or {}, "HeadersConfig")
    return CloudFrontPolicy(id=policy.get("Id"), name=config.get("Name"), type=kind, headers_behavior=behavior, headers=headers,
                            forwards_host=header_rule_forwards_host(behavior, headers, origin_request=False))


def origin_request_policy_from(item: dict[str, Any], kind: str) -> CloudFrontPolicy:
    policy = item.get("OriginRequestPolicy") or {}
    config = policy.get("OriginRequestPolicyConfig") or {}
    behavior, headers = policy_headers(config, "HeadersConfig")
    return CloudFrontPolicy(id=policy.get("Id"), name=config.get("Name"), type=kind, headers_behavior=behavior, headers=headers,
                            forwards_host=header_rule_forwards_host(behavior, headers, origin_request=True))


def _distribution(client: BaseClient, summary: dict[str, Any], flags: dict[str, bool]) -> CloudFrontDistribution:
    """One distribution: its full configuration and ETag when readable, else what the list gave (no ETag)."""
    config, etag = None, None
    try:
        response = client.get_distribution_config(Id=summary["Id"])
        config, etag = response.get("DistributionConfig"), response.get("ETag")
    except ClientError as error:
        flags["denied" if _code(error) in _DENIED_CODES else "failed"] = True
    except Exception:
        flags["failed"] = True
    source = config if isinstance(config, dict) else summary
    fields, _ = config_to_fields(source, replace=isinstance(config, dict))
    if not isinstance(config, dict):
        fields.pop("extra", None)
    tags = None
    arn = summary.get("ARN")
    if arn:
        try:
            listed = client.list_tags_for_resource(Resource=arn)
            tags = {t["Key"]: t.get("Value", "") for t in _items(listed.get("Tags"))}
        except ClientError as error:
            flags["denied" if _code(error) in _DENIED_CODES else "failed"] = True
        except Exception:
            flags["failed"] = True
    return CloudFrontDistribution(id=summary["Id"], arn=arn, domain_name=summary.get("DomainName"), status=summary.get("Status"),
                                  tags=tags, etag=etag if isinstance(config, dict) else None, **fields)


def collect_cloudfront(key, secret, token, region, warnings) -> CloudFrontData:
    """Distributions with origins, behaviors and policy rules (read only).

    Cache policy and origin request policy contents come from the provider's own listings (managed and
    custom): the list response carries each policy's full configuration, so a branch that moves a behavior to
    a policy no distribution uses yet can still be judged. Status: ok, denied (a read was refused; what was
    read is kept) or error.
    """
    data = CloudFrontData()
    status = "error"
    try:
        client = boto3.client("cloudfront", aws_access_key_id=key, aws_secret_access_key=secret, aws_session_token=token,
                              region_name="us-east-1", config=_BOTO_CONFIG)
        flags: dict[str, bool] = {}
        summaries = list(_marker_pages(client.list_distributions, "DistributionList"))
        data.distributions = [_distribution(client, summary, flags) for summary in summaries]
        if summaries:
            for kind in ("managed", "custom"):
                for label, call, key_name, build, target in (
                        ("cache policies", client.list_cache_policies, "CachePolicyList", cache_policy_from, data.cache_policies),
                        ("origin request policies", client.list_origin_request_policies, "OriginRequestPolicyList",
                         origin_request_policy_from, data.origin_request_policies)):
                    try:
                        target.extend(build(item, kind) for item in _marker_pages(call, key_name, Type=kind))
                    except ClientError as error:
                        flags["denied" if _code(error) in _DENIED_CODES else "failed"] = True
                    except Exception:
                        flags["failed"] = True
            try:
                data.origin_access_controls = [
                    CloudFrontOriginAccessControl(id=item.get("Id"), name=item.get("Name"), origin_type=item.get("OriginAccessControlOriginType"),
                                                  signing_behavior=item.get("SigningBehavior"), signing_protocol=item.get("SigningProtocol"))
                    for item in _marker_pages(client.list_origin_access_controls, "OriginAccessControlList")]
            except ClientError as error:
                flags["denied" if _code(error) in _DENIED_CODES else "failed"] = True
            except Exception:
                flags["failed"] = True
        if flags.get("denied"):
            warnings.append("CloudFront details skipped: insufficient permissions")
            print("CloudFront details skipped: insufficient permissions")
        if flags.get("failed"):
            warnings.append("CloudFront details skipped: read error")
            print("CloudFront details skipped: read error")
        status = "denied" if flags.get("denied") else "error" if flags.get("failed") else "ok"
    except ClientError as error:
        code = _code(error)
        if code in _DENIED_CODES:
            status = "denied"
            warnings.append("CloudFront scan skipped: insufficient permissions")
            print("CloudFront scan skipped: insufficient permissions")
        else:
            warnings.append("CloudFront scan skipped: read error")
            print("CloudFront scan skipped: read error")
    except Exception:
        warnings.append("CloudFront scan skipped: unexpected error")
        print("CloudFront scan skipped: unexpected error")
    data.collection_status = {"cloudfront": status}
    return data
