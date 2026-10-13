from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from app import delete_lens
from app.evidence_models import (
    MAX_EVIDENCE_RESOURCES, METRIC_SPECS, SOURCES, EvidenceCall, EvidenceEstimate,
    EvidenceRecord, EvidenceRequest, EstimateResource, MetricSummary, parse_iso,
)
from app.mutations import deletion_ledger

WINDOW_DAYS = delete_lens.RECENT_USE_DAYS
_sleep = time.sleep


def _value(item: Any, key: str, default=None):
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _deleted_resources(base: Any, branch: Any) -> list[EstimateResource]:
    return sorted(
        [EstimateResource(resource_type=str(item.get("resource_type", "")), resource_id=str(item.get("resource_id", "")), sources=[])
         for item in deletion_ledger(branch)],
        key=lambda x: (x.resource_type, x.resource_id),
    )


def build_estimate(base: Any, branch_infra: Any, branch_revision: str, sources: list[str]) -> EvidenceEstimate:
    resources = _deleted_resources(base, branch_infra)
    for resource in resources:
        resource.sources = [source for source in sorted(set(sources)) if source == "cloudtrail_events" or resource.resource_type in METRIC_SPECS]
    calls = []
    if "cloudtrail_events" in sources:
        calls.append(EvidenceCall(source="cloudtrail_events", api="cloudtrail:LookupEvents", max_requests=3 * len(resources), billable=False, note="CloudTrail does not charge for event history lookups; AWS allows 2 lookups per second", pricing_url="https://aws.amazon.com/cloudtrail/pricing/"))
    if "cloudwatch_metrics" in sources:
        calls.append(EvidenceCall(source="cloudwatch_metrics", api="cloudwatch:GetMetricStatistics", max_requests=sum(len(METRIC_SPECS.get(r.resource_type, [])) for r in resources), billable=True, note="CloudWatch bills API requests beyond its free tier; see pricing for your region", pricing_url="https://aws.amazon.com/cloudwatch/pricing/"))
    payload = {"branch_revision": branch_revision, "sources": sorted(set(sources)), "resources": [r.model_dump(mode="json") for r in resources], "calls": [c.model_dump(mode="json") for c in calls]}
    estimate_id = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return EvidenceEstimate(estimate_id=estimate_id, branch_revision=branch_revision, window_days=WINDOW_DAYS, sources=sorted(set(sources)), resources=resources, calls=calls, max_resources=MAX_EVIDENCE_RESOURCES)


def _default_client(service, region, creds):
    return boto3.client(service, region_name=region, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds.get("SessionToken"))


def _denied(exc: Exception) -> bool:
    return isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess"}


def _dimension_value(resource) -> str:
    value = str(_value(resource, "dimension_value", _value(resource, "resource_id", "")))
    typ = str(_value(resource, "resource_type", ""))
    if value.startswith("arn:"):
        if typ == "s3_bucket":
            return value.rsplit(":", 1)[-1]
        return value.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return value


def _observed_at(now: datetime) -> str:
    stamp = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _metric_record(resource, client, now, observed_at):
    specs = METRIC_SPECS[resource.resource_type]
    summaries = []
    values_by_metric = {}
    try:
        for namespace, metric, dimension, statistic in specs:
            dimensions = [{"Name": dimension, "Value": _dimension_value(resource)}]
            if resource.resource_type == "s3_bucket":
                dimensions.append({"Name": "StorageType", "Value": "AllStorageTypes"})
            response = client.get_metric_statistics(Namespace=namespace, MetricName=metric, Dimensions=dimensions, StartTime=now - timedelta(days=WINDOW_DAYS), EndTime=now, Period=86400, Statistics=[statistic])
            points = sorted(response.get("Datapoints", []), key=lambda p: p.get("Timestamp", datetime.min.replace(tzinfo=timezone.utc)))
            values = [float(p[statistic]) for p in points if statistic in p]
            summaries.append(MetricSummary(metric=metric, statistic=statistic, datapoints=len(values), peak=max(values) if values else None, latest=values[-1] if values else None))
            values_by_metric[metric] = {str(p.get("Timestamp")): float(p[statistic]) for p in points if statistic in p}
        any_points = any(s.datapoints for s in summaries)
        if resource.resource_type == "s3_bucket":
            holds = bool(summaries[0].latest > 0) if summaries[0].latest is not None else None
            return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="ok" if any_points else "no_data", used=None, holds_data=holds, window_days=WINDOW_DAYS, observed_at=observed_at, metrics=summaries)
        used = any((s.peak is not None and s.peak > 0) for s in summaries)
        if resource.resource_type == "ec2_instance":
            cpu = values_by_metric.get("CPUUtilization", {})
            net = values_by_metric.get("NetworkIn", {})
            net.update({k: net.get(k, 0) + v for k, v in values_by_metric.get("NetworkOut", {}).items()})
            used = any(v >= 5.0 for v in cpu.values()) or any(v >= 5_000_000 for v in net.values())
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="ok" if any_points else "no_data", used=used, window_days=WINDOW_DAYS, observed_at=observed_at, metrics=summaries)
    except Exception as exc:
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="denied" if _denied(exc) else "error", used=None, window_days=WINDOW_DAYS, observed_at=observed_at)


def _trail_record(resource, client, now, own_session_name, observed_at, sleep, first_lookup):
    start = now - timedelta(days=WINDOW_DAYS)
    token = None
    found = None
    try:
        for page in range(3):
            if not first_lookup() :
                sleep(0.5)
            kwargs = {"LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": resource.resource_id}], "StartTime": start, "EndTime": now, "MaxResults": 50}
            if token:
                kwargs["NextToken"] = token
            response = client.lookup_events(**kwargs)
            for event in response.get("Events", []):
                if event.get("ReadOnly") == "true" or event.get("Username") == own_session_name:
                    continue
                found = event
                break
            if found:
                break
            token = response.get("NextToken")
            if not token:
                break
        status = "ok" if found else ("incomplete" if token else "no_data")
        stamp = found.get("EventTime") if found else None
        event_time = stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(stamp, datetime) else (str(stamp).replace("+00:00", "Z") if stamp else None)
        name = found.get("EventName") if found and re.fullmatch(r"[A-Za-z0-9]{1,128}", str(found.get("EventName", ""))) else None
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudtrail_events", status=status, used=None, window_days=WINDOW_DAYS, observed_at=observed_at, last_event_at=event_time, event_name=name)
    except Exception as exc:
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudtrail_events", status="denied" if _denied(exc) else "error", used=None, window_days=WINDOW_DAYS, observed_at=observed_at)


def read_evidence(creds, region, resources, sources, *, now, own_session_name, client_factory=None, sleep=None):
    factory = client_factory or _default_client
    sleeper = sleep or _sleep
    clients = {}
    records = []
    first_cloudtrail = True

    def take_first():
        nonlocal first_cloudtrail
        result = first_cloudtrail
        first_cloudtrail = False
        return result

    for resource in resources:
        if "cloudwatch_metrics" in sources and resource.resource_type in METRIC_SPECS:
            clients.setdefault(("cloudwatch", region), factory("cloudwatch", region, creds))
            records.append(_metric_record(resource, clients[("cloudwatch", region)], now, _observed_at(now)))
        if "cloudtrail_events" in sources:
            trail_region = "us-east-1" if resource.resource_type == "iam_role" else region
            clients.setdefault(("cloudtrail", trail_region), factory("cloudtrail", trail_region, creds))
            records.append(_trail_record(resource, clients[("cloudtrail", trail_region)], now, own_session_name, _observed_at(now), sleeper, take_first))
    return records


# Keep these imports available from the historical module path.
__all__ = ["SOURCES", "METRIC_SPECS", "MetricSummary", "EvidenceRecord", "EvidenceCall", "EstimateResource", "EvidenceEstimate", "EvidenceRequest", "parse_iso", "build_estimate", "read_evidence", "MAX_EVIDENCE_RESOURCES"]
