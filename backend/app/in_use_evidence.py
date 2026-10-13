from __future__ import annotations

import hashlib
import json
import re
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import boto3
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, Field

from app import delete_lens
from app.mutations import deletion_ledger

SOURCES = ("cloudtrail_events", "cloudwatch_metrics")
WINDOW_DAYS = delete_lens.RECENT_USE_DAYS

# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch.html
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/monitoring-cloudwatch.html
# https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
# https://docs.aws.amazon.com/ebs/latest/userguide/using_cloudwatch_ebs.html
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html
METRIC_SPECS = {
    "ec2_instance": [("AWS/EC2", "CPUUtilization", "InstanceId", "Maximum"), ("AWS/EC2", "NetworkIn", "InstanceId", "Sum"), ("AWS/EC2", "NetworkOut", "InstanceId", "Sum")],
    "rds_instance": [("AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", "Maximum")],
    "lambda_function": [("AWS/Lambda", "Invocations", "FunctionName", "Sum")],
    "ebs_volume": [("AWS/EBS", "VolumeReadOps", "VolumeId", "Sum"), ("AWS/EBS", "VolumeWriteOps", "VolumeId", "Sum")],
    "s3_bucket": [("AWS/S3", "NumberOfObjects", "BucketName", "Average")],
}

class MetricSummary(BaseModel):
    metric: str
    statistic: str
    datapoints: int
    peak: float | None = None
    latest: float | None = None

class EvidenceRecord(BaseModel):
    resource_id: str
    resource_type: str
    source: str
    status: Literal["ok", "no_data", "denied", "error", "incomplete"]
    used: bool | None
    holds_data: bool | None = None
    window_days: int
    last_event_at: str | None = None
    event_name: str | None = None
    metrics: list[MetricSummary] = Field(default_factory=list)

class EvidenceCall(BaseModel):
    source: str
    api: str
    max_requests: int
    billable: bool
    note: str
    pricing_url: str

class EstimateResource(BaseModel):
    resource_type: str
    resource_id: str
    sources: list[str]

class EvidenceEstimate(BaseModel):
    estimate_id: str
    branch_revision: str
    window_days: int
    sources: list[str]
    resources: list[EstimateResource]
    calls: list[EvidenceCall]

class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_arn: str
    sources: list[str] = Field(min_length=1)
    accept_estimate_id: str = Field(pattern=r"^[0-9a-f]{64}$")

    def model_post_init(self, __context: Any) -> None:
        if re.fullmatch(r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}", self.role_arn) is None:
            raise ValueError("invalid role ARN")
        if any(source not in SOURCES for source in self.sources) or len(set(self.sources)) != len(self.sources):
            raise ValueError("invalid evidence sources")

def _value(item: Any, key: str, default=None):
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)

def _deleted_resources(base: Any, branch: Any) -> list[EstimateResource]:
    result = []
    for item in deletion_ledger(branch):
        result.append(EstimateResource(resource_type=str(item.get("resource_type", "")), resource_id=str(item.get("resource_id", "")), sources=[]))
    return sorted(result, key=lambda x: (x.resource_type, x.resource_id))

def build_estimate(base: Any, branch_infra: Any, branch_revision: str, sources: list[str]) -> EvidenceEstimate:
    resources = _deleted_resources(base, branch_infra)
    for resource in resources:
        resource.sources = [source for source in sorted(set(sources)) if source == "cloudtrail_events" or resource.resource_type in METRIC_SPECS]
    calls = []
    if "cloudtrail_events" in sources:
        calls.append(EvidenceCall(source="cloudtrail_events", api="cloudtrail:LookupEvents", max_requests=sum(3 for _ in resources), billable=False, note="CloudTrail does not charge for event history lookups; AWS allows 2 lookups per second", pricing_url="https://aws.amazon.com/cloudtrail/pricing/"))
    if "cloudwatch_metrics" in sources:
        calls.append(EvidenceCall(source="cloudwatch_metrics", api="cloudwatch:GetMetricStatistics", max_requests=sum(len(METRIC_SPECS.get(r.resource_type, [])) for r in resources), billable=True, note="CloudWatch bills API requests beyond its free tier; see pricing for your region", pricing_url="https://aws.amazon.com/cloudwatch/pricing/"))
    payload = {"branch_revision": branch_revision, "sources": sorted(set(sources)), "resources": [r.model_dump(mode="json") for r in resources], "calls": [c.model_dump(mode="json") for c in calls]}
    estimate_id = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return EvidenceEstimate(estimate_id=estimate_id, branch_revision=branch_revision, window_days=WINDOW_DAYS, sources=sorted(set(sources)), resources=resources, calls=calls)

def _default_client(service, region, creds):
    return boto3.client(service, region_name=region, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds.get("SessionToken"))

def _denied(exc: Exception) -> bool:
    return isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess"}

def _metric_record(resource, client, now, sleep):
    specs = METRIC_SPECS[resource.resource_type]
    summaries = []
    values_by_metric = {}
    try:
        for namespace, metric, dimension, statistic in specs:
            dimensions = [{"Name": dimension, "Value": resource.resource_id}]
            if resource.resource_type == "s3_bucket": dimensions.append({"Name": "StorageType", "Value": "AllStorageTypes"})
            response = client.get_metric_statistics(Namespace=namespace, MetricName=metric, Dimensions=dimensions, StartTime=now - timedelta(days=WINDOW_DAYS), EndTime=now, Period=86400, Statistics=[statistic])
            points = sorted(response.get("Datapoints", []), key=lambda p: p.get("Timestamp", datetime.min.replace(tzinfo=timezone.utc)))
            values = [float(p[statistic]) for p in points if statistic in p]
            summaries.append(MetricSummary(metric=metric, statistic=statistic, datapoints=len(values), peak=max(values) if values else None, latest=values[-1] if values else None))
            values_by_metric[metric] = {str(p.get("Timestamp")): float(p[statistic]) for p in points if statistic in p}
        any_points = any(s.datapoints for s in summaries)
        if resource.resource_type == "s3_bucket":
            return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="ok" if any_points else "no_data", used=None, holds_data=bool(summaries[0].latest > 0) if summaries[0].latest is not None else None, window_days=WINDOW_DAYS, metrics=summaries)
        used = any((s.peak is not None and s.peak > 0) for s in summaries)
        if resource.resource_type == "ec2_instance":
            cpu = values_by_metric.get("CPUUtilization", {})
            net = values_by_metric.get("NetworkIn", {})
            net.update({k: net.get(k, 0) + v for k, v in values_by_metric.get("NetworkOut", {}).items()})
            used = any(v >= 5.0 for v in cpu.values()) or any(v >= 5_000_000 for v in net.values())
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="ok" if any_points else "no_data", used=used, window_days=WINDOW_DAYS, metrics=summaries)
    except Exception as exc:
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudwatch_metrics", status="denied" if _denied(exc) else "error", used=None, window_days=WINDOW_DAYS)

def _trail_record(resource, client, now, own_session_name, sleep):
    start = now - timedelta(days=WINDOW_DAYS)
    token = None
    found = None
    try:
        for page in range(3):
            if page: sleep(0.5)
            kwargs = {"LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": resource.resource_id}], "StartTime": start, "EndTime": now, "MaxResults": 50}
            if token: kwargs["NextToken"] = token
            response = client.lookup_events(**kwargs)
            for event in response.get("Events", []):
                if event.get("ReadOnly") == "true" or event.get("Username") == own_session_name: continue
                found = event; break
            if found: break
            token = response.get("NextToken")
            if not token: break
        status = "ok" if found else ("incomplete" if token else "no_data")
        stamp = found.get("EventTime") if found else None
        iso = stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(stamp, datetime) else (str(stamp).replace("+00:00", "Z") if stamp else None)
        name = found.get("EventName") if found and re.fullmatch(r"[A-Za-z0-9]{1,128}", str(found.get("EventName", ""))) else None
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudtrail_events", status=status, used=None, window_days=WINDOW_DAYS, last_event_at=iso, event_name=name)
    except Exception as exc:
        return EvidenceRecord(resource_id=resource.resource_id, resource_type=resource.resource_type, source="cloudtrail_events", status="denied" if _denied(exc) else "error", used=None, window_days=WINDOW_DAYS)

def read_evidence(creds, region, resources, sources, *, now, own_session_name, client_factory=_default_client, sleep=time.sleep):
    clients = {}
    records = []
    for resource in resources:
        if "cloudwatch_metrics" in sources and resource.resource_type in METRIC_SPECS:
            clients.setdefault("cloudwatch", client_factory("cloudwatch", region, creds)); records.append(_metric_record(resource, clients["cloudwatch"], now, sleep))
        if "cloudtrail_events" in sources:
            clients.setdefault("cloudtrail", client_factory("cloudtrail", region, creds)); records.append(_trail_record(resource, clients["cloudtrail"], now, own_session_name, sleep))
    return records
