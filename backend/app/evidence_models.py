from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SOURCES = ("cloudtrail_events", "cloudwatch_metrics")
MAX_EVIDENCE_RESOURCES = 50

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
    status: Literal["ok", "no_data", "denied", "error", "incomplete", "unknown"]
    used: bool | None
    holds_data: bool | None = None
    window_days: int
    observed_at: str
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
    max_resources: int


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", regex_engine="python-re")
    role_arn: str = Field(pattern=r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
    sources: list[Literal["cloudtrail_events", "cloudwatch_metrics"]] = Field(min_length=1, max_length=2)
    accept_estimate_id: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("sources")
    @classmethod
    def sources_unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("sources must be unique")
        return value


def parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
