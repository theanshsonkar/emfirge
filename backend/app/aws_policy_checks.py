"""AWS adapter: IAM Access Analyzer CheckNoPublicAccess with the customer's role.

Each call is billed by AWS (about $0.002; https://aws.amazon.com/iam/access-analyzer/pricing/).
Results are per policy; a failure on one policy never stops the others.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.policy_checks import PolicyEvidenceRecord, PolicyRef

MAX_ATTEMPTS = 3
MAX_WAIT_SECONDS = 5.0
_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def _default_client(creds, region):
    return boto3.client("accessanalyzer", region_name=region, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds.get("SessionToken"))


def _retry_after(exc: ClientError) -> float:
    meta = exc.response
    value = meta.get("retryAfterSeconds") or meta.get("Error", {}).get("retryAfterSeconds")
    value = value or meta.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("retry-after")
    try:
        return min(max(float(value), 0.0), MAX_WAIT_SECONDS)
    except (TypeError, ValueError):
        return 1.0


def check_policies(creds, region, refs: list[PolicyRef], *, now: datetime | None = None, client_factory=None, sleep=None, revision: str = "") -> list[PolicyEvidenceRecord]:
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    sleeper = sleep or time.sleep
    client = (client_factory or _default_client)(creds, region)
    records = []
    for ref in refs:
        base = dict(resource_type=ref.resource_type, resource_id=ref.resource_id, side=ref.side, local_answer=ref.local_answer, checked_at=stamp, branch_revision=revision)
        record = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                out = client.check_no_public_access(policyDocument=ref.document, resourceType=ref.aws_resource_type)
                result = out.get("result")
                answer = "public" if result == "FAIL" else "not_public" if result == "PASS" else "unknown"
                raw = out.get("reasons")
                reasons = [str(r.get("description", ""))[:300] for r in raw[:5]] if isinstance(raw, list) else []
                record = PolicyEvidenceRecord(provider_answer=answer, status="ok" if answer != "unknown" else "error", reasons=reasons, **base)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {"ThrottlingException", "Throttling"}:
                    if attempt + 1 < MAX_ATTEMPTS:
                        sleeper(_retry_after(exc))
                        continue
                    record = PolicyEvidenceRecord(provider_answer="unknown", status="throttled", **base)
                else:
                    status = "denied" if code in _DENIED else "invalid" if code == "ValidationException" else "error"
                    record = PolicyEvidenceRecord(provider_answer="unknown", status=status, **base)
                break
            except BotoCoreError:
                record = PolicyEvidenceRecord(provider_answer="unknown", status="error", **base)
                break
        records.append(record)
    return records
