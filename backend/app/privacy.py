"""Privacy: the single registry and routine for purging one AWS account's stored data.

PURGE_PLAN names every table in ``Base.metadata``. A table is either purged for an
AWS account (``account_column`` or ``branch_ids``) or deliberately ``kept`` with a reason.
A law test fails if a new table is added without an entry here.
"""
import json
import logging
import os
from dataclasses import dataclass

import boto3

from app import database
from app.log_safe import safe_exc
from app.storage import REPORTS_PREFIX

logger = logging.getLogger(__name__)

ACCOUNT_COLUMN = "account_column"  # rows carry aws_account_id
BRANCH_IDS = "branch_ids"          # rows carry branch_id of a branch based on one of the account's analyses
KEPT = "kept"


@dataclass(frozen=True)
class Rule:
    kind: str
    detail: str  # column name for purged tables, the reason for kept tables


PURGE_PLAN: dict[str, Rule] = {
    "analysis_logs": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "drift_events": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "simulation_logs": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "feedback": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "llm_usage": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "account_bindings": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "account_binding_events": Rule(ACCOUNT_COLUMN, "aws_account_id"),
    "branch_logs": Rule(BRANCH_IDS, "branch_id"),
    "branch_owners": Rule(BRANCH_IDS, "branch_id"),
    "plan_logs": Rule(BRANCH_IDS, "branch_id"),
    "branch_evidence_logs": Rule(BRANCH_IDS, "branch_id"),
    "branch_policy_check_logs": Rule(BRANCH_IDS, "branch_id"),
    "projects": Rule(KEPT, "the user's login/workspace, not AWS account data"),
    "api_keys": Rule(KEPT, "the user's login credential (hashed), not AWS account data"),
    "supabase_identities": Rule(KEPT, "the user's login identity, not AWS account data"),
    "tf_resources": Rule(KEPT, "legacy GitHub-installation index keyed by installation, not by AWS account; legacy routes are disabled when auth is on"),
    "ci_api_keys": Rule(KEPT, "legacy GitHub-installation keys keyed by installation, not by AWS account; legacy routes are disabled when auth is on"),
}

_CHUNK = 500


def _chunks(items: list):
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


def _analysis_uuids(session, account_id: str) -> list[str]:
    uuids = []
    for (findings_json,) in session.query(database.AnalysisLog.findings_json).filter_by(aws_account_id=account_id):
        try:
            uid = (json.loads(findings_json) if findings_json else {}).get("analysis_id")
        except Exception:
            continue
        if uid:
            uuids.append(uid)
    return uuids


def _delete_in(session, table, column: str, values: list) -> int:
    count = 0
    for chunk in _chunks(values):
        count += session.query(table).filter(getattr(table, column).in_(chunk)).delete(synchronize_session=False)
    return count


def purge_db(account_id: str) -> tuple[dict[str, int], list[str]]:
    """Delete every purgeable row for the account in one transaction.

    Returns (per-table deleted counts, analysis uuids). Branch ids and analysis
    uuids are collected before analysis_logs is deleted.
    """
    tables = {m.class_.__tablename__: m.class_ for m in database.Base.registry.mappers}
    session = database.SessionLocal()
    try:
        uuids = _analysis_uuids(session, account_id)
        branch_ids = []
        for chunk in _chunks(uuids):
            branch_ids += [b for (b,) in session.query(database.BranchLog.branch_id)
                           .filter(database.BranchLog.base_analysis_id.in_(chunk))]
        counts: dict[str, int] = {}
        # Children of branches first, then the branches, then account rows (analysis_logs last of those).
        for name, rule in PURGE_PLAN.items():
            if rule.kind == BRANCH_IDS:
                counts[name] = _delete_in(session, tables[name], rule.detail, branch_ids)
        for name, rule in PURGE_PLAN.items():
            if rule.kind == ACCOUNT_COLUMN:
                cls = tables[name]
                counts[name] = session.query(cls).filter(
                    getattr(cls, rule.detail) == account_id).delete(synchronize_session=False)
        session.commit()
        return counts, uuids
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def purge_s3_reports(analysis_uuids: list[str]) -> int:
    """Best-effort delete of stored reports (reports/...analysis-<uuid>.json); never raises."""
    deleted = 0
    try:
        bucket = os.getenv("S3_BUCKET_NAME")
        if not bucket or not analysis_uuids:
            return 0
        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_REGION", "ap-south-1"),
        )
        uid_set = set(analysis_uuids)
        token = None
        while True:
            kwargs = {"Bucket": bucket, "Prefix": REPORTS_PREFIX}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                key = obj["Key"]
                if any(uid in key for uid in uid_set):
                    try:
                        s3.delete_object(Bucket=bucket, Key=key)
                        deleted += 1
                    except Exception as err:
                        logger.warning("S3 delete failed for 1 object: %s", safe_exc(err))
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
    except Exception as err:
        logger.warning("S3 purge step failed: %s", safe_exc(err))
    return deleted


def purge_account(account_id: str) -> dict[str, int]:
    """Purge the account's database rows and S3 reports; returns per-table counts plus s3_objects."""
    counts, uuids = purge_db(account_id)
    counts["s3_objects"] = purge_s3_reports(uuids)
    return counts
