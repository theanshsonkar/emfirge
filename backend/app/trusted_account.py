"""Resolve the AWS account trusted by the generated setup template."""

import os
import re

import boto3
from botocore.config import Config

_ACCOUNT_ID = re.compile(r"^\d{12}$")
_cached_account_id: str | None = None


def trusted_account_id() -> str | None:
    """Return the configured account, or the backend caller's AWS account.

    Successful STS lookups are cached for the lifetime of this process. Failed
    lookups are intentionally not cached so a transient failure can recover.
    """
    configured = os.environ.get("EMFIRGE_TRUSTED_ACCOUNT_ID")
    if configured and _ACCOUNT_ID.fullmatch(configured):
        return configured

    global _cached_account_id
    if _cached_account_id is not None:
        return _cached_account_id

    try:
        account_id = boto3.client(
            "sts",
            config=Config(
                connect_timeout=2,
                read_timeout=2,
                retries={"max_attempts": 1},
            ),
        ).get_caller_identity()["Account"]
        if not _ACCOUNT_ID.fullmatch(str(account_id)):
            return None
        _cached_account_id = str(account_id)
        return _cached_account_id
    except Exception:
        return None
