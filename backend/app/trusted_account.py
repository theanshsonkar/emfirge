"""Resolve the AWS account trusted by the generated setup template."""

import logging
import os
import re

import boto3
from botocore.config import Config

_ACCOUNT_ID = re.compile(r"^\d{12}$")
_cached_account_id: str | None = None
logger = logging.getLogger(__name__)
_WARNING = (
    "EMFIRGE_TRUSTED_ACCOUNT_ID does not match the server credentials account; "
    "using the credentials account"
)


def trusted_account_id() -> str | None:
    """Return the configured account, or the backend caller's AWS account."""
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


def verified_trusted_account_id() -> str | None:
    """Return the credentials account, falling back to the configured account."""
    configured = os.environ.get("EMFIRGE_TRUSTED_ACCOUNT_ID")
    configured_valid = bool(configured and _ACCOUNT_ID.fullmatch(configured))

    global _cached_account_id
    if _cached_account_id is not None:
        if configured_valid and configured != _cached_account_id:
            logger.warning(_WARNING)
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
        account_id = str(account_id)
        if _ACCOUNT_ID.fullmatch(account_id):
            if configured_valid and configured != account_id:
                logger.warning(_WARNING)
            _cached_account_id = account_id
            return _cached_account_id
    except Exception:
        pass

    return trusted_account_id()
