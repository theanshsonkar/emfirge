"""Helpers that keep customer identifiers out of server logs (law L71g).

Exception text from botocore, the database driver and LLM clients embeds ARNs, account
ids, SQL parameters and prompt text, so it must never be logged. Log the exception's type
name plus, for a botocore ClientError, the AWS error code.
"""
import re

from botocore.exceptions import ClientError

_CODE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def safe_exc(exc: BaseException) -> str:
    """'ClientError(AccessDenied)' for AWS errors, otherwise just the class name."""
    name = type(exc).__name__
    if isinstance(exc, ClientError):
        code = str((getattr(exc, "response", None) or {}).get("Error", {}).get("Code", ""))
        if _CODE_RE.fullmatch(code):
            return f"{name}({code})"
        return f"{name}(Unknown)"
    return name


def safe_choice(value, allowed) -> str:
    """Return value only when it is one of a fixed set of non-identifying labels."""
    return value if value in allowed else "unknown"
