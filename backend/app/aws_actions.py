"""AWS action catalog for the neutral permission expansion (adapter: botocore and policy-sentry).

``actions_for_service("dynamodb")`` is the list of IAM action names (``dynamodb:DeleteItem``) that a
wildcard such as ``dynamodb:*`` or ``dynamodb:Delete*`` stands for. Nothing here is hand written:

  1. policy-sentry's bundled IAM data (already used by ``iam_classifier``) when it knows the service:
     these are the IAM action names themselves.
  2. otherwise the service's API operation names from botocore's service model, turned into
     ``service:Operation``.

Known gap (stated to callers as ``ACTION_CATALOG_GAP``): IAM action names are not always the API
operation names. For example the IAM action ``s3:ListBucket`` authorizes the ``ListObjects`` operation.
Only step 2 can mislabel such actions.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

ACTION_CATALOG_GAP = (
    "action wildcards are expanded from the provider's IAM action list where it has the service, otherwise from "
    "API operation names; IAM action names and API operations differ in some services (for example s3:ListBucket "
    "authorizes the ListObjects operation), so an expansion built from operation names can be incomplete or mislabeled"
)


def _iam_catalog(service: str) -> Optional[frozenset[str]]:
    from policy_sentry.querying.actions import get_actions_for_service
    names = get_actions_for_service(service)
    return frozenset(n for n in names if isinstance(n, str) and ":" in n) or None


@lru_cache(maxsize=1)
def _endpoint_prefixes() -> dict[str, str]:
    """endpointPrefix -> botocore service name (some IAM prefixes, such as 'monitoring', are endpoint prefixes)."""
    import botocore.session
    session = botocore.session.get_session()
    found: dict[str, str] = {}
    for name in session.get_available_services():
        try:
            prefix = session.get_service_model(name).endpoint_prefix
        except Exception:  # an unreadable model is skipped, never guessed
            continue
        found.setdefault(prefix, name)
    return found


def _botocore_catalog(service: str) -> Optional[frozenset[str]]:
    import botocore.session
    from botocore.exceptions import UnknownServiceError
    session = botocore.session.get_session()
    try:
        model = session.get_service_model(service)
    except UnknownServiceError:
        mapped = _endpoint_prefixes().get(service)
        if mapped is None:
            return None
        model = session.get_service_model(mapped)
    return frozenset(f"{service}:{op}" for op in model.operation_names) or None


@lru_cache(maxsize=512)
def actions_for_service(service: str) -> Optional[frozenset[str]]:
    """IAM action names of a service (lowercase prefix), or None when neither source knows it."""
    service = service.lower()
    return _iam_catalog(service) or _botocore_catalog(service)
