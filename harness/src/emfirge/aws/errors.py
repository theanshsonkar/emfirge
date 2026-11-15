"""How AWS says a thing does not exist, the same for every service (NotFound, NoSuch..., DoesNotExist, 404)."""
from __future__ import annotations

import re

import botocore.exceptions

_ABSENT = re.compile(r'NotFound|NoSuch|NonExistent|DoesNotExist')


def absent(e: botocore.exceptions.ClientError) -> bool:
    """The service's way of saying the thing does not exist."""
    code = e.response.get('Error', {}).get('Code', '')
    status = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    return bool(_ABSENT.search(code)) or code == '404' or (status == 404 and not code)
