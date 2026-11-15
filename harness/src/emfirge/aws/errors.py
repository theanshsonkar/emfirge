"""How AWS says a thing does not exist (NotFound, NoSuch..., DoesNotExist, 404), and how a copier says it does not
know a kind of resource."""
from __future__ import annotations

import re

import botocore.exceptions

from emfirge.core.ports import CannotTell

_ABSENT = re.compile(r'NotFound|NoSuch|NonExistent|DoesNotExist')


def absent(e: botocore.exceptions.ClientError) -> bool:
    """The service's way of saying the thing does not exist."""
    code = e.response.get('Error', {}).get('Code', '')
    status = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    return bool(_ABSENT.search(code)) or code == '404' or (status == 404 and not code)


class UnknownType(CannotTell):
    """A copier does not know how to copy this kind of resource at all (said before it writes anything), so another
    copier may try. A refusal of one resource of a known kind is a plain CannotTell, and stands."""
