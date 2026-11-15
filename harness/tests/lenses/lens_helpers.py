"""Small builders for lens tests. Made-up names and the account 000000000000 (and 999999999999 as 'another') only."""
from __future__ import annotations

import json
import urllib.parse

from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef
from emfirge.lenses import LensView, builtin_lenses, run_lenses

OWN, OTHER = '000000000000', '999999999999'


def policy(*statements: dict) -> str:
    return json.dumps({'Version': '2012-10-17', 'Statement': list(statements)})


def url_encoded(text: str) -> str:
    """IAM returns policy documents URL-encoded."""
    return urllib.parse.quote(text)


def allow(action, resource='*', principal=None, condition=None, effect='Allow') -> dict:
    s = {'Effect': effect, 'Action': action}
    if resource is not None:
        s['Resource'] = resource
    if principal is not None:
        s['Principal'] = principal
    if condition is not None:
        s['Condition'] = condition
    return s


def modified(type_: str, id_: str, *fields: tuple, calls: tuple[str, ...] = ()) -> Change:
    return Change(ResourceRef(type_, id_), ChangeType.MODIFIED, tuple(FieldChange(*f) for f in fields), calls)


def codes(changes: list[Change], **kw) -> set[str]:
    return {f.code for f in run_lenses(builtin_lenses(**kw), LensView(changes)).findings}
