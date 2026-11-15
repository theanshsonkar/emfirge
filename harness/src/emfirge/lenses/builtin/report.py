"""How a built-in lens says a fact or an unknown: the same shape in every lens, so the gate and the report read one."""
from __future__ import annotations

from typing import Any

from emfirge.core.model import Change, ChangeType, FieldChange, Finding, Unknown

from .state import is_status


def fact(lens: str, code: str, message: str, change: Change, path: str = '', before: Any = None, after: Any = None,
         **more: Any) -> Finding:
    """A finding about one changed resource. detail always has path / before / after (what the fact is read from)."""
    return Finding(lens, f'{lens}.{code}', f'{change.ref}: {message}', (change.ref,),
                   {'path': path, 'before': before, 'after': after, **more})


def unknown(lens: str, what: str, change: Change) -> Unknown:
    return Unknown(f'{change.ref}: {what}', f'lens:{lens}', change.ref)


def unread_creation(lens: str, change: Change, concern: str) -> Unknown | None:
    """A created resource whose settings the branch did not give: everything in it is new, and none of it was seen."""
    if change.type is ChangeType.CREATED and not change.fields:
        return unknown(lens, f'created, and its settings were not given, so {concern} cannot be told', change)
    return None


def status_unknown(lens: str, field: FieldChange, change: Change, words: Any) -> Unknown | None:
    """A read that now answers with another status (a policy read that now says 'none') has no value to compare."""
    if is_status(field) and words.search(field.path):
        return unknown(lens, f'the read {field.path} now answers {field.after} (was {field.before}); '
                             f'what that means here cannot be told', change)
    return None
