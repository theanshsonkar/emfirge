"""Walking one changed setting the same way for every service.

The built-in lenses know no service. They see a FieldChange (a path, a value before, a value after) and walk both
values: mappings, lists, and documents packed in strings (a policy is JSON in a string, sometimes URL-encoded). Every
detector then turns a walked value into a set of facts, and a lens reports the facts of `after` that `before` lacks.
That one rule is what makes a lens report only what is new: an open rule that was already there is in both sets.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from emfirge.core.model import FieldChange

_INDEX = re.compile(r'\[\d+\]')
_MAX_DEPTH = 3   # a document in a string in a document in a string: deeper is not a setting


@dataclass(frozen=True)
class Node:
    """One place in a walked value.
    path     where it is: 'Policy<json>.Statement[0].Principal'
    key      the nearest mapping key ('Principal'); for list items, the key of the list
    value    the value there (packed strings already opened)
    parents  the mappings around it, nearest first: they give a value its context (the ports beside an address)"""
    path: str
    key: str
    value: Any
    parents: tuple[Mapping[str, Any], ...] = ()

    @property
    def shape(self) -> str:
        return shape(self.path)

    @property
    def is_leaf(self) -> bool:
        return not isinstance(self.value, (dict, list, tuple))


def nodes(value: Any, path: str) -> Iterator[Node]:
    """Every node of `value`, which sits at `path`, the containers included."""
    yield from _walk(value, path, key_of(path), (), 0)


def leaves(value: Any, path: str) -> Iterator[Node]:
    return (n for n in nodes(value, path) if n.is_leaf)


def _walk(value: Any, path: str, key: str, parents: tuple, depth: int) -> Iterator[Node]:
    if isinstance(value, str) and depth < _MAX_DEPTH:
        opened = open_document(value)
        if opened is not None:
            yield from _walk(opened, f'{path}<json>', key, parents, depth + 1)
            return
    yield Node(path, key, value, parents)
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, f'{path}.{k}' if path else str(k), str(k), (value,) + parents, depth)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _walk(v, f'{path}[{i}]', key, parents, depth)


def open_document(text: str) -> Any:
    """The JSON document held in a string (plain or URL-encoded), or None when the string is not one."""
    s = text.strip()
    if s[:3].upper() in ('%7B', '%5B'):
        s = urllib.parse.unquote(s)
    if s[:1] not in '{[':
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def shape(path: str) -> str:
    """The path with list positions removed: the same rule at another position in a list is the same rule."""
    return _INDEX.sub('[]', path)


def key_of(path: str) -> str:
    last = _INDEX.sub('', path).replace('<json>', '').split('.')[-1]
    return last.strip('()')


def is_status(change: FieldChange) -> bool:
    """The branch writes a read whose answer status changed (200 -> 404) as path '(Operation)'. No value to walk."""
    return change.path.startswith('(') and change.path.endswith(')')


def as_switch(value: Any, on: frozenset[str], off: frozenset[str]) -> bool | None:
    """True / False for a value that reads as on or off ('Enabled', 'DISABLED', 'true', True), else None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        word = value.strip().lower()
        return True if word in on else False if word in off else None
    return None


def as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def operation(call: str) -> str:
    """'lambda.UpdateFunctionConfiguration' -> 'UpdateFunctionConfiguration'. The service part is never read."""
    return call.rsplit('.', 1)[-1]


def short(items: Any, limit: int = 3) -> str:
    """A list in plain words, cut after `limit` items."""
    values = sorted(str(i) for i in items)
    head = ', '.join(values[:limit]) or '(none)'
    return head + (f' and {len(values) - limit} more' if len(values) > limit else '')
