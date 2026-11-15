"""Every string in a resource's settings, with what is packed inside strings opened up.

Clouds hide links inside strings: a policy is a JSON document in a string (sometimes URL-encoded), a machine's
start-up script is base64 text. The graph must see inside them, or it misses exactly the links that cross services.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Iterator

_BASE64 = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
_MAX_DEPTH = 4          # strings inside strings inside strings: enough for a policy in base64 in JSON
_PRINTABLE = 0.95       # share of printable characters a decoded string needs to be read as text


@dataclass(frozen=True)
class Leaf:
    """One string in a resource's state.
    path      where it is, e.g. 'GetRolePolicy.PolicyDocument<json>.Statement[0].Resource'
    text      the string itself (for packed strings: the opened text)
    own       True when the string sits in a plain field of the resource (only mappings on the way, no list, not
              inside a packed string): such a value can be the resource's own name or address
    scope     the other patterns in the same mapping (siblings): they say what a catch-all '*' beside them covers"""
    path: str
    text: str
    own: bool
    scope: tuple[str, ...] = ()


def leaves(state: Any, has_wildcard: Callable[[str], bool]) -> Iterator[Leaf]:
    """All string leaves of a state. has_wildcard picks the sibling patterns kept as a leaf's scope."""
    yield from _walk(state, '', True, (), has_wildcard, 0)


def _walk(node: Any, path: str, own: bool, scope: tuple[str, ...], wild: Callable[[str], bool], depth: int) -> Iterator[Leaf]:
    if isinstance(node, dict):
        siblings = tuple(s for v in node.values() for s in _strings_of(v) if wild(s))
        for key, value in node.items():
            yield from _walk(value, f'{path}.{key}' if path else str(key), own, siblings, wild, depth)
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            yield from _walk(value, f'{path}[{i}]', False, scope, wild, depth)
    elif isinstance(node, str):
        yield from _string(node, path, own, scope, wild, depth)


def _strings_of(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str)]
    return []


def _string(text: str, path: str, own: bool, scope: tuple[str, ...], wild: Callable[[str], bool], depth: int) -> Iterator[Leaf]:
    if depth < _MAX_DEPTH:
        opened = open_packed(text)
        if opened is not None:
            kind, inner = opened
            if isinstance(inner, str):
                yield Leaf(f'{path}<{kind}>', inner, False, scope)
            else:
                yield from _walk(inner, f'{path}<{kind}>', False, (), wild, depth + 1)
            return
    yield Leaf(path, text, own, scope)


def open_packed(text: str) -> tuple[str, Any] | None:
    """('json', data), ('url', data), ('base64', data or text), or None when the string is not packed."""
    s = text.strip()
    if s[:3].upper() in ('%7B', '%5B'):
        data = _json(urllib.parse.unquote(s))
        return ('url', data) if data is not None else None
    if s[:1] in '{[':
        data = _json(s)
        return ('json', data) if data is not None else None
    decoded = _base64_text(s)
    if decoded is not None:
        data = _json(decoded.strip())
        return ('base64', data if data is not None else decoded)
    return None


def _json(s: str) -> Any:
    if s[:1] not in '{[':
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def _base64_text(s: str) -> str | None:
    """Text, when s is base64 of readable text. Hashes and keys decode to bytes that are not text, and are left alone."""
    if len(s) % 4 or not _BASE64.fullmatch(s):
        return None
    try:
        decoded = base64.b64decode(s, validate=True).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError):
        return None
    printable = sum(ch.isprintable() or ch in '\n\r\t' for ch in decoded)
    if not decoded or printable / len(decoded) < _PRINTABLE or not re.search(r'\s', decoded):
        return None
    return decoded
