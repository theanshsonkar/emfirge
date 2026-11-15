"""Compare a real answer with the engine's answer to the same read: which ids the engine gave out instead of the real
ones, whether the copy has settled, and what the copy lacks. Pure: no I/O.

Why: the copier cannot know in advance what a create leaves out (a setting with no write, a value the engine
refused). Reading both sides after the copy measures it, and the copy's notes say it in plain words.
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Callable, Iterator

from ..catalog.names import related, split

ID_VALUE = re.compile(r'^[\w./:+=@-]{6,}$')
STATE_KEY = re.compile(r'(State|Status)$')
NOISE_KEY = re.compile(r'(Date|Time|Timestamp|Modified|RequestId|ETag|Etag|RevisionId|Sha256|Location)$', re.I)


def leaves(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    """(path, value) for every scalar in plain nested data; list items are addressed by their index."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from leaves(v, path + (str(k),))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from leaves(v, path + (str(i),))
    else:
        yield path, value


def new_ids(real: Any, engine: Any, word: str) -> list[tuple[str, str]]:
    """(real value, engine value) where the same field holds an id, ARN or address of the resource itself (RoleId,
    KeyId, a bare Id, a secret's ARN with its random end, a queue's URL) and the two differ: the engine gave out its
    own. `word` names the resource (its type's name, or a list item's noun: 'accesskey'). An id at the top of the
    answer (a secret's VersionId) is the resource's own too."""
    mine = dict(leaves(engine))
    out = []
    for path, value in leaves(real):
        other = mine.get(path)
        if not path or not isinstance(value, str) or not isinstance(other, str) or value == other:
            continue
        words = split(path[-1])
        own = words.designator in ('id', 'arn', 'url') and (not words.words or related(words.joined, word)) \
            or path[-1] == 'UUID' or len(path) == 1 and words.designator == 'id'
        if own and ID_VALUE.match(value) and ID_VALUE.match(other):
            out.append((value, other))
    return list(dict.fromkeys(out))


def same_item(real: Any, engine: Any, translate: Callable[[str], str]) -> bool:
    """The engine's list item is the real one: every name, id or ARN field of the real item has the same value
    (in engine ids) in the engine's item."""
    if not isinstance(real, dict) or not isinstance(engine, dict):
        return translate(real) == engine if isinstance(real, str) else real == engine
    keys = [k for k, v in real.items() if isinstance(v, str) and split(k).designator in ('name', 'id', 'arn')]
    return bool(keys) and all(translate(real[k]) == engine.get(k) for k in keys)


def states(body: Any) -> dict[tuple[str, ...], str]:
    """The fields that say where a resource is in its life (State, Status, TableStatus), at the top two levels."""
    return {p: v for p, v in leaves(body) if len(p) <= 2 and isinstance(v, str) and STATE_KEY.search(p[-1])}


def differences(real: Any, engine: Any, translate: Callable[[str], str]) -> list[str]:
    """Top-level settings whose values differ (real translated into engine ids; clocks and checksums left out)."""
    if not isinstance(real, dict) or not isinstance(engine, dict):
        return [] if _norm(real, translate) == _norm(engine, translate) else ['the answer']
    out = []
    for key in sorted(set(real) | set(engine)):
        if NOISE_KEY.search(key):
            continue
        if _norm(real.get(key), translate) != _norm(engine.get(key), lambda s: s):
            out.append(key)
    return out


def _norm(value: Any, translate: Callable[[str], str]) -> Any:
    if isinstance(value, dict):
        out = {k: _norm(v, translate) for k, v in value.items() if not NOISE_KEY.search(k)}
        return {k: v for k, v in out.items() if v not in (None, '', [], {})}
    if isinstance(value, list):
        return [_norm(v, translate) for v in value]
    if isinstance(value, str):
        return translate(value)
    if isinstance(value, datetime.datetime):
        return None
    return value
