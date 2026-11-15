"""The identifiers of every resource, and finding them inside strings as whole tokens.

A match must be a whole token: 'media-files' is found in 'urn:...:store/media-files/*' and in
'copy store://media-files/in /srv', but not in 'media-files-backup'. Words are runs of letters, digits, '-' and '_';
everything else separates words. An identifier may span several words ('/logs/jobs/fn', 'feeds.example.org'), so
candidate spans start at a word that begins some identifier and are looked up by exact text: no scan per identifier.
Where spans overlap, the longest wins: inside 'log-group:/logs/jobs/fn' the log group is named, not the function.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from emfirge.core.model import ResourceRef

_NAME_CHARS = 'A-Za-z0-9_-'
_WORD = re.compile(f'[{_NAME_CHARS}]+')
_HARD = re.compile(r'[\s"\'`,;()\[\]{}<>|\\]+')       # never inside an identifier: a span stops here
_EDGES = re.compile(f'^[^{_NAME_CHARS}]+|[^{_NAME_CHARS}]+$')
_ALIAS_SEPARATORS = '/:'                               # 'path/name', 'prefix:name': the last part is a name too


class KeyKind(str, Enum):
    ID = 'id'          # the resource's id as given
    ALIAS = 'alias'    # the last part of a path-shaped id ('.../queue-url/jobs' -> 'jobs')
    OWNED = 'owned'    # an address or opaque id in the resource's own fields that names nothing else (its host name)


@dataclass(frozen=True)
class Key:
    ref: ResourceRef
    kind: KeyKind
    text: str


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    keys: tuple[Key, ...]


def bare(text: str) -> str:
    """The text without separators at its ends: '/logs/x' and 'host.example.' are looked up as 'logs/x', 'host.example'."""
    return _EDGES.sub('', text)


def alias_of(ident: str, min_length: int) -> str | None:
    """The last part of an id shaped like a path ('/' or ':' separated), when it is long enough to be a name."""
    b = bare(ident)
    cut = max(b.rfind(c) for c in _ALIAS_SEPARATORS)
    last = b[cut + 1:]
    if cut < 0 or len(last) < min_length or not _WORD.fullmatch(last):
        return None
    return last


class KeyTable:
    """Identifier text -> the resources it names. An id beats an alias of the same text."""

    def __init__(self, max_words: int) -> None:
        self._max_words = max_words
        self._by_text: dict[str, list[Key]] = {}
        self._lengths: dict[str, set[int]] = {}      # first word -> lengths (in words) of identifiers starting with it
        self._spaced: dict[str, list[Key]] = {}      # identifiers that contain a hard separator: whole-value only

    def add(self, key: Key) -> None:
        text = bare(key.text)
        if not text:
            return
        if _HARD.search(text):
            self._spaced.setdefault(text, []).append(key)
            return
        words = _WORD.findall(text)
        if len(words) > self._max_words:
            self._spaced.setdefault(text, []).append(key)
            return
        bucket = self._by_text.setdefault(text, [])
        if key not in bucket:
            bucket.append(key)
        self._lengths.setdefault(words[0], set()).add(len(words))

    def texts(self) -> list[str]:
        return list(self._by_text)

    def keys_for(self, text: str) -> tuple[Key, ...]:
        found = self._by_text.get(text) or self._spaced.get(text) or []
        if any(k.kind is KeyKind.ID for k in found):
            found = [k for k in found if k.kind is not KeyKind.ALIAS]
        return tuple(found)

    def spans(self, text: str) -> list[Span]:
        """Every identifier found in text as whole tokens, overlaps resolved longest first."""
        whole = bare(text)
        if whole in self._spaced:
            return [Span(text.find(whole), text.find(whole) + len(whole), self.keys_for(whole))]
        found: list[Span] = []
        for start, end in _chunks(text):
            words = [(m.start(), m.end()) for m in _WORD.finditer(text, start, end)]
            for i, (ws, we) in enumerate(words):
                lengths = self._lengths.get(text[ws:we])
                if not lengths:
                    continue
                for n in lengths:
                    if i + n <= len(words):
                        cand = text[ws:words[i + n - 1][1]]
                        if cand in self._by_text:
                            found.append(Span(ws, words[i + n - 1][1], self.keys_for(cand)))
        return _longest_first(found)


def _chunks(text: str) -> list[tuple[int, int]]:
    """The stretches of text between hard separators."""
    out, pos = [], 0
    for m in _HARD.finditer(text):
        if m.start() > pos:
            out.append((pos, m.start()))
        pos = m.end()
    if pos < len(text):
        out.append((pos, len(text)))
    return out


def _longest_first(spans: list[Span]) -> list[Span]:
    kept: list[Span] = []
    for span in sorted(spans, key=lambda s: (s.start - s.end, s.start)):
        if all(span.end <= k.start or span.start >= k.end for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: s.start)
