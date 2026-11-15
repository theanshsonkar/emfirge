"""What identifiers look like in one cloud. Data, handed in by the cloud plug-in; the graph itself knows no cloud.

The graph finds links by looking for one resource's identifiers in another resource's settings. To judge how sure a
match is, it needs to know which strings are addresses (a qualified resource name, a URL, a host name) and which are opaque ids
(a generated key such as 'i-0abc...'): an exact address or opaque id is strong evidence, a bare short name is not.
Those shapes differ per cloud, so they come in here as regular expressions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Vocabulary:
    """address_patterns  strings that are an address of something (matched against the whole string)
    opaque_patterns      strings that are a generated id (matched against the whole string)
    min_name_length      a bare name shorter than this is never matched as a whole value (too many collisions)
    min_text_length      an id shorter than this is never matched inside longer text
    max_key_words        the longest identifier, in words, that is looked for inside a string
    wildcards            characters that make a string a pattern rather than a name
    ambient_share        a resource named by at least this share of all resources that name anything ...
    ambient_min          ... and by at least this many, is context (a region, the account), not a dependency"""
    address_patterns: tuple[re.Pattern[str], ...] = ()
    opaque_patterns: tuple[re.Pattern[str], ...] = ()
    min_name_length: int = 4
    min_text_length: int = 6
    max_key_words: int = 16
    wildcards: str = '*?'
    ambient_share: float = 0.2
    ambient_min: int = 25
    _wild: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_wild', re.compile('[' + re.escape(self.wildcards) + ']'))

    @classmethod
    def of(cls, addresses: Iterable[str], opaque: Iterable[str], **settings: float) -> 'Vocabulary':
        """Build from plain regular-expression strings (how a plug-in keeps them: as data)."""
        return cls(tuple(re.compile(p) for p in addresses), tuple(re.compile(p) for p in opaque), **settings)

    def is_address(self, text: str) -> bool:
        return any(p.fullmatch(text) for p in self.address_patterns)

    def is_opaque(self, text: str) -> bool:
        return any(p.fullmatch(text) for p in self.opaque_patterns)

    def is_exact_shape(self, text: str) -> bool:
        """An address or an opaque id: a string that names one thing, so an exact match on it is strong."""
        return self.is_address(text) or self.is_opaque(text)

    def has_wildcard(self, text: str) -> bool:
        return bool(self._wild.search(text))

    def is_catch_all(self, text: str) -> bool:
        """A pattern with no literal part ('*'): it names nothing in particular, only 'everything'."""
        return bool(text) and not self._wild.sub('', text)
