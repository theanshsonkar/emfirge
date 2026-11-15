"""The reference index: which resource names which, found in the account's own settings, with the evidence.

"A names B" when a string in A's state contains an identifier of B. The identifiers of B come from B alone: its id,
the last part of a path-shaped id, and addresses or opaque ids that sit in B's own plain fields and name
nothing else (a distribution's host name, a role's generated id). No code knows any resource type.

How sure a link is (Strength):
  STRONG  the whole value is B's address, opaque id or owned name; or B's id is a whole token inside an address
          ('urn:...:store/media/*', 'media.store.example.net'); or an exact address or opaque id of B in any text
  TEXT    B's id as a whole word inside longer free text (a line of a start-up script); only ids that are not a
          plain word (they hold a digit, '-', '_' or '.'), so a resource called 'default' is not found in every comment
  WEAK    a bare name equal to the whole value (an environment variable 'my-bucket': a name, but of what?); a pattern
          that matches B ('my-*'); a catch-all '*' whose sibling patterns cover B's type ('store:*' beside '*')

A name that several resources share ('default') does not say which one is meant: such a match is WEAK.

A resource that a large share of the account names (the region in every address, the account itself) is ambient:
context, not a dependency. Its edges are kept apart and no chain goes through it (Vocabulary.ambient_*).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Iterable, Mapping

from emfirge.core.model import ResourceRef

from .keys import Key, KeyKind, KeyTable, Span, alias_of, bare
from .unpack import Leaf, leaves
from .vocabulary import Vocabulary

_SNIPPET = 40          # characters of context on each side of a match, for the evidence
_MIN_LITERAL = 3       # a pattern needs this many literal characters to name anything


class Strength(IntEnum):
    WEAK = 1
    TEXT = 2
    STRONG = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Edge:
    """source names target. how: exact | address | text | name | pattern | catch-all."""
    source: ResourceRef
    target: ResourceRef
    strength: Strength
    how: str
    path: str
    snippet: str


class ReferenceIndex:
    """Edges between resources of one account state. Build once per state (before, after) and ask it questions."""

    def __init__(self, edges: Iterable[Edge], refs: Iterable[ResourceRef], leaves_by_ref: Mapping[ResourceRef, list[Leaf]],
                 ambient: frozenset[ResourceRef] = frozenset()) -> None:
        self.refs = frozenset(refs)
        self.ambient = ambient
        self._leaves = dict(leaves_by_ref)
        self._out: dict[ResourceRef, list[Edge]] = {}
        self._in: dict[ResourceRef, list[Edge]] = {}
        for e in edges:
            if e.target not in ambient:
                self._out.setdefault(e.source, []).append(e)
                self._in.setdefault(e.target, []).append(e)

    @classmethod
    def build(cls, states: Mapping[ResourceRef, Any], vocabulary: Vocabulary,
              ghosts: Mapping[ResourceRef, Any] | None = None) -> 'ReferenceIndex':
        """ghosts: resources that are gone in this state but whose identifiers must still be found (a deleted
        bucket: who still names it?). They give identifiers and no edges."""
        ghosts = {r: s for r, s in (ghosts or {}).items() if r not in states}
        found = {r: list(leaves(s, vocabulary.has_wildcard)) for r, s in {**states, **ghosts}.items()}
        table = _key_table(found, vocabulary)
        matcher = _Matcher(table, vocabulary, {r.type for r in found}, list(found))
        edges = _dedupe([e for ref in states for leaf in found[ref] for e in matcher.edges(ref, leaf)])
        return cls(edges, states, {r: found[r] for r in states}, _ambient(edges, vocabulary))

    def names(self, ref: ResourceRef) -> list[Edge]:
        """What ref names (outgoing edges)."""
        return self._out.get(ref, [])

    def named_by(self, ref: ResourceRef) -> list[Edge]:
        """Who names ref (incoming edges)."""
        return self._in.get(ref, [])

    def leaf_at(self, ref: ResourceRef, path: str) -> str | None:
        return next((leaf.text for leaf in self._leaves.get(ref, []) if leaf.path == path), None)

    def edge_count(self) -> int:
        return sum(len(v) for v in self._out.values())


def _key_table(found: Mapping[ResourceRef, list[Leaf]], vocabulary: Vocabulary) -> KeyTable:
    table = KeyTable(vocabulary.max_key_words)
    for ref in found:
        table.add(Key(ref, KeyKind.ID, ref.id))
        alias = alias_of(ref.id, vocabulary.min_text_length)
        if alias and not vocabulary.is_opaque(bare(ref.id)):
            table.add(Key(ref, KeyKind.ALIAS, alias))
    for ref, value in _owned(found, table, vocabulary):
        table.add(Key(ref, KeyKind.OWNED, value))
    return table


def _owned(found: Mapping[ResourceRef, list[Leaf]], table: KeyTable, vocabulary: Vocabulary) -> list[tuple[ResourceRef, str]]:
    """Addresses and opaque ids in a resource's own plain fields that name nothing else, as (owner, value).
    A value claimed by several resources belongs to the one whose own id appears in it, else to nobody: a value
    many resources carry (a shared runtime id, the account's id) is nobody's name."""
    claims: dict[str, set[ResourceRef]] = {}
    for ref, items in found.items():
        for leaf in items:
            value = bare(leaf.text)
            if not leaf.own or not value or value == bare(ref.id) or not vocabulary.is_exact_shape(leaf.text.strip()):
                continue
            if {k.ref for span in table.spans(leaf.text) for k in span.keys} - {ref}:
                continue                      # it holds another resource's identifier: a pointer, not a name
            claims.setdefault(value, set()).add(ref)
    pairs = []
    for value, refs in claims.items():
        if len(refs) > 1:
            refs = refs & {k.ref for span in table.spans(value) for k in span.keys}
        if len(refs) == 1:
            pairs.append((next(iter(refs)), value))
    return pairs


class _Matcher:
    """Turns one string of one resource into edges."""

    def __init__(self, table: KeyTable, vocabulary: Vocabulary, types: set[str], refs: list[ResourceRef]) -> None:
        self._table = table
        self._vocab = vocabulary
        self._refs_by_type: dict[str, list[ResourceRef]] = {}
        for r in refs:
            self._refs_by_type.setdefault(r.type, []).append(r)
        self._types = sorted(types)
        self._texts = table.texts()
        wild = re.escape(vocabulary.wildcards)
        self._pattern_token = re.compile(f'[A-Za-z0-9_\\-{wild}]+')
        self._pattern_cache: dict[str, list[str]] = {}

    def edges(self, source: ResourceRef, leaf: Leaf) -> list[Edge]:
        text = leaf.text.strip()
        if not text:
            return []
        if self._vocab.is_catch_all(text):
            return self._catch_all(source, leaf)
        out = [e for span in self._table.spans(leaf.text) for e in self._span_edges(source, leaf, span)]
        if self._vocab.has_wildcard(text):
            named = {e.target for e in out}
            out += [e for e in self._pattern_edges(source, leaf) if e.target not in named]
        return out

    def _span_edges(self, source: ResourceRef, leaf: Leaf, span: Span) -> list[Edge]:
        whole = bare(leaf.text) == leaf.text[span.start:span.end]
        shared = len({k.ref for k in span.keys}) > 1
        out = []
        for key in span.keys:
            if key.ref == source:
                continue
            judged = self._judge(key, whole, leaf.text.strip())
            if judged and shared:
                judged = Strength.WEAK, f'{judged[1]}, a name several resources share'
            if judged:
                out.append(Edge(source, key.ref, judged[0], judged[1], leaf.path, _snippet(leaf.text, span.start, span.end)))
        return out

    def _judge(self, key: Key, whole: bool, text: str) -> tuple[Strength, str] | None:
        exact_shape = key.kind is KeyKind.OWNED or self._vocab.is_exact_shape(bare(key.text))
        if whole:
            if exact_shape:
                return Strength.STRONG, 'exact'
            return (Strength.WEAK, 'name') if len(bare(key.text)) >= self._vocab.min_name_length else None
        if exact_shape:
            return Strength.STRONG, 'exact'
        if self._vocab.is_address(text):
            return Strength.STRONG, 'address'
        word = bare(key.text)
        return (Strength.TEXT, 'text') if len(word) >= self._vocab.min_text_length and not word.isalpha() else None

    def _pattern_edges(self, source: ResourceRef, leaf: Leaf) -> list[Edge]:
        out = []
        for m in self._pattern_token.finditer(leaf.text):
            token = m.group()
            if not self._vocab.has_wildcard(token) or len(re.sub(f'[{re.escape(self._vocab.wildcards)}]', '', token)) < _MIN_LITERAL:
                continue
            for text in self._matching_texts(token):
                for key in self._table.keys_for(text):
                    if key.ref != source:
                        out.append(Edge(source, key.ref, Strength.WEAK, 'pattern', leaf.path, _snippet(leaf.text, m.start(), m.end())))
        return out

    def _matching_texts(self, token: str) -> list[str]:
        if token not in self._pattern_cache:
            rx = re.compile(fnmatch.translate(token))
            self._pattern_cache[token] = [t for t in self._texts if rx.match(t)]
        return self._pattern_cache[token]

    def _catch_all(self, source: ResourceRef, leaf: Leaf) -> list[Edge]:
        """'*' covers everything; the patterns beside it ('store:*') say of which types. Without them: nothing."""
        scopes = [p for p in leaf.scope if not self._vocab.is_catch_all(p)]
        types = [t for t in self._types if any(fnmatch.fnmatchcase(t, p) for p in scopes)]
        return [Edge(source, r, Strength.WEAK, 'catch-all', leaf.path, f'{leaf.text} beside {", ".join(scopes)[:80]}')
                for t in types for r in self._refs_by_type[t] if r != source]


def _ambient(edges: list[Edge], vocabulary: Vocabulary) -> frozenset[ResourceRef]:
    """Targets named by so many resources that being named by them says nothing (see the module notes)."""
    sources: dict[ResourceRef, set[ResourceRef]] = {}
    for e in edges:
        sources.setdefault(e.target, set()).add(e.source)
    naming = len({e.source for e in edges})
    floor = max(vocabulary.ambient_min, vocabulary.ambient_share * naming)
    return frozenset(t for t, s in sources.items() if len(s) >= floor)


def _snippet(text: str, start: int, end: int) -> str:
    left, right = max(0, start - _SNIPPET), min(len(text), end + _SNIPPET)
    return ('...' if left else '') + ' '.join(text[left:right].split()) + ('...' if right < len(text) else '')


def _dedupe(edges: list[Edge]) -> list[Edge]:
    """One edge per (source, target, path): the strongest reading of that string."""
    best: dict[tuple[ResourceRef, ResourceRef, str], Edge] = {}
    for e in edges:
        k = (e.source, e.target, e.path)
        if k not in best or e.strength > best[k].strength:
            best[k] = e
    return list(best.values())
