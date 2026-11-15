"""The reference index: which resource names which, found in the account's own settings, with the evidence.

"A names B" when a string in A's state contains an identifier of B. The identifiers of B come from B alone: its id,
the last part of a path-shaped id, and addresses or opaque ids that sit in B's own plain fields (B's own name).

B's own name. An address or generated id in a plain field of B is B's own when it names nothing else. Three
refinements, each true of any provider:
  * Words that occur in the own addresses of many resources (the region, the account) are context, not a pointer:
    they do not make an address someone else's.
  * A provider may add a short random suffix to an id inside its own address ('db-password-a1B2c3'). In a field whose
    key says it identifies ('Id', 'Name', 'Uri', ...), an address holding the id so suffixed is still the resource's.
  * A host or address that is part of OTHER resources' own addresses (a shared endpoint) is nobody's name.
Two resources where one's id is the other's own name (a role listed again under its internal id, a function under its
full address) are one resource: the duplicate is folded into the owner, everywhere.

How sure a link is (Strength):
  STRONG  the whole value is B's address, opaque id or own name; B's id is a whole token inside an address
          ('urn:...:store/media/*', 'media.store.example.net'); an exact address or opaque id of B in any text; or a
          bare name of B that is unique in the account and either has an inner separator ('alias/x', '/a/b') or sits
          under a label that names B's type (a 'QueueName' key or name/value pair holding a queue's name)
  TEXT    B's id as a whole word inside longer free text (a line of a start-up script); only ids that are not a plain
          word (they hold a digit, '-', '_' or '.'), so a resource called 'default' is not found in every comment
  WEAK    any other bare name equal to the whole value (an environment variable 'my-bucket': a name, but of what?);
          a pattern that matches B ('my-*'); a catch-all '*' whose sibling patterns cover B's type ('store:*')
A name that several resources share ('default') does not say which one is meant: such a match is WEAK.

A resource that a large share of the account names (the region in every address, the account itself) is ambient:
context, not a dependency. Its edges are kept apart and no chain goes through it (Vocabulary.ambient_*).

The index of the state after a change is built from the index before (ReferenceIndex.with_changes): only changed
resources and strings that hold a new identifier are read again.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Collection, Iterable, Mapping

from emfirge.core.model import ResourceRef

from .keys import Key, KeyKind, KeyTable, Span, alias_of, bare
from .unpack import Leaf, leaves
from .vocabulary import Vocabulary
from .words import label_names_type

_SNIPPET = 40          # characters of context on each side of a match, for the evidence
_MIN_LITERAL = 3       # a pattern needs this many literal characters to name anything
_NAME_CHARS = re.compile(r'[A-Za-z0-9_-]')


class Strength(IntEnum):
    WEAK = 1
    TEXT = 2
    STRONG = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Edge:
    """source names target. how: exact | address | text | name | typed name | pattern | catch-all."""
    source: ResourceRef
    target: ResourceRef
    strength: Strength
    how: str
    path: str
    snippet: str


class ReferenceIndex:
    """Edges between resources of one account state. Build once per state and ask it questions."""

    def __init__(self, vocabulary: Vocabulary, found: Mapping[ResourceRef, list[Leaf]], sources: frozenset[ResourceRef],
                 table: KeyTable, by_source: Mapping[ResourceRef, list[Edge]], canonical: Mapping[ResourceRef, ResourceRef]) -> None:
        self._vocab = vocabulary
        self._found = found
        self._sources = sources
        self._table = table
        self._by_source = by_source
        self._canonical = canonical
        edges = [e for es in by_source.values() for e in es]
        self.ambient = _ambient(edges, vocabulary)
        self.refs = frozenset(canonical.get(r, r) for r in sources)
        self._out: dict[ResourceRef, list[Edge]] = {}
        self._in: dict[ResourceRef, list[Edge]] = {}
        for e in edges:
            if e.target not in self.ambient:
                self._out.setdefault(e.source, []).append(e)
                self._in.setdefault(e.target, []).append(e)

    @classmethod
    def build(cls, states: Mapping[ResourceRef, Any], vocabulary: Vocabulary,
              ghosts: Mapping[ResourceRef, Any] | None = None) -> 'ReferenceIndex':
        """ghosts: resources that are gone in this state but whose identifiers must still be found (a deleted
        bucket: who still names it?). They give identifiers and no edges."""
        ghosts = {r: s for r, s in (ghosts or {}).items() if r not in states}
        found = {r: list(leaves(s, vocabulary.has_wildcard)) for r, s in {**states, **ghosts}.items()}
        return _assemble(vocabulary, found, frozenset(states))

    def with_changes(self, changed: Mapping[ResourceRef, Any], gone: Collection[ResourceRef]) -> 'ReferenceIndex':
        """The index of the state after: changed (created or modified) resources take their new state; gone ones stay
        as ghosts. Strings of unchanged resources are read again only where they may hold a new identifier."""
        found = dict(self._found)
        found.update({r: list(leaves(s, self._vocab.has_wildcard)) for r, s in changed.items()})
        sources = (self._sources - frozenset(gone)) | frozenset(r for r in changed if r not in gone)
        return _assemble(self._vocab, found, sources, previous=self, changed=frozenset(changed))

    def canonical(self, ref: ResourceRef) -> ResourceRef:
        """The resource ref stands for (itself, unless it is a duplicate of another)."""
        return self._canonical.get(ref, ref)

    def names(self, ref: ResourceRef) -> list[Edge]:
        """What ref names (outgoing edges)."""
        return self._out.get(self.canonical(ref), [])

    def named_by(self, ref: ResourceRef) -> list[Edge]:
        """Who names ref (incoming edges)."""
        return self._in.get(self.canonical(ref), [])

    def leaf_at(self, ref: ResourceRef, path: str) -> str | None:
        return next((leaf.text for leaf in self._found.get(ref, []) if leaf.path == path), None)

    def edge_count(self) -> int:
        return sum(len(v) for v in self._out.values())


def _assemble(vocabulary: Vocabulary, found: Mapping[ResourceRef, list[Leaf]], sources: frozenset[ResourceRef],
              previous: ReferenceIndex | None = None, changed: frozenset[ResourceRef] = frozenset()) -> ReferenceIndex:
    table = _key_table(found, vocabulary)
    canonical = _fold(table)
    matcher = _Matcher(table, vocabulary, found, canonical)
    by_source: dict[ResourceRef, list[Edge]] = {}
    fresh = _new_texts(table, previous)
    for src in sources:
        if previous is None or src in changed or src not in previous._by_source:
            by_source[src] = _scan(matcher, src, found[src])
            continue
        again = [leaf for leaf in found[src] if fresh is not None and (fresh.search(leaf.text) or vocabulary.has_wildcard(leaf.text))]
        paths = {leaf.path for leaf in again}
        kept = [e for e in previous._by_source[src] if e.path not in paths]
        by_source[src] = kept + _scan(matcher, src, again) if again else kept
    merged: dict[ResourceRef, list[Edge]] = {}
    for src, edges in by_source.items():
        merged.setdefault(canonical.get(src, src), []).extend(edges)
    return ReferenceIndex(vocabulary, found, sources, table, {s: _dedupe(es) for s, es in merged.items()}, canonical)


def _new_texts(table: KeyTable, previous: ReferenceIndex | None) -> re.Pattern[str] | None:
    """A pattern for identifiers that the previous index did not have (None: nothing new to look for)."""
    if previous is None:
        return None
    new = set(table.texts()) - set(previous._table.texts())
    return re.compile('|'.join(re.escape(t) for t in sorted(new, key=len, reverse=True))) if new else None


def _scan(matcher: '_Matcher', source: ResourceRef, items: Iterable[Leaf]) -> list[Edge]:
    return [e for leaf in items for e in matcher.edges(source, leaf)]


def _key_table(found: Mapping[ResourceRef, list[Leaf]], vocabulary: Vocabulary) -> KeyTable:
    table = KeyTable(vocabulary.max_key_words)
    for ref in found:
        table.add(Key(ref, KeyKind.ID, ref.id))
        alias = alias_of(ref.id, vocabulary.min_text_length)
        if alias and not vocabulary.is_opaque(bare(ref.id)):
            table.add(Key(ref, KeyKind.ALIAS, alias))
    for ref, value in _Owner(found, table, vocabulary).owned():
        table.add(Key(ref, KeyKind.OWNED, value))
    return table


@dataclass(frozen=True)
class _Claim:
    ref: ResourceRef
    leaf: Leaf
    value: str
    spans: tuple[Span, ...]


class _Owner:
    """Decides which addresses in resources' own fields are their own names (see the module notes)."""

    def __init__(self, found: Mapping[ResourceRef, list[Leaf]], table: KeyTable, vocabulary: Vocabulary) -> None:
        self._vocab = vocabulary
        self._table = table
        self._found = found
        self._claims = [_Claim(ref, leaf, bare(leaf.text), tuple(table.spans(leaf.text)))
                        for ref, items in found.items() for leaf in items if self._may_claim(ref, leaf)]
        self._context = self._address_context()

    def owned(self) -> list[tuple[ResourceRef, str]]:
        owners: dict[str, set[ResourceRef]] = {}
        for c in self._claims:
            if not self._foreign(c) or (self._identifying(c.leaf) and self._holds_id(c.ref, c.value)):
                owners.setdefault(c.value, set()).add(c.ref)
        pairs = []
        for value, refs in owners.items():
            if len(refs) > 1:
                refs = {r for r in refs if self._holds_id(r, value)}
            if len(refs) == 1:
                pairs.append((next(iter(refs)), value))
        return self._not_shared(pairs)

    def _may_claim(self, ref: ResourceRef, leaf: Leaf) -> bool:
        text = leaf.text.strip()
        return leaf.own and bool(bare(text)) and bare(text) != bare(ref.id) and self._vocab.is_exact_shape(text)

    def _address_context(self) -> frozenset[ResourceRef]:
        """Resources whose identifiers sit in the own addresses of many resources: the region, the account."""
        claimants: dict[ResourceRef, set[ResourceRef]] = {}
        for c in self._claims:
            for r in {k.ref for span in c.spans for k in span.keys} - {c.ref}:
                claimants.setdefault(r, set()).add(c.ref)
        total = len({c.ref for c in self._claims})
        floor = max(self._vocab.ambient_min, self._vocab.ambient_share * total)
        return frozenset(r for r, who in claimants.items() if len(who) >= floor)

    def _foreign(self, c: _Claim) -> set[ResourceRef]:
        """Other resources named inside the claim. Not foreign: a span that is also the claimant's own id; context
        (region, account); and a resource whose id is the whole claim and that names the claimant back (the same
        resource listed twice, under its name and under its internal id)."""
        named = {k.ref for span in c.spans if all(k.ref != c.ref for k in span.keys) for k in span.keys} - self._context
        whole = {k.ref for span in c.spans if span.end - span.start == len(c.leaf.text.strip()) for k in span.keys}
        return {r for r in named if not (r in whole and self._same_resource(r, c))}

    def _same_resource(self, dup: ResourceRef, c: _Claim) -> bool:
        """dup's id is the whole claim: one resource under two ids when dup names the claimant back and the field's
        label does not name dup's kind instead of the claimant's ('InstanceId' on a network card is a pointer)."""
        generic = self._vocab.generic_words
        if label_names_type(c.leaf.labels[:1], dup.type, generic) and not label_names_type(c.leaf.labels[:1], c.ref.type, generic):
            return False
        ident = bare(c.ref.id)
        return any(bare(leaf.text) == ident for leaf in self._found.get(dup, []))

    def _identifying(self, leaf: Leaf) -> bool:
        return bool(leaf.labels) and bool(self._vocab.identifying_key.search(leaf.labels[0]))

    def _holds_id(self, ref: ResourceRef, value: str) -> bool:
        """The id is in the value as a whole token, or with a short suffix the provider added ('name-a1B2c3')."""
        ident = re.escape(bare(ref.id))
        return bool(ident) and bool(re.search(f'(?<![A-Za-z0-9_-]){ident}(-[A-Za-z0-9]{{1,{self._vocab.max_suffix}}})?(?![A-Za-z0-9_-])', value))

    def _not_shared(self, pairs: list[tuple[ResourceRef, str]]) -> list[tuple[ResourceRef, str]]:
        """Drop a value that is part of other resources' own addresses: a shared endpoint is nobody's name."""
        if not pairs:
            return pairs
        candidates = KeyTable(self._vocab.max_key_words)
        for ref, value in pairs:
            candidates.add(Key(ref, KeyKind.OWNED, value))
        shared = {k.text for c in self._claims for span in candidates.spans(c.value, resolve=False)
                  for k in span.keys if k.ref != c.ref and (span.end - span.start) < len(c.value)}
        return [(r, v) for r, v in pairs if v not in shared]


def _fold(table: KeyTable) -> dict[ResourceRef, ResourceRef]:
    """Duplicate -> owner: a resource whose id is another resource's own name, in the same service."""
    canonical: dict[ResourceRef, ResourceRef] = {}
    for _, keys in table.items():
        owners = {k.ref for k in keys if k.kind is KeyKind.OWNED}
        if len(owners) != 1:
            continue
        owner = next(iter(owners))
        for k in keys:
            if k.kind is KeyKind.ID and k.ref != owner and _service(k.ref) == _service(owner):
                canonical[k.ref] = owner
    return canonical


def _service(ref: ResourceRef) -> str:
    return ref.type.split(':', 1)[0]


class _Matcher:
    """Turns one string of one resource into edges, in terms of canonical resources."""

    def __init__(self, table: KeyTable, vocabulary: Vocabulary, found: Mapping[ResourceRef, list[Leaf]],
                 canonical: Mapping[ResourceRef, ResourceRef]) -> None:
        self._table = table
        self._vocab = vocabulary
        self._canonical = canonical
        self._refs_by_type: dict[str, set[ResourceRef]] = {}
        for r in found:
            c = canonical.get(r, r)
            self._refs_by_type.setdefault(c.type, set()).add(c)
        self._types = sorted(self._refs_by_type)
        self._texts = table.texts()
        wild = re.escape(vocabulary.wildcards)
        self._pattern_token = re.compile(f'[A-Za-z0-9_\\-{wild}]+')
        self._pattern_cache: dict[str, list[str]] = {}

    def _c(self, ref: ResourceRef) -> ResourceRef:
        return self._canonical.get(ref, ref)

    def edges(self, source: ResourceRef, leaf: Leaf) -> list[Edge]:
        text = leaf.text.strip()
        if not text:
            return []
        source = self._c(source)
        if self._vocab.is_catch_all(text):
            return self._catch_all(source, leaf)
        out = [e for span in self._table.spans(leaf.text) for e in self._span_edges(source, leaf, span)]
        if self._vocab.has_wildcard(text):
            named = {e.target for e in out}
            out += [e for e in self._pattern_edges(source, leaf) if e.target not in named]
        return out

    def _span_edges(self, source: ResourceRef, leaf: Leaf, span: Span) -> list[Edge]:
        whole = bare(leaf.text) == leaf.text[span.start:span.end]
        best: dict[ResourceRef, Key] = {}
        for key in span.keys:
            target = self._c(key.ref)
            if target != source and (target not in best or key.kind is KeyKind.OWNED):
                best[target] = key
        shared = len(best) > 1 or len({self._c(k.ref) for k in span.keys}) > 1
        out = []
        for target, key in best.items():
            judged = self._judge(key, target, whole, leaf, shared)
            if judged and shared:
                judged = Strength.WEAK, f'{judged[1]}, a name several resources share'
            if judged:
                out.append(Edge(source, target, judged[0], judged[1], leaf.path, _snippet(leaf.text, span.start, span.end)))
        return out

    def _judge(self, key: Key, target: ResourceRef, whole: bool, leaf: Leaf, shared: bool) -> tuple[Strength, str] | None:
        word = bare(key.text)
        exact_shape = key.kind is KeyKind.OWNED or self._vocab.is_exact_shape(word)
        if exact_shape:
            return Strength.STRONG, 'exact'
        if whole:
            if len(word) < self._vocab.min_name_length:
                return None
            if not shared and (_NAME_CHARS.sub('', word) or label_names_type(leaf.labels, target.type, self._vocab.generic_words)):
                return Strength.STRONG, 'typed name'
            return Strength.WEAK, 'name'
        if self._vocab.is_address(leaf.text.strip()):
            return Strength.STRONG, 'address'
        return (Strength.TEXT, 'text') if len(word) >= self._vocab.min_text_length and not word.isalpha() else None

    def _pattern_edges(self, source: ResourceRef, leaf: Leaf) -> list[Edge]:
        out = []
        for m in self._pattern_token.finditer(leaf.text):
            token = m.group()
            if not self._vocab.has_wildcard(token) or len(re.sub(f'[{re.escape(self._vocab.wildcards)}]', '', token)) < _MIN_LITERAL:
                continue
            for text in self._matching_texts(token):
                for key in self._table.keys_for(text):
                    target = self._c(key.ref)
                    if target != source:
                        out.append(Edge(source, target, Strength.WEAK, 'pattern', leaf.path, _snippet(leaf.text, m.start(), m.end())))
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
                for t in types for r in sorted(self._refs_by_type[t], key=str) if r != source]


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
