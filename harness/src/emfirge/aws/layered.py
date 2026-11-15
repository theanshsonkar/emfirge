"""The generic catalog and copier first, the hand-written (curated) ones only where the generic ones do not know.

LayeredCatalog (core.ports.Catalog)
  kind     the generic catalog's two-key answer, except calls that run the customer's own code (an operation named
           Invoke... or TestInvoke..., or an action in data/runs_code.json): UNKNOWN, so the branch refuses them.
  refs     the generic catalog's refs, with data held inside a container (an object in a bucket: a type whose parent
           holds data and that holds data itself) placed on its container, as the container is what is copied. Where
           it cannot place a changing call and the curated naming can, the curated
           primary is used; resources only the curated naming finds (a copy source bucket, a group id inside a rule)
           are added as mentioned. Both use one vocabulary: the generic catalog's types and ids.
  reads    the curated reads first where a curated type has them (they name the resource the way agents do, and the
           first one tells whether it exists), then the generic reads, then the list reads that can show the type.
           For other types the read named after the type comes first.
  `fallbacks` counts each use of the curated layer, so its cost can be measured.

LayeredCopier (core.ports.Copier)
  Tries copiers in order for each type. When one refuses (CannotTell) having written nothing to the engine, the next
  one tries. The order per type is data (data/copier_order.json), written from experiment 23's measurement.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from emfirge.core.model import Call, Kind, Refs, ResourceRef, WireRequest, WireResponse
from emfirge.core.ports import Account, CannotTell, Catalog, Copier, CopyResult, Placement

from .catalog import AwsCatalog, ResourceTypeInfo
from .catalog.store import DATA
from .codec import AwsCodec
from .outcomes_generic import list_ops
from .resource_words import noun_of, type_word, verb_of

CODE_VERBS = ('Invoke', 'TestInvoke')


def runs_code_actions(path: Path | None = None) -> frozenset[str]:
    """The IAM actions data/runs_code.json lists."""
    raw = json.loads((path or DATA / 'runs_code.json').read_text())
    return frozenset(e['action'] for e in raw['actions'])


class LayeredCatalog:
    def __init__(self, generic: AwsCatalog, codec: AwsCodec, curated: Catalog | None = None,
                 runs_code: frozenset[str] | None = None) -> None:
        self._generic, self._codec, self._curated = generic, codec, curated
        self._runs_code = runs_code_actions() if runs_code is None else runs_code
        self.fallbacks: Counter[str] = Counter()

    # ---------------------------------------------------------------- kinds
    def kind(self, service: str, operation: str) -> Kind:
        return Kind.UNKNOWN if self.runs_code(service, operation) else self._generic.kind(service, operation)

    def why_kind(self, service: str, operation: str) -> str:
        if self.runs_code(service, operation):
            return "this call runs the customer's own code, and what that code changes cannot be told from the call."
        return self._generic.why_kind(service, operation)

    def runs_code(self, service: str, operation: str) -> bool:
        return operation.startswith(CODE_VERBS) or self._generic.action(service, operation) in self._runs_code

    # ---------------------------------------------------------------- refs
    def refs(self, call: Call) -> Refs:
        mine = self._contents_on_containers(self._generic.refs(call))
        if self._curated is None:
            return mine
        theirs = self._curated.refs(call)
        primary, complete = mine.primary, mine.complete
        if not mine.complete and theirs.complete and theirs.primary and not self.kind(call.service, call.operation).reads_only:
            primary, complete = theirs.primary, True
            self.fallbacks['refs: placed by the curated naming'] += 1
        extra = tuple(r for r in theirs.all if r not in primary and r not in mine.mentioned)
        if extra:
            self.fallbacks['refs: named only by the curated naming'] += 1
        mentioned = tuple(r for r in mine.all if r not in primary) + extra
        return Refs(primary, mentioned, complete)

    def _contents_on_containers(self, refs: Refs) -> Refs:
        moved = [self._container(r, refs.mentioned) for r in refs.primary]
        if all(m is None for m in moved):
            return refs
        primary = tuple(dict.fromkeys(m or r for r, m in zip(refs.primary, moved)))
        return Refs(primary, tuple(r for r in refs.mentioned if r not in primary), refs.complete)

    def _container(self, ref: ResourceRef, mentioned: tuple[ResourceRef, ...]) -> ResourceRef | None:
        info = self._generic.resource_type(ref.type)
        if info is None or not info.parent or not info.holds_data:
            return None
        return next((m for m in mentioned if m.type == info.parent and ref.id.startswith(m.id + '/')), None)

    # ---------------------------------------------------------------- reads
    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]:
        theirs = self._curated.reads_of(ref) if self._curated is not None else []
        mine = _existence_first(ref.type, self._generic.reads_of(ref))
        if theirs:
            self.fallbacks['reads: curated reads first'] += 1
        out = _unique(theirs + mine)
        services = list(dict.fromkeys(s for s, _, _ in out))
        for service in services[:1]:
            out = _unique(out + [(service, op, {}) for op in list_ops(self._codec, service, ref.type)])
        return out

    # ---------------------------------------------------------------- passed through, for outcomes and copiers
    def resource_type(self, type_: str) -> ResourceTypeInfo | None:
        return self._generic.resource_type(type_)

    def parse_arn(self, value: str) -> ResourceRef | None:
        return self._generic.parse_arn(value)

    def action(self, service: str, operation: str) -> str | None:
        return self._generic.action(service, operation)

    def types_of(self, prefix: str) -> tuple[str, ...]:
        return self._generic.types_of(prefix)


def _existence_first(type_: str, reads: list[tuple[str, str, dict[str, Any]]]) -> list[tuple[str, str, dict[str, Any]]]:
    """The read named after the type (GetHostedZone, DescribeInstances) first: the branch asks the first read whether
    the resource exists."""
    word = type_word(type_)
    named = [r for r in reads if verb_of(r[1]) in ('Get', 'Describe') and noun_of(r[1]) == word]
    return named + [r for r in reads if r not in named]


def _unique(reads: list[tuple[str, str, dict[str, Any]]]) -> list[tuple[str, str, dict[str, Any]]]:
    seen, out = set(), []
    for r in reads:
        key = (r[0], r[1], json.dumps(r[2], sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


# -------------------------------------------------------------------- copiers
def copier_order(path: Path | None = None) -> dict[str, tuple[str, ...]]:
    """type -> copier names, first to try; written from experiment 23's measurement ('*' is every other type)."""
    raw = json.loads((path or DATA / 'copier_order.json').read_text())
    return {t: tuple(names) for t, names in raw['order'].items()}


class LayeredCopier:
    def __init__(self, copiers: Mapping[str, Copier], order: Mapping[str, Sequence[str]], codec: AwsCodec,
                 kinds: Catalog) -> None:
        self._copiers, self._order, self._codec, self._kinds = dict(copiers), dict(order), codec, kinds
        self.used: Counter[str] = Counter()

    def order_of(self, type_: str) -> tuple[str, ...]:
        names = self._order.get(type_) or self._order.get('*') or tuple(self._copiers)
        return tuple(n for n in names if n in self._copiers)

    def copy(self, ref: ResourceRef, place: Placement) -> CopyResult:
        refusals = []
        for name in self.order_of(ref.type):
            watched = _Watched(place, self._codec, self._kinds)
            try:
                result = self._copiers[name].copy(ref, watched)
            except CannotTell as e:
                if watched.engine.changed:
                    raise
                refusals.append(f'{name}: {e}')
                continue
            self.used[f'{ref.type} by {name}'] += 1
            return result
        raise CannotTell('; '.join(refusals) or f'no copier for {ref.type}')


class _Counting:
    """The engine, counting the calls that change it."""

    def __init__(self, engine: Account, codec: AwsCodec, kinds: Catalog) -> None:
        self._engine, self._codec, self._kinds = engine, codec, kinds
        self.name = engine.name
        self.changed = 0

    def send(self, request: WireRequest) -> WireResponse:
        call = self._codec.decode(request)
        if call is None or not self._kinds.kind(call.service, call.operation).reads_only:
            self.changed += 1
        return self._engine.send(request)


class _Watched:
    """A Placement whose engine is watched, so a refusal can be told apart from a half-made copy."""

    def __init__(self, place: Placement, codec: AwsCodec, kinds: Catalog) -> None:
        self._place = place
        self.real = place.real
        self.engine = _Counting(place.engine, codec, kinds)

    def need(self, ref: ResourceRef) -> None:
        self._place.need(ref)

    def engine_value(self, value: str) -> str:
        return self._place.engine_value(value)

    def same(self, real_id: str, engine_id: str) -> None:
        self._place.same(real_id, engine_id)

    def known(self, real_id: str) -> bool:
        return self._place.known(real_id)
