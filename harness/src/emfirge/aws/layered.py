"""The generic catalog and copier first, the hand-written (curated) ones only where the generic ones do not know.

LayeredCatalog (core.ports.Catalog)
  kind     the generic catalog's two-key answer, except calls that run the customer's own code (an operation named
           Invoke... or TestInvoke..., or an action in data/runs_code.json): UNKNOWN, so the branch refuses them.
  refs     the generic catalog's refs, then four generic rules and one fallback:
           * data held inside a container (a type that holds data, whose parent holds data: an object in a bucket)
             is placed on its container, as the container is what is copied;
           * a read with no primary resource that names one by an ARN member of its own reads that resource
             (GetSubscriptionAttributes' SubscriptionArn names the topic);
           * a call that names a resource by a required member (a name, id or ARN, or a member named after a type of
             its service: ecs taskDefinition) that nothing places is not complete, even where AWS's list ties the
             action to no resource: the branch refuses it rather than send it to an engine that does not have it;
           * fallback: where the generic catalog cannot place a call, or places no primary resource, and the curated
             naming does, the curated primary is used; resources only the curated naming finds (a copy source
             bucket, a group id inside a rule) are added as mentioned. One vocabulary: the generic catalog's.
  reads    the curated reads first where a curated type has them (they name the resource the way agents do, and the
           first one tells whether it exists), then the generic reads, then the list reads that can show the type.
           For other types the read named after the type (or its ARN variable) comes first.
  `fallbacks` counts each use of the curated layer, so its cost can be measured.

LayeredCopier (core.ports.Copier)
  Tries copiers in order for each type. When one does not know the type at all (UnknownType, raised before anything
  is written to the engine), the next one tries. A copier that knows the type and refuses this resource (a role in an
  instance profile, a VPC with a gateway) is not overruled: its refusal stands. The order per type is data
  (data/copier_order.json), written from experiment 23's measurement.
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
from .errors import UnknownType
from .outcomes_generic import list_ops
from .catalog.names import split
from .resource_words import formats, names_type, noun_of, type_word, verb_of

CODE_VERBS = ('Invoke', 'TestInvoke')
CREATE_VERBS = ('Create', 'Put', 'Register', 'Run', 'Allocate', 'Import')


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
        mine = self._generic.refs(call)
        mine = self._unplaced(call, self._arn_read(call, self._contents_on_containers(mine)))
        if self._curated is None:
            return mine
        theirs = self._curated.refs(call)
        primary, complete = mine.primary, mine.complete
        if (not mine.complete or not mine.primary) and theirs.complete and theirs.primary:
            primary, complete = theirs.primary, True
            self.fallbacks['refs: placed by the curated naming'] += 1
        extra = tuple(r for r in theirs.all if r not in primary and r not in mine.mentioned)
        if extra:
            self.fallbacks['refs: named only by the curated naming'] += 1
        mentioned = tuple(r for r in mine.all if r not in primary) + extra
        return Refs(primary, mentioned, complete)

    def _arn_read(self, call: Call, refs: Refs) -> Refs:
        """A read with no primary resource that names one by an ARN member of its own (GetSubscriptionAttributes'
        SubscriptionArn names the topic) reads that resource: on a branch that holds it, the engine answers."""
        if refs.primary or not self.kind(call.service, call.operation).reads_only:
            return refs
        named = [self._generic.parse_arn(v) for k, v in call.params.items()
                 if isinstance(v, str) and v.startswith('arn:') and split(k).designator == 'arn']
        primary = tuple(r for r in dict.fromkeys(named) if r is not None)
        return Refs(primary, tuple(r for r in refs.mentioned if r not in primary), refs.complete) if primary else refs

    def _unplaced(self, call: Call, refs: Refs) -> Refs:
        if refs.all or not refs.complete or call.operation.startswith(CREATE_VERBS):
            return refs
        shape = self._codec.operation(call).input_shape
        types = self._generic.types_of((self._generic.action(call.service, call.operation) or ':').split(':')[0])
        for name in shape.required_members if shape is not None else ():
            words = split(name)
            if shape.members[name].type_name in ('string', 'list') and call.params.get(name) and (
                    words.designator in ('name', 'id', 'arn', 'identifier') or
                    any(names_type(words.joined, t) and words.joined for t in types)):
                return Refs((), (), False)
        return refs

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
        mine = _existence_first(ref.type, self._generic.resource_type(ref.type), self._generic.reads_of(ref))
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


def _existence_first(type_: str, info: ResourceTypeInfo | None,
                     reads: list[tuple[str, str, dict[str, Any]]]) -> list[tuple[str, str, dict[str, Any]]]:
    """The read named after the type or its ARN variable (GetHostedZone, DescribeInstances, DescribeDBInstances for
    rds:db) first: the branch asks the first read whether the resource exists."""
    words = {type_word(type_)} | {split(f.variables[-1]).joined
                                  for f in formats(type_, info.arn_formats if info else ()) if f.variables}
    named = [r for r in reads if verb_of(r[1]) in ('Get', 'Describe') and noun_of(r[1]) in words - {''}]
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
            except UnknownType as e:
                if watched.engine.changed:
                    raise CannotTell(str(e)) from e
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
