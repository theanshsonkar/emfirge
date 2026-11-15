"""Where a piece of an AWS answer belongs: which resource a list item is, and which reads a known value can fill.

Generic, no code per service. Every resource is keyed by the catalog's own ResourceRef, so one thing is one resource
whatever field names it (an ARN, a name, a URL): an item is placed by its own ARN (AwsCatalog.parse_arn), else by
filling one of its service's reads from the item and asking the catalog which resource that read is about
(AwsCatalog.refs). An internal id (a role's RoleId) never becomes a resource of its own: it stays a field of the
resource that owns it, where the graph finds it as one of that resource's identifiers.

The conventions here are AWS-wide (experiments 12, 18 and 21): list names are plural nouns ('Buckets', 'taskDefinitionArns'),
a generic list ('Items', 'items', 'member') takes its noun from the operation, a parameter P can be filled from a field
named P, or P's stem plus Arn/Name/Id/Url, and an optional list parameter that accepts 'All' asks for every attribute.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterator

from botocore.model import Shape

from emfirge.core.model import ResourceRef

from .catalog import AwsCatalog
from .codec import AwsCodec

ID_KEYS = ('Name', 'Id', 'Arn', 'Url', 'name', 'id', 'arn')
SUFFIXES = ('Arn', 'Name', 'Id', 'Url', 'ARN', 'Arns', 'Names', 'Ids', 'Urls')
GENERIC_LISTS = frozenset({'Items', 'items', 'member', 'item'})
FULL_OBJECT_KEYS = 4                      # an item with more fields than this is a resource's settings, not a reference
EVERY = {'All': list}                     # optional parameters whose allowed values ask for everything
OWN_SCOPE = ('Local',)                    # an optional scope that limits a list to the account's own resources
READ_VERB = re.compile(r'^(Get|List|Describe)')
CONTEXTS_PER_ANSWER = 40


@dataclass(frozen=True)
class Placed:
    """A list item placed as a resource. full: the item is the resource's settings (not a two-field reference)."""
    ref: ResourceRef
    full: bool


def singular(word: str) -> str:
    for a, b in (('ies', 'y'), ('sses', 'ss'), ('uses', 'us'), ('s', '')):
        if word.endswith(a) and len(word) > len(a):
            return word[:-len(a)] + b
    return word


def norm(text: str) -> str:
    return re.sub(r'[^a-z0-9]', '', text.lower())


def stem(name: str) -> str:
    """'taskDefinitionArns' -> 'taskDefinition', 'QueueUrls' -> 'Queue'."""
    for s in SUFFIXES:
        if name.endswith(s) and len(name) > len(s):
            return name[:-len(s)]
    return name


def op_noun(operation: str) -> str:
    """'GetRestApis' -> 'RestApi'."""
    return singular(READ_VERB.sub('', operation))


class Places:
    """The catalog and the service models, asked the questions the reader needs. Results are cached per session."""

    def __init__(self, codec: AwsCodec, catalog: AwsCatalog) -> None:
        self.codec, self.catalog = codec, catalog
        self._owner_cache: dict[str, tuple[ResourceRef, ...]] = {}

    # ------------------------------------------------------------------ services and types
    @lru_cache(maxsize=None)
    def prefix(self, service: str) -> str:
        """The service's prefix in AWS's authorization reference ('monitoring' calls are 'cloudwatch:...')."""
        ops = self.catalog._store.ops(service) or {}
        action = next((e.get('a', '') for e in ops.values() if ':' in e.get('a', '')), '')
        return action.split(':', 1)[0] or service

    @lru_cache(maxsize=None)
    def types(self, service: str) -> dict[str, str]:
        """{normalised type name: type} for the service's resource types."""
        prefix = self.prefix(service)
        store = self.catalog._store
        store.type_row(prefix + ':')
        return {norm(name): f'{prefix}:{name}' for name in store._types.get(prefix, {})}

    def types_for(self, service: str, noun: str) -> tuple[str, ...]:
        """The types a noun names: the exact type, else types whose name starts with it ('rule-on-default-event-bus')."""
        types, n = self.types(service), norm(noun)
        if not n:
            return ()
        if n in types:
            return (types[n],)
        return tuple(t for t in types.values() if t.split(':', 1)[1].lower().startswith(n + '-'))

    @lru_cache(maxsize=None)
    def weight(self, type_: str) -> int:
        """How many of the service's calls name this type: AWS's own measure of how central a type is."""
        service_ops = self.catalog._store.ops(self._service_of_prefix(type_.split(':', 1)[0])) or {}
        return sum(1 for e in service_ops.values() for b in e.get('b', []) + e.get('m', []) if b.get('t') == type_)

    def _service_of_prefix(self, prefix: str) -> str:
        return next((s for s in self.catalog._store.services() if self.prefix(s) == prefix), prefix)

    # ------------------------------------------------------------------ operations
    @lru_cache(maxsize=None)
    def read_ops(self, service: str) -> tuple[str, ...]:
        model = self.codec.model(service)
        return tuple(op for op in model.operation_names if self.catalog.kind(service, op).reads_only)

    def input_members(self, service: str, operation: str) -> tuple[dict[str, Shape], tuple[str, ...]]:
        shape = self.codec.model(service).operation_model(operation).input_shape
        return (dict(shape.members), tuple(shape.required_members)) if shape else ({}, ())

    def extras(self, service: str, operation: str) -> dict[str, Any]:
        """Optional parameters that make a read show everything it can, for the account's own resources only:
        a list parameter that accepts 'All' (GetQueueAttributes answers nothing without it), a scope 'Local'
        (ListPolicies would otherwise page through AWS's own policies)."""
        members, required = self.input_members(service, operation)
        out: dict[str, Any] = {}
        for name, shape in members.items():
            if name in required:
                continue
            if shape.type_name == 'list' and 'All' in (getattr(shape.member, 'enum', None) or []):
                out[name] = ['All']
            elif shape.type_name == 'string':
                scope = next((v for v in OWN_SCOPE if v in (getattr(shape, 'enum', None) or [])), None)
                if scope:
                    out[name] = scope
        return out

    def listings(self, service: str) -> list[tuple[str, str]]:
        """(operation, type) for the reads that list a type of the service with no input, most central type first."""
        found = []
        for op in self.read_ops(service):
            if self.input_members(service, op)[1]:
                continue
            for t in self.types_for(service, op_noun(op)):
                found.append((op, t))
        found.sort(key=lambda x: (-self.weight(x[1]), x[0]))
        return list(dict.fromkeys(found))

    def owners(self, service: str, operation: str, params: dict[str, Any]) -> tuple[ResourceRef, ...]:
        """The resources a read with these parameters is about, by the catalog."""
        key = json.dumps([service, operation, params], sort_keys=True, default=str)
        if key not in self._owner_cache:
            try:
                call = self.codec.encode(service, operation, params)
                self._owner_cache[key] = self.catalog.refs(call).primary
            except Exception:   # noqa: BLE001 - a value botocore cannot serialise names nothing
                self._owner_cache[key] = ()
        return self._owner_cache[key]

    def fill(self, service: str, operation: str, ctx: dict[str, Any]) -> dict[str, Any] | None:
        """The read's required parameters from known values, or None when one is missing."""
        members, required = self.input_members(service, operation)
        if not required:
            return None
        params = {}
        for name in required:
            value = fill_value(ctx, name, members[name])
            if value is None:
                return None
            params[name] = value
        return {**params, **self.extras(service, operation)}

    # ------------------------------------------------------------------ placing list items
    def place(self, service: str, operation: str, key: str, parent: str, item: Any,
              params: dict[str, Any]) -> Placed | None:
        """The resource a list item is, or None (a part of the resource around it, or not a resource)."""
        noun = list_noun(key, parent, operation)
        types = self.types_for(service, stem(noun))
        if not types:
            return None
        if isinstance(item, str):
            ref = self._by_arn(item, types) or self._by_read(service, item_context(params, {}, noun, item), types)
            return Placed(ref, False) if ref else None
        if not isinstance(item, dict):
            return None
        for k, v in item.items():
            if isinstance(v, str) and norm(k) in ('arn', norm(stem(noun)) + 'arn'):
                ref = self._by_arn(v, types)
                if ref:
                    return Placed(ref, True)
        ref = self._by_read(service, item_context(params, item, noun), types)
        return Placed(ref, _full(item, noun)) if ref else None

    def _by_arn(self, value: str, types: tuple[str, ...]) -> ResourceRef | None:
        ref = self.catalog.parse_arn(value) if value.startswith('arn:') else None
        return ref if ref and ref.type in types else None

    def _by_read(self, service: str, ctx: dict[str, Any], types: tuple[str, ...]) -> ResourceRef | None:
        """Fill a read of the service from the item; the catalog says which resource that read is about."""
        own = {k for k in ctx if k not in ctx.get('__inherited__', ())}
        for op in self._reads_of_types(service, types):
            members, required = self.input_members(service, op)
            params = {}
            for name in required:
                value = fill_value(ctx, name, members[name])
                if value is None:
                    break
                params[name] = value
            else:
                if not any(_filled_from(name, own) for name in required):
                    continue
                ref = next((r for r in self.owners(service, op, params) if r.type in types), None)
                if ref:
                    return ref
        return None

    @lru_cache(maxsize=None)
    def _reads_of_types(self, service: str, types: tuple[str, ...]) -> tuple[str, ...]:
        """The service's reads that name one of these types, the type's own read ('GetSchedule') first."""
        ops = self.catalog._store.ops(service) or {}
        wanted = [op for op in self.read_ops(service)
                  if self.input_members(service, op)[1] and any(b.get('t') in types for b in ops.get(op, {}).get('b', []))]
        names = {norm(t.split(':', 1)[1]) for t in types}
        return tuple(sorted(wanted, key=lambda op: (norm(op_noun(op)) not in names, len(op))))


# ---------------------------------------------------------------------- values and contexts
def list_noun(key: str, parent: str, operation: str) -> str:
    if key in GENERIC_LISTS:
        key = parent if parent and parent not in GENERIC_LISTS else ''
        if not key:
            return op_noun(operation)
    return singular(re.sub(r'(List|Set|Summaries|Summary)$', '', key) or key)


def item_context(params: dict[str, Any], item: dict[str, Any], noun: str, value: str | None = None) -> dict[str, Any]:
    """Every name a value of this item can be filled under: its own fields, and its id under the list's noun."""
    ctx: dict[str, Any] = dict(params)
    ctx['__inherited__'] = tuple(params)
    ctx.update({k: v for k, v in item.items() if isinstance(v, (str, int)) and not isinstance(v, bool)})
    cap = noun[:1].upper() + noun[1:]
    base = stem(cap)
    if value is not None:
        ctx[cap] = value
        ctx.setdefault(base, value)
    for k in ID_KEYS:
        v = item.get(k)
        if isinstance(v, str):
            ctx.setdefault(base + k[:1].upper() + k[1:], v)
            ctx.setdefault(base, v)
    return ctx


def contexts(params: dict[str, Any], answer: Any, operation: str) -> list[dict[str, Any]]:
    """The contexts an answer offers for filling later reads (experiment 12's crawl, with experiment 21's fixes)."""
    out = [dict(params, __inherited__=tuple(params))]

    def walk(node: Any, key: str, parent: str) -> None:
        if len(out) >= CONTEXTS_PER_ANSWER:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k, key)
        elif isinstance(node, list):
            noun = list_noun(key, parent, operation)
            for x in node:
                if isinstance(x, dict):
                    out.append(item_context(params, x, noun))
                    walk(x, '', key)
                elif isinstance(x, str):
                    out.append(item_context(params, {}, noun, x))
    if isinstance(answer, dict):
        for k, v in answer.items():
            walk(v, k, '')
        out.append(dict(params, __inherited__=tuple(params),
                        **{k: v for k, v in answer.items() if isinstance(v, str)}))
    return out[:CONTEXTS_PER_ANSWER]


def fill_value(ctx: dict[str, Any], member: str, shape: Shape) -> Any:
    """A value for parameter `member` from a context, or None. A list of strings takes one value."""
    is_list = shape.type_name == 'list' and getattr(shape.member, 'type_name', '') == 'string'
    if shape.type_name not in ('string', 'list') or (shape.type_name == 'list' and not is_list):
        return None
    name = singular(member) if is_list else member
    base = stem(name)
    for key in (name, member, *(base + s for s in ('Arn', 'Name', 'Id', 'Url', 'ARN')), base,
                base[:1].upper() + base[1:]):
        v = ctx.get(key)
        if isinstance(v, str) and v:
            return [v] if is_list else v
    return None


def _filled_from(member: str, own: set[str]) -> bool:
    base = stem(singular(member))
    return any(k == member or stem(k) == base or k == base for k in own)


def _full(item: dict[str, Any], noun: str) -> bool:
    """The item is a resource's settings: many fields, or its own plain id ('Arn', 'Id', '<Noun>Name')."""
    own = {'arn', 'id', 'name', norm(stem(noun)) + 'name', norm(stem(noun)) + 'id', norm(stem(noun)) + 'arn'}
    return len(item) > FULL_OBJECT_KEYS or any(norm(k) in own for k in item)


def strings(value: Any) -> Iterator[str]:
    """Every string in nested data."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from strings(v)
