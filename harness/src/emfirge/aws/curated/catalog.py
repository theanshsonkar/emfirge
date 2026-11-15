"""core.ports.Catalog and core.ports.Outcomes from the hand-written types: the measured fallback until the generic
catalog (emfirge.aws.catalog) replaces the naming part."""
from __future__ import annotations

from typing import Any, Iterator

from emfirge.core.model import Call, Kind, Listed, Refs, ResourceRef
from emfirge.core.ports import CannotTell

from ..codec import AwsCodec, items_at
from .kinds import kind_of
from .naming import Naming, Unplaced
from .spec import TypeSpec, Where


class CuratedCatalog:
    def __init__(self, codec: AwsCodec, naming: Naming, where: Where) -> None:
        self._codec, self._naming, self._where = codec, naming, where

    def kind(self, service: str, operation: str) -> Kind:
        return kind_of(operation)

    def refs(self, call: Call) -> Refs:
        params = dict(call.params)
        opm = self._codec.operation(call)
        present = [n for n in self._naming.naming_members(call.service, opm.input_shape) if params.get(n) not in (None, '', [])]
        primary: list[ResourceRef] = []
        unplaced = False
        for n in present:
            for v in params[n] if isinstance(params[n], list) else [params[n]]:
                r = self._naming.recognize(v, call.service, n, params, call.operation)
                unplaced |= isinstance(r, Unplaced)
                if isinstance(r, ResourceRef) and r not in primary:
                    primary.append(r)
        mentioned = []
        for r in self._walk(params, call):
            unplaced |= isinstance(r, Unplaced)
            if isinstance(r, ResourceRef) and r not in primary and r not in mentioned:
                mentioned.append(r)
        complete = not unplaced and not (present and not primary)
        if complete and not primary and not mentioned and not self.kind(call.service, call.operation).reads_only:
            complete = call.operation.startswith('Create')   # a creation names nothing that exists; anything else must
        return Refs(tuple(primary), tuple(mentioned), complete)

    def _walk(self, o: Any, call: Call, param: str | None = None) -> Iterator[ResourceRef | Unplaced]:
        if isinstance(o, dict):
            for k, v in o.items():
                yield from self._walk(v, call, k)
        elif isinstance(o, list):
            for v in o:
                yield from self._walk(v, call, param)
        else:
            r = self._naming.recognize(o, call.service, param, call.params, call.operation)
            if r is not None:
                yield r

    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]:
        spec = self._naming.specs.get(ref.type)
        if spec is None:
            return []
        reads = [(spec.service, op, p) for op, p in spec.reads(self._where, ref.id)]
        return reads + [(spec.service, op, {}) for op, _, _ in spec.lists]


class CuratedOutcomes:
    def __init__(self, codec: AwsCodec, naming: Naming) -> None:
        self._codec, self._naming = codec, naming

    def listed(self, call: Call, body: Any) -> list[Listed]:
        if self._codec.truncated(call, body):
            raise CannotTell('the real list has more than one page, and a merged page would be wrong')
        out = []
        mine = self._naming.of_service(call.service)
        for lp in self._codec.list_paths(call, body):
            items = items_at(body, lp.path)
            decl = [(s, field) for s in mine for (_, member, field) in s.lists if member == lp.member]
            if not decl:
                out.append(Listed(lp.path, items, (None,) * len(items), frozenset(s.type for s in mine)))
                continue
            refs = tuple(self._item_ref(decl, item, lp.item, body) for item in items)
            out.append(Listed(lp.path, items, refs, frozenset(s.type for s, _ in decl)))
        return out

    def _item_ref(self, decl: list[tuple[TypeSpec, str | None]], item: Any, shape: Any, body: Any) -> ResourceRef | None:
        for spec, field in decl:
            v = item if field is None or not isinstance(item, dict) else item.get(self._codec.field(shape, field, body))
            r = self._naming.item_ref(spec, v) if isinstance(v, str) else None
            if r is not None:
                return r
        return None

    def born(self, call: Call, body: Any) -> tuple[ResourceRef, ...]:
        found: list[ResourceRef] = []

        def walk(o: Any, param: str | None = None) -> None:
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, k)
            elif isinstance(o, list):
                for v in o:
                    walk(v, param)
            else:
                r = self._naming.recognize(o, call.service, param, {}, call.operation)
                if isinstance(r, ResourceRef) and self._naming.specs[r.type].service_ids and r not in found:
                    found.append(r)
        walk(body)
        return tuple(found)

    def removes(self, call: Call) -> bool:
        return any(call.operation in s.removed_by for s in self._naming.of_service(call.service))

    def opaque(self, call: Call) -> bool:
        return self._codec.blob_payload(call, 'input_shape') or self._codec.blob_payload(call, 'output_shape')

    def shape(self, call: Call) -> str | None:
        return self._codec.shape(call)
