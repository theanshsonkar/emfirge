"""core.ports.Outcomes for AWS with no code per resource type: lists, born ids and deletes from botocore's models and
the compiled catalog.

  listed   a list in an answer holds the types its member or item shape is named after (Functions -> function,
           TableNames -> table, Rules -> both rule types). Each item's resource comes from an ARN in it, or from the
           field that carries the type's ARN variable (FunctionName, GroupId -> ${SecurityGroupId}). A list named after
           no type may hold any type of the service: its items are not known (the branch then refuses to merge).
  born     the ids in a change's answer that the service gave out: values of the types the operation is named after
           whose id the service gives (CloudFormation's schema says so), that the request did not carry.
  removes  the call is one of the type's delete operations (catalog.resource_type(t).delete_operations).
"""
from __future__ import annotations

from typing import Any, Iterator, Protocol

from botocore.model import Shape

from emfirge.core.model import Call, Listed, Refs, ResourceRef
from emfirge.core.ports import CannotTell

from .catalog import ResourceTypeInfo
from .codec import AwsCodec, items_at
from .resource_words import binds, canonical, formats, list_word, names_type, type_word

URL_TAIL = '/'


class TypeFacts(Protocol):
    """What the outcomes need from a catalog (AwsCatalog, or a layered one that passes these through)."""

    def refs(self, call: Call) -> Refs: ...
    def resource_type(self, type_: str) -> ResourceTypeInfo | None: ...
    def parse_arn(self, value: str) -> ResourceRef | None: ...
    def action(self, service: str, operation: str) -> str | None: ...
    def types_of(self, prefix: str) -> tuple[str, ...]: ...


class GenericOutcomes:
    def __init__(self, codec: AwsCodec, catalog: TypeFacts) -> None:
        self._codec, self._catalog = codec, catalog

    # ---------------------------------------------------------------- lists
    def listed(self, call: Call, body: Any) -> list[Listed]:
        if self._codec.truncated(call, body):
            raise CannotTell('the real list has more than one page, and a merged page would be wrong')
        service_types = self._types(call.service, call.operation)
        out = []
        for lp in self._codec.list_paths(call, body):
            items = items_at(body, lp.path)
            holds = self.list_types(service_types, lp.member, lp.item.name if lp.item is not None else None)
            if not holds:
                out.append(Listed(lp.path, items, (None,) * len(items), frozenset(service_types)))
                continue
            refs = tuple(self._item_ref(holds, item, lp.item, body) for item in items)
            out.append(Listed(lp.path, items, refs, frozenset(holds)))
        return out

    @staticmethod
    def list_types(service_types: tuple[str, ...], member: str, item_shape: str | None) -> tuple[str, ...]:
        """The types a list member can hold, by its name and its items' shape name."""
        words = list_word(member, item_shape)
        exact = tuple(t for t in service_types if type_word(t) in words)
        return exact or tuple(t for t in service_types if any(names_type(w, t) for w in words))

    def _item_ref(self, holds: tuple[str, ...], item: Any, shape: Shape, body: Any) -> ResourceRef | None:
        if isinstance(item, str):
            return self._value_ref(holds, item)
        if not isinstance(item, dict) or shape.type_name != 'structure':
            return None
        fields = [(name, item.get(self._codec.field(shape, name, body))) for name in shape.members]
        fields = [(n, v) for n, v in fields if isinstance(v, str) and v]
        for _, value in fields:                 # an ARN names its type exactly
            ref = self._catalog.parse_arn(value) if value.startswith('arn:') else None
            if ref is not None and ref.type in holds:
                return ref
        for name, value in fields:
            for t in holds:
                ref = self._bound(t, name, value)
                if ref is not None:
                    return ref
        return None

    def _value_ref(self, holds: tuple[str, ...], value: str) -> ResourceRef | None:
        """A list of plain strings (TableNames, QueueUrls): an ARN, a URL's last part, or the name itself."""
        if value.startswith('arn:'):
            ref = self._catalog.parse_arn(value)
            return ref if ref is not None and ref.type in holds else None
        if len(holds) != 1:
            return None
        if '://' in value:
            value = value.rstrip(URL_TAIL).rsplit(URL_TAIL, 1)[-1]
        info = self._catalog.resource_type(holds[0])
        fmt = info.arn_formats if info else ()
        variables = list(_single_variables(holds[0], fmt))
        return ResourceRef(holds[0], canonical(fmt, holds[0], variables[0], value)) if variables else None

    def _bound(self, type_: str, field: str, value: str) -> ResourceRef | None:
        info = self._catalog.resource_type(type_)
        if info is None:
            return None
        var = binds(field, type_, info.arn_formats)
        return ResourceRef(type_, canonical(info.arn_formats, type_, var, value)) if var else None

    # ---------------------------------------------------------------- born ids
    def born(self, call: Call, body: Any) -> tuple[ResourceRef, ...]:
        targets = [t for t in self._types(call.service, call.operation) if self._service_gives_id(t)
                   and type_word(t) in _squash(call.operation)]
        if not targets:
            return ()
        sent = set(_strings(call.params))
        found: list[ResourceRef] = []
        for path, value in _leaves(body):
            if value in sent or any(value in s for s in sent if len(value) > 3):
                continue
            ref = self._born_ref(targets, path, value)
            if ref is not None and ref.id not in sent and ref not in found:
                found.append(ref)
        return tuple(found)

    def _born_ref(self, targets: list[str], path: tuple[str, ...], value: str) -> ResourceRef | None:
        if value.startswith('arn:'):
            ref = self._catalog.parse_arn(value)
            return ref if ref is not None and ref.type in targets else None
        names = [path[-1]] + ([path[-2] + path[-1][:1].upper() + path[-1][1:]] if len(path) > 1 else [])
        for t in targets:
            for name in names:
                ref = self._bound(t, name, value)
                if ref is not None:
                    return ref
        return None

    def _service_gives_id(self, type_: str) -> bool:
        info = self._catalog.resource_type(type_)
        return bool(info and info.id_given_by_service)

    # ---------------------------------------------------------------- deletes, payloads, shapes
    def removes(self, call: Call) -> bool:
        op = f'{call.service}.{call.operation}'
        for ref in self._catalog.refs(call).primary:
            info = self._catalog.resource_type(ref.type)
            if info is not None and op in info.delete_operations:
                return True
        return False

    def opaque(self, call: Call) -> bool:
        return self._codec.blob_payload(call, 'input_shape') or self._codec.blob_payload(call, 'output_shape')

    def shape(self, call: Call) -> str | None:
        return self._codec.shape(call)

    # ---------------------------------------------------------------- helpers
    def _types(self, service: str, operation: str | None) -> tuple[str, ...]:
        """The resource types of the IAM prefix the service's operations act in."""
        return self._catalog.types_of(_prefix(self._codec, self._catalog, service, operation))


def _prefix(codec: AwsCodec, catalog: TypeFacts, service: str, operation: str | None) -> str:
    """The IAM prefix of an operation (stepfunctions -> states), from AWS's list; the signing name otherwise."""
    ops = [operation] if operation else codec.model(service).operation_names[:20]
    for op in ops:
        action = catalog.action(service, op)
        if action:
            return action.split(':', 1)[0]
    meta = codec.model(service).metadata
    return meta.get('signingName') or meta['endpointPrefix']


def _single_variables(type_: str, texts: tuple[str, ...]) -> Iterator[str]:
    for f in formats(type_, texts):
        if len(f.variables) == 1:
            yield f.variables[0]


def list_ops(codec: AwsCodec, service: str, type_: str) -> list[str]:
    """List operations of `service` that need no parameters and whose answer has a list named after `type_`."""
    model = codec.model(service)
    out = []
    for op in model.operation_names:
        if not op.startswith(('List', 'Describe')):
            continue
        om = model.operation_model(op)
        if om.input_shape is not None and om.input_shape.required_members:
            continue
        out_shape = om.output_shape
        if out_shape is None:
            continue
        lists = [(n, m.member.name) for n, m in out_shape.members.items() if m.type_name == 'list']
        if any(GenericOutcomes.list_types((type_,), n, item) for n, item in lists):
            out.append(op)
    return out


def _squash(text: str) -> str:
    return ''.join(c for c in text.lower() if c.isalnum())


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _leaves(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str]]:
    """(path of keys, string) for every string in plain nested data; list items keep their list's key."""
    if isinstance(value, str):
        if path:
            yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _leaves(v, path + (str(k),))
    elif isinstance(value, list):
        for v in value:
            yield from _leaves(v, path)
