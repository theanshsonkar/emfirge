"""A tiny in-memory cloud for testing the branch with no network and no AWS: one resource type ('thing'), calls
as JSON {op, params}. Each port is implemented the plain way, so a branch test shows the branch's own behaviour."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from emfirge.core.model import Call, Kind, Listed, Refs, ResourceRef, WireRequest, WireResponse
from emfirge.core.ports import CannotTell, Placement

THING = 'cloud:thing'
KINDS = {'get': Kind.READ, 'peek': Kind.READ, 'list': Kind.LIST, 'put': Kind.WRITE, 'delete': Kind.WRITE, 'create': Kind.WRITE,
         'grant': Kind.PERMISSION}


def request(op: str, **params: Any) -> WireRequest:
    return WireRequest('POST', '/', '', {'content-type': 'application/json'}, json.dumps({'op': op, 'params': params}).encode())


def ok(body: Any, status: int = 200) -> WireResponse:
    return WireResponse(status, {'content-type': 'application/json'}, json.dumps(body).encode())


class FakeCodec:
    def decode(self, r: WireRequest) -> Call | None:
        try:
            d = json.loads(r.body)
        except ValueError:
            return None
        return Call('cloud', d['op'], d['params'], Kind.UNKNOWN, r)

    def encode(self, service: str, operation: str, params: dict[str, Any]) -> Call:
        return Call(service, operation, params, Kind.UNKNOWN, request(operation, **params))

    def body(self, call: Call, response: WireResponse) -> Any:
        return json.loads(response.body) if response.body else b''

    def render(self, call: Call, response: WireResponse, body: Any) -> WireResponse:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        return WireResponse(response.status, response.headers, data)

    def refusal(self, call: Call | None, request: WireRequest, message: str) -> WireResponse:
        return WireResponse(400, {'x-refused': 'true'}, json.dumps({'code': 'CannotTell', 'message': message}).encode())


class FakeCatalog:
    def kind(self, service: str, operation: str) -> Kind:
        return KINDS.get(operation, Kind.UNKNOWN)

    def refs(self, call: Call) -> Refs:
        p = call.params
        primary = tuple(ResourceRef(THING, n) for n in ([p['name']] if 'name' in p else []))
        mentioned = tuple(ResourceRef(THING, n) for n in ([p['uses']] if 'uses' in p else []))
        return Refs(primary, mentioned, complete='mystery' not in p)

    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]:
        return [('cloud', 'get', {'name': ref.id}), ('cloud', 'list', {})]


class FakeOutcomes:
    def listed(self, call: Call, body: Any) -> list[Listed]:
        if call.operation != 'list':
            return []
        items = tuple(body['items'])
        return [Listed(('items',), items, tuple(ResourceRef(THING, i['name']) for i in items), frozenset({THING}))]

    def born(self, call: Call, body: Any) -> tuple[ResourceRef, ...]:
        return tuple(ResourceRef(THING, body['id']) for _ in [0] if call.operation == 'create' and isinstance(body, dict))

    def removes(self, call: Call) -> bool:
        return call.operation == 'delete'

    def opaque(self, call: Call) -> bool:
        return False

    def shape(self, call: Call) -> str | None:
        return 'Thing' if call.operation in ('get', 'put') else None


@dataclass
class FakeAccount:
    """A store of things: {name: {'size': int, 'colour': str}}. `sent` records every operation it answered."""
    name: str
    things: dict[str, dict[str, Any]] = field(default_factory=dict)
    sent: list[str] = field(default_factory=list)
    counter: int = 0

    def send(self, r: WireRequest) -> WireResponse:
        d = json.loads(r.body)
        op, p = d['op'], d['params']
        self.sent.append(op)
        if op in ('get', 'peek'):   # peek: a read no baseline is taken for
            t = self.things.get(p['name'])
            return ok({'name': p['name'], **t}) if t is not None else ok({'error': 'NotFound'}, 404)
        if op == 'list':
            return ok({'items': [{'name': n, **t} for n, t in sorted(self.things.items())]})
        if op == 'put':
            if p.get('uses') and p['uses'] not in self.things:
                return ok({'error': 'NoSuchThing'}, 400)
            self.things.setdefault(p['name'], {}).update(p.get('set', {}))
            return ok({'name': p['name'], **self.things[p['name']]})
        if op == 'delete':
            return ok({}) if self.things.pop(p['name'], None) is not None else ok({'error': 'NotFound'}, 404)
        if op == 'create':
            self.counter += 1
            self.things[f'thing-{self.counter:04x}'] = {'size': 0}
            return ok({'id': f'thing-{self.counter:04x}'})
        return ok({'error': 'Unknown'}, 400)


@dataclass(frozen=True)
class Copied:
    found: bool
    also: tuple[ResourceRef, ...] = ()
    notes: tuple[str, ...] = ()
    faithful: frozenset[str] = frozenset()


class FakeCopier:
    """Copies a thing as it is. A thing whose name starts with 'cursed' cannot be copied; one whose name starts with
    'lossy' is copied without its colour, and says so in a note; any other copy says its 'peek' read answers alike."""

    def __init__(self) -> None:
        self.copied: list[str] = []

    def copy(self, ref: ResourceRef, place: Placement) -> Copied:
        if ref.id.startswith('cursed'):
            raise CannotTell('cursed things cannot be copied')
        got = place.real.send(request('get', name=ref.id))
        if got.status == 404:
            return Copied(False)
        body = json.loads(got.body)
        lossy = ref.id.startswith('lossy')
        place.engine.send(request('put', name=ref.id, set={k: v for k, v in body.items()
                                                           if k != 'name' and not (lossy and k == 'colour')}))
        self.copied.append(ref.id)
        return Copied(True, notes=('its colour',) if lossy else (), faithful=frozenset() if lossy else frozenset({'peek'}))


def make(real_things: dict[str, dict[str, Any]] | None = None):
    """A branch over a fake real account, with a fresh fake engine. Returns (branch, real, engine, copier)."""
    from emfirge.branch import Branch
    real = FakeAccount('real', dict(real_things or {}))
    engine = FakeAccount('engine')
    copier = FakeCopier()
    return Branch(FakeCodec(), FakeCatalog(), copier, real, engine, FakeOutcomes()), real, engine, copier


def answer(r: WireResponse) -> Any:
    return json.loads(r.body)
