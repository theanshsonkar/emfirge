"""AccountReader: the real account's settings around a change set, as the graph's `states` (session.ports.StateReader).

Generic, no code per service (experiments 12, 18, 21). What to read comes from the catalog and the service models;
every resource is keyed by the catalog's ResourceRef (aws/places.py), so the graph meets the same names the branch uses.

Why not read everything: an account has hundreds of services and the real account's API limits are the owner's.
The reader reads in this order, and stops at a budget of reads with an honest Unknown:

  1 changed     every read the catalog lists for each changed resource (and the reads its answers fill in, such as
                each inline policy of a role). Nothing is read for a created one: the real account does not have it.
  2 listings    the list reads of the changed resources' services, then of DEFAULT_SERVICES (where AWS keeps
                references to other resources). Per service the most central types first: those most of AWS's own
                calls name (AwsCatalog bindings). A list that answers empty is tried again with the parents other lists
                found (ECS services live in a cluster).
  3 details     for each listed resource, the few reads most likely to hold references (DETAIL_WORDS): its policy, its
                targets, its configuration. Changed services first.
  4 references  ARNs found in what was read name resources not read yet: their own reads, up to `depth` links out.

A read about one resource that answers with other whole resources ('the instance profiles of this role') is a reverse
read: those resources are recorded on their own, and the resource read does not name them (they name it).

All reads go through the Account it is given: the branch's read-only door (the reader never holds the raw account).
"""
from __future__ import annotations

import json
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

import botocore.exceptions
import botocore.parsers

from emfirge.core.model import Change, ChangeType, ResourceRef, Unknown, WireRequest, WireResponse
from emfirge.core.ports import Account, CannotTell
from emfirge.session.ports import Reading

from .accounts import sdk_client
from .catalog import AwsCatalog
from .catalog.arns import ARN_IN_TEXT
from .codec import AwsCodec, encode_body
from .places import Places, contexts, item_context, list_noun, norm, op_noun, strings

DEFAULT_SERVICES: dict[str, str] = {
    'iam': 'policies name the resources they allow; instance profiles name roles',
    'lambda': 'functions name roles, tables, buckets, queues; event source mappings name their sources',
    'ec2': 'instances name profiles, groups and subnets; groups name other groups',
    's3': 'bucket policies and notifications name principals, queues, topics and functions',
    'events': 'rules start targets',
    'scheduler': 'schedules start targets with a role',
    'sns': 'subscriptions name queues, functions and addresses',
    'cloudfront': 'origins name buckets and hosts',
    'route53': 'records name hosts',
}
"""Services listed in every session, with why: AWS keeps most references to other resources in these settings."""

SKIP = frozenset({
    'GetObject', 'GetObjectTorrent', 'GetItem', 'BatchGetItem', 'Scan', 'Query', 'ReceiveMessage', 'GetLogEvents',
    'FilterLogEvents', 'GetMetricData', 'GetMetricStatistics', 'GetQueryResults', 'GetLogRecord', 'GetCredentialReport',
    'GetAccountAuthorizationDetails', 'GetConsoleOutput', 'GetConsoleScreenshot', 'GetPasswordData',
    'GetLaunchTemplateData', 'DescribeImages', 'DescribeSnapshots', 'DescribeSpotPriceHistory', 'DescribeInstanceTypes',
    'DescribeInstanceTypeOfferings', 'DescribeReservedInstancesOfferings', 'DescribeImageAttribute',
    'DescribeVpcEndpointServices', 'DescribePrefixLists', 'GetInstanceUefiData', 'ListMultipartUploads',
    'DescribeLogStreams', 'ListVersionsByFunction', 'ListInvalidations',
})
"""Reads of data (objects, items, messages, logs, secrets) or of AWS's public catalogue (images, prices, instance
types): not the account's settings, and often large. From experiment 12's crawl, plus four history lists."""

DETAIL_WORDS = ('Policy', 'Target', 'Subscription', 'Notification', 'Integration', 'Origin', 'Environment',
                'Attribute', 'Configuration', 'Config', 'Definition', 'Mapping', 'RecordSet', 'Profile')
"""Words in the reads that hold references: policies name principals and resources; targets, subscriptions,
notifications and integrations name what they call; configurations, attributes and definitions hold ids."""


@dataclass(frozen=True)
class ReaderSettings:
    budget: int = 400                 # reads sent to the real account, at most
    depth: int = 2                    # links followed out from what was read, by ARN
    services: tuple[str, ...] = tuple(DEFAULT_SERVICES)
    lists_per_service: int = 12
    reads_per_changed: int = 40
    reads_per_resource: int = 3
    follow_ups: int = 4               # reads an answer fills in (each inline policy), per resource
    pages: int = 3
    parent_retries: int = 5


class Spent(Exception):
    """The budget of reads is used up."""


class _Door:
    """Counts the reads sent and refuses once the budget is used up. Every read passes here."""

    def __init__(self, account: Account, budget: int) -> None:
        self._account, self._budget = account, budget
        self.name = account.name
        self.sent = 0

    def send(self, request: WireRequest) -> WireResponse:
        if self.sent >= self._budget:
            raise Spent()
        self.sent += 1
        return self._account.send(request)


class AccountReader:
    def __init__(self, real: Account, codec: AwsCodec, catalog: AwsCatalog, region: str,
                 settings: ReaderSettings = ReaderSettings()) -> None:
        self._real, self._codec, self._catalog, self._region = real, codec, catalog, region
        self._places = Places(codec, catalog)
        self.settings = settings

    def before(self, changes: Sequence[Change]) -> Reading:
        door = _Door(self._real, self.settings.budget)
        return _Crawl(self._places, door, self._region, self.settings).run(changes)

    def after(self, states: Mapping[ResourceRef, Any]) -> dict[ResourceRef, Any]:
        """The branch's states (the codec's plain data) parsed as the SDK parses them, like `before` reads them."""
        return {ref: {name: self._shaped(ref, name, body) for name, body in state.items()} if isinstance(state, dict)
                else state for ref, state in states.items()}

    def _shaped(self, ref: ResourceRef, name: str, body: Any) -> Any:
        op = name.split('{', 1)[0]
        service = next((s for s, o, _ in self._catalog.reads_of(ref) if o == op), None)
        if service is None or not isinstance(body, (dict, list)):
            return body
        try:
            model = self._codec.model(service)
            output = model.operation_model(op).output_shape
            parser = botocore.parsers.create_parser(model.metadata['protocol'])
            parsed = parser.parse({'body': encode_body(body), 'headers': {}, 'status_code': 200}, output)
        except Exception:   # noqa: BLE001 - a body the SDK cannot parse is compared as it is
            return body
        parsed.pop('ResponseMetadata', None)
        return plain(parsed)


@dataclass
class _Crawl:
    """One reading of the account. Holds what was read; never reused."""
    places: Places
    door: _Door
    region: str
    settings: ReaderSettings
    states: dict[ResourceRef, dict[str, Any]] = field(default_factory=dict)
    depth: dict[ResourceRef, int] = field(default_factory=dict)
    service: dict[ResourceRef, str] = field(default_factory=dict)
    ctx: dict[ResourceRef, list[dict[str, Any]]] = field(default_factory=dict)
    read_directly: set[ResourceRef] = field(default_factory=set)
    unknowns: list[Unknown] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    _done: dict[str, Any] = field(default_factory=dict)
    _clients: dict[str, Any] = field(default_factory=dict)

    def run(self, changes: Sequence[Change]) -> Reading:
        t = time.perf_counter()
        services: list[str] = []
        try:
            services = self._changed(changes)
            for service in dict.fromkeys([*services, *self.settings.services]):
                self._list(service)
            self._details(services)
            self._follow()
        except Spent:
            self.unknowns.append(Unknown(f'the reader stopped at its budget of {self.settings.budget} reads of your '
                                         'account: settings it did not read may name what changed', 'reader'))
        self.counts.update(resources=len(self.states), seconds_ms=int((time.perf_counter() - t) * 1000))
        return Reading(dict(self.states), tuple(dict.fromkeys(self.unknowns)), self.door.sent, dict(self.counts))

    # ------------------------------------------------------------------ 1 changed resources
    def _changed(self, changes: Sequence[Change]) -> list[str]:
        services = []
        for change in changes:
            reads = self.places.catalog.reads_of(change.ref)
            service = reads[0][0] if reads else None
            if service:
                services.append(service)
            if change.type is ChangeType.CREATED or not service:
                continue
            self.depth[change.ref], self.service[change.ref] = 0, service
            self.read_directly.add(change.ref)
            self._read_resource(change.ref, self.settings.reads_per_changed, everything=True)
        return list(dict.fromkeys(services))

    # ------------------------------------------------------------------ 2 listings
    def _list(self, service: str) -> None:
        empty = []
        for op, _ in self.places.listings(service)[:self.settings.lists_per_service]:
            if op in SKIP:
                continue
            params = self.places.extras(service, op)
            answer = self._read(service, op, params)
            if answer is not None and not self._absorb_listing(service, op, params, answer):
                empty.append(op)
        for op in empty:
            self._retry_with_parents(service, op)

    def _absorb_listing(self, service: str, op: str, params: dict[str, Any], answer: Any) -> int:
        """Place each listed item as a resource; returns how many were placed."""
        placed = 0

        def place(key: str, parent: str, item: Any) -> bool:
            nonlocal placed
            got = self.places.place(service, op, key, parent, item, params)
            if got is None:
                return False
            placed += 1
            noun = list_noun(key, parent, op)
            ctx = item_context(params, item, noun) if isinstance(item, dict) else item_context(params, {}, noun, item)
            self._found(got.ref, service, f'{op}[]', item, 1, [ctx])
            return True
        _cut(answer, place)
        self.counts['listed'] += placed
        return placed

    def _retry_with_parents(self, service: str, op: str) -> None:
        """A list that answered empty, asked again once per parent another list found (ECS services need a cluster)."""
        members, _ = self.places.input_members(service, op)
        optional = [m for m, s in members.items() if s.type_name == 'string']
        tried = 0
        for ref, ctxs in list(self.ctx.items()):
            if self.service.get(ref) != service or tried >= self.settings.parent_retries:
                continue
            for name in optional:
                value = next((c.get(name) or c.get(name + 'Arn') or c.get(name + 'Name') for c in ctxs
                              if isinstance(c.get(name) or c.get(name + 'Arn') or c.get(name + 'Name'), str)), None)
                if value:
                    params = {name: value, **self.places.extras(service, op)}
                    answer = self._read(service, op, params)
                    tried += 1
                    if answer is not None:
                        self._absorb_listing(service, op, params, answer)
                    break

    # ------------------------------------------------------------------ 3 details, 4 references
    def _details(self, changed_services: list[str]) -> None:
        listed = [r for r in self.states if r not in self.read_directly]
        listed.sort(key=lambda r: (self.service.get(r) not in changed_services, -self.places.weight(r.type), str(r)))
        for ref in listed:
            self._read_resource(ref, self.settings.reads_per_resource, everything=False)

    def _follow(self) -> None:
        """Resources named by ARN in what was read, not read yet: their own reads, `depth` links out."""
        for _ in range(self.settings.depth):
            new = {}
            for ref, state in list(self.states.items()):
                for found in self._named(state):
                    if found not in self.states and found not in new and self.depth.get(ref, 1) < self.settings.depth:
                        new[found] = self.depth.get(ref, 1) + 1
            if not new:
                return
            for ref, depth in new.items():
                reads = self.places.catalog.reads_of(ref)
                if not reads:
                    continue
                self.depth[ref], self.service[ref] = depth, reads[0][0]
                self.counts['followed'] += 1
                self._read_resource(ref, self.settings.reads_per_resource, everything=False)

    def _named(self, state: Any) -> Iterable[ResourceRef]:
        for text in strings(state):
            if '%3A' in text:
                text = urllib.parse.unquote(text)
            for m in ARN_IN_TEXT.finditer(text):
                ref = self.places.catalog.parse_arn(m.group(0))
                if ref:
                    yield ref

    # ------------------------------------------------------------------ reading one resource
    def _read_resource(self, ref: ResourceRef, cap: int, everything: bool) -> None:
        """The resource's reads, most telling first. everything: all of them (a changed resource); else only those
        likely to hold references, at most `cap`, plus what their answers fill in."""
        service = self.service.get(ref)
        if service is None:
            return
        listed = ref in self.states
        planned = self._candidates(ref, service, self.ctx.get(ref, []))
        ranked = sorted(planned, key=lambda c: _rank(c[0], ref, listed))
        if not everything:
            ranked = [c for c in ranked if _rank(c[0], ref, listed) < 2][:cap]
        follow_ups = self.settings.reads_per_changed if everything else self.settings.follow_ups
        queue = list(ranked)
        while queue:
            op, params = queue.pop(0)
            answer = self._read(service, op, params)
            if answer is None:
                continue
            new_ctx = self._absorb_read(ref, service, op, params, answer)
            more = [c for c in self._candidates(ref, service, new_ctx) if c not in queue and not self._was_read(service, *c)]
            take = more[:max(0, follow_ups)]
            follow_ups -= len(take)
            queue += take

    def _candidates(self, ref: ResourceRef, service: str, ctxs: list[dict[str, Any]]) -> list[tuple[str, dict]]:
        """(operation, params): the catalog's reads of the resource, and reads of its service that known values
        fill and that the catalog says are about this resource."""
        out = [(op, {**params, **self.places.extras(svc, op)}) for svc, op, params in self.places.catalog.reads_of(ref)
               if svc == service and op not in SKIP]
        last = ref.id.rsplit('/', 1)[-1]
        for op in self.places.read_ops(service):
            if op in SKIP or any(o == op for o, _ in out):
                continue
            for ctx in ctxs:
                params = self.places.fill(service, op, ctx)
                if params and any(last in v for v in strings(params)) and ref in self.places.owners(service, op, params):
                    out.append((op, params))
                    break
        return [c for c in out if not self._was_read(service, *c)]

    def _absorb_read(self, ref: ResourceRef, service: str, op: str, params: dict[str, Any], answer: Any) -> list[dict]:
        """Record a read about `ref`. Whole other resources in its lists are a reverse read: recorded on their own and
        cut from this answer. Returns the contexts the answer offers."""
        kept = _cut(answer, lambda key, parent, item: self._other(ref, service, op, key, parent, item, params))
        name = op if op not in self.states.get(ref, {}) else f'{op}{json.dumps(params, sort_keys=True, default=str)}'
        self._put(ref, name, kept)
        new = contexts(params, answer, op)
        self.ctx.setdefault(ref, []).extend(new)
        return new

    def _other(self, ref: ResourceRef, service: str, op: str, key: str, parent: str, item: Any,
               params: dict[str, Any]) -> bool:
        got = self.places.place(service, op, key, parent, item, params)
        if got is None or got.ref == ref or not got.full:
            return False
        self.counts['reverse'] += 1
        self._found(got.ref, service, f'{op}[]', item, self.depth.get(ref, 0) + 1, [])
        return True

    def _found(self, ref: ResourceRef, service: str, name: str, item: Any, depth: int, ctxs: list[dict]) -> None:
        """A resource seen in a list. A changed resource keeps only its own reads (the branch's after-state is made
        of the same reads, so the two compare)."""
        self.depth[ref] = min(depth, self.depth.get(ref, depth))
        self.service.setdefault(ref, service)
        self.ctx.setdefault(ref, []).extend(ctxs)
        if ref not in self.read_directly:
            self._put(ref, name, item)

    def _put(self, ref: ResourceRef, name: str, data: Any) -> None:
        state = self.states.setdefault(ref, {})
        key, n = name, 1
        while key in state:
            n += 1
            key = f'{name}#{n}'
        state[key] = data

    # ------------------------------------------------------------------ one read
    def _was_read(self, service: str, op: str, params: dict[str, Any]) -> bool:
        return _key(service, op, params) in self._done

    def _read(self, service: str, op: str, params: dict[str, Any]) -> Any:
        """The SDK-parsed answer (plain data), or None when the account refused or the read failed. Raises Spent."""
        key = _key(service, op, params)
        if key in self._done:
            return self._done[key]
        self._done[key] = None
        client = self._client(service)
        method = {v: k for k, v in client.meta.method_to_api_mapping.items()}.get(op)
        if method is None:
            return None
        try:
            answer = self._pages(client, method, params) if client.can_paginate(method) else getattr(client, method)(**params)
        except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError, CannotTell):
            self.counts['failed'] += 1
            return None
        except botocore.exceptions.BotoCoreError:
            self.counts['failed'] += 1
            return None
        answer.pop('ResponseMetadata', None)
        self._done[key] = plain(answer)
        return self._done[key]

    def _pages(self, client: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for i, page in enumerate(client.get_paginator(method).paginate(**params)):
            if i >= self.settings.pages:
                self.unknowns.append(Unknown(f'only the first {self.settings.pages} pages of {client.meta.service_model.service_name}.'
                                             f'{client.meta.method_to_api_mapping[method]} were read', 'reader'))
                break
            for k, v in page.items():
                if isinstance(v, list) and isinstance(merged.get(k), list):
                    merged[k] = merged[k] + v
                else:
                    merged.setdefault(k, v)
        return merged

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            self._clients[service] = sdk_client(self.door, service, self.region)
        return self._clients[service]


# ---------------------------------------------------------------------- helpers
def _key(service: str, op: str, params: dict[str, Any]) -> str:
    return json.dumps([service, op, params], sort_keys=True, default=str)


def _rank(op: str, ref: ResourceRef, listed: bool) -> int:
    """0 and 1 are read for a listed or followed resource; 2 only for a changed one. A listed resource's list item
    already holds what its main read ('GetRole') shows, so its reference-holding reads come first."""
    main = norm(op_noun(op)) == norm(ref.type.split(':', 1)[1])
    words = any(w in op for w in DETAIL_WORDS)
    if main:
        return 1 if listed else 0
    return (0 if listed else 1) if words else 2


def _cut(node: Any, claims: Callable[[str, str, Any], bool], key: str = '', parent: str = '') -> Any:
    """A copy of node without the list items `claims(list key, parent key, item)` takes. A claimed item's own lists
    are not looked into: they are parts of that resource."""
    if isinstance(node, dict):
        return {k: _cut(v, claims, k, key) for k, v in node.items()}
    if isinstance(node, list):
        return [_cut(x, claims, '', key) for x in node if not claims(key, parent, x)]
    return node


def plain(value: Any) -> Any:
    """SDK answers as plain JSON-able data: times as ISO text, bytes as text."""
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode(errors='replace')
    if hasattr(value, 'read'):
        return ''
    return value
