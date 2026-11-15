"""core.ports.Copier with no code per resource type: a real resource rebuilt in the engine from published data only.

One copy, step by step (the same for every type):
  1 read      the reads the catalog gives for the resource (catalog.reads_of), on the real account. The first one
              says whether it exists.
  2 create    an operation named after creating the type (plan.creates), filled from the answers by member names and
              shapes (fill.py). Nothing is written to the engine before this step can be filled: a type that cannot
              be planned raises CannotTell having written nothing, so another copier may try.
  3 refer     every resource the create names (the catalog's own refs of that call) is copied first (place.need),
              and every real id in it is written in the engine's ids.
  4 ids       the ids the engine gave out (in the create's answer, and id fields of the same read on both sides) are
              recorded (place.same); then the copy waits until its State/Status fields match the real ones.
  5 settings  each write that sets what a read shows (plan.settings) is replayed when the engine's answer to that
              read differs; a list (inline policies, attached policies, objects, aliases) is replayed item by item,
              with a detail read for each item where the write needs more than the list gives.
  6 compare   every read is asked of the engine too; what still differs is recorded in `notes` as what the copy lacks.

Lossy copies are allowed: reads of a copied resource lay the branch's change over the real account's live answer, so a
value the copy lacks is still read right. A change that depends on it may not be: the notes say what is missing.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import botocore.exceptions
from botocore import xform_name
from botocore.model import OperationModel

from emfirge.core.model import Call, Kind, Refs, ResourceRef
from emfirge.core.ports import CannotTell, Placement

from ..catalog import ResourceTypeInfo
from ..catalog.names import related, split
from ..codec import AwsCodec
from ..resource_words import binds, canonical, formats, list_word, names_type, noun_of, type_word, verb_of
from ..outcomes_generic import list_ops
from . import compare, contents, locate, plan
from .fill import Fetch, Filled, empty, fill, unwrap
from ..errors import UnknownType
from .sdk import Answer, Clients, fetch

URL_TAIL = re.compile(r'^https?://[^/]+/(?:[^?#]*/)?([^/?#]+)/?(?:[?#].*)?$')
MAX_ITEMS = 200           # a list longer than this is not replayed item by item
SETTLE_TRIES = 150        # 0.2 s apart


class Catalog(Protocol):
    def refs(self, call: Call) -> Refs: ...
    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]: ...
    def resource_type(self, type_: str) -> ResourceTypeInfo | None: ...
    def kind(self, service: str, operation: str) -> Kind: ...
    def parse_arn(self, value: str) -> ResourceRef | None: ...
    def types_of(self, prefix: str) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class Copied:
    found: bool
    also: tuple[ResourceRef, ...] = field(default=())
    notes: tuple[str, ...] = field(default=())     # what the copy lacks, in plain words (core.ports.CopyResult)
    faithful: frozenset[str] = field(default=frozenset())
    """Read operations that answer on the engine's copy as on the real account (checked after the copy). When its
    contents were copied and checked whole, also the reads the catalog leaves out (GetItem, HeadObject)."""


class GenericCopier:
    def __init__(self, catalog: Catalog, codec: AwsCodec, region: str,
                 sleep: Callable[[float], None] = time.sleep, *, copy_data: bool = False) -> None:
        """`copy_data`: the copier may read the customer's data from the real account (a table's items, an object's
        body) to copy it. Off by default: the owner decides. Names (a bucket's keys) are read either way."""
        self._catalog, self._codec, self._copy_data = catalog, codec, copy_data
        self._clients = Clients(region)
        self._sleep = sleep
        self.notes: dict[ResourceRef, list[str]] = {}

    def copy(self, ref: ResourceRef, place: Placement) -> Copied:
        lost: list[str] = []
        try:
            job = _Copy(self._catalog, self._codec, self._clients, self._sleep, ref, place, lost, self._copy_data)
            result = job.run()
            return Copied(result.found, result.also, tuple(lost), frozenset(job.faithful) if result.found else frozenset())
        finally:
            if lost:
                self.notes[ref] = lost

    def verify(self, ref: ResourceRef, place: Placement) -> tuple[frozenset[str], tuple[str, ...]]:
        """(faithful reads, notes) of a copy another copier made: the same reads and checks, nothing written."""
        lost: list[str] = []
        job = _Copy(self._catalog, self._codec, self._clients, self._sleep, ref, place, lost, self._copy_data)
        try:
            job.verify()
        except CannotTell as e:
            lost.append(f'not checked: {e}')
        return frozenset(job.faithful), tuple(lost)


class _Copy:
    """One copy of one resource (see the module docstring for the steps)."""

    def __init__(self, catalog: Catalog, codec: AwsCodec, clients: Clients, sleep: Callable[[float], None], ref: ResourceRef,
                 place: Placement, lost: list[str], copy_data: bool) -> None:
        self.catalog, self.codec, self.clients, self.sleep = catalog, codec, clients, sleep
        self.copy_data = copy_data
        self.placeholders = 0          # items rebuilt from their names only (no data read)
        self.data_left_out = False     # a contents read returns data, and reading data is switched off
        self.ref, self.place, self.lost = ref, place, lost
        self.info = catalog.resource_type(ref.type)
        self.delegated = set()
        self.faithful: set[str] = set()
        self.given = frozenset()

    # ------------------------------------------------------------------ 1-2: read, plan
    def run(self) -> Copied:
        if not self._read():
            return Copied(False)
        create, filled = self._plan()
        self._create(create, filled)
        paired = self._settings(create)
        self._replay_contents(paired)
        self._listed_with_it()
        self._settle()          # settings may have started an update (a function's LastUpdateStatus)
        self._compare(strict=True)
        self._contents_notes()
        return Copied(True)

    def verify(self) -> None:
        """Steps 1 and 6 only, for a copy another copier made."""
        if self._read():
            self._compare(strict=False)
            self._contents_notes()

    def _read(self) -> bool:
        """Step 1: the reads (and the contents reads) on the real account. False: the resource is not there."""
        reads = [r for r in self.catalog.reads_of(self.ref) if r[2]]
        if not reads and self.info is not None:
            listed, reads = self._reads_by_list()
            if listed and not reads:
                return False                  # its own list does not have it
        if not reads or self.info is None:
            raise UnknownType("AWS's lists give no read that shows this kind of resource, so Emfirge cannot copy it yet")
        self.service = reads[0][0]
        self.model = self.codec.model(self.service)
        answers = [self.clients.read(self.place.real, s, op, p) for s, op, p in reads if s == self.service]
        first = answers[0]
        if first.absent or (first.body is not None and _nothing(first.body) and _about_type(first, self.ref.type)):
            return False
        if first.body is None:
            raise CannotTell(f'the read {first.operation} failed on the real account ({first.error})')
        self.answers = [a for a in answers if a.body is not None]
        self.ids = self._ids(reads)
        self.answers += self._detail_reads()
        self.known = {op for _, op, _ in reads}
        self.contents = self._contents(set(self.known))
        self.answers += self.contents
        return True

    def _ids(self, reads: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        """The members that name the resource itself, as the reads name it (the first read's form wins)."""
        out: dict[str, Any] = {}
        for _, _, params in reads:
            for k, v in params.items():
                out.setdefault(k, v)
        return out

    def _reads_by_list(self) -> tuple[bool, list[tuple[str, str, dict[str, Any]]]]:
        """(listed, reads) for a type the catalog builds no read for: its ARN from its own list (locate.py)."""
        service = self.ref.type.split(':', 1)[0]
        try:
            self.codec.model(service)
        except botocore.exceptions.UnknownServiceError:
            return False, []      # the IAM prefix is not an SDK service name
        client = self.clients.client(self.place.real, service)
        for op in list_ops(self.codec, service, self.ref.type):
            name = xform_name(op)
            try:
                pages = client.get_paginator(name).paginate() if client.can_paginate(name) else iter([getattr(client, name)()])
                arn = locate.arn_of(iter(pages), self.ref, self.catalog.parse_arn)
            except Exception:     # a list this account cannot answer: try the next one
                continue
            model = self.codec.model(service)
            return True, [(service, op2, p) for op2, p in locate.reads_by_arn(model, self.ref.type, arn)] if arn else []
        return False, []

    def _contents(self, known: set[str]) -> list[Answer]:
        """What the resource holds, as its contents reads answer it (contents.py). A list of names (AWS's list kind:
        ListObjectsV2) is read always; a read that returns the data itself (Scan) only when reading data is switched
        on. More than one page is not copied: the copy is refused."""
        if not self.info.holds_data:
            return []
        known |= {a.operation for a in self.answers}
        out = []
        for op, params in contents.contents_reads(self.model, self.service, self.ref, self.ids, known,
                                                  self.catalog.kind, self._refs_of):
            if self.catalog.kind(self.service, op) is not Kind.LIST and not self.copy_data:
                self.data_left_out = True
                continue
            a = self.clients.read(self.place.real, self.service, op, params)
            if a.body is None or not contents.lists(a.body):
                continue
            if contents.more_pages(a.body) or any(len(v) > MAX_ITEMS for _, v in contents.lists(a.body)):
                raise CannotTell(f'it holds more data than Emfirge copies ({op} has more than one page)')
            out.append(a)
        return out

    def _reads_data(self, op: str, params: dict[str, Any]) -> bool:
        """The read returns customer data: a READ (not a list) on a resource that holds data, which the catalog leaves
        out of that resource's reads (its compile step leaves out exactly AWS's data-plane reads: GetObject, GetItem)."""
        if self.catalog.kind(self.service, op) is not Kind.READ:
            return False
        named = self._refs_of(self.service, op, params)
        for r in named.primary if named is not None else ():
            info = self.catalog.resource_type(r.type)
            if info is not None and info.holds_data and op not in {o for _, o, _ in self.catalog.reads_of(r)}:
                return True
        return False

    def _contents_notes(self) -> None:
        if self.placeholders:
            self.lost.append(f'the copy holds the names of its {self.placeholders} items, not their contents '
                             '(reading data is switched off)')
        if self.data_left_out:
            self.lost.append('the copy does not hold its items (reading them is switched off)')

    def _refs_of(self, service: str, op: str, params: dict[str, Any]) -> Refs | None:
        try:
            return self.catalog.refs(self.codec.encode(service, op, params))
        except Exception:
            return None

    def _replay_contents(self, paired: set[str]) -> None:
        """Contents no setting replayed are written back item by item (a later delete or scan must see them)."""
        for a in self.contents:
            if a.operation in paired:
                continue
            for key, _ in contents.lists(a.body):
                write = contents.item_write(self.model, a.operation, key)
                if write is not None:       # without one, the compare step decides (fewer items refuses the copy)
                    self._each(a, write, self._items(a, write, key) or [])

    def _detail_reads(self) -> list[Answer]:
        """Reads about the type that the catalog's reads do not cover, filled from what they answered (an IAM
        policy's document: GetPolicyVersion with GetPolicy's DefaultVersionId)."""
        done = {a.operation for a in self.answers}
        word = type_word(self.ref.type)
        out = []
        for op in self.model.operation_names:
            if op in done or verb_of(op) != 'Get' or not noun_of(op).startswith(word) or noun_of(op) == word:
                continue
            got = fill(self.model.operation_model(op).input_shape, [self.ids, *self._sources()])
            if got.params and not got.missing:
                a = self.clients.read(self.place.real, self.service, op, got.params)
                if a.body is not None and not _nothing(a.body):
                    out.append(a)
        return out

    def _plan(self) -> tuple[str, Filled]:
        words = frozenset({type_word(self.ref.type), *self._variable_words()}) - {''}
        candidates = plan.creates(self.model, words)
        if not candidates:
            raise UnknownType(f'no operation of {self.service} creates a {self.ref.type}, so Emfirge cannot copy it yet')
        tried = []
        for op in candidates:
            om = self.model.operation_model(op)
            filled = fill(om.input_shape, [self._own_names(om), *self._sources()])
            if not filled.missing:
                return op, filled
            tried.append(f'{op} needs {", ".join(filled.missing)}')
        raise UnknownType(f'no read answers what creating one needs ({"; ".join(tried[:2])}), so Emfirge cannot copy it '
                          'yet')

    def _variable_words(self) -> list[str]:
        return [split(f.variables[-1]).joined for f in formats(self.ref.type, self.info.arn_formats) if f.variables]

    def _own_names(self, om: OperationModel) -> dict[str, Any]:
        """The id itself, for the members of the create that carry the type's name (Name -> ${TopicName})."""
        out = dict(self.ids)
        if om.input_shape is None:
            return out
        for name in om.input_shape.required_members:
            if binds(name, self.ref.type, self.info.arn_formats, strong=2) and '/' not in self.ref.id:
                out.setdefault(name, self.ref.id)
        return out

    def _sources(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for a in self.answers:
            out += [unwrap(a.body, self.ref.type), a.body]
        return out

    # ------------------------------------------------------------------ 3-4: create, ids, settle
    given: frozenset[str] = frozenset()     # the top-level members the create set (not made up by the service)
    delegated: set[tuple[str, str]]         # (read, list) whose items were each copied on their own

    def _create(self, op: str, filled: Filled) -> None:
        """Create the copy, unless the engine already has it: what every account has (the default event bus, the
        default schedule group) is in the engine too. Only for a caller-chosen id: an id the service gave out may
        name something else in the engine."""
        mine = self._engine_read(self.answers[0]) if self.info.id_given_by_service is not True else None
        if mine is not None and mine.body is not None and not _nothing(mine.body):
            self._settle()
            return
        params = self._resolve(op, filled, strict=True)
        self.given = frozenset(params)
        self._write_only(op, params)
        om = self.model.operation_model(op)
        answer = self.clients.write(self.place.engine, self.service, op, params,
                                    frozenset(om.input_shape.required_members), self.lost.append)
        engine_id = self._engine_id(answer)
        if engine_id and engine_id != self.ref.id:
            self.place.same(self.ref.id, engine_id)
        self._settle()

    def _write_only(self, op: str, params: dict[str, Any]) -> None:
        """Settings AWS publishes as write-only (a password, a secret's value given at create) that the create takes
        and no read gave: the copy has none, and says so."""
        shape = self.model.operation_model(op).input_shape
        members = {m.lower(): m for m in shape.members} if shape else {}
        for setting in self.info.write_only_settings:
            name = members.get(setting.split('/', 1)[0].lower())
            if name and name not in params:
                self.lost.append(f'{name} is write-only (AWS never shows it), so the copy has no value for it')

    def _resolve(self, op: str, filled: Filled, strict: bool = False) -> dict[str, Any]:
        """Downloads fetched, what the call names copied first, real ids written in the engine's ids. `strict` (the
        create): what it names must be copied, or the copy is refused; an untranslated real id could name another
        thing in the engine."""
        params = _replace_fetches(filled.params, lambda f: fetch(self.place.real, f.url))
        names = self.catalog.refs(self.codec.encode(self.service, op, params)).all + self._named_by_members(params)
        for other in dict.fromkeys(names):
            if other == self.ref or other.type == self.ref.type and other.id == self.ref.id:
                continue
            try:
                self.place.need(other)
            except CannotTell as e:
                if strict:
                    raise CannotTell(f'it names {other}, which could not be copied') from e
                self.lost.append(f'{op} names {other}, which could not be copied ({str(e)[:160]})')
        return _translate(params, self.place.engine_value)

    def _named_by_members(self, params: dict[str, Any]) -> tuple[ResourceRef, ...]:
        """Other resources of the same service named by a member called exactly like their ARN variable
        (EventBusName -> an event bus, FunctionName in a mapping -> a function): the catalog binds only the members
        AWS's list ties to the call's own resource."""
        out = []
        for t in self.catalog.types_of(self.ref.type.split(':', 1)[0]):
            info = self.catalog.resource_type(t)
            if t == self.ref.type or info is None:
                continue
            for name, value in params.items():
                if binds(name, self.ref.type, self.info.arn_formats, strong=5):
                    continue      # UserName in CreateUser names the user itself, not a federated user
                for v in value if isinstance(value, list) else [value]:
                    if isinstance(v, str) and v and not v.startswith('arn:') and binds(name, t, info.arn_formats, strong=5):
                        out.append(ResourceRef(t, v))
        return tuple(out)

    def _engine_id(self, answer: dict[str, Any]) -> str | None:
        """The id the engine gave the copy: an ARN of the type in the create's answer, or the field that carries
        the type's ARN variable (VpcId, GroupId, UUID, a hosted zone's Id)."""
        found = []
        for path, value in compare.leaves(answer):
            if not isinstance(value, str) or not path:
                continue
            if value.startswith('arn:'):
                r = self.catalog.parse_arn(value)
                if r is not None and r.type == self.ref.type:
                    return r.id
            for name in _field_names(path):
                var = binds(name, self.ref.type, self.info.arn_formats)
                if var:
                    value = URL_TAIL.sub(r'\1', value)      # a queue's URL: the name is its last part
                    found.append(canonical(self.info.arn_formats, self.ref.type, var, value))
        if not found and self.info.id_given_by_service:     # a bare 'id' at the top (API Gateway's CreateRestApi)
            found = [v for k, v in answer.items() if isinstance(v, str)
                     and binds(k, self.ref.type, self.info.arn_formats, strong=2)]
        return found[0] if found else None

    def _engine_read(self, answer: Answer) -> Answer:
        params = _translate(answer.params, self.place.engine_value)
        return self.clients.read(self.place.engine, self.service, answer.operation, params)

    def _settle(self) -> None:
        """Record the engine's own ids for the resource; wait until its states match the real ones."""
        first = self.answers[0]
        want = compare.states(unwrap(first.body, self.ref.type))
        for _ in range(SETTLE_TRIES):
            mine = self._engine_read(first)
            if mine.absent:
                raise CannotTell(f'the engine does not find the copy by its id ({mine.error[:120]})')
            if mine.body is not None:
                self._adopt_ids(first.body, mine.body)
                got = compare.states(unwrap(mine.body, self.ref.type))
                if all(got.get(k) == v for k, v in want.items()):
                    return
            self.sleep(0.2)
        self.lost.append(f'the copy did not reach the real state ({want})')

    def _adopt_ids(self, real: Any, engine: Any) -> None:
        """Ids the engine gave the copy (or its versions) instead of the real ones, and values the service made up
        for it (a distribution's domain name): what the create did not set."""
        real, engine = unwrap(real, self.ref.type), unwrap(engine, self.ref.type)
        pairs = compare.new_ids(real, engine, type_word(self.ref.type)) + compare.generated(real, engine, self.given)
        for real_id, engine_id in pairs:
            if not self.place.known(real_id):
                self.place.same(real_id, engine_id)

    # ------------------------------------------------------------------ 5: settings and lists
    def _settings(self, create: str) -> set[str]:
        """Replays each setting; returns the reads whose settings were paired with a write."""
        by_op = {a.operation: a for a in self.answers}
        paired = set()
        for s in plan.settings(self.model, list(by_op), create):
            paired.add(s.read)
            answer = by_op[s.read]
            if _nothing(answer.body):
                continue
            items = self._items(answer, s.write, s.item)
            if items is None:
                self._setting(answer, s.write)
            else:
                self._each(answer, s.write, items)
        return paired

    def _items(self, answer: Answer, write: str, item: str = '') -> list[dict[str, Any]] | None:
        """The answer's list, item by item, when the write takes one item of it (not the whole list). `item`: the
        list must be named after it (a profile's Roles for AddRoleToInstanceProfile)."""
        body = unwrap(answer.body, self.ref.type)
        shape = self.model.operation_model(write).input_shape
        members = {m.lower() for m in shape.members} if shape else set()
        lists = [(k, v) for k, v in body.items() if isinstance(v, list) and v]
        if item:
            lists = [(k, v) for k, v in lists if k == item or any(related(w, item) for w in list_word(k))]
        if len(lists) != 1 or lists[0][0].lower() in members:
            return [] if item else None
        key, values = lists[0]
        if len(values) > MAX_ITEMS:
            self.lost.append(f'{answer.operation}: more than {MAX_ITEMS} items, not copied')
            return []
        return [{**v, _singular(key): v} if isinstance(v, dict) else {_singular(key): v} for v in values]

    def _setting(self, answer: Answer, write: str) -> None:
        """Replayed only when the engine's answer differs in what the write sets (not in what only the service
        writes, such as a revision id or a last-update status)."""
        sources = [self.ids, unwrap(answer.body, self.ref.type), answer.body]
        filled = fill(self.model.operation_model(write).input_shape, sources).params
        sets = {p[-1] for p, _ in compare.leaves(filled) if p} | set(filled)
        sets -= set(self.ids)
        mine = self._engine_read(answer)
        if mine.body is not None:
            real, engine = unwrap(answer.body, self.ref.type), unwrap(mine.body, self.ref.type)
            if not set(compare.differences(real, engine, self.place.engine_value)) & sets:
                return
        self._send(write, sources)

    def _each(self, answer: Answer, write: str, items: list[dict[str, Any]]) -> None:
        """Each item the engine does not have yet (the first version of a policy came with its create)."""
        mine = self._engine_read(answer)
        have = self._items(mine, write) if mine.body is not None else []
        for item in items:
            if any(compare.same_item(item, other, self.place.engine_value) for other in have or []):
                continue
            sources: list[Any] = [item, self.ids]
            for detail in plan.details(self.model, write):
                got = fill(self.model.operation_model(detail).input_shape, [item, self.ids])
                if not got.missing and not self.copy_data and self._reads_data(detail, got.params):
                    self.placeholders += 1        # its name only: the write goes without the data
                    break
                if not got.missing:
                    d = self.clients.read(self.place.real, self.service, detail, got.params)
                    if d.body is not None:
                        sources += [unwrap(d.body), d.body]
                    break
            result = self._send(write, sources)
            if result is not None:
                for real_id, engine_id in compare.new_ids(item, unwrap(result), noun_of(write)):
                    if not self.place.known(real_id):
                        self.place.same(real_id, engine_id)

    def _send(self, write: str, sources: list[Any]) -> dict[str, Any] | None:
        """One setting write. When the answers do not fill it, there is nothing to set (the compare step still says
        what the copy lacks)."""
        om = self.model.operation_model(write)
        filled = fill(om.input_shape, sources)
        if filled.missing:
            return None
        if not self._about_me(write, filled.params):
            return None
        try:
            params = self._resolve(write, filled)
            return self.clients.write(self.place.engine, self.service, write, params,
                                      frozenset(om.input_shape.required_members), self.lost.append)
        except Exception as e:   # a setting the engine refuses: the copy goes on without it, and says so
            self.lost.append(f'{write}: {type(e).__name__}: {str(e)[:160]}')
            return None

    def _about_me(self, write: str, params: dict[str, Any]) -> bool:
        """The write acts on this resource (the catalog places it here), not on another one it mentions."""
        try:
            refs = self.catalog.refs(self.codec.encode(self.service, write, _replace_fetches(params, lambda f: b'')))
        except Exception:
            return False
        return self.ref in refs.primary or (not refs.primary and self.ref in refs.mentioned)

    def _listed_with_it(self) -> None:
        """What a read of it lists, by the item's own ARN or by the id of the type the list is named after (the
        instance profiles a role is in, a function's event source mappings), is copied too: the engine can only
        refuse what depends on them (deleting the role) when it has them."""
        for a in self.answers:
            if verb_of(a.operation) != 'List':
                continue
            for key, values in {**a.body, **unwrap(a.body, self.ref.type)}.items():
                refs = [self._own_arn(key, v) or self._listed_id(key, v) for v in values] if isinstance(values, list) else []
                refs = [r for r in refs if r is not None and r.type != self.ref.type]
                if refs and len(refs) == len(values) and all(self._need(a.operation, r) for r in refs):
                    self.delegated.add((a.operation, key))   # each item is its own copy (maybe still on the way)

    def _need(self, operation: str, other: ResourceRef) -> bool:
        try:
            self.place.need(other)
            return True
        except CannotTell as e:
            self.lost.append(f'{operation} lists {other}, which could not be copied ({str(e)[:160]})')
            return False

    def _own_arn(self, key: str, item: Any) -> ResourceRef | None:
        """The ARN a list item carries as its own (Arn, or <item>Arn), as a resource."""
        if not isinstance(item, dict):
            return None
        for k, v in item.items():
            words = split(k)
            if isinstance(v, str) and words.designator == 'arn' and \
                    (not words.words or any(related(words.joined, w) for w in list_word(key))):
                return self.catalog.parse_arn(v)
        return None

    def _listed_id(self, key: str, item: Any) -> ResourceRef | None:
        """The item's id, when the list is named exactly after a type of the service (EventSourceMappings -> its
        UUID)."""
        if not isinstance(item, dict):
            return None
        for t in self.catalog.types_of(self.ref.type.split(':', 1)[0]):
            info = self.catalog.resource_type(t)
            if info is None or t == self.ref.type or type_word(t) not in list_word(key):
                continue
            for k, v in item.items():
                var = binds(k, t, info.arn_formats) if isinstance(v, str) else None
                if var:
                    return ResourceRef(t, canonical(info.arn_formats, t, var, v))
        return None

    # ------------------------------------------------------------------ 6: what the copy lacks
    def _compare(self, strict: bool) -> None:
        """What the copy lacks, in notes, and which reads answer alike on both sides (`faithful`). `strict` (a copy
        this copier made): a list the engine shows fewer items of (records of a zone, resources of an API,
        subscriptions) means parts of the resource were not copied, and a change to it could be answered wrong, so
        the copy is refused; so is a number the engine made up for it."""
        for a in self.answers:
            mine = self._engine_read(a)
            if mine.body is not None:
                self._adopt_ids(a.body, mine.body)
                mine = self._engine_read(a)
            if mine.body is None:
                self.lost.append(f'{a.operation}: the engine has no answer ({mine.error[:100]})')
                continue
            real, engine = unwrap(a.body, self.ref.type), unwrap(mine.body, self.ref.type)
            diff = compare.differences(real, engine, self.place.engine_value)
            if diff:
                self.lost.append(f'{a.operation}: differs in {", ".join(diff[:6])}')
            invented = compare.invented_numbers(real, engine, self.given) if a is self.answers[0] else []
            if invented and strict:
                raise CannotTell(f'the engine made up values for its copy that Emfirge cannot show as the real ones '
                                 f'({", ".join(invented[:3])})')
            short = [s for s in compare.fewer_items(real, engine) + compare.fewer_items(a.body, mine.body)
                     if (a.operation, s.split(':', 1)[0]) not in self.delegated]
            if short and strict:
                raise CannotTell(f'the copy lacks parts of it that Emfirge cannot rebuild yet ({a.operation}: '
                                 f'{", ".join(short[:3])})')
            if not diff and not short and not invented:
                self.faithful.add(a.operation)
        self._data_reads_faithful()

    def _data_reads_faithful(self) -> None:
        """The contents were copied with their data and every contents read answers alike: the reads of its data
        that the catalog leaves out (a table's GetItem, a bucket's HeadObject) answer alike too. Never for a copy
        holding names only, or no contents: those reads go to the real account, or are refused once changed."""
        if not self.info.holds_data or not self.contents or self.placeholders or self.data_left_out or \
                any(a.operation not in self.faithful for a in self.contents):
            return
        self.faithful |= set(contents.data_reads(self.model, self.service, self.ref, self.ids, self.known,
                                                 self.catalog.kind, self._refs_of))


# ---------------------------------------------------------------------- helpers
def _nothing(body: Any) -> bool:
    """An answer with no content (a Describe... of something that does not exist answers an empty list)."""
    return isinstance(body, dict) and all(empty(v) for v in body.values())


def _about_type(answer: Answer, type_: str) -> bool:
    """The read is named after the type (DescribeVpcs for a VPC): its empty answer means the thing is not there."""
    return names_type(noun_of(answer.operation), type_)


def _field_names(path: tuple[str, ...]) -> list[str]:
    """A field's own name, and its name joined to its parent's (HostedZone.Id -> HostedZoneId)."""
    names = [k for k in path if not k.isdigit()]
    if not names:
        return []
    out = [names[-1]]
    if len(names) > 1:
        out.append(names[-2] + names[-1][:1].upper() + names[-1][1:])
    return out


def _singular(key: str) -> str:
    """'PolicyNames' -> 'PolicyName': the name one item of a list of plain strings has."""
    return key[:-1] if key.endswith('s') else key


def _replace_fetches(value: Any, get: Any) -> Any:
    if isinstance(value, Fetch):
        return get(value)
    if isinstance(value, dict):
        return {k: _replace_fetches(v, get) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_fetches(v, get) for v in value]
    return value


def _translate(value: Any, to_engine: Any) -> Any:
    """Every string with the real ids the engine knows by another id replaced (bytes are customer data: kept)."""
    if isinstance(value, str):
        return to_engine(value)
    if isinstance(value, dict):
        return {k: _translate(v, to_engine) for k, v in value.items()}
    if isinstance(value, list):
        return [_translate(v, to_engine) for v in value]
    return value
