"""The branch: one object that answers an agent's calls as if they ran on the real account, without changing it.

It composes the parts and holds all of a branch's state, so two branches can live in one process. Nothing here
knows a cloud: wire traffic goes through the Codec, what a call names and does through the Catalog (and the optional
Outcomes), copies through the Copier.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import replace
from typing import Any

from emfirge.core.model import Call, Change, Refs, ResourceRef, Unknown, WireRequest, WireResponse
from emfirge.core.ports import Account, CannotTell, Catalog, Codec, Copier, Outcomes

from . import diff, lists, transplant
from .baseline import Answer, Baseline, Baselines
from .guard import ReadOnly
from .ids import IdMap, alias_of
from .journal import Entry, Journal
from .lifecycle import Lifecycle, Stage
from .overlay import Overlay, State
from .router import Route, Way, route
from .sides import Sides
from .touch import CopyOnTouch

log = logging.getLogger(__name__)

ADVICE = ('Nothing was changed. You can leave this step out, or make it in the real account yourself after the '
          'branch is reviewed.')


class Branch:
    def __init__(self, codec: Codec, catalog: Catalog, copier: Copier, real: Account, engine: Account,
                 outcomes: Outcomes | None = None) -> None:
        self._codec, self._catalog, self._outcomes = codec, catalog, outcomes
        self.real = ReadOnly(real, codec, catalog)
        self.life = Lifecycle()
        self.overlay = Overlay()
        self.ids = IdMap()
        self.journal = Journal()
        self.baselines = Baselines()
        self._sides = Sides(codec, self.real, engine, self.ids, outcomes)
        self._touch = CopyOnTouch(copier, catalog, self.overlay, self.baselines, self._sides, self.ids,
                                  self.real, engine)
        self._unknowns: list[Unknown] = []
        self._counts: dict[str, int] = {}
        self._refusals: dict[str, int] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ calls
    def handle(self, request: WireRequest) -> WireResponse:
        """Answer one wire request. Never raises: what cannot be told is refused in the client's own error shape."""
        with self._lock:
            call = None
            try:
                call = self._decode(request)
                if not self.life.accepting:
                    raise CannotTell(f'the branch is {self.life.stage.value} and takes no more calls. Open a new branch')
                return self._answer(call)
            except CannotTell as e:
                return self._refuse(call, request, str(e))
            except Exception as e:   # a failure of the branch itself is also something it cannot tell
                log.exception('branch failure')
                return self._refuse(call, request, f'the branch failed: {type(e).__name__}: {str(e)[:200]}')

    def _decode(self, request: WireRequest) -> Call:
        call = self._codec.decode(request)
        if call is None:
            raise CannotTell('it is not known which operation this request is, so it was sent nowhere')
        return replace(call, kind=self._catalog.kind(call.service, call.operation))

    def _answer(self, call: Call) -> WireResponse:
        refs = self._catalog.refs(call)
        way = self._route(call, refs)
        if way.way is Way.COPY:
            for ref in way.refs:
                self._touch.ensure(ref)
            way = self._route(call, refs)
        self._count(way.way.value)
        if way.way is Way.REFUSE:
            raise CannotTell(self._reason(way))
        if way.way is Way.REAL:
            return self._sides.real(call)
        if way.way is Way.MERGED_LIST:
            return self._merged_list(call)
        if way.way is Way.TRANSPLANT:
            return self._transplant(call, way.refs[0])
        if call.kind.reads_only:
            return self._sides.engine(call)
        return self._change(call, refs)

    def _route(self, call: Call, refs: Refs) -> Route:
        return route(call.kind, refs, self.overlay.state, changed_anything=self.overlay.changed_anything(),
                     head=call.wire.method == 'HEAD')

    def _reason(self, way: Route) -> str:
        why = [f'{r}: {self.overlay.why_opaque(r)}' for r in way.refs if self.overlay.why_opaque(r)]
        return way.reason + (f' ({"; ".join(why)})' if why else '')

    # ------------------------------------------------------------------ reads
    def _transplant(self, call: Call, ref: ResourceRef) -> WireResponse:
        """The real account's live answer with the branch's change (E0 -> E1) laid over it."""
        e1 = self._sides.engine(call)
        base = self.baselines.find(ref, call)
        if base is None:
            self._count('transplant_miss')
            return e1
        r = self._sides.real(call)
        e0, a1, ar = base.e0, self._sides.answer(call, e1), self._sides.answer(call, r)
        if not e0.ok and a1.status == e0.status:
            self._count('transplanted')   # refused before and after: nothing changed on the branch
            return r
        if not (e0.ok and a1.ok and ar.ok and transplant.structured(e0.body, a1.body, ar.body)):
            self._count('transplant_skipped')
            return e1
        self._count('transplanted')
        return self._codec.render(call, e1, transplant.lay(e0.body, a1.body, ar.body))

    def _merged_list(self, call: Call) -> WireResponse:
        r = self._sides.real(call)
        held = self.overlay.held_types()
        if r.status >= 300 or not held:
            return r
        body = self._codec.body(call, r)
        if not isinstance(body, (dict, list)):
            return r
        if self._outcomes is None:
            raise CannotTell('the branch holds changes, and this plug-in cannot say which list items are its own')
        real_slots = lists.relevant(self._outcomes.listed(call, body), held)
        if not real_slots:
            self._count('list_passthrough')
            return r
        e = self._sides.engine(call)
        if e.status >= 300:
            raise CannotTell(f'the engine refused a list the real account answered ({e.status})')
        engine_slots = self._outcomes.listed(call, self._codec.body(call, e))
        merged = lists.merge(body, real_slots, engine_slots, self.overlay.state,
                             lambda ref, path: self._item_baseline(call, ref, path))
        self._count('merged')
        return self._codec.render(call, r, merged)

    def _item_baseline(self, call: Call, ref: ResourceRef, path: tuple[str, ...]) -> Any:
        base = self.baselines.find(ref, call)
        if base is None or not base.e0.ok or self._outcomes is None:
            return None
        return lists.item_of(self._outcomes.listed(base.call, base.e0.body), ref, path)

    # ------------------------------------------------------------------ changes
    def _change(self, call: Call, refs: Refs) -> WireResponse:
        raw = self._sides.engine_raw(call)
        born: tuple[ResourceRef, ...] = ()
        if raw.status < 300:
            self._settle(call, refs)
            born = self._adopt_born(call, raw)
            if not refs.all and not born:
                self._unknowns.append(Unknown(f'{call.name} changed something on the branch that it cannot name',
                                              'branch'))
        self.journal.add(call.name, dict(call.params), raw.status, refs.all, born)
        return self._sides.to_client(call, raw)

    def _settle(self, call: Call, refs: Refs) -> None:
        """After a change: which named resources now exist on the branch, and which do not."""
        removed = set()
        if self._outcomes is not None and self._outcomes.removes(call):
            for ref in refs.primary:
                if self.overlay.state(ref) in (State.COPIED, State.BORN):
                    self.overlay.move(ref, State.DELETED)
                    removed.add(ref)
        for ref in refs.all:
            if ref in removed:
                continue
            exists = self._exists(ref)
            state = self.overlay.state(ref)
            if exists is True and state in (State.ABSENT, State.DELETED):
                self.overlay.move(ref, State.BORN)
            elif exists is False and state in (State.COPIED, State.BORN):
                self.overlay.move(ref, State.DELETED)

    def _exists(self, ref: ResourceRef) -> bool | None:
        reads = self._catalog.reads_of(ref)
        if not reads:
            return None
        return self._sides.engine_answer(self._codec.encode(*reads[0])).ok

    def _adopt_born(self, call: Call, raw: WireResponse) -> tuple[ResourceRef, ...]:
        """Resources the engine created with ids it gave out: the client sees a stable alias for each."""
        if self._outcomes is None:
            return ()
        out = []
        for ref in dict.fromkeys(self._outcomes.born(call, self._codec.body(call, raw))):
            if self.ids.known_engine_id(ref.id) or self.overlay.state(ref) is not State.LIVE:
                continue
            alias = alias_of(ref.id)
            self.ids.add(alias, ref.id)
            mine = ResourceRef(ref.type, alias)
            self.overlay.move(mine, State.ABSENT)
            self.overlay.move(mine, State.BORN)
            out.append(mine)
        return tuple(out)

    # ------------------------------------------------------------------ refusals
    def _refuse(self, call: Call | None, request: WireRequest, what: str) -> WireResponse:
        name = call.name if call else f'{request.method} {request.path}'
        self._unknowns.append(Unknown(f'{name}: {what}', 'branch'))
        self._refusals[what[:120]] = self._refusals.get(what[:120], 0) + 1
        self._count('refused')
        return self._codec.refusal(call, request, f'Emfirge cannot tell: {what}. {ADVICE}')

    def _count(self, what: str) -> None:
        self._counts[what] = self._counts.get(what, 0) + 1

    # ------------------------------------------------------------------ the branch's report
    def seal(self) -> None:
        with self._lock:
            self.life.move(Stage.SEALED)

    def move(self, to: Stage) -> None:
        with self._lock:
            self.life.move(to)

    def changes(self) -> list[Change]:
        with self._lock:
            return diff.changes(self.overlay.held(), self.overlay.from_real(), self.baselines.all(),
                                self._now(self._sides.engine_answer), self._about, self.journal)

    def drift(self) -> list[Change]:
        """What changed in the real account under the branch since each copy."""
        with self._lock:
            return diff.drift(self.baselines.all(), self._now(self._sides.real_answer), self._about)

    def _now(self, read) -> diff.Now:
        return lambda b: read(b.call)

    def _about(self, b: Baseline, body: Any) -> Any:
        return self._sides.about(b.ref, b.call, body)

    def log(self) -> tuple[Entry, ...]:
        return self.journal.entries()

    def unknowns(self) -> tuple[Unknown, ...]:
        return tuple(self._unknowns)

    def stats(self) -> dict[str, Any]:
        return {'routes': dict(self._counts), 'copies': dict(self._touch.copies), 'refusals': dict(self._refusals),
                'real_reads': self.real.passed, 'real_blocked': self.real.blocked,
                'held': {s.value: sum(1 for x in self.overlay.held().values() if x is s) for s in State}}

    def copy(self, ref: ResourceRef) -> State:
        """Copy one resource without changing it (for measuring how faithful copies are)."""
        with self._lock:
            self._touch.ensure(ref)
            return self.overlay.state(ref)
