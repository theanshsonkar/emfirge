"""Copy on touch: bring a real resource into the engine the first time a change names it, and keep its baselines.

This is the branch's side of core.ports.Placement: a copier asks for what must be there first (`need`), translates
values (`engine_value`) and records ids (`same`). Copies nest (a function needs its role); baselines are taken once
the outermost copy is done, so that what a nested copy did to an already-copied resource counts as copying, not as
the branch's change.
"""
from __future__ import annotations

from emfirge.core.model import ResourceRef
from emfirge.core.ports import Account, CannotTell, Catalog, Copier

from .baseline import Answer, Baseline, Baselines, noise_between
from .guard import NotARead
from .ids import IdMap
from .overlay import Overlay, State
from .sides import Sides


class CopyOnTouch:
    def __init__(self, copier: Copier, catalog: Catalog, overlay: Overlay, baselines: Baselines, sides: Sides,
                 ids: IdMap, real: Account, engine: Account) -> None:
        self._copier, self._catalog, self._overlay, self._baselines = copier, catalog, overlay, baselines
        self._sides, self._ids = sides, ids
        self.real, self.engine = real, engine
        self._busy: set[ResourceRef] = set()
        self._new: list[ResourceRef] = []
        self._touched: dict[ResourceRef, list[Answer]] = {}
        self.copies: dict[str, int] = {}

    # ---- core.ports.Placement
    def need(self, ref: ResourceRef) -> None:
        self.ensure(ref)

    def engine_value(self, value: str) -> str:
        return self._ids.translate(value, True)

    def same(self, real_id: str, engine_id: str) -> None:
        self._ids.add(real_id, engine_id)

    def known(self, real_id: str) -> bool:
        return self._ids.engine_id(real_id) is not None

    # ---- the branch's side
    def ensure(self, ref: ResourceRef) -> None:
        """Make `ref` something the engine can answer for. Raises CannotTell (and leaves it opaque) when it cannot."""
        state = self._overlay.state(ref)
        if state is State.OPAQUE:
            raise CannotTell(f'{ref} could not be copied earlier: {self._overlay.why_opaque(ref)}')
        if ref in self._busy:
            return
        if state is not State.LIVE:
            if state is State.COPIED and self._busy and ref not in self._new and ref not in self._touched:
                self._touched[ref] = self._engine_answers(ref)
            return
        self._busy.add(ref)
        try:
            self._copy(ref)
        finally:
            self._busy.discard(ref)
            if not self._busy:
                self._finish()

    def _copy(self, ref: ResourceRef) -> None:
        try:
            result = self._copier.copy(ref, self)
        except CannotTell as e:
            self._overlay.move(ref, State.OPAQUE, str(e))
            raise CannotTell(f'{ref} could not be copied: {e}') from e
        except Exception as e:   # a copier bug or an engine failure: the copy is not trustworthy
            why = f'{type(e).__name__}: {str(e)[:200]}'
            self._overlay.move(ref, State.OPAQUE, why)
            raise CannotTell(f'{ref} could not be copied: {why}') from e
        if not result.found:
            self._overlay.move(ref, State.ABSENT)
            return
        for r in (ref, *result.also):
            if self._overlay.state(r) is State.LIVE:
                self._overlay.move(r, State.COPIED)
                self._new.append(r)
                self.copies[r.type] = self.copies.get(r.type, 0) + 1

    def _finish(self) -> None:
        new, touched = self._new, self._touched
        self._new, self._touched = [], {}
        for ref in new:
            self._baselines.set(ref, self._take(ref))
        for ref, before in touched.items():
            self._baselines.fold(ref, before, self._engine_answers(ref))

    def _take(self, ref: ResourceRef) -> list[Baseline]:
        out = []
        for service, operation, params in self._catalog.reads_of(ref):
            call = self._sides.codec.encode(service, operation, params)
            try:
                r0 = self._sides.real_answer(call)
            except NotARead:
                continue
            e0, again = self._sides.engine_answer(call), self._sides.engine_answer(call)
            noise = noise_between(self._sides.about(ref, call, e0.body), self._sides.about(ref, call, again.body))
            out.append(Baseline(ref, call, e0, r0, noise))
        return out

    def _engine_answers(self, ref: ResourceRef) -> list[Answer]:
        return [self._sides.engine_answer(b.call) for b in self._baselines.of(ref)]
