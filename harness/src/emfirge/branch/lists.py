"""Merged lists: the real list, minus what the branch holds, plus the engine's items for those. Pure.

Why: a list call names no single resource, so neither side alone is right once the branch holds something the list
can show. Items of copied resources get the same lay-over as reads: the real item with the branch's change on it.
"""
from __future__ import annotations

import copy
from typing import Any, Callable

from emfirge.core.model import Listed, ResourceRef
from emfirge.core.ports import CannotTell

from . import transplant
from .overlay import ENGINE_ANSWERS, State

ItemBaseline = Callable[[ResourceRef, tuple[str, ...]], Any]
"""(resource, list path) -> its item in the engine's list right after the copy, or None."""


def relevant(slots: list[Listed], held_types: frozenset[str]) -> list[Listed]:
    """The lists that can show something the branch holds."""
    return [s for s in slots if s.types & held_types]


def merge(real_body: Any, real_slots: list[Listed], engine_slots: list[Listed],
          state_of: Callable[[ResourceRef], State], baseline_item: ItemBaseline) -> Any:
    """The real answer with each relevant list replaced by its merged list."""
    out = copy.deepcopy(real_body)
    by_path = {s.path: s for s in engine_slots}
    for slot in real_slots:
        mine = by_path.get(slot.path)
        if None in slot.refs or (mine is not None and None in mine.refs):
            raise CannotTell('the branch holds resources this list can show, and cannot tell which items are its own')
        keep = [i for i, r in zip(slot.items, slot.refs) if state_of(r) not in ENGINE_ANSWERS]
        add = []
        for item, ref in zip(mine.items, mine.refs) if mine else ():
            if state_of(ref) in ENGINE_ANSWERS:
                add.append(_item(ref, item, slot, state_of, baseline_item))
        out = set_at(out, slot.path, keep + add)
    return out


def _item(ref: ResourceRef, item: Any, slot: Listed, state_of: Callable[[ResourceRef], State],
          baseline_item: ItemBaseline) -> Any:
    if state_of(ref) is not State.COPIED:
        return item
    e0 = baseline_item(ref, slot.path)
    real = next((i for i, r in zip(slot.items, slot.refs) if r == ref), None)
    if e0 is None or real is None or not transplant.structured(e0, item, real):
        return item
    return transplant.lay(e0, item, real)


def item_of(slots: list[Listed], ref: ResourceRef, path: tuple[str, ...]) -> Any:
    """`ref`'s item in the list at `path`, or None."""
    for s in slots:
        if s.path == path:
            return next((i for i, r in zip(s.items, s.refs) if r == ref), None)
    return None


def set_at(body: Any, path: tuple[str, ...], value: Any) -> Any:
    """`body` with `value` at `path`, making the containers on the way where the answer had an empty element."""
    if not path:
        return value
    out = body if isinstance(body, dict) else {}
    cur = out
    for k in path[:-1]:
        if not isinstance(cur.get(k), dict):
            cur[k] = {}
        cur = cur[k]
    cur[path[-1]] = value
    return out
