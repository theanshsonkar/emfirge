"""Who answers a call: one pure decision, no I/O.

Default deny: a change reaches the engine only when every resource it names is in a state the engine can answer
for. A change that names a live resource is first copied (COPY, then decide again). Anything else is refused with
plain words, never guessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from emfirge.core.model import Kind, Refs, ResourceRef

from .overlay import ENGINE_ANSWERS, State


class Way(str, Enum):
    REAL = 'real'                # the real account answers, live
    ENGINE = 'engine'            # the engine answers
    MERGED_LIST = 'merged_list'  # the real list, minus what the branch holds, plus the engine's items for those
    TRANSPLANT = 'transplant'    # the real account's live answer with the branch's own change laid over it
    COPY = 'copy'                # copy these live resources into the engine, then decide again
    REFUSE = 'refuse'            # cannot tell


@dataclass(frozen=True)
class Route:
    way: Way
    refs: tuple[ResourceRef, ...] = ()
    reason: str = ''


def route(kind: Kind, refs: Refs, state_of: Callable[[ResourceRef], State], *, changed_nearby: bool) -> Route:
    """The way for one call. `changed_nearby`: the branch holds a change to a resource of the call's own service,
    which a read naming something unidentifiable might show. A read of a copied resource is a TRANSPLANT even
    when it has no body (a HEAD): the branch then decides as for a read with no copy-time answer."""
    if kind is Kind.UNKNOWN:
        return Route(Way.REFUSE, refs.all, 'it is not known what this call changes (it may run code, or change '
                                           'something the branch cannot see), so it was sent nowhere')
    opaque = tuple(r for r in refs.all if state_of(r) is State.OPAQUE)
    if opaque:
        return Route(Way.REFUSE, opaque, 'it names a resource the branch could not copy')
    if kind.reads_only:
        return _read(refs, state_of, changed_nearby)
    return _change(refs, state_of)


def _read(refs: Refs, state_of: Callable[[ResourceRef], State], changed_nearby: bool) -> Route:
    if not refs.complete and changed_nearby:
        return Route(Way.REFUSE, refs.all, 'it is not known which resource this read names, and the branch holds '
                                           'changes it might show')
    if not refs.primary:
        return Route(Way.MERGED_LIST)
    states = [state_of(r) for r in refs.primary]
    if all(s is State.LIVE for s in states):
        return Route(Way.REAL, refs.primary)
    live = tuple(r for r, s in zip(refs.primary, states) if s is State.LIVE)
    if live:
        return Route(Way.COPY, live)
    if states[0] is State.COPIED:
        return Route(Way.TRANSPLANT, refs.primary)
    return Route(Way.ENGINE, refs.primary)


def _change(refs: Refs, state_of: Callable[[ResourceRef], State]) -> Route:
    if not refs.complete:
        return Route(Way.REFUSE, refs.all, 'it is not known which resource this change acts on (Emfirge does not '
                                           'know this kind of resource yet), so the branch cannot place it')
    live = tuple(r for r in refs.all if state_of(r) is State.LIVE)
    if live:
        return Route(Way.COPY, live)
    assert all(state_of(r) in ENGINE_ANSWERS for r in refs.all)   # live and opaque were handled above
    return Route(Way.ENGINE, refs.all)
