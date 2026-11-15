"""The words every part of Emfirge shares. Pure data: no I/O, no cloud SDK.

A cloud plug-in (emfirge.aws is the first) turns its wire traffic into these, and everything above the
plug-in (branch, graph, lenses, gate) works on these only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Kind(str, Enum):
    """What a call does, as the cloud provider's own published list says. UNKNOWN is never treated as a read."""
    READ = 'read'
    LIST = 'list'
    WRITE = 'write'
    PERMISSION = 'permission'   # changes who may do what
    TAGGING = 'tagging'
    UNKNOWN = 'unknown'

    @property
    def reads_only(self) -> bool:
        return self in (Kind.READ, Kind.LIST)


@dataclass(frozen=True)
class ResourceRef:
    """One thing in an account, named the same way whichever call mentions it.
    type is '<service>:<resource type>' in the provider's own vocabulary (aws: 'lambda:function'); id is the
    provider's stable key for it (aws: the name or id part; the catalog decides, callers never parse it)."""
    type: str
    id: str

    def __str__(self) -> str:
        return f'{self.type}/{self.id}'


@dataclass(frozen=True)
class WireRequest:
    method: str
    path: str
    query: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class WireResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Call:
    """One decoded request. `wire` is what the client sent, untouched."""
    service: str
    operation: str
    params: Mapping[str, Any]
    kind: Kind
    wire: WireRequest

    @property
    def name(self) -> str:
        return f'{self.service}.{self.operation}'


@dataclass(frozen=True)
class Refs:
    """Which resources a call names.
    primary    the resource(s) the call acts on
    mentioned  other resources named anywhere in its parameters (a role passed to a function, ...)
    complete   False when the catalog could not tell which resource a changing call acts on. The branch must then
               refuse the call: it never forwards a change it cannot place."""
    primary: tuple[ResourceRef, ...] = ()
    mentioned: tuple[ResourceRef, ...] = ()
    complete: bool = True

    @property
    def all(self) -> tuple[ResourceRef, ...]:
        return self.primary + tuple(r for r in self.mentioned if r not in self.primary)


@dataclass(frozen=True)
class Listed:
    """One list inside a list answer, and which resource each of its items is.
    path   where the list sits in the answer's plain nested data (keys from the top)
    items  the items, in order
    refs   the resource each item is, or None where the plug-in cannot tell
    types  the resource types this list can hold (a branch holding one of them must merge, or refuse)"""
    path: tuple[str, ...]
    items: tuple[Any, ...]
    refs: tuple[ResourceRef | None, ...]
    types: frozenset[str] = frozenset()


class ChangeType(str, Enum):
    CREATED = 'created'
    MODIFIED = 'modified'
    DELETED = 'deleted'
    ACTION = 'action'    # a changing call that is not a setting of a resource (invoke, send, start, ...)


@dataclass(frozen=True)
class FieldChange:
    path: str            # where in the resource's state, e.g. 'Environment.Variables.DRY_RUN'
    before: Any = None
    after: Any = None


@dataclass(frozen=True)
class Change:
    """What the branch holds for one resource, at state level (not call level)."""
    ref: ResourceRef
    type: ChangeType
    fields: tuple[FieldChange, ...] = ()
    calls: tuple[str, ...] = ()      # the changing calls that touched it, in order ('lambda.UpdateFunctionConfiguration')


@dataclass(frozen=True)
class Unknown:
    """Something Emfirge could not tell. Unknowns are facts too: they are shown, and they stop an automatic go-ahead."""
    what: str                         # plain words
    where: str = ''                   # 'branch' | 'graph' | 'lens:<name>' | 'gate'
    ref: ResourceRef | None = None


@dataclass(frozen=True)
class Affected:
    """Something outside the change that the change reaches."""
    ref: ResourceRef
    because: str                      # the evidence in plain words: 'its policy names the bucket'
    via: tuple[ResourceRef, ...] = () # the chain from the changed resource, empty for a direct link
    strength: str = 'strong'          # 'strong' (an exact id, ARN or address) | 'weak' (a bare name, a wildcard)


@dataclass(frozen=True)
class Finding:
    """One fact from a lens. A lens reports only what the change makes new."""
    lens: str                         # 'data' | 'public' | 'money' | 'permissions' | '<your tool>'
    code: str                         # stable, machine-readable
    message: str                      # plain words
    refs: tuple[ResourceRef, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)


class Undo(str, Enum):
    YES = 'yes'            # the change can be put back exactly, and that was established, not assumed
    NO = 'no'              # something would be lost or come back different (data, a new id, a secret)
    UNKNOWN = 'unknown'    # Emfirge cannot tell; treated like NO by the gate


@dataclass(frozen=True)
class UndoFact:
    """Can this change be put back? With the reasons, each a fact from a published source or from a test on the branch."""
    ref: ResourceRef
    undo: Undo
    reasons: tuple[str, ...] = ()     # plain words: 'deleting a bucket loses the objects inside it'
