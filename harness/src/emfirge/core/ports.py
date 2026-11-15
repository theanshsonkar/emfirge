"""The plug boundaries. A cloud plug-in implements Codec, Catalog, Copier and gives two Accounts (the real one,
read-only; and an engine, a fake that answers changes). Everything else in Emfirge is written against these and
knows no cloud.

Rules every implementation keeps:
  * No answer is ever invented. What cannot be told raises CannotTell; the branch turns it into a refusal the
    client's own tools understand (Codec.refusal), never into a guess.
  * The real account is only read. ReadOnly (emfirge.branch.guard) wraps it; a plug-in never gets the raw one.
"""
from __future__ import annotations

from typing import Any, Iterable, Protocol, runtime_checkable

from .model import Call, Change, Kind, Listed, Refs, ResourceRef, UndoFact, WireRequest, WireResponse


class CannotTell(Exception):
    """Emfirge cannot answer this truthfully. Carries plain words for the person and the agent."""


@runtime_checkable
class Account(Protocol):
    """Anything that answers wire requests of one cloud: the real account, or a fake."""
    name: str

    def send(self, request: WireRequest) -> WireResponse: ...


@runtime_checkable
class Engine(Account, Protocol):
    """A fake account that answers changes. Swappable: nothing above this may depend on which fake it is."""

    def start(self) -> None: ...
    def stop(self) -> None: ...


class Codec(Protocol):
    """Wire traffic <-> Calls and structured bodies, for one cloud."""

    def decode(self, request: WireRequest) -> Call | None:
        """None when the request is not a call of this cloud that the codec can read."""

    def encode(self, service: str, operation: str, params: dict[str, Any]) -> Call:
        """A call the way the cloud's own SDK would send it (used for the branch's own reads)."""

    def body(self, call: Call, response: WireResponse) -> Any:
        """The answer as plain nested data (dict / list / str), whatever the wire format."""

    def render(self, call: Call, response: WireResponse, body: Any) -> WireResponse:
        """The inverse of body(): the same response with a changed body, in the original wire format."""

    def refusal(self, call: Call | None, request: WireRequest, message: str) -> WireResponse:
        """'I cannot tell', in the error shape this client's protocol expects, marked as not retryable."""


class Catalog(Protocol):
    """What the cloud provider publishes about its own calls and resources. Compiled, not hand-written."""

    def kind(self, service: str, operation: str) -> Kind: ...

    def refs(self, call: Call) -> Refs: ...

    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]:
        """(service, operation, params) of the reads that show this resource's state. May be empty."""


class Placement(Protocol):
    """What a copier gets from the branch while it copies. The branch owns ids and resource states, and hands out the
    real account only behind its read-only door."""
    real: Account      # the real account, read only
    engine: Account    # the branch's engine (ids untranslated: the copier records them with `same`)

    def need(self, ref: ResourceRef) -> None:
        """Make sure `ref` is on the branch before going on (copy it, or accept it as already there).
        Raises CannotTell when it cannot be."""

    def engine_value(self, value: str) -> str:
        """`value` with every real id the engine knows by another id replaced by the engine's id."""

    def same(self, real_id: str, engine_id: str) -> None:
        """Record that the engine calls this real id `engine_id`."""

    def known(self, real_id: str) -> bool:
        """True when an engine id was recorded for this real id."""


class Copier(Protocol):
    """Brings one real resource into the engine, so a change to it can run there."""

    def copy(self, ref: ResourceRef, place: Placement) -> 'CopyResult':
        """Raises CannotTell when the resource cannot be copied faithfully enough to answer changes."""


class CopyResult(Protocol):
    found: bool                          # False: the real account does not have it
    also: Iterable[ResourceRef]          # other resources copied with it (addressed through it, or needed by it)


class Outcomes(Protocol):
    """What a cloud's answers mean for a branch. Optional for a plug-in: without it a branch refuses list answers
    that mix its own resources with the account's, and tracks only resources that calls name."""

    def listed(self, call: Call, body: Any) -> list[Listed]:
        """The lists in a list answer. Raises CannotTell when the answer is one page of several."""

    def born(self, call: Call, body: Any) -> tuple[ResourceRef, ...]:
        """Resources in a change's answer whose id the service gave out (the caller did not choose it)."""

    def removes(self, call: Call) -> bool:
        """The call deletes the resource it acts on, even when the service finishes the deletion later."""

    def opaque(self, call: Call) -> bool:
        """The call's request or answer payload is the customer's data (an object, a blob): never rewrite it."""

    def shape(self, call: Call) -> str | None:
        """A name for the structure of the call's answer: calls with the same name answer alike (a change that
        answers with the resource's new state can then be laid over the real state, like a read)."""


class Reversibility(Protocol):
    """Says whether a change can be put back, from what the provider publishes about the resource type
    (does it hold data, is its id given by the service, are some settings write-only) and the kind of call."""

    def assess(self, change: Change) -> UndoFact: ...
