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

from .model import Call, Change, Kind, Refs, ResourceRef, UndoFact, WireRequest, WireResponse


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


class Copier(Protocol):
    """Brings one real resource into the engine, so a change to it can run there."""

    def copy(self, ref: ResourceRef) -> 'CopyResult':
        """Raises CannotTell when the resource cannot be copied faithfully enough to answer changes."""


class CopyResult(Protocol):
    found: bool                          # False: the real account does not have it
    also: Iterable[ResourceRef]          # other resources copied with it (addressed through it, or needed by it)


class Reversibility(Protocol):
    """Says whether a change can be put back, from what the provider publishes about the resource type
    (does it hold data, is its id given by the service, are some settings write-only) and the kind of call."""

    def assess(self, change: Change) -> UndoFact: ...
