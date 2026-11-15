"""The only door to the real account: it lets reads through and nothing else.

Why here and not in the plug-in: whatever a plug-in or a copier asks, the real account is wrapped once, by the
branch's own code, and a call passes only when the catalog says it only reads (Kind.READ or Kind.LIST). A call
the codec cannot read, or whose kind is unknown, never passes.
"""
from __future__ import annotations

from typing import Protocol

from emfirge.core.model import Kind, WireRequest, WireResponse
from emfirge.core.ports import Account, CannotTell, Codec


class Kinds(Protocol):
    def kind(self, service: str, operation: str) -> Kind: ...


class NotARead(CannotTell):
    """A call to the real account that is not a read. Raised before anything is sent."""


class ReadOnly:
    """An Account that forwards reads to `account` and refuses everything else."""

    def __init__(self, account: Account, codec: Codec, kinds: Kinds) -> None:
        self._account, self._codec, self._kinds = account, codec, kinds
        self.name = f'{account.name} (read only)'
        self.passed = 0
        self.blocked = 0

    def send(self, request: WireRequest) -> WireResponse:
        call = self._codec.decode(request)
        if call is None or not self._kinds.kind(call.service, call.operation).reads_only:
            self.blocked += 1
            what = call.name if call else f'{request.method} {request.path}'
            raise NotARead(f'{what} is not a read; the real account is only read')
        self.passed += 1
        return self._account.send(request)
