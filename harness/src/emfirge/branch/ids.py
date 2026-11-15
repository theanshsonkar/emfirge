"""The two-way id map between what the client sees and what the engine calls things.

Why: the engine gives its copies (and what is born on the branch) its own ids. The client must only ever see the
real account's ids, and for things born on the branch a stable alias in the same format, so a branch-born id can
never name something in the real account, now or later.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from typing import overload

from emfirge.core.model import WireRequest, WireResponse

_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_HEX_TAIL = re.compile(r'[0-9a-f]+$')


class IdMap:
    """client id <-> engine id, applied in one pass so that swapped ids cannot chain."""

    def __init__(self) -> None:
        self._to_engine: dict[str, str] = {}
        self._to_client: dict[str, str] = {}
        self._rx: dict[tuple[bool, bool], re.Pattern] = {}

    def add(self, client: str, engine: str) -> None:
        self._to_engine[client] = engine
        self._to_client[engine] = client
        self._rx.clear()

    def known_engine_id(self, engine: str) -> bool:
        return engine in self._to_client

    def engine_id(self, client: str) -> str | None:
        return self._to_engine.get(client)

    def pairs(self) -> dict[str, str]:
        return dict(self._to_engine)

    @overload
    def translate(self, data: str, to_engine: bool) -> str: ...
    @overload
    def translate(self, data: bytes, to_engine: bool) -> bytes: ...

    def translate(self, data, to_engine):
        if not data:
            return data
        pairs = {k: v for k, v in (self._to_engine if to_engine else self._to_client).items() if k != v}
        if not pairs:
            return data
        as_bytes = isinstance(data, bytes)
        key = (to_engine, as_bytes)
        if key not in self._rx:
            alts = '|'.join(re.escape(k) for k in sorted(pairs, key=len, reverse=True))
            self._rx[key] = re.compile(alts.encode() if as_bytes else alts)
        if as_bytes:
            table = {k.encode(): v.encode() for k, v in pairs.items()}
            return self._rx[key].sub(lambda m: table[m.group(0)], data)
        return self._rx[key].sub(lambda m: pairs[m.group(0)], data)

    def request_to_engine(self, request: WireRequest, opaque: bool) -> WireRequest:
        """The client's request in engine ids. An opaque payload (customer data) is left as it is."""
        return WireRequest(request.method, self.translate(request.path, True), self.translate(request.query, True),
                           request.headers, request.body if opaque else self.translate(request.body, True))

    def response_to_client(self, response: WireResponse, opaque: bool) -> WireResponse:
        """The engine's answer in client ids."""
        headers = {k: self.translate(v, False) for k, v in response.headers.items()}
        return WireResponse(response.status, headers, response.body if opaque else self.translate(response.body, False))


def alias_of(engine_id: str) -> str:
    """A stable client-side id for an id the engine gave out, in the same format: a UUID stays a UUID, a trailing
    run of hex digits is replaced by digits from a hash (engines count ids up; real accounts look random)."""
    if _UUID.fullmatch(engine_id):
        return str(uuid.UUID(hashlib.md5(engine_id.encode()).hexdigest()))
    return _HEX_TAIL.sub(lambda m: hashlib.sha1(engine_id.encode()).hexdigest()[:len(m.group(0))], engine_id)
