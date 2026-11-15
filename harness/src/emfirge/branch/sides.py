"""The two places a branch can send a call: the real account (through the read-only door) and the engine (in the
engine's ids). Kept in one place so every call to either side is translated and decoded the same way."""
from __future__ import annotations

from typing import Any

from emfirge.core.model import Call, ResourceRef, WireResponse
from emfirge.core.ports import Account, CannotTell, Codec, Outcomes

from .baseline import Answer
from .guard import ReadOnly
from .ids import IdMap


class Sides:
    def __init__(self, codec: Codec, real: ReadOnly, engine: Account, ids: IdMap, outcomes: Outcomes | None) -> None:
        self.codec, self._real, self._engine, self.ids, self._outcomes = codec, real, engine, ids, outcomes

    def opaque(self, call: Call) -> bool:
        return bool(self._outcomes and self._outcomes.opaque(call))

    def real(self, call: Call) -> WireResponse:
        """The call as the client sent it, to the real account. Raises NotARead for anything but a read."""
        return self._real.send(call.wire)

    def engine_raw(self, call: Call) -> WireResponse:
        """The call in engine ids, to the engine; the answer still in engine ids."""
        return self._engine.send(self.ids.request_to_engine(call.wire, self.opaque(call)))

    def to_client(self, call: Call, response: WireResponse) -> WireResponse:
        return self.ids.response_to_client(response, self.opaque(call))

    def engine(self, call: Call) -> WireResponse:
        return self.to_client(call, self.engine_raw(call))

    def answer(self, call: Call, response: WireResponse) -> Answer:
        return Answer(response.status, self.codec.body(call, response))

    def engine_answer(self, call: Call) -> Answer:
        return self.answer(call, self.engine(call))

    def real_answer(self, call: Call) -> Answer:
        return self.answer(call, self.real(call))

    def about(self, ref: ResourceRef, call: Call, body: Any) -> Any:
        """The part of an answer that is about `ref`: its item when the answer is a list that holds it, else all."""
        if self._outcomes is None or not isinstance(body, (dict, list)):
            return body
        try:
            slots = self._outcomes.listed(call, body)
        except CannotTell:
            return body
        for s in slots:
            if ref in s.refs:
                return s.items[s.refs.index(ref)]
        return body
