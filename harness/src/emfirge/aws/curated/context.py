"""What a hand-written copy function may use: SDK clients on the real account (read only, through the branch's
door) and on the engine, and the branch's placement (copy what this needs first, translate ids, record ids)."""
from __future__ import annotations

import time
from typing import Any, Callable
from urllib.parse import urlsplit

import botocore.exceptions

from emfirge.core.model import ResourceRef, WireRequest
from emfirge.core.ports import CannotTell, Placement

from ..errors import absent
from .spec import Where


class CopyContext:
    def __init__(self, place: Placement, where: Where, clients: Callable[[Any, str], Any],
                 recognize: Callable[[str], ResourceRef | None], copy_data: bool = False) -> None:
        self._place, self.where, self._clients, self._recognize = place, where, clients, recognize
        self.copy_data = copy_data     # the copy may read the customer's data (items, object bodies): the owner decides
        self.also: list[ResourceRef] = []

    @property
    def region(self) -> str:
        return self.where.region

    @property
    def account(self) -> str:
        return self.where.account

    def real(self, service: str) -> Any:
        return self._clients(self._place.real, service)

    def engine(self, service: str) -> Any:
        return self._clients(self._place.engine, service)

    def find(self, call: Callable[..., Any], **kw: Any) -> Any:
        """The answer, or None when the service says the thing does not exist."""
        try:
            return call(**kw)
        except botocore.exceptions.ClientError as e:
            if absent(e):
                return None
            raise

    def ref(self, value: str) -> str:
        """Copy what `value` names first (when it is ours), and return `value` in the engine's ids."""
        r = self._recognize(value)
        if r is not None:
            self._place.need(r)
        return self._place.engine_value(value)

    def need(self, type_: str, key: str) -> None:
        self._place.need(ResourceRef(type_, key))

    def tr(self, value: str) -> str:
        """Translate ids only; do not copy (for references the service does not check)."""
        return self._place.engine_value(value)

    def same(self, real_id: str, engine_id: str) -> None:
        self._place.same(real_id, engine_id)

    def known(self, real_id: str) -> bool:
        return self._place.known(real_id)

    def adopt(self, type_: str, key: str) -> None:
        """Say that copying this also copied that (subnets and groups with their VPC)."""
        self.also.append(ResourceRef(type_, key))

    def fetch(self, url: str) -> bytes:
        """A download a read handed out (a function's code), through the real account's read-only door."""
        u = urlsplit(url)
        r = self._place.real.send(WireRequest('GET', u.path, u.query, {}, b''))
        if r.status >= 300:
            raise CannotTell(f'the download a read handed out failed ({r.status})')
        return r.body

    def wait(self, service: str, waiter: str, **kw: Any) -> None:
        self.engine(service).get_waiter(waiter).wait(WaiterConfig={'Delay': 0.2, 'MaxAttempts': 150}, **kw)

    def settle(self, read: Callable[[], dict], field: str, busy: tuple[str, ...], tries: int = 150) -> None:
        """Wait until the engine's copy leaves its transitional states, as the real one already has."""
        for _ in range(tries):
            if read().get(field) not in busy:
                return
            time.sleep(0.2)
        raise CannotTell(f'the copy did not settle ({field})')

