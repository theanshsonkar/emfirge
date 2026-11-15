"""core.ports.Copier from the hand-written types: experiment 09's copy functions, behind the port."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from emfirge.core.model import ResourceRef
from emfirge.core.ports import Account, CannotTell, Placement

from ..accounts import sdk_client
from ..errors import UnknownType
from .context import CopyContext
from .naming import Naming, Unplaced
from .spec import Where


@dataclass(frozen=True)
class Copied:
    found: bool
    also: tuple[ResourceRef, ...] = field(default=())


class CuratedCopier:
    def __init__(self, naming: Naming, where: Where, copy_data: bool = False) -> None:
        self._naming, self._where, self._copy_data = naming, where, copy_data
        self._clients: dict[tuple[int, str], tuple[Account, Any]] = {}

    def copy(self, ref: ResourceRef, place: Placement) -> Copied:
        spec = self._naming.specs.get(ref.type)
        if spec is None or spec.copy is None:
            raise UnknownType(f'nothing can copy a {ref.type} yet')
        x = CopyContext(place, self._where, self._client, self._recognize, self._copy_data)
        found = spec.copy(x, ref.id)
        return Copied(found, tuple(x.also))

    def _recognize(self, value: str) -> ResourceRef | None:
        r = self._naming.recognize(value)
        if isinstance(r, Unplaced):
            raise CannotTell(f'nothing can copy what {value} names yet')
        return r

    def _client(self, account: Account, service: str) -> Any:
        """One SDK client per account and service (making one takes tens of milliseconds)."""
        key = (id(account), service)
        if key not in self._clients:
            self._clients[key] = (account, sdk_client(account, service, self._where.region))
        return self._clients[key][1]
