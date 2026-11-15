"""The generic copier's calls: reads of the real account (through the branch's read-only door), writes to the engine,
and downloads a read handed out. One SDK client per account and service."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

import botocore.exceptions
from botocore import xform_name

from emfirge.core.model import WireRequest
from emfirge.core.ports import Account, CannotTell

from ..accounts import sdk_client
from ..errors import absent

MAX_BYTES = 1 << 20          # a downloaded blob or a streamed answer larger than this is not copied
MAX_DROPS = 8                # values the engine may refuse, one by one, before the write counts as refused
FAILURES = (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError)


@dataclass(frozen=True)
class Answer:
    operation: str
    params: dict[str, Any]
    body: dict[str, Any] | None       # None: the call failed
    absent: bool = False              # the service said the thing does not exist
    error: str = ''


class Clients:
    def __init__(self, region: str) -> None:
        self._region = region
        self._clients: dict[tuple[int, str], tuple[Account, Any]] = {}

    def client(self, account: Account, service: str) -> Any:
        key = (id(account), service)
        if key not in self._clients:
            self._clients[key] = (account, sdk_client(account, service, self._region))
        return self._clients[key][1]

    def read(self, account: Account, service: str, operation: str, params: dict[str, Any]) -> Answer:
        """One read; a failure is an answer too (absent, or an error the copy can report)."""
        try:
            body = getattr(self.client(account, service), xform_name(operation))(**params)
        except botocore.exceptions.ClientError as e:
            return Answer(operation, params, None, absent(e), _short(e))
        except (botocore.exceptions.ParamValidationError, CannotTell) as e:
            return Answer(operation, params, None, False, _short(e))
        return Answer(operation, params, plain(body))

    def write(self, account: Account, service: str, operation: str, params: dict[str, Any],
              required: frozenset[str], lost: Callable[[str], None]) -> dict[str, Any]:
        """One write. When the engine refuses a value it names (an attribute it does not take, a setting out of its
        range), that value is left out, said in `lost`, and the write is tried again. Raises the last failure."""
        params = dict(params)
        call = getattr(self.client(account, service), xform_name(operation))
        for _ in range(MAX_DROPS):
            try:
                return plain(call(**params))
            except FAILURES as e:
                named = refused_value(str(e), params, required)
                if named is None:
                    raise
                lost(f'{operation}: the engine refused {".".join(named)} ({_short(e)[:120]}), so it was left out')
                params = _without(params, named)
        return plain(call(**params))


def fetch(real: Account, url: str) -> bytes:
    """A download a read handed out (a function's code), through the real account's read-only door."""
    u = urlsplit(url)
    r = real.send(WireRequest('GET', u.path, u.query, {}, b''))
    if r.status >= 300:
        raise CannotTell(f'the download a read handed out failed ({r.status})')
    if len(r.body) > MAX_BYTES:
        raise CannotTell('the download a read handed out is too big to copy')
    return r.body


def plain(body: Any) -> Any:
    """An SDK answer without its metadata, with streamed bodies read (up to MAX_BYTES)."""
    if isinstance(body, dict):
        return {k: plain(v) for k, v in body.items() if k != 'ResponseMetadata'}
    if isinstance(body, list):
        return [plain(v) for v in body]
    if hasattr(body, 'read') and callable(body.read):
        data = body.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise CannotTell('a streamed answer is too big to copy')
        return data
    return body


def refused_value(message: str, params: dict[str, Any], required: frozenset[str]) -> tuple[str, ...] | None:
    """The optional member, or key of a map member, that an error message names (the longest name wins)."""
    names: list[tuple[str, ...]] = [(k,) for k in params if k not in required]
    names += [(k, sub) for k, v in params.items() if isinstance(v, dict) for sub in v]
    hits = [n for n in names if re.search(rf'(?<![A-Za-z]){re.escape(n[-1])}(?![a-z])', message)]
    return max(hits, key=lambda n: (len(n[-1]), len(n))) if hits else None


def _without(params: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    out = dict(params)
    if len(path) == 1:
        out.pop(path[0], None)
    else:
        inner = {k: v for k, v in out[path[0]].items() if k != path[1]}
        if inner:
            out[path[0]] = inner
        else:
            out.pop(path[0])
    return out


def _short(e: Exception) -> str:
    return str(e).replace('\n', ' ')[:200]
