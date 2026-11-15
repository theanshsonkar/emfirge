"""Accounts that answer AWS wire requests over HTTP, and SDK clients that talk through any Account.

HttpAccount is one endpoint (the lab's emulators, moto). It forwards the request as the client sent it; it does not
sign. A real AWS account needs per-service endpoints and SigV4 signing with real credentials: that is a separate
Account, not built yet (the lab never contacts AWS).

sdk_client gives a boto3 client whose every request goes through an Account's `send` (botocore's own 'before-send'
hook answers it), so code written against boto3 (the curated copiers) keeps boto3's parsing, errors and waiters
while the read-only door of the real account stays in the path.
"""
from __future__ import annotations

from typing import Any, Iterator
import urllib.parse

import boto3
import botocore.awsrequest
import botocore.config
import urllib3

from emfirge.core.model import WireRequest, WireResponse
from emfirge.core.ports import Account

HOP = frozenset({'host', 'content-length', 'connection', 'accept-encoding', 'expect', 'transfer-encoding'})


class HttpAccount:
    """core.ports.Account for one HTTP(S) endpoint."""

    def __init__(self, name: str, url: str, ca: str | None = None, timeout: float = 60.0) -> None:
        self.name = name
        self.url = url.rstrip('/')
        self.ca = ca
        self._timeout = timeout
        self._pool: urllib3.PoolManager | None = None

    def _http(self) -> urllib3.PoolManager:
        if self._pool is None:
            tls = {'cert_reqs': 'CERT_REQUIRED', 'ca_certs': self.ca} if self.ca else {}
            self._pool = urllib3.PoolManager(maxsize=8, timeout=urllib3.Timeout(connect=5, read=self._timeout), **tls)
        return self._pool

    def send(self, request: WireRequest) -> WireResponse:
        target = self.url + request.path + ('?' + request.query if request.query else '')
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
        r = self._http().request(request.method, target, body=request.body or None, headers=headers,
                                 redirect=False, retries=False, preload_content=True)
        return WireResponse(r.status, dict(r.headers), r.data)


class _Raw:
    """What botocore reads an answer body from (whole, or as a stream for object downloads)."""

    def __init__(self, data: bytes) -> None:
        self._data, self._at = data, 0

    def stream(self, **_: Any) -> Iterator[bytes]:
        yield self._data

    def read(self, amt: int | None = None) -> bytes:
        end = len(self._data) if amt is None else self._at + amt
        out, self._at = self._data[self._at:end], min(end, len(self._data))
        return out

    def close(self) -> None:
        self._at = len(self._data)


def sdk_client(account: Account, service: str, region: str) -> Any:
    """A boto3 client for `service` whose requests go through `account.send` (and nowhere else)."""
    cfg = botocore.config.Config(retries={'max_attempts': 1}, s3={'addressing_style': 'path'})
    client = boto3.client(service, endpoint_url='https://emfirge.invalid', region_name=region,
                          aws_access_key_id='emfirge', aws_secret_access_key='emfirge', config=cfg)

    def send(request: Any, **_: Any) -> botocore.awsrequest.AWSResponse:
        url = urllib.parse.urlsplit(request.url)
        body = request.body
        body = body.read() if hasattr(body, 'read') else body
        body = body.encode() if isinstance(body, str) else (body or b'')
        headers = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()}
        r = account.send(WireRequest(request.method, url.path or '/', url.query, headers, body))
        return botocore.awsrequest.AWSResponse(request.url, r.status, r.headers, _Raw(r.body))

    client.meta.events.register('before-send', send)
    return client
