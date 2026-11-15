"""RealAccount: the owner's real AWS account as a core.ports.Account, for reads only.

The client's wire request arrives signed with dummy keys. It is decoded (AwsCodec), checked to be a read, and the
same call is made again by botocore with the owner's own credentials: botocore's credential chain, its endpoint
resolution for the service and region (global services, S3 addressing) and its SigV4 signing. The answer goes back
to the caller as it came off the wire.

Two keys must turn before anything reaches AWS: the branch wraps this account in its read-only door
(emfirge.branch.guard.ReadOnly), and this class checks again, on its own, that the catalog calls the call a read,
both before botocore builds the request and right before it is sent. A changing call never leaves this module.
Credentials are never logged, stored or put in an error message: botocore holds them.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Protocol

import botocore.awsrequest
import botocore.config
import botocore.exceptions
import botocore.session
import urllib3

from emfirge.core.model import Call, Kind, WireRequest, WireResponse
from emfirge.core.ports import CannotTell

from .accounts import HOP, _Raw
from .codec import AwsCodec


class NotARead(CannotTell):
    """A call that is not a read reached the real account's own check. Nothing was sent."""


class Kinds(Protocol):
    """What the second check asks: the catalog's kind of a call."""

    def kind(self, service: str, operation: str) -> Kind: ...


class RealAccount:
    """Reads on the real account with the owner's credentials.

    endpoint_url and ca are for tests only: they point every service at one local stand-in (AWS's emulator started
    with authentication on) instead of AWS. session: a botocore session (default: the owner's usual credential chain)."""

    def __init__(self, codec: AwsCodec, kinds: Kinds, region: str, session: botocore.session.Session | None = None,
                 endpoint_url: str | None = None, ca: str | None = None, timeout: float = 60.0) -> None:
        self.name = 'real AWS account' if endpoint_url is None else f'stand-in {endpoint_url}'
        self._codec, self._kinds, self._region = codec, kinds, region
        self._session = session or botocore.session.get_session()
        self._endpoint_url, self._ca = endpoint_url, ca
        self._http = urllib3.PoolManager(maxsize=8, timeout=urllib3.Timeout(connect=5, read=timeout),
                                         **({'cert_reqs': 'CERT_REQUIRED', 'ca_certs': ca} if ca else {}))
        self._clients: dict[str, Any] = {}
        self.sent = 0

    def send(self, request: WireRequest) -> WireResponse:
        call = self._codec.decode(request)
        self._check(call, request)
        client = self._client(call.service)
        captured: list[WireResponse] = []
        handler = self._sender(call, captured)
        client.meta.events.register_first('before-send', handler)
        try:
            client._make_api_call(call.operation, dict(call.params))
        except botocore.exceptions.ClientError:
            pass                       # an error answer is still an answer: it goes back to the caller as it came
        finally:
            client.meta.events.unregister('before-send', handler)
        if not captured:
            raise CannotTell(f'{call.name}: the real account gave no answer')
        return captured[0]

    def _check(self, call: Call | None, request: WireRequest) -> None:
        if call is None:
            raise NotARead(f'{request.method} {request.path} is not a call Emfirge can read; it was sent nowhere')
        if not self._kinds.kind(call.service, call.operation).reads_only:
            raise NotARead(f'{call.name} is not a read; the real account is only read')

    def _sender(self, call: Call, captured: list[WireResponse]) -> Any:
        """botocore's last step: send the signed request ourselves, after decoding the request botocore built and
        checking once more that it is the read that was asked for, and keep the raw answer."""
        def send(request: Any, **_: Any) -> botocore.awsrequest.AWSResponse:
            body = request.body.read() if hasattr(request.body, 'read') else request.body
            body = body.encode() if isinstance(body, str) else (body or b'')
            headers = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in request.headers.items()}
            url = urllib.parse.urlsplit(request.url)
            built = self._codec.decode(WireRequest(request.method, url.path or '/', url.query, headers, body))
            if built is None or built.operation != call.operation or \
                    not self._kinds.kind(built.service, built.operation).reads_only:
                raise NotARead(f'{call.name}: the request to send is not that read; nothing was sent')
            r = self._http.request(request.method, request.url, body=body or None, headers=headers,
                                   redirect=False, retries=False, preload_content=True)
            self.sent += 1
            answer = WireResponse(r.status, {k: v for k, v in r.headers.items() if k.lower() not in HOP}, r.data)
            captured.append(answer)
            return botocore.awsrequest.AWSResponse(request.url, r.status, dict(r.headers), _Raw(r.data))
        return send

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            cfg = botocore.config.Config(retries={'max_attempts': 1}, parameter_validation=False,
                                         s3={'addressing_style': 'path'} if self._endpoint_url else None)
            self._clients[service] = self._session.create_client(
                service, region_name=self._region, endpoint_url=self._endpoint_url, config=cfg,
                verify=self._ca if self._ca else None)
        return self._clients[service]

