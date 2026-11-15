"""The local endpoint an agent's own AWS tools talk to. Every request goes to Branch.handle; admin routes under
/__emfirge/ show the branch's state, diff, log, unknowns and counters, and seal it."""
from __future__ import annotations

import dataclasses
import json
import threading
import urllib.parse
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from emfirge.branch import Branch
from emfirge.branch.lifecycle import IllegalMove
from emfirge.core.model import WireRequest, WireResponse

ADMIN = '/__emfirge/'
SKIP_HEADERS = frozenset({'content-length', 'transfer-encoding', 'connection', 'content-encoding', 'date', 'server'})

Admin = Callable[[str, str, bytes], Any]
"""(method, path, body) -> a JSON-able answer, or None when the path is not one of its routes."""


def admin_routes(branch: Branch) -> Admin:
    def route(method: str, path: str, body: bytes) -> Any:
        name = path[len(ADMIN):]
        if method == 'POST' and name == 'seal':
            branch.seal()
            return {'stage': branch.life.stage.value}
        if method != 'GET':
            return None
        if name == 'state':
            return {'stage': branch.life.stage.value, 'history': [s.value for s in branch.life.history]}
        if name == 'diff':
            return {'changes': branch.changes(), 'real_changed_since_copy': branch.drift()}
        if name == 'log':
            return list(branch.log())
        if name == 'unknowns':
            return list(branch.unknowns())
        if name == 'stats':
            return branch.stats()
        return None
    return route


def to_json(o: Any) -> Any:
    """core.model objects (dataclasses, enums, refs) as plain JSON."""
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {f.name: to_json(getattr(o, f.name)) for f in dataclasses.fields(o)}
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, dict):
        return {str(k): to_json(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set, frozenset)):
        return [to_json(v) for v in o]
    if isinstance(o, bytes):
        return o.decode(errors='replace')
    return o if isinstance(o, (str, int, float, bool)) or o is None else str(o)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True   # headers and body go out as separate writes: delayed ACKs would add ~40 ms
    branch: Branch
    admins: tuple[tuple[str, Admin], ...]

    def log_message(self, *args: Any) -> None:
        pass

    def _body(self) -> bytes:
        if self.headers.get('Content-Length'):
            return self.rfile.read(int(self.headers['Content-Length']))
        if 'chunked' in (self.headers.get('Transfer-Encoding') or '').lower():
            out = b''
            while n := int(self.rfile.readline().split(b';')[0].strip() or b'0', 16):
                out += self.rfile.read(n)
                self.rfile.readline()
            self.rfile.readline()
            return out
        return b''

    def _send(self, r: WireResponse) -> None:
        self.send_response(r.status)
        for k, v in r.headers.items():
            if k.lower() not in SKIP_HEADERS:
                self.send_header(k, v)
        length = next((v for k, v in r.headers.items() if k.lower() == 'content-length'), None) if self.command == 'HEAD' else None
        self.send_header('Content-Length', length or str(len(r.body)))   # a HEAD answer keeps the object's length
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(r.body)

    def _any(self) -> None:
        url = urllib.parse.urlsplit(self.path)
        body = self._body()
        for prefix, admin in self.admins:
            if url.path.startswith(prefix):
                return self._admin(admin, url.path, body)
        self._send(self.branch.handle(WireRequest(self.command, url.path, url.query, dict(self.headers), body)))

    def _admin(self, admin: Admin, path: str, body: bytes) -> None:
        try:
            out, status = admin(self.command, path, body), 200
        except IllegalMove as e:
            out, status = {'error': str(e)}, 409
        if out is None:
            out, status = {'error': f'no admin route {self.command} {path}'}, 404
        data = json.dumps(to_json(out), indent=1).encode()
        self._send(WireResponse(status, {'Content-Type': 'application/json'}, data))

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _any


class BranchServer:
    """A threading HTTP server for one branch, on 127.0.0.1."""

    def __init__(self, branch: Branch, port: int, extra_admin: tuple[tuple[str, Admin], ...] = ()) -> None:
        handler = type('Handler', (_Handler,), {'branch': branch, 'admins': ((ADMIN, admin_routes(branch)), *extra_admin)})
        self._httpd = ThreadingHTTPServer(('127.0.0.1', port), handler)
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None
        self.port = self._httpd.server_address[1]
        self.url = f'http://127.0.0.1:{self.port}'

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def start(self) -> 'BranchServer':
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
