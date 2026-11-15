"""The HTTP endpoint: calls go to the branch, admin routes show its state and seal it."""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'branch'))
from branch_fakes import make, request  # noqa: E402

from emfirge.server.http import BranchServer  # noqa: E402


@pytest.fixture
def served():
    branch, real, engine, _ = make({'a': {'size': 1}})
    srv = BranchServer(branch, 0).start()
    yield srv, branch
    srv.stop()


def call(url: str, data: bytes | None = None, method: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_calls_reach_the_branch_and_admin_routes_report(served):
    srv, _ = served
    r = request('put', name='a', set={'size': 2})
    status, body = call(srv.url + '/', r.body, 'POST')
    assert status == 200 and json.loads(body)['size'] == 2
    assert json.loads(call(srv.url + '/__emfirge/state')[1])['stage'] == 'open'
    diff = json.loads(call(srv.url + '/__emfirge/diff')[1])
    assert diff['changes'][0]['ref'] == {'type': 'cloud:thing', 'id': 'a'} and diff['changes'][0]['type'] == 'modified'
    entry = json.loads(call(srv.url + '/__emfirge/log')[1])[0]
    assert (entry['service'], entry['operation'], entry['status']) == ('cloud', 'put', 200)
    assert entry['params'] == {'name': 'a', 'set': {'size': 2}} and entry['refs'] == [{'type': 'cloud:thing', 'id': 'a'}]
    assert json.loads(call(srv.url + '/__emfirge/states')[1])['cloud:thing/a']['get'] == {'name': 'a', 'size': 2}
    assert json.loads(call(srv.url + '/__emfirge/stats')[1])['held']['copied'] == 1
    assert json.loads(call(srv.url + '/__emfirge/unknowns')[1]) == []


def test_seal_then_every_call_is_refused_and_a_second_seal_conflicts(served):
    srv, branch = served
    assert json.loads(call(srv.url + '/__emfirge/seal', b'', 'POST')[1])['stage'] == 'sealed'
    status, body = call(srv.url + '/', request('get', name='a').body, 'POST')
    assert status == 400 and 'sealed' in json.loads(body)['message']
    assert call(srv.url + '/__emfirge/seal', b'', 'POST')[0] == 409
    assert call(srv.url + '/__emfirge/nothing')[0] == 404
    assert len(json.loads(call(srv.url + '/__emfirge/unknowns')[1])) == 1


def test_any_endpoint_can_be_served_and_gets_no_branch_routes():
    from emfirge.core.model import WireResponse

    class Echo:
        def handle(self, request):
            return WireResponse(200, {'content-type': 'text/plain'}, request.path.encode())

    srv = BranchServer(Echo(), 0).start()
    try:
        assert call(srv.url + '/hello')[1] == b'/hello'
        assert call(srv.url + '/__emfirge/state')[1] == b'/__emfirge/state'   # not an admin route: no branch here
    finally:
        srv.stop()
