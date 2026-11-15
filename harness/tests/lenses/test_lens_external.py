"""Outside tools as lenses: the toy scanner runs as a subprocess against two tiny local HTTP stubs (the real account
and the branch). Only findings the branch has and the real account lacks are reported."""
from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from emfirge.lenses import ExternalLens, LensView, json_records, run_lenses, text_lines

SCANNER = str(Path(__file__).resolve().parents[2] / 'examples' / 'lenses' / 'toy_scanner.py')
PORTS = range(9650, 9700)

REAL = {'buckets': [{'name': 'old-open', 'public': True}, {'name': 'feed', 'public': False}]}
BRANCH = {'buckets': [{'name': 'old-open', 'public': True}, {'name': 'feed', 'public': True, 'encrypted': False}]}


@contextmanager
def stub(state):
    """A local HTTP server answering /state.json, on the first free port of 9650-9699."""
    body = json.dumps(state).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = None
    for port in PORTS:
        try:
            server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
            break
        except OSError:
            continue
    assert server is not None, 'no free port in 9650-9699'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()


def toy(**kw):
    return ExternalLens('toy', (sys.executable, '-I', SCANNER), json_records(('check', 'resource'), 'message', {'status': 'FAIL'}), **kw)


def test_only_what_the_branch_adds_is_reported():
    with stub(REAL) as real, stub(BRANCH) as branch:
        r = run_lenses([toy()], LensView((), real, branch, {}))
    assert [(f.code, f.detail['key'], f.message) for f in r.findings] == [
        ('toy.new', 'bucket_public | feed', 'feed is public'),
        ('toy.new', 'bucket_unencrypted | feed', 'feed is not encrypted'),
    ]
    assert r.unknowns == ()


def test_the_same_account_on_both_sides_gives_nothing():
    with stub(REAL) as a, stub(REAL) as b:
        assert run_lenses([toy()], LensView((), a, b, {})).findings == ()


def test_files_work_as_endpoints_too(tmp_path):
    before, after = tmp_path / 'before.json', tmp_path / 'after.json'
    before.write_text(json.dumps(REAL))
    after.write_text(json.dumps(BRANCH))
    assert len(run_lenses([toy()], LensView((), str(before), str(after), {})).findings) == 2


def test_timeout_is_an_unknown(tmp_path):
    (tmp_path / 's.json').write_text('{}')
    r = run_lenses([toy(timeout=0.5)], LensView((), str(tmp_path / 's.json'), str(tmp_path / 's.json'), {'TOY_SLEEP': '5'}))
    assert r.findings == ()
    assert len(r.unknowns) == 2 and all('did not finish' in u.what for u in r.unknowns)


def test_non_zero_exit_is_an_unknown_unless_declared_ok(tmp_path):
    (tmp_path / 's.json').write_text('{}')
    view = LensView((), str(tmp_path / 's.json'), str(tmp_path / 's.json'), {'TOY_EXIT': '3'})
    assert all('exited with 3' in u.what for u in run_lenses([toy()], view).unknowns)
    assert run_lenses([toy(ok_exit_codes=frozenset({0, 3}))], view).unknowns == ()


def test_unreadable_output_is_an_unknown(tmp_path):
    lens = ExternalLens('echo', (sys.executable, '-c', 'print("not json")'), json_records(('id',)))
    r = run_lenses([lens], LensView((), 'a', 'b', {}))
    assert r.unknowns and 'could not be read' in r.unknowns[0].what


def test_missing_endpoint_is_an_unknown():
    r = run_lenses([toy()], LensView(()))
    assert 'needs both endpoints' in r.unknowns[0].what


def test_text_lines_parser():
    script = 'import os; print("ok-1"); print("open:" + os.environ["AWS_ENDPOINT_URL"])'
    lens = ExternalLens('lines', (sys.executable, '-c', script), text_lines())
    r = run_lenses([lens], LensView((), 'real', 'branch', {}))
    assert [f.message for f in r.findings] == ['open:branch']


@pytest.mark.parametrize('layout', ['array', 'lines'])
def test_prowler_style_records(layout):
    """The parser in examples/lenses/prowler_lens.py, on OCSF-shaped records (as experiment 04 read them)."""
    def rec(code, uid, status):
        return {'status_code': status, 'metadata': {'event_code': code}, 'resources': [{'uid': uid}], 'status_detail': f'{code} on {uid}'}
    records = [rec('s3_bucket_public_access', 'arn:aws:s3:::feed', 'FAIL'), rec('s3_bucket_default_encryption', 'arn:aws:s3:::feed', 'PASS')]
    text = json.dumps(records) if layout == 'array' else '\n'.join(json.dumps(r) for r in records)
    parse = json_records(('metadata.event_code', 'resources.0.uid'), 'status_detail', {'status_code': 'FAIL'})
    assert parse(text) == {'s3_bucket_public_access | arn:aws:s3:::feed': 's3_bucket_public_access on arn:aws:s3:::feed'}
