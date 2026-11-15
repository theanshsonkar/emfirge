"""A whole session with a fake bench: the command runs with the bench's environment, the report is printed even when
the command fails, and the exit code is the verdict's or the command's."""
from __future__ import annotations

import io
import json
import sys
import threading
from dataclasses import dataclass, field

import pytest

from emfirge.server.http import BranchServer
from emfirge.session import Output, end_remote, run, serve
from emfirge.session.command import exit_code, run_command
from emfirge.session.runner import env_lines

from .fakes import STORE, FakeHeld, created, deleted, parts, ref


@dataclass
class FakeBench:
    held: FakeHeld
    url: str = 'http://127.0.0.1:1'
    closed: bool = False
    server: BranchServer | None = None
    stops: list = field(default_factory=list)

    def client_env(self, base):
        return {**base, 'BRANCH_URL': self.url}

    def lens_endpoints(self):
        return ('', '')

    def close(self):
        self.closed = True
        if self.server:
            self.server.stop()


def opener(held: FakeHeld, bench_box: list):
    def open_bench(admin):
        bench = FakeBench(held)
        bench_box.append(bench)
        return bench, parts()
    return open_bench


def py(code: str) -> list[str]:
    return [sys.executable, '-c', code]


def test_the_command_gets_the_benchs_environment_and_go_exits_0(tmp_path):
    box, out = [], io.StringIO()
    seen = tmp_path / 'env.txt'
    code = run(opener(FakeHeld(), box), py(f'import os; open({str(seen)!r}, "w").write(os.environ["BRANCH_URL"])'),
               Output(), {'PATH': '/usr/bin'}, out)
    assert code == 0
    assert seen.read_text() == 'http://127.0.0.1:1'
    assert box[0].closed


def test_ask_exits_3_and_writes_the_json_report(tmp_path):
    report = tmp_path / 'r.json'
    out = io.StringIO()
    code = run(opener(FakeHeld([deleted(STORE)]), []), py('pass'), Output(report_path=report), {}, out)
    assert code == 3
    assert json.loads(report.read_text())['verdict'] == 'ask'
    assert out.getvalue().startswith('Verdict: ASK')


def test_a_failing_command_still_gets_a_report_and_its_own_code():
    out = io.StringIO()
    new = ref('store', 'fresh-one')
    code = run(opener(FakeHeld([created(new)], {new: {}}), []), py('import sys; sys.exit(5)'), Output(), {}, out)
    assert code == 64 + 5
    assert 'Your command failed (exit 5)' in out.getvalue()
    assert 'Created:' in out.getvalue()


def test_a_missing_command_is_127_as_a_shell_says():
    assert run_command(['/no/such/command-here'], {}) == 127
    assert exit_code(0, 127) == 125


@pytest.mark.parametrize('verdict,command,expected', [(0, 0, 0), (3, 0, 3), (3, None, 3), (0, 1, 65), (3, 61, 125),
                                                      (0, 200, 125), (3, -9, 125)])
def test_exit_codes(verdict, command, expected):
    assert exit_code(verdict, command) == expected


def test_the_bench_is_closed_when_judging_fails():
    box = []

    def open_bench(admin):
        bench = FakeBench(FakeHeld())
        bench.held.changes = lambda: (_ for _ in ()).throw(RuntimeError('engine gone'))
        box.append(bench)
        return bench, parts()
    with pytest.raises(RuntimeError):
        run(open_bench, py('pass'), Output(), {}, io.StringIO())
    assert box[0].closed


def test_env_lines_unset_what_was_removed_and_export_what_was_set():
    text = env_lines({'A': '1', 'B': 'x y'}, {'A': '1', 'C': 'secret'})
    assert text.splitlines() == ['unset C', "export B='x y'"]


def test_serve_prints_the_lines_and_seal_ends_it_with_the_report():
    out = io.StringIO()
    box: list = []

    def open_bench(admin):
        bench = FakeBench(FakeHeld([deleted(STORE)]))
        bench.server = BranchServer(bench.held, 0, admin).start()   # type: ignore[arg-type]
        bench.url = bench.server.url
        box.append(bench)
        return bench, parts()

    got = {}

    def seal_when_up():
        while not box or 'export BRANCH_URL' not in out.getvalue():
            threading.Event().wait(0.05)
        got['report'], got['code'] = end_remote(box[0].url)

    t = threading.Thread(target=seal_when_up)
    t.start()
    code = serve(open_bench, Output(), {}, out)
    t.join(10)
    assert code == 3 and got['code'] == 3
    assert got['report'].startswith('Verdict: ASK')
    assert 'export BRANCH_URL=' in out.getvalue()
