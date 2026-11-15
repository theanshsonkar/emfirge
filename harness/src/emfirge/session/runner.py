"""One session, end to end: open a bench, let a command (`run`) or a person (`serve`) work on the branch, judge it,
print the report, give the exit code. The bench and the parts come from a cloud plug-in through `Opener`."""
from __future__ import annotations

import json
import shlex
import threading
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO

from .command import exit_code, run_command
from .judge import Judgement, Parts, judge
from .ports import Bench
from .report import as_json, as_text

Admin = Callable[[str, str, bytes], Any]
Opener = Callable[[tuple[tuple[str, Admin], ...]], tuple[Bench, Parts]]
"""Opens a bench (with extra admin routes on its endpoint) and gives the parts that judge it."""

SESSION_ROUTES = '/__emf-session/'
END = SESSION_ROUTES + 'end'
HANDOVER_SECONDS = 600.0


@dataclass(frozen=True)
class Output:
    show_all: bool = False
    report_path: Path | None = None


def run(open_bench: Opener, argv: Sequence[str], output: Output, base_env: Mapping[str, str], out: TextIO) -> int:
    """Run `argv` against a fresh branch, then judge it. The report is printed even when the command failed."""
    bench, parts = open_bench(())
    try:
        env = bench.client_env(base_env)
        code = run_command(argv, env)
        judgement = judge(bench.held, parts, _endpoints(bench, parts), env)
    finally:
        bench.close()
    return deliver(judgement, code, output, out)


def serve(open_bench: Opener, output: Output, base_env: Mapping[str, str], out: TextIO) -> int:
    """Serve a branch until Ctrl-C or `emf seal --url` (POST END), then judge it. Prints the lines to source first."""
    ended, judged = threading.Event(), threading.Event()
    handover: dict[str, Any] = {}

    def route(method: str, path: str, body: bytes) -> Any:
        if method != 'POST' or path != END:
            return None
        ended.set()
        judged.wait(HANDOVER_SECONDS)
        return handover or {'error': 'the session did not finish judging in time'}

    bench, parts = open_bench(((SESSION_ROUTES, route),))
    try:
        env = bench.client_env(base_env)
        out.write(f'# Emfirge branch at {bench.url}. Run this in your shell, then use your AWS tools as usual:\n')
        out.write(env_lines(env, base_env))
        out.write(f'# End with Ctrl-C here, or: emf seal --url {bench.url}\n')
        out.flush()
        _wait(ended)
        try:
            judgement = judge(bench.held, parts, _endpoints(bench, parts), env)
            handover.update(report=as_text(judgement, output.show_all), exit_code=judgement.decision.exit_code)
        except Exception as e:
            handover.update(error=f'{type(e).__name__}: {e}')
            raise
        finally:
            judged.set()
    finally:
        bench.close()
    return deliver(judgement, None, output, out)


def end_remote(url: str, timeout: float = HANDOVER_SECONDS) -> tuple[str, int]:
    """`emf seal --url`: end a served session and get its report and exit code."""
    request = urllib.request.Request(url.rstrip('/') + END, data=b'{}', method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as r:
        answer = json.loads(r.read())
    if 'error' in answer:
        raise RuntimeError(answer['error'])
    return answer['report'], int(answer['exit_code'])


def deliver(judgement: Judgement, command_code: int | None, output: Output, out: TextIO) -> int:
    out.write(as_text(judgement, output.show_all, command_code))
    if output.report_path is not None:
        output.report_path.write_text(as_json(judgement, command_code) + '\n')
    return exit_code(judgement.decision.exit_code, command_code)


def env_lines(env: Mapping[str, str], base: Mapping[str, str]) -> str:
    """Shell lines that turn `base` into `env`: unset what was removed, export what was set or changed."""
    lines = [f'unset {k}' for k in sorted(set(base) - set(env))]
    lines += [f'export {k}={shlex.quote(v)}' for k, v in sorted(env.items()) if base.get(k) != v]
    return '\n'.join(lines) + '\n'


def _endpoints(bench: Bench, parts: Parts) -> tuple[str, str]:
    return bench.lens_endpoints() if parts.outside else ('', '')


def _wait(ended: threading.Event) -> None:
    try:
        while not ended.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
