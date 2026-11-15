"""Any outside tool as a lens, with no code of ours per tool.

The tool runs twice, unchanged: once pointed at the real account (read-only) and once at the branch. Each output is
parsed into finding keys; what the branch has and the real account does not is what the change makes new. A problem
the account already had appears in both runs and is not reported. Experiment 04 did exactly this by hand with an
unmodified scanner: 8 new failures after a risky change.
"""
from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from emfirge.core.model import Finding, Unknown

from .api import LensResult, LensView
from .builtin.patterns import ENDPOINT_VAR

Parser = Callable[[str], Mapping[str, str]]
"""A tool's output -> {finding key: plain words}. Raises ValueError when the output cannot be read."""


@dataclass(frozen=True)
class ExternalLens:
    """name          the lens name (findings carry it)
    command          the tool's command line, run as is
    parser           turns one output into finding keys (json_records, text_lines, or your own)
    endpoint_var     the variable that points the tool at an account
    timeout          seconds per run
    ok_exit_codes    exit codes that mean 'ran' (scanners often exit non-zero when they found something)"""
    name: str
    command: Sequence[str]
    parser: Parser
    endpoint_var: str = ENDPOINT_VAR
    timeout: float = 300.0
    ok_exit_codes: frozenset[int] = frozenset({0})

    def look(self, view: LensView) -> LensResult:
        if not (view.before_endpoint and view.after_endpoint):
            return LensResult(unknowns=(self._unknown('needs both endpoints (the real account and the branch); not run'),))
        with ThreadPoolExecutor(max_workers=2) as pool:
            before, after = pool.map(lambda ep: self._scan(ep, view.env), (view.before_endpoint, view.after_endpoint))
        problems = tuple(self._unknown(f'the {side} run {why}') for side, (_, why) in (('before', before), ('after', after)) if why)
        if problems:
            return LensResult(unknowns=problems)
        old, new = before[0], after[0]
        return LensResult(tuple(Finding(self.name, f'{self.name}.new', new[key], (), {'key': key, 'before': None, 'after': key})
                                for key in sorted(set(new) - set(old))))

    def _scan(self, endpoint: str, env: Mapping[str, str]) -> tuple[Mapping[str, str], str]:
        """(keys, '') when the run worked, ({}, why) when it did not."""
        try:
            done = subprocess.run(list(self.command), env={**env, self.endpoint_var: endpoint}, capture_output=True,
                                  text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return {}, f'did not finish in {self.timeout:g} s'
        except OSError as exc:
            return {}, f'could not start: {exc}'
        if done.returncode not in self.ok_exit_codes:
            return {}, f'exited with {done.returncode}: {done.stderr.strip()[-300:]}'
        try:
            return self.parser(done.stdout), ''
        except ValueError as exc:
            return {}, f'gave output that could not be read: {exc}'

    def _unknown(self, what: str) -> Unknown:
        return Unknown(f'{self.name}: {what}', f'lens:{self.name}')


def json_records(key_fields: Sequence[str], message_field: str = '', where: Mapping[str, Any] | None = None) -> Parser:
    """A parser for a JSON array or JSON lines of records.
    key_fields     dotted paths whose values together identify a finding ('metadata.event_code', 'resources.0.uid')
    message_field  dotted path of plain words for the finding (the key is used when empty)
    where          keep only records whose dotted paths have these values ({'status_code': 'FAIL'})"""
    def parse(text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for record in _records(text):
            if where and any(_get(record, k) != v for k, v in where.items()):
                continue
            key = ' | '.join(str(_get(record, f)) for f in key_fields)
            out[key] = str(_get(record, message_field)) if message_field else key
        return out
    return parse


def text_lines() -> Parser:
    """A parser for tools that print one finding per line."""
    def parse(text: str) -> dict[str, str]:
        return {line.strip(): line.strip() for line in text.splitlines() if line.strip()}
    return parse


def _records(text: str) -> list[dict]:
    s = text.strip()
    if not s:
        return []
    if s.startswith('['):
        data = json.loads(s)
        return [r for r in data if isinstance(r, dict)]
    return [r for r in (json.loads(line) for line in s.splitlines() if line.strip()) if isinstance(r, dict)]


def _get(record: Any, path: str) -> Any:
    for part in path.split('.'):
        if isinstance(record, dict):
            record = record.get(part)
        elif isinstance(record, list) and part.isdigit() and int(part) < len(record):
            record = record[int(part)]
        else:
            return None
    return record
