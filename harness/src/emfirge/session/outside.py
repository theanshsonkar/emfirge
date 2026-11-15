"""Outside tools as lenses from a command line: `--lens 'name=command'`.

The default parser reads JSON lines (or one JSON array) and takes each whole record as one finding: a record the
tool gives on the branch and not on the real account is new. A record's 'message' (or 'title', 'description') is
its plain words when it has one. A tool that prints something else is reported as an unknown, never as 'nothing new'.
"""
from __future__ import annotations

import json
import shlex
from typing import Any

from emfirge.lenses import ExternalLens

MESSAGE_KEYS = ('message', 'Message', 'title', 'description')


def outside_lens(spec: str) -> ExternalLens:
    """'name=command line' -> an ExternalLens. Raises ValueError for a spec without a name or a command."""
    name, sep, command = spec.partition('=')
    if not sep or not name.strip() or not command.strip():
        raise ValueError(f'--lens needs name=command, got {spec!r}')
    return ExternalLens(name.strip(), tuple(shlex.split(command)), whole_records)


def whole_records(text: str) -> dict[str, str]:
    """{the record as sorted JSON: its plain words}. Raises ValueError when the output is not JSON."""
    out = {}
    for record in _records(text):
        key = json.dumps(record, sort_keys=True, ensure_ascii=False)
        words = next((record[k] for k in MESSAGE_KEYS if isinstance(record, dict) and isinstance(record.get(k), str)), key)
        out[key] = words
    return out


def _records(text: str) -> list[Any]:
    s = text.strip()
    if not s:
        return []
    if s.startswith('['):
        return list(json.loads(s))
    return [json.loads(line) for line in s.splitlines() if line.strip()]
