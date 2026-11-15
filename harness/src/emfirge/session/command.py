"""Run the wrapped command, and the exit code of a session (README: 'Exit codes of emf run')."""
from __future__ import annotations

import subprocess
from typing import Mapping, Sequence

FAILED = 2                 # Emfirge itself failed
COMMAND_BASE, COMMAND_CAP = 64, 125
NOT_FOUND = 127            # as a shell says it


def run_command(argv: Sequence[str], env: Mapping[str, str]) -> int:
    """The command's exit code. It shares the terminal. Ctrl-C reaches it too (same process group); the session
    still judges what the branch holds afterwards."""
    try:
        proc = subprocess.Popen(list(argv), env=dict(env))
    except OSError:
        return NOT_FOUND
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue           # the command got the same Ctrl-C; wait for it to finish


def exit_code(verdict_code: int, command_code: int | None) -> int:
    """The verdict's code (0 go, 3 ask), unless the command failed: then 64 + its code, at most 125. A command
    killed by a signal counts as 128 + the signal, as a shell says it."""
    if not command_code:
        return verdict_code
    code = command_code if command_code > 0 else 128 - command_code
    return min(COMMAND_BASE + code, COMMAND_CAP)
