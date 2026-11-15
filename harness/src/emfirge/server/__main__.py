"""Run one branch as a local endpoint (lab use: the real account is an emulator).

  python -m emfirge.server --port 9540 --real https://127.0.0.1:9521 --real-ca CA --engine emulator --engine-port 9522
                           [--workdir DIR] [--legacy]

--legacy also serves the prototype's /__branch/ routes for experiments 09 and 14.
"""
from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from .http import BranchServer
from .legacy import PREFIX, legacy_routes
from .wiring import Setup, build_from


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='python -m emfirge.server')
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--real', required=True)
    ap.add_argument('--real-ca')
    ap.add_argument('--engine', choices=('emulator', 'moto'), default='emulator')
    ap.add_argument('--engine-port', type=int, required=True)
    ap.add_argument('--workdir', type=Path, default=Path('/tmp/emfirge-branch'))
    ap.add_argument('--region', default='us-west-2')
    ap.add_argument('--legacy', action='store_true')
    a = ap.parse_args(argv)
    branch, engine = build_from(Setup(a.real, a.real_ca, a.engine, a.engine_port, a.workdir, a.region))
    extra = ((PREFIX, legacy_routes(branch)),) if a.legacy else ()
    server = BranchServer(branch, a.port, extra)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f'branch on {server.url}  real={a.real} (read only)  engine={engine.name}', flush=True)
    try:
        server.serve_forever()
    finally:
        engine.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
