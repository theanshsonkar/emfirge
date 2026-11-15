"""moto's server as an engine: a second, independent fake, to show the engine plug is really swappable."""
from __future__ import annotations

import os
from pathlib import Path

from ..accounts import HttpAccount
from .emulator import LAB
from .process import LocalProcess

BINARY = Path(os.environ.get('MOTO_BIN', LAB / 'moto-venv' / 'bin' / 'moto_server'))
ACCOUNT = '000000000000'


class MotoEngine(HttpAccount):
    """core.ports.Engine: one fresh moto server on 127.0.0.1:port, plain HTTP."""

    def __init__(self, port: int, workdir: Path, binary: Path = BINARY) -> None:
        super().__init__(f'moto:{port}', f'http://127.0.0.1:{port}')
        self.port = port
        self._proc = LocalProcess([str(binary), '-H', '127.0.0.1', '-p', str(port)],
                                  {'MOTO_ACCOUNT_ID': ACCOUNT}, workdir / f'moto-{port}.log')

    def start(self) -> None:
        self._proc.start()
        self._proc.wait_until(f'{self.url}/moto-api/')

    def stop(self) -> None:
        self._proc.stop()
