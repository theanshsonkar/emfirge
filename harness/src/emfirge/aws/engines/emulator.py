"""AWS's own emulator as an engine (or, in the lab, as the account under the branch)."""
from __future__ import annotations

import os
from pathlib import Path

from ..accounts import HttpAccount
from .process import LocalProcess

LAB = Path(os.environ.get('EMFIRGE_LAB_DIR', Path.home() / '.cache' / 'emfirge-lab'))
BINARY = Path(os.environ.get('EMULATOR_BIN', LAB / 'root' / 'opt' / 'aws-emulator' / 'bin' / 'aws-emulator'))


class EmulatorEngine(HttpAccount):
    """core.ports.Engine: one fresh emulator on 127.0.0.1:port, plain TLS with the emulator's own CA."""

    def __init__(self, port: int, workdir: Path, binary: Path = BINARY, name: str = 'emulator') -> None:
        self.ca_path = Path.home() / '.aws' / 'emulator' / str(port) / 'ca.pem'
        super().__init__(f'{name}:{port}', f'https://127.0.0.1:{port}', str(self.ca_path))
        self.port = port
        self._proc = LocalProcess([str(binary), '--telemetry', 'off', '-a', 'off', '-p', str(port)],
                                  {'EMULATOR_TELEMETRY': 'off'}, workdir / f'emulator-{port}.log')

    def start(self) -> None:
        self._proc.start()
        self._proc.wait_until(f'{self.url}/__admin/health', self.ca_path)

    def stop(self) -> None:
        self._proc.stop()
