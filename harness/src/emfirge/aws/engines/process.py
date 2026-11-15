"""Start a local fake as a subprocess, wait until it answers, stop it. Shared by every engine."""
from __future__ import annotations

import os
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path


class EngineFailed(RuntimeError):
    """The fake did not start (or not in time)."""


class LocalProcess:
    def __init__(self, argv: list[str], env: dict[str, str], log: Path) -> None:
        self._argv, self._env, self._log = argv, env, log
        self._proc: subprocess.Popen | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> None:
        if self.running:
            return
        self._log.parent.mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        env.update(self._env)
        with open(self._log, 'wb') as out:
            self._proc = subprocess.Popen(self._argv, stdout=out, stderr=subprocess.STDOUT, env=env,
                                          start_new_session=True)

    def stop(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._proc = None

    def wait_until(self, url: str, ca: Path | None = None, seconds: float = 60.0) -> None:
        """Poll `url` until it answers 2xx; the CA file may only appear once the fake is up."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not self.running:
                raise EngineFailed(f'{self._argv[0]} exited; see {self._log}')
            if ca is None or ca.exists():
                try:
                    ctx = ssl.create_default_context(cafile=str(ca)) if ca else None
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                         urllib.request.HTTPSHandler(context=ctx))
                    with opener.open(url, timeout=1) as r:
                        if r.status < 300:
                            return
                except OSError:
                    pass
            time.sleep(0.25)
        self.stop()
        raise EngineFailed(f'{self._argv[0]} did not answer {url} within {seconds:.0f} s; see {self._log}')
