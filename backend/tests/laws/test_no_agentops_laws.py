import ast
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / "backend"


def _requirement_names(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        package = re.split(r"[=<>~!\[;\s]", line, maxsplit=1)[0].strip().lower()
        if package:
            names.add(package)
    return names


def test_no_app_module_imports_agentops():
    files = list((BACKEND / "app").rglob("*.py"))
    assert len(files) > 10
    violations = []
    for path in files:
        source = path.read_text()
        if "AGENTOPS_API_KEY" in source:
            violations.append(f"{path.relative_to(ROOT)}:string:AGENTOPS_API_KEY")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "agentops" or alias.name.startswith("agentops."):
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "agentops" or module.startswith("agentops."):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not violations, "AgentOps references: " + ", ".join(violations)


def test_agentops_not_in_requirements():
    files = [
        path for path in ROOT.rglob("requirements*.txt")
        if ".venv" not in path.parts and "node_modules" not in path.parts
    ]
    assert files
    names = set()
    for path in files:
        names.update(_requirement_names(path.read_text()))
    assert "agentops" not in names
    assert "fastapi" in names


def test_importing_app_main_makes_no_outbound_call():
    script = r'''
import json
import socket
import time

outbound = []
_original_getaddrinfo = socket.getaddrinfo
_original_create_connection = socket.create_connection
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex


def blocked_getaddrinfo(host, *args, **kwargs):
    outbound.append(repr(host))
    raise OSError("blocked by law")


def blocked_create_connection(address, *args, **kwargs):
    outbound.append(repr(address[0] if isinstance(address, tuple) else address))
    raise OSError("blocked by law")


def blocked_connect(self, address):
    if self.family == socket.AF_UNIX:
        return _original_connect(self, address)
    outbound.append(repr(address))
    raise OSError("blocked by law")


def blocked_connect_ex(self, address):
    if self.family == socket.AF_UNIX:
        return _original_connect_ex(self, address)
    outbound.append(repr(address))
    raise OSError("blocked by law")

socket.getaddrinfo = blocked_getaddrinfo
socket.create_connection = blocked_create_connection
socket.socket.connect = blocked_connect
socket.socket.connect_ex = blocked_connect_ex
import app.main
time.sleep(3)
print("OUTBOUND=" + json.dumps(outbound))
'''
    env = os.environ.copy()
    env.update({
        "DATABASE_URL": "sqlite:///:memory:",
        "AGENTOPS_API_KEY": "00000000-0000-0000-0000-000000000000",
    })
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    line = next((line for line in result.stdout.splitlines() if line.startswith("OUTBOUND=")), None)
    assert line is not None, result.stdout + result.stderr
    outbound = json.loads(line.removeprefix("OUTBOUND="))
    assert outbound == []
