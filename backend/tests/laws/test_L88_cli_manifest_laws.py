"""L88: the CLI manifest is a public, static, true description of the API the CLI calls.

The ``emfirge`` CLI builds its commands from ``GET /cli/manifest``, so a command added on the server shows up in an
already installed CLI without a new npm version. The manifest must therefore be true and safe:

L88a  the protocol is present, an integer, and the document has commands
L88b  every request path exists in the FastAPI app with that method (placeholders matched by position)
L88c  deterministic: same bytes on every call, and across Python hash seeds
L88d  no customer data: no account id, ARN, AWS resource id, address, key, token or e-mail anywhere in it
L88e  public: served without sign-in even when auth is required; the module reads no database and no caller
L88f  internally consistent: every reference (path placeholder, query, body, when, require) names a real argument
L88g  the copy bundled in the npm package equals what the server returns
L88h  every command can be run: a request or a client key, in every mode; positional order is sane
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app import auth
from app.cli_manifest import PROTOCOL, build_manifest
from app.main import app

BACKEND = Path(__file__).resolve().parents[2]
BUNDLED = BACKEND.parent / "mcp" / "src" / "cli" / "bundled-manifest.json"
ARG_TYPES = {"string", "number", "integer", "bool", "json"}
PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


def _served() -> dict:
    return TestClient(app).get("/cli/manifest").json()


def _requests(manifest: dict):
    """Every (command, mode, request) the manifest describes."""
    for cmd in manifest["commands"]:
        if "request" in cmd:
            yield cmd, "default", cmd["request"]
        for variant in cmd.get("variants", []):
            if "request" in variant:
                yield cmd, variant["when"], variant["request"]


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_L88a_protocol_present_and_commands_listed():
    served = _served()
    assert isinstance(served["protocol"], int) and not isinstance(served["protocol"], bool)
    assert served["protocol"] == PROTOCOL >= 1
    assert served["commands"], "no commands"
    names = [c["name"] for c in served["commands"]]
    assert len(names) == len(set(names)), "duplicate command name"
    for expected in ("context", "branch open", "branch get", "try", "check", "report"):
        assert expected in names


def _normalized(path: str) -> str:
    return PLACEHOLDER.sub("{}", path.split("?")[0])


def test_L88b_every_manifest_path_exists_with_that_method():
    routes = {(m, _normalized(r.path)) for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    seen = 0
    for cmd, mode, req in _requests(build_manifest()):
        seen += 1
        key = (req["method"], _normalized(req["path"]))
        assert key in routes, f"{cmd['name']} [{mode}]: {req['method']} {req['path']} is not a route"
    assert seen >= 10


def test_L88b_a_static_path_is_not_shadowed_by_a_template():
    """/branches/compare must reach its own route, not /branches/{branch_id}: static routes come first."""
    order = [(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods]
    for cmd, mode, req in _requests(build_manifest()):
        if "{" in req["path"]:
            continue
        static = (req["method"], req["path"])
        for method, path in order[: order.index(static)]:
            if method == req["method"] and "{" in path:
                template = re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path))
                assert not re.fullmatch(template, req["path"]), f"{cmd['name']}: {req['path']} is shadowed by {path}"


def test_L88c_deterministic_same_bytes():
    client = TestClient(app)
    first = client.get("/cli/manifest").content
    assert first == client.get("/cli/manifest").content
    assert json.dumps(build_manifest()) == json.dumps(build_manifest())
    assert json.loads(first) == build_manifest()


def test_L88c_deterministic_across_hash_seeds():
    code = "import json; from app.cli_manifest import build_manifest as b; print(json.dumps(b()))"
    outputs = set()
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        outputs.add(subprocess.run([sys.executable, "-c", code], cwd=BACKEND, env=env, capture_output=True, text=True, check=True).stdout)
    assert len(outputs) == 1


CUSTOMER_PATTERNS = {
    "ARN": re.compile(r"arn:aws[\w-]*:"),
    "12-digit account id": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "AWS resource id": re.compile(r"\b(?:sg|i|vol|subnet|vpc|eni|rtb|igw|nat|acl|eipalloc|ami|snap)-[0-9a-f]{8,}\b"),
    "IP address": re.compile(r"\b(?!0\.0\.0\.0\b)\d{1,3}(?:\.\d{1,3}){3}\b"),
    "e-mail": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "API key or token": re.compile(r"\bemf_[\w-]{8,}|\beyJ[\w-]{10,}|AKIA[0-9A-Z]{12,}|\bBearer\s+\S+"),
    "uuid": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "64-hex digest": re.compile(r"\b[0-9a-f]{64}\b"),
}


def test_L88d_no_customer_data_in_the_manifest():
    for text in _strings(_served()):
        if re.fullmatch(r"\^\[0-9a-f\]\{64\}\$", text):  # the pattern that CHECKS a revision, not a revision
            continue
        for label, pattern in CUSTOMER_PATTERNS.items():
            assert not pattern.search(text), f"{label} in manifest text: {text!r}"


def test_L88d_the_detectors_do_catch_customer_data():
    for sample in ("arn:aws:iam::123456789012:role/x", "123456789012", "sg-0abc123def4567890", "10.1.2.3",
                   "a@b.co", "emf_abcdefghijk", "a" * 64):
        assert any(p.search(sample) for p in CUSTOMER_PATTERNS.values()), sample


def test_L88e_public_even_when_auth_is_required(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    response = TestClient(app).get("/cli/manifest")
    assert response.status_code == 200
    assert response.json()["protocol"] == PROTOCOL


def test_L88e_the_module_reads_no_database_and_no_caller():
    import ast
    tree = ast.parse((BACKEND / "app" / "cli_manifest.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "typing"}, imported
    route = next(r for r in app.routes if isinstance(r, APIRoute) and r.path == "/cli/manifest")
    assert not route.dependant.dependencies and not route.dependencies


def _arg_names(cmd: dict) -> set[str]:
    return {a["name"] for a in cmd["args"]}


def test_L88f_every_reference_names_a_real_argument():
    manifest = build_manifest()
    assert set(manifest.get("groups", {})) <= {c["name"].split()[0] for c in manifest["commands"]}
    for cmd in manifest["commands"]:
        names = [a["name"] for a in cmd["args"]]
        assert len(names) == len(set(names)), f"{cmd['name']}: duplicate arg"
        known = set(names)
        for a in cmd["args"]:
            assert a["type"] in ARG_TYPES and a["kind"] in {"flag", "positional"}, (cmd["name"], a)
            assert a["help"].strip(), (cmd["name"], a["name"])
            if a["type"] == "bool":
                assert a["kind"] == "flag" and not a.get("multiple") and not a.get("required"), (cmd["name"], a["name"])
            if "pattern" in a:
                re.compile(a["pattern"])
        assert set(cmd.get("require", [])) <= known, cmd["name"]
        for variant in cmd.get("variants", []):
            assert variant["when"] in known, (cmd["name"], variant)
            assert set(variant.get("require", [])) <= known, (cmd["name"], variant)
    for cmd, mode, req in _requests(manifest):
        known = _arg_names(cmd)
        assert req["method"] in {"GET", "POST"}
        assert req["path"].startswith("/")
        for placeholder in PLACEHOLDER.findall(req["path"]):
            assert placeholder in known, (cmd["name"], mode, placeholder)
        for section in ("query", "body"):
            for field, arg in req.get(section, {}).items():
                assert arg in known, (cmd["name"], mode, section, field, arg)
        assert not (req["method"] == "GET" and "body" in req), (cmd["name"], mode)


def test_L88g_the_bundled_copy_equals_what_the_server_returns():
    assert BUNDLED.exists(), "run: cd backend && python scripts/export_cli_manifest.py"
    assert json.loads(BUNDLED.read_text(encoding="utf-8")) == _served(), (
        "mcp/src/cli/bundled-manifest.json is stale: run `cd backend && python scripts/export_cli_manifest.py`")


def test_L88h_every_command_can_be_run():
    for cmd in build_manifest()["commands"]:
        modes = [("default", "request" in cmd or "client" in cmd)]
        modes += [(v["when"], "request" in v or "client" in v) for v in cmd.get("variants", [])]
        if "client" in cmd:
            assert "request" not in cmd and "variants" not in cmd, cmd["name"]
        else:
            assert modes[0][1], f"{cmd['name']} has no default request"
        assert all(ok for _, ok in modes), cmd["name"]
        for variant in cmd.get("variants", []):
            assert ("request" in variant) != ("client" in variant), (cmd["name"], variant)
        positionals = [a for a in cmd["args"] if a["kind"] == "positional"]
        assert all(not a.get("multiple") for a in positionals[:-1]), f"{cmd['name']}: a repeated positional must be last"
        seen_optional = False
        for a in positionals:
            assert not (seen_optional and a.get("required")), f"{cmd['name']}: required positional after an optional one"
            seen_optional = seen_optional or not a.get("required")
