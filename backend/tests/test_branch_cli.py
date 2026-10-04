import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
from threading import Thread

import pytest


CLI = Path(__file__).parents[1] / "scripts" / "emfirge-branch.py"


class BranchAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        body = json.loads(raw_body) if raw_body else None
        self.server.requests.append((self.command, self.path, body, self.headers.get("Authorization")))
        status = 422 if self.path.endswith("/bad/diff") else 200
        response = {"detail": "unknown branch"} if status == 422 else {"z": 2, "a": 1}
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    do_GET = _respond
    do_POST = _respond


@pytest.fixture
def api_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), BranchAPIHandler)
    server.requests = []
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def invoke(server, *args, stdin=None, base_url_env=True):
    env = os.environ.copy()
    env.pop("EMFIRGE_BASE_URL", None)
    env.pop("EMFIRGE_API_KEY", None)
    if base_url_env:
        env["EMFIRGE_BASE_URL"] = f"http://127.0.0.1:{server.server_port}/api"
    env["EMFIRGE_API_KEY"] = "test-key"
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        input=stdin,
        text=True,
        capture_output=True,
        env=env,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize(
    ("args", "expected_request"),
    [
        (("create", "--analysis-id", "scan-1", "--name", "candidate"),
         ("POST", "/api/branches", {"base_analysis_id": "scan-1", "name": "candidate"})),
        (("list", "--analysis-id", "scan-1"),
         ("GET", "/api/branches?base_analysis_id=scan-1", None)),
        (("apply", "--branch-id", "b-1", "--op", "modify", "--resource-type", "s3_bucket",
          "--resource-id", "bucket", "--fields-json", '{"encrypted":true}'),
         ("POST", "/api/branches/b-1/changes", {
             "op": "modify", "resource_type": "s3_bucket", "resource_id": "bucket",
             "fields": {"encrypted": True},
         })),
        (("apply", "--branch-id", "b-1", "--op", "modify", "--resource-type", "s3_bucket",
          "--resource-id", "bucket", "--expected-count", "2", "--fields-json", '{"encrypted":true}'),
         ("POST", "/api/branches/b-1/changes", {
             "op": "modify", "resource_type": "s3_bucket", "resource_id": "bucket",
             "fields": {"encrypted": True}, "expected_change_count": 2,
         })),
        (("apply", "--branch-id", "b-1", "--op", "modify", "--resource-type", "iam_role_policy",
          "--resource-id", "arn:role", "--fields-file", "-"),
         ("POST", "/api/branches/b-1/changes", {
             "op": "modify", "resource_type": "iam_role_policy", "resource_id": "arn:role",
             "fields": {"access_statements": []},
         })),
        (("diff", "--branch-id", "b-1"), ("GET", "/api/branches/b-1/diff", None)),
        (("verdict", "--branch-id", "b-1"), ("GET", "/api/branches/b-1/verdict", None)),
        (("rollback", "--branch-id", "b-1"), ("POST", "/api/branches/b-1/rollback", {})),
        (("compare", "b-1", "b-2"), ("POST", "/api/branches/compare", {"branch_ids": ["b-1", "b-2"]})),
    ],
)
def test_commands_match_branch_api_and_emit_stable_json(api_server, args, expected_request):
    stdin = '{"access_statements": []}' if "--fields-file" in args else None
    result = invoke(api_server, *args, stdin=stdin)

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == '{\n  "a": 1,\n  "z": 2\n}\n'
    method, path, body = expected_request
    assert api_server.requests[-1][:3] == (method, path, body)
    assert api_server.requests[-1][3] == "Bearer test-key"


def test_apply_url_encodes_branch_id(api_server):
    result = invoke(api_server, "diff", "--branch-id", "branch/one")

    assert result.returncode == 0
    assert api_server.requests[-1][1] == "/api/branches/branch%2Fone/diff"


def test_api_error_is_plain_stderr_and_nonzero(api_server):
    result = invoke(api_server, "diff", "--branch-id", "bad")

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "emfirge-branch: API request failed (HTTP 422): unknown branch\n"


def test_base_url_required_when_environment_is_missing(api_server):
    result = invoke(api_server, "diff", "--branch-id", "b-1", base_url_env=False)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "EMFIRGE_BASE_URL" in result.stderr
    assert api_server.requests == []


def test_invalid_fields_json_fails_before_http_request(api_server):
    result = invoke(
        api_server, "apply", "--branch-id", "b-1", "--op", "modify",
        "--resource-type", "s3_bucket", "--fields-json", "[]",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "fields JSON must be an object" in result.stderr
    assert api_server.requests == []
