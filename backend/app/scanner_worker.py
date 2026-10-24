"""Warm Checkov scan worker: ``python -m app.scanner_worker``.

A verdict used to spawn the Checkov CLI six times; each cold start costs about
4 s and ~150 MB of imports.  This process imports Checkov once and keeps it
warm, so a scan of an already-loaded interpreter takes 0.02-1.25 s.  It runs
as its own memory-capped container so a runaway scan can never take the API
down.

Deliberately stdlib + Checkov only: it runs inside the Checkov virtualenv,
which has none of the app's dependencies, and importing the app would only
add memory.

Contract
  GET  /health -> 200 {"status": "ok", "checkov": "<version or null>"}
  POST /scan   {"terraform": {...}, "checks": ["CKV_AWS_24", ...]?}
       -> 200 {"findings": [{"check_id", "resource", "severity", "title",
                              "guideline"}, ...]}
       -> 400 invalid JSON / body shape, 413 body too large,
          503 busy, 500 scan failed.  Errors are {"error": "<message>"}.

Environment
  EMFIRGE_SCANNER_WORKER_BIND      host:port (default 127.0.0.1:8765)
  EMFIRGE_SCANNER_WORKER_MAX_BODY  request size limit in bytes (default 8 MiB)
  EMFIRGE_SCANNER_WORKER_LOCK_S    seconds to wait for the scan slot (default 30)
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional

DEFAULT_BIND = "127.0.0.1:8765"
DEFAULT_MAX_BODY = 8 * 1024 * 1024
DEFAULT_LOCK_S = 30.0

logger = logging.getLogger("emfirge.scanner_worker")

# Checkov's runners and registries are not thread-safe and a second concurrent
# scan would only add memory: scans go through one slot.
_SCAN_LOCK = threading.Lock()


def _text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def failed_checks_to_findings(failed_checks: Any) -> list[dict[str, Any]]:
    """Same shape and ordering as ``scanners._parse_findings`` produces."""
    findings: list[dict[str, Any]] = []
    for check in failed_checks or []:
        if not isinstance(check, dict):
            continue
        check_id = _text(check.get("check_id"))
        resource = _text(check.get("resource"))
        title = _text(check.get("check_name"))
        if not check_id or not resource or not title:
            continue
        guideline = _text(check.get("guideline")) or _text(check.get("guideline_url"))
        findings.append({
            "check_id": check_id,
            "resource": resource,
            "severity": _text(check.get("severity")) or "UNKNOWN",
            "title": title,
            "guideline": guideline,
        })
    findings.sort(key=lambda f: (f["check_id"], f["resource"], f["title"], f["severity"], f["guideline"] or ""))
    return findings


def checkov_version() -> Optional[str]:
    try:
        from checkov.version import version
        return str(version)
    except Exception:  # noqa: BLE001
        return None


def run_checkov_in_process(terraform: dict, checks: Optional[list[str]] = None) -> list[dict[str, Any]]:
    """Scan one Terraform JSON document with Checkov's in-process runner."""
    # Imported lazily so ``python -m app.scanner_worker --help`` and the tests
    # work without Checkov; the first scan (or ``warm_up``) pays the import once.
    from checkov.runner_filter import RunnerFilter
    from checkov.terraform_json.runner import TerraformJsonRunner

    with tempfile.TemporaryDirectory() as temp_dir:
        Path(temp_dir, "main.tf.json").write_text(
            json.dumps(terraform, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        # A fresh runner per scan: TerraformJsonRunner caches definitions on the
        # instance and would otherwise return the previous scan's resources.
        runner = TerraformJsonRunner()
        runner_filter = RunnerFilter(
            framework=["terraform_json"],
            checks=checks or None,
            download_external_modules=False,
            show_progress_bar=False,
        )
        reports = runner.run(root_folder=temp_dir, runner_filter=runner_filter)
    if not isinstance(reports, list):
        reports = [reports]
    findings: list[dict[str, Any]] = []
    for report in reports:
        findings.extend(failed_checks_to_findings(report.get_dict().get("results", {}).get("failed_checks")))
    findings.sort(key=lambda f: (f["check_id"], f["resource"], f["title"], f["severity"], f["guideline"] or ""))
    return findings


def warm_up() -> None:
    """Import Checkov and load its check registries with a trivial scan."""
    run_checkov_in_process({"resource": {"aws_s3_bucket": {"warm": {"bucket": "warm"}}}})


class ScanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def handle_scan(
    body: bytes,
    scan: Callable[[dict, Optional[list[str]]], list[dict[str, Any]]],
    lock_timeout_s: float = DEFAULT_LOCK_S,
) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError(400, f"request body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScanError(400, "request body must be a JSON object")
    terraform = payload.get("terraform")
    if not isinstance(terraform, dict):
        raise ScanError(400, "'terraform' must be a JSON object")
    checks = payload.get("checks")
    if checks is not None and not (isinstance(checks, list) and all(isinstance(c, str) for c in checks)):
        raise ScanError(400, "'checks' must be a list of check ids")
    if not _SCAN_LOCK.acquire(timeout=lock_timeout_s):
        raise ScanError(503, "scanner busy")
    try:
        try:
            findings = scan(terraform, checks)
        except Exception as exc:  # noqa: BLE001 - always answer in JSON
            logger.exception("scan failed")
            raise ScanError(500, f"scan failed: {type(exc).__name__}: {exc}") from exc
    finally:
        _SCAN_LOCK.release()
    return {"findings": findings}


def make_handler(
    scan: Callable[[dict, Optional[list[str]]], list[dict[str, Any]]] = run_checkov_in_process,
    max_body: int = DEFAULT_MAX_BODY,
    lock_timeout_s: float = DEFAULT_LOCK_S,
):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            logger.debug(fmt, *args)

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok", "checkov": checkov_version()})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/scan":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(411, {"error": "Content-Length required"})
                return
            if length < 0:
                self._send(400, {"error": "invalid Content-Length"})
                return
            if length > max_body:
                # Close rather than drain an oversized body.
                self.close_connection = True
                self._send(413, {"error": f"request body exceeds {max_body} bytes"})
                return
            body = self.rfile.read(length)
            try:
                self._send(200, handle_scan(body, scan, lock_timeout_s))
            except ScanError as exc:
                self._send(exc.status, {"error": exc.message})

    return Handler


def parse_bind(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return (host or "127.0.0.1"), int(port)


def main() -> None:
    # Checkov logs every scan at INFO on the root logger; keep only our own lines.
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(name)s %(message)s")
    logger.setLevel(logging.INFO)
    host, port = parse_bind(os.environ.get("EMFIRGE_SCANNER_WORKER_BIND", DEFAULT_BIND))
    max_body = int(os.environ.get("EMFIRGE_SCANNER_WORKER_MAX_BODY", DEFAULT_MAX_BODY))
    lock_s = float(os.environ.get("EMFIRGE_SCANNER_WORKER_LOCK_S", DEFAULT_LOCK_S))
    try:
        warm_up()
        logger.info("checkov warm (version %s)", checkov_version())
    except Exception:  # noqa: BLE001 - /health still answers; /scan reports the failure
        logger.exception("warm-up failed")
    server = ThreadingHTTPServer((host, port), make_handler(max_body=max_body, lock_timeout_s=lock_s))
    server.daemon_threads = True
    logger.info("scanner worker listening on %s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
