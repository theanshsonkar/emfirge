"""L61 scanner worker: a warm out-of-process Checkov, a base cache, an incremental scan and an advisory severity policy.

None of these tests needs Checkov installed: the worker call and the scan
function are stubbed, and the HTTP contract is exercised against the real
server class with a stub scan.
"""
import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from app import scanner_worker, scanners
from app.scanners import build_terraform, plan_scan_scope, run_checkov, run_trivy, scan_scope
from app.verdict import combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base

URL = "http://scanner.test:8765"


def _base():
    return load_synthetic_base("delete")


def _with_sg_rule(infra, sg_id, rule):
    out = infra.model_copy(deep=True)
    for group in out.ec2.security_groups:
        if group.id == sg_id:
            group.rules = list(group.rules) + [rule]
    return out


def _ssh_open_branch(base):
    return _with_sg_rule(base, "sg-dl-web", {
        "protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": [],
    })


def _bigger_instance_branch(base):
    out = base.model_copy(deep=True)
    out.ec2.instances[0].type = "t3.large"
    return out


def _tf_name(infra, resource_type, rid):
    return next(n for n, (t, i) in build_terraform(infra).names.items() if (t, i) == (resource_type, rid))


class FakeWorker:
    """Stands in for the HTTP worker; records each Terraform body it was sent."""

    def __init__(self, finder=None):
        self.bodies = []
        self.finder = finder or (lambda tf: [])

    def __call__(self, url, terraform_json, timeout_s):
        tf = json.loads(terraform_json)
        self.bodies.append(tf)
        return [scanners.ScannerFinding(**f) for f in self.finder(tf)]


@pytest.fixture
def worker(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", URL)
    fake = FakeWorker()
    monkeypatch.setattr(scanners, "_scan_via_worker", fake)
    # Only checkov is under test; keep the other scanners out of the way.
    for name in ("run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(f"app.verdict.{name}", lambda *_a, **_k: {"available": False, "findings": [], "error": "off"})
    return fake


# (a) -----------------------------------------------------------------------

def test_L61a_worker_down_is_unavailable_and_verdict_still_returns(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", "http://127.0.0.1:1")  # nothing listens here
    for name in ("run_trivy", "run_cloudsplaining"):
        monkeypatch.setattr(f"app.verdict.{name}", lambda *_a, **_k: {"available": False, "findings": [], "error": "off"})
    base = _base()
    result = run_checkov(base)
    assert result.available is False and "worker" in result.error
    verdict = combined_verdict(base, _ssh_open_branch(base), run_scanners=True)
    assert verdict.verdict in {"pass", "warn", "block"}
    assert verdict.scanner_status["checkov"].startswith("unavailable: ")
    assert verdict.scanner_available is False


def test_L61a_worker_timeout_is_unavailable(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)  # accepts the connection (backlog) but never answers
    try:
        monkeypatch.setenv("EMFIRGE_SCANNER_URL", f"http://127.0.0.1:{listener.getsockname()[1]}")
        monkeypatch.setenv("EMFIRGE_SCANNER_TIMEOUT_S", "0.3")
        result = run_checkov(_base())
    finally:
        listener.close()
    assert result.available is False
    assert "timed out" in result.error


def test_L61a_worker_5xx_and_garbage_are_unavailable(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", URL)

    def server_error(*_a, **_k):
        raise urllib.error.HTTPError(URL, 503, "busy", {}, None)

    monkeypatch.setattr(scanners, "_scan_via_worker", server_error)
    assert "HTTP 503" in run_checkov(_base()).error
    monkeypatch.setattr(scanners, "_scan_via_worker", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("junk")))
    assert run_checkov(_base()).available is False


# (b) -----------------------------------------------------------------------

def test_L61b_unchanged_snapshot_is_scanned_once(worker):
    base = _base()
    first = run_checkov(base)
    second = run_checkov(base)
    assert len(worker.bodies) == 1
    assert first.model_dump() == second.model_dump()


def test_L61b_second_verdict_on_same_base_does_not_rescan(worker):
    base = _base()
    branch = _ssh_open_branch(base)
    combined_verdict(base, branch, run_scanners=True)
    scans_after_first = len(worker.bodies)
    assert scans_after_first == 2  # base + branch, once each
    combined_verdict(base, branch, run_scanners=True)
    assert len(worker.bodies) == scans_after_first


def test_L61b_cache_is_bounded(worker):
    base = _base()
    for index in range(scanners._CACHE_MAX + 10):
        branch = base.model_copy(deep=True)
        branch.ec2.instances[0].type = f"t3.size{index}"
        run_checkov(branch)
    assert len(scanners._cache) == scanners._CACHE_MAX


# (c) -----------------------------------------------------------------------

def test_L61c_subset_has_changed_resource_and_its_neighbours(worker):
    base = _base()
    web_sg = _tf_name(base, "security_group", "sg-dl-web")
    web_instance = _tf_name(base, "ec2_instance", "i-dl-web")
    scope = plan_scan_scope(base, _ssh_open_branch(base))
    # The changed group and the instance that uses it; unrelated groups, the
    # database and the bucket are not scanned.
    assert scope.names == {web_sg, web_instance}


def test_L61c_rds_change_brings_its_security_group_and_bucket_change_its_subresources(worker):
    base = _base()
    db_sg = _tf_name(base, "security_group", "sg-dl-db")
    sg_change = _with_sg_rule(base, "sg-dl-db", {
        "protocol": "tcp", "from_port": 5432, "to_port": 5432, "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": [],
    })
    scope = plan_scan_scope(base, sg_change)
    assert db_sg in scope.names
    assert {_tf_name(base, "rds_instance", "db-dl-prod"), _tf_name(base, "rds_instance", "db-dl-reports")} <= scope.names

    bucket_change = base.model_copy(deep=True)
    bucket_change.s3.buckets[0].versioning_enabled = not bool(bucket_change.s3.buckets[0].versioning_enabled)
    names = build_terraform(base).tf["resource"]
    scope = plan_scan_scope(base, bucket_change)
    assert set(names["aws_s3_bucket"]) <= scope.names
    assert set(names["aws_s3_bucket_versioning"]) <= scope.names
    assert set(names["aws_s3_bucket_server_side_encryption_configuration"]) <= scope.names


def test_L61c_same_subset_is_scanned_on_base_and_branch(worker):
    base = _base()
    combined_verdict(base, _ssh_open_branch(base), run_scanners=True)
    base_body, branch_body = worker.bodies
    names = lambda tf: {n for entries in tf["resource"].values() for n in entries}  # noqa: E731
    assert names(base_body) == names(branch_body)
    full = {n for entries in build_terraform(base).tf["resource"].values() for n in entries}
    assert names(base_body) < full  # genuinely a subset


def test_L61c_unchanged_infra_scans_nothing_and_unplannable_scope_falls_back(worker):
    base = _base()
    combined_verdict(base, base.model_copy(deep=True), run_scanners=True)
    assert worker.bodies == []
    assert plan_scan_scope(base, object()) is None  # cannot decide -> caller scans everything


# (d) -----------------------------------------------------------------------

def _finding_on_large_instance(severity):
    def finder(tf):
        if "t3.large" not in json.dumps(tf):
            return []
        name = next(iter(tf["resource"]["aws_instance"]))
        return [{
            "check_id": "CKV_AWS_24", "resource": f"aws_instance.{name}", "severity": severity or "UNKNOWN",  # the worker reports a missing severity as UNKNOWN
            "title": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22", "guideline": None,
        }]
    return finder


def _codes(verdict):
    return {reason["code"] for reason in verdict.reasons}


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", None, "UNKNOWN"])
def test_L61d_new_scanner_finding_without_crosswalk_warns_and_never_blocks(worker, severity):
    worker.finder = _finding_on_large_instance(severity)
    base = _base()
    verdict = combined_verdict(base, _bigger_instance_branch(base), run_scanners=True)
    assert [item["check_id"] for item in verdict.scanner_added] == ["CKV_AWS_24"]
    assert verdict.scanner_added[0]["resource"] == "i-dl-web"  # mapped back to the Emfirge resource
    assert verdict.scanner_added[0]["severity"] != "critical"
    assert "new_scanner_finding" in _codes(verdict)
    assert "introduced_critical_finding" not in _codes(verdict)
    assert verdict.verdict == "warn"


def test_L61d_crosswalked_critical_finding_can_block(worker, monkeypatch):
    worker.finder = _finding_on_large_instance(None)  # scanner itself gives no severity
    monkeypatch.setattr(scanners, "severity_crosswalk", lambda: {
        "CKV_AWS_24": {"severity": "critical", "source": "test table"},
    })
    base = _base()
    verdict = combined_verdict(base, _bigger_instance_branch(base), run_scanners=True)
    assert verdict.scanner_added[0]["severity"] == "critical"
    assert "introduced_critical_finding" in _codes(verdict)
    assert verdict.verdict == "block"


def test_L61d_crosswalk_table_exists_starts_empty_and_ignores_bad_rows(monkeypatch, tmp_path):
    shipped = scanners._CROSSWALK_PATH
    assert json.loads(shipped.read_text()) == []
    table = tmp_path / "t.json"
    table.write_text(json.dumps([
        {"check_id": "A", "severity": "Critical", "source": "Prowler"},
        {"check_id": "B", "severity": "catastrophic", "source": "Prowler"},
        {"check_id": "C", "severity": "high"},
        "junk",
    ]))
    monkeypatch.setattr(scanners, "_CROSSWALK_PATH", table)
    scanners.severity_crosswalk.cache_clear()
    try:
        assert scanners.severity_crosswalk() == {"A": {"severity": "critical", "source": "Prowler"}}
    finally:
        scanners.severity_crosswalk.cache_clear()


# (e) -----------------------------------------------------------------------

def _count_subprocess(monkeypatch):
    calls = []

    def run(args, **_kwargs):
        calls.append(args[0])
        return SimpleNamespace(stdout=json.dumps({"Results": []}), returncode=0)

    monkeypatch.setattr("app.scanners.subprocess.run", run)
    return calls


def test_L61e_trivy_is_not_invoked_unless_enabled(monkeypatch):
    calls = _count_subprocess(monkeypatch)
    monkeypatch.delenv("EMFIRGE_RUN_TRIVY", raising=False)
    result = run_trivy(_base())
    assert calls == [] and result.available is False and result.error == "disabled (memory)"
    monkeypatch.setenv("EMFIRGE_RUN_TRIVY", "0")
    run_trivy(_base())
    assert calls == []
    monkeypatch.setenv("EMFIRGE_RUN_TRIVY", "1")
    assert run_trivy(_base()).available is True
    assert calls == ["trivy"]


def test_L61e_scanner_status_reports_trivy_disabled_by_default(monkeypatch):
    calls = _count_subprocess(monkeypatch)
    monkeypatch.setattr("app.verdict.run_checkov", lambda *_a, **_k: {"available": True, "findings": []})
    monkeypatch.setattr("app.verdict.run_cloudsplaining", lambda *_a, **_k: {"available": True, "findings": []})
    base = _base()
    verdict = combined_verdict(base, base.model_copy(deep=True), run_scanners=True)
    assert verdict.scanner_status["trivy"] == "disabled (memory)"
    assert calls == []


# (f) -----------------------------------------------------------------------

@pytest.fixture
def server():
    started = []

    def start(scan, max_body=1024 * 1024):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), scanner_worker.make_handler(scan=scan, max_body=max_body, lock_timeout_s=1))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        started.append(httpd)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    yield start
    for httpd in started:
        httpd.shutdown()
        httpd.server_close()


def _request(url, body=None, method=None):
    request = urllib.request.Request(url, data=body, method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_L61f_health_ok(server):
    status, body = _request(server(lambda tf, checks: []) + "/health")
    assert status == 200 and body["status"] == "ok"


def test_L61f_scan_contract(server):
    seen = []

    def scan(tf, checks):
        seen.append((tf, checks))
        return [{"check_id": "CKV_AWS_24", "resource": "aws_security_group.a", "severity": "UNKNOWN", "title": "t", "guideline": None}]

    url = server(scan)
    status, body = _request(url + "/scan", json.dumps({"terraform": {"resource": {}}, "checks": ["CKV_AWS_24"]}).encode())
    assert status == 200 and body["findings"][0]["check_id"] == "CKV_AWS_24"
    assert seen == [({"resource": {}}, ["CKV_AWS_24"])]


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"terraform": 3}', b'{"terraform": {}, "checks": "x"}', b"\xff\xfe"])
def test_L61f_bad_request_is_400_json(server, payload):
    status, body = _request(server(lambda tf, checks: []) + "/scan", payload)
    assert status == 400 and "error" in body


def test_L61f_oversize_is_413_scan_failure_is_500_unknown_path_is_404(server):
    url = server(lambda tf, checks: [], max_body=64)
    assert _request(url + "/scan", b"x" * 500)[0] == 413

    def boom(tf, checks):
        raise RuntimeError("checkov exploded")

    url = server(boom)
    status, body = _request(url + "/scan", b'{"terraform": {}}')
    assert status == 500 and "checkov exploded" in body["error"]
    assert _request(url + "/nope")[0] == 404
    assert _request(url + "/nope", b"{}")[0] == 404


def test_L61f_client_round_trips_through_real_worker_http(server, monkeypatch):
    url = server(lambda tf, checks: [{
        "check_id": "CKV_AWS_24", "resource": "aws_security_group.x", "severity": "UNKNOWN", "title": "ssh", "guideline": None,
    }])
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", url)
    result = run_checkov(_base())
    assert result.available is True
    assert [f.check_id for f in result.findings] == ["CKV_AWS_24"]
    assert result.resource_map  # findings can be keyed back to Emfirge resources


def test_L61f_findings_shape_matches_cli_parser():
    failed = [
        {"check_id": "CKV_AWS_2", "resource": "aws_s3_bucket.z", "severity": None, "check_name": "Second", "guideline_url": "u"},
        {"check_id": "CKV_AWS_1", "resource": "aws_s3_bucket.a", "severity": "HIGH", "check_name": "First", "guideline": "g"},
        {"check_id": "", "resource": "x", "check_name": "dropped"},
    ]
    from_worker = scanner_worker.failed_checks_to_findings(failed)
    from_cli = scanners._parse_findings({"results": {"failed_checks": failed}})
    assert from_worker == [f.model_dump(exclude={"source"}) for f in from_cli]
