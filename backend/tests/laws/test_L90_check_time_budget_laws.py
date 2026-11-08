"""L90: a verdict (and so check, try with a plan, report) answers inside a fixed time budget.

The incident (2026-11-08, live server): every check, diff and verdict call ended in a gateway 504
after about 60s. The engine itself answers in well under a second on the same account shape; the
time went to the borrowed scanners. The Checkov worker runs in a small container, each side could
wait up to its own timeout, the sides ran one after the other, and a timed-out call kept its
thread, so later calls queued behind it.

L90a  All borrowed scanners share ONE wall-clock budget (EMFIRGE_SCANNER_BUDGET_S). A scanner that
      is still running when the budget ends is reported as not run ("exceeded the time budget"),
      the verdict says it is NOT full coverage, and it returns on time. Never silent.
L90b  The base and branch scans run at the same time, so the budget is not doubled.
L90c  After the Checkov worker fails, the next calls skip it for EMFIRGE_SCANNER_BACKOFF_S and say
      why, instead of each waiting for the same failure again.
L90d  Scan scope (the changed resources and their neighbours) still applies inside the budget.
"""
import time
import urllib.error

import pytest

from app import scanners
from app import verdict as verdict_mod
from app.models import AWSInfrastructure, S3Bucket
from app.scanners import ScanResult


def _infra():
    return AWSInfrastructure(s3_buckets=[S3Bucket(name="b1")])


def _branch():
    return AWSInfrastructure(s3_buckets=[S3Bucket(name="b1", versioning_enabled=True)])


def _ok(name):
    def run(_infra):
        return ScanResult(scanner=name, available=True, findings=[], resource_map={})
    return run


def _slow(seconds, name="checkov"):
    def run(_infra):
        time.sleep(seconds)
        return ScanResult(scanner=name, available=True, findings=[], resource_map={})
    return run


@pytest.fixture(autouse=True)
def _budget(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_BUDGET_S", "1")
    monkeypatch.setattr(verdict_mod, "run_trivy", _ok("trivy"))
    monkeypatch.setattr(verdict_mod, "run_cloudsplaining", _ok("cloudsplaining"))
    scanners._reset_worker_backoff()
    yield
    scanners._reset_worker_backoff()


def test_L90a_slow_scanner_is_cut_at_the_budget_and_named(monkeypatch):
    monkeypatch.setattr(verdict_mod, "run_checkov", _slow(5))
    start = time.monotonic()
    result = verdict_mod.combined_verdict(_infra(), _branch(), run_scanners=True)
    elapsed = time.monotonic() - start
    assert elapsed < 3, f"verdict took {elapsed:.1f}s with a 1s scanner budget"
    assert "time budget" in result.scanner_status["checkov"]
    assert any("NOT full coverage" in w for w in result.coverage_warnings)
    assert result.scanner_status["cloudsplaining"] == "ok"


def test_L90b_sides_run_at_the_same_time(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_BUDGET_S", "3")
    monkeypatch.setattr(verdict_mod, "run_checkov", _slow(1.2))
    start = time.monotonic()
    result = verdict_mod.combined_verdict(_infra(), _branch(), run_scanners=True)
    elapsed = time.monotonic() - start
    assert result.scanner_status["checkov"] == "ok"
    assert elapsed < 2.3, f"base and branch ran one after the other ({elapsed:.1f}s)"


def test_L90c_worker_failure_is_not_retried_inside_the_backoff(monkeypatch):
    monkeypatch.setenv("EMFIRGE_SCANNER_URL", "http://worker.invalid:8765")
    monkeypatch.setenv("EMFIRGE_SCANNER_BACKOFF_S", "60")
    calls = []

    def boom(url, tf, timeout_s):
        calls.append(url)
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(scanners, "_scan_via_worker", boom)
    first = scanners.run_checkov(_infra())
    assert first.available is False and "timed out" in (first.error or "")
    second = scanners.run_checkov(_branch())
    assert len(calls) == 1, "the worker was called again inside the backoff window"
    assert second.available is False and "skipped" in (second.error or "")


def test_L90d_scope_applies_inside_worker_threads(monkeypatch):
    seen = []

    def spy(_infra):
        seen.append(scanners._SCOPE.get())
        return ScanResult(scanner="checkov", available=True, findings=[], resource_map={})

    monkeypatch.setattr(verdict_mod, "run_checkov", spy)
    verdict_mod.combined_verdict(_infra(), _branch(), run_scanners=True)
    assert seen and all(scope is not None for scope in seen)
