import importlib
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import database, demo_seed, main


@pytest.fixture
def demo_client(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'demo.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(main, "SessionLocal", factory, raising=False)
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    yield TestClient(main.app), factory
    main.app.dependency_overrides.pop(main.require_api_key, None)
    database.Base.metadata.drop_all(engine)
    engine.dispose()


def test_L42a_demo_arn_is_pinned_to_zero_account(monkeypatch):
    monkeypatch.setenv("DEMO_ACCOUNT_ID", "111111111111")
    monkeypatch.setenv("DEMO_ACCOUNT_ID_V2", "111111111111")
    importlib.reload(demo_seed)
    role = demo_seed.DEMO_ROLE_ARN.rsplit("/", 1)[-1]
    assert demo_seed.is_demo_arn(f"arn:aws:iam::111111111111:role/{role}") is False
    assert demo_seed.is_demo_arn(f"arn:aws:iam::000000000000:role/{role}") is True
    # main uses the imported demo constants/dispatch when present; this codebase
    # does not re-export is_demo_arn, so validate its module-level constants.
    if hasattr(main, "is_demo_arn"):
        assert main.is_demo_arn(f"arn:aws:iam::111111111111:role/{role}") is False
        assert main.is_demo_arn(demo_seed.DEMO_ROLE_ARN) is True
    assert demo_seed.DEMO_ROLE_ARN.startswith("arn:aws:iam::000000000000:")
    assert demo_seed.DEMO_ROLE_ARN_V2.startswith("arn:aws:iam::000000000000:")
    monkeypatch.delenv("DEMO_ACCOUNT_ID")
    monkeypatch.delenv("DEMO_ACCOUNT_ID_V2")
    importlib.reload(demo_seed)


def test_L42b_demo_does_not_touch_real_account_data(demo_client, monkeypatch):
    client, factory = demo_client
    real = "111111111111"
    real_id = database.save_analysis({"aws_account_id": real, "region_analyzed": "us-east-1",
                                      "findings_json": {"real_analysis": "REAL-ID"}})
    real_marker = f"REAL-ID-{real_id}"
    for _ in range(main.DAILY_SCAN_LIMIT - database.get_scan_count_today(real)):
        database.save_analysis({"aws_account_id": real, "region_analyzed": "us-east-1"})
    before = database.get_scan_count_today(real)
    calls = []

    def spy_count(account, *args, **kwargs):
        calls.append(("count", account)); return database.get_scan_count_today(account)
    def spy_save(data, *args, **kwargs):
        calls.append(("save", data.get("aws_account_id"))); return database.save_analysis(data)
    def spy_previous(account, *args, **kwargs):
        calls.append(("previous", account)); return database.get_previous_scan_for_account(account, *args, **kwargs)
    monkeypatch.setattr(main, "get_scan_count_today", spy_count)
    monkeypatch.setattr(main, "save_analysis", spy_save)
    monkeypatch.setattr(main, "get_previous_scan_for_account", spy_previous)
    if hasattr(main, "_load_analysis_record"):
        original = main._load_analysis_record
        def spy_load(*args, **kwargs):
            calls.append(("load", args[0] if args else kwargs.get("analysis_id"))); return original(*args, **kwargs)
        monkeypatch.setattr(main, "_load_analysis_record", spy_load)
    monkeypatch.setattr(main, "collect_infrastructure", lambda *a, **k: demo_seed.get_demo_infrastructure(k.get("role_arn") or (a[0] if a else None)))
    monkeypatch.setattr(main, "generate_explanation", lambda *a, **k: {"ai_summary": "demo", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0})
    monkeypatch.setattr(main, "save_report", lambda *a, **k: "demo-report")
    monkeypatch.setattr(main, "get_report_url", lambda *a, **k: "demo-url")
    for arn in (demo_seed.DEMO_ROLE_ARN, demo_seed.DEMO_ROLE_ARN_V2):
        for endpoint in ("/analyze", "/analyze/stream"):
            response = client.post(endpoint, json={"role_arn": arn, "region": "us-east-1"})
            assert response.status_code == 200, response.text
            assert real_marker not in response.text
    assert before == database.get_scan_count_today(real)
    assert calls and all(account == "000000000000" for _kind, account in calls if _kind in {"count", "save", "previous"})


def test_L42c_demo_infrastructure_is_builtin(monkeypatch):
    def fail():
        raise AssertionError("demo must not use the database")
    monkeypatch.setattr(database, "SessionLocal", fail)
    first = demo_seed.get_demo_infrastructure(demo_seed.DEMO_ROLE_ARN)
    second = demo_seed.get_demo_infrastructure(demo_seed.DEMO_ROLE_ARN)
    v2 = demo_seed.get_demo_infrastructure(demo_seed.DEMO_ROLE_ARN_V2)
    assert first.model_dump() == second.model_dump()
    assert v2.model_dump()
