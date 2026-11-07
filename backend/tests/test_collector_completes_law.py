"""L72: a real scan finishes.  collect_infrastructure must run end to end and return an
AWSInfrastructure with a timezone-aware ISO collected_at (a `datetime` import clash once made
it raise AttributeError after every collector had run)."""
from __future__ import annotations

import ast
from datetime import datetime
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[1] / "app" / "aws_collector.py"


def test_L72_a_collector_does_not_shadow_datetime_module():
    tree = ast.parse(COLLECTOR.read_text())
    module_import = any(
        isinstance(n, ast.Import) and any(a.name == "datetime" and a.asname is None for a in n.names)
        for n in ast.walk(tree)
    )
    class_import = any(
        isinstance(n, ast.ImportFrom) and n.module == "datetime"
        and any(a.name == "datetime" and a.asname is None for a in n.names)
        for n in ast.walk(tree)
    )
    assert not (module_import and class_import), "`import datetime` and `from datetime import datetime` clash"
    if class_import:
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute) \
                    and isinstance(n.value.value, ast.Name) and n.value.value.id == "datetime" \
                    and n.value.attr in ("datetime", "timezone"):
                raise AssertionError(f"module-style datetime use at line {n.lineno}")


def test_L72_b_collect_infrastructure_completes_under_moto(monkeypatch):
    from moto import mock_aws

    for var, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                       ("AWS_SESSION_TOKEN", "testing"), ("AWS_DEFAULT_REGION", "us-east-1")):
        monkeypatch.setenv(var, value)
    from app import aws_collector
    from app.models import AWSCredentials, AWSInfrastructure

    monkeypatch.setattr(aws_collector._time_module, "sleep", lambda _s: None)
    with mock_aws():
        creds = AWSCredentials(role_arn="arn:aws:iam::123456789012:role/x", region="us-east-1")
        assumed = {"AccessKeyId": "testing", "SecretAccessKey": "testing", "SessionToken": "testing"}
        infra = aws_collector.collect_infrastructure(creds, assumed)

    assert isinstance(infra, AWSInfrastructure)
    parsed = datetime.fromisoformat(infra.collected_at)
    assert parsed.tzinfo is not None and parsed.utcoffset() is not None
