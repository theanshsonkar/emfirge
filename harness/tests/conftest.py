"""Shared test set-up. Tests marked `lab` start local fakes (never real AWS) and run only with EMFIRGE_LAB=1."""
from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get('EMFIRGE_LAB') == '1':
        return
    skip = pytest.mark.skip(reason='lab test: set EMFIRGE_LAB=1 to start local fakes')
    for item in items:
        if 'lab' in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _no_aws_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may pick up a real AWS profile, endpoint or proxy from the shell."""
    for k in ('AWS_PROFILE', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_SESSION_TOKEN', 'AWS_CA_BUNDLE',
              'AWS_ENDPOINT_URL', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'HTTPS_PROXY', 'https_proxy',
              'HTTP_PROXY', 'http_proxy'):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    monkeypatch.setenv('no_proxy', '127.0.0.1,localhost')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-west-2')
