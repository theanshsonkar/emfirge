"""Focused tests for API-key authentication and protected routes."""

from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import auth
from app.main import app


client = TestClient(app)


class FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False
        self.closed = False

    def add(self, value):
        self.added.append(value)

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def test_auth_disabled_allows_sensitive_route(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    with patch("app.main.branches.list_branches", return_value=[]):
        response = client.get("/branches")
    assert response.status_code == 200


def test_auth_enabled_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    response = client.get("/branches")
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


def test_valid_created_key_allows_sensitive_route(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setattr(auth, "verify_api_key", lambda raw: SimpleNamespace(active=True))
    with patch("app.main.branches.list_branches", return_value=[]):
        response = client.get("/branches", headers={"Authorization": "Bearer emf_test"})
    assert response.status_code == 200


def test_inactive_key_is_rejected(monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setattr(auth, "verify_api_key", lambda raw: None)
    response = client.get("/branches", headers={"X-API-Key": "emf_inactive"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


def test_hash_is_deterministic_and_generated_keys_differ():
    assert auth.hash_key("emf_same") == auth.hash_key("emf_same")
    assert auth.hash_key("emf_same") != auth.hash_key("emf_other")
    assert auth.generate_api_key() != auth.generate_api_key()
    assert auth.generate_api_key().startswith("emf_")


def test_create_key_persists_only_hash_and_closes_session(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(auth, "SessionLocal", lambda: session)

    raw = auth.create_api_key("test-project")

    assert raw.startswith("emf_")
    assert session.committed is True
    assert session.closed is True
    assert len(session.added) == 1
    stored = session.added[0]
    assert stored.project_name == "test-project"
    assert stored.active is True
    assert stored.key_hash == auth.hash_key(raw)
    assert raw not in stored.key_hash
    assert not hasattr(stored, "key")
