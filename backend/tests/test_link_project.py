import pytest
from sqlalchemy import inspect

from app import auth, database
from app.database import AccountBinding, Project, SupabaseIdentity
from app.main import app
from fastapi.testclient import TestClient
from tests.supabase_fake import make_token


@pytest.fixture
def client(shared_test_db, supabase_env):
    return TestClient(app)


def headers(token, key):
    return {"Authorization": f"Bearer {token}", "X-Emfirge-Link-Key": key}


def test_link_moves_empty_supabase_project_to_api_key_project(client):
    token = make_token("link-user")
    assert client.get("/project", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    key = auth.create_api_key("old-project")
    response = client.post("/auth/link-project", headers=headers(token, key))
    assert response.status_code == 200
    assert response.json() == {"linked": True, "project": "old-project"}
    assert client.get("/project", headers={"Authorization": f"Bearer {token}"}).json()["project"] == "old-project"
    with database.SessionLocal() as db:
        assert db.query(Project).filter_by(name="sb-link-user").first() is None
        assert db.query(SupabaseIdentity).filter_by(supabase_user_id="link-user").one().project_id == db.query(Project).filter_by(name="old-project").one().id


def test_link_requires_supabase_token_and_link_key(client):
    assert client.post("/auth/link-project").status_code == 401
    key = auth.create_api_key("missing-link-header-project")
    assert client.post(
        "/auth/link-project",
        headers={"Authorization": f"Bearer {key}"},
    ).status_code == 401


def test_link_is_idempotent_and_rejects_bad_key_without_mutation(client):
    token = make_token("idempotent-user")
    key = auth.create_api_key("idempotent-project")
    assert client.post("/auth/link-project", headers=headers(token, key)).status_code == 200
    second = client.post("/auth/link-project", headers=headers(token, key))
    assert second.status_code == 200
    bad = client.post("/auth/link-project", headers=headers(token, "not-a-key"))
    assert bad.status_code == 401
    assert bad.json() == {"detail": "Unauthorized"}


def test_link_refuses_project_with_existing_signed_in_data(client):
    token = make_token("data-user")
    client.get("/project", headers={"Authorization": f"Bearer {token}"})
    with database.SessionLocal() as db:
        project = db.query(Project).filter_by(name="sb-data-user").one()
        db.add(AccountBinding(aws_account_id="123456789012", project_id=project.id))
        db.commit()
    key = auth.create_api_key("another-project")
    response = client.post("/auth/link-project", headers=headers(token, key))
    assert response.status_code == 409
    assert response.json()["detail"] == "Your signed-in project already has data. Ask the operator to merge."


def test_link_auth_material_never_logged(client, caplog):
    token = make_token("private-user")
    key = "synthetic-link-key"
    caplog.set_level("DEBUG")
    client.post("/auth/link-project", headers=headers(token, key))
    assert token not in caplog.text
    assert key not in caplog.text
