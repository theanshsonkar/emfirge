import secrets

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app import auth, role_access
from app.database import (
    APIKey,
    AccountBinding,
    AccountBindingEvent,
    Base,
    Project,
    SessionLocal,
    engine,
)
from app.main import app
from app.models import AWSInfrastructure


ROLE = "arn:aws:iam::123456789012:role/Emfirge"


class FakeSTS:
    def __init__(self, accepted_by_role=None):
        self.accepted_by_role = accepted_by_role or {}
        self.calls = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        accepted = self.accepted_by_role.get(
            kwargs["RoleArn"], self.accepted_by_role.get(ROLE, set())
        )
        if accepted != "ANY" and kwargs["ExternalId"] not in accepted:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "AssumeRole",
            )
        return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"}}


@pytest.fixture
def client(monkeypatch):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setenv("EMFIRGE_REQUIRE_AUTH", "1")
    return TestClient(app)


@pytest.fixture
def sts(monkeypatch):
    fake = FakeSTS()
    monkeypatch.setattr(role_access, "_sts_client", lambda: fake)
    return fake


def make_key(project_name):
    return auth.create_api_key(project_name)


def project_info(client, key):
    response = client.get("/project", headers={"X-API-Key": key})
    assert response.status_code == 200
    return response.json()


def project_id(project_name):
    db = SessionLocal()
    try:
        return db.query(Project).filter_by(name=project_name).one().id
    finally:
        db.close()


def bind(account_id, project_name):
    db = SessionLocal()
    try:
        db.add(AccountBinding(aws_account_id=account_id, project_id=project_id(project_name)))
        db.commit()
    finally:
        db.close()


def binding_exists(account_id):
    db = SessionLocal()
    try:
        return db.query(AccountBinding).filter_by(aws_account_id=account_id).first() is not None
    finally:
        db.close()


def event_exists(account_id, action):
    db = SessionLocal()
    try:
        return db.query(AccountBindingEvent).filter_by(
            aws_account_id=account_id, action=action
        ).first() is not None
    finally:
        db.close()


def remove_binding(account_id):
    db = SessionLocal()
    try:
        db.query(AccountBindingEvent).filter_by(aws_account_id=account_id).delete()
        db.query(AccountBinding).filter_by(aws_account_id=account_id).delete()
        db.commit()
    finally:
        db.close()


def enable_scan(monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "collect_infrastructure", lambda credentials, assumed_credentials=None: AWSInfrastructure(region=credentials.region))
    monkeypatch.setattr(main, "generate_explanation", lambda *args: {
        "ai_summary": "ok", "recommended_improvements": [], "priority_actions": [], "latency_ms": 0,
    })
    monkeypatch.setattr(main, "save_report", lambda *args, **kwargs: "report.json")
    monkeypatch.setattr(main, "get_report_url", lambda *args, **kwargs: "https://example.test/report")
    monkeypatch.setattr(main, "save_analysis", lambda *args, **kwargs: 1)
    monkeypatch.setattr(main, "get_previous_scan_for_account", lambda *args, **kwargs: {})


def analyze(client, key, role=ROLE, account="123456789012", **extra):
    body = {"role_arn": role.replace("123456789012", account), "region": "us-east-1", **extra}
    return client.post("/analyze", json=body, headers={"X-API-Key": key})


def names():
    suffix = secrets.token_hex(8)
    return f"law-a-{suffix}", f"law-b-{suffix}"


def test_law_key_a_never_uses_key_b_external_id(client, sts):
    name_a, name_b = names()
    key_a, key_b = make_key(name_a), make_key(name_b)
    id_a = project_info(client, key_a)["external_id"]
    id_b = project_info(client, key_b)["external_id"]
    remove_binding("123456789012")
    sts.accepted_by_role[ROLE] = {id_b}

    response = analyze(client, key_a)

    assert response.status_code == 403
    assert all(call["ExternalId"] != id_b for call in sts.calls)
    assert id_a in [call["ExternalId"] for call in sts.calls]


def test_law_bound_and_failed_errors_identical(client, sts):
    name_a, name_b = names()
    key_a, key_b = make_key(name_a), make_key(name_b)
    id_b = project_info(client, key_b)["external_id"]
    account_bound, account_failed = "111111111111", "222222222222"
    remove_binding(account_bound)
    bind(account_bound, name_b)
    sts.accepted_by_role[ROLE] = {id_b}

    response_x = analyze(client, key_a, account=account_bound)
    response_y = analyze(client, key_a, account=account_failed)

    assert response_x.status_code == response_y.status_code == 403
    assert response_x.json() == response_y.json()


def test_failed_attempt_by_b_does_not_block_a(client, sts, monkeypatch):
    name_a, name_b = names()
    key_a, key_b = make_key(name_a), make_key(name_b)
    id_a = project_info(client, key_a)["external_id"]
    account = "333333333333"
    remove_binding(account)
    sts.accepted_by_role[ROLE] = {id_a}

    failed = analyze(client, key_b, account=account)
    assert failed.status_code == 403
    assert not binding_exists(account)

    enable_scan(monkeypatch)
    succeeded = analyze(client, key_a, account=account)
    assert succeeded.status_code == 200
    assert binding_exists(account)


def test_bound_account_refuses_other_project_without_sts_call(client, sts, monkeypatch):
    name_a, name_b = names()
    key_a, key_b = make_key(name_a), make_key(name_b)
    id_a = project_info(client, key_a)["external_id"]
    id_b = project_info(client, key_b)["external_id"]
    account = "444444444444"
    remove_binding(account)
    sts.accepted_by_role[ROLE] = {id_a}
    enable_scan(monkeypatch)
    assert analyze(client, key_a, account=account).status_code == 200
    sts.calls.clear()
    sts.accepted_by_role[ROLE] = {id_b}

    response = analyze(client, key_b, account=account)

    assert response.status_code == 403
    assert all(call["ExternalId"] != id_b for call in sts.calls)


def test_replacement_key_keeps_external_id_and_access(client, sts, monkeypatch):
    name_a, _ = names()
    key_a = make_key(name_a)
    id_a = project_info(client, key_a)["external_id"]
    account = "555555555555"
    remove_binding(account)
    sts.accepted_by_role[ROLE] = {id_a}
    enable_scan(monkeypatch)
    assert analyze(client, key_a, account=account).status_code == 200

    db = SessionLocal()
    try:
        replacement = auth.generate_api_key()
        db.add(APIKey(key_hash=auth.hash_key(replacement), project_name=name_a, active=True))
        db.commit()
    finally:
        db.close()

    assert project_info(client, replacement)["external_id"] == id_a
    assert analyze(client, replacement, account=account).status_code == 200


def test_old_shared_role_gets_redeploy_message(client, sts):
    name_a, _ = names()
    key_a = make_key(name_a)
    remove_binding("123456789012")
    sts.accepted_by_role[ROLE] = {"old-shared-id"}

    response = analyze(client, key_a)

    assert response.status_code == 403
    assert "redeploy" in response.json()["detail"].lower()


def test_request_external_id_field_is_ignored(client, sts, monkeypatch):
    name_a, _ = names()
    key_a = make_key(name_a)
    remove_binding("123456789012")
    id_a = project_info(client, key_a)["external_id"]
    sts.accepted_by_role[ROLE] = {id_a}
    enable_scan(monkeypatch)

    response = analyze(client, key_a, external_id="attacker", ExternalId="attacker")

    assert response.status_code == 200
    assert all(call["ExternalId"] != "attacker" for call in sts.calls)
    assert sts.calls[0]["ExternalId"] == id_a


def test_project_external_ids_unique_and_long(client):
    name_a, name_b = names()
    key_a, key_b = make_key(name_a), make_key(name_b)
    id_a = project_info(client, key_a)["external_id"]
    id_b = project_info(client, key_b)["external_id"]

    assert id_a != id_b
    assert len(id_a) >= 32
    assert len(id_b) >= 32


def test_self_host_requires_env(client, sts, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    monkeypatch.delenv("EMFIRGE_EXTERNAL_ID", raising=False)
    response = analyze(client, "", account="666666666666")
    assert response.status_code == 503

    value = "self-host-external-id-for-test"
    monkeypatch.setenv("EMFIRGE_EXTERNAL_ID", value)
    sts.accepted_by_role[ROLE] = {value}
    enable_scan(monkeypatch)
    response = analyze(client, "", account="666666666666")

    assert response.status_code == 200
    assert [call["ExternalId"] for call in sts.calls] == [value]


def test_admin_unbind(client, sts):
    name_a, _ = names()
    key_a = make_key(name_a)
    project_info(client, key_a)
    account = "777777777777"
    remove_binding(account)
    bind(account, name_a)

    response = client.delete(f"/admin/account-bindings/{account}")
    assert response.status_code == 404

    import os
    os.environ["EMFIRGE_ADMIN_KEY"] = "law-admin-key"
    try:
        assert client.delete(f"/admin/account-bindings/{account}", headers={"X-Admin-Key": "wrong"}).status_code == 403
        response = client.delete(f"/admin/account-bindings/{account}", headers={"X-Admin-Key": "law-admin-key"})
    finally:
        os.environ.pop("EMFIRGE_ADMIN_KEY", None)

    assert response.status_code == 200
    assert not binding_exists(account)
    assert event_exists(account, "unbind")


def test_unsafe_role_any_external_id_refused(client, sts):
    name_a, _ = names()
    key_a = make_key(name_a)
    account = "888888888888"
    remove_binding(account)
    sts.accepted_by_role[ROLE] = "ANY"

    response = analyze(client, key_a, account=account)

    assert response.status_code == 403
    assert "unsafe" in response.json()["detail"].lower()
    assert not binding_exists(account)
