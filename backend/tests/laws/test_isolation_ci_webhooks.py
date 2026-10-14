from app import auth, database
from app.database import CIAPIKey, TFResource
from app.main import app

from .test_tenant_isolation import tenant_client


A_INSTALLATION = 101
A_REPO = "tenant-a/infrastructure"


def _headers(key):
    return {"X-API-Key": key}


def _seed_rows():
    database.save_tf_index(A_INSTALLATION, A_REPO, [{
        "resource_type": "aws_s3_bucket",
        "resource_name": "tenant_a_bucket",
        "file_path": "main.tf",
        "line_number": 1,
        "identifiers": {"id": "a-bucket"},
        "block_content": "resource aws_s3_bucket tenant_a_bucket {}",
    }])
    database.create_ci_api_key(A_INSTALLATION, A_REPO)


def _row_state():
    session = database.SessionLocal()
    try:
        tf = [
            (r.installation_id, r.repo_full_name, r.resource_type, r.resource_name,
             r.file_path, r.line_number, r.identifiers_json, r.block_content)
            for r in session.query(TFResource).order_by(TFResource.id).all()
        ]
        ci = [
            (r.installation_id, r.repo_full_name, r.api_key, r.is_active)
            for r in session.query(CIAPIKey).order_by(CIAPIKey.id).all()
        ]
        return tf, ci
    finally:
        session.close()


def _assert_hosted_legacy_route(client, key_b, path, method="get", **kwargs):
    _seed_rows()
    before = _row_state()
    shared = getattr(client, method)(path, headers=_headers(key_b), **kwargs)
    nonexistent = getattr(client, method)(
        path.replace(str(A_INSTALLATION), "999"),
        headers=_headers(key_b),
        **kwargs,
    )
    assert shared.status_code == nonexistent.status_code == 404
    assert shared.content == nonexistent.content
    assert _row_state() == before


def test_github_install_url_is_non_tenant_data(tenant_client):
    client, key_a, _, _ = tenant_client
    response = client.get("/github/install-url", headers=_headers(key_a))
    assert response.status_code == 200
    assert response.json()["url"]


def test_github_repos_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    _assert_hosted_legacy_route(client, key_b, f"/github/repos?installation_id={A_INSTALLATION}")


def test_github_pr_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    body = {"installation_id": A_INSTALLATION, "repo": A_REPO, "finding": {}, "hcl": "resource {}"}
    _assert_hosted_legacy_route(client, key_b, "/github/pr", "post", json=body)


def test_github_index_tf_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    body = {"installation_id": A_INSTALLATION, "repo": A_REPO}
    _assert_hosted_legacy_route(client, key_b, "/github/index-tf", "post", json=body)


def test_github_index_status_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    _assert_hosted_legacy_route(
        client, key_b,
        f"/github/index-status?installation_id={A_INSTALLATION}&repo={A_REPO}",
    )


def test_github_webhook_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    _assert_hosted_legacy_route(
        client, key_b,
        f"/github/webhook?installation_id={A_INSTALLATION}",
        "post",
        content=b"{}",
    )


def test_ci_api_key_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    body = {"installation_id": A_INSTALLATION, "repo": A_REPO}
    _assert_hosted_legacy_route(client, key_b, "/ci/api-key", "post", json=body)


def test_ci_api_keys_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    _assert_hosted_legacy_route(
        client, key_b,
        f"/ci/api-keys?installation_id={A_INSTALLATION}",
    )


def test_ci_analyze_hosted_mode_is_disabled(tenant_client):
    client, _, key_b, _ = tenant_client
    body = {"repo": A_REPO, "pr_number": 1, "analysis_id": "999999"}
    _assert_hosted_legacy_route(
        client, key_b,
        f"/ci/analyze?installation_id={A_INSTALLATION}",
        "post",
        json=body,
    )
