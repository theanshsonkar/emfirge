import json

from app import auth, database
from app.demo_seed import build_demo_infrastructure
from app.database import AnalysisLog

from .test_tenant_isolation import tenant_client


NOT_FOUND_BRANCH = "00000000-0000-0000-0000-000000000000"


def _headers(key):
    return {"X-API-Key": key}


def _same_not_found(resp_hidden, hidden_id, resp_missing, missing_id):
    assert resp_hidden.status_code == resp_missing.status_code
    assert json.dumps(resp_hidden.json()).replace(hidden_id, '<ID>') == json.dumps(resp_missing.json()).replace(missing_id, '<ID>')


def _seed_demo_analysis():
    db = database.SessionLocal()
    try:
        log = db.query(AnalysisLog).filter_by(aws_account_id="111111111111").one()
        findings = json.loads(log.findings_json)
        findings["infrastructure"] = build_demo_infrastructure().model_dump(mode="json")
        db.query(AnalysisLog).filter(AnalysisLog.id == log.id).update(
            {AnalysisLog.findings_json: json.dumps(findings)}
        )
        db.commit()
    finally:
        db.close()


def _clear_branch_limiter():
    from app import main
    main._branch_request_log.clear()


def _create_a_branch(client, key_a):
    _seed_demo_analysis()
    _clear_branch_limiter()
    response = client.post(
        "/branches", headers=_headers(key_a),
        json={"base_analysis_id": "a-uuid", "name": "tenant-law-branch"},
    )
    assert response.status_code == 200, response.text
    branch_id = response.json()["branch_id"]
    own = client.get(f"/branches/{branch_id}", headers=_headers(key_a))
    assert own.status_code == 200, own.text
    return branch_id


def _assert_hidden(client, key_b, branch_id, route, *, method="get", json_body=None, content=None):
    request = getattr(client, method)
    route = route.replace("A_BRANCH", branch_id)
    random_route = route.replace(branch_id, NOT_FOUND_BRANCH)
    kwargs = {"headers": _headers(key_b)}
    if json_body is not None:
        kwargs["json"] = json_body
    if content is not None:
        kwargs["content"] = content
    _clear_branch_limiter()
    hidden = request(route, **kwargs)
    _clear_branch_limiter()
    random = request(random_route, **kwargs)
    _same_not_found(hidden, branch_id, random, NOT_FOUND_BRANCH)
    return hidden


def _append_payload():
    return {
        "op": "add", "resource_type": "s3_bucket",
        "resource_id": "tenant-law-extra", "fields": {},
    }


def test_branch_create_is_scoped_to_analysis_account(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    missing = client.post(
        "/branches", headers=_headers(key_b),
        json={"base_analysis_id": "does-not-exist", "name": "stolen"},
    )
    cross = client.post(
        "/branches", headers=_headers(key_b),
        json={"base_analysis_id": "a-uuid", "name": "stolen"},
    )
    assert cross.status_code == missing.status_code == 404
    assert cross.json() == missing.json()
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200


def test_branch_list_is_scoped_and_matches_a_fresh_project(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    key_fresh = auth.create_api_key("tenant-law-fresh")
    client.get("/project", headers=_headers(key_fresh))
    listed_b = client.get("/branches", headers=_headers(key_b))
    listed_fresh = client.get("/branches", headers=_headers(key_fresh))
    assert listed_b.status_code == listed_fresh.status_code == 200
    assert listed_b.json() == listed_fresh.json() == []
    assert branch_id not in listed_b.text
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200


def test_branch_inspect_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH")
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200


def test_branch_append_is_scoped_and_does_not_mutate_a(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    before = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/changes", method="post", json_body=_append_payload())
    after = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    assert after["num_changes"] == before["num_changes"]
    assert after["branch_revision"] == before["branch_revision"]


def test_branch_diff_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/diff")
    assert client.get(f"/branches/{branch_id}/diff", headers=_headers(key_a)).status_code == 200


def test_branch_verdict_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/verdict")
    assert client.get(f"/branches/{branch_id}/verdict", headers=_headers(key_a)).status_code == 200


def test_branch_rollback_is_scoped_and_does_not_mutate_a(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    assert client.post(f"/branches/{branch_id}/changes", headers=_headers(key_a), json=_append_payload()).status_code == 200
    before = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/rollback", method="post", json_body={})
    after = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    assert after["num_changes"] == before["num_changes"]
    assert after["branch_revision"] == before["branch_revision"]


def test_branch_discard_is_scoped_and_does_not_mutate_a(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    before = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/discard", method="post", json_body={})
    after = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    assert after["num_changes"] == before["num_changes"]
    assert after["branch_revision"] == before["branch_revision"]


def test_branch_fork_is_scoped_and_does_not_mutate_a(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    before = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/fork", method="post", json_body={"name": "stolen"})
    after = client.get(f"/branches/{branch_id}", headers=_headers(key_a)).json()
    assert after["num_changes"] == before["num_changes"]
    assert after["branch_revision"] == before["branch_revision"]


def test_branch_compare_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    hidden = client.post("/branches/compare", headers=_headers(key_b), json={"branch_ids": [branch_id]})
    random = client.post("/branches/compare", headers=_headers(key_b), json={"branch_ids": [NOT_FOUND_BRANCH]})
    _same_not_found(hidden, branch_id, random, NOT_FOUND_BRANCH)
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200


def test_branch_plan_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    plan = {"format_version": "1.0", "resource_changes": []}
    _assert_hidden(client, key_b, branch_id, "/branches/A_BRANCH/plans/terraform", method="post", json_body=plan)
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200


def test_branch_handback_is_scoped(tenant_client):
    client, key_a, key_b, _ = tenant_client
    branch_id = _create_a_branch(client, key_a)
    plan = {"format_version": "1.0", "resource_changes": []}
    created = client.post(f"/branches/{branch_id}/plans/terraform", headers=_headers(key_a), json=plan)
    assert created.status_code == 200, created.text
    plan_id = created.json()["plan_id"]
    _assert_hidden(client, key_b, branch_id, f"/branches/A_BRANCH/plans/{plan_id}/handback")
    assert client.get(f"/branches/{branch_id}", headers=_headers(key_a)).status_code == 200
