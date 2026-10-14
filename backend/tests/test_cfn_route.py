import json

from tests.test_aws_api_route import _branch
from tests.test_plan_ingest import plan_client  # noqa: F401
from tests.laws.test_tenant_isolation import tenant_client  # noqa: F401


def post_cfn(client, changes, raw=None):
    branch = _branch(client)
    body = raw if raw is not None else json.dumps({"Changes": changes}, separators=(",", ":")).encode()
    response = client.post(f"/branches/{branch}/plans/cloudformation", content=body)
    return branch, body, response


def resource(action, typ, logical="Thing", physical="id-1", replacement="False", **extra):
    rc = {"Action": action, "LogicalResourceId": logical, "PhysicalResourceId": physical,
          "ResourceType": typ, "Replacement": replacement}
    rc.update(extra)
    return {"Type": "Resource", "ResourceChange": rc}


def verdict(client, branch):
    return client.get(f"/branches/{branch}/verdict").json()


def test_cloudformation_remove_instance_matches_aws_api(plan_client):
    cfn_branch, _, response = post_cfn(plan_client, [resource("Remove", "AWS::EC2::Instance", physical="i-dl-web")])
    assert response.status_code == 200, response.text
    api_branch = _branch(plan_client)
    api = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [{
        "service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}}]})
    assert api.status_code == 200, api.text
    assert verdict(plan_client, cfn_branch)["verdict"] == verdict(plan_client, api_branch)["verdict"]
    assert {(x["code"], x["level"]) for x in verdict(plan_client, cfn_branch)["reasons"]} == {(x["code"], x["level"]) for x in verdict(plan_client, api_branch)["reasons"]}


def test_cloudformation_sg_public_ssh_modify_has_same_exposure_reason(plan_client):
    before = json.dumps({"Properties": {"SecurityGroupIngress": []}})
    after = json.dumps({"Properties": {"SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}})
    branch, _, response = post_cfn(plan_client, [resource("Modify", "AWS::EC2::SecurityGroup", physical="sg-dl-web", BeforeContext=before, AfterContext=after)])
    assert response.status_code == 200, response.text
    assert any(r["code"] == "introduced_critical_exposure" for r in verdict(plan_client, branch)["reasons"])


def test_cloudformation_rds_replacement_behaves_as_delete(plan_client):
    base_analysis_id = "rds-replacement-equivalence"
    cfn_branch = plan_client.post("/branches", json={"base_analysis_id": base_analysis_id, "name": "rds-cfn"}).json()["branch_id"]
    api_branch = plan_client.post("/branches", json={"base_analysis_id": base_analysis_id, "name": "rds-api"}).json()["branch_id"]

    cfn = plan_client.post(
        f"/branches/{cfn_branch}/plans/cloudformation",
        json={"Changes": [resource("Modify", "AWS::RDS::DBInstance", physical="db-dl-prod", replacement="True")]},
    )
    assert cfn.status_code == 200, cfn.text
    api = plan_client.post(
        f"/branches/{api_branch}/plans/aws-api",
        json={"format": "aws-api-calls/1", "calls": [{
            "service": "rds",
            "operation": "DeleteDBInstance",
            "parameters": {"DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True},
        }]},
    )
    assert api.status_code == 200, api.text

    cfn_result = verdict(plan_client, cfn_branch)
    api_result = verdict(plan_client, api_branch)
    if cfn_result["verdict"] != api_result["verdict"]:
        pytest.fail(f"verdicts differ: cfn={cfn_result!r}; aws_api={api_result!r}")
    assert {r["code"] for r in cfn_result["reasons"]} == {r["code"] for r in api_result["reasons"]}
    assert cfn_result["verdict"] != "pass"
    assert "db-dl-prod" in plan_client.get(f"/branches/{cfn_branch}/diff").json()["removed_nodes"]
    assert "db-dl-prod" in plan_client.get(f"/branches/{api_branch}/diff").json()["removed_nodes"]


def test_cloudformation_conditional_replacement_has_warn_unmodeled_change(plan_client):
    branch, _, response = post_cfn(plan_client, [resource("Modify", "AWS::RDS::DBInstance", physical="db-dl-prod", replacement="Conditional")])
    assert response.status_code == 200, response.text
    assert any(r["code"] == "unmodeled_change" and r["level"] == "warn" for r in verdict(plan_client, branch)["reasons"])


def test_cloudformation_exact_handback_and_one_character_rejection(plan_client):
    raw = b'{ "Changes" : [ { "Type":"Resource", "ResourceChange":{"Action":"Remove","LogicalResourceId":"I","PhysicalResourceId":"i-dl-web","ResourceType":"AWS::EC2::Instance","Replacement":"False"} } ] }\n'
    branch, _, response = post_cfn(plan_client, [], raw=raw)
    assert response.status_code == 200, response.text
    plan_id = response.json()["plan_id"]
    handback = plan_client.get(f"/branches/{branch}/plans/{plan_id}/handback").json()
    assert handback["plan_text"].encode() == raw
    assert plan_client.post("/handback/verify", json={"plan_id": plan_id, "verdict_id": handback["verdict_id"], "plan_text": handback["plan_text"]}).json() == {"ok": True}
    changed = handback["plan_text"][:-1] + ("0" if handback["plan_text"][-1] != "0" else "1")
    rejected = plan_client.post("/handback/verify", json={"plan_id": plan_id, "verdict_id": handback["verdict_id"], "plan_text": changed})
    assert rejected.status_code == 409 and rejected.json() == {"ok": False, "reason_code": "input_hash_mismatch"}


def test_cloudformation_rds_replace_and_retain_keeps_database(plan_client):
    branch, _, response = post_cfn(plan_client, [resource("Modify", "AWS::RDS::DBInstance", physical="db-dl-prod", replacement="True", PolicyAction="ReplaceAndRetain")])
    assert response.status_code == 200, response.text
    result = verdict(plan_client, branch)
    assert not any(r.get("code") == "unmodeled_delete" or r.get("code") == "plan_delete_rejected" for r in result["reasons"])
    assert plan_client.get(f"/branches/{branch}/diff").json()["removed_nodes"] == []


def test_cloudformation_deeply_nested_json_is_422(plan_client):
    branch = _branch(plan_client)
    raw = (b"[" * 2000) + (b"]" * 2000)
    response = plan_client.post(f"/branches/{branch}/plans/cloudformation", content=raw)
    assert response.status_code == 422


def test_cloudformation_bad_document_is_422(plan_client):
    branch = _branch(plan_client)
    response = plan_client.post(f"/branches/{branch}/plans/cloudformation", content=b'{"Changes":')
    assert response.status_code == 422


def test_cloudformation_unknown_branch_matches_aws_api(plan_client):
    body = b'{"Changes":[]}'
    cfn = plan_client.post("/branches/not-a-branch/plans/cloudformation", content=body)
    api = plan_client.post("/branches/not-a-branch/plans/aws-api", content=b'{"format":"aws-api-calls/1","calls":[]}')
    assert cfn.status_code == api.status_code == 404
    assert cfn.json() == api.json()


def test_cloudformation_plan_is_tenant_isolated(tenant_client):
    from tests.laws.test_isolation_branches import _assert_hidden, _create_a_branch
    client, key_a, key_b, _ = tenant_client
    branch = _create_a_branch(client, key_a)
    raw = b'{"Changes":[]}'
    hidden = _assert_hidden(client, key_b, branch, "/branches/A_BRANCH/plans/cloudformation", method="post", content=raw)
    assert hidden.status_code == 404
    created = client.post(f"/branches/{branch}/plans/cloudformation", headers={"X-API-Key": key_a}, content=raw)
    assert created.status_code == 200, created.text
    plan_id = created.json()["plan_id"]
    _assert_hidden(client, key_b, branch, f"/branches/A_BRANCH/plans/{plan_id}/handback")
