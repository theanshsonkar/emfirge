from tests.incidents.synthetic_base import load_synthetic_base
from hypothesis import HealthCheck, given, settings, strategies as st

from app import plan_ingest
from tests.test_plan_ingest import _post, plan_client  # noqa: F401


aws_provider = st.one_of(
    st.sampled_from([
        "registry.terraform.io/hashicorp/aws",
        "registry.opentofu.org/hashicorp/aws",
        "registry.terraform.io/hashicorp/awscc",
        "registry.terraform.io/hashicorp/AWS",
    ]),
    st.none(),
)
unmodeled_aws_type = st.one_of(
    st.sampled_from([
        "aws_dynamodb_table", "aws_efs_file_system", "aws_rds_cluster", "aws_kms_key",
        "aws_secretsmanager_secret", "aws_sqs_queue", "awscc_rds_db_cluster",
    ]),
    st.from_regex(r"aws_[a-z]{3,12}", fullmatch=True),
    st.from_regex(r"awscc_[a-z]{3,12}", fullmatch=True),
).filter(lambda t: t not in plan_ingest._RESOURCE_MAP)
non_aws_word = st.one_of(
    st.sampled_from(["random", "null", "local", "tls", "time", "http", "kubernetes",
                     "google", "azurerm", "cloudflare"]),
    st.from_regex(r"[a-z]{2,10}", fullmatch=True),
).filter(lambda w: w not in {"aws", "awscc"})
non_aws_provider = st.builds(
    lambda host, ns, name: f"{host}/{ns}/{name}",
    st.sampled_from(["registry.terraform.io", "registry.opentofu.org"]),
    st.one_of(st.sampled_from(["hashicorp", "example"]), st.from_regex(r"[a-z]{2,8}", fullmatch=True)),
    non_aws_word,
)
non_aws_type = st.one_of(
    st.builds(lambda name, suffix: f"{name}_{suffix}", non_aws_word,
              st.from_regex(r"[a-z]{2,8}", fullmatch=True)),
    st.sampled_from(sorted(plan_ingest._RESOURCE_MAP)),
)
any_action = st.sampled_from([["create"], ["update"], ["delete"], ["delete", "create"], ["create", "delete"]])
delete_action = st.sampled_from([["delete"], ["delete", "create"], ["create", "delete"]])
aws_nondelete_action = st.sampled_from([["create"], ["update"]])
before_after = st.dictionaries(
    st.from_regex(r"[a-z]{1,8}", fullmatch=True),
    st.one_of(st.integers(-5, 5), st.booleans(), st.text(alphabet="abcxyz", max_size=6)),
    max_size=3,
)


def _entry(address, typ, provider, actions, before, after):
    result = {"address": address, "mode": "managed", "type": typ, "name": "x",
              "change": {"actions": actions, "before": before, "after": after}}
    if provider is not None:
        result["provider_name"] = provider
    return result


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(data=st.data())
def test_L10_unmodeled_aws_delete_or_replace_blocks(plan_client, monkeypatch, data):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    provider = data.draw(aws_provider)
    typ = data.draw(unmodeled_aws_type)
    actions = data.draw(delete_action)
    required = (typ, provider, actions, data.draw(before_after), data.draw(before_after))
    extras = []
    for _ in range(data.draw(st.integers(0, 4))):
        if data.draw(st.booleans()):
            extras.append((data.draw(non_aws_type), data.draw(non_aws_provider),
                           data.draw(any_action), data.draw(before_after), data.draw(before_after)))
        else:
            extras.append((data.draw(unmodeled_aws_type), data.draw(aws_provider),
                           data.draw(aws_nondelete_action), data.draw(before_after), data.draw(before_after)))
    entries = extras[:]
    entries.insert(data.draw(st.integers(0, len(entries))), required)
    payload = {"format_version": "1.2", "resource_changes": [
        _entry(f"{typ}.r{index}", typ, provider, actions, before, after)
        for index, (typ, provider, actions, before, after) in enumerate(entries)
    ]}
    branch_id, _, response = _post(plan_client, payload)
    assert response.status_code == 200
    assert len(response.json()["unmodeled"]) == len(entries)
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert "unmodeled_delete" in {reason["code"] for reason in result["reasons"]}


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(data=st.data(), entries=st.lists(
    st.tuples(non_aws_provider, non_aws_type, any_action, before_after, before_after),
    min_size=1, max_size=5,
))
def test_L11_non_aws_provider_warns_never_blocks_never_passes(plan_client, monkeypatch, data, entries):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    payload = {"format_version": "1.2", "resource_changes": [
        _entry(f"{typ}.r{index}", typ, provider, actions, before, after)
        for index, (provider, typ, actions, before, after) in enumerate(entries)
    ]}
    branch_id, _, response = _post(plan_client, payload)
    assert response.status_code == 200
    body = response.json()
    assert body["applied"] == []
    assert len(body["unmodeled"]) == len(entries)
    assert all(item["outside_view"] is True for item in body["unmodeled"])
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "warn"
    assert {reason["code"] for reason in result["reasons"]} == {"outside_view"}


def test_L15_terraform_and_aws_api_deletions_are_equivalent(plan_client):
    def compare(terraform_item, api_call):
        tf_branch, _, tf_response = _post(plan_client, {"format_version": "1.0", "resource_changes": [terraform_item]})
        assert tf_response.status_code == 200, tf_response.text
        tf_body = tf_response.json()
        assert tf_body["applied"]
        assert tf_body["rejected"] == []
        api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "aws-api-law"}).json()["branch_id"]
        api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [api_call]})
        assert api_response.status_code == 200, api_response.text
        api_body = api_response.json()
        assert api_body["applied"]
        assert api_body["rejected"] == []
        tf_verdict = plan_client.get(f"/branches/{tf_branch}/verdict").json()
        api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
        tf_reasons = {(item["code"], item["level"]) for item in tf_verdict["reasons"]}
        assert tf_reasons
        assert tf_reasons == {(item["code"], item["level"]) for item in api_verdict["reasons"]}
        assert tf_verdict["verdict"] == api_verdict["verdict"]

    compare(
        {"address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance",
         "change": {"actions": ["delete"], "before": {"identifier": "db-dl-prod", "skip_final_snapshot": True, "delete_automated_backups": True}, "after": None}},
        {"service": "rds", "operation": "DeleteDBInstance", "parameters": {"DBInstanceIdentifier": "db-dl-prod", "SkipFinalSnapshot": True, "DeleteAutomatedBackups": True}},
    )
    compare(
        {"address": "aws_instance.instance", "mode": "managed", "type": "aws_instance",
         "change": {"actions": ["delete"], "before": {"id": "i-dl-web"}, "after": None}},
        {"service": "ec2", "operation": "TerminateInstances", "parameters": {"InstanceIds": ["i-dl-web"]}},
    )



def test_L16_terraform_and_aws_api_public_ssh_are_equivalent(plan_client):
    base = load_synthetic_base("delete")
    sg = next(item for item in base.ec2.security_groups if item.id == "sg-dl-web")
    before = [{"from_port": rule.get("from_port"), "to_port": rule.get("to_port"),
               "protocol": rule.get("protocol"), "cidr_blocks": rule.get("ip_ranges", []),
               "security_groups": rule.get("source_sg_ids", [])} for rule in sg.rules]
    public_ssh = {"from_port": 22, "to_port": 22, "protocol": "tcp",
                  "cidr_blocks": ["0.0.0.0/0"], "security_groups": []}
    tf_branch, _, tf_response = _post(plan_client, {"format_version": "1.0", "resource_changes": [{
        "address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group",
        "name": "web", "change": {"actions": ["update"], "before": {"id": sg.id, "ingress": before},
        "after": {"id": sg.id, "ingress": before + [public_ssh]}}}]})
    assert tf_response.status_code == 200, tf_response.text
    tf_body = tf_response.json()
    api_branch = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "l16-api"}).json()["branch_id"]
    api_response = plan_client.post(f"/branches/{api_branch}/plans/aws-api", json={
        "format": "aws-api-calls/1", "calls": [{"service": "ec2",
        "operation": "AuthorizeSecurityGroupIngress", "parameters": {"GroupId": sg.id,
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}}]})
    assert api_response.status_code == 200, api_response.text
    api_body = api_response.json()
    for body in (tf_body, api_body):
        assert body["applied"] and body["rejected"] == []
    tf_verdict = plan_client.get(f"/branches/{tf_branch}/verdict").json()
    api_verdict = plan_client.get(f"/branches/{api_branch}/verdict").json()
    assert tf_verdict["verdict"] == api_verdict["verdict"]
    assert {(r["code"], r["level"]) for r in tf_verdict["reasons"]}
    assert {(r["code"], r["level"]) for r in tf_verdict["reasons"]} == {(r["code"], r["level"]) for r in api_verdict["reasons"]}


@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(prefix=st.one_of(
    st.sampled_from(["Delete", "Terminate", "Purge", "Deregister", "Release", "Remove",
                     "Detach", "Disassociate", "Revoke", "Stop", "Disable", "Create",
                     "Put", "Tag", "Start", "Modify", "Update", "Attach", "Associate",
                     "Enable", "Run"]),
    st.builds(lambda suffix: "Put" + suffix + "Policy",
              st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True)),
    st.builds(lambda suffix: "Put" + suffix + "Acl",
              st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True)),
), suffix=st.from_regex(r"[A-Z][a-z]{2,8}", fullmatch=True))
def test_L16_unmapped_aws_call_block_rule(plan_client, monkeypatch, prefix, suffix):
    from app import branches
    from app.aws_api_ingest import _DELETE_PREFIXES, _MAPPED
    import re

    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    operation = prefix + suffix
    assert not any((service, operation) in _MAPPED for service in ("custom", "ec2", "s3", "iam", "rds", "lambda"))
    risky = operation.startswith(("Detach", "Disassociate", "Revoke", "Stop", "Disable")) or bool(re.fullmatch(r"Put[A-Za-z0-9]*(Policy|Acl)", operation))
    delete = operation.startswith(_DELETE_PREFIXES)
    branch_id = plan_client.post("/branches", json={"base_analysis_id": "delete", "name": "aws-api-law"}).json()["branch_id"]
    response = plan_client.post(f"/branches/{branch_id}/plans/aws-api", json={"format": "aws-api-calls/1", "calls": [
        {"service": "custom", "operation": operation, "parameters": {}}
    ]})
    assert response.status_code == 200, response.text
    reasons = plan_client.get(f"/branches/{branch_id}/verdict").json()["reasons"]
    expected = "unmodeled_delete" if delete else "unmodeled_risky_change" if risky else "unmodeled_change"
    expected_level = "block" if delete or risky else "warn"
    assert any(reason["code"] == expected and reason["level"] == expected_level for reason in reasons)
    assert "pass" not in {reason["code"] for reason in reasons}
