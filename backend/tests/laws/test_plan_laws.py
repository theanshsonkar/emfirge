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
