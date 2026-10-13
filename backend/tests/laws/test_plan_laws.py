from hypothesis import HealthCheck, given, settings, strategies as st

from app import plan_ingest
from tests.test_plan_ingest import plan_client


AWS_PROVIDERS = st.one_of(
    st.sampled_from([
        "registry.terraform.io/hashicorp/aws",
        "registry.opentofu.org/hashicorp/aws",
        "registry.terraform.io/hashicorp/awscc",
    ]), st.none(),
)
AWS_TYPES = st.sampled_from([
    "aws_dynamodb_table", "aws_efs_file_system", "aws_rds_cluster", "aws_kms_key",
    "aws_secretsmanager_secret", "aws_sqs_queue", "awscc_rds_db_cluster",
])
AWS_ACTIONS = st.sampled_from([["delete"], ["delete", "create"], ["create", "delete"]])
NON_AWS_NAMES = st.sampled_from(["random", "null", "local", "tls", "time", "http", "kubernetes", "google", "azurerm", "cloudflare"])
NON_AWS_ACTIONS = st.sampled_from([["create"], ["update"], ["delete"], ["delete", "create"], ["create", "delete"]])


def _entry(address, typ, provider, actions):
    result = {"address": address, "mode": "managed", "type": typ, "name": "x",
              "change": {"actions": actions, "before": {}, "after": {}}}
    if provider is not None:
        result["provider_name"] = provider
    return result


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(AWS_PROVIDERS, AWS_TYPES, AWS_ACTIONS)
def test_L10_unmodeled_aws_delete_or_replace_blocks(plan_client, monkeypatch, provider, typ, actions):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    payload = {"format_version": "1.2", "resource_changes": [_entry("aws.x", typ, provider, actions)]}
    branch_id, _, response = __import__("tests.test_plan_ingest", fromlist=["_post"])._post(plan_client, payload)
    assert response.status_code == 200
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "block"
    assert "unmodeled_delete" in {reason["code"] for reason in result["reasons"]}


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(NON_AWS_NAMES, NON_AWS_ACTIONS)
def test_L11_non_aws_provider_warns_never_blocks_never_passes(plan_client, monkeypatch, name, actions):
    from app import branches
    monkeypatch.setattr(branches, "MAX_OPEN_BRANCHES_PER_BASE", 10000)
    provider = f"registry.terraform.io/example/{name}"
    payload = {"format_version": "1.2", "resource_changes": [
        _entry("resource.x", f"{name}_synthetic", provider, actions),
    ]}
    branch_id, _, response = __import__("tests.test_plan_ingest", fromlist=["_post"])._post(plan_client, payload)
    assert response.status_code == 200
    assert response.json()["applied"] == []
    result = plan_client.get(f"/branches/{branch_id}/verdict").json()
    assert result["verdict"] == "warn"
    assert {reason["code"] for reason in result["reasons"]} == {"outside_view"}
