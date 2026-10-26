"""L67 Terraform role identity: a role created with an unknown arn is identified by name plus an account id, never by a guess.

The arn of aws_iam_role is "known after apply", but AWS builds it from account, path and name.
The account comes from the base snapshot (when it has exactly one), else from the plan
(an aws_caller_identity data source in prior_state), else the placeholder 000000000000, which
is recorded in unknown_fields because it is only fit for identity, not for comparing accounts.
"""
import json

from app.models import AWSInfrastructure
from app.mutations import Change, apply_change
from app.plan_ingest import translate_plan

TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def role_item(name="web", path="/", address="aws_iam_role.web", unknown=None, **extra):
    after = {"name": name, "path": path, "assume_role_policy": json.dumps(TRUST), **extra}
    return {"address": address, "mode": "managed", "type": "aws_iam_role", "name": address.split(".")[-1],
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["create"], "before": None, "after": after,
                       "after_unknown": {"arn": True, "id": True, **(unknown or {})}}}


def plan(*items, account=None):
    document = {"format_version": "1.2", "resource_changes": list(items)}
    if account:
        document["prior_state"] = {"values": {"root_module": {"resources": [
            {"address": "data.aws_caller_identity.current", "mode": "data", "type": "aws_caller_identity",
             "name": "current", "values": {"account_id": account}}]}}}
    return document


def base_with_account(account):
    infra = AWSInfrastructure(region="us-east-1")
    return apply_change(infra, Change(op="add", resource_type="iam_role",
                                      resource_id=f"arn:aws:iam::{account}:role/existing", fields={"trust_policy": TRUST}))


def test_account_from_plan_caller_identity():
    result = translate_plan(plan(role_item(), account="123456789012"))
    assert result["changes"][0].resource_id == "arn:aws:iam::123456789012:role/web"
    assert not [u for u in result["unknown_fields"] if u["field"] == "arn"]


def test_account_from_single_base_account_wins_over_plan():
    base = base_with_account("111111111111")
    result = translate_plan(plan(role_item(), account="123456789012"), iam_roles=base.iam.role_policies)
    assert result["changes"][0].resource_id == "arn:aws:iam::111111111111:role/web"


def test_two_base_accounts_fall_back_to_plan():
    base = base_with_account("111111111111")
    base = apply_change(base, Change(op="add", resource_type="iam_role", resource_id="arn:aws:iam::222222222222:role/other", fields={}))
    result = translate_plan(plan(role_item(), account="123456789012"), iam_roles=base.iam.role_policies)
    assert result["changes"][0].resource_id == "arn:aws:iam::123456789012:role/web"


def test_placeholder_is_recorded_as_unknown():
    result = translate_plan(plan(role_item()))
    assert result["changes"][0].resource_id == "arn:aws:iam::000000000000:role/web"
    assert {"address": "aws_iam_role.web", "field": "arn",
            "reason": "account id unknown at plan time; placeholder used for identity only"} in result["unknown_fields"]


def test_path_is_part_of_the_arn_and_trust_policy_is_carried():
    result = translate_plan(plan(role_item(path="/service-role/"), account="123456789012"))
    change = result["changes"][0]
    assert change.resource_id == "arn:aws:iam::123456789012:role/service-role/web"
    assert change.fields["trust_policy"] == TRUST
    branch = apply_change(AWSInfrastructure(region="us-east-1"), change)
    role = branch.iam.role_policies[0]
    assert role.role_name == "web" and role.trusted_services == ["ec2.amazonaws.com"]


def test_known_arn_is_used_as_is():
    item = role_item(arn="arn:aws:iam::999999999999:role/imported", unknown={})
    item["change"]["after_unknown"] = {}
    result = translate_plan(plan(item, account="123456789012"))
    assert result["changes"][0].resource_id == "arn:aws:iam::999999999999:role/imported"


def test_unknown_name_is_reported_not_guessed():
    item = role_item(name=None, unknown={"name": True})
    result = translate_plan(plan(item, account="123456789012"))
    assert result["changes"] == []
    assert result["unmodeled"] and result["unmodeled"][0]["address"] == "aws_iam_role.web"
    assert {"address": "aws_iam_role.web", "field": "name", "reason": "unknown Terraform value"} in result["unknown_fields"]


def test_unknown_trust_policy_stays_unknown():
    item = role_item(unknown={"assume_role_policy": True})
    item["change"]["after"].pop("assume_role_policy")
    result = translate_plan(plan(item, account="123456789012"))
    assert "trust_policy" not in result["changes"][0].fields
    assert any(u["field"] == "assume_role_policy" for u in result["unknown_fields"])


def test_every_created_role_applies_on_an_empty_base():
    result = translate_plan(plan(role_item("a", address="aws_iam_role.a"), role_item("b", address="aws_iam_role.b")))
    branch = AWSInfrastructure(region="us-east-1")
    for change in result["changes"]:
        branch = apply_change(branch, change)
    assert sorted(role.role_name for role in branch.iam.role_policies) == ["a", "b"]
