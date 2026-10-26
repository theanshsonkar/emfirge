"""L68 Terraform IAM permissions: roles and users get the permissions Terraform grants them, and nothing Terraform leaves unknown.

Inline policies, customer-managed policies and their attachments, AdministratorAccess, user
policies, access keys and instance profiles are read; references are followed through
plan.configuration when a value is unknown at plan time. A policy document or an AWS-managed
policy whose contents the plan does not carry is reported in unknown_fields, never guessed.
Users are principals that can escalate, exactly like roles.
"""
import json

from app.egraph import build_graph
from app.models import AWSInfrastructure
from app.mutations import Change, apply_change
from app.plan_ingest import translate_plan
from app.rules import run_all_checks
from app.verdict import combined_verdict

ACCOUNT = "123456789012"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
ESCALATE = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:CreatePolicyVersion"], "Resource": "*"}]})
S3_READ = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]})


def resource(typ, name, after, *, unknown=None, actions=("create",), before=None, module=None):
    address = f"{typ}.{name}"
    item = {"address": address, "mode": "managed", "type": typ, "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": list(actions), "before": before, "after": after, "after_unknown": unknown or {}}}
    return item


def role(name="r"):
    return resource("aws_iam_role", name, {"name": name, "path": "/", "assume_role_policy": TRUST}, unknown={"arn": True, "id": True})


def user(name="u"):
    return resource("aws_iam_user", name, {"name": name, "path": "/"}, unknown={"arn": True, "id": True})


def plan(*items, config=None, account=ACCOUNT):
    document = {"format_version": "1.2", "resource_changes": list(items),
                "configuration": {"root_module": {"resources": config or []}}}
    if account:
        document["prior_state"] = {"values": {"root_module": {"resources": [
            {"address": "data.aws_caller_identity.c", "mode": "data", "type": "aws_caller_identity", "name": "c",
             "values": {"account_id": account}}]}}}
    return document


def config(typ, name, **expressions):
    return {"address": f"{typ}.{name}", "mode": "managed", "type": typ, "name": name,
            "expressions": {key: {"references": value} for key, value in expressions.items()}}


def apply_all(document, base=None, **kwargs):
    result = translate_plan(document, **kwargs)
    branch = base or AWSInfrastructure(region="us-east-1")
    for change in result["changes"]:
        branch = apply_change(branch, change)
    return result, branch


def role_policy(branch, name):
    return next(p for p in branch.iam.role_policies if p.role_name == name)


def test_inline_role_policy_reaches_the_role_and_its_address():
    inline = resource("aws_iam_role_policy", "p", {"name": "p", "role": "r", "policy": S3_READ})
    result, branch = apply_all(plan(role(), inline))
    statements = role_policy(branch, "r").access_statements
    assert [(s.effect, s.actions, s.resources) for s in statements] == [("allow", ["s3:GetObject"], ["arn:aws:s3:::data/*"])]
    assert "aws_iam_role_policy.p" in result["addresses"]
    assert [r.kind for r in role_policy(branch, "r").policy_documents] == ["inline"]


def test_permission_changes_come_after_the_role_exists_whatever_the_addresses():
    inline = resource("aws_iam_role_policy", "a-first", {"name": "p", "role": "zz", "policy": S3_READ})
    result, _ = apply_all(plan(inline, role("zz")))
    kinds = [(c.op, c.resource_type) for c in result["changes"]]
    assert kinds.index(("add", "iam_role")) < kinds.index(("modify", "iam_role_policy"))


def test_managed_policy_followed_through_configuration_when_arn_is_unknown():
    policy = resource("aws_iam_policy", "esc", {"name": "esc", "path": "/", "policy": ESCALATE}, unknown={"arn": True, "id": True})
    attach = resource("aws_iam_role_policy_attachment", "a", {"role": "r"}, unknown={"policy_arn": True, "id": True})
    document = plan(role(), policy, attach,
                    config=[config("aws_iam_role_policy_attachment", "a", policy_arn=["aws_iam_policy.esc.arn", "aws_iam_policy.esc"])])
    result, branch = apply_all(document)
    docs = role_policy(branch, "r").policy_documents
    assert [(d.kind, d.name, d.arn) for d in docs] == [("managed", "esc", f"arn:aws:iam::{ACCOUNT}:policy/esc")]
    assert {"aws_iam_role_policy_attachment.a", "aws_iam_policy.esc"} <= set(result["addresses"])
    findings = run_all_checks(branch, build_graph(branch))
    assert any(f.rule_id == "EMFIRGE-IAM-007" and f.resource_id == "r" for items in findings.values() for f in items)


def test_administrator_access_is_known_but_other_aws_managed_policies_stay_unknown():
    admin = resource("aws_iam_role_policy_attachment", "adm", {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    other = resource("aws_iam_role_policy_attachment", "ro", {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    result, branch = apply_all(plan(role(), admin, other))
    statements = role_policy(branch, "r").access_statements
    assert [(s.actions, s.resources) for s in statements] == [(["*"], ["*"])]
    assert any(u["address"] == "aws_iam_role_policy_attachment.ro" and u["field"] == "policy_arn" for u in result["unknown_fields"])


def test_unknown_policy_document_is_reported_not_guessed():
    inline = resource("aws_iam_role_policy", "p", {"name": "p", "role": "r"}, unknown={"policy": True})
    result, branch = apply_all(plan(role(), inline))
    assert role_policy(branch, "r").access_statements == []
    assert {"address": "aws_iam_role_policy.p", "field": "policy", "reason": "unknown Terraform value"} in result["unknown_fields"]


def test_role_found_through_reference_when_its_name_is_unknown():
    unnamed = resource("aws_iam_role", "r", {"name_prefix": "x-", "path": "/", "assume_role_policy": TRUST}, unknown={"arn": True, "id": True, "name": True})
    inline = resource("aws_iam_role_policy", "p", {"name": "p", "policy": S3_READ}, unknown={"role": True})
    result, branch = apply_all(plan(unnamed, inline, config=[config("aws_iam_role_policy", "p", role=["aws_iam_role.r.id", "aws_iam_role.r"])]))
    assert branch.iam.role_policies == []
    assert any(u["address"] == "aws_iam_role.r" for u in result["unmodeled"])
    assert any(u["address"] == "aws_iam_role_policy.p" for u in result["unmodeled"])


def test_base_role_statements_are_merged_with_the_new_ones():
    base = apply_change(AWSInfrastructure(region="us-east-1"), Change(op="add", resource_type="iam_role",
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/old", fields={"trust_policy": json.loads(TRUST)}))
    base = apply_change(base, Change(op="modify", resource_type="iam_role_policy", resource_id=f"arn:aws:iam::{ACCOUNT}:role/old",
        fields={"access_statements": [{"effect": "allow", "actions": ["sqs:SendMessage"], "resources": ["*"]}]}))
    inline = resource("aws_iam_role_policy", "p", {"name": "p", "role": "old", "policy": S3_READ})
    result, branch = apply_all(plan(inline, account=None), base=base, iam_roles=base.iam.role_policies)
    actions = [s.actions for s in role_policy(branch, "old").access_statements]
    assert actions == [["sqs:SendMessage"], ["s3:GetObject"]]


def test_removing_an_attachment_removes_its_statements():
    base_plan = plan(role(), resource("aws_iam_role_policy_attachment", "adm", {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    _, branch = apply_all(base_plan)
    detach = resource("aws_iam_role_policy_attachment", "adm", None, actions=("delete",),
                      before={"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    _, after = apply_all(plan(detach, account=None), base=branch, iam_roles=branch.iam.role_policies)
    assert role_policy(after, "r").access_statements == []


def test_user_policy_and_access_key_make_the_user_a_principal_that_escalates():
    inline = resource("aws_iam_user_policy", "up", {"name": "up", "user": "u", "policy": ESCALATE})
    key = resource("aws_iam_access_key", "k", {"user": "u"}, unknown={"id": True, "secret": True})
    result, branch = apply_all(plan(user(), inline, key))
    created = next(u for u in branch.iam.iam_users if u.username == "u")
    assert created.has_access_keys is True
    assert [s.actions for s in created.access_statements] == [["iam:CreatePolicyVersion"]]
    findings = run_all_checks(branch, build_graph(branch))
    assert any(f.rule_id == "EMFIRGE-IAM-007" and f.resource_id == "u" and f.resource_type == "iam_user"
               for items in findings.values() for f in items)
    verdict = combined_verdict(AWSInfrastructure(region="us-east-1"), branch, run_scanners=False)
    assert verdict.introduces_privilege_escalation is True
    assert any(reason["code"] == "privilege_escalation" for reason in verdict.reasons)


def test_user_admin_policy_is_listed_as_admin():
    attach = resource("aws_iam_user_policy_attachment", "a", {"user": "u", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    _, branch = apply_all(plan(user(), attach))
    assert branch.iam.users_with_admin_policy == ["u"]


def test_user_not_collected_is_not_overwritten():
    base = AWSInfrastructure(region="us-east-1")
    base = apply_change(base, Change(op="add", resource_type="iam_user", resource_id="legacy", fields={}))
    base.iam.iam_users[0].access_statements = None
    inline = resource("aws_iam_user_policy", "up", {"name": "up", "user": "legacy", "policy": S3_READ})
    # created through the model the user has an empty list, so simulate a collected user with unknown policies
    collected = base.model_copy(deep=True)
    collected.iam.iam_users[0] = collected.iam.iam_users[0].model_copy(update={"access_statements": None, "policy_documents": None})
    result = translate_plan(plan(inline, account=None), iam_users=collected.iam.iam_users)
    assert result["changes"] == [] and result["unmodeled"][0]["unseen"] is True


def test_instance_profile_links_the_instance_to_its_role():
    profile = resource("aws_iam_instance_profile", "prof", {"name": "prof", "path": "/", "role": "r"}, unknown={"arn": True, "id": True})
    instance = resource("aws_instance", "i", {"instance_type": "t3.micro", "iam_instance_profile": "prof", "tags": {}, "tags_all": {}}, unknown={"id": True})
    result, branch = apply_all(plan(role(), profile, instance))
    arn = f"arn:aws:iam::{ACCOUNT}:instance-profile/prof"
    assert branch.iam.instance_profile_roles[arn] == {"role_name": "r", "role_arn": f"arn:aws:iam::{ACCOUNT}:role/r"}
    assert branch.ec2.instances[0].instance_profile_arn == arn
    graph = build_graph(branch)
    assert any(e.src == branch.ec2.instances[0].id and e.dst == "iam-role-r" and e.relationship.value == "uses_iam_role"
               for e in graph.edges)


def test_instance_profile_with_unknown_role_is_recorded_without_a_link():
    profile = resource("aws_iam_instance_profile", "prof", {"name": "prof", "path": "/"}, unknown={"arn": True, "id": True, "role": True})
    result, branch = apply_all(plan(profile))
    assert branch.iam.instance_profile_roles == {f"arn:aws:iam::{ACCOUNT}:instance-profile/prof": {}}
    assert any(u["field"] == "role" for u in result["unknown_fields"])


def test_every_emitted_iam_change_applies_cleanly_in_order():
    inline = resource("aws_iam_role_policy", "p", {"name": "p", "role": "r", "policy": S3_READ})
    attach = resource("aws_iam_role_policy_attachment", "adm", {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    result, branch = apply_all(plan(role(), inline, attach))
    assert len(role_policy(branch, "r").access_statements) == 2
    assert result["unmodeled"] == []
