"""L70 Terraform Lambda and EC2 settings: a Lambda's role, environment secrets and VPC, an instance's IMDS setting and user-data secrets; unknown is unknown.

An instance whose metadata_options Terraform cannot show at plan time has imdsv2_required None:
no IMDSv1 finding is raised, the serializer omits metadata_options and the loss report lists it.
User data is only judged when its text is in the plan (user_data_base64, or a constant in the
configuration); the provider keeps a hash otherwise, so the answer stays None.
"""
import base64
import json

from app.egraph import build_graph
from app.models import AWSInfrastructure
from app.mutations import apply_change
from app.plan_ingest import translate_plan
from app.rules import run_all_checks
from app.serializer import build_terraform

ACCOUNT = "123456789012"
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def item(typ, name, after, unknown=None):
    return {"address": f"{typ}.{name}", "mode": "managed", "type": typ, "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["create"], "before": None, "after": after, "after_unknown": unknown or {}}}


def run(*items, config=None):
    document = {"format_version": "1.2", "resource_changes": list(items), "configuration": {"root_module": {"resources": config or []}},
                "prior_state": {"values": {"root_module": {"resources": [{"mode": "data", "type": "aws_caller_identity", "name": "c", "values": {"account_id": ACCOUNT}}]}}}}
    result = translate_plan(document)
    branch = AWSInfrastructure(region="us-east-1")
    for change in result["changes"]:
        branch = apply_change(branch, change)
    return result, branch


def role():
    return item("aws_iam_role", "fn", {"name": "fn", "path": "/", "assume_role_policy": TRUST}, {"arn": True})


def instance(**after):
    unknown = after.pop("_unknown", {})
    return item("aws_instance", "i", {"instance_type": "t3.micro", "tags": {}, "tags_all": {}, **after}, unknown)


def function(**after):
    unknown = after.pop("_unknown", {})
    return item("aws_lambda_function", "f", {"function_name": "f", "tags": {}, "tags_all": {}, **after}, unknown)


def test_lambda_role_resolved_through_reference_and_env_secrets_like_the_collector():
    cfg = [{"address": "aws_lambda_function.f", "mode": "managed", "type": "aws_lambda_function", "name": "f",
            "expressions": {"role": {"references": ["aws_iam_role.fn.arn", "aws_iam_role.fn"]}}}]
    fn = function(environment=[{"variables": {"DB_PASSWORD": "x", "REGION": "us-east-1",
                                              "REF": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbC"}}],
                  vpc_config=[{"subnet_ids": ["subnet-1"], "security_group_ids": ["sg-1"]}], _unknown={"role": True, "arn": True})
    result, branch = run(role(), fn, config=cfg)
    f = branch.lambda_data.functions[0]
    assert f.role_arn == f"arn:aws:iam::{ACCOUNT}:role/fn"
    assert f.secret_refs == ["env:DB_PASSWORD", "prod/db-AbC"]
    assert (f.subnet_ids, f.sg_ids) == (["subnet-1"], ["sg-1"])


def test_lambda_unknown_environment_and_role_are_reported_not_defaulted():
    result, branch = run(function(_unknown={"role": True, "environment": True}))
    f = branch.lambda_data.functions[0]
    assert f.role_arn is None and f.secret_refs == []
    fields = {u["field"] for u in result["unknown_fields"]}
    assert {"role", "environment"} <= fields


def test_lambda_unknown_variable_value_still_checks_names():
    fn = function(environment=[{"variables": {}}], _unknown={"environment": [{"variables": {"API_KEY": True, "OTHER": True}}]})
    result, branch = run(fn)
    assert branch.lambda_data.functions[0].secret_refs == ["env:API_KEY"]
    assert any(u["field"] == "environment" for u in result["unknown_fields"])


def test_imdsv2_known_values():
    _, required = run(instance(metadata_options=[{"http_tokens": "required"}], _unknown={"metadata_options": [{}]}))
    _, optional = run(instance(metadata_options=[{"http_tokens": "optional"}], _unknown={"metadata_options": [{}]}))
    assert required.ec2.instances[0].imdsv2_required is True
    assert optional.ec2.instances[0].imdsv2_required is False


def test_unknown_metadata_options_is_unknown_not_false():
    result, branch = run(instance(metadata_options=None, _unknown={"metadata_options": True}))
    assert branch.ec2.instances[0].imdsv2_required is None
    assert any(u["field"] == "metadata_options" for u in result["unknown_fields"])
    findings = run_all_checks(branch, build_graph(branch))
    assert not any(f.rule_id == "EMFIRGE-EC2-016" for items in findings.values() for f in items)
    built = build_terraform(branch)
    assert "metadata_options" not in next(iter(built.tf["resource"]["aws_instance"].values()))
    assert any(e.get("field") == "imdsv2_required" for e in built.loss)


def test_optional_tokens_still_raise_the_imds_finding():
    _, branch = run(instance(metadata_options=[{"http_tokens": "optional"}], _unknown={"metadata_options": [{}]}))
    findings = run_all_checks(branch, build_graph(branch))
    assert any(f.rule_id == "EMFIRGE-EC2-016" for items in findings.values() for f in items)


def test_user_data_secret_from_base64_and_from_configuration_constant():
    text = "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    _, a = run(instance(user_data_base64=base64.b64encode(text.encode()).decode(), _unknown={"metadata_options": True}))
    assert a.ec2.instances[0].user_data_has_secrets is True
    cfg = [{"address": "aws_instance.i", "mode": "managed", "type": "aws_instance", "name": "i",
            "expressions": {"user_data": {"constant_value": "db_password=hunter22xyz\n"}}}]
    _, b = run(instance(user_data="0123456789abcdef0123456789abcdef01234567", _unknown={"metadata_options": True}), config=cfg)
    assert b.ec2.instances[0].user_data_has_secrets is True
    findings = run_all_checks(b, build_graph(b))
    assert any(f.rule_id == "EMFIRGE-EC2-019" and f.resource_id == b.ec2.instances[0].id for items in findings.values() for f in items)


def test_user_data_clean_text_is_false_and_hash_only_is_unknown():
    cfg = [{"address": "aws_instance.i", "mode": "managed", "type": "aws_instance", "name": "i",
            "expressions": {"user_data": {"constant_value": "#!/bin/bash\nyum -y update\nexport TOKEN=$(fetch)\n"}}}]
    _, clean = run(instance(user_data="a" * 40, _unknown={"metadata_options": True}), config=cfg)
    assert clean.ec2.instances[0].user_data_has_secrets is False
    result, hashed = run(instance(user_data="a" * 40, _unknown={"metadata_options": True}))
    assert hashed.ec2.instances[0].user_data_has_secrets is None
    assert any(u["field"] == "user_data" for u in result["unknown_fields"])
    _, none = run(instance(user_data=None, _unknown={"metadata_options": True}))
    assert none.ec2.instances[0].user_data_has_secrets is False
