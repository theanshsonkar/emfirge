"""L69 Terraform S3 settings: bucket ACL, versioning, encryption, logging, policy and Block Public Access are read from inline blocks and separate resources; unknown stays None.

A value Terraform marks "known after apply" (or an unconfigured computed block) is left as None and
listed in unknown_fields, never read as off. Public exposure is derived from the parts exactly as
for a collected bucket.
"""
import json

from app.models import AWSInfrastructure
from app.mutations import apply_change
from app.plan_ingest import translate_plan

PUBLIC_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]})


def item(typ, name, after, unknown=None, actions=("create",), config=None):
    return {"address": f"{typ}.{name}", "mode": "managed", "type": typ, "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": list(actions), "before": None, "after": after, "after_unknown": unknown or {}}}


def bucket(name="b", **after):
    unknown = after.pop("_unknown", {})
    return item("aws_s3_bucket", "b", {"bucket": name, "tags": {}, "tags_all": {}, **after}, unknown)


def run(*items, config=None):
    document = {"format_version": "1.2", "resource_changes": list(items),
                "configuration": {"root_module": {"resources": config or []}}}
    result = translate_plan(document)
    branch = AWSInfrastructure(region="us-east-1")
    for change in result["changes"]:
        branch = apply_change(branch, change)
    return result, branch.s3.buckets[0], branch


def test_inline_v4_blocks_are_read():
    result, b, branch = run(bucket(
        acl="public-read", versioning=[{"enabled": True, "mfa_delete": False}],
        server_side_encryption_configuration=[{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}],
        logging=[{"target_prefix": "log/"}], _unknown={"grant": True, "policy": True}))
    assert (b.acl_public, b.versioning_enabled, b.encrypted, b.logging_enabled) == (True, True, True, True)
    assert b.is_public is True and branch.s3.public_buckets == ["b"]
    assert branch.s3.unencrypted_buckets == [] and branch.s3.buckets_without_versioning == []
    assert b.policy is None
    assert {"address": "aws_s3_bucket.b", "field": "policy", "reason": "unknown Terraform value"} in result["unknown_fields"]


def test_unconfigured_computed_blocks_stay_unknown_not_off():
    result, b, branch = run(bucket(_unknown={"acl": True, "grant": True, "logging": True, "policy": True,
                                            "server_side_encryption_configuration": True, "versioning": True}))
    assert (b.acl_public, b.versioning_enabled, b.encrypted, b.logging_enabled, b.policy) == (None, None, None, None, None)
    assert branch.s3.unencrypted_buckets == [] and branch.s3.buckets_without_logging == []
    fields = {u["field"] for u in result["unknown_fields"]}
    assert {"acl", "versioning", "logging", "policy", "server_side_encryption_configuration"} <= fields


def test_private_canned_acl_and_disabled_versioning_are_known_false():
    _, b, branch = run(bucket(acl="private", versioning=[{"enabled": False, "mfa_delete": False}]))
    assert b.acl_public is False and b.versioning_enabled is False and b.is_public is False
    assert branch.s3.buckets_without_versioning == ["b"]


def test_separate_resources_apply_after_the_bucket_exists():
    result, b, branch = run(
        item("aws_s3_bucket_versioning", "v", {"bucket": "b", "versioning_configuration": [{"status": "Enabled"}]}),
        item("aws_s3_bucket_server_side_encryption_configuration", "e", {"bucket": "b", "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}),
        item("aws_s3_bucket_logging", "l", {"bucket": "b", "target_bucket": "logs"}),
        item("aws_s3_bucket_acl", "a", {"bucket": "b", "acl": "public-read-write"}),
        bucket(_unknown={"acl": True}))
    assert (b.versioning_enabled, b.encrypted, b.logging_enabled, b.acl_public, b.is_public) == (True, True, True, True, True)
    for address in ("aws_s3_bucket_versioning.v", "aws_s3_bucket_acl.a", "aws_s3_bucket_logging.l"):
        assert address in result["addresses"]


def test_public_access_block_makes_a_public_acl_not_effective():
    _, b, _ = run(
        item("aws_s3_bucket_acl", "a", {"bucket": "b", "acl": "public-read"}),
        item("aws_s3_bucket_public_access_block", "p", {"bucket": "b", "block_public_acls": True, "ignore_public_acls": True,
                                                        "block_public_policy": True, "restrict_public_buckets": True}),
        bucket())
    assert b.acl_public is True and b.ignore_public_acls is True and b.is_public is False


def test_bucket_policy_is_public_through_s3_public():
    _, b, branch = run(item("aws_s3_bucket_policy", "pol", {"bucket": "b", "policy": PUBLIC_POLICY}), bucket())
    assert b.policy_public is True and b.is_public is True and branch.s3.public_buckets == ["b"]


def test_unknown_policy_is_reported_not_guessed():
    result, b, _ = run(item("aws_s3_bucket_policy", "pol", {"bucket": "b"}, unknown={"policy": True}), bucket())
    assert b.policy is None and b.is_public is False
    assert any(u["address"] == "aws_s3_bucket_policy.pol" and u["field"] == "policy" for u in result["unknown_fields"])


def test_bucket_found_through_configuration_reference():
    pab = item("aws_s3_bucket_public_access_block", "p", {"block_public_acls": True, "ignore_public_acls": True,
                                                         "block_public_policy": True, "restrict_public_buckets": True}, unknown={"bucket": True})
    cfg = [{"address": "aws_s3_bucket_public_access_block.p", "mode": "managed", "type": "aws_s3_bucket_public_access_block", "name": "p",
            "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}}]
    _, b, _ = run(pab, bucket(), config=cfg)
    assert b.block_public_policy is True


def test_setting_for_an_unresolvable_bucket_is_unseen():
    pab = item("aws_s3_bucket_public_access_block", "p", {"block_public_acls": False}, unknown={"bucket": True})
    result = translate_plan({"format_version": "1.2", "resource_changes": [pab]})
    assert result["changes"] == [] and result["unmodeled"][0]["unseen"] is True
