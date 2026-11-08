"""L82 A CloudFormation change set that REMOVES a property is never silently dropped.

The incident class: when AfterContext lacks a property BeforeContext had, CloudFormation resets
that property to its default (PITR off, deletion protection off, WAF detached, aliases gone).
Emfirge read only the properties present in AfterContext, so the branch looked unchanged and the
answer said nothing. Fix rule: a removed property becomes either the correct reset (only when the
AWS CloudFormation resource documentation states the default) or an explicit unknown that names
the property. When in doubt, unknown.

Defaults the documentation states (fetched 2026-11-08):
  * AWS::DynamoDB::Table DeletionProtectionEnabled: "This setting is disabled by default."
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html
  Defaults the documentation does NOT state, so the answer is unknown:
  * AWS::DynamoDB::Table PointInTimeRecoverySpecification (same page)
  * AWS::CloudFront::Distribution Aliases, WebACLId, CacheBehaviors, PriceClass, Origins
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html
  * AWS::RDS::DBInstance DeletionProtection, BackupRetentionPeriod, PubliclyAccessible, VPCSecurityGroups

L82a  DynamoDB PointInTimeRecoverySpecification removed -> unknown naming it (never a silent no-op)
L82b  DynamoDB DeletionProtectionEnabled removed -> reset to false (documented default); already false -> nothing
L82c  CloudFront WebACLId removed -> unknown naming DistributionConfig.WebACLId
L82d  CloudFront Aliases removed -> unknown naming DistributionConfig.Aliases
L82e  CloudFront one CacheBehaviors entry removed -> the branch's behavior list loses it; the whole list removed -> unknown
L82f  a property present in both before and after, unchanged, produces no extra change and no unknown
L82g  RDS DBInstance modeled property removed -> unknown naming it
L82h  CloudFront modeled member removed inside a matched behavior or origin -> unknown naming it
"""
from __future__ import annotations

import json

from app.aws_api_ingest import translate_api_calls
from app.cfn_ingest import convert_change_set

DIST = "E2JARVISFEED01"
TABLE = "orders"
BEHAVIOR = {"PathPattern": "feed.xml", "TargetOriginId": "s3-feed", "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6", "AllowedMethods": ["GET", "HEAD"]}
OTHER_BEHAVIOR = {**BEHAVIOR, "PathPattern": "img/*"}
DEFAULT = {"TargetOriginId": "s3-feed", "ViewerProtocolPolicy": "redirect-to-https",
           "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6", "AllowedMethods": ["GET", "HEAD"]}
ORIGIN = {"Id": "s3-feed", "DomainName": "feed.s3.us-east-1.amazonaws.com", "OriginAccessControlId": "E3OAC"}


def _run(typ, physical, before, after):
    change = {"Action": "Modify", "LogicalResourceId": "Thing", "ResourceType": typ, "PhysicalResourceId": physical,
              "Replacement": "False", "BeforeContext": json.dumps({"Properties": before}),
              "AfterContext": json.dumps({"Properties": after})}
    return convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": change}]})


def _dist(before, after):
    base = {"Enabled": True, "DefaultCacheBehavior": DEFAULT, "Origins": [ORIGIN]}
    doc, extras = _run("AWS::CloudFront::Distribution", DIST,
                       {"DistributionConfig": {**base, **before}}, {"DistributionConfig": {**base, **after}})
    assert extras == []
    return translate_api_calls(doc)


def _fields(result):
    return [c.fields for c in result["changes"]]


def _named(extras, prop):
    return [e for e in extras if prop in json.dumps(e)]


# ── DynamoDB ─────────────────────────────────────────────────────────────────

def test_L82a_pitr_removed_is_an_unknown_naming_the_property():
    before = {"TableName": TABLE, "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, before, {"TableName": TABLE})
    assert doc["calls"] == []  # the default is not documented, so no reset is claimed
    assert len(_named(extras, "PointInTimeRecoverySpecification")) == 1


def test_L82b_deletion_protection_removed_resets_to_the_documented_default_false():
    before = {"TableName": TABLE, "DeletionProtectionEnabled": True}
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, before, {"TableName": TABLE})
    assert extras == []
    assert doc["calls"] == [{"service": "dynamodb", "operation": "UpdateTable",
                             "parameters": {"TableName": TABLE, "DeletionProtectionEnabled": False}}]
    # string booleans from the change set are read the same way
    doc, _ = _run("AWS::DynamoDB::Table", TABLE, {"TableName": TABLE, "DeletionProtectionEnabled": "true"}, {"TableName": TABLE})
    assert [c["parameters"]["DeletionProtectionEnabled"] for c in doc["calls"]] == [False]


def test_L82b_deletion_protection_removed_when_it_was_already_off_changes_nothing():
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, {"TableName": TABLE, "DeletionProtectionEnabled": False}, {"TableName": TABLE})
    assert doc["calls"] == [] and extras == []


def test_L82b_deletion_protection_removed_from_an_unresolved_value_is_unknown():
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, {"TableName": TABLE, "DeletionProtectionEnabled": {"Ref": "Flag"}}, {"TableName": TABLE})
    assert doc["calls"] == [] and len(_named(extras, "DeletionProtectionEnabled")) == 1


def test_L82f_dynamodb_property_present_in_both_is_not_a_change():
    props = {"TableName": TABLE, "DeletionProtectionEnabled": True,
             "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, props, dict(props))
    assert doc["calls"] == [] and extras == []
    # removing one leaves the untouched one out of the answer
    doc, extras = _run("AWS::DynamoDB::Table", TABLE, props, {k: v for k, v in props.items() if k != "PointInTimeRecoverySpecification"})
    assert doc["calls"] == [] and not _named(extras, "DeletionProtectionEnabled")


# ── CloudFront ───────────────────────────────────────────────────────────────

def test_L82c_web_acl_removed_is_an_unknown_naming_the_property():
    result = _dist({"WebACLId": "arn:aws:wafv2:us-east-1:000000000000:global/webacl/x/1"}, {})
    assert [u["field"] for u in result["unknown_fields"]] == ["DistributionConfig.WebACLId"]
    assert all("web_acl_id" not in f for f in _fields(result))  # no invented reset


def test_L82d_aliases_removed_is_an_unknown_naming_the_property():
    result = _dist({"Aliases": ["feed.example.com"]}, {})
    assert [u["field"] for u in result["unknown_fields"]] == ["DistributionConfig.Aliases"]
    assert all("aliases" not in f for f in _fields(result))


def test_L82e_one_cache_behavior_removed_leaves_the_remaining_list_and_no_unknown():
    result = _dist({"CacheBehaviors": [BEHAVIOR, OTHER_BEHAVIOR]}, {"CacheBehaviors": [OTHER_BEHAVIOR]})
    assert result["unknown_fields"] == []
    assert [[b["path_pattern"] for b in f["cache_behaviors"]] for f in _fields(result)] == [["img/*"]]


def test_L82e_every_cache_behavior_removed_is_an_unknown_naming_the_property():
    result = _dist({"CacheBehaviors": [BEHAVIOR]}, {})
    assert [u["field"] for u in result["unknown_fields"]] == ["DistributionConfig.CacheBehaviors"]
    assert all("cache_behaviors" not in f for f in _fields(result))


def test_L82f_cloudfront_properties_present_in_both_are_not_a_change():
    same = {"Aliases": ["feed.example.com"], "WebACLId": "acl-1", "CacheBehaviors": [BEHAVIOR], "PriceClass": "PriceClass_All"}
    result = _dist(same, dict(same))
    assert result["unknown_fields"] == []
    # removing only the alias leaves the untouched WebACLId out of the unknowns
    result = _dist(same, {k: v for k, v in same.items() if k != "Aliases"})
    assert [u["field"] for u in result["unknown_fields"]] == ["DistributionConfig.Aliases"]


def test_L82h_a_modeled_member_removed_inside_a_matched_behavior_or_origin_is_unknown():
    result = _dist({}, {"DefaultCacheBehavior": {k: v for k, v in DEFAULT.items() if k != "CachePolicyId"}})
    assert [u["field"] for u in result["unknown_fields"]] == ["DefaultCacheBehavior.CachePolicyId"]
    result = _dist({}, {"Origins": [{k: v for k, v in ORIGIN.items() if k != "OriginAccessControlId"}]})
    assert [u["field"] for u in result["unknown_fields"]] == ["Origins.OriginAccessControlId"]


# ── RDS (same before/after pattern) ──────────────────────────────────────────

def test_L82g_rds_modeled_property_removed_is_an_unknown_naming_it():
    for prop, value in (("DeletionProtection", True), ("BackupRetentionPeriod", 7), ("PubliclyAccessible", False),
                        ("VPCSecurityGroups", ["sg-1"])):
        doc, extras = _run("AWS::RDS::DBInstance", "db-1", {"DBInstanceClass": "db.t3.micro", prop: value}, {"DBInstanceClass": "db.t3.micro"})
        assert doc["calls"] == [], prop
        assert len(_named(extras, prop)) == 1, prop


def test_L82g_rds_property_present_in_both_is_not_a_change():
    props = {"DeletionProtection": True, "BackupRetentionPeriod": 7}
    doc, extras = _run("AWS::RDS::DBInstance", "db-1", props, dict(props))
    assert doc["calls"] == [] and extras == []
