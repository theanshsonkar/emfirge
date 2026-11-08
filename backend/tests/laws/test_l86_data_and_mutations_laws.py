"""L86 data honesty and mutation-testing survivors.

L86a  DynamoDB ItemCount 0 is unknown emptiness: "DynamoDB updates this value approximately every six hours.
      Recent changes might not be reflected in this value."
      https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html
      (fetched 2026-11-08). So 0 is never a recovery point and never proof of no data loss.
"""
from __future__ import annotations

from pathlib import Path

from app.delete_lens import analyze_deletions
from app.mutations import apply_change
from app.verdict import combined_verdict

from .test_check_facts_laws import _check, _dump
from .test_dynamodb_table_laws import ORDERS, base_with, data_facts, delete, table

APP = Path(__file__).resolve().parents[2] / "app"


def test_L86a_item_count_zero_is_never_a_recovery_point_in_any_answer():
    for extra in (dict(item_count=0), dict(item_count=0, item_count_reported=True)):
        base = base_with(table(**extra))
        branch = apply_change(base, delete())
        lens = analyze_deletions(base, branch)
        assert lens.recovery_points == [] and lens.data_lost == []
        assert [x.resource_id for x in lens.recovery_unknown] == [ORDERS]
        assert data_facts(_dump(_check(base, branch)))[0]["has_recovery_point"] is None
        got = {(r["code"] if isinstance(r, dict) else r.code) for r in combined_verdict(base, branch, run_scanners=False).reasons}
        assert "data_store_deleted_with_recovery_point" not in got and "data_store_deleted_recovery_unknown" in got


def test_L86a_the_reported_empty_kind_no_longer_exists():
    assert "reported_empty_table" not in "".join(p.read_text() for p in APP.glob("*.py"))


# ── L86b-e CloudFront Host fact: origin kind, news, OAI and public S3 ─────────────────────────────

from .test_cloudfront_laws import (  # noqa: E402
    ALL_VIEWER, ALL_VIEWER_EXCEPT_HOST, CACHING_OPTIMIZED, CUSTOM_HOST_POLICY, OAC, USE_ORIGIN_CACHE_CONTROL, api_config,
    availability, checked, distribution, host_facts, move_feed,
)
from .test_cloudfront_laws import base_with as cf_base_with  # noqa: E402


def _unknown_topics(body):
    return {u["topic"] for u in availability(body)["unknown"]}


def test_L86b_the_host_fact_is_only_for_s3_origins_even_when_an_access_control_id_is_present():
    """Mutation guard: dropping the origin_type == "s3" test made a custom origin with an OAC id a fact."""
    base = cf_base_with(distribution(api_config()))
    origin = base.cloudfront.distributions[0].origins[0]
    for kind in ("custom", "other"):
        dist = base.cloudfront.distributions[0].model_copy(deep=True)
        dist.origins = [origin.model_copy(update={"origin_type": kind, "s3_bucket": None, "origin_access_control_id": OAC})]
        custom = cf_base_with(dist)
        body = checked(custom, apply_change(custom, move_feed(USE_ORIGIN_CACHE_CONTROL)))
        assert host_facts(body) == [], kind
    s3 = checked(base, apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL)))
    assert len(host_facts(s3)) == 1


def test_L86c_the_host_fact_needs_host_to_be_newly_forwarded():
    """Mutation guard: dropping the before-state test made every changed behavior that already forwarded Host a fact."""
    base = cf_base_with(distribution(api_config(USE_ORIGIN_CACHE_CONTROL)))
    assert host_facts(checked(base, apply_change(base, move_feed(CUSTOM_HOST_POLICY)))) == []
    assert host_facts(checked(base, apply_change(base, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=ALL_VIEWER)))) == []
    good = cf_base_with(distribution(api_config(CACHING_OPTIMIZED)))
    assert len(host_facts(checked(good, apply_change(good, move_feed(CUSTOM_HOST_POLICY))))) == 1


def _s3_variant(kind):
    config = api_config()
    item = config["Origins"]["Items"][0]
    item.pop("OriginAccessControlId")
    if kind == "oai":
        item["S3OriginConfig"] = {"OriginAccessIdentity": "origin-access-identity/cloudfront/E1OAIJARVIS001"}
    return cf_base_with(distribution(config))


def test_L86d_an_oai_or_public_s3_origin_getting_host_is_unknown_never_a_fact_and_never_silent():
    """Only OAC is the observed incident. An OAI or public S3 origin may break the same way but that is not observed,
    so it is a named unknown."""
    for kind in ("oai", "public"):
        base = _s3_variant(kind)
        body = checked(base, apply_change(base, move_feed(USE_ORIGIN_CACHE_CONTROL)))
        assert host_facts(body) == [], kind
        assert "origin_host_header_s3_without_oac" in _unknown_topics(body), kind
        reason = next(u["reason"] for u in availability(body)["unknown"] if u["topic"] == "origin_host_header_s3_without_oac")
        assert "origin access identity" in reason and "not observed" in reason


def test_L86d_an_oai_or_public_s3_origin_not_getting_host_adds_no_note():
    for kind in ("oai", "public"):
        base = _s3_variant(kind)
        body = checked(base, apply_change(base, move_feed(CACHING_OPTIMIZED, origin_request_policy_id=ALL_VIEWER_EXCEPT_HOST)))
        assert host_facts(body) == [] and "origin_host_header_s3_without_oac" not in _unknown_topics(body), kind


# ── L86e IAM action names are case-insensitive; L86f endpoint-prefix fallback ──────────────────────

import pytest  # noqa: E402

from app import aws_actions  # noqa: E402
from app.iam_escalation import _action_matches as escalation_matches  # noqa: E402
from app.permission_facts import action_matches  # noqa: E402


@pytest.mark.parametrize("pattern, action", [
    ("s3:getobject", "s3:GetObject"), ("S3:GETOBJECT", "s3:GetObject"), ("s3:GetObject", "S3:getobject"),
    ("DynamoDB:Delete*", "dynamodb:deleteitem"), ("iam:pass?ole", "IAM:PassRole"), ("*:*", "Lambda:InvokeFunction"),
])
def test_L86e_action_matching_ignores_case_like_aws_does(pattern, action):
    """"The prefix and the action name are case insensitive. For example, iam:ListAccessKeys is the same as IAM:listaccesskeys."
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html (fetched 2026-11-08).
    Mutation guard for a case-sensitive matcher."""
    assert action_matches(pattern, action) is True
    assert escalation_matches(pattern, action) is True


def test_L86e_case_insensitive_matching_still_rejects_other_actions():
    assert action_matches("s3:getobject", "s3:GetObjectAcl") is False
    assert action_matches("s3:Get*", "s3:PutObject") is False
    assert escalation_matches("s3:getobject", "s3:putobject") is False


def test_L86f_an_iam_prefix_that_is_only_a_botocore_endpoint_prefix_still_expands():
    """'monitoring' is the CloudWatch endpoint prefix and an IAM-side name botocore has no service called; without the
    endpoint-prefix fallback it was unknown."""
    aws_actions.actions_for_service.cache_clear()
    try:
        names = aws_actions.actions_for_service("monitoring")
        assert names and "monitoring:PutMetricData" in names
        assert aws_actions.actions_for_service("not-a-real-service") is None
    finally:
        aws_actions.actions_for_service.cache_clear()


# ── L86g CloudFormation security group: egress is diffed, every other changed property is a named unknown ──

import json  # noqa: E402

from app.aws_api_ingest import translate_api_calls  # noqa: E402
from app.cfn_ingest import convert_change_set  # noqa: E402

SG = "sg-0123456789abcdef0"
SSH = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "10.0.0.0/8"}
ALL_OUT = {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}
HTTPS_OUT = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.1.0.0/16"}


def _sg(before, after, *, replacement="False"):
    change = {"Action": "Modify", "LogicalResourceId": "Web", "ResourceType": "AWS::EC2::SecurityGroup", "PhysicalResourceId": SG,
              "Replacement": replacement, "BeforeContext": json.dumps({"Properties": before}),
              "AfterContext": json.dumps({"Properties": after})}
    return convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": change}]})


def _ops(doc):
    return [(c["operation"], c["parameters"]["IpPermissions"]) for c in doc["calls"]]


def test_L86g_added_and_removed_egress_rules_are_calls_like_ingress():
    doc, extras = _sg({"SecurityGroupEgress": [ALL_OUT]}, {"SecurityGroupEgress": [HTTPS_OUT]})
    assert extras == []
    assert _ops(doc) == [
        ("AuthorizeSecurityGroupEgress", [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.1.0.0/16"}]}]),
        ("RevokeSecurityGroupEgress", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]),
    ]
    assert all(c["parameters"]["GroupId"] == SG for c in doc["calls"])


def test_L86g_egress_changes_reach_the_branch_as_egress_rules_and_not_as_ingress():
    doc, _ = _sg({"SecurityGroupEgress": [ALL_OUT]}, {"SecurityGroupEgress": [ALL_OUT, HTTPS_OUT]})
    result = translate_api_calls(doc, sg_rules={SG: {"rules": [], "egress_rules": [
        {"from_port": None, "to_port": None, "protocol": "-1", "ip_ranges": ["0.0.0.0/0"], "dest_sg_ids": []}]}}.get)
    fields = [c.fields for c in result["changes"]]
    assert len(fields) == 1 and set(fields[0]) == {"egress_rules"} and len(fields[0]["egress_rules"]) == 2


def test_L86g_destination_security_group_and_ipv6_egress_rules_are_normalized():
    rule = {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "DestinationSecurityGroupId": "sg-db"}
    doc, extras = _sg({"SecurityGroupEgress": []}, {"SecurityGroupEgress": [rule, {"IpProtocol": "tcp", "CidrIpv6": "::/0"}]})
    assert extras == []
    assert _ops(doc)[0] == ("AuthorizeSecurityGroupEgress", [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": "sg-db"}]}])
    assert _ops(doc)[1][1] == [{"IpProtocol": "tcp", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]


def test_L86g_ingress_and_egress_change_together_and_unchanged_egress_makes_no_call():
    doc, extras = _sg({"SecurityGroupIngress": [], "SecurityGroupEgress": [ALL_OUT]},
                      {"SecurityGroupIngress": [SSH], "SecurityGroupEgress": [ALL_OUT]})
    assert extras == [] and [op for op, _ in _ops(doc)] == ["AuthorizeSecurityGroupIngress"]


def test_L86g_a_security_group_with_only_egress_properties_does_not_fail():
    doc, extras = _sg({"SecurityGroupEgress": [ALL_OUT]}, {"SecurityGroupEgress": [ALL_OUT, HTTPS_OUT]})
    assert extras == [] and len(doc["calls"]) == 1


def test_L86g_egress_added_or_removed_as_a_whole_is_a_named_unknown_not_a_guess():
    """With no SecurityGroupEgress property the group keeps whatever default egress it has; that default is not stated
    here, so adding or removing the whole property is unknown, never an empty or allow-all egress list."""
    for before, after in (({}, {"SecurityGroupEgress": [HTTPS_OUT]}), ({"SecurityGroupEgress": [HTTPS_OUT]}, {})):
        doc, extras = _sg(before, after)
        assert doc["calls"] == []
        assert [e.get("field") for e in extras] == ["SecurityGroupEgress"]
        assert "SecurityGroupEgress" in extras[0]["detail"]


def test_L86g_every_other_changed_property_is_a_named_unknown_never_silent():
    before = {"GroupDescription": "web", "VpcId": "vpc-1", "Tags": [{"Key": "a", "Value": "1"}], "SecurityGroupIngress": [SSH]}
    after = {"GroupDescription": "web2", "VpcId": "vpc-1", "Tags": [{"Key": "a", "Value": "2"}], "SecurityGroupIngress": [SSH],
             "SomeNewProperty": 1}
    doc, extras = _sg(before, after)
    assert doc["calls"] == []
    assert sorted(e["field"] for e in extras) == ["GroupDescription", "SomeNewProperty", "Tags"]
    assert all(e["type"].startswith("ec2.") and e["actions"] == ["update"] for e in extras)
    assert all(e["field"] in e["detail"] for e in extras)


def test_L86g_unchanged_properties_make_no_unknown():
    props = {"GroupDescription": "web", "VpcId": "vpc-1", "SecurityGroupIngress": [SSH], "SecurityGroupEgress": [ALL_OUT]}
    doc, extras = _sg(props, json.loads(json.dumps(props)))
    assert doc["calls"] == [] and extras == []
