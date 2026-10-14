import pytest

from app.aws_api_ingest import translate_api_calls


def doc(*calls):
    return {"format": "aws-api-calls/1", "calls": list(calls)}


def call(service, operation, parameters=None, **extra):
    result = {"service": service, "operation": operation}
    if parameters is not None:
        result["parameters"] = parameters
    result.update(extra)
    return result


def test_ec2_terminate_expands_ids_in_call_order_and_lowercases_service():
    result = translate_api_calls(doc(
        call("EC2", "TerminateInstances", {"InstanceIds": ["i-1", "i-2"]}),
    ))
    assert [(c.op, c.resource_type, c.resource_id, c.fields) for c in result["changes"]] == [
        ("delete", "ec2_instance", "i-1", {}), ("delete", "ec2_instance", "i-2", {}),
    ]
    assert result["addresses"] == ["calls[0] EC2.TerminateInstances"] * 2


def test_all_simple_mapped_deletes():
    result = translate_api_calls(doc(
        call("ec2", "DeleteVolume", {"VolumeId": "vol-1"}),
        call("ec2", "DeleteSnapshot", {"SnapshotId": "snap-1"}),
        call("ec2", "DeleteSecurityGroup", {"GroupId": "sg-1"}),
        call("s3", "DeleteBucket", {"Bucket": "bucket-1"}),
        call("lambda", "DeleteFunction", {"FunctionName": "fn-1"}),
    ))
    assert [(c.resource_type, c.resource_id) for c in result["changes"]] == [
        ("ebs_volume", "vol-1"), ("ebs_snapshot", "snap-1"),
        ("security_group", "sg-1"), ("s3_bucket", "bucket-1"),
        ("lambda_function", "fn-1"),
    ]
    assert all(c.fields == {} for c in result["changes"])


def test_rds_instance_defaults_and_options():
    result = translate_api_calls(doc(call("rds", "DeleteDBInstance", {
        "DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": True,
        "DeleteAutomatedBackups": False, "FinalDBSnapshotIdentifier": "final-1",
    })))
    assert result["changes"][0].model_dump(exclude_none=True) == {
        "op": "delete", "resource_type": "rds_instance", "resource_id": "db-1",
        "fields": {"skip_final_snapshot": True, "delete_automated_backups": False,
                   "final_db_snapshot_identifier": "final-1"},
    }
    defaults = translate_api_calls(doc(call("rds", "DeleteDBInstance", {"DBInstanceIdentifier": "db-2"})))
    assert defaults["changes"][0].fields == {"skip_final_snapshot": False, "delete_automated_backups": True}


def test_remaining_rds_and_iam_mapped_deletes():
    result = translate_api_calls(doc(
        call("rds", "DeleteDBSnapshot", {"DBSnapshotIdentifier": "snap"}),
        call("iam", "DeleteRole", {"RoleName": "role"}),
    ), resolve_role_arn=lambda name: "arn:aws:iam::123:role/" + name)
    assert [(c.resource_type, c.resource_id) for c in result["changes"]] == [
        ("rds_snapshot", "snap"), ("iam_role", "arn:aws:iam::123:role/role")
    ]
    fallback = translate_api_calls(doc(call("iam", "DeleteRole", {"RoleName": "role"})), resolve_role_arn=lambda _: None)
    assert fallback["changes"][0].resource_id == "role"


def test_lambda_arn_uses_function_segment_and_qualifier_is_unmodeled():
    result = translate_api_calls(doc(call("lambda", "DeleteFunction", {
        "FunctionName": "arn:aws:lambda:us-east-1:123:function:fn:live",
    })))
    assert result["changes"][0].resource_id == "fn"
    qualified = translate_api_calls(doc(call("lambda", "DeleteFunction", {
        "FunctionName": "fn", "Qualifier": "live",
    })))
    assert not qualified["changes"]
    assert qualified["unmodeled"][0]["actions"] == ["delete"]


def test_dry_run_and_read_only_produce_nothing():
    result = translate_api_calls(doc(
        call("ec2", "DeleteVolume", {"VolumeId": "v", "DryRun": True}),
        call("ec2", "DescribeInstances", {"InstanceIds": ["i"]}),
        call("s3", "ListBuckets"), call("iam", "GetRole", {"RoleName": "r"}),
        call("ec2", "HeadThing"),
    ))
    assert result == {"changes": [], "addresses": [], "unmodeled": [], "unknown_fields": []}


def test_unknown_mapped_parameters_are_reported_but_change_remains():
    result = translate_api_calls(doc(call("ec2", "DeleteVolume", {"VolumeId": "v", "Nope": 1, "Other": 2})))
    assert result["changes"]
    assert result["unknown_fields"] == [
        {"address": "calls[0] ec2.DeleteVolume", "field": "Nope", "reason": "unsupported_attribute"},
        {"address": "calls[0] ec2.DeleteVolume", "field": "Other", "reason": "unsupported_attribute"},
    ]


def test_security_group_name_only_is_unmodeled_and_unmapped_actions():
    result = translate_api_calls(doc(
        call("ec2", "DeleteSecurityGroup", {"GroupName": "default"}),
        call("custom", "RemoveWidget", {"Id": "x"}),
        call("custom", "UpdateWidget", {"Id": "x"}),
    ))
    assert result["unmodeled"] == [
        {"address": "calls[0] ec2.DeleteSecurityGroup", "type": "ec2.DeleteSecurityGroup", "actions": ["delete"], "provider_name": "aws", "outside_view": False, "source": "aws_api"},
        {"address": "calls[1] custom.RemoveWidget", "type": "custom.RemoveWidget", "actions": ["delete"], "provider_name": "aws", "outside_view": False, "source": "aws_api"},
        {"address": "calls[2] custom.UpdateWidget", "type": "custom.UpdateWidget", "actions": ["update"], "provider_name": "aws", "outside_view": False, "source": "aws_api"},
    ]


@pytest.mark.parametrize("bad", [None, [], {"format": "aws-api-calls/2", "calls": []}, {"format": "aws-api-calls/1", "calls": []}, {"format": "aws-api-calls/1", "calls": "x"}])
def test_document_validation_has_fixed_message(bad):
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(bad)


@pytest.mark.parametrize("bad_call", [None, {}, {"service": "", "operation": "X"}, {"service": "ec2", "operation": ""}, {"service": "ec2", "operation": "X", "parameters": []}, {"service": "ec2", "operation": "X", "region": 3}])
def test_call_validation_has_fixed_message(bad_call):
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(doc(bad_call))


@pytest.mark.parametrize("operation, parameters", [
    ("TerminateInstances", {"InstanceIds": []}),
    ("TerminateInstances", {"InstanceIds": ["i", 2]}),
    ("DeleteVolume", {"VolumeId": []}),
    ("DeleteSnapshot", {"SnapshotId": ""}),
    ("DeleteDBInstance", {"DBInstanceIdentifier": 1}),
    ("DeleteBucket", {"Bucket": None}),
])
def test_mapped_identifier_validation_has_fixed_message(operation, parameters):
    service = "ec2" if operation in {"TerminateInstances", "DeleteVolume", "DeleteSnapshot"} else "rds" if operation == "DeleteDBInstance" else "s3"
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(doc(call(service, operation, parameters)))


@pytest.mark.parametrize("parameters", [
    {"DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": "true"},
    {"DBInstanceIdentifier": "db-1", "DeleteAutomatedBackups": 1},
    {"DBInstanceIdentifier": "db-1", "FinalDBSnapshotIdentifier": ""},
    {"DBInstanceIdentifier": "db-1", "FinalDBSnapshotIdentifier": 42},
])
def test_rds_delete_options_have_expected_types(parameters):
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(doc(call("rds", "DeleteDBInstance", parameters)))


def _sg_call(operation, parameters):
    return call("ec2", operation, {"GroupId": "sg-test", **parameters})


def _permission(**overrides):
    value = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    value.update(overrides)
    return value


def test_authorize_ip_permissions_appends_to_current_rules():
    current = [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                "ip_ranges": ["10.0.0.0/8"], "source_sg_ids": []}]
    result = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpPermissions": [_permission()]})), sg_rules=lambda _: current)
    assert result["changes"][0].fields["rules"] == current + [{
        "protocol": "tcp", "from_port": 22, "to_port": 22,
        "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []}]


def test_legacy_permission_form_matches_ip_permissions_form():
    nested = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpPermissions": [_permission()]})), sg_rules=lambda _: [])
    legacy = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"})), sg_rules=lambda _: [])
    assert nested["changes"][0].fields == legacy["changes"][0].fields


def test_ipv6_and_source_security_group_fields_are_translated():
    permission = _permission(IpRanges=[], Ipv6Ranges=[{"CidrIpv6": "::/0"}],
                             UserIdGroupPairs=[{"GroupId": "sg-source"}])
    result = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpPermissions": [permission]})), sg_rules=lambda _: [])
    assert result["changes"][0].fields["rules"] == [{
        "protocol": "tcp", "from_port": 22, "to_port": 22,
        "ip_ranges": ["::/0"], "source_sg_ids": ["sg-source"]}]


def test_duplicate_authorize_adds_nothing():
    rule = {"protocol": "tcp", "from_port": 22, "to_port": 22,
            "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []}
    result = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpPermissions": [_permission()]})), sg_rules=lambda _: [rule])
    assert result["changes"] == []


def test_authorize_then_revoke_accumulates_working_rules():
    current = [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                "ip_ranges": ["10.0.0.0/8"], "source_sg_ids": []}]
    result = translate_api_calls(doc(
        _sg_call("AuthorizeSecurityGroupIngress", {"IpPermissions": [_permission()]}),
        _sg_call("RevokeSecurityGroupIngress", {"IpPermissions": [_permission()]})),
        sg_rules=lambda _: current)
    assert result["changes"][1].fields["rules"] == current


def test_revoke_without_match_reports_unknown_and_no_change():
    result = translate_api_calls(doc(_sg_call("RevokeSecurityGroupIngress", {
        "IpPermissions": [_permission()]})), sg_rules=lambda _: [])
    assert result["changes"] == []
    assert result["unknown_fields"][0]["reason"] == "no_matching_rule"


def test_prefix_list_is_reported_unsupported():
    result = translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", {
        "IpPermissions": [_permission(PrefixListIds=[{"PrefixListId": "pl-1"}])]})), sg_rules=lambda _: [])
    assert result["unknown_fields"] == [{"address": "calls[0] ec2.AuthorizeSecurityGroupIngress",
        "field": "PrefixListIds", "reason": "unsupported_attribute"}]


def test_group_name_only_is_unmodeled_update():
    result = translate_api_calls(doc(call("ec2", "AuthorizeSecurityGroupIngress", {"GroupName": "default"})))
    assert result["unmodeled"][0]["actions"] == ["update"]


@pytest.mark.parametrize("permission", [
    {"IpPermissions": "not-list"},
    {"IpPermissions": [{} | {"IpProtocol": "tcp"}, "not-dict"]},
    {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": "22"}]},
    {"IpPermissions": [{"IpProtocol": "tcp", "IpRanges": [{}]}]},
])
def test_malformed_security_group_permissions_have_fixed_message(permission):
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(doc(_sg_call("AuthorizeSecurityGroupIngress", permission)), sg_rules=lambda _: [])


def test_modify_db_instance_maps_all_fields_and_ignores_apply_immediately():
    result = translate_api_calls(doc(call("rds", "ModifyDBInstance", {
        "DBInstanceIdentifier": "db-1", "BackupRetentionPeriod": 3,
        "DeletionProtection": True, "PubliclyAccessible": False,
        "VpcSecurityGroupIds": ["sg-1"], "ApplyImmediately": True,
        "Other": "ignored"})))
    assert result["changes"][0].fields == {"backup_retention_days": 3, "deletion_protection": True,
        "publicly_accessible": False, "sg_ids": ["sg-1"]}
    assert all(item["field"] != "ApplyImmediately" for item in result["unknown_fields"])
    assert result["unknown_fields"][0]["field"] == "Other"


@pytest.mark.parametrize("parameters", [
    {"DBInstanceIdentifier": "db-1", "BackupRetentionPeriod": True},
    {"DBInstanceIdentifier": "db-1", "DeletionProtection": "true"},
    {"DBInstanceIdentifier": "db-1", "PubliclyAccessible": 1},
    {"DBInstanceIdentifier": "db-1", "VpcSecurityGroupIds": [1]},
])
def test_modify_db_instance_wrong_types_are_rejected(parameters):
    with pytest.raises(ValueError, match=r"^Invalid AWS API calls document$"):
        translate_api_calls(doc(call("rds", "ModifyDBInstance", parameters)))


def test_modify_db_instance_without_mapped_field_has_no_change():
    result = translate_api_calls(doc(call("rds", "ModifyDBInstance", {
        "DBInstanceIdentifier": "db-1", "ApplyImmediately": True, "Other": 1})))
    assert result["changes"] == []


@pytest.mark.parametrize("operation", [
    "DetachRolePolicy", "DisassociateRouteTable", "RevokeGrant", "StopInstances",
    "StopLogging", "DisableKey", "PutBucketPolicy", "PutRolePolicy", "PutBucketAcl",
    "PutObjectAcl", "PutKeyPolicy",
])
def test_unmodeled_risky_operations_are_marked_risky(operation):
    result = translate_api_calls(doc(call("custom", operation)))
    assert result["unmodeled"][0]["actions"] == ["update"]
    assert result["unmodeled"][0]["risk"] == "risky"


@pytest.mark.parametrize("operation", [
    "PutObject", "PutBucketTagging", "PutMetricData", "CreateBucket", "TagResource",
    "StartInstances",
])
def test_unmodeled_non_risky_operations_remain_warn_changes(operation):
    result = translate_api_calls(doc(call("custom", operation)))
    assert result["unmodeled"][0]["actions"] == ["update"]
    assert "risk" not in result["unmodeled"][0]


@pytest.mark.parametrize("operation", [
    "DeleteWidget", "TerminateWidget", "PurgeWidget", "DeregisterWidget",
    "ReleaseWidget", "RemoveWidget",
])
def test_unmodeled_delete_prefixes_remain_delete_actions(operation):
    result = translate_api_calls(doc(call("custom", operation)))
    assert result["unmodeled"][0]["actions"] == ["delete"]
    assert "risk" not in result["unmodeled"][0]
