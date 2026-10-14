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
