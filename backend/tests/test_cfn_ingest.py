import json

import pytest

from app.cfn_ingest import convert_change_set


def rc(action, typ, logical="Thing", physical="id-1", replacement="False", **kwargs):
    item = {"Type": "Resource", "ResourceChange": {
        "Action": action, "LogicalResourceId": logical, "PhysicalResourceId": physical,
        "ResourceType": typ, "Replacement": replacement,
    }}
    item["ResourceChange"].update(kwargs)
    return item


def call(service, operation, parameters):
    return {"service": service, "operation": operation, "parameters": parameters}


@pytest.mark.parametrize("typ,service,operation,param", [
    ("AWS::EC2::Instance", "ec2", "TerminateInstances", {"InstanceIds": ["i-1"]}),
    ("AWS::EC2::Volume", "ec2", "DeleteVolume", {"VolumeId": "vol-1"}),
    ("AWS::EC2::SecurityGroup", "ec2", "DeleteSecurityGroup", {"GroupId": "sg-1"}),
    ("AWS::RDS::DBInstance", "rds", "DeleteDBInstance", {"DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": True}),
    ("AWS::S3::Bucket", "s3", "DeleteBucket", {"Bucket": "bucket-1"}),
    ("AWS::Lambda::Function", "lambda", "DeleteFunction", {"FunctionName": "fn-1"}),
    ("AWS::IAM::Role", "iam", "DeleteRole", {"RoleName": "role-1"}),
])
def test_remove_mapped_delete_calls(typ, service, operation, param):
    api, extras = convert_change_set({"Changes": [rc("Remove", typ, physical=next(iter(param.values())) if operation != "TerminateInstances" else "i-1")]})
    assert api == {"format": "aws-api-calls/1", "calls": [call(service, operation, param)]}
    assert extras == []


def test_remove_retain_is_warn_unmodeled_and_non_resource_is_ignored():
    api, extras = convert_change_set({"Changes": [{"Type": "Resource", "ResourceChange": {
        "Action": "Remove", "LogicalResourceId": "Keep", "ResourceType": "AWS::S3::Bucket",
        "PhysicalResourceId": "b", "PolicyAction": "Retain", "Replacement": "False"}}, {"Type": "ResourceDefinition", "x": 1}]})
    assert api["calls"] == []
    assert extras[0]["type"] == "cloudformation.RetainResource" and extras[0]["actions"] == ["update"]

@pytest.mark.parametrize("typ,expected", [("AWS::Foo::Bar", "foo.DeleteBar"), ("Custom::Widget", "custom.DeleteWidget")])
def test_remove_unmapped_is_block_delete(typ, expected):
    api, extras = convert_change_set({"Changes": [rc("Remove", typ)]})
    assert api["calls"] == []
    assert extras[0]["type"] == expected and extras[0]["actions"] == ["delete"]


def test_remove_missing_physical_id_is_block_delete():
    api, extras = convert_change_set({"Changes": [rc("Remove", "AWS::Foo::Bar", physical=None)]})
    assert api["calls"] == [] and extras[0]["actions"] == ["delete"]


def test_rds_snapshot_remove_and_replacements():
    for action, replacement, policy, expected_call, extra in [
        ("Modify", "True", None, call("rds", "DeleteDBInstance", {"DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": True}), False),
        ("Modify", "Conditional", None, call("rds", "DeleteDBInstance", {"DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": True}), True),
        ("Modify", "True", "ReplaceAndRetain", None, False),
        ("Modify", "True", "ReplaceAndSnapshot", call("rds", "DeleteDBInstance", {"DBInstanceIdentifier": "db-1", "SkipFinalSnapshot": False, "FinalDBSnapshotIdentifier": "db-1-final"}), False),
    ]:
        api, extras = convert_change_set({"Changes": [rc(action, "AWS::RDS::DBInstance", physical="db-1", replacement=replacement, PolicyAction=policy)]})
        assert api["calls"] == ([] if expected_call is None else [expected_call])
        assert any(x["type"] == "cloudformation.ConditionalReplacement" for x in extras) is extra


def props(rules):
    return json.dumps({"Properties": {"SecurityGroupIngress": rules}})


def test_security_group_modify_adds_and_removes_ipv4_ssh_rule_and_normalizes_strings():
    before = [{"IpProtocol": "6", "FromPort": "22", "ToPort": "22", "CidrIp": "10.0.0.0/8"}]
    after = before + [{"IpProtocol": "tcp", "FromPort": "22", "ToPort": "22", "CidrIp": "0.0.0.0/0"}]
    api, _ = convert_change_set({"Changes": [rc("Modify", "AWS::EC2::SecurityGroup", physical="sg-1", BeforeContext=props(before), AfterContext=props(after))]})
    assert api["calls"] == [call("ec2", "AuthorizeSecurityGroupIngress", {"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]})]
    api, _ = convert_change_set({"Changes": [rc("Modify", "AWS::EC2::SecurityGroup", physical="sg-1", BeforeContext=props(after), AfterContext=props(before))]})
    assert api["calls"][0]["operation"] == "RevokeSecurityGroupIngress"


def test_rds_modify_changed_supported_properties_and_no_change():
    before = {"Properties": {"DeletionProtection": True, "BackupRetentionPeriod": 7, "PubliclyAccessible": True, "VPCSecurityGroups": ["sg-a"]}}
    after = {"Properties": {"DeletionProtection": "false", "BackupRetentionPeriod": 7, "PubliclyAccessible": True, "VPCSecurityGroups": ["sg-a"]}}
    item = rc("Modify", "AWS::RDS::DBInstance", physical="db-1", BeforeContext=json.dumps(before), AfterContext=json.dumps(after))
    api, _ = convert_change_set({"Changes": [item]})
    assert api["calls"] == [call("rds", "ModifyDBInstance", {"DBInstanceIdentifier": "db-1", "DeletionProtection": False})]
    unchanged = rc("Modify", "AWS::RDS::DBInstance", physical="db-1", BeforeContext=json.dumps(before), AfterContext=json.dumps(before))
    assert convert_change_set({"Changes": [unchanged]})[0]["calls"] == []

@pytest.mark.parametrize("typ", ["AWS::EC2::SecurityGroup", "AWS::RDS::DBInstance"])
def test_missing_property_values_is_warn_unmodeled(typ):
    _, extras = convert_change_set({"Changes": [rc("Modify", typ, physical="id-1")]})
    assert extras[0]["type"] == "cloudformation.MissingPropertyValues" and extras[0]["actions"] == ["update"]


def test_other_modify_is_warn_update_unmodeled():
    _, extras = convert_change_set({"Changes": [rc("Modify", "AWS::S3::Bucket", physical="b")]})
    assert extras[0]["type"] == "s3.UpdateBucket" and extras[0]["actions"] == ["update"]


def test_security_group_ingress_add_remove_and_security_group_add():
    rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0", "GroupId": "sg-1"}
    add = rc("Add", "AWS::EC2::SecurityGroupIngress", AfterContext=json.dumps({"Properties": rule}), physical=None)
    api, _ = convert_change_set({"Changes": [add]})
    assert api["calls"][0]["operation"] == "AuthorizeSecurityGroupIngress"
    remove = rc("Remove", "AWS::EC2::SecurityGroupIngress", BeforeContext=json.dumps({"Properties": rule}), physical="ing-1")
    assert convert_change_set({"Changes": [remove]})[0]["calls"][0]["operation"] == "RevokeSecurityGroupIngress"
    _, extras = convert_change_set({"Changes": [rc("Add", "AWS::EC2::SecurityGroup", AfterContext=json.dumps({"Properties": {"SecurityGroupIngress": [rule]}}))]})
    assert extras[0]["type"] == "ec2.CreateSecurityGroup"

@pytest.mark.parametrize("action,operation", [("Add", "CreateBucket"), ("Import", "Import"), ("Dynamic", "DynamicChange")])
def test_other_add_import_dynamic_are_warn_unmodeled(action, operation):
    _, extras = convert_change_set({"Changes": [rc(action, "AWS::S3::Bucket" if action == "Add" else "AWS::Foo::Bar")]})
    assert extras[0]["type"].endswith("." + operation) and extras[0]["actions"] == ["update"]


def test_nested_stack_modify_is_warn_unmodeled():
    _, extras = convert_change_set({"Changes": [rc("Modify", "AWS::CloudFormation::Stack")]})
    assert extras[0]["type"] == "cloudformation.UpdateNestedStack"

@pytest.mark.parametrize("doc", [None, [], {}, {"Changes": None}, {"Changes": "bad"}, {"Changes": [rc("Modify", "AWS::S3::Bucket", BeforeContext="{")]}, {"Changes": [rc("Remove", "AWS::S3::Bucket") for _ in range(2001)]}])
def test_invalid_change_set_documents_raise_value_error(doc):
    with pytest.raises(ValueError):
        convert_change_set(doc)
