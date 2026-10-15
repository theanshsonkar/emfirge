import re

import pytest

from app.aws_cli_ingest import parse_cli_commands


def _parse(command):
    return parse_cli_commands({"format": "aws-cli/1", "commands": [command]})


@pytest.mark.parametrize("command, option", [
    ("aws ec2 create-tags --resources i-1 --tags 'Key=a,Value=b'", "--tags"),
    ("aws ec2 authorize-security-group-ingress --group-id sg-1 --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]'", "--ip-permissions"),
    ("aws lambda update-function-configuration --function-name f --environment 'Variables={A=b}'", "--environment"),
])
def test_structured_options_refuse_aws_shorthand(command, option):
    expected = f"Command 1: {option} uses AWS shorthand syntax. Emfirge does not support shorthand and will not guess what it means; pass the value as JSON."
    with pytest.raises(ValueError, match=rf"^{re.escape(expected)}$"):
        _parse(command)


def test_structured_option_invalid_json_is_not_called_shorthand():
    with pytest.raises(ValueError, match=r"^Command 1: invalid JSON for --ip-permissions\.$"):
        _parse("aws ec2 authorize-security-group-ingress --group-id sg-1 --ip-permissions '[{bad'")


def test_scalar_string_keeps_equals_and_commas():
    assert _parse("aws rds delete-db-instance --db-instance-identifier 'a=b,c'")["calls"][0]["parameters"]["DBInstanceIdentifier"] == "a=b,c"


def test_parse_terminate_command():
    assert _parse(
        "aws ec2 terminate-instances --instance-ids i-0a i-0b --dry-run"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["i-0a", "i-0b"], "DryRun": True},
        }],
    }


def test_parse_rds_delete_with_region():
    assert _parse(
        "aws rds delete-db-instance --db-instance-identifier db1 "
        "--skip-final-snapshot --region us-east-1"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "rds",
            "operation": "DeleteDBInstance",
            "parameters": {
                "DBInstanceIdentifier": "db1",
                "SkipFinalSnapshot": True,
            },
            "region": "us-east-1",
        }],
    }


def test_parse_rds_modify_types_and_negative_boolean():
    assert _parse(
        "aws rds modify-db-instance --db-instance-identifier db1 "
        "--no-deletion-protection --backup-retention-period 0"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "rds",
            "operation": "ModifyDBInstance",
            "parameters": {
                "DBInstanceIdentifier": "db1",
                "DeletionProtection": False,
                "BackupRetentionPeriod": 0,
            },
        }],
    }


def test_parse_security_group_ingress_json():
    assert _parse(
        "aws ec2 authorize-security-group-ingress --group-id sg-1 "
        '--ip-permissions \'[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]\''
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "AuthorizeSecurityGroupIngress",
            "parameters": {
                "GroupId": "sg-1",
                "IpPermissions": [{
                    "IpProtocol": "-1",
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
            },
        }],
    }


def test_parse_s3api_delete_bucket_uses_s3_service():
    assert _parse("aws s3api delete-bucket --bucket b") == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "s3",
            "operation": "DeleteBucket",
            "parameters": {"Bucket": "b"},
        }],
    }


def test_parse_s3_rb_and_force():
    assert _parse("aws s3 rb s3://b") == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "s3",
            "operation": "DeleteBucket",
            "parameters": {"Bucket": "b"},
        }],
    }
    assert _parse("aws s3 rb s3://b --force") == {
        "format": "aws-api-calls/1",
        "calls": [
            {
                "service": "s3",
                "operation": "DeleteBucket",
                "parameters": {"Bucket": "b"},
            },
            {
                "service": "s3",
                "operation": "DeleteObjects",
                "parameters": {"Bucket": "b"},
            },
        ],
    }


def test_parse_s3_rm():
    assert _parse("aws s3 rm s3://b/k") == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "s3",
            "operation": "DeleteObject",
            "parameters": {"Bucket": "b", "Key": "k"},
        }],
    }


def test_parse_iam_and_lambda_commands():
    assert parse_cli_commands({
        "format": "aws-cli/1",
        "commands": [
            "aws iam delete-role --role-name r",
            "aws lambda delete-function --function-name f",
        ],
    }) == {
        "format": "aws-api-calls/1",
        "calls": [
            {
                "service": "iam",
                "operation": "DeleteRole",
                "parameters": {"RoleName": "r"},
            },
            {
                "service": "lambda",
                "operation": "DeleteFunction",
                "parameters": {"FunctionName": "f"},
            },
        ],
    }


def test_parse_region_equals():
    assert _parse("aws ec2 terminate-instances --instance-ids i-1 --region=eu-west-1") == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["i-1"]},
            "region": "eu-west-1",
        }],
    }


def test_parse_backslash_newline_continuation():
    assert _parse(
        "aws ec2 terminate-instances --instance-ids i-0a i-0b \\\n--dry-run"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["i-0a", "i-0b"], "DryRun": True},
        }],
    }


@pytest.mark.parametrize("command", [
    "aws ec2 terminate-instances --instance-ids i-1\naws ec2 delete-volume --volume-id vol-9",
    "aws ec2 terminate-instances --instance-ids i-1\r\naws ec2 delete-volume --volume-id vol-9",
    "aws ec2 terminate-instances --instance-ids i-1\raws ec2 delete-volume --volume-id vol-9",
    "aws ec2 terminate-instances --instance-ids $TARGET",
    "aws ec2 terminate-instances --instance-ids ${TARGET}",
    "aws ec2 terminate-instances --instance-ids $'i-1'",
    'aws ec2 terminate-instances --instance-ids "$TARGET"',
    'aws ec2 terminate-instances --instance-ids "`id`"',
    "aws ec2 terminate-instances --instance-ids i-*",
    "aws ec2 terminate-instances --instance-ids i-?",
    "aws ec2 terminate-instances --instance-ids i-[12]",
    "aws ec2 terminate-instances --instance-ids {i-1,i-2}",
    "aws ec2 terminate-instances --instance-ids ~/x",
    "aws ec2 terminate-instances --instance-ids i-1 # trailing",
    "aws ec2 terminate-instances --instance-ids i-1\x00",
    "aws ec2 terminate-instances --instance-ids i-1\x1b",
])
def test_rejects_shell_ambiguity(command):
    with pytest.raises(ValueError, match=r"Command 1"):
        _parse(command)


@pytest.mark.parametrize("command, expected", [
    (
        "aws ec2 authorize-security-group-ingress --group-id sg-1 --ip-permissions '[{\n  \"IpProtocol\": \"-1\"\n}]'",
        {"GroupId": "sg-1", "IpPermissions": [{"IpProtocol": "-1"}]},
    ),
    (
        "aws ec2 create-security-group --group-name g --description 'cost $5 * [x] {y} #z ~w'",
        {"GroupName": "g", "Description": "cost $5 * [x] {y} #z ~w"},
    ),
    (
        "aws ec2 terminate-instances --instance-ids i-1 \\\n--dry-run",
        {"InstanceIds": ["i-1"], "DryRun": True},
    ),
    (
        "aws ec2 terminate-instances\t--instance-ids\ti-1",
        {"InstanceIds": ["i-1"]},
    ),
    (
        "aws ec2 terminate-instances --instance-ids a#b",
        {"InstanceIds": ["a#b"]},
    ),
])
def test_quoted_shell_chars_are_literal(command, expected):
    assert _parse(command)["calls"][0]["parameters"] == expected


def test_parse_cli_input_json_explicit_flag_wins():
    assert _parse(
        "aws ec2 terminate-instances "
        '--cli-input-json \'{"InstanceIds":["from-json"],"DryRun":false}\' '
        "--instance-ids explicit --dry-run"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["explicit"], "DryRun": True},
        }],
    }


def test_parse_ignores_global_options():
    assert _parse(
        "aws ec2 terminate-instances --instance-ids i-1 --output json "
        "--profile p --no-cli-pager"
    ) == {
        "format": "aws-api-calls/1",
        "calls": [{
            "service": "ec2",
            "operation": "TerminateInstances",
            "parameters": {"InstanceIds": ["i-1"]},
        }],
    }


@pytest.mark.parametrize("document", [
    {"format": "aws-cli/1", "commands": ["ec2 terminate-instances"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances | tee x"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances ; rm -rf /"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances && echo x"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances > out"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances $(whoami)"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances `whoami`"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances --endpoint-url http://x"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances --no-verify-ssl"]},
    {"format": "aws-cli/1", "commands": ["aws madeup operation"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 madeup"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 wait"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances --made-up x"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 authorize-security-group-ingress --protocol tcp"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 authorize-security-group-ingress --ip-permissions IpProtocol=tcp,FromPort=22"]},
    {"format": "aws-cli/1", "commands": ["aws s3api delete-bucket --bucket file://x"]},
    {"format": "aws-cli/1", "commands": ["aws s3api delete-bucket --bucket https://x"]},
    {"format": "aws-cli/1", "commands": ["aws s3api delete-bucket --bucket b --bucket c"]},
    {"format": "aws-cli/1", "commands": ["aws rds modify-db-instance --db-instance-identifier db1 --backup-retention-period x"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances i-1"]},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances"] * 201},
    {"format": "aws-cli/1", "commands": ["aws ec2 terminate-instances " + "x" * 16385]},
    {"format": "wrong", "commands": ["aws ec2 terminate-instances"]},
    {"format": "aws-cli/1", "commands": []},
    {"format": "aws-cli/1", "commands": [123]},
])
def test_parse_rejects_invalid_documents(document):
    with pytest.raises(ValueError):
        parse_cli_commands(document)
