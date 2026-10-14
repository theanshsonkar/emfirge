import pytest

from app.aws_cli_ingest import parse_cli_commands


def test_parse_terminate_command():
    assert parse_cli_commands({"format": "aws-cli/1", "commands": [
        "aws ec2 terminate-instances --instance-ids i-0a i-0b --dry-run"
    ]}) == {"format": "aws-api-calls/1", "calls": [{
        "service": "ec2", "operation": "TerminateInstances",
        "parameters": {"InstanceIds": ["i-0a", "i-0b"], "DryRun": True},
    }]}


def test_rejects_shell_operator():
    with pytest.raises(ValueError, match="shell operators"):
        parse_cli_commands({"format": "aws-cli/1", "commands": [
            "aws ec2 terminate-instances --instance-ids i-1 | tee x"
        ]})
