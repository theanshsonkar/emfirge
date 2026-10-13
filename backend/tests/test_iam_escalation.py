import json
import json
from pathlib import Path

from app.iam_escalation import matching_paths
from app.models import AccessStatement

DATA = json.loads((Path(__file__).parents[1] / 'app/data/pathfinding_paths.json').read_text())


def allow(actions, resources='*', **kwargs):
    return AccessStatement(effect='Allow', actions=actions if isinstance(actions, list) else [actions], resources=[resources], **kwargs)


def ids(statements):
    return {path['id'] for path in matching_paths(statements)}


def test_dataset_has_required_permissions():
    assert all(path['required'] for path in DATA['paths'])


def test_create_policy_version_and_wildcard():
    expected = {path['id'] for path in DATA['paths'] if path['required'] == ['iam:CreatePolicyVersion']}
    assert expected <= ids([allow('iam:CreatePolicyVersion')])
    assert ids([allow('*')]) == {path['id'] for path in DATA['paths']}


def test_resource_and_deny_semantics():
    assert ids([allow('s3:GetObject', 'arn:aws:s3:::one/*')]) == set()
    statements = [allow('*'), AccessStatement(effect='Deny', actions=['*'], resources=['*'])]
    assert ids(statements) == set()


def test_lambda_passrole_path_and_resource_restriction():
    actions = ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
    expected = {path['id'] for path in DATA['paths'] if path['name'] == 'iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction'}
    assert expected <= ids([allow(actions)])
    assert ids([allow(actions, 'arn:aws:s3:::x')]) == set()


def test_not_action_and_conditional_allow():
    matches = matching_paths([allow(['s3:*'], is_not_action=True, has_condition=True)])
    assert matches
    assert all(item['evidence'][0]['conditional'] for item in matches)


def test_cross_service_resource_arns_are_checked_by_action_formats():
    sts_matches = matching_paths([allow('sts:AssumeRole', 'arn:aws:iam::000000000000:role/x')])
    assert any('sts:AssumeRole' in path['required'] for path in sts_matches)

    ssm_matches = matching_paths([allow('ssm:SendCommand', 'arn:aws:ec2:ap-south-1:000000000000:instance/i-1')])
    assert any('ssm:SendCommand' in path['required'] for path in ssm_matches)


def test_resource_service_does_not_follow_wildcard_action_service():
    matches = matching_paths([allow('*', 'arn:aws:s3:::bucket')])
    assert not any(any(permission.lower().startswith('iam:') for permission in path['required']) for path in matches)


def test_iam_policy_resource_arn_still_matches():
    matches = matching_paths([allow('iam:CreatePolicyVersion', 'arn:aws:iam::000000000000:policy/p')])
    assert any('iam:CreatePolicyVersion' in path['required'] for path in matches)
