import json
import pytest

from app.aws_api_ingest import translate_api_calls
from app.models import AWSInfrastructure
from app.mutations import Change, apply_change
from app.plan_ingest import translate_plan
from app.typed_handback import UnmappableChanges, build_api_calls

ROLE_ARN = 'arn:aws:iam::000000000000:role/new'
POLICY = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 'sts:AssumeRole'}]}

def api(service, operation, parameters):
    return {'format': 'aws-api-calls/1', 'calls': [{'service': service, 'operation': operation, 'parameters': parameters}]}

def plan(action, typ, after, before=None, unknown=None):
    return {'format_version': '1.2', 'resource_changes': [{'address': 'x', 'type': typ, 'change': {'actions': [action], 'before': before, 'after': after, 'after_unknown': unknown or {}}}]}

def test_typed_iam_role_and_user_and_existing_behavior():
    base = AWSInfrastructure(region='us-east-1')
    assert build_api_calls(base, [Change(op='add', resource_type='iam_role', resource_id=ROLE_ARN, fields={'trust_policy': POLICY})]) == [{'change_index': 0, 'service': 'iam', 'operation': 'CreateRole', 'params': {'RoleName': 'new', 'AssumeRolePolicyDocument': json.dumps(POLICY, sort_keys=True)}}]
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [Change(op='add', resource_type='iam_role', resource_id=ROLE_ARN, fields={})])
    assert exc.value.changes[0]['reason'] == 'error'
    assert build_api_calls(base, [Change(op='add', resource_type='iam_user', resource_id='alice', fields={})])[0]['operation'] == 'CreateUser'
    with pytest.raises(UnmappableChanges) as exc:
        build_api_calls(base, [Change(op='add', resource_type='iam_user', resource_id='alice', fields={'has_console_access': True})])
    assert exc.value.changes[0]['reason'] == 'operation_not_mapped'

def test_api_iam_create_modify_user_and_validation():
    result = translate_api_calls(api('iam', 'CreateRole', {'RoleName': 'new', 'AssumeRolePolicyDocument': json.dumps(POLICY)}))
    assert result['changes'] == [Change(op='add', resource_type='iam_role', resource_id='new', fields={'trust_policy': POLICY})]
    result = translate_api_calls(api('iam', 'UpdateAssumeRolePolicy', {'RoleName': 'old', 'PolicyDocument': POLICY}))
    assert result['changes'] == [Change(op='modify', resource_type='iam_role', resource_id='old', fields={'trust_policy': POLICY})]
    result = translate_api_calls(api('iam', 'CreateUser', {'UserName': 'alice', 'Path': '/', 'Tags': []}))
    assert result['changes'] == [Change(op='add', resource_type='iam_user', resource_id='alice', fields={})]
    assert any(x.get('field') == 'Path' and x.get('reason') == 'unsupported_attribute' for x in result['unknown_fields'])
    assert not any(x.get('field') == 'Tags' for x in result['unknown_fields'])
    with pytest.raises(ValueError, match='Invalid AWS API calls'):
        translate_api_calls(api('iam', 'CreateRole', {'RoleName': 'new', 'AssumeRolePolicyDocument': '{'}))
    assert translate_api_calls(api('iam', 'CreateRole', {'AssumeRolePolicyDocument': POLICY}))['unmodeled']

def test_api_round_trip_three_ops():
    base = apply_change(AWSInfrastructure(region='us-east-1'), Change(op='add', resource_type='iam_role', resource_id='arn:aws:iam::000000000000:role/base', fields={'trust_policy': POLICY}))
    for change in [
        Change(op='add', resource_type='iam_role', resource_id=ROLE_ARN, fields={'trust_policy': POLICY}),
        Change(op='modify', resource_type='iam_role', resource_id='existing', fields={'trust_policy': POLICY}),
        Change(op='add', resource_type='iam_user', resource_id='alice', fields={}),
    ]:
        if change.op == 'modify':
            base = apply_change(base, Change(op='add', resource_type='iam_role', resource_id='arn:aws:iam::000000000000:role/existing', fields={'trust_policy': POLICY}))
        calls = build_api_calls(base, [change])
        translated = translate_api_calls({'format': 'aws-api-calls/1', 'calls': [{'service': x['service'], 'operation': x['operation'], 'parameters': x['params']} for x in calls]})['changes'][0]
        assert apply_change(base, translated).model_dump() == apply_change(base, change).model_dump()

def test_terraform_iam_role_and_user():
    created = translate_plan(plan('create', 'aws_iam_role', {'name': 'new', 'arn': None, 'assume_role_policy': json.dumps(POLICY)}))
    assert created['changes'][0] == Change(op='add', resource_type='iam_role', resource_id=ROLE_ARN, fields={'trust_policy': POLICY})
    unknown = translate_plan(plan('create', 'aws_iam_role', {'name': 'new', 'assume_role_policy': None}, unknown=['assume_role_policy']))
    assert unknown['changes'][0].fields == {}
    before = {'name': 'old', 'assume_role_policy': json.dumps({'Statement': []})}
    updated = translate_plan(plan('update', 'aws_iam_role', {'name': 'old', 'assume_role_policy': json.dumps(POLICY)}, before=before))
    assert updated['changes'][0] == Change(op='modify', resource_type='iam_role', resource_id='old', fields={'trust_policy': POLICY})
    user = translate_plan(plan('create', 'aws_iam_user', {'name': 'alice'}))
    assert user['changes'][0] == Change(op='add', resource_type='iam_user', resource_id='alice', fields={})
