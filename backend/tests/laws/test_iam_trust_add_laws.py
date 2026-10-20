import json
import itertools
import pytest

from app.aws_collector import _parse_role_trust_policy
from app.diffing import diff_infrastructure
from app.models import AWSInfrastructure, IAMData, RolePolicy, IAMUser
from app.mutations import Change, TargetNotFound, apply_change
from app.rules import check_iam_external_trust, run_all_checks
from app.trust_policy import external_trust
from app.verdict import combined_verdict

OWN = '000000000000'
OUT = '111111111111'
ROLE = f'arn:aws:iam::{OWN}:role/existing'
NEW = f'arn:aws:iam::{OWN}:role/new'

def stmt(principal='*', effect='Allow', action='sts:AssumeRole', condition=None):
    d = {'Effect': effect, 'Principal': principal, 'Action': action}
    if condition is not None: d['Condition'] = condition
    return d

@pytest.mark.parametrize('document, expected', [
    (stmt({'AWS': f'arn:aws:iam::{OWN}:root'}), (False, False)),
    (stmt({'AWS': ROLE}), (False, False)),
    (stmt({'Service': 'ec2.amazonaws.com'}), (False, False)),
    (stmt('*'), (True, True)), (stmt({'AWS': '*'}), (True, True)),
    (stmt({'AWS': f'arn:aws:iam::{OUT}:root'}), (True, True)),
    (stmt({'AWS': OUT}), (True, True)),
    (stmt({'Federated': 'token.actions.githubusercontent.com'}, condition={'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'}}), (True, True)),
    (stmt({'Federated': 'token.actions.githubusercontent.com'}, condition={'StringLike': {'token.actions.githubusercontent.com:sub': 'repo:org/repo:*'}}), (True, False)),
    (stmt({'AWS': OUT}, condition={'StringEquals': {'sts:ExternalId': 'x'}}), (True, False)),
    (stmt('*', condition={'StringEquals': {'aws:PrincipalOrgID': 'o-abc'}}), (True, False)),
    (stmt('*', condition={'Bool': {'aws:SecureTransport': 'true'}}), (True, True)),
    (stmt({'Federated': f'arn:aws:iam::{OWN}:saml-provider/idp'}, action='sts:AssumeRoleWithSAML', condition={'StringEquals': {'SAML:aud': 'https://signin.aws.amazon.com/saml'}}), (True, False)),
    (stmt({'Federated': f'arn:aws:iam::{OUT}:saml-provider/idp'}, action='sts:AssumeRoleWithSAML'), (True, True)),
    (stmt({'Federated': 'cognito-identity.amazonaws.com'}, action='sts:AssumeRoleWithWebIdentity', condition={'StringEquals': {'cognito-identity.amazonaws.com:aud': 'us-east-1:pool'}}), (True, False)),
    ({'bad': 'document'}, (True, True)),
    ({'Statement': {'Effect': 'Allow', 'Principal': '*', 'NotAction': 's3:*'}}, (True, True)),
    (stmt('*', action='sts:Assume*'), (True, True)),
    (stmt({'AWS': OUT}, condition={'StringEqualsIfExists': {'sts:ExternalId': 'x'}}), (True, True)),
    (stmt('*', condition={'StringEquals': {'sts:ExternalId': '*'}}), (True, True)),
    ({'Statement': [stmt({'AWS': f'arn:aws:iam::{OWN}:root'}, condition={'StringEquals': {'sts:ExternalId': 'x'}}), stmt('*')]}, (True, True)),
    (stmt('*', effect='Deny'), (False, False)),
    ({'Effect':'Allow','NotPrincipal': {'AWS': f'arn:aws:iam::{OWN}:root'}, 'Action':'sts:AssumeRole'}, (True, True)),
    (stmt('*', action='s3:GetObject'), (False, False)),
    (stmt('*', action='sts:*'), (True, True)),
    (stmt('*', action='sts:AssumeRoleWithWebIdentity'), (True, True)),
    (stmt('*')['copy'] if False else stmt('*'), (True, True)),
])
def test_external_trust_cases(document, expected):
    assert external_trust(document, ROLE) == expected

def test_external_trust_accepts_single_statement_and_json():
    document = stmt('*')
    assert external_trust(document, ROLE) == (True, True)
    assert external_trust(json.dumps(document), ROLE) == (True, True)

def test_parser_agreement_small_bruteforce():
    principals = ['*', {'AWS':'*'}, f'arn:aws:iam::{OWN}:root', ROLE,
                  f'arn:aws:iam::{OUT}:root', OUT, {'Service':'ec2.amazonaws.com'},
                  {'Federated':'token.actions.githubusercontent.com'}]
    conditions = [None, {'StringEquals': {'sts:ExternalId':'x'}}, {'Bool': {'aws:SecureTransport':'true'}}]
    disagreements = []
    statements = [stmt(p, effect, action, condition)
                  for p, effect, action, condition in itertools.product(
                      principals, ('Allow','Deny'), ('sts:AssumeRole','sts:*','s3:GetObject'), conditions)]
    for count in (1, 2):
        docs = ((statement,) for statement in statements) if count == 1 else itertools.product(statements, statements)
        for pair in docs:
            selected = list(pair)
            if count == 2 and selected[0] == selected[1]: continue
            doc = {'Statement': selected}
            expected = _parse_role_trust_policy(doc, ROLE)[2]
            actual = external_trust(doc, ROLE)[0]
            if actual != expected:
                disagreements.append((doc, actual, expected))
    # Plain-string principals other than '*' are not valid IAM grammar.
    remaining = [item for item in disagreements if not any(isinstance(statement.get('Principal'), str) and statement.get('Principal') != '*' for statement in item[0]['Statement'])]
    assert remaining == [], f'first 3 disagreements: {remaining[:3]}'

def test_rule_severity():
    def check(**kw):
        infra = AWSInfrastructure(region='us-east-1', iam=IAMData(role_policies=[RolePolicy(role_name='r', role_arn=ROLE, **kw)]))
        found = check_iam_external_trust(infra)
        return found[0].severity if found else None
    assert check(trust_external_unrestricted=True) == 'Critical'
    assert check(trust_allows_external=True, trust_has_conditions=False) == 'Critical'
    assert check(trust_allows_external=True, trust_has_conditions=True) == 'High'
    assert check() is None

def test_role_add_and_modify_and_user():
    base = AWSInfrastructure(region='us-east-1', iam=IAMData(role_policies=[RolePolicy(role_name='existing', role_arn=ROLE)]))
    policy = {'Version':'2012-10-17','Statement':stmt({'AWS':OUT})}
    added = apply_change(base, Change(op='add', resource_type='iam_role', resource_id='new', fields={'trust_policy':policy}))
    assert added.iam.role_policies[-1].role_arn == NEW
    assert base.iam.role_policies[0].role_arn == ROLE
    assert combined_verdict(base, added, run_scanners=False).verdict == 'block'
    modified = apply_change(base, Change(op='modify', resource_type='iam_role', resource_id='existing', fields={'trust_policy':{'Statement': [stmt('*')]}}))
    assert combined_verdict(base, modified, run_scanners=False).verdict == 'block'
    user = apply_change(base, Change(op='add', resource_type='iam_user', resource_id='alice', fields={'has_console_access': True}))
    assert user.iam.iam_users[-1].username == 'alice'
    assert sum(item['resource_type'] == 'iam_user' and item['id'] == 'alice' for item in diff_infrastructure(base, user).resources_added) == 1
    assert 'alice' in user.iam.users_without_mfa

    path_role = apply_change(base, Change(op='add', resource_type='iam_role', resource_id='arn:aws:iam::000000000000:role/service-role/x', fields={}))
    assert path_role.iam.role_policies[-1].role_name == 'x'
    with pytest.raises(ValueError):
        apply_change(base, Change(op='add', resource_type='iam_user', resource_id='', fields={}))

def test_role_validation_and_missing_detail():
    base = AWSInfrastructure(region='us-east-1')
    with pytest.raises(ValueError, match='full role ARN'):
        apply_change(base, Change(op='add', resource_type='iam_role', resource_id='new', fields={}))
    added = apply_change(base, Change(op='add', resource_type='iam_role', resource_id=NEW, fields={}))
    result = combined_verdict(base, added, run_scanners=False)
    assert any(r['code'] == 'unspecified_values' for r in result.reasons)
