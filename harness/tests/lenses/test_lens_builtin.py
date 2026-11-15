"""The built-in lenses' rules beyond single settings: created and deleted resources, calls, prices, unknowns."""
from __future__ import annotations

from emfirge.core.model import Change, ChangeType, FieldChange, Kind, ResourceRef
from emfirge.lenses import DataLens, LensView, MoneyLens, PermissionsLens, PublicLens, builtin_lenses, run_lenses

from lens_helpers import allow, modified, policy

TABLE = ResourceRef('dynamodb:table', 'episodes')
BUCKET = ResourceRef('s3:bucket', 'feed')


def _run(lenses, *changes):
    return run_lenses(lenses, LensView(list(changes)))


def test_created_resource_without_settings_is_an_unknown_not_silence():
    r = _run([PublicLens(), PermissionsLens()], Change(BUCKET, ChangeType.CREATED, calls=('s3.CreateBucket',)))
    assert not r.findings
    assert [u.where for u in r.unknowns] == ['lens:public', 'lens:permissions']


def test_created_resource_with_settings_everything_in_it_is_new():
    born = Change(BUCKET, ChangeType.CREATED, (FieldChange('Policy', None, policy(allow('s3:GetObject', '*', '*'))),))
    assert {f.code for f in _run([PublicLens()], born).findings} == {'public.policy_allows_everyone'}


def test_deleted_store_uses_the_holds_data_flag():
    gone = Change(TABLE, ChangeType.DELETED, calls=('dynamodb.DeleteTable',))
    assert [f.code for f in _run([DataLens(lambda ref: True)], gone).findings] == ['data.store_deleted']
    assert not _run([DataLens(lambda ref: False)], gone).findings
    unknown = _run([DataLens(lambda ref: None)], gone)
    assert not unknown.findings and 'whether it holds data' in unknown.unknowns[0].what
    assert _run([DataLens()], gone).unknowns   # no flag given: cannot be told


def test_emptying_calls_are_reported_by_verb():
    r = _run([DataLens()], Change(BUCKET, ChangeType.ACTION, calls=('s3.DeleteObjects', 's3.PutObject')),
             Change(ResourceRef('sqs:queue', 'jobs'), ChangeType.ACTION, calls=('sqs.PurgeQueue',)),
             Change(TABLE, ChangeType.ACTION, calls=('dynamodb.PutItem',)))
    assert [(f.code, f.refs[0].id) for f in r.findings] == [('data.emptied', 'feed'), ('data.emptied', 'jobs')]


def test_data_protection_on_a_new_resource_is_not_a_loss():
    born = Change(TABLE, ChangeType.CREATED, (FieldChange('DeletionProtectionEnabled', None, False),))
    assert not _run([DataLens()], born).findings


def test_dry_run_removed_is_a_safety_switch_off():
    fn = modified('lambda:function', 'sentinel', ('Configuration.Environment.Variables', {'DRY_RUN': 'true', 'SHOW': 'gita'}, {'SHOW': 'gita'}))
    assert [f.code for f in _run([DataLens()], fn).findings] == ['data.protection_off']


def test_money_counts_created_resources_and_says_no_price_was_looked_up():
    r = _run([MoneyLens()], Change(BUCKET, ChangeType.CREATED), Change(ResourceRef('s3:bucket', 'b2'), ChangeType.CREATED),
             Change(TABLE, ChangeType.CREATED))
    assert r.findings[0].message == '3 new resources of 2 types (1 dynamodb:table, 2 s3:bucket)'
    assert r.unknowns[0].what.startswith('no price was looked up')


def test_money_with_a_price_function():
    fn = modified('lambda:function', 'f', ('MemorySize', 128, 512))
    priced = _run([MoneyLens(price=lambda c: 4.5)], fn)
    assert priced.findings[-1].code == 'money.monthly_estimate' and priced.findings[-1].detail['after'] == 4.5
    assert not priced.unknowns
    unpriced = _run([MoneyLens(price=lambda c: None)], fn)
    assert 'no price was found' in unpriced.unknowns[0].what


def test_money_commitment_calls():
    quota = Change(ResourceRef('service-quotas:quota', 'L-1'), ChangeType.ACTION, calls=('service-quotas.RequestServiceQuotaIncrease',))
    assert [f.code for f in _run([MoneyLens()], quota).findings] == ['money.commitment_call']


def test_money_quiet_on_nothing():
    r = _run([MoneyLens()], modified('lambda:function', 'f', ('Description', 'a', 'b')))
    assert r.findings == () and r.unknowns == ()


def test_permission_call_with_no_policy_in_the_state():
    kinds = {'lambda.AddPermission': Kind.PERMISSION}
    action = Change(ResourceRef('lambda:function', 'f'), ChangeType.ACTION, calls=('lambda.AddPermission',))
    lens = PermissionsLens(kind_of=lambda c: kinds.get(c, Kind.WRITE))
    assert [f.code for f in _run([lens], action).findings] == ['permissions.permission_call_unseen']
    assert not _run([PermissionsLens()], action).findings   # no catalog: this part cannot say anything


def test_permission_call_is_not_repeated_when_the_policy_was_compared():
    seen = modified('lambda:function', 'f', ('Policy', policy(allow('lambda:InvokeFunction', 'x', {'Service': 's.example'})),
                                             policy(allow('lambda:InvokeFunction', 'x', {'Service': 's.example'}))),
                    calls=('lambda.AddPermission',))
    lens = PermissionsLens(kind_of=lambda c: Kind.PERMISSION)
    assert not _run([lens], seen).findings


def test_policy_detached():
    role = modified('iam:role', 'r', ('AttachedPolicies', [{'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}], []))
    assert [f.code for f in _run([PermissionsLens()], role).findings] == ['permissions.policy_detached']


def test_too_large_policy_is_an_unknown():
    big = policy(allow([f'svc:A{i}' for i in range(100)], [f'res{i}' for i in range(100)]))
    r = _run([PermissionsLens()], modified('iam:role', 'r', ('PolicyDocument', None, big)))
    assert 'too large' in r.unknowns[0].what


def test_a_read_that_now_fails_is_an_unknown_for_the_lens_it_concerns():
    status = modified('s3:bucket', 'b', ('(GetPublicAccessBlock)', 200, 404))
    r = run_lenses(builtin_lenses(), LensView([status]))
    assert [u.where for u in r.unknowns] == ['lens:public']


def test_detail_carries_path_before_after():
    f = _run([PublicLens()], modified('rds:db', 'd', ('PubliclyAccessible', False, True))).findings[0]
    assert {'path', 'before', 'after'} <= set(f.detail)
    assert f.refs == (ResourceRef('rds:db', 'd'),)


def test_same_input_same_answer():
    changes = [modified('s3:bucket', 'b', ('Policy', None, policy(allow(['s3:GetObject', 's3:PutObject'], ['a', 'b'], '*'))))]
    assert run_lenses(builtin_lenses(), LensView(changes)) == run_lenses(builtin_lenses(), LensView(changes))
