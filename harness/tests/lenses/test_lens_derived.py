"""Fields the service computed (FieldChange.derived: no call of the session set them) are not money or data facts.
The permissions and public lenses still look at every field."""
from __future__ import annotations

import json

from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef
from emfirge.lenses import DataLens, LensView, MoneyLens, PermissionsLens

FN = ResourceRef('lambda:function', 'f')


def change(*fields: FieldChange) -> Change:
    return Change(FN, ChangeType.MODIFIED, fields, ('lambda.UpdateFunctionCode',))


def test_a_size_the_service_computed_is_not_a_money_fact():
    found = MoneyLens().look(LensView([change(FieldChange('GetFunction.Configuration.CodeSize', 197, 335, derived=True))]))
    assert found.findings == ()


def test_a_size_the_session_set_is_a_money_fact():
    found = MoneyLens().look(LensView([change(FieldChange('GetFunction.Configuration.MemorySize', 128, 1024))]))
    assert [f.code for f in found.findings] == ['money.size_up']


def test_a_switch_turned_on_is_a_money_fact_even_when_computed():
    found = MoneyLens().look(LensView([change(FieldChange('GetSchedule.State', 'DISABLED', 'ENABLED', derived=True))]))
    assert [f.code for f in found.findings] == ['money.switched_on']


def test_the_data_lens_ignores_computed_fields():
    computed = FieldChange('GetBucketVersioning.Status', 'Enabled', 'Suspended', derived=True)
    assert DataLens().look(LensView([change(computed)])).findings == ()
    set_by_session = FieldChange('GetBucketVersioning.Status', 'Enabled', 'Suspended')
    assert DataLens().look(LensView([change(set_by_session)])).findings


def test_the_permissions_lens_still_reads_computed_fields():
    policy = json.dumps({'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject', 'Resource': '*'}]})
    f = FieldChange('GetBucketPolicy.Policy', None, policy, derived=True)
    assert PermissionsLens().look(LensView([change(f)])).findings
