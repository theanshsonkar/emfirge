"""Plain, single report lines from the lenses (experiment 25's confusing lines)."""
from __future__ import annotations

import json

from emfirge.core.model import Change, ChangeType, FieldChange, ResourceRef
from emfirge.lenses import DataLens, LensView, PermissionsLens

ROLE = ResourceRef('iam:role', 'worker')
TRUST = json.dumps({'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                   'Action': 'sts:AssumeRole'}]})
NONE = json.dumps({'Statement': []})


def test_a_lost_trust_is_one_line_without_none():
    change = Change(ROLE, ChangeType.MODIFIED, (FieldChange('GetRole.Role.AssumeRolePolicyDocument', TRUST, NONE),
                                                FieldChange('ListRoles.AssumeRolePolicyDocument', TRUST, NONE)),
                    ('iam.UpdateAssumeRolePolicy',))
    lost = [f for f in PermissionsLens().look(LensView([change])).findings if 'no longer' in f.message]
    assert len(lost) == 1
    assert 'sts:AssumeRole' in lost[0].message and '(none)' not in lost[0].message


def test_a_deleted_store_can_hold_data():
    change = Change(ResourceRef('s3:bucket', 'b'), ChangeType.DELETED, (), ('s3.DeleteBucket',))
    [f] = DataLens(holds_data=lambda ref: True).look(LensView([change])).findings
    assert f.message.endswith('deleted; it can hold data, and any data in it goes with it')
