"""IAM: roles, users and customer managed policies (with their inline and attached policies)."""
from __future__ import annotations

import json

from emfirge.core.ports import CannotTell

from .context import CopyContext
from .spec import TypeSpec, Where, pick

ROLE, USER, POLICY = 'iam:role', 'iam:user', 'iam:policy'


def copy_principal_policies(x: CopyContext, kind: str, n: str) -> None:
    """Inline and attached policies of a role or a user."""
    iam, e = x.real('iam'), x.engine('iam')
    K = kind.capitalize()
    for p in getattr(iam, f'list_{kind}_policies')(**{f'{K}Name': n})['PolicyNames']:
        doc = getattr(iam, f'get_{kind}_policy')(**{f'{K}Name': n, 'PolicyName': p})['PolicyDocument']
        getattr(e, f'put_{kind}_policy')(**{f'{K}Name': n, 'PolicyName': p, 'PolicyDocument': json.dumps(doc)})
    for a in getattr(iam, f'list_attached_{kind}_policies')(**{f'{K}Name': n})['AttachedPolicies']:
        getattr(e, f'attach_{kind}_policy')(**{f'{K}Name': n, 'PolicyArn': x.ref(a['PolicyArn'])})


def copy_role(x: CopyContext, n: str) -> bool:
    iam = x.real('iam')
    r = x.find(iam.get_role, RoleName=n)
    if r is None:
        return False
    r = r['Role']
    if iam.list_instance_profiles_for_role(RoleName=n)['InstanceProfiles']:
        raise CannotTell('the role is in an instance profile, and instance profiles are not copied yet')
    kw = pick(r, 'Path', 'Description', 'MaxSessionDuration', 'Tags')
    if r.get('PermissionsBoundary'):
        kw['PermissionsBoundary'] = x.ref(r['PermissionsBoundary']['PermissionsBoundaryArn'])
    e = x.engine('iam').create_role(RoleName=n, AssumeRolePolicyDocument=json.dumps(r['AssumeRolePolicyDocument']), **kw)['Role']
    x.same(r['RoleId'], e['RoleId'])
    copy_principal_policies(x, 'role', n)
    return True


def copy_user(x: CopyContext, n: str) -> bool:
    iam, e = x.real('iam'), x.engine('iam')
    u = x.find(iam.get_user, UserName=n)
    if u is None:
        return False
    u = u['User']
    if iam.list_groups_for_user(UserName=n)['Groups']:
        raise CannotTell('the user is in a group, and groups are not copied yet')
    eu = e.create_user(UserName=n, **pick(u, 'Path', 'Tags'))['User']
    x.same(u['UserId'], eu['UserId'])
    for k in iam.list_access_keys(UserName=n)['AccessKeyMetadata']:
        ek = e.create_access_key(UserName=n)['AccessKey']
        x.same(k['AccessKeyId'], ek['AccessKeyId'])
        if k['Status'] != 'Active':
            e.update_access_key(UserName=n, AccessKeyId=ek['AccessKeyId'], Status=k['Status'])
    copy_principal_policies(x, 'user', n)
    return True


def policy_arn(w: Where, name: str) -> str:
    return f'arn:aws:iam::{w.account}:policy/{name}'


def copy_policy(x: CopyContext, name: str) -> bool:
    """The policy with all its versions; then the roles and users it is attached to, because the service refuses to
    delete an attached policy and the engine can only say so when it has them."""
    iam, e = x.real('iam'), x.engine('iam')
    a = policy_arn(x.where, name)
    p = x.find(iam.get_policy, PolicyArn=a)
    if p is None:
        return False
    p = p['Policy']
    if p.get('Path', '/') != '/':
        raise CannotTell('policies with a path are not copied yet')
    vs = sorted(iam.list_policy_versions(PolicyArn=a)['Versions'], key=lambda v: int(v['VersionId'][1:]))
    doc = lambda v: json.dumps(iam.get_policy_version(PolicyArn=a, VersionId=v['VersionId'])['PolicyVersion']['Document'])
    ep = e.create_policy(PolicyName=p['PolicyName'], PolicyDocument=doc(vs[0]), **pick(p, 'Description', 'Tags'))['Policy']
    x.same(p['PolicyId'], ep['PolicyId'])
    for v in vs[1:]:
        e.create_policy_version(PolicyArn=a, PolicyDocument=doc(v), SetAsDefault=v['IsDefaultVersion'])
    if len(vs) > 1 and vs[0]['IsDefaultVersion']:
        e.set_default_policy_version(PolicyArn=a, VersionId='v1')
    users = iam.list_entities_for_policy(PolicyArn=a)
    if users['PolicyGroups']:
        raise CannotTell('the policy is attached to a group, and groups are not copied yet')
    for r in users['PolicyRoles']:
        x.need(ROLE, r['RoleName'])
    for u in users['PolicyUsers']:
        x.need(USER, u['UserName'])
    return True


def _from_name(m, value: str) -> str:
    return m.group(1).rsplit('/', 1)[-1]


TYPES = [
    TypeSpec(ROLE, 'iam', params=('RoleName',), arn=r'role/(.+)', key_from_arn=_from_name,
             lists=(('ListRoles', 'Roles', 'RoleName'),), removed_by=('DeleteRole',),
             reads=lambda w, n: [('GetRole', {'RoleName': n}), ('ListRolePolicies', {'RoleName': n}),
                                 ('ListAttachedRolePolicies', {'RoleName': n})],
             copy=copy_role),
    TypeSpec(USER, 'iam', params=('UserName',), arn=r'user/(.+)', key_from_arn=_from_name,
             lists=(('ListUsers', 'Users', 'UserName'),), removed_by=('DeleteUser',),
             reads=lambda w, n: [('GetUser', {'UserName': n}), ('ListAccessKeys', {'UserName': n}),
                                 ('ListUserPolicies', {'UserName': n}), ('ListAttachedUserPolicies', {'UserName': n})],
             copy=copy_user),
    TypeSpec(POLICY, 'iam', params=('PolicyArn',), arn=r'policy/(.+)', key_from_arn=_from_name,
             lists=(('ListPolicies', 'Policies', 'Arn'),), removed_by=('DeletePolicy',),
             reads=lambda w, n: [('GetPolicy', {'PolicyArn': policy_arn(w, n)}),
                                 ('ListPolicyVersions', {'PolicyArn': policy_arn(w, n)})],
             copy=copy_policy),
]
