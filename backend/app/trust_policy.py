"""IAM trust-policy classification without AWS dependencies."""
import fnmatch
import json
import re
from urllib.parse import unquote

_ASSUME = ('sts:assumerole', 'sts:assumerolewithsaml', 'sts:assumerolewithwebidentity')
_RESTRICT_KEYS = {'sts:externalid', 'aws:principalorgid', 'aws:principalorgpaths', 'aws:principalaccount', 'aws:principalarn', 'aws:sourceaccount', 'aws:sourcearn', 'aws:sourceorgid', 'aws:sourceorgpaths', 'cognito-identity.amazonaws.com:aud', 'saml:aud'}

def _values(value):
    if isinstance(value, list):
        out = []
        for item in value: out.extend(_values(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values(): out.extend(_values(item))
        return out
    return [value] if isinstance(value, str) else []

def _restricted(condition):
    if not isinstance(condition, dict): return False
    for operator, values in condition.items():
        op = str(operator).lower()
        if 'ifexists' in op or op.startswith(('stringnot', 'arnnot', 'null')): continue
        if not isinstance(values, dict): continue
        for key, value in values.items():
            key = str(key).lower()
            if key in _RESTRICT_KEYS or key.endswith(':sub'):
                if all(str(item) != '*' for item in _values(value)):
                    return True
    return False

def external_trust(document: dict, role_arn: str) -> tuple[bool, bool]:
    try:
        if isinstance(document, str): document = json.loads(unquote(document))
        if not isinstance(document, dict):
            return (True, True)
        if 'Statement' not in document:
            if 'Effect' not in document: return (True, True)
            statements = [document]
        else:
            statements = document['Statement']
        if isinstance(statements, dict): statements = [statements]
        if not isinstance(statements, list): return (True, True)
        own = str(role_arn).split(':')[4] if len(str(role_arn).split(':')) > 4 else None
        allows = unrestricted = False
        for statement in statements:
            if not isinstance(statement, dict) or 'Effect' not in statement:
                return (True, True)
            if str(statement.get('Effect', '')).lower() != 'allow': continue
            if 'NotAction' in statement:
                return (True, True)
            actions = [str(item).lower() for item in _values(statement.get('Action', []))]
            if not any(fnmatch.fnmatchcase(target, pattern) for pattern in actions for target in _ASSUME): continue
            principal = statement.get('Principal')
            external = 'NotPrincipal' in statement
            if principal == '*' or 'NotPrincipal' in statement: external = True
            if isinstance(principal, dict):
                if 'CanonicalUser' in principal: external = True
                if any(str(item) == '*' for item in _values(principal.get('AWS'))): external = True
                for item in _values(principal.get('AWS')):
                    if item == '*': continue
                    if re.fullmatch(r'\d{12}', item): external |= item != own
                    elif item.lower().startswith('arn:'):
                        parts = item.split(':')
                        account = parts[4] if len(parts) > 4 else None
                        resource = parts[5] if len(parts) > 5 else ''
                        if account != own: external = True
                        elif resource == 'root': pass
                        elif resource.startswith(('role/', 'user/')): pass
                        else: external = True
                    else: external = True
                for item in _values(principal.get('Federated')):
                    if re.fullmatch(r'arn:aws:iam::\d{12}:saml-provider/.+', item) and item.split(':')[4] == own:
                        external = True
                    else: external = True
            elif principal is not None and principal != '*':
                external = True
            if external:
                allows = True
                unrestricted |= not _restricted(statement.get('Condition'))
        return allows, unrestricted
    except Exception:
        return (True, True)
