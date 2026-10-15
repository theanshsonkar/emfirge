"""Customer role assumption and account-binding enforcement."""
import re
import secrets

import boto3
from botocore.exceptions import ClientError
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.auth import Caller
from app.database import AccountBinding, AccountBindingEvent

ROLE_RE = re.compile(r'^arn:aws(-[a-z]+)*:iam::(\d{12}):role/[\w+=,.@/-]+$')
FORBIDDEN_DETAIL = "Emfirge could not access this AWS account. Make sure the role trusts Emfirge with your project's ExternalId. Roles made with the old shared ExternalId must be redeployed from emfirge_setup."
UNSAFE_DETAIL = 'This role accepts any ExternalId, so it is unsafe. Redeploy the template from emfirge_setup.'


def _forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail=FORBIDDEN_DETAIL)


def _sts_client():
    return boto3.client('sts')


def _assume(sts, role_arn: str, external_id: str):
    return sts.assume_role(RoleArn=role_arn, RoleSessionName='EmfirgeSecurityScan', ExternalId=external_id, DurationSeconds=3600)


def assume_customer_role(role_arn: str, caller: Caller, db) -> dict:
    match = ROLE_RE.fullmatch(role_arn or '')
    if not match:
        raise HTTPException(status_code=400, detail='Invalid role ARN')
    if caller.external_id is None:
        if caller.mode == 'self-host':
            raise HTTPException(status_code=503, detail='EMFIRGE_EXTERNAL_ID is not set. Set it on the server and use the same value in your role trust policy.')
        raise _forbidden()
    account_id = match.group(2)
    binding = db.query(AccountBinding).filter_by(aws_account_id=account_id).first()
    if caller.mode == 'hosted' and binding is not None and binding.project_id != caller.project_id:
        raise _forbidden()
    sts = _sts_client()
    try:
        assumed = _assume(sts, role_arn, caller.external_id)
    except Exception:
        raise _forbidden()
    if caller.mode == 'self-host' or binding is not None:
        return assumed['Credentials']
    try:
        _assume(sts, role_arn, secrets.token_urlsafe(32))
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        if code != 'AccessDenied':
            raise HTTPException(status_code=503, detail='Could not verify that this role checks its ExternalId. Try again.')
    except Exception:
        raise HTTPException(status_code=503, detail='Could not verify that this role checks its ExternalId. Try again.')
    else:
        db.add(AccountBindingEvent(aws_account_id=account_id, project_id=caller.project_id,
                                   action='refused_unsafe', actor=caller.project_name or 'hosted'))
        db.commit()
        raise HTTPException(status_code=403, detail=UNSAFE_DETAIL)
    try:
        db.add(AccountBinding(aws_account_id=account_id, project_id=caller.project_id))
        db.flush()
    except IntegrityError:
        db.rollback()
        binding = db.query(AccountBinding).filter_by(aws_account_id=account_id).first()
        if binding is None or binding.project_id != caller.project_id:
            raise _forbidden()
    else:
        db.add(AccountBindingEvent(aws_account_id=account_id, project_id=caller.project_id,
                                   action='bind', actor=caller.project_name or 'hosted'))
        db.commit()
    return assumed['Credentials']
