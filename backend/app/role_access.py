"""Customer role assumption and account-binding enforcement."""
import re
import secrets

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.auth import Caller
from app.database import AccountBinding, AccountBindingEvent

ROLE_RE = re.compile(r'^arn:aws(-[a-z]+)*:iam::(\d{12}):role/[\w+=,.@/-]+$')
DENIED_DETAIL = "Emfirge could not access this AWS account (class: trust_or_external_id). AWS refused to let Emfirge assume the role. Usually the role's trust policy does not trust Emfirge, or its ExternalId does not match your project's ExternalId; AWS does not say which. Roles made with the old shared ExternalId must be redeployed from emfirge_setup."
UNSAFE_DETAIL = 'This role accepts any ExternalId, so it is unsafe. Redeploy the template from emfirge_setup.'
_FAILURE_HINTS = {
    'sts_throttled': 'AWS STS is throttling requests.',
    'emfirge_credentials': "This is a problem with the Emfirge server's own AWS credentials, not your role.",
    'sts_region_disabled': 'AWS STS is disabled in the region the Emfirge server uses.',
    'sts_unreachable': 'The Emfirge server could not reach AWS STS.',
    'aws_error': 'AWS returned an unexpected error.',
    'internal_error': 'An internal error happened.',
}


def _forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail=DENIED_DETAIL)


def _assume_failure(kind: str) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=f"Emfirge could not assume the role, but not because of a trust or ExternalId mismatch (class: {kind}). {_FAILURE_HINTS[kind]} Try again later.",
    )


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
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        if code == 'AccessDenied':
            raise _forbidden()
        if code in {'Throttling', 'ThrottlingException'}:
            raise _assume_failure('sts_throttled')
        if code in {'ExpiredToken', 'ExpiredTokenException', 'InvalidClientTokenId', 'SignatureDoesNotMatch', 'UnrecognizedClientException'}:
            raise _assume_failure('emfirge_credentials')
        if code == 'RegionDisabledException':
            raise _assume_failure('sts_region_disabled')
        raise _assume_failure('aws_error')
    except BotoCoreError:
        raise _assume_failure('sts_unreachable')
    except Exception:
        raise _assume_failure('internal_error')
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
