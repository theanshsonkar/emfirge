"""API key authentication helpers for the FastAPI application."""

import hashlib
import os
import secrets
from datetime import datetime

from fastapi import HTTPException, Request

from app.database import APIKey, SessionLocal


AUTH_ENABLED = os.getenv('EMFIRGE_REQUIRE_AUTH', '').lower() in {'1', 'true', 'yes'}


def generate_api_key() -> str:
    """Generate a high-entropy, recognizable Emfirge API key."""
    return 'emf_' + secrets.token_urlsafe(32)


def hash_key(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def create_api_key(project_name: str) -> str:
    """Create a key, persist only its digest, and return the raw key once."""
    raw = generate_api_key()
    session = SessionLocal()
    try:
        session.add(APIKey(
            key_hash=hash_key(raw),
            project_name=project_name,
            active=True,
            created_at=datetime.utcnow(),
        ))
        session.commit()
        return raw
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def verify_api_key(raw: str):
    """Validate an active key, recording its most recent use."""
    if not raw:
        return None
    session = SessionLocal()
    try:
        key = session.query(APIKey).filter(APIKey.key_hash == hash_key(raw)).first()
        if key is None or not key.active:
            return None
        key.last_used_at = datetime.utcnow()
        session.commit()
        session.refresh(key)
        session.expunge(key)
        return key
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()


async def require_api_key(request: Request):
    """Require a valid API key when EMFIRGE_REQUIRE_AUTH is enabled.

    Authorization: Bearer takes precedence over X-API-Key when both headers
    are present. All authentication failures use the same generic response.
    """
    if not AUTH_ENABLED:
        return None

    authorization = request.headers.get('authorization')
    if authorization is not None:
        scheme, separator, token = authorization.partition(' ')
        raw = token.strip() if separator and scheme.lower() == 'bearer' else ''
    else:
        raw = request.headers.get('x-api-key', '').strip()

    if not raw or verify_api_key(raw) is None:
        raise HTTPException(status_code=401, detail='Unauthorized')
    return None
