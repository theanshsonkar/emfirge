"""API key authentication helpers for the FastAPI application."""

import hashlib
import os
import secrets
from datetime import datetime

from dataclasses import dataclass
from fastapi import HTTPException, Request, Depends
from sqlalchemy.exc import IntegrityError

from app.database import APIKey, Project, SupabaseIdentity, SessionLocal
from app import supabase_auth


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


@dataclass
class Caller:
    mode: str
    project_id: int | None
    project_name: str | None
    external_id: str | None


def _request_key(request: Request) -> str:
    authorization = request.headers.get('authorization')
    if authorization is not None:
        scheme, separator, token = authorization.partition(' ')
        return token.strip() if separator and scheme.lower() == 'bearer' else ''
    return request.headers.get('x-api-key', '').strip()


def _get_or_create_project(session, project_name: str) -> Project:
    project = session.query(Project).filter(Project.name == project_name).first()
    if project:
        return project
    project = Project(name=project_name, external_id=secrets.token_urlsafe(32))
    session.add(project)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        project = session.query(Project).filter(Project.name == project_name).first()
        if project is None:
            raise
    return project


def backfill_legacy_key_projects(session_factory=SessionLocal) -> int:
    """Create projects for API keys from before eager project provisioning."""
    session = session_factory()
    created = 0
    try:
        names = session.query(APIKey.project_name).distinct().all()
        for (project_name,) in names:
            if not project_name or not project_name.strip():
                continue
            if session.query(Project).filter(Project.name == project_name).first():
                continue
            _get_or_create_project(session, project_name)
            created += 1
        return created
    finally:
        session.close()


async def get_caller(request: Request) -> Caller:
    if not AUTH_ENABLED:
        return Caller('self-host', None, None, os.environ.get('EMFIRGE_EXTERNAL_ID') or None)
    raw = _request_key(request)
    key = verify_api_key(raw)
    if key is None:
        if raw and supabase_auth.supabase_url():
            try:
                sub = supabase_auth.verify_supabase_token(raw)
            except supabase_auth.SignInUnavailable:
                raise HTTPException(status_code=503, detail='Sign-in is temporarily unavailable')
            except supabase_auth.TokenInvalid:
                raise HTTPException(status_code=401, detail='Unauthorized')
            session = SessionLocal()
            try:
                identity = session.query(SupabaseIdentity).filter_by(supabase_user_id=sub).first()
                if identity is None:
                    project = Project(name=f'sb-{sub}', external_id=secrets.token_urlsafe(32))
                    session.add(project)
                    session.flush()
                    identity = SupabaseIdentity(supabase_user_id=sub, project_id=project.id)
                    session.add(identity)
                    try:
                        session.commit()
                    except IntegrityError:
                        session.rollback()
                        identity = session.query(SupabaseIdentity).filter_by(supabase_user_id=sub).first()
                        if identity is None:
                            raise
                project = session.query(Project).filter_by(id=identity.project_id).one()
                return Caller('hosted', project.id, project.name, project.external_id)
            finally:
                session.close()
        raise HTTPException(status_code=401, detail='Unauthorized')
    session = SessionLocal()
    try:
        project = _get_or_create_project(session, getattr(key, 'project_name', 'default'))
        return Caller('hosted', project.id, project.name, project.external_id)
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


async def legacy_ci_enabled():
    """Disable legacy CI and GitHub webhook integrations in hosted mode."""
    if AUTH_ENABLED:
        raise HTTPException(status_code=404, detail='Not Found')


async def require_api_key(request: Request, caller: Caller = Depends(get_caller)):
    """Require a valid caller; retained name for compatibility with existing routes.

    The caller dependency supplies the same authentication behavior and makes
    tenant identity available to routes that have not yet migrated signatures.
    """
    return None
