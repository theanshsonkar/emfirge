"""Supabase JWT verification with a small per-project JWKS cache."""

import logging
import os
import time

import httpx
import jwt

logger = logging.getLogger(__name__)
ALLOWED_ALGS = ('ES256', 'RS256')
_CACHE_TTL = 600
_REFETCH_INTERVAL = 30
_jwks_cache = {}
_jwks_refetched = {}


class TokenInvalid(Exception):
    pass


class SignInUnavailable(Exception):
    pass


def supabase_url():
    value = os.environ.get('SUPABASE_URL', '').strip().rstrip('/')
    return value or None


def _fetch_jwks(base):
    response = httpx.get(f'{base}/auth/v1/.well-known/jwks.json', timeout=5)
    response.raise_for_status()
    return response.json()


_jwks_fetcher = _fetch_jwks


def reset_jwks_cache():
    _jwks_cache.clear()
    _jwks_refetched.clear()


def _keys_for(base, *, force=False):
    now = time.monotonic()
    cached = _jwks_cache.get(base)
    if not force and cached and now - cached[0] < _CACHE_TTL:
        return cached[1]
    try:
        document = _jwks_fetcher(base)
        keys = {item.get('kid'): item for item in document.get('keys', []) if isinstance(item, dict) and isinstance(item.get('kid'), str)}
    except Exception as exc:
        logger.debug('Supabase JWKS fetch failed: %s', type(exc).__name__)
        raise SignInUnavailable from exc
    _jwks_cache[base] = (now, keys)
    return keys


def verify_supabase_token(token: str) -> str:
    base = supabase_url()
    if not base:
        raise TokenInvalid
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        logger.debug('Supabase token rejected: %s', type(exc).__name__)
        raise TokenInvalid from exc
    alg = header.get('alg')
    if alg not in ALLOWED_ALGS:
        raise TokenInvalid
    kid = header.get('kid')
    if not isinstance(kid, str):
        raise TokenInvalid
    keys = _keys_for(base)
    jwk = keys.get(kid)
    if jwk is None:
        now = time.monotonic()
        if now - _jwks_refetched.get(base, 0) >= _REFETCH_INTERVAL:
            _jwks_refetched[base] = now
            keys = _keys_for(base, force=True)
            jwk = keys.get(kid)
        if jwk is None:
            raise TokenInvalid
    try:
        if jwk.get('kty') == 'oct' or ('alg' in jwk and jwk['alg'] != alg):
            raise TokenInvalid
        key = jwt.PyJWK(jwk, algorithm=alg).key
        claims = jwt.decode(
            token, key, algorithms=[alg], audience='authenticated',
            issuer=f'{base}/auth/v1', leeway=10,
            options={'require': ['exp', 'iss', 'aud', 'sub']},
        )
        sub = claims.get('sub')
        if not isinstance(sub, str) or not sub or len(sub) > 64:
            raise TokenInvalid
        if claims.get('is_anonymous') is True:
            raise TokenInvalid
        if 'role' in claims and claims['role'] != 'authenticated':
            raise TokenInvalid
        return sub
    except TokenInvalid:
        raise
    except Exception as exc:
        logger.debug('Supabase token rejected: %s', type(exc).__name__)
        raise TokenInvalid from exc
