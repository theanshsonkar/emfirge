import base64
import json
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

TEST_SUPABASE_URL = 'https://test-project.supabase.co'
EC_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def _ec_jwk():
    n = EC_PRIVATE_KEY.public_key().public_numbers()
    return {'kty': 'EC', 'crv': 'P-256', 'x': _b64(n.x.to_bytes(32, 'big')), 'y': _b64(n.y.to_bytes(32, 'big')), 'kid': 'test-ec', 'alg': 'ES256'}


def _rsa_jwk():
    n = RSA_PRIVATE_KEY.public_key().public_numbers()
    return {'kty': 'RSA', 'n': _b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, 'big')), 'e': _b64(n.e.to_bytes((n.e.bit_length() + 7) // 8, 'big')), 'kid': 'test-rsa', 'alg': 'RS256'}


JWKS = {'keys': [_ec_jwk(), _rsa_jwk()]}


def make_token(sub, *, alg='ES256', kid=None, key=None, iss=f'{TEST_SUPABASE_URL}/auth/v1', aud='authenticated', exp_delta=3600, extra=None, drop=()):
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {'sub': sub, 'iss': iss, 'aud': aud, 'exp': now + exp_delta, 'iat': now, 'role': 'authenticated'}
    payload.update(extra or {})
    for name in drop:
        payload.pop(name, None)
    if key is None:
        key = EC_PRIVATE_KEY if alg == 'ES256' else RSA_PRIVATE_KEY
    return jwt.encode(payload, key, algorithm=alg, headers={'kid': kid or ('test-ec' if alg == 'ES256' else 'test-rsa')})


@pytest.fixture
def supabase_env(monkeypatch):
    from app import auth, supabase_auth
    monkeypatch.setenv('SUPABASE_URL', TEST_SUPABASE_URL)
    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    monkeypatch.setattr(supabase_auth, '_jwks_fetcher', lambda base: JWKS)
    supabase_auth.reset_jwks_cache()
    yield
    supabase_auth.reset_jwks_cache()


@pytest.fixture
def fake_keys():
    return EC_PRIVATE_KEY, RSA_PRIVATE_KEY


def unsigned_token(payload):
    def enc(value):
        return _b64(json.dumps(value, separators=(',', ':')).encode())
    return f'{enc({"alg": "none", "typ": "JWT", "kid": "test-ec"})}.{enc(payload)}.'


@pytest.fixture
def client(shared_test_db, supabase_env):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def hs256_with_key(payload, key, kid='test-ec'):
    import hashlib
    import hmac
    header = {'alg': 'HS256', 'typ': 'JWT', 'kid': kid}
    def enc(value):
        return _b64(json.dumps(value, separators=(',', ':')).encode())
    signing_input = f'{enc(header)}.{enc(payload)}'.encode()
    return f'{signing_input.decode()}.{_b64(hmac.new(key, signing_input, hashlib.sha256).digest())}'
