import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from app import database
from app.main import app
from tests.supabase_fake import TEST_SUPABASE_URL, make_token, unsigned_token, hs256_with_key


@pytest.mark.parametrize('case', [
    'expired', 'wrong_iss', 'wrong_aud', 'bad_signature', 'unknown_kid', 'alg_none',
    'hs256_random', 'hs256_ec_public', 'missing_sub', 'missing_exp', 'anonymous', 'anon_role', 'garbage',
], ids=lambda case: f'L22-{case}')
def test_l22_every_invalid_token_matches_bad_api_key(client, case, fake_keys):
    expected = client.get('/project', headers={'X-API-Key': 'bogus'}).json()
    ec_key, _ = fake_keys
    if case == 'expired': token = make_token('u', exp_delta=-3600)
    elif case == 'wrong_iss': token = make_token('u', iss='https://wrong.example/auth/v1')
    elif case == 'wrong_aud': token = make_token('u', aud='anon')
    elif case == 'bad_signature': token = make_token('u', key=ec.generate_private_key(ec.SECP256R1()))
    elif case == 'unknown_kid': token = make_token('u', kid='unknown')
    elif case == 'alg_none': token = unsigned_token({'sub': 'u', 'iss': f'{TEST_SUPABASE_URL}/auth/v1', 'aud': 'authenticated', 'exp': 9999999999})
    elif case == 'hs256_random': token = jwt.encode({'sub': 'u'}, 'random-secret', algorithm='HS256', headers={'kid': 'test-ec'})
    elif case == 'hs256_ec_public':
        pem = ec_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        token = hs256_with_key({'sub': 'u'}, pem)
    elif case == 'missing_sub': token = make_token('u', drop=('sub',))
    elif case == 'missing_exp': token = make_token('u', drop=('exp',))
    elif case == 'anonymous': token = make_token('u', extra={'is_anonymous': True})
    elif case == 'anon_role': token = make_token('u', extra={'role': 'anon'})
    else: token = 'a.b.c'
    actual = client.get('/project', headers={'Authorization': f'Bearer {token}'})
    assert actual.status_code == 401
    assert actual.json() == expected
