"""L71d CI API keys are stored as sha256 digests (base64url, fits the String(64) column); key material is never returned after creation."""
import base64
import hashlib
import json
import secrets
from pathlib import Path

from app import auth, database

PREFIX = "sha256:"


def _stored_form(raw: str) -> str:
    """Independent statement of the stored form: 'sha256:' + unpadded base64url of the digest bytes."""
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return PREFIX + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _stored():
    with database.SessionLocal() as db:
        return [r.api_key for r in db.query(database.CIAPIKey).order_by(database.CIAPIKey.id)]


def test_L71d_create_stores_only_a_hash_and_validate_revoke_work(shared_test_db):
    key = database.create_ci_api_key(7, "o/r")
    assert len(key) == 64
    assert _stored() == [_stored_form(key)]
    assert _stored()[0].startswith(PREFIX)
    assert len(_stored()[0]) <= 64
    assert key not in _stored()[0]
    assert database.validate_ci_api_key(key) == {"installation_id": 7, "repo_full_name": "o/r"}
    assert database.validate_ci_api_key(auth.hash_key(key)) is None  # the stored hash is not a credential
    assert database.validate_ci_api_key(_stored_form(key)) is None  # the stored form is not a credential
    assert database.validate_ci_api_key("0" * 64) is None
    listed = database.get_ci_api_keys(7)
    assert len(listed) == 1 and listed[0]["is_active"] is True
    dumped = json.dumps(listed)
    assert key not in dumped and key[:8] not in dumped
    assert database.revoke_ci_api_key(key) is True
    assert database.validate_ci_api_key(key) is None
    assert database.get_ci_api_keys(7)[0]["is_active"] is False


def test_L71d_startup_migrates_plaintext_rows_and_is_idempotent(shared_test_db):
    legacy = secrets.token_hex(32)
    with database.SessionLocal() as db:
        db.add(database.CIAPIKey(installation_id=9, api_key=legacy, repo_full_name="o/legacy"))
        db.commit()
    database.create_tables()
    assert _stored() == [_stored_form(legacy)]
    assert database.validate_ci_api_key(legacy) == {"installation_id": 9, "repo_full_name": "o/legacy"}
    database.create_tables()
    assert _stored() == [_stored_form(legacy)]
    assert database.validate_ci_api_key(legacy) is not None


def test_L71d_column_is_original_width_and_no_schema_change_is_issued():
    assert database.CIAPIKey.__table__.c.api_key.type.length == 64
    source = Path(database.__file__).read_text(encoding="utf-8")
    assert "ALTER TABLE" not in source.upper()
