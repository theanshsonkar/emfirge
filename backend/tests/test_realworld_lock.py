"""answer_keys.json is locked: it must match the sha256 recorded in LOCK.json."""
import hashlib
import json
from pathlib import Path

DATA = Path(__file__).parent / "data" / "realworld"


def test_answer_keys_match_lock():
    lock = json.loads((DATA / "LOCK.json").read_text())
    actual = hashlib.sha256((DATA / "answer_keys.json").read_bytes()).hexdigest()
    assert actual == lock["answer_keys_sha256"], "answer_keys.json changed after it was locked"
