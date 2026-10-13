import hashlib
from pathlib import Path

LOCKED_SHA256 = {
    "scenarios.json": "30a043ca6c6888b1760a02417c9f9c5addb8f7906fdf2d864a8de80f87d0f966",
    "scenarios_phase_d.json": "3cb21d351799784516cbe234bc696ba8bafa1a8eb5eef43ebdb3756971cb9189",
    "delete_base.json": "83230183bf7af35980fcbeed50f1a2721151501bdc2ccd80ba7b22d054f3cef8",
    "fixtures/datatalks_destroy_plan.json": "7a68c3ec17d55fad5599dfca7807be497a295ffa3509de15cdd2230407e8ca15",
}


def test_locked_answer_files_unchanged():
    root = Path(__file__).parent
    for relative, expected in LOCKED_SHA256.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        assert actual == expected, "Locked answer file changed. Locked answers may only change with Ansh's approval."
