import hashlib
from pathlib import Path

LOCKED_SHA256 = {
    "scenarios.json": "30a043ca6c6888b1760a02417c9f9c5addb8f7906fdf2d864a8de80f87d0f966",
    "delete_base.json": "b0f3d9922efd037d81f4c8a62e1ea88adfcf916ed8a628036a0466bcd680ade3",
    "fixtures/datatalks_destroy_plan.json": "d9b123083fa111fda085954c60c731be3931e3459d7c4265035d1e25e8536fa4",
    "phase_d/D01.json": "3ce7dd0eb849d5b2a8502db135148ef3394514375d12605a196b4b571cd422e0",
    "phase_d/D02.json": "111e5e9b59d7cdcb3d8293e0c2710e23e646c4e95d1ef6fa634a5a051886b5d9",
    "phase_d/D03.json": "6684fc19c031134bc53440e71f3d8d5ce347c06d95321d1627f5bffc109737d4",
    "phase_d/D04.json": "ded5a97a13afb0d75dae26638f7f711e6488203cd71bf9963de406b89db62354",
    "phase_d/D05.json": "9c78cfc975be6f8e4130b7b92ae1cfe6a2bced74c41def9f0c3bd5dad635c859",
    "phase_d/D06.json": "576851bae952364ac4cdace54fb21a2de9c2bec518a2bdf195614a73d40af9e0",
    "phase_d/D07.json": "bfbcedf35cf6584f48b73f41d948a414a3600e1ed85340b2eb24ac37f1ec8825",
    "phase_d/D08.json": "d58ce00f69cfe1497c4f3b546e040de1ad22a206e023e12a01a4c36b38b0d57d",
    "phase_d/D09.json": "9cbd16d847765dc5d73d58679696c487ae82c1095437891cbfd8904e1512f3ce",
    "phase_d/D10.json": "02e73df13d95f00c4c78c36a34dbe2260d3ffb030b136ed36531486e1dcfc681",
    "phase_d/D11.json": "4afcaf13cc8a531cec0dc67efe60ba1cf96b7b389eb0edca9791cfc17332ff64",
    "phase_d/D12.json": "90c6e31ed1914f7f1bc0d8ccae39ad2ded41e52b8de6382969aa165abede4205",
    "phase_d/D13.json": "96cc73785a46f8f03f02ee97073551debe63522dffbb63ae38a9b2f143b89bd2",
    "phase_d/D14.json": "afbc9dd2b08c93ab87b868fc5b8005350f1244d7146cf5744422cf753e44b70a",
    "phase_d/L01.json": "33c8712cb5578b6f6d77ae654d0f65d8c089054af54048c24e6fa5e47399c45c",
    "phase_d/L02.json": "5ac2bed5a49e65a1ab6cc135990114c137b7af84983fb21798383d135d947e74",
    "phase_d/L03.json": "e867404048d9311316eacff4d3a8e063cd4da88de651cdf79ae6f0a0c4660360",
}


def test_locked_answer_files_unchanged():
    root = Path(__file__).parent
    for relative, expected in LOCKED_SHA256.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        assert actual == expected, "Locked answer file changed. Locked answers may only change with Ansh's approval."


def test_locked_phase_d_file_set_unchanged():
    root = Path(__file__).parent
    actual = {p.relative_to(root).as_posix() for p in (root / "phase_d").glob("*.json")}
    expected = {relative for relative in LOCKED_SHA256 if relative.startswith("phase_d/")}
    assert actual == expected, "Locked Phase D scenario file set changed."
