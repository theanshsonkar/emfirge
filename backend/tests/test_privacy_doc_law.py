"""L71h PRIVACY.md says only what the code does: the doc and the code are checked against each other.

Checks (each is a function of the doc text, so the self-test can feed it doctored copies):
  (a) the tables in the storage table == every table in database.Base.metadata
  (b) each row's "Deleted by purge" agrees with privacy.PURGE_PLAN
  (c) the S3 prefixes in the storage table == the prefixes the code writes (storage.REPORTS_PREFIX,
      confirmed by really calling save_report, and no other S3 write exists in backend/app)
  (d) no retention period / time-based deletion claim (no such code exists)
  (e) every `<!-- law: X -->` marker names a law that has a test
  (f) no backticked table or S3 prefix that does not exist
"""
import os
import re
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from app import database, privacy, storage

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "PRIVACY.md"
APP_DIR = ROOT / "backend" / "app"
START, END = "<!-- privacy-storage:start -->", "<!-- privacy-storage:end -->"
COLUMNS = ["Where", "What it holds", "Deleted by purge", "Kept for"]
NOT_PREFIXES = {"backend/", "mcp/", "site/"}  # repo folders, not S3 prefixes
NOT_TABLES = {"emfirge_setup", "s3_objects"}  # underscore words in backticks that are tool/response names, not tables

RETENTION_RE = re.compile(
    r"\b\d+\s*[- ]?\s*(day|days|month|months|year|years)\b"
    r"|auto-?delet|automatically[ -]delet|\blifecycle\b",
    re.IGNORECASE,
)
RETENTION_MSG = (
    "PRIVACY.md states a retention period or time-based deletion ({found!r}), but no time-based deletion "
    "code exists (no sweeps, no S3 expiry rules). When real retention code lands, change this law together with it (L71h)."
)


def doc_text() -> str:
    return DOC.read_text(encoding="utf-8")


def storage_rows(text: str) -> list[dict]:
    """Parse the storage table between the markers into [{where_kind, name, purged, cells}]."""
    assert START in text and END in text, f"PRIVACY.md needs {START} ... {END} around the storage table"
    block = text.split(START, 1)[1].split(END, 1)[0]
    lines = [l.strip() for l in block.splitlines() if l.strip().startswith("|")]
    assert len(lines) >= 3, "storage table has no rows"
    header = [c.strip() for c in lines[0].strip("|").split("|")]
    assert header == COLUMNS, f"storage table columns must be {COLUMNS}, got {header}"
    rows = []
    for line in lines[2:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        assert len(cells) == 4, f"storage row needs 4 cells: {line}"
        m = re.fullmatch(r"(Postgres|S3) `([^`]+)`", cells[0])
        assert m, f"first cell must be Postgres `table` or S3 `prefix/`: {cells[0]!r}"
        assert cells[2] in ("yes", "no"), f"'Deleted by purge' must be exactly yes or no: {line}"
        assert cells[3], f"'Kept for' is empty: {line}"
        rows.append({"kind": m.group(1), "name": m.group(2), "purged": cells[2] == "yes", "cells": cells})
    return rows


def code_s3_prefixes() -> set[str]:
    """The top-level prefixes save_report really writes, plus proof it is the only S3 writer."""
    writers = [p.name for p in APP_DIR.glob("*.py")
               if re.search(r"\.(put_object|upload_file|upload_fileobj|copy_object)\(", p.read_text(encoding="utf-8"))]
    assert writers == ["storage.py"], f"only storage.py may write to S3, found {writers}; update PRIVACY.md and L71h"
    saved = {}
    with mock_aws():
        old = {k: os.environ.get(k) for k in ("S3_BUCKET_NAME", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION")}
        os.environ.update(S3_BUCKET_NAME="l71h-bucket", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="y", AWS_REGION="us-east-1")
        try:
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="l71h-bucket")
            storage.save_report("l71h-analysis", {"k": "v"})
            keys = [o["Key"] for o in s3.list_objects_v2(Bucket="l71h-bucket").get("Contents", [])]
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    prefixes = {k.split("/", 1)[0] + "/" for k in keys}
    assert prefixes == {storage.REPORTS_PREFIX}, prefixes
    return prefixes


def check_tables(text: str) -> list[str]:
    doc = {r["name"] for r in storage_rows(text) if r["kind"] == "Postgres"}
    code = set(database.Base.metadata.tables)
    problems = [f"table in code but not in PRIVACY.md storage table: {t}" for t in sorted(code - doc)]
    problems += [f"table in PRIVACY.md but not in code: {t}" for t in sorted(doc - code)]
    return problems


def check_purge_cells(text: str) -> list[str]:
    problems = []
    for r in storage_rows(text):
        if r["kind"] != "Postgres" or r["name"] not in privacy.PURGE_PLAN:
            continue
        really = privacy.PURGE_PLAN[r["name"]].kind != privacy.KEPT
        if r["purged"] != really:
            problems.append(f"{r['name']}: PRIVACY.md says purge={'yes' if r['purged'] else 'no'}, "
                            f"PURGE_PLAN says {'yes' if really else 'no'}")
    return problems


def check_s3(text: str) -> list[str]:
    doc = {r["name"] for r in storage_rows(text) if r["kind"] == "S3"}
    code = code_s3_prefixes()
    problems = [f"S3 prefix the code writes but PRIVACY.md omits: {p}" for p in sorted(code - doc)]
    problems += [f"S3 prefix in PRIVACY.md the code never writes: {p}" for p in sorted(doc - code)]
    return problems


def check_no_retention(text: str) -> list[str]:
    return [RETENTION_MSG.format(found=m.group(0)) for m in RETENTION_RE.finditer(text)]


def _law_corpus() -> str:
    files = [p for p in (ROOT / "backend" / "tests").rglob("*.py") if p.name != Path(__file__).name]
    files += [p for p in (ROOT / "mcp" / "src").rglob("*.test.ts")]
    own_tests = re.findall(r"def (test_\w+)", Path(__file__).read_text(encoding="utf-8"))  # this file's own test names only
    return "\n".join([p.read_text(encoding="utf-8", errors="ignore") for p in files] + own_tests)


def check_law_markers(text: str) -> list[str]:
    corpus = _law_corpus()
    ids = [i.strip() for m in re.finditer(r"<!--\s*law:\s*([^>]*?)\s*-->", text) for i in re.split(r"[,\s]+", m.group(1)) if i.strip()]
    problems = [] if ids else ["PRIVACY.md has no <!-- law: ... --> markers"]
    for i in sorted(set(ids)):
        if not re.search(rf"(?<![A-Za-z0-9]){re.escape(i)}(?![A-Za-z0-9])", corpus):
            problems.append(f"law marker {i} has no test that names it")
    return problems


def check_no_phantoms(text: str) -> list[str]:
    tables = set(database.Base.metadata.tables)
    prefixes = {storage.REPORTS_PREFIX}
    problems = []
    for m in re.finditer(r"Postgres `([^`]+)`", text):
        if m.group(1) not in tables:
            problems.append(f"PRIVACY.md mentions Postgres table that does not exist: {m.group(1)}")
    for m in re.finditer(r"S3 `([^`]+)`", text):
        if m.group(1) not in prefixes:
            problems.append(f"PRIVACY.md mentions S3 prefix the code never writes: {m.group(1)}")
    for m in re.finditer(r"`([a-z][a-z0-9_]*)`\s+(?:table|rows?)\b|\btables?\s+`([a-z][a-z0-9_]*)`", text):
        name = m.group(1) or m.group(2)  # a bare word used as a table name, e.g. "`findings` rows"
        if name not in tables:
            problems.append(f"PRIVACY.md mentions `{name}` as a table, which does not exist")
    for tok in re.findall(r"`([^`\n]+)`", text):
        if re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)+", tok) and tok not in tables and tok not in NOT_TABLES:
            problems.append(f"PRIVACY.md mentions `{tok}`, which is not a table")
        if re.fullmatch(r"[a-z][a-z0-9_-]*/", tok) and tok not in prefixes and tok not in NOT_PREFIXES:
            problems.append(f"PRIVACY.md mentions `{tok}`, which is not an S3 prefix the code writes")
    return sorted(set(problems))


CHECKS = [check_tables, check_purge_cells, check_s3, check_no_retention, check_law_markers, check_no_phantoms]


def _fail(problems):
    assert not problems, "\n".join(problems)


def test_L71h_a_every_table_is_in_the_doc_and_no_other():
    _fail(check_tables(doc_text()))


def test_L71h_b_purge_column_matches_purge_plan():
    _fail(check_purge_cells(doc_text()))


def test_L71h_c_s3_prefixes_match_what_the_code_writes():
    _fail(check_s3(doc_text()))


def test_L71h_d_no_retention_period_is_promised():
    _fail(check_no_retention(doc_text()))


def test_L71h_e_every_law_marker_names_a_real_test():
    _fail(check_law_markers(doc_text()))


def test_L71h_f_doc_names_no_table_or_prefix_that_does_not_exist():
    _fail(check_no_phantoms(doc_text()))


def test_L71h_self_test_doctored_docs_are_caught():
    good = doc_text()
    for check in CHECKS:
        assert check(good) == [], f"{check.__name__} must pass on the real doc"

    lines = good.splitlines()
    row = next(l for l in lines if l.startswith("| Postgres `analysis_logs`"))
    kept = next(l for l in lines if l.startswith("| Postgres `api_keys`"))
    s3row = next(l for l in lines if l.startswith("| S3 `reports/`"))

    removed_table = good.replace(row + "\n", "")
    assert any("analysis_logs" in p for p in check_tables(removed_table))

    flipped = good.replace(row, row.replace("| yes |", "| no |"))
    assert flipped != good and any("analysis_logs" in p for p in check_purge_cells(flipped))
    flipped_kept = good.replace(kept, kept.replace("| no |", "| yes |"))
    assert flipped_kept != good and any("api_keys" in p for p in check_purge_cells(flipped_kept))

    ghost = good.replace(s3row, s3row + "\n" + s3row.replace("S3 `reports/`", "S3 `snapshots/`"))
    assert any("snapshots/" in p for p in check_s3(ghost))
    assert any("snapshots/" in p for p in check_no_phantoms(ghost))
    assert any("reports/" in p for p in check_s3(good.replace(s3row + "\n", "")))

    for claim in ("Findings are deleted after 90 days.", "Kept for 6 months.", "1 year", "S3 lifecycle rules remove it.",
                  "It is auto-deleted.", "Data is automatically deleted."):
        assert check_no_retention(good + "\n" + claim), claim
    assert "change this law together with it" in check_no_retention(good + "\n90 days")[0]

    assert any("L99z" in p for p in check_law_markers(good + "\n<!-- law: L99z -->"))
    assert any("markers" in p for p in check_law_markers(re.sub(r"<!--\s*law:[^>]*-->", "", good)))

    assert any("findings" in p for p in check_no_phantoms(good + "\nWe store `findings` rows."))
    assert any("Postgres table" in p for p in check_no_phantoms(good + "\nPostgres `findings`"))
    assert any("not a table" in p for p in check_no_phantoms(good + "\nSee `finding_rows`."))
