"""L56 core/adapter boundary: the cloud-neutral core must not gain new AWS coupling.

Emfirge's architecture rule: the core (branches, change ledger, diff, verdict,
lenses, graph categories) is cloud-neutral; AWS specifics live in an AWS adapter
(collector, models, mutations, ingest, hand-back, field catalog, AWS graph
semantics).  We are not refactoring yet; this is a ratchet.  Current coupling is
listed in ALLOWED, new coupling fails, and ALLOWED may only shrink (stale
entries fail so the list is cleaned as code is decoupled).

Core modules are parsed with ``ast`` and never imported.
"""
from __future__ import annotations

import ast
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[2] / "app"

# Deliberate edit required to add/remove a core module.
CORE_MODULES = {
    "branches", "diffing", "verdict", "exposure", "scoring", "delete_lens",
    "cost", "limits", "graph_schema", "evidence_models", "in_use_evidence",
    "egraph",
}

# AWS-adapter modules (app.<name>).  Ambiguous calls: `models` (defines
# AWSInfrastructure), `mutations` (AWS resource mutations), `scanners`,
# `plan_ingest` (terraform plan -> AWS), `iam_*`/`rds_ports`/`tags` (AWS semantics).
ADAPTER_MODULES = {
    "aws_collector", "aws_api_ingest", "aws_cli_ingest", "cfn_ingest",
    "plan_ingest", "typed_handback", "s3_public", "rds_ports", "tags",
    "field_catalog", "mutations", "models", "trust_policy", "trusted_account",
    "iam_classifier", "iam_escalation", "role_access", "tf_parser",
    "tf_indexer", "serializer", "scanners", "drift_service", "fix_mutations",
}
AWS_LIBS = {"boto3", "botocore"}

# BASELINE: current coupling.  This may ONLY SHRINK.  Never add an entry to make
# a failing test pass unless the coupling is truly unavoidable (state why in a
# comment); prefer putting the AWS-specific part behind the adapter.
ALLOWED: dict[str, set[str]] = {
    "branches": {"mutations", "models"},
    "diffing": {"mutations", "models", "tags"},
    "verdict": {"tags", "iam_escalation", "mutations", "models",
                "plan_ingest", "scanners"},
    "exposure": {"rds_ports"},
    "scoring": {"mutations"},
    "delete_lens": {"mutations"},
    "cost": {"models"},
    "limits": {"models"},
    "graph_schema": set(),
    "evidence_models": set(),
    "in_use_evidence": {"boto3", "botocore", "mutations"},
    "egraph": {"models", "iam_classifier", "iam_escalation", "rds_ports"},
}


def _app_module_names() -> set[str]:
    return {p.stem for p in APP_DIR.glob("*.py")}


def _imported_names(core: str) -> set[str]:
    """Top-level app modules and AWS libs imported (anywhere) by a core module."""
    tree = ast.parse((APP_DIR / f"{core}.py").read_text())
    app_mods = _app_module_names()
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                parts = a.name.split(".")
                if parts[0] in AWS_LIBS:
                    found.add(parts[0])
                elif parts[0] == "app" and len(parts) > 1:
                    found.add(parts[1])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            parts = mod.split(".") if mod else []
            if node.level == 0 and parts and parts[0] in AWS_LIBS:
                found.add(parts[0])
            elif node.level == 0 and parts and parts[0] == "app":
                if len(parts) > 1:
                    found.add(parts[1])
                else:  # from app import x
                    found.update(a.name for a in node.names if a.name in app_mods)
            elif node.level == 1:  # from .x import y / from . import x
                if parts:
                    found.add(parts[0])
                else:
                    found.update(a.name for a in node.names if a.name in app_mods)
    return found & (ADAPTER_MODULES | AWS_LIBS)


def test_L56a_core_module_set_is_deliberate():
    """L56 core/adapter boundary: the core module list equals the pinned set."""
    assert set(ALLOWED) == CORE_MODULES, (
        "ALLOWED keys and CORE_MODULES differ; changing the core list is a "
        "deliberate edit of both constants"
    )
    for core in CORE_MODULES:
        assert (APP_DIR / f"{core}.py").exists(), f"core module {core} missing"


def test_L56b_no_new_adapter_coupling():
    """L56 core/adapter boundary: core modules import no un-baselined adapter module or AWS lib."""
    problems = []
    for core in sorted(CORE_MODULES):
        for imp in sorted(_imported_names(core) - ALLOWED.get(core, set())):
            what = "AWS library" if imp in AWS_LIBS else "AWS adapter"
            problems.append(
                f"core module {core} now imports {what} {imp}; put the "
                f"AWS-specific part behind the adapter or, if unavoidable, add "
                f"it to ALLOWED with a reason"
            )
    assert not problems, "\n".join(problems)


def test_L56c_baseline_has_no_stale_entries():
    """L56 core/adapter boundary: every ALLOWED entry is still imported (the baseline only shrinks)."""
    problems = []
    for core in sorted(CORE_MODULES):
        for imp in sorted(ALLOWED.get(core, set()) - _imported_names(core)):
            problems.append(
                f"ALLOWED[{core!r}] lists {imp!r} but {core} no longer imports "
                f"it; remove the stale entry so the baseline shrinks"
            )
    assert not problems, "\n".join(problems)


def test_L56d_no_aws_library_in_core_unless_baselined():
    """L56 core/adapter boundary: boto3/botocore appear in core only where baselined."""
    for core in sorted(CORE_MODULES):
        libs = _imported_names(core) & AWS_LIBS
        assert libs <= ALLOWED.get(core, set()), (
            f"core module {core} now imports AWS library {sorted(libs)}; put "
            f"the AWS-specific part behind the adapter or, if unavoidable, add "
            f"it to ALLOWED with a reason"
        )


def test_L56e_baseline_only_names_adapter_modules():
    """L56 core/adapter boundary: ALLOWED entries are real adapter modules or AWS libs."""
    for core, imps in ALLOWED.items():
        assert imps <= (ADAPTER_MODULES | AWS_LIBS), (core, imps)
