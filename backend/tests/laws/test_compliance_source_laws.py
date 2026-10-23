"""L57 compliance from a published source: requirement ids come from Prowler's published data, the
Emfirge to Prowler mapping only names things that exist, and a requirement Emfirge does not
evaluate is never reported as pass."""
import json
import os
import re

from app import compliance_sources as cs
from app.compliance import evaluate_framework

FRAMEWORKS = ["cis-aws-1.5", "soc2"]
RULES_PY = os.path.join(os.path.dirname(cs.__file__), "rules.py")


def _vendored_ids(fw):
    return {r["Id"] for r in cs.load_framework(fw)["Requirements"]}


def _vendored_checks():
    return {c for fw in FRAMEWORKS for r in cs.load_framework(fw)["Requirements"] for c in r["Checks"]}


def test_L57a_every_reported_control_id_exists_in_vendored_framework():
    """L57 compliance from a published source: reported control ids exist in the vendored JSON."""
    fired = set(cs.EMFIRGE_TO_PROWLER)
    for fw in FRAMEWORKS:
        for fired_set in (set(), fired):
            result = evaluate_framework(fw, fired_set)
            ids = [c["id"] for c in result["controls"]]
            assert set(ids) == _vendored_ids(fw)
            assert result["totalControls"] == len(_vendored_ids(fw))


def test_L57b_every_prowler_check_in_table_exists_in_vendored_data():
    """L57 compliance from a published source: every mapped Prowler check id is in the vendored data."""
    known = _vendored_checks()
    for rule_id, checks in cs.EMFIRGE_TO_PROWLER.items():
        assert checks, rule_id
        for check in checks:
            assert check in known, f"{rule_id} -> {check}"


def test_L57c_every_emfirge_rule_in_table_exists_in_rules_py():
    """L57 compliance from a published source: every mapped Emfirge rule id is defined in rules.py."""
    with open(RULES_PY, encoding="utf-8") as f:
        defined = set(re.findall(r"rule_id='(EMFIRGE-[A-Z0-9]+-\d+)'", f.read()))
    for rule_id in list(cs.EMFIRGE_TO_PROWLER) + list(cs.RULE_SERVICE):
        assert rule_id in defined, rule_id


def test_L57d_control_without_mapped_rule_is_never_pass():
    """L57 compliance from a published source: a control with no covering rule is never pass, even with nothing fired."""
    mapped_checks = set(cs.prowler_check_to_rules())
    for fw in FRAMEWORKS:
        reqs = {r["Id"]: r for r in cs.load_framework(fw)["Requirements"]}
        result = evaluate_framework(fw, set())
        unmapped = 0
        for c in result["controls"]:
            checks = reqs[c["id"]]["Checks"]
            if not any(x in mapped_checks for x in checks):
                unmapped += 1
                assert c["status"] == "not_evaluated"
                assert c["mappedRuleIds"] == []
            if c["status"] == "pass":
                assert all(x in mapped_checks for x in checks)
        assert unmapped > 0
        assert result["coverage"]["evaluated"] == result["totalControls"] - unmapped


def test_L57e_vendored_source_metadata_present():
    """L57 compliance from a published source: repo, commit, license and files are recorded and present."""
    meta = cs.load_source_metadata()
    assert meta["repo"] == "https://github.com/prowler-cloud/prowler"
    assert re.fullmatch(r"[0-9a-f]{40}", meta["commit"])
    assert meta["license"] == "Apache-2.0"
    assert meta["fetched"]
    license_path = os.path.join(cs.DATA_DIR, meta["license_file"])
    assert "Apache License" in open(license_path, encoding="utf-8").read()
    for f in meta["files"]:
        assert os.path.isfile(os.path.join(cs.DATA_DIR, f["path"]))
    for fw in FRAMEWORKS:
        src = evaluate_framework(fw, set())["source"]
        assert src["commit"] == meta["commit"] and src["license"] == "Apache-2.0"


def test_L57f_firing_rule_fails_its_mapped_controls():
    """L57 compliance from a published source: a firing rule makes every control listing its Prowler check fail."""
    for rule_id, checks in cs.EMFIRGE_TO_PROWLER.items():
        for fw in FRAMEWORKS:
            expected = {r["Id"] for r in cs.load_framework(fw)["Requirements"]
                        if set(r["Checks"]) & set(checks)}
            result = evaluate_framework(fw, {rule_id})
            failed = {c["id"] for c in result["controls"] if c["status"] == "fail"}
            assert failed == expected, (rule_id, fw)
