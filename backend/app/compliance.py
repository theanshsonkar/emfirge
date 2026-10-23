"""
Compliance framework evaluation.

Requirements come from Prowler's published CIS AWS Foundations 1.5 and SOC 2
files (vendored, Apache-2.0; see compliance_sources.py and
data/third_party/prowler/compliance/SOURCE.json). Each requirement lists Prowler
checks; EMFIRGE_TO_PROWLER says which Emfirge rules test the same condition.

Status per requirement:
- fail:           a mapped Emfirge rule fired
- pass:           every Prowler check of the requirement is covered by an Emfirge
                  rule and none fired
- partial:        some, not all, of its checks are covered and none fired. Nothing
                  wrong was found in what Emfirge evaluates; the rest is not evaluated
- not_applicable: every mapped rule's service has no resources, and coverage is full
- not_evaluated:  no Emfirge rule covers it (never reported as pass)
"""

import re
from typing import Optional

from app.compliance_sources import (
    EMFIRGE_TO_PROWLER,
    FRAMEWORK_FILES,
    RULE_SERVICE,
    load_framework,
    load_source_metadata,
    prowler_check_to_rules,
)


def _check_service_has_resources(service_key: str, infrastructure: Optional[dict]) -> bool:
    """Check if a service has any resources deployed. Used for N/A determination."""
    if not infrastructure:
        return True  # If no infra data, assume resources exist (don't mark N/A)

    checks = {
        "ec2": lambda i: i.get("ec2", {}).get("instance_count", 0) > 0,
        "s3": lambda i: i.get("s3", {}).get("total_buckets", 0) > 0,
        "rds": lambda i: len(i.get("rds", {}).get("instances", [])) > 0,
        "lambda": lambda i: i.get("lambda_data", {}).get("function_count", 0) > 0,
        "ecs": lambda i: i.get("ecs", {}).get("total_task_definitions", 0) > 0,
        "vpc": lambda i: i.get("vpc", {}).get("total_vpcs", 0) > 0,
        "kms": lambda i: i.get("kms", {}).get("total_cmks", 0) > 0,
        "waf": lambda i: i.get("waf", {}).get("total_albs", 0) > 0,
    }

    check_fn = checks.get(service_key)
    if not check_fn:
        return True  # Unknown service key → assume resources exist
    return check_fn(infrastructure)


def _sort_key(req_id: str):
    return [int(p) if p.isdigit() else p for p in re.split(r"[.]", req_id)]


def _requirement_view(framework_id: str, req: dict) -> dict:
    """Normalise one Prowler requirement into id / label / title / section."""
    attrs = (req.get("Attributes") or [{}])[0]
    section_raw = attrs.get("Section", "")
    if framework_id == "cis-aws-1.5":
        sec_id, _, sec_title = section_raw.partition(" ")
        label = req["Id"]
        title = req.get("Description", "")
    else:
        sec_id, _, sec_title = section_raw.partition(" - ")
        name = req.get("Name", "")
        label = name.split(" ", 1)[0] if name else req["Id"]
        title = name
    return {"id": req["Id"], "label": label, "title": title,
            "section": sec_id, "section_title": sec_title}


def evaluate_framework(
    framework_id: str,
    fired_rule_ids: set,
    infrastructure: Optional[dict] = None,
) -> dict:
    """
    Evaluate a compliance framework against fired rule IDs.

    Args:
        framework_id: "cis-aws-1.5" or "soc2"
        fired_rule_ids: set of rule_id strings that fired during the scan
        infrastructure: optional infrastructure dict for N/A determination

    Returns:
        dict with framework metadata, sections, source and per-requirement status.
    """
    data = load_framework(framework_id)
    if data is None:
        return {"error": f"Unknown framework: {framework_id}"}

    check_to_rules = prowler_check_to_rules()
    meta = load_source_metadata()
    file_name, name = FRAMEWORK_FILES[framework_id]
    file_meta = next((f for f in meta["files"] if f["path"] == file_name), {})

    requirements = data["Requirements"]
    if framework_id == "cis-aws-1.5":
        requirements = sorted(requirements, key=lambda r: _sort_key(r["Id"]))

    controls = []
    sections = []
    seen_sections = set()
    counts = {"pass": 0, "fail": 0, "partial": 0, "not_applicable": 0, "not_evaluated": 0}

    for req in requirements:
        view = _requirement_view(framework_id, req)
        if view["section"] not in seen_sections:
            seen_sections.add(view["section"])
            sections.append({"id": view["section"], "title": view["section_title"]})

        checks = list(req.get("Checks") or [])
        mapped_rules = sorted({r for c in checks for r in check_to_rules.get(c, [])})
        covered = [c for c in checks if c in check_to_rules]
        fired = [r for r in mapped_rules if r in fired_rule_ids]

        if fired:
            status = "fail"
            description = f"Emfirge found: {', '.join(fired)}"
        elif not mapped_rules:
            status = "not_evaluated"
            description = "Emfirge has no rule for this requirement"
        elif all(
            RULE_SERVICE.get(r) and not _check_service_has_resources(RULE_SERVICE[r], infrastructure)
            for r in mapped_rules
        ):
            if len(covered) == len(checks):
                status = "not_applicable"
                description = "No resources of the relevant service are deployed"
            else:
                status = "not_evaluated"
                description = "Covered rules do not apply (no resources); the remaining checks are not evaluated"
        elif len(covered) == len(checks):
            status = "pass"
            description = f"Emfirge evaluates all {len(checks)} check(s) of this requirement; none fired"
        else:
            status = "partial"
            description = (f"Nothing found in the {len(covered)} of {len(checks)} check(s) "
                           f"Emfirge evaluates; the rest are not evaluated")

        counts[status] += 1
        controls.append({
            "id": view["id"],
            "label": view["label"],
            "title": view["title"],
            "section": view["section"],
            "status": status,
            "mappedRuleId": mapped_rules[0] if mapped_rules else None,
            "mappedRuleIds": mapped_rules,
            "checks": {"total": len(checks), "evaluated": len(covered)},
            "description": description,
        })

    total = len(controls)
    evaluated = total - counts["not_evaluated"]

    return {
        "id": framework_id,
        "name": name,
        "version": data.get("Version") or "unversioned",
        "totalControls": total,
        "passedControls": counts["pass"],
        "failedControls": counts["fail"],
        "partialControls": counts["partial"],
        "naControls": counts["not_applicable"],
        "notEvaluatedControls": counts["not_evaluated"],
        "evaluatedControls": evaluated,
        "coverage": {"evaluated": evaluated, "total": total},
        "source": {
            "publisher": meta["project"],
            "repo": meta["repo"],
            "commit": meta["commit"],
            "file": file_meta.get("upstream_path"),
            "license": meta["license"],
            "fetched": meta["fetched"],
        },
        "sections": sections,
        "controls": controls,
    }


def evaluate_all_frameworks(fired_rule_ids: set, infrastructure: Optional[dict] = None) -> list:
    """Evaluate all supported frameworks and return results."""
    return [
        evaluate_framework("cis-aws-1.5", fired_rule_ids, infrastructure),
        evaluate_framework("soc2", fired_rule_ids, infrastructure),
    ]
