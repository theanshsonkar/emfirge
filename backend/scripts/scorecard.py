"""Build a public scorecard from pytest's JUnit XML output."""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def testcase_status(testcase):
    failure = testcase.find("failure")
    error = testcase.find("error")
    if failure is not None or error is not None:
        return "fail"
    skipped = testcase.find("skipped")
    if skipped is not None:
        kind = skipped.get("type", "")
        message = skipped.get("message", "")
        if kind == "pytest.xfail" or message.lower().startswith("xfail"):
            return "known_gap"
        return "skipped"
    return "pass"


def aggregate(statuses):
    if "fail" in statuses:
        return "fail"
    if "known_gap" in statuses:
        return "known_gap"
    if statuses and all(status == "skipped" for status in statuses):
        return "skipped"
    return "pass"


def counts(items):
    result = {"total": len(items), "pass": 0, "known_gap": 0, "fail": 0, "skipped": 0}
    for item in items:
        result[item["status"]] += 1
    return result


def scenario_id(name):
    match = re.search(r"\[([^\]]+)\]", name)
    return match.group(1) if match else name


def classify(root):
    incidents = {}
    laws = {}
    unlabelled = []
    must_block = []
    negatives = []
    for testcase in root.iter("testcase"):
        classname = testcase.get("classname", "")
        name = testcase.get("name", "")
        status = testcase_status(testcase)
        lower_class = classname.lower()
        lower_name = name.lower()
        if lower_class.endswith("test_incidents") or lower_class.endswith("test_phase_d_scenarios"):
            if "test_incident_scenario" in lower_name or "test_phase_d_scenario" in lower_name:
                key = scenario_id(name)
                incidents.setdefault(key, []).append(status)
        elif "pathfinding" in lower_class or "pathfinding" in lower_name:
            if "requires_every_action" in lower_name or "without-" in lower_name:
                negatives.append({"id": scenario_id(name), "status": status})
            elif "path_is_blocked" in lower_name:
                must_block.append({"id": scenario_id(name), "status": status})
        elif "/laws/" in lower_class or ".laws." in lower_class or lower_class.endswith("laws"):
            match = re.search(r"test_[lL](\d+)", name)
            if match:
                laws.setdefault("L" + str(int(match.group(1))), []).append(status)
            else:
                unlabelled.append({"id": name, "status": status})

    incident_items = [{"id": key, "status": aggregate(values)} for key, values in sorted(incidents.items())]
    law_items = [{"id": key, "status": aggregate(values)} for key, values in sorted(laws.items(), key=lambda pair: int(pair[0][1:]))]
    must_counts = counts(must_block)
    negative_counts = counts(negatives)
    incident_counts = counts(incident_items)
    law_counts = counts(law_items)
    counted_groups = (incident_counts, must_counts, negative_counts, law_counts)
    totals = {
        status: sum(group[status] for group in counted_groups)
        for status in ("pass", "known_gap", "fail", "skipped")
    }
    headline = (
        f"{incident_counts['total']} locked scenarios, "
        f"{must_counts['total']} escalation paths (+{negative_counts['total']} one-action-removed negatives), "
        f"{law_counts['total']} laws: {totals['pass']} pass, {totals['known_gap']} known gaps, {totals['fail']} fail"
    )
    if totals["skipped"] > 0:
        headline += f", {totals['skipped']} skipped"
    categories = {
        "incidents": {**incident_counts, "items": incident_items},
        "escalation_paths": {
            "must_block": {**must_counts, "items": must_block},
            "negatives": {**negative_counts, "items": negatives},
        },
        "laws": {**law_counts, "items": law_items, "unlabelled": unlabelled},
        "scanners": {"status": "not_run", "reason": "native rules only (EMFIRGE_RUN_SCANNERS off)"},
    }
    return headline, categories


def markdown(headline, categories):
    lines = [f"# {headline}", "", "## Locked scenarios", "", "| ID | Status |", "|---|---|"]
    lines += [f"| {item['id']} | {item['status']} |" for item in categories["incidents"]["items"]]
    lines += ["", "## Escalation paths", "", "| Group | Total | Pass | Known gaps | Fail | Skipped |", "|---|---:|---:|---:|---:|---:|"]
    for key, label in (("must_block", "Must block"), ("negatives", "Negatives")):
        item = categories["escalation_paths"][key]
        lines.append(f"| {label} | {item['total']} | {item['pass']} | {item['known_gap']} | {item['fail']} | {item['skipped']} |")
    lines += ["", "## Laws", "", "| ID | Status |", "|---|---|"]
    lines += [f"| {item['id']} | {item['status']} |" for item in categories["laws"]["items"]]
    lines += ["", "## Scanners", "", f"Not run: {categories['scanners']['reason']}"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("junit")
    parser.add_argument("--json", required=True, dest="json_path")
    parser.add_argument("--md", required=True, dest="md_path")
    parser.add_argument("--commit", default=None)
    args = parser.parse_args(argv)
    root = ET.parse(args.junit).getroot()
    headline, categories = classify(root)
    output = {"generated_at": datetime.now(timezone.utc).isoformat(), "commit": args.commit, "headline": headline, "categories": categories}
    with open(args.json_path, "w") as handle:
        json.dump(output, handle, indent=2)
        handle.write("\n")
    with open(args.md_path, "w") as handle:
        handle.write(markdown(headline, categories))
    if any(not categories[key]["items"] for key in ("incidents", "laws")) or any(
        not categories["escalation_paths"][key]["items"] for key in ("must_block", "negatives")
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
