#!/usr/bin/env python3
"""Grade Emfirge's results from realworld_eval.py against the locked answer keys.

Written and committed BEFORE any per-entry result was looked at. The rules below are the contract.

Inputs: the results JSON from realworld_eval.py and tests/data/realworld/answer_keys.json
(its sha256 must match LOCK.json, otherwise the grader refuses to run).

Per entry (project/scenario -> results key "terragoat" or "cloudgoat/<scenario>"):

1. Resolve the entry's Terraform resource(s) to plan addresses (exact, or `address[...]` for
   count/for_each). Resources are `resource` plus, for attack_path entries, every `path_resources`.
2. A resource is READABLE when its address is in ingest.address_to_emfirge_ids (translate_plan
   produced a change AND apply_change accepted it). Otherwise it is UNREADABLE, with a reason:
   rejected (the apply_change error), unmodeled (the type translate_plan reports), or not_in_plan.
3. misconfiguration: UNREADABLE -> `missed_ingest`. Otherwise `caught` when any evidence item
   (below) on one of the resource's Emfirge ids matches the entry's category in CATEGORY_EVIDENCE,
   else `missed_logic`.
4. attack_path: a chain, so EVERY path resource must be readable, else `missed_ingest` (reasons for
   each unreadable one; any evidence found on the readable ones is still listed as partial_evidence).
   When all are readable: `caught` when graph-level evidence (exposure, internet-reachable mark,
   escalation role) exists on any path resource, or category evidence from ATTACK_PATH_CATEGORIES
   exists on at least two distinct path resources; else `missed_logic`.
5. negative: the stated thing is "reachable/exposed": evidence of category `network` (which includes
   exposures and internet-reachable marks) on the resource. No such evidence -> `negative_correct`
   (flagged vacuous when the resource was unreadable, so Emfirge could not have said anything),
   evidence -> `negative_violated`.

Evidence items on a resource id (all taken from the harness results):
  native    native_findings[] with that resource_id; matched by regex on the finding's `issue`
  scanner   verdict.scanner_added[] (checkov/cloudsplaining; base is empty so added == all) with
            that resource; matched by regex on `title`
  exposure  exposures[] with that resource_id
  reachable resource id in internet_reachable
  escalation resource id in roles_with_privilege_escalation

Clean set: every Critical/High native finding, Critical/High scanner finding, and every `block`
reason in the verdict is listed as a false alarm candidate. Native findings whose resource_id is
not a mapped Emfirge id of that target are account-level findings produced by the empty base
(CloudTrail, GuardDuty, Config, CloudWatch alarms, budgets, root account, "all-buckets"...); they
are EXCLUDED and listed with that reason. Block reasons are split into security findings
(introduced_critical_finding / introduced_critical_exposure / privilege_escalation) and
ingest-coverage blocks (unmodeled/unseen/rejected), which are reported separately.

Outputs: a scored JSON and a Markdown scorecard. Nothing here changes app code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
DATA = BACKEND / "tests" / "data" / "realworld"

# ---------------------------------------------------------------------------
# The one explicit category -> evidence table.
#   native:  regex on the native finding's `issue` text
#   scanner: regex on the scanner finding's `title`
#   graph:   which graph-level evidence counts (exposure | reachable | escalation)
# ---------------------------------------------------------------------------
CATEGORY_EVIDENCE: dict[str, dict] = {
    "public_exposure": {
        "native": r"open to the (entire )?internet|publicly accessible|public s3|allows inbound traffic from the internet|internet-reachable",
        "scanner": r"public|0\.0\.0\.0|open to the world|ingress from|publicly",
        "graph": ["exposure", "reachable"],
    },
    "network": {
        "native": r"security group|open to the internet|nacl|peering|vpc|flow logs|reachable",
        "scanner": r"security group|ingress|egress|vpc|nacl|route|peering|flow",
        "graph": ["exposure", "reachable"],
    },
    "encryption": {
        "native": r"encrypt|rotation",
        "scanner": r"encrypt|kms|cmk|rotation",
        "graph": [],
    },
    "logging": {
        "native": r"logging|log exports|flow logs|cloudtrail|log file validation|cloudwatch",
        "scanner": r"logging|\blogs?\b|trail|flow",
        "graph": [],
    },
    "data_protection": {
        "native": r"versioning|backup|deletion protection|multi-az",
        "scanner": r"versioning|backup|deletion protection|mfa delete|lifecycle|replication",
        "graph": [],
    },
    "secrets_exposure": {
        "native": r"secret|credential|access key",
        "scanner": r"secret|credential|hard-?coded|user data|environment variable|access key",
        "graph": [],
    },
    "imds": {
        "native": r"imdsv1|metadata",
        "scanner": r"imds|metadata",
        "graph": [],
    },
    "iam_escalation": {
        "native": r"escalate privileges|full admin|admin iam permissions|outside principal|wildcard",
        "scanner": r"privilege escalation|passrole|permissions management|iam.*(\*|admin|wildcard|full)|assume role",
        "graph": ["escalation"],
    },
    "data_exposure": {
        "native": r"broad data access|public s3|publicly accessible|snapshot|secret",
        "scanner": r"public|snapshot|secret",
        "graph": ["exposure", "reachable"],
    },
}
ATTACK_PATH_CATEGORIES = ["public_exposure", "iam_escalation", "data_exposure", "network", "imds", "secrets_exposure"]
HIGH_SEVERITIES = {"critical", "high"}
SECURITY_BLOCK_CODES = {"introduced_critical_finding", "introduced_critical_exposure", "privilege_escalation"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def result_key(entry: dict) -> str:
    return "terragoat" if entry["project"] == "terragoat" else f"cloudgoat/{entry['scenario']}"


class Target:
    """Everything the grader needs from one scenario's results."""

    def __init__(self, name: str, data: dict):
        self.name, self.data = name, data
        em = data.get("emfirge") or {}
        self.status = data.get("status")
        self.ingest = em.get("ingest") or {}
        self.addr_ids: dict[str, list[str]] = self.ingest.get("address_to_emfirge_ids", {})
        self.rejected = {r["address"]: r for r in self.ingest.get("rejected", [])}
        self.unmodeled = {u["address"]: u for u in self.ingest.get("unmodeled", [])}
        self.native = em.get("native_findings", [])
        self.scanner = (em.get("verdict") or {}).get("scanner_added", [])
        self.exposures = em.get("exposures", [])
        self.reachable = set(em.get("internet_reachable", []))
        self.escalating = set(em.get("roles_with_privilege_escalation", []))
        self.reasons = (em.get("verdict") or {}).get("reasons", [])
        self.verdict = (em.get("verdict") or {}).get("verdict")
        self.mapped_ids = {i.split(":", 1)[1] for ids in self.addr_ids.values() for i in ids}

    def addresses_for(self, resource: str) -> list[str]:
        keys = set(self.addr_ids) | set(self.rejected) | set(self.unmodeled)
        return sorted(a for a in keys if a == resource or a.startswith(resource + "["))

    def resource_state(self, resource: str) -> tuple[bool, list[str], str]:
        """(readable, emfirge ids, reason)."""
        addrs = self.addresses_for(resource)
        ids = sorted({i.split(":", 1)[1] for a in addrs for i in self.addr_ids.get(a, [])})
        if ids:
            return True, ids, "mapped"
        for a in addrs:
            if a in self.rejected:
                r = self.rejected[a]
                return False, [], f"rejected: {r['resource_type']}: {r['error'][:120]}"
            if a in self.unmodeled:
                return False, [], f"unmodeled: {self.unmodeled[a]['type']}"
        if self.status != "planned":
            return False, [], f"no plan ({self.status})"
        return False, [], "not_in_plan"

    def evidence(self, ids: set[str], category: str) -> list[dict]:
        spec = CATEGORY_EVIDENCE[category]
        out = []
        for f in self.native:
            if f.get("resource_id") in ids and re.search(spec["native"], f.get("issue") or "", re.I):
                out.append({"kind": "native", "id": f.get("rule_id"), "resource": f["resource_id"], "text": f.get("issue")})
        for f in self.scanner:
            if f.get("resource") in ids and re.search(spec["scanner"], f.get("title") or "", re.I):
                out.append({"kind": "scanner", "id": f.get("check_id"), "resource": f["resource"], "text": f.get("title")})
        if "exposure" in spec["graph"]:
            for e in self.exposures:
                if e.get("resource_id") in ids:
                    out.append({"kind": "exposure", "id": f"{e.get('protocol')}/{e.get('from_port')}-{e.get('to_port')}", "resource": e["resource_id"], "text": e.get("source")})
        if "reachable" in spec["graph"]:
            out += [{"kind": "reachable", "id": "internet_reachable", "resource": i, "text": ""} for i in sorted(ids & self.reachable)]
        if "escalation" in spec["graph"]:
            out += [{"kind": "escalation", "id": "role_escalation", "resource": i, "text": ""} for i in sorted(ids & self.escalating)]
        return out


def grade_entry(entry: dict, t: Target | None) -> dict:
    res = {"id": entry["id"], "project": entry["project"], "scenario": entry["scenario"], "resource": entry["resource"],
           "category": entry["category"], "kind": entry["kind"]}
    if t is None or t.status != "planned":
        res.update(status="missed_ingest", reasons=[f"no plan ({t.status if t else 'no result'})"])
        return res
    resources = entry.get("path_resources") if entry["kind"] == "attack_path" else [entry["resource"]]
    states = {r: t.resource_state(r) for r in resources}
    unreadable = {r: s[2] for r, s in states.items() if not s[0]}
    all_ids = {i for s in states.values() for i in s[1]}
    res["resource_states"] = {r: {"readable": s[0], "ids": s[1], "reason": s[2]} for r, s in states.items()}

    if entry["kind"] == "negative":
        ev = t.evidence(all_ids, "network") if all_ids else []
        res["evidence"] = ev
        res["status"] = "negative_violated" if ev else "negative_correct"
        res["vacuous"] = not all_ids
        if not all_ids:
            res["reasons"] = list(unreadable.values())
        return res

    if entry["kind"] == "attack_path":
        partial = [e for c in ATTACK_PATH_CATEGORIES for e in t.evidence(all_ids, c)] if all_ids else []
        if unreadable:
            res.update(status="missed_ingest", reasons=[f"{r}: {why}" for r, why in unreadable.items()], partial_evidence=partial)
            return res
        graph = [e for e in partial if e["kind"] in {"exposure", "reachable", "escalation"}]
        cat_resources = {e["resource"] for e in partial}
        if graph or len(cat_resources) >= 2:
            res.update(status="caught", evidence=partial)
        else:
            res.update(status="missed_logic", evidence=partial)
        return res

    if unreadable:
        res.update(status="missed_ingest", reasons=list(unreadable.values()))
        return res
    cat = entry["category"]
    if cat not in CATEGORY_EVIDENCE:
        res.update(status="missed_logic", reasons=[f"category {cat} has no evidence mapping"])
        return res
    ev = t.evidence(all_ids, cat)
    res.update(status="caught" if ev else "missed_logic", evidence=ev)
    return res


def grade_clean(name: str, t: Target | None) -> dict:
    out: dict = {"target": name}
    if t is None or t.status != "planned":
        out["status"] = t.status if t else "no result"
        return out
    out["verdict"] = t.verdict
    fa, excluded = [], []
    for f in t.native:
        if (f.get("severity") or "").lower() not in HIGH_SEVERITIES:
            continue
        item = {"source": "native", "id": f.get("rule_id"), "resource": f.get("resource_id"), "severity": f.get("severity"), "text": f.get("issue")}
        if f.get("resource_id") in t.mapped_ids:
            fa.append(item)
        else:
            excluded.append({**item, "excluded_because": "account-level finding from the empty base (resource id is not a mapped plan resource)"})
    for f in t.scanner:
        if (f.get("severity") or "").lower() in HIGH_SEVERITIES:
            fa.append({"source": f.get("source"), "id": f.get("check_id"), "resource": f.get("resource"), "severity": f.get("severity"), "text": f.get("title")})
    blocks = [r for r in t.reasons if r.get("level") == "block"]
    out["false_alarms"] = fa
    out["excluded_account_level"] = excluded
    out["block_reasons_security"] = [r for r in blocks if r.get("code") in SECURITY_BLOCK_CODES]
    out["block_reasons_coverage"] = [r for r in blocks if r.get("code") not in SECURITY_BLOCK_CODES]
    return out


def fix_candidates(graded: list[dict]) -> list[dict]:
    """For each ingest-failure reason: entries it touches, and entries it alone blocks."""
    touch, sole = defaultdict(set), defaultdict(set)
    for g in graded:
        if g["status"] != "missed_ingest":
            continue
        if g["kind"] == "attack_path":
            reasons = {re.sub(r"^[^:]+: ", "", r) for r in g["reasons"]}
        else:
            reasons = set(g["reasons"])
        reasons = {_short(r) for r in reasons}
        for r in reasons:
            touch[r].add(g["id"])
        if len(reasons) == 1:
            sole[next(iter(reasons))].add(g["id"])
    rows = [{"reason": r, "entries_touched": len(ids), "entries_fully_unblocked_alone": len(sole.get(r, ()))} for r, ids in touch.items()]
    return sorted(rows, key=lambda x: (-x["entries_fully_unblocked_alone"], -x["entries_touched"], x["reason"]))


def _short(reason: str) -> str:
    if reason.startswith("unmodeled: "):
        return reason
    if reason.startswith("rejected: "):
        m = re.match(r"rejected: (\w+): (?:\w+: )?(.*)", reason)
        return f"rejected {m.group(1)}: {m.group(2)[:60]}" if m else reason
    return reason


def render(scored: dict) -> str:
    g = scored["graded"]
    c = Counter(x["status"] for x in g)
    non_neg = [x for x in g if x["kind"] != "negative"]
    lines = ["# Real-world evaluation scorecard", "",
             f"Answer keys sha256 `{scored['answer_keys_sha256']}` (locked). Results: terraform {scored['terraform_version']}, "
             f"scanners {'on' if scored['scanners_on'] else 'off'}. Grading rules are in the docstring of `backend/scripts/realworld_score.py`.", "",
             "## Totals", "", f"- Entries: {len(g)} ({len(non_neg)} misconfiguration/attack_path, {len(g) - len(non_neg)} negative)",
             f"- caught: **{c['caught']}** / {len(non_neg)}",
             f"- missed_ingest: **{c['missed_ingest']}** (Emfirge could not read the resource)",
             f"- missed_logic: **{c['missed_logic']}** (resource read, no matching evidence)",
             f"- negatives correct: **{c['negative_correct']}** of {c['negative_correct'] + c['negative_violated']}"
             f" ({sum(1 for x in g if x.get('vacuous'))} vacuous because the resource was unreadable)", ""]

    def table(title, key, rows_key=None):
        lines.extend([f"## {title}", "", f"| {key} | entries | caught | missed_ingest | missed_logic | negative ok |", "|---|---|---|---|---|---|"])
        groups = defaultdict(Counter)
        for x in g:
            groups[x[key] if key != "scenario" else f"{x['project']}/{x['scenario']}"][x["status"]] += 1
        for k in sorted(groups):
            s = groups[k]
            lines.append(f"| {k} | {sum(s.values())} | {s['caught']} | {s['missed_ingest']} | {s['missed_logic']} | {s['negative_correct']}/{s['negative_correct'] + s['negative_violated']} |")
        lines.append("")

    table("Per scenario", "scenario")
    table("Per category", "category")

    lines += ["## Clean set (false alarms)", ""]
    for cl in scored["clean"]:
        if "false_alarms" not in cl:
            lines += [f"- {cl['target']}: not graded ({cl.get('status')})"]
            continue
        lines.append(f"### {cl['target']} (verdict: {cl['verdict']})")
        lines.append(f"- Critical/High false alarms: {len(cl['false_alarms'])}")
        for f in cl["false_alarms"]:
            lines.append(f"  - [{f['source']}] {f['id']} {f['severity']} on `{f['resource']}`: {f['text']}")
        lines.append(f"- Block reasons from security findings: {len(cl['block_reasons_security'])}")
        for r in cl["block_reasons_security"]:
            lines.append(f"  - {r['code']}: {r['message']} ({', '.join(r.get('resources', []))[:200]})")
        lines.append(f"- Block reasons from ingest coverage (not security findings): {len(cl['block_reasons_coverage'])}")
        for r in cl["block_reasons_coverage"]:
            lines.append(f"  - {r['code']}: {r['message']}")
        ex = Counter((f["id"], f["resource"]) for f in cl["excluded_account_level"])
        lines.append(f"- Excluded account-level Critical/High findings (empty-base artifacts): {sum(ex.values())}" + (": " + "; ".join(f"{i} on {r}" for (i, r) in sorted(ex, key=str)) if ex else ""))
        lines.append("")

    lines += ["## Why entries were missed", "", "### Ingest failures (missed_ingest) by reason", "",
              "| reason | entries touched | entries it alone blocks |", "|---|---|---|"]
    for r in scored["fix_candidates"]:
        lines.append(f"| {r['reason']} | {r['entries_touched']} | {r['entries_fully_unblocked_alone']} |")
    ml = [x for x in g if x["status"] == "missed_logic"]
    lines += ["", f"### missed_logic ({len(ml)})", "", "| entry | resource | category |", "|---|---|---|"]
    for x in ml:
        lines.append(f"| {x['id']} | {x['resource']} | {x['category']} |")
    lines += ["", "### Entry detail", "", "| entry | status | evidence / reason |", "|---|---|---|"]
    for x in g:
        d = "; ".join(sorted({f"{e['kind']}:{e['id']}" for e in x.get("evidence", [])})) or "; ".join(x.get("reasons", []))[:160]
        lines.append(f"| {x['id']} | {x['status']} | {d} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--keys", default=str(DATA / "answer_keys.json"))
    ap.add_argument("--lock", default=str(DATA / "LOCK.json"))
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--out-md", default=str(DATA / "SCORECARD.md"))
    a = ap.parse_args()
    keys_path = Path(a.keys)
    lock = json.loads(Path(a.lock).read_text())
    if sha256(keys_path) != lock["answer_keys_sha256"]:
        print("answer_keys.json does not match LOCK.json; refusing to grade", file=sys.stderr)
        return 2
    keys = json.loads(keys_path.read_text())
    results = json.loads(Path(a.results).read_text())
    targets = {k: Target(k, v) for k, v in results["scenarios"].items()}
    graded = [grade_entry(e, targets.get(result_key(e))) for e in keys["entries"]]
    clean = [grade_clean(f"clean/{c['dir'].split('/')[-1]}", targets.get(f"clean/{c['dir'].split('/')[-1]}")) for c in keys["clean_set"]]
    scored = {"answer_keys_sha256": lock["answer_keys_sha256"], "terraform_version": results["terraform_version"],
              "scanners_on": results.get("checkov_available"), "graded": graded, "clean": clean, "fix_candidates": fix_candidates(graded)}
    if a.out_json:
        Path(a.out_json).write_text(json.dumps(scored, indent=2, default=str))
    Path(a.out_md).write_text(render(scored))
    c = Counter(x["status"] for x in graded)
    print(dict(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
