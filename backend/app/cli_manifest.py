"""The command manifest the ``emfirge`` CLI reads: which commands exist, their arguments, and the request each sends.

The CLI is a generic runner. It fetches this document (``GET /cli/manifest``), builds its help from it, parses
arguments by it, and makes the HTTP call it describes. A new command that only needs a request is added HERE and
deployed with the server; nobody has to publish a new npm version. A copy is bundled in the npm package for offline use
and old servers (``mcp/src/cli/bundled-manifest.json``, written by ``scripts/export_cli_manifest.py``).

Public and static: no database, no caller, no customer data. Only command names, help text and path templates.

Shape (protocol 1)::

    {"protocol": 1,
     "groups":   {"branch": "summary of a command group"},            # optional, for the top-level help
     "commands": [{
        "name": "branch open",              # words; the first word is the group
        "summary": "...", "usage": ["emfirge ..."], "examples": ["emfirge ..."],
        "args": [{"name": "analysis", "kind": "flag" | "positional", "type": "string|number|integer|bool|json",
                  "required": bool, "multiple": bool, "id": bool,        # id: may hold a privacy token, expanded first
                  "choices": [...], "pattern": "regex", "min": 0, "help": "..."}],
        "require": ["arg"],                 # args the default mode needs (mode-specific, see variants)
        "request": {"method": "GET|POST", "path": "/branches/{branch}",  # {arg} is filled from that arg, URL-encoded
                    "query": {"param": "arg"}, "body": {"field": "arg"}, "null_unset": bool},
        "client": "key",                    # the CLI runs its own code for this command (needs that key built in)
        "variants": [{"when": "flag", "request": {...} | "client": "key", "require": [...]}],
        "variants_exclusive": bool,         # at most one "when" flag may be given
        "response": {"list_key": "branches"},   # an array answer is printed as {list_key: [...], count: n}
        "human": {"title": "text {field}", "sections": ["key", ...]},   # layout hint for --human
        "requires": ["feature"]}]}          # CLI features the command needs; unknown ones => "needs a newer emfirge"

Protocol rule: ``protocol`` goes up only for a change an older CLI cannot read safely (a changed meaning of an
existing field, not a new command and not a new optional field). An older CLI shows "run npx emfirge@latest" then.
"""
from __future__ import annotations

from typing import Any

PROTOCOL = 1

_CONTEXT_QUESTIONS = ["inventory", "resource", "depends_on", "dependents", "reachable",
                      "access", "data", "cost", "live", "marks", "baseline"]
_HEX64 = "^[0-9a-f]{64}$"


def _flag(name: str, help: str, type: str = "string", **extra: Any) -> dict[str, Any]:
    return {"name": name, "kind": "flag", "type": type, "help": help, **extra}


def _pos(name: str, help: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "kind": "positional", "type": "string", "help": help, **extra}


def _branch_pos() -> dict[str, Any]:
    return _pos("branch", "Branch id.", required=True, id=True)


def _revision(help: str = "branch_revision you last saw; a stale one is rejected.") -> dict[str, Any]:
    return _flag("revision", help, pattern=_HEX64)


def _expected_count() -> dict[str, Any]:
    return _flag("expected-count", "Change count you last saw; a stale one is rejected.", "integer", min=0)


def _build() -> dict[str, Any]:
    commands: list[dict[str, Any]] = [
        {
            "name": "context",
            "summary": "Ask what is true about the cloud. Facts only, with what was checked and what is unknown.",
            "usage": [
                "emfirge context <question> [--analysis ID | --branch ID] [--resource ID]",
                "emfirge context --refresh --role-arn ARN --region REGION",
                "emfirge context --findings|--attack-paths|--compliance --analysis ID",
                "emfirge context --simulate \"what if ...\" --analysis ID",
            ],
            "examples": [
                "emfirge context inventory",
                "emfirge context reachable --branch BRANCH_ID",
                "emfirge context resource --resource S3_001",
            ],
            "args": [
                _pos("question", "What to ask: " + ", ".join(_CONTEXT_QUESTIONS) + ".", choices=_CONTEXT_QUESTIONS),
                _flag("analysis", "Analysis id from a scan (default: your latest)."),
                _flag("branch", "Ask about a branch instead of a scan.", id=True),
                _flag("resource", "Resource id or token (S3_001); needed for resource, depends_on, dependents.", id=True),
                _flag("refresh", "Run a fresh scan (needs --role-arn and --region).", "bool"),
                _flag("role-arn", "IAM role ARN to scan with."),
                _flag("region", "AWS region to scan."),
                _flag("findings", "List scan findings (use --severity to filter).", "bool"),
                _flag("severity", "Critical, Moderate or Low.", choices=["Critical", "Moderate", "Low"]),
                _flag("attack-paths", "Paths from the internet to inside resources.", "bool"),
                _flag("compliance", "CIS AWS 1.5 / SOC 2 status (use --framework to filter).", "bool"),
                _flag("framework", "cis-aws-1.5 or soc2.", choices=["cis-aws-1.5", "soc2"]),
                _flag("simulate", "Walk a what-if kill chain; the value is the question.", id=True),
            ],
            "require": ["question"],
            "request": {
                "method": "POST", "path": "/context", "null_unset": True,
                "body": {"question": "question", "analysis_id": "analysis", "branch_id": "branch", "resource_id": "resource"},
            },
            "variants": [
                {"when": "refresh", "client": "context.refresh", "require": ["role-arn", "region"]},
                {"when": "findings", "client": "context.findings", "require": ["analysis"]},
                {"when": "attack-paths", "client": "context.attack-paths", "require": ["analysis"]},
                {"when": "compliance", "client": "context.compliance", "require": ["analysis"]},
                {"when": "simulate", "client": "context.simulate", "require": ["analysis"]},
            ],
            "variants_exclusive": True,
        },
        {
            "name": "branch open",
            "summary": "Open a branch: a safe copy of a scan. Never touches the cloud.",
            "examples": ["emfirge branch open --analysis ANALYSIS_ID --name close-ssh"],
            "args": [
                _flag("analysis", "Base analysis id.", required=True),
                _flag("name", "Branch name.", required=True),
            ],
            "request": {"method": "POST", "path": "/branches", "body": {"base_analysis_id": "analysis", "name": "name"}},
        },
        {
            "name": "branch fork",
            "summary": "Copy a branch, with its changes, under a new name.",
            "args": [_branch_pos(), _flag("name", "Name of the copy.", required=True), _revision()],
            "request": {"method": "POST", "path": "/branches/{branch}/fork", "body": {"name": "name", "branch_revision": "revision"}},
        },
        {
            "name": "branch list",
            "summary": "List your branches.",
            "examples": ["emfirge branch list"],
            "args": [_flag("analysis", "Only branches of this base analysis.")],
            "request": {"method": "GET", "path": "/branches", "query": {"base_analysis_id": "analysis"}},
            "response": {"list_key": "branches"},
        },
        {
            "name": "branch get",
            "summary": "Read one branch and its ordered changes.",
            "args": [_branch_pos()],
            "request": {"method": "GET", "path": "/branches/{branch}"},
        },
        {
            "name": "branch rollback",
            "summary": "Clear the changes on a branch.",
            "args": [_branch_pos(), _revision(), _expected_count()],
            "request": {"method": "POST", "path": "/branches/{branch}/rollback",
                        "body": {"expected_change_count": "expected-count", "branch_revision": "revision"}},
        },
        {
            "name": "branch rollback-to",
            "summary": "Keep the first N changes on a branch and drop the rest.",
            "args": [_branch_pos(),
                     _flag("count", "Number of leading changes to keep.", "integer", required=True, min=0),
                     _revision()],
            "request": {"method": "POST", "path": "/branches/{branch}/rollback-to-count",
                        "body": {"target_change_count": "count", "branch_revision": "revision"}},
        },
        {
            "name": "branch discard",
            "summary": "Discard a branch.",
            "args": [_branch_pos(), _revision(), _expected_count()],
            "request": {"method": "POST", "path": "/branches/{branch}/discard",
                        "body": {"expected_change_count": "expected-count", "branch_revision": "revision"}},
        },
        {
            "name": "branch compare",
            "summary": "Compare two or more branches.",
            "args": [_pos("branches", "Branch ids to compare.", required=True, multiple=True, id=True)],
            "request": {"method": "POST", "path": "/branches/compare", "body": {"branch_ids": "branches"}},
        },
        {
            "name": "try",
            "summary": "Put a change on a branch. Emfirge models it; it never runs it.",
            "usage": [
                "emfirge try BRANCH --typed JSON",
                "emfirge try BRANCH --aws-cli \"aws ec2 ...\" [--aws-cli \"...\"]",
                "emfirge try BRANCH --aws-api FILE|JSON|-",
                "emfirge try BRANCH --terraform FILE|JSON|-",
                "emfirge try BRANCH --cloudformation FILE|JSON|-",
                "emfirge try --verify-fix --rule RULE --resource ID --analysis ID",
            ],
            "examples": [
                "emfirge try BRANCH_ID --aws-cli \"aws ec2 revoke-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0\"",
                "emfirge try BRANCH_ID --terraform plan.json",
            ],
            # Several inputs (file, stdin, inline JSON), AWS CLI shorthand refusal and a three-request flow
            # (ingest, verdict, hand-back): the CLI keeps its own code for this one.
            "client": "try",
            "args": [
                _pos("branch", "Branch id.", id=True),
                _flag("typed", "One typed change as JSON: {op, resource_type, resource_id, fields}."),
                _flag("aws-cli", "An AWS CLI command (repeat for several), or a JSON list.", multiple=True),
                _flag("aws-api", "AWS API calls JSON: {format:\"aws-api-calls/1\", calls:[...]}."),
                _flag("terraform", "Output of `terraform show -json PLAN`."),
                _flag("cloudformation", "Output of `aws cloudformation describe-change-set`."),
                _flag("verify-fix", "Model the fix for one finding on a copy of a scan (no branch).", "bool"),
                _flag("rule", "Rule id such as EC2-002 (verify-fix)."),
                _flag("resource", "Resource id or token (verify-fix).", id=True),
                _flag("analysis", "Analysis id (verify-fix)."),
            ],
        },
        {
            "name": "check",
            "summary": "Check a branch: what changed, six damage answers, evidence, and unknowns.",
            "usage": [
                "emfirge check BRANCH",
                "emfirge check BRANCH --verdict | --diff",
                "emfirge check BRANCH --policy [--approve --accept-estimate ID]",
                "emfirge check BRANCH --evidence [--source S] [--accept-estimate ID --role-arn ARN]",
            ],
            "examples": ["emfirge check BRANCH_ID", "emfirge check BRANCH_ID --human"],
            "args": [
                _branch_pos(),
                _flag("verdict", "Old pass / warn / block verdict.", "bool"),
                _flag("diff", "Diff against the base scan.", "bool"),
                _flag("policy", "Ask IAM Access Analyzer about changed policies (costs money; shows an estimate first).", "bool"),
                _flag("evidence", "Read CloudTrail / CloudWatch use of deleted resources (shows an estimate first).", "bool"),
                _flag("approve", "With --policy: the owner agreed to the estimate.", "bool"),
                _flag("accept-estimate", "Estimate id the owner agreed to."),
                _flag("source", "With --evidence: cloudtrail_events or cloudwatch_metrics (repeatable).", multiple=True),
                _flag("role-arn", "Same role ARN used for the scan (needed when accepting an estimate)."),
            ],
            "request": {"method": "GET", "path": "/branches/{branch}/check"},
            "variants": [
                {"when": "verdict", "request": {"method": "GET", "path": "/branches/{branch}/verdict"}},
                {"when": "diff", "request": {"method": "GET", "path": "/branches/{branch}/diff"}},
                {"when": "policy", "client": "check.policy"},
                {"when": "evidence", "client": "check.evidence"},
            ],
        },
        {
            "name": "report",
            "summary": "Say what you applied. For now: returns the hand-back for the branch or plan.",
            "examples": ["emfirge report BRANCH_ID --verify"],
            "args": [
                _branch_pos(),
                _flag("plan", "Hand-back for one plan from `emfirge try`."),
                _flag("verify", "Verify the hand-back with the server.", "bool"),
            ],
            "request": {"method": "GET", "path": "/branches/{branch}/handback"},
            "variants": [
                {"when": "plan", "request": {"method": "GET", "path": "/branches/{branch}/plans/{plan}/handback"}},
                {"when": "verify", "client": "report.verify"},
            ],
        },
    ]
    return {
        "protocol": PROTOCOL,
        "groups": {"branch": "Open and manage a branch: a safe copy of the cloud model. Never touches the cloud."},
        "commands": commands,
    }


def build_manifest() -> dict[str, Any]:
    """A fresh copy every call; the content is a pure function of this file."""
    return _build()
