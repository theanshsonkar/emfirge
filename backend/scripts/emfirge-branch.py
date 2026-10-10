#!/usr/bin/env python3
"""Small stdlib-only CLI for Emfirge's modeled branch API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


TIMEOUT_SECONDS = 180


class CLIError(Exception):
    """Expected, user-correctable CLI or API error."""


def _base_url(value: str | None) -> str:
    if not value:
        raise CLIError("set EMFIRGE_BASE_URL or pass --base-url (the API root URL)")
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise CLIError("base URL must be an absolute http(s) API root without query or fragment")
    if parsed.username or parsed.password:
        raise CLIError("credentials must be supplied with EMFIRGE_API_KEY, not embedded in the base URL")
    return value


def _json_body(response_body: bytes, status: int) -> Any:
    try:
        return json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CLIError(f"API returned a non-JSON response (HTTP {status})") from exc


class APIClient:
    def __init__(self, base_url: str, api_key: str | None):
        self.base_url = _base_url(base_url)
        self.api_key = api_key

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return _json_body(response.read(), response.status)
        except HTTPError as exc:
            detail = ""
            try:
                error_body = json.loads(exc.read().decode("utf-8"))
                detail = error_body.get("detail", "") if isinstance(error_body, dict) else ""
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            message = str(detail)[:500] if detail else exc.reason
            raise CLIError(f"API request failed (HTTP {exc.code}): {message}") from None
        except (URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise CLIError(f"API request failed: {reason}") from None


def _fields(args: argparse.Namespace) -> dict[str, Any]:
    if args.fields_file:
        try:
            raw = sys.stdin.read() if args.fields_file == "-" else Path(args.fields_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise CLIError(f"cannot read fields file: {exc}") from None
    else:
        raw = args.fields_json
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CLIError(f"fields must be valid JSON: {exc.msg} at character {exc.pos}") from None
    if not isinstance(result, dict):
        raise CLIError("fields JSON must be an object")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="emfirge-branch",
        description="Create and inspect modeled Emfirge branches. This CLI only calls the Emfirge API.",
    )
    parser.add_argument("--base-url", help="Emfirge API root; defaults to EMFIRGE_BASE_URL")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a branch from a completed scan")
    create.add_argument("--analysis-id", required=True)
    create.add_argument("--name", required=True)

    list_branches = subparsers.add_parser("list", help="list branches and their current change counts")
    list_branches.add_argument("--analysis-id", help="filter by base analysis ID")

    show = subparsers.add_parser("show", help="show branch metadata and its ordered changes")
    show.add_argument("--branch-id", required=True)

    fork = subparsers.add_parser("fork", help="fork an open branch into an independent branch")
    fork.add_argument("--branch-id", required=True)
    fork.add_argument("--name", required=True)
    fork.add_argument("--branch-revision", help="fail if the parent state no longer matches this revision")

    subparsers.add_parser("capabilities", help="show supported branch mutation types and constraints")

    apply = subparsers.add_parser("apply", help="append a modeled change to a branch")
    apply.add_argument("--branch-id", required=True)
    apply.add_argument("--op", required=True)
    apply.add_argument("--resource-type", required=True)
    apply.add_argument("--resource-id", default="")
    apply.add_argument("--expected-count", type=int, help="fail if the branch no longer has this many changes")
    apply.add_argument("--branch-revision", help="fail if the branch state no longer matches this GET /branches revision")
    fields = apply.add_mutually_exclusive_group()
    fields.add_argument("--fields-json", default="{}", help="JSON object of resource fields")
    fields.add_argument("--fields-file", help="read a JSON object from a file, or '-' for stdin")

    for command, help_text in (
        ("diff", "show modeled infrastructure, finding, and dependency changes"),
        ("verdict", "evaluate the modeled branch"),
        ("rollback", "undo the most recent modeled change"),
        ("rollback-to-count", "truncate the ordered change log to an existing count"),
        ("discard", "discard an open branch"),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("--branch-id", required=True)
        if command in {"rollback", "discard"}:
            command_parser.add_argument("--expected-count", type=int,
                                        help="fail if the branch no longer has this many changes")
            command_parser.add_argument("--branch-revision", help="fail if the branch state no longer matches this revision")
        if command == "rollback-to-count":
            command_parser.add_argument("--target-count", type=int, required=True,
                                        help="retain exactly this many leading changes (0 through current count)")
            command_parser.add_argument("--branch-revision", help="fail if the branch state no longer matches this revision")

    compare = subparsers.add_parser("compare", help="compare branches from one or more bases")
    compare.add_argument("branch_ids", nargs="+", metavar="BRANCH_ID")
    return parser


def _run(args: argparse.Namespace, client: APIClient) -> Any:
    if args.command == "create":
        return client.request("POST", "/branches", {
            "base_analysis_id": args.analysis_id,
            "name": args.name,
        })
    if args.command == "list":
        query = "" if not args.analysis_id else "?" + urlencode({"base_analysis_id": args.analysis_id})
        return client.request("GET", f"/branches{query}")
    if args.command == "show":
        return client.request("GET", f"/branches/{quote(args.branch_id, safe='')}")
    if args.command == "fork":
        payload = {"name": args.name}
        if args.branch_revision is not None:
            payload["branch_revision"] = args.branch_revision
        return client.request(
            "POST", f"/branches/{quote(args.branch_id, safe='')}/fork", payload
        )
    if args.command == "capabilities":
        return client.request("GET", "/branches/capabilities")
    if args.command == "apply":
        change = {
            "op": args.op,
            "resource_type": args.resource_type,
            "resource_id": args.resource_id,
            "fields": _fields(args),
        }
        if args.expected_count is not None:
            if args.expected_count < 0:
                raise CLIError("--expected-count must be zero or greater")
            change["expected_change_count"] = args.expected_count
        if args.branch_revision is not None:
            change["branch_revision"] = args.branch_revision
        return client.request("POST", f"/branches/{quote(args.branch_id, safe='')}/changes", change)
    if args.command == "diff":
        return client.request("GET", f"/branches/{quote(args.branch_id, safe='')}/diff")
    if args.command == "verdict":
        return client.request("GET", f"/branches/{quote(args.branch_id, safe='')}/verdict")
    if args.command == "rollback":
        payload = {}
        if args.expected_count is not None:
            if args.expected_count < 0:
                raise CLIError("--expected-count must be zero or greater")
            payload["expected_change_count"] = args.expected_count
        if args.branch_revision is not None:
            payload["branch_revision"] = args.branch_revision
        return client.request("POST", f"/branches/{quote(args.branch_id, safe='')}/rollback", payload)
    if args.command == "rollback-to-count":
        if args.target_count < 0:
            raise CLIError("--target-count must be zero or greater")
        payload = {"target_change_count": args.target_count}
        if args.branch_revision is not None:
            payload["branch_revision"] = args.branch_revision
        return client.request(
            "POST", f"/branches/{quote(args.branch_id, safe='')}/rollback-to-count", payload,
        )
    if args.command == "discard":
        payload = {}
        if args.expected_count is not None:
            if args.expected_count < 0:
                raise CLIError("--expected-count must be zero or greater")
            payload["expected_change_count"] = args.expected_count
        if args.branch_revision is not None:
            payload["branch_revision"] = args.branch_revision
        return client.request("POST", f"/branches/{quote(args.branch_id, safe='')}/discard", payload)
    if args.command == "compare":
        return client.request("POST", "/branches/compare", {"branch_ids": args.branch_ids})
    raise CLIError(f"unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        client = APIClient(
            args.base_url or os.environ.get("EMFIRGE_BASE_URL"),
            os.environ.get("EMFIRGE_API_KEY"),
        )
        result = _run(args, client)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        return 0
    except CLIError as exc:
        sys.stderr.write(f"emfirge-branch: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
