"""Parse AWS CLI command text without executing commands."""
from __future__ import annotations

import functools
import json
import re
import shlex
from typing import Any

import botocore.session
from botocore import xform_name


_GLOBAL_WITH_VALUE = {"--region", "--profile", "--output", "--query", "--color"}
_GLOBAL_FLAGS = {"--no-cli-pager", "--no-paginate", "--debug"}
_ENDPOINT_FLAGS = {"--endpoint-url", "--no-verify-ssl", "--ca-bundle"}
_OPERATORS = {"|", "||", "&", "&&", ";", ">", ">>", "<", "(", ")"}


@functools.lru_cache(maxsize=None)
def _service_model(name: str):
    try:
        return botocore.session.get_session().get_service_model(name)
    except Exception as exc:
        raise ValueError(f"Unknown AWS service: {name}") from exc


@functools.lru_cache(maxsize=None)
def _operations(name: str) -> dict[str, str]:
    model = _service_model(name)
    return {xform_name(operation, '-') : operation for operation in model.operation_names}


def _has_unquoted_operator(command: str) -> bool:
    quote = None
    escaped = False
    i = 0
    while i < len(command):
        char = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            i += 1
            continue
        if quote:
            if char == quote:
                quote = None
            i += 1
            continue
        if char in {"'", '"'}:
            quote = char
            i += 1
            continue
        if char in "|&;><()":
            return True
        i += 1
    return False


def _file_value(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(("file://", "fileb://", "http://", "https://"))


def _json_value(command_no: int, option: str, value: str) -> Any:
    if _file_value(value):
        raise ValueError(f"Command {command_no}: cannot read files or URLs; pass literal values instead.")
    if not value.startswith(("{", "[")):
        raise ValueError(f"Command {command_no}: {option} uses shorthand syntax, which is not supported yet; pass JSON instead.")
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Command {command_no}: invalid JSON for {option}.") from exc


def _s3_uri(value: str) -> tuple[str, str] | None:
    if not value.startswith("s3://"):
        return None
    rest = value[5:]
    bucket, _, key = rest.partition("/")
    return bucket, key


def _s3_call(command_no: int, args: list[str]) -> list[dict[str, Any]]:
    if not args:
        raise ValueError(f"Command {command_no}: an s3 subcommand is required.")
    subcommand = args[0]
    positional = [item for item in args[1:] if not item.startswith("--") and not _s3_option_value(args, item)]
    # High-level S3 flags are intentionally ignored; retain only URI operands.
    uris = [_s3_uri(item) for item in args[1:] if _s3_uri(item)]
    if subcommand == "rb":
        if not uris:
            raise ValueError(f"Command {command_no}: s3 rb requires an s3 URI.")
        bucket, _ = uris[0]
        calls = [{"service": "s3", "operation": "DeleteBucket", "parameters": {"Bucket": bucket}}]
        if "--force" in args:
            calls.append({"service": "s3", "operation": "DeleteObjects", "parameters": {"Bucket": bucket}})
        return calls
    if subcommand == "rm":
        if not uris:
            raise ValueError(f"Command {command_no}: s3 rm requires an s3 URI.")
        bucket, key = uris[0]
        if "--recursive" in args:
            return [{"service": "s3", "operation": "DeleteObjects", "parameters": {"Bucket": bucket}}]
        if not key:
            raise ValueError(f"Command {command_no}: s3 rm requires an object key.")
        return [{"service": "s3", "operation": "DeleteObject", "parameters": {"Bucket": bucket, "Key": key}}]
    if subcommand == "mb":
        if not uris:
            raise ValueError(f"Command {command_no}: s3 mb requires an s3 URI.")
        return [{"service": "s3", "operation": "CreateBucket", "parameters": {"Bucket": uris[0][0]}}]
    if subcommand in {"cp", "sync", "mv"}:
        if len(uris) < 1:
            raise ValueError(f"Command {command_no}: s3 {subcommand} requires an s3 destination.")
        destination = uris[-1]
        calls = [{"service": "s3", "operation": "PutObject", "parameters": {"Bucket": destination[0]}}]
        if subcommand == "mv" and len(uris) >= 2:
            source = uris[-2]
            if source[1]:
                calls.append({"service": "s3", "operation": "DeleteObject", "parameters": {"Bucket": source[0], "Key": source[1]}})
        return calls
    if subcommand == "ls":
        params = {"Bucket": uris[0][0]} if uris else {}
        return [{"service": "s3", "operation": "ListObjectsV2", "parameters": params}]
    if subcommand == "presign":
        params = {}
        if uris:
            params = {"Bucket": uris[0][0]}
            if uris[0][1]: params["Key"] = uris[0][1]
        return [{"service": "s3", "operation": "GetObject", "parameters": params}]
    raise ValueError(f"Command {command_no}: unsupported s3 subcommand: {subcommand}")


def _s3_option_value(args: list[str], item: str) -> bool:
    # Kept deliberately conservative: values which are not URI operands are ignored.
    return item.startswith("-")


def _convert_scalar(command_no: int, option: str, value: str, shape: Any) -> Any:
    if _file_value(value):
        raise ValueError(f"Command {command_no}: cannot read files or URLs; pass literal values instead.")
    kind = shape.type_name
    try:
        if kind in {"string", "timestamp", "blob"}: return str(value)
        if kind in {"integer", "long"}: return int(value)
        if kind in {"float", "double"}: return float(value)
    except ValueError as exc:
        raise ValueError(f"Command {command_no}: invalid value for {option}.") from exc
    return value


def _parse_command(command: str, command_no: int) -> list[dict[str, Any]]:
    command = re.sub(r"\\\r?\n", "", command)
    if "$(" in command or "`" in command:
        raise ValueError(f"Command {command_no}: shell operators are not supported; send one aws command per entry.")
    if _has_unquoted_operator(command):
        raise ValueError(f"Command {command_no}: shell operators are not supported; send one aws command per entry.")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        if "shell operators" in str(exc): raise
        raise ValueError(f"Command {command_no}: invalid shell quoting.") from exc
    if not tokens or tokens[0] != "aws":
        raise ValueError(f"Command {command_no}: command must start with aws.")
    if len(tokens) < 3:
        raise ValueError(f"Command {command_no}: service and operation are required.")
    # Strip global options while locating service/operation; region is retained per call.
    region = None
    core: list[str] = ["aws"]
    i = 1
    while i < len(tokens):
        token = tokens[i]
        name, eq, value = token.partition("=")
        if name in _ENDPOINT_FLAGS:
            raise ValueError(f"Command {command_no}: points the command at a different endpoint")
        if name == "--region":
            if not eq:
                i += 1
                if i >= len(tokens): raise ValueError(f"Command {command_no}: --region requires a value.")
                value = tokens[i]
            region = value
        elif name in _GLOBAL_WITH_VALUE:
            if not eq: i += 1
        elif name in _GLOBAL_FLAGS:
            pass
        else:
            core.append(token)
        i += 1
    if len(core) < 3:
        raise ValueError(f"Command {command_no}: service and operation are required.")
    service_token, operation_token = core[1], core[2]
    if service_token == "s3":
        calls = _s3_call(command_no, core[2:])
        if region:
            for call in calls: call["region"] = region
        return calls
    service = {"s3api": "s3", "configservice": "config", "deploy": "codedeploy"}.get(service_token, service_token)
    operations = _operations(service)
    operation = operations.get(operation_token)
    if operation is None or operation_token in {"wait", "help"}:
        raise ValueError(f"Command {command_no}: unknown AWS operation: {operation_token}")
    model = _service_model(service)
    shape = model.operation_model(operation).input_shape
    members = shape.members if shape else {}
    by_cli = {xform_name(name, '-'): (name, member) for name, member in members.items()}
    params: dict[str, Any] = {}
    explicit: set[str] = set()
    i = 3
    while i < len(core):
        token = core[i]
        if not token.startswith("--"):
            raise ValueError(f"Command {command_no}: stray positional argument: {token}")
        raw_name, eq, value = token[2:].partition("=")
        negative = raw_name.startswith("no-")
        lookup = raw_name[3:] if negative else raw_name
        if lookup == "cli-input-json":
            if not eq:
                i += 1
                if i >= len(core): raise ValueError(f"Command {command_no}: --cli-input-json requires a value.")
                value = core[i]
            loaded = _json_value(command_no, "--cli-input-json", value)
            if not isinstance(loaded, dict): raise ValueError(f"Command {command_no}: --cli-input-json must be a JSON object.")
            for key, item in loaded.items():
                if _file_value(item):
                    raise ValueError(f"Command {command_no}: cannot read files or URLs; pass literal values instead.")
                params.setdefault(key, item)
            i += 1; continue
        if lookup not in by_cli:
            raise ValueError(f"Command {command_no}: unknown option --{raw_name}")
        member_name, member = by_cli[lookup]
        if member_name in explicit: raise ValueError(f"Command {command_no}: duplicate option --{lookup}")
        explicit.add(member_name)
        if member.type_name == "boolean":
            if eq: raise ValueError(f"Command {command_no}: boolean option --{lookup} takes no value")
            params[member_name] = not negative
            i += 1; continue
        if negative: raise ValueError(f"Command {command_no}: invalid boolean option --no-{lookup}")
        if not eq:
            i += 1
            if i >= len(core): raise ValueError(f"Command {command_no}: --{lookup} requires a value")
            value = core[i]
        if member.type_name in {"structure", "map"} or (member.type_name == "list" and member.member.type_name in {"structure", "map"}):
            params[member_name] = _json_value(command_no, f"--{lookup}", value)
        elif member.type_name == "list":
            values = [value]
            while i + 1 < len(core) and not core[i + 1].startswith("--"):
                i += 1; values.append(core[i])
            params[member_name] = [_convert_scalar(command_no, f"--{lookup}", item, member.member) for item in values]
        else:
            params[member_name] = _convert_scalar(command_no, f"--{lookup}", value, member)
        i += 1
    if region is not None:
        return [{"service": service, "operation": operation, "parameters": params, "region": region}]
    return [{"service": service, "operation": operation, "parameters": params}]


def parse_cli_commands(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("format") != "aws-cli/1":
        raise ValueError("Invalid AWS CLI commands document")
    commands = doc.get("commands")
    if not isinstance(commands, list) or not commands or len(commands) > 200 or any(not isinstance(item, str) or len(item) > 16384 for item in commands):
        raise ValueError("commands must be a non-empty list of strings with at most 200 commands, each at most 16384 characters")
    calls = []
    for index, command in enumerate(commands, 1):
        calls.extend(_parse_command(command, index))
    return {"format": "aws-api-calls/1", "calls": calls}
