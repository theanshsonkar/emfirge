"""L71g privacy-of-logs law: server logs contain no customer identifiers.

Emfirge's privacy promise is that logs hold no AWS account ids, resource ids/ARNs,
bucket/role/user/table/topic/queue names, repo names, customer file paths, PR urls or
emails.  Raw exception text is also banned: botocore, DB and LLM exception messages embed
ARNs, account ids, SQL parameters and prompt text.  Exceptions are logged as
``app.log_safe.safe_exc(e)`` (type name, plus the AWS error code for a ClientError).

Three layers:
  (1) static AST law over every .py in backend/app (every value reaching print()/logger.*
      must be an allowed expression),
  (2) runtime law: run the real AWS collector against moto with planted names and forced
      failures, and assert nothing planted reaches stdout/stderr/logging,
  (3) unit test of safe_exc.
"""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError

from app.log_safe import safe_choice, safe_exc

APP_DIR = Path(__file__).resolve().parents[1] / "app"

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}

# ── allowlist: names/attributes whose VALUE can never identify a customer ─────
# Kept deliberately small.  Anything else (resource ids, names, ARNs, urls, repo names,
# exception objects, request fields) must not be logged.
ALLOWED_NAMES = {
    "rule_id",      # Emfirge rule catalogue id such as EMFIRGE-S3-001; ours, not the customer's
    "severity",     # CRITICAL/HIGH/MEDIUM/LOW enum
    "region",       # AWS region name (us-east-1); a public enum, not an identifier
    "status_code",  # HTTP status code (int)
    "analysis_id",  # internal Emfirge uuid
    "branch_id",    # internal Emfirge uuid
    "plan_id",      # internal Emfirge uuid
    "attempt",      # retry counter (int)
}
# Attribute access (obj.rule_id) is allowed under the same names, whatever the base object.
ALLOWED_ATTRS = ALLOWED_NAMES

# Per-file exceptions, (file name, symbol): too context-specific to allow globally.
ALLOWED_FILE_SYMBOLS = {
    ("main.py", "linked"),             # count of projects linked at startup (int)
    ("demo_seed.py", "env_name"),      # name of an operator env var (e.g. DEMO_ACCOUNT_ID), not its value
    ("scanner_worker.py", "host"),     # the worker's own bind address (deployment config)
    ("scanner_worker.py", "port"),     # the worker's own bind port
    ("scanner_worker.py", "checkov_version"),  # call returning the Checkov library version
}

# Calls whose result is safe regardless of arguments (helpers in log_safe.py, plus the
# aws_collector helper that returns the AWS error code only) or only structure
# (len, type name).
SAFE_CALLS = {"len", "safe_exc", "safe_choice", "get_error_code"}
# Wrappers that are safe iff their argument is.
PASSTHROUGH_CALLS = {"str", "int"}


def _is_log_call(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name) and f.id == "print":
        return "print"
    if isinstance(f, ast.Attribute) and f.attr in LOG_METHODS:
        base = f.value
        root = base.id if isinstance(base, ast.Name) else base.attr if isinstance(base, ast.Attribute) else ""
        if root == "logging" or root.lower().endswith(("logger", "log")):
            return f.attr
    return None


class _Checker:
    def __init__(self, tree: ast.Module, filename: str):
        self.tree = tree
        self.filename = filename
        self.parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent

    def _enclosing_function(self, node):
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    @staticmethod
    def _bindings(scope):
        """(assigned values by name, opaque names bound by params/loops/except/with/imports)."""
        assigned: dict[str, list[ast.AST]] = {}
        opaque: set[str] = set()
        for n in ast.walk(scope):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigned.setdefault(t.id, []).append(n.value)
                    else:
                        opaque.update(x.id for x in ast.walk(t) if isinstance(x, ast.Name))
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name):
                if n.value is not None:
                    assigned.setdefault(n.target.id, []).append(n.value)
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                opaque.update(x.id for x in ast.walk(n.target) if isinstance(x, ast.Name))
            elif isinstance(n, ast.ExceptHandler) and n.name:
                opaque.add(n.name)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                opaque.update(x.id for x in ast.walk(n.optional_vars) if isinstance(x, ast.Name))
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                opaque.update((a.asname or a.name).split(".")[0] for a in n.names)
            elif isinstance(n, ast.NamedExpr):
                opaque.add(n.target.id)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and n is scope:
                a = n.args
                for arg in a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]:
                    opaque.add(arg.arg)
        return assigned, opaque

    def _name_ok(self, name: str, scope, seen: frozenset) -> bool:
        if name in ALLOWED_NAMES or (self.filename, name) in ALLOWED_FILE_SYMBOLS:
            return True
        if name in seen:
            return False
        for sc in (scope, self.tree):
            if sc is None:
                continue
            assigned, opaque = self._bindings(sc)
            if name in opaque:
                return False
            if name in assigned:
                # A local variable is as safe as everything ever assigned to it.
                return all(self.ok(v, scope, seen | {name}) for v in assigned[name])
        return False

    def ok(self, e: ast.AST, scope, seen: frozenset = frozenset()) -> bool:
        if isinstance(e, ast.Constant):
            return isinstance(e.value, (str, int, float, bool, type(None)))
        if isinstance(e, ast.JoinedStr):
            return all(self.ok(v.value, scope, seen) for v in e.values if isinstance(v, ast.FormattedValue))
        if isinstance(e, ast.Name):
            return self._name_ok(e.id, scope, seen)
        if isinstance(e, ast.Attribute):
            if e.attr == "__name__":  # type(X).__name__
                v = e.value
                return isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "type"
            return e.attr in ALLOWED_ATTRS
        if isinstance(e, ast.Call):
            f = e.func
            if isinstance(f, ast.Name):
                if f.id in SAFE_CALLS or (self.filename, f.id) in ALLOWED_FILE_SYMBOLS:
                    return True
                if f.id in PASSTHROUGH_CALLS:
                    return all(self.ok(a, scope, seen) for a in e.args) and not e.keywords
            if isinstance(f, ast.Attribute) and f.attr == "format" and isinstance(f.value, ast.Constant):
                return all(self.ok(a, scope, seen) for a in e.args) and \
                    all(self.ok(k.value, scope, seen) for k in e.keywords)
            return False
        if isinstance(e, ast.IfExp):  # the test only selects between two allowed values
            return self.ok(e.body, scope, seen) and self.ok(e.orelse, scope, seen)
        if isinstance(e, ast.BinOp):  # 'fmt %s' % (a, b), attempt + 1, 'a' + 'b'
            return self.ok(e.left, scope, seen) and self.ok(e.right, scope, seen)
        if isinstance(e, (ast.Tuple, ast.List)):
            return all(self.ok(x, scope, seen) for x in e.elts)
        return False

    def violations(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            kind = _is_log_call(node)
            if kind is None:
                continue
            where = f"{self.filename}:{node.lineno}"
            if kind == "exception":
                yield where, "logger.exception() embeds the traceback text; use logger.error with safe_exc(e)"
                continue
            scope = self._enclosing_function(node)
            for kw in node.keywords:
                if kw.arg == "exc_info" and not (isinstance(kw.value, ast.Constant) and not kw.value.value):
                    yield where, "exc_info logs the traceback text"
            args = list(node.args)
            for a in args:
                inner = a.value if isinstance(a, ast.Starred) else a
                if isinstance(a, ast.Starred) or not self.ok(inner, scope):
                    yield where, f"disallowed logged value: {ast.unparse(a)[:100]}"
            for kw in node.keywords:
                if kw.arg in ("flush", "file", "end", "sep", "exc_info", "stacklevel"):
                    continue
                if not self.ok(kw.value, scope):
                    yield where, f"disallowed logged value ({kw.arg}=): {ast.unparse(kw.value)[:100]}"


def test_L71g_a_every_log_value_is_allowed():
    problems = []
    for path in sorted(APP_DIR.rglob("*.py")):
        rel = path.relative_to(APP_DIR)
        checker = _Checker(ast.parse(path.read_text(), filename=str(path)), path.name)
        problems += [f"app/{rel}:{w.split(':')[1]}: {why}" for w, why in checker.violations()]
    assert not problems, (
        f"{len(problems)} log call(s) may leak customer identifiers (L71g):\n" + "\n".join(problems)
    )


def test_L71g_a2_checker_catches_known_leaks():
    """The law's own checker must reject the classic leak shapes and accept the safe ones."""
    def bad(src):
        return list(_Checker(ast.parse(src), "x.py").violations())

    assert bad("def f(e):\n    print(f'x {e}')")
    assert bad("def f(name):\n    logger.info('x %s', name)")
    assert bad("def f(e):\n    logger.error('x ' + str(e))")
    assert bad("def f():\n    logger.exception('x')")
    assert bad("def f(bucket):\n    print('x {}'.format(bucket))")
    assert bad("def f(e):\n    msg = f'x {e}'\n    print(msg)")
    assert bad("def f(r):\n    log.warning('x', r['Arn'])")
    assert not bad("def f(e):\n    print(f'x {safe_exc(e)} {type(e).__name__} {len(e)}')")
    assert not bad("def f():\n    msg = 'a' if 1 else 'b'\n    print(msg)\n    logger.info('n=%s', 3)")
    assert not bad("def f(r):\n    logger.info('x %s %s', r.rule_id, severity)")


# ── (3) safe_exc ──────────────────────────────────────────────────────────────

def test_L71g_c_safe_exc_client_error_has_only_class_and_code():
    err = ClientError(
        {"Error": {"Code": "AccessDenied",
                   "Message": "User arn:aws:iam::123456789012:user/planted-user-zq7 is not authorized "
                              "on plantedbucket-zq7"}},
        "GetBucketEncryption",
    )
    out = safe_exc(err)
    assert out == "ClientError(AccessDenied)"
    for leak in ("123456789012", "planted", "arn:", "GetBucketEncryption", "not authorized"):
        assert leak not in out


def test_L71g_c_safe_exc_other_exceptions_are_type_name_only():
    assert safe_exc(ValueError("secret prompt text plantedbucket-zq7")) == "ValueError"
    assert safe_exc(KeyError("arn:aws:s3:::plantedbucket-zq7")) == "KeyError"


def test_L71g_c_safe_exc_rejects_hostile_error_codes():
    err = ClientError({"Error": {"Code": "Bad code with 123456789012 and spaces", "Message": "m"}}, "Op")
    assert safe_exc(err) == "ClientError(Unknown)"
    assert safe_exc(ClientError({}, "Op")) == "ClientError(Unknown)"


def test_L71g_c_safe_choice_only_passes_known_labels():
    assert safe_choice("s3", {"s3", "ec2"}) == "s3"
    assert safe_choice("plantedbucket-zq7", {"s3", "ec2"}) == "unknown"


# ── (2) runtime law against moto ──────────────────────────────────────────────

PLANTED = [
    "plantedbucket-zq7", "planted-user-zq7", "planted-role-zq7", "planted-table-zq7",
    "planted-queue-zq7", "planted-topic-zq7", "planted-fn-zq7", "planted-key-zq7",
    "123456789012",
]
SNEAKY = "plantedbucket-zq7 arn:aws:iam::123456789012:user/planted-user-zq7"


def _plant(region="us-east-1"):
    kw = {"region_name": region}
    s3 = boto3.client("s3", **kw)
    s3.create_bucket(Bucket="plantedbucket-zq7")
    iam = boto3.client("iam", **kw)
    iam.create_user(UserName="planted-user-zq7")
    iam.create_access_key(UserName="planted-user-zq7")
    iam.put_user_policy(UserName="planted-user-zq7", PolicyName="planted-pol-zq7",
                        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}')
    iam.create_role(RoleName="planted-role-zq7", AssumeRolePolicyDocument=(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},'
        '"Action":"sts:AssumeRole"}]}'))
    boto3.client("dynamodb", **kw).create_table(
        TableName="planted-table-zq7", BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}])
    boto3.client("sqs", **kw).create_queue(QueueName="planted-queue-zq7")
    boto3.client("sns", **kw).create_topic(Name="planted-topic-zq7")
    boto3.client("kms", **kw).create_key(Description="planted-key-zq7")
    ec2 = boto3.client("ec2", **kw)
    ec2.create_vpc(CidrBlock="10.77.0.0/16")


# Per-resource operations to break (all collectors use these through botocore).
FAIL_OPS = {
    "GetBucketAcl", "GetBucketEncryption", "GetBucketVersioning", "GetBucketLogging", "GetBucketPolicy",
    "GetBucketTagging", "GetPublicAccessBlock", "ListObjectsV2",
    "ListMFADevices", "ListAccessKeys", "ListAttachedUserPolicies", "ListUserPolicies",
    "GetLoginProfile", "ListAttachedRolePolicies", "ListRolePolicies", "GetRolePolicy",
    "GetCredentialReport", "ListInstanceProfiles",
    "GetQueueAttributes", "DescribeTable", "DescribeContinuousBackups", "ListTagsOfResource",
    "GetTopicAttributes", "DescribeFlowLogs", "GetKeyRotationStatus", "DescribeKey", "ListResourceTags",
    "DescribeTaskDefinition", "DescribeNetworkInterfaces", "DescribeLoadBalancers",
}


def _install_failures(monkeypatch, exc_factory, ops):
    from botocore.client import BaseClient

    original = BaseClient._make_api_call

    def patched(self, operation_name, api_params):
        if operation_name in ops:
            raise exc_factory(operation_name)
        return original(self, operation_name, api_params)

    monkeypatch.setattr(BaseClient, "_make_api_call", patched)


def _client_error(op):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": f"{SNEAKY} denied for {op}"}}, op)


def _runtime_error(op):
    return RuntimeError(f"{SNEAKY} exploded in {op}")


@pytest.mark.parametrize("mode", ["healthy", "client_errors", "unexpected_errors", "everything_fails"])
def test_L71g_b_collector_logs_no_customer_identifiers(mode, monkeypatch, capsys, caplog):
    from moto import mock_aws

    for var, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                       ("AWS_SESSION_TOKEN", "testing"), ("AWS_DEFAULT_REGION", "us-east-1")):
        monkeypatch.setenv(var, value)
    from app import aws_collector
    from app.models import AWSCredentials

    monkeypatch.setattr(aws_collector._time_module, "sleep", lambda _s: None)
    with mock_aws():
        _plant()
        if mode == "client_errors":
            _install_failures(monkeypatch, _client_error, FAIL_OPS)
        elif mode == "unexpected_errors":
            _install_failures(monkeypatch, _runtime_error, FAIL_OPS)
        elif mode == "everything_fails":
            # every call except the region-validation STS call
            from botocore.client import BaseClient
            original = BaseClient._make_api_call

            def patched(self, operation_name, api_params):
                if operation_name == "GetCallerIdentity":
                    return original(self, operation_name, api_params)
                if operation_name.startswith(("List", "Get", "Describe")):
                    raise _runtime_error(operation_name) if len(operation_name) % 2 else _client_error(operation_name)
                return original(self, operation_name, api_params)

            monkeypatch.setattr(BaseClient, "_make_api_call", patched)

        creds = AWSCredentials(role_arn="arn:aws:iam::123456789012:role/x", region="us-east-1")
        assumed = {"AccessKeyId": "testing", "SecretAccessKey": "testing", "SessionToken": "testing"}
        capsys.readouterr()
        with caplog.at_level(logging.DEBUG):
            try:
                aws_collector.collect_infrastructure(creds, assumed)
            except AttributeError as exc:
                # Pre-existing, unrelated bug in aws_collector: `from datetime import datetime`
                # shadows `import datetime`, so the final `datetime.datetime.now(...)` raises after
                # every collector has already run and logged.  Not fixed here (log-lines-only change).
                if "datetime" not in str(exc):
                    raise

    captured = capsys.readouterr()
    # Third-party libraries (botocore at DEBUG logs raw request/response bodies) are out of the law's
    # scope: the app never enables DEBUG for them (no basicConfig/setLevel in app/; production root
    # level is WARNING).  Everything else, i.e. the app's own loggers, is checked at DEBUG.
    third_party = ("botocore", "boto3", "urllib3", "moto", "s3transfer", "werkzeug", "responses")
    own = [r for r in caplog.records if not r.name.split(".")[0] in third_party]
    haystack = "\n".join([captured.out, captured.err, *(r.getMessage() for r in own)])
    assert haystack.strip(), "collector produced no log output; the law would be vacuous"
    leaked = [p for p in PLANTED if p in haystack]
    assert not leaked, f"{mode}: planted identifiers reached logs: {leaked}\n{haystack[:3000]}"
    for forbidden in ("arn:aws", "RuntimeError: ", "exploded"):
        assert forbidden not in haystack, f"{mode}: {forbidden!r} reached logs"
