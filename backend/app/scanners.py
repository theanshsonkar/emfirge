"""Adapters for optional infrastructure security scanners."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, List, Optional

from pydantic import BaseModel, Field

from app.models import AWSInfrastructure
import json as _json

from app.serializer import attribute_fields, build_terraform, loss_summary  # noqa: F401 (loss_summary re-exported)


class ScannerFinding(BaseModel):
    source: str = "checkov"
    check_id: str
    resource: str
    severity: str
    title: str
    guideline: Optional[str] = None


class ScanResult(BaseModel):
    scanner: str
    available: bool
    findings: List[ScannerFinding] = Field(default_factory=list)
    error: Optional[str] = None
    # Terraform name -> {"resource_type", "id"} of the Emfirge resource it
    # was serialized from, so findings can be keyed by the Emfirge resource.
    resource_map: dict[str, dict[str, str]] = Field(default_factory=dict)
    # Findings dropped because an attribute the check reads was not collected
    # for that resource: {"check_id", "resource_type", "id", "inputs"}.
    skipped: List[dict[str, Any]] = Field(default_factory=list)


def _text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _frameworks(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise TypeError("Checkov JSON must be an object or list")


def _parse_findings(payload: Any) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    for framework in _frameworks(payload):
        results = framework.get("results")
        if not isinstance(results, dict):
            continue
        failed_checks = results.get("failed_checks")
        if not isinstance(failed_checks, list):
            continue
        for check in failed_checks:
            if not isinstance(check, dict):
                continue
            check_id = _text(check.get("check_id"))
            resource = _text(check.get("resource"))
            title = _text(check.get("check_name"))
            if not check_id or not resource or not title:
                continue
            severity = _text(check.get("severity")) or "UNKNOWN"
            guideline = _text(check.get("guideline"))
            if guideline is None:
                guideline = _text(check.get("guideline_url"))
            findings.append(
                ScannerFinding(
                    check_id=check_id,
                    resource=resource,
                    severity=severity,
                    title=title,
                    guideline=guideline,
                )
            )
    return sorted(
        findings,
        key=lambda finding: (
            finding.check_id,
            finding.resource,
            finding.title,
            finding.severity,
            finding.guideline or "",
        ),
    )


def _unavailable(reason: str) -> ScanResult:
    return ScanResult(scanner="checkov", available=False, findings=[], error=reason)


def _trivy_unavailable(reason: str) -> ScanResult:
    return ScanResult(scanner="trivy", available=False, findings=[], error=reason)


def _trivy_findings(payload: Any) -> list[ScannerFinding]:
    if not isinstance(payload, dict):
        raise TypeError("Trivy JSON must be an object")
    results = payload.get("Results", [])
    if results is None:
        results = []
    if not isinstance(results, list):
        raise TypeError("Trivy Results must be a list")

    findings: list[ScannerFinding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _text(result.get("Target"))
        misconfigurations = result.get("Misconfigurations", [])
        if misconfigurations is None:
            continue
        if not isinstance(misconfigurations, list):
            continue
        for misconfiguration in misconfigurations:
            if not isinstance(misconfiguration, dict):
                continue
            check_id = _text(misconfiguration.get("ID"))
            cause_metadata = misconfiguration.get("CauseMetadata")
            resource = None
            if isinstance(cause_metadata, dict):
                resource = _text(cause_metadata.get("Resource"))
            resource = resource or target
            if not check_id or not resource:
                continue
            severity = _text(misconfiguration.get("Severity")) or "UNKNOWN"
            title = _text(misconfiguration.get("Title")) or ""
            references = misconfiguration.get("References")
            guideline = None
            if isinstance(references, list) and references:
                guideline = _text(references[0])
            findings.append(
                ScannerFinding(
                    source="trivy",
                    check_id=check_id,
                    resource=resource,
                    severity=severity,
                    title=title,
                    guideline=guideline,
                )
            )
    return sorted(
        findings,
        key=lambda finding: (
            finding.check_id,
            finding.resource,
            finding.title,
            finding.severity,
            finding.guideline or "",
        ),
    )


def check_reads() -> dict[str, tuple[str, tuple[str, ...]]]:
    """check_id -> (Terraform type, attributes the check reads), from the crosswalk table."""
    return {
        check_id: (str(row["tf_type"]), tuple(row["reads"]))
        for check_id, row in _crosswalk_rows().items()
        if isinstance(row.get("reads"), list) and row.get("tf_type")
    }


def skip_unknown_input(result: "ScanResult", loss: list[dict[str, Any]]) -> "ScanResult":
    """Drop findings whose checked attribute was omitted as not collected.

    A check that reads an attribute the serializer left out fires on the
    missing value, not on the resource.  Such a finding is removed and listed
    in ``skipped`` so the verdict reports it as not checked.
    """
    if not result.findings:
        return result
    omitted: dict[tuple[str, str], set[str]] = {}
    for entry in loss:
        if entry.get("kind") == "omitted_field" and entry.get("field"):
            omitted.setdefault((entry["resource_type"], entry["id"]), set()).add(entry["field"])
    reads = check_reads()
    kept: list[ScannerFinding] = []
    skipped: list[dict[str, Any]] = []
    for finding in result.findings:
        mapped = result.resource_map.get(finding.resource.rsplit(".", 1)[-1])
        read = reads.get(finding.check_id)
        if mapped is not None and read is not None:
            tf_type, attributes = read
            carried = attribute_fields(tf_type)
            unknown = sorted(
                attribute for attribute in attributes
                if omitted.get((mapped["resource_type"], mapped["id"]), set()) & set(carried.get(attribute, ()))
            )
            if unknown:
                skipped.append({
                    "check_id": finding.check_id, "resource_type": mapped["resource_type"],
                    "id": mapped["id"], "inputs": unknown,
                })
                continue
        kept.append(finding)
    if not skipped:
        return result
    return result.model_copy(update={"findings": kept, "skipped": skipped})


def scanner_loss(infra: AWSInfrastructure) -> list[dict[str, Any]]:
    """What the Terraform given to the scanners omits or synthesizes."""
    return build_terraform(infra).loss


# --------------------------------------------------------------------------
# Scan scope, result cache, worker client
# --------------------------------------------------------------------------

_TF_REF = re.compile(r"\$\{(aws_[a-z0-9_]+)\.([A-Za-z0-9_]+)[.}]")


@dataclass(frozen=True)
class ScanScope:
    """Terraform names to scan; the same scope is used for base and branch."""

    names: frozenset[str]


_SCOPE: contextvars.ContextVar[Optional[ScanScope]] = contextvars.ContextVar("emfirge_scan_scope", default=None)


@contextlib.contextmanager
def scan_scope(scope: Optional[ScanScope]) -> Iterator[None]:
    token = _SCOPE.set(scope)
    try:
        yield
    finally:
        _SCOPE.reset(token)


def _flatten(tf: dict) -> dict[str, tuple[str, Any]]:
    flat: dict[str, tuple[str, Any]] = {}
    for tf_type, entries in (tf.get("resource") or {}).items():
        for name, args in (entries or {}).items():
            flat[name] = (tf_type, args)
    return flat


def _references(args: Any) -> set[str]:
    found: set[str] = set()
    stack = [args]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            found.update(name for _, name in _TF_REF.findall(item))
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


# Where a changed resource points at one of these, the parent's other referrers join
# the scope (all of them for None), since checks on the parent read them.
_SIBLING_TYPES: dict[str, Optional[frozenset[str]]] = {
    "aws_s3_bucket": None,
    "aws_iam_role": frozenset({"aws_iam_role_policy"}),
    "aws_vpc": frozenset({"aws_flow_log"}),
}


def plan_scan_scope(base: AWSInfrastructure, branch: AWSInfrastructure) -> Optional[ScanScope]:
    """Changed resources plus the neighbours graph checks need, or None (scan everything).

    Neighbours: what a changed resource references (an instance's security
    groups, a bucket sub-resource's bucket) and what references it (a bucket's
    policy and sub-resources, the instances using a changed security group).
    Where a changed resource points at a bucket, the bucket's other
    sub-resources join too, since bucket checks read them; likewise a role's
    policies (a Lambda function that points at a role brings in its policies)
    and a VPC's flow logs (a changed subnet brings in its VPC's flow logs).  Both sides are
    scanned with this one name set, so a finding can only appear or vanish
    because the resource itself changed.
    """
    try:
        base_flat = _flatten(build_terraform(base).tf)
        branch_flat = _flatten(build_terraform(branch).tf)
        names = set(base_flat) | set(branch_flat)
        changed = {n for n in names if base_flat.get(n) != branch_flat.get(n)}
        edges: set[tuple[str, str]] = set()  # (referrer, referenced)
        for flat in (base_flat, branch_flat):
            for name, (tf_type, args) in flat.items():
                for ref in _references(args):
                    if ref not in names or ref == name:
                        continue
                    # A security group's rule naming a peer group is not a link a check reads.
                    if tf_type == "aws_security_group" and (flat.get(ref) or ("", None))[0] == "aws_security_group":
                        continue
                    edges.add((name, ref))
        scope = set(changed)
        outgoing = {dst for src, dst in edges if src in changed}
        scope |= outgoing | {src for src, dst in edges if dst in changed}
        for parent in outgoing:
            parent_type = (base_flat.get(parent) or branch_flat.get(parent) or ("", None))[0]
            if parent_type not in _SIBLING_TYPES:
                continue
            wanted = _SIBLING_TYPES[parent_type]
            scope |= {
                src for src, dst in edges
                if dst == parent and (
                    wanted is None
                    or (base_flat.get(src) or branch_flat.get(src) or ("", None))[0] in wanted
                )
            }
        return ScanScope(frozenset(scope))
    except Exception:  # noqa: BLE001 - the subset logic must never break a verdict
        return None


_CACHE_MAX = 64
_cache: "OrderedDict[str, ScanResult]" = OrderedDict()
_cache_lock = threading.Lock()


def clear_scan_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _cache_get(key: str) -> Optional[ScanResult]:
    with _cache_lock:
        hit = _cache.get(key)
        if hit is None:
            return None
        _cache.move_to_end(key)
        return hit.model_copy(deep=True)


def _cache_put(key: str, result: ScanResult) -> None:
    with _cache_lock:
        _cache[key] = result.model_copy(deep=True)
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


def _scanner_url() -> Optional[str]:
    return (os.environ.get("EMFIRGE_SCANNER_URL") or "").strip().rstrip("/") or None


def _worker_timeout() -> float:
    try:
        return float(os.environ.get("EMFIRGE_SCANNER_TIMEOUT_S", "20"))
    except ValueError:
        return 20.0


def _scan_via_worker(url: str, terraform_json: str, timeout_s: float) -> list[ScannerFinding]:
    """POST the serialized Terraform to the warm worker; raises on any failure."""
    body = ('{"terraform":' + terraform_json + "}").encode("utf-8")
    request = urllib.request.Request(
        url + "/scan", data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310 - operator-configured URL
        payload = json.loads(response.read().decode("utf-8"))
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        raise TypeError("worker response has no findings list")
    parsed = [ScannerFinding(**item) for item in findings if isinstance(item, dict)]
    return sorted(
        parsed,
        key=lambda f: (f.check_id, f.resource, f.title, f.severity, f.guideline or ""),
    )


def _worker_failure(exc: BaseException) -> ScanResult:
    if isinstance(exc, urllib.error.HTTPError):
        return _unavailable(f"Checkov worker returned HTTP {exc.code}")
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, TimeoutError):
            return _unavailable("Checkov worker timed out")
        return _unavailable(f"Checkov worker unreachable: {reason}")
    if isinstance(exc, TimeoutError):
        return _unavailable("Checkov worker timed out")
    if isinstance(exc, (json.JSONDecodeError, TypeError, ValueError)):
        return _unavailable("Checkov worker returned an invalid response")
    reason = str(exc).strip()
    return _unavailable(f"Checkov worker failed: {type(exc).__name__}{(': ' + reason) if reason else ''}")


def run_checkov(infra: AWSInfrastructure, timeout_s: int = 60) -> ScanResult:
    """Run Checkov on the serialized infrastructure.

    With EMFIRGE_SCANNER_URL set the Terraform goes to the warm scanner worker;
    otherwise the Checkov CLI runs in a subprocess.  Results are cached by the
    hash of the (scoped) Terraform, so an unchanged base is scanned once.
    """
    try:
        built = build_terraform(infra)
        tf, names = built.tf, built.names
        scope = _SCOPE.get()
        if scope is not None:
            kept = {
                tf_type: {n: a for n, a in entries.items() if n in scope.names}
                for tf_type, entries in (tf.get("resource") or {}).items()
            }
            tf = {**tf, "resource": {t: e for t, e in kept.items() if e}}
            names = {n: v for n, v in names.items() if n in scope.names}
        resource_map = {n: {"resource_type": t, "id": i} for n, (t, i) in names.items()}
        loss = built.loss
        if scope is not None and not tf.get("resource"):  # nothing in scope: nothing to scan
            return ScanResult(scanner="checkov", available=True, findings=[], resource_map=resource_map)
        terraform_json = _json.dumps(tf, sort_keys=True, separators=(",", ":"))
        url = _scanner_url()
        key = hashlib.sha256(
            ("worker\0" if url else "cli\0").encode() + terraform_json.encode("utf-8")
        ).hexdigest()
        cached = _cache_get(key)
        if cached is not None:
            return skip_unknown_input(cached.model_copy(update={"resource_map": resource_map}), loss)
        if url:
            try:
                findings = _scan_via_worker(url, terraform_json, _worker_timeout())
            except Exception as exc:  # noqa: BLE001 - the API must never crash on a scanner
                return _worker_failure(exc)
            result = ScanResult(scanner="checkov", available=True, findings=findings, resource_map=resource_map)
            _cache_put(key, result)
            return skip_unknown_input(result, loss)
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "main.tf.json").write_text(terraform_json, encoding="utf-8")
            completed = subprocess.run(
                [
                    "checkov",
                    "-d",
                    temp_dir,
                    "-o",
                    "json",
                    "--compact",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            stdout = completed.stdout
            if not isinstance(stdout, str) or not stdout.strip():
                return _unavailable("Checkov returned empty output")
            payload = json.loads(stdout)
            findings = _parse_findings(payload)
            result = ScanResult(scanner="checkov", available=True, findings=findings, resource_map=resource_map)
            _cache_put(key, result)
            return skip_unknown_input(result, loss)
    except FileNotFoundError:
        return _unavailable("Checkov executable not found")
    except subprocess.TimeoutExpired:
        return _unavailable("Checkov timed out")
    except json.JSONDecodeError:
        return _unavailable("Checkov returned invalid JSON")
    except (TypeError, ValueError):
        return _unavailable("Checkov returned an invalid JSON structure")
    except Exception as exc:
        reason = str(exc).strip()
        return _unavailable(f"Checkov failed: {type(exc).__name__}{(': ' + reason) if reason else ''}")


# --------------------------------------------------------------------------
# Severity policy
# --------------------------------------------------------------------------

_CROSSWALK_PATH = Path(__file__).resolve().parent / "data" / "scanner_severity_crosswalk.json"
_CROSSWALK_SEVERITIES = {"critical", "high", "medium", "low"}


@lru_cache(maxsize=1)
def _crosswalk_rows() -> dict[str, dict[str, Any]]:
    try:
        rows = json.loads(_CROSSWALK_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(r["check_id"]): r for r in rows if isinstance(r, dict) and r.get("check_id")} if isinstance(rows, list) else {}


@lru_cache(maxsize=1)
def severity_crosswalk() -> dict[str, dict[str, str]]:
    """check_id -> {"severity", "source"} from the published-source table.

    Scanner severities are not trusted on their own (Checkov reports none
    without a paid key), so only a check listed here may carry a severity
    that can block.  Malformed rows are ignored rather than trusted.
    """
    try:
        rows = json.loads(_CROSSWALK_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    table: dict[str, dict[str, str]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        check_id, severity, source = (_text(row.get(k)) for k in ("check_id", "severity", "source"))
        if check_id and source and severity and severity.lower() in _CROSSWALK_SEVERITIES:
            table[check_id] = {"severity": severity.lower(), "source": source}
    return table


def govern_scanner_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Apply the severity policy to a normalized scanner finding.

    Crosswalked check: the table's severity.  Any other check: never above
    "high", so a scanner finding without a published severity cannot block.
    An absent or unknown scanner severity is already "low" upstream.
    """
    entry = severity_crosswalk().get(str(finding.get("check_id")))
    if entry is not None:
        finding["severity"] = entry["severity"]
    elif finding.get("severity") == "critical":
        finding["severity"] = "high"
    return finding


TRIVY_DISABLED_REASON = "disabled (memory)"


def trivy_enabled() -> bool:
    """Trivy spikes to 1.3-1.5 GB at 500-700 resources, so it is opt-in."""
    return os.environ.get("EMFIRGE_RUN_TRIVY", "0") == "1"


def run_trivy(infra: AWSInfrastructure, timeout_s: int = 60) -> ScanResult:
    """Run Trivy config against a temporary Terraform JSON configuration."""
    if not trivy_enabled():
        return _trivy_unavailable(TRIVY_DISABLED_REASON)
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            built = build_terraform(infra)
            terraform_json = _json.dumps(built.tf, sort_keys=True, separators=(",", ":"))
            resource_map = {n: {"resource_type": t, "id": i} for n, (t, i) in built.names.items()}
            Path(temp_dir, "main.tf.json").write_text(terraform_json, encoding="utf-8")
            completed = subprocess.run(
                ["trivy", "config", temp_dir, "--format", "json", "--quiet"],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            stdout = completed.stdout
            if not isinstance(stdout, str) or not stdout.strip():
                return _trivy_unavailable("Trivy returned empty output")
            payload = json.loads(stdout)
            findings = _trivy_findings(payload)
            return ScanResult(scanner="trivy", available=True, findings=findings, resource_map=resource_map)
    except FileNotFoundError:
        return _trivy_unavailable("Trivy executable not found")
    except subprocess.TimeoutExpired:
        return _trivy_unavailable("Trivy timed out")
    except json.JSONDecodeError:
        return _trivy_unavailable("Trivy returned invalid JSON")
    except (TypeError, ValueError):
        return _trivy_unavailable("Trivy returned an invalid JSON structure")
    except Exception as exc:
        reason = str(exc).strip()
        return _trivy_unavailable(f"Trivy failed: {type(exc).__name__}{(': ' + reason) if reason else ''}")


_CLOUDSPLAINING_CATEGORIES = (
    ("PrivilegeEscalation", ("allows_privilege_escalation",), "high"),
    (
        "DataExfiltration",
        ("allows_data_exfiltration_actions", "allows_data_exfiltration"),
        "medium",
    ),
    ("CredentialsExposure", ("credentials_exposure",), "high"),
    ("InfrastructureModification", ("infrastructure_modification",), "medium"),
)
_CLOUDSPLAINING_RESOURCE_EXPOSURE_PROPERTIES = (
    "allows_resource_exposure_actions",
    "resource_exposure",
    "allows_resource_exposure",
)

def _cloudsplaining_unavailable(reason: str) -> ScanResult:
    return ScanResult(scanner="cloudsplaining", available=False, findings=[], error=reason)


def _cloudsplaining_value_is_present(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, dict)):
        return bool(value)
    return True


def _cloudsplaining_named_values(document: Any, property_names: tuple[str, ...]) -> list[Any]:
    """Read only explicitly named PolicyDocument properties that are present."""
    instance_attributes = getattr(document, "__dict__", {}) or {}
    values = []
    for property_name in property_names:
        # Avoid treating dynamic mock attributes as an API property. Real
        # cloudsplaining properties are either class descriptors or instance
        # attributes supplied by the implementation.
        if property_name not in instance_attributes and not hasattr(type(document), property_name):
            continue
        try:
            values.append(getattr(document, property_name))
        except AttributeError:
            continue
    return values


def _cloudsplaining_category_is_present(document: Any, property_names: tuple[str, ...]) -> bool:
    return any(
        _cloudsplaining_value_is_present(value)
        for value in _cloudsplaining_named_values(document, property_names)
    )


def _cloudsplaining_role_findings(role: Any, policy_document_type: Any) -> list[ScannerFinding]:
    resource = _text(getattr(role, "role_arn", None)) or _text(getattr(role, "role_name", None))
    if not resource:
        return []
    statements = []
    for statement in getattr(role, "access_statements", []) or []:
        statements.append(
            {
                "Effect": statement.effect,
                "Action": list(statement.actions),
                "Resource": list(statement.resources),
            }
        )
    policy_document = {
        "Version": "2012-10-17",
        "Statement": statements,
    }
    document = policy_document_type(policy_document)
    findings: list[ScannerFinding] = []
    category_values = list(_CLOUDSPLAINING_CATEGORIES)
    category_values.append(
        (
            "ResourceExposure",
            _CLOUDSPLAINING_RESOURCE_EXPOSURE_PROPERTIES,
            "medium",
        )
    )
    for category, property_names, severity in category_values:
        if not _cloudsplaining_category_is_present(document, property_names):
            continue
        findings.append(
            ScannerFinding(
                source="cloudsplaining",
                check_id=category,
                resource=resource,
                severity=severity,
                title=f"Cloudsplaining detected {category} risk",
                guideline=None,
            )
        )
    return findings


def run_cloudsplaining(infra: AWSInfrastructure) -> ScanResult:
    """Run cloudsplaining against normalized IAM role policies when installed."""
    try:
        from cloudsplaining.scan.policy_document import PolicyDocument
    except ImportError as exc:
        return _cloudsplaining_unavailable(f"Cloudsplaining unavailable: {exc}")
    except Exception as exc:
        reason = str(exc).strip()
        return _cloudsplaining_unavailable(
            f"Cloudsplaining failed: {type(exc).__name__}{(': ' + reason) if reason else ''}"
        )

    try:
        roles = getattr(getattr(infra, "iam", None), "role_policies", []) or []
        ordered_roles = sorted(
            roles,
            key=lambda role: (
                _text(getattr(role, "role_arn", None)) or _text(getattr(role, "role_name", None)),
                _text(getattr(role, "role_name", None)),
            ),
        )
        findings: list[ScannerFinding] = []
        for role in ordered_roles:
            findings.extend(_cloudsplaining_role_findings(role, PolicyDocument))
        findings.sort(
            key=lambda finding: (
                finding.check_id,
                finding.resource,
                finding.severity,
                finding.title,
                finding.guideline or "",
            )
        )
        return ScanResult(scanner="cloudsplaining", available=True, findings=findings)
    except Exception as exc:
        reason = str(exc).strip()
        return _cloudsplaining_unavailable(
            f"Cloudsplaining failed: {type(exc).__name__}{(': ' + reason) if reason else ''}"
        )
