"""Adapters for optional infrastructure security scanners."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from app.models import AWSInfrastructure
from app.serializer import to_terraform_json_string


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


def run_checkov(infra: AWSInfrastructure, timeout_s: int = 60) -> ScanResult:
    """Run Checkov against a temporary Terraform JSON configuration."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_json = to_terraform_json_string(infra)
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
            return ScanResult(scanner="checkov", available=True, findings=findings)
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


def run_trivy(infra: AWSInfrastructure, timeout_s: int = 60) -> ScanResult:
    """Run Trivy config against a temporary Terraform JSON configuration."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_json = to_terraform_json_string(infra)
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
            return ScanResult(scanner="trivy", available=True, findings=findings)
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
