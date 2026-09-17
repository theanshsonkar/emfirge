import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from app.models import AWSInfrastructure
from app.scanners import run_checkov


@pytest.fixture
def infra():
    return AWSInfrastructure(region="us-east-1")


def fake_run(stdout, returncode=0):
    def run(*args, **kwargs):
        return SimpleNamespace(stdout=stdout, returncode=returncode)

    return run


def test_dict_output_normalizes_and_sorts_findings(monkeypatch, infra):
    output = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_2",
                    "resource": "aws_s3_bucket.z",
                    "severity": None,
                    "check_name": "Second check",
                    "guideline_url": "https://example.test/two",
                },
                {
                    "check_id": "CKV_AWS_1",
                    "resource": "aws_s3_bucket.a",
                    "severity": "HIGH",
                    "check_name": "First check",
                    "guideline": "Use encryption",
                },
            ]
        }
    }
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        temp_dir = Path(args[2])
        assert (temp_dir / "main.tf.json").is_file()
        assert json.loads((temp_dir / "main.tf.json").read_text()) == {"resource": {}}
        return SimpleNamespace(stdout=json.dumps(output), returncode=1)

    monkeypatch.setattr("app.scanners.subprocess.run", run)
    result = run_checkov(infra)

    assert result.available is True
    assert [finding.model_dump() for finding in result.findings] == [
        {
            "source": "checkov",
            "check_id": "CKV_AWS_1",
            "resource": "aws_s3_bucket.a",
            "severity": "HIGH",
            "title": "First check",
            "guideline": "Use encryption",
        },
        {
            "source": "checkov",
            "check_id": "CKV_AWS_2",
            "resource": "aws_s3_bucket.z",
            "severity": "UNKNOWN",
            "title": "Second check",
            "guideline": "https://example.test/two",
        },
    ]
    assert calls[0][0] == [
        "checkov", "-d", calls[0][0][2], "-o", "json", "--compact", "--quiet"
    ]
    assert calls[0][1] == {
        "capture_output": True,
        "text": True,
        "timeout": 60,
        "check": False,
    }


def test_list_output_aggregates_frameworks_and_ignores_malformed_checks(monkeypatch, infra):
    output = [
        {"results": {"failed_checks": [{"check_id": "B", "resource": "r2", "check_name": "B"}]}},
        {
            "results": {
                "failed_checks": [
                    {"check_id": "A", "resource": "r1", "check_name": "A", "severity": "LOW"},
                    {"resource": "missing-id", "check_name": "ignored"},
                    "not a check",
                ]
            }
        },
    ]
    monkeypatch.setattr("app.scanners.subprocess.run", fake_run(json.dumps(output)))

    result = run_checkov(infra)
    assert result.available is True
    assert [(item.check_id, item.severity) for item in result.findings] == [("A", "LOW"), ("B", "UNKNOWN")]


@pytest.mark.parametrize(
    "side_effect, expected",
    [
        (FileNotFoundError(), "not found"),
        (subprocess.TimeoutExpired("checkov", 1), "timed out"),
    ],
)
def test_checkov_process_errors_are_graceful(monkeypatch, infra, side_effect, expected):
    def run(*args, **kwargs):
        raise side_effect

    monkeypatch.setattr("app.scanners.subprocess.run", run)
    result = run_checkov(infra)
    assert result.scanner == "checkov"
    assert result.available is False
    assert result.findings == []
    assert result.error is not None
    assert expected in result.error.lower()


@pytest.mark.parametrize("stdout", ["", "not json", "null", "[]"])
def test_empty_or_malformed_output(monkeypatch, infra, stdout):
    monkeypatch.setattr("app.scanners.subprocess.run", fake_run(stdout))
    result = run_checkov(infra)
    if stdout == "[]":
        assert result.available is True
        assert result.findings == []
    else:
        assert result.available is False
        assert result.findings == []
        assert result.error


def test_parseable_no_findings_is_available(monkeypatch, infra):
    monkeypatch.setattr("app.scanners.subprocess.run", fake_run(json.dumps({"results": {"failed_checks": []}})))
    result = run_checkov(infra)
    assert result.available is True
    assert result.findings == []
    assert result.error is None


@pytest.mark.skipif(shutil.which("checkov") is None, reason="Checkov is not installed")
def test_real_checkov_is_optional(infra):
    result = run_checkov(infra, timeout_s=10)
    assert result.scanner == "checkov"
    assert isinstance(result.available, bool)



def test_trivy_output_normalizes_resources_and_findings(monkeypatch, infra):
    output = {
        "Results": [
            {
                "Target": "main.tf.json",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0001",
                        "Severity": "HIGH",
                        "Title": "Public bucket",
                        "CauseMetadata": {"Resource": "aws_s3_bucket.data"},
                        "References": ["https://example.test/bucket"],
                    }
                ],
            },
            {
                "Target": "fallback.tf.json",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0002",
                        "Severity": "LOW",
                        "Title": "Missing logging",
                        "References": ["https://example.test/logging"],
                    }
                ],
            },
        ]
    }
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        temp_dir = Path(args[2])
        assert (temp_dir / "main.tf.json").is_file()
        assert json.loads((temp_dir / "main.tf.json").read_text()) == {"resource": {}}
        return SimpleNamespace(stdout=json.dumps(output), returncode=0)

    monkeypatch.setattr("app.scanners.subprocess.run", run)
    from app.scanners import run_trivy

    result = run_trivy(infra)

    assert result.available is True
    assert result.scanner == "trivy"
    assert [finding.model_dump() for finding in result.findings] == [
        {
            "source": "trivy",
            "check_id": "AVD-AWS-0001",
            "resource": "aws_s3_bucket.data",
            "severity": "HIGH",
            "title": "Public bucket",
            "guideline": "https://example.test/bucket",
        },
        {
            "source": "trivy",
            "check_id": "AVD-AWS-0002",
            "resource": "fallback.tf.json",
            "severity": "LOW",
            "title": "Missing logging",
            "guideline": "https://example.test/logging",
        },
    ]
    assert calls[0][0] == ["trivy", "config", calls[0][0][2], "--format", "json", "--quiet"]
    assert calls[0][1] == {
        "capture_output": True,
        "text": True,
        "timeout": 60,
        "check": False,
    }


def test_trivy_not_installed_is_unavailable(monkeypatch, infra):
    def run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr("app.scanners.subprocess.run", run)
    from app.scanners import run_trivy

    result = run_trivy(infra)
    assert result.scanner == "trivy"
    assert result.available is False
    assert result.findings == []
    assert "not found" in result.error.lower()



def _install_fake_cloudsplaining(monkeypatch, policy_document):
    import sys
    from types import ModuleType

    cloudsplaining = ModuleType("cloudsplaining")
    scan = ModuleType("cloudsplaining.scan")
    policy_document_module = ModuleType("cloudsplaining.scan.policy_document")
    policy_document_module.PolicyDocument = policy_document
    scan.policy_document = policy_document_module
    cloudsplaining.scan = scan
    monkeypatch.setitem(sys.modules, "cloudsplaining", cloudsplaining)
    monkeypatch.setitem(sys.modules, "cloudsplaining.scan", scan)
    monkeypatch.setitem(sys.modules, "cloudsplaining.scan.policy_document", policy_document_module)


def _role_with_access_statements():
    from app.models import AccessStatement, IAMData, RolePolicy

    return AWSInfrastructure(
        region="us-east-1",
        iam=IAMData(role_policies=[RolePolicy(
            role_name="CloudRole",
            role_arn="arn:aws:iam::123456789012:role/CloudRole",
            access_statements=[
                AccessStatement(effect="Allow", actions=["iam:PassRole"], resources=["*"]),
                AccessStatement(effect="Deny", actions=["s3:DeleteObject"], resources=["arn:aws:s3:::example/*"]),
            ],
        )]),
    )


def test_cloudsplaining_normalizes_privilege_escalation_and_policy(monkeypatch):
    from app.scanners import run_cloudsplaining

    captured = []

    class FakePolicyDocument:
        def __init__(self, policy):
            captured.append(policy)

        @property
        def allows_privilege_escalation(self):
            return ["iam:PassRole"]

        allows_data_exfiltration_actions = []
        credentials_exposure = []
        infrastructure_modification = []

    _install_fake_cloudsplaining(monkeypatch, FakePolicyDocument)
    result = run_cloudsplaining(_role_with_access_statements())

    assert result.available is True
    assert [finding.model_dump() for finding in result.findings] == [{
        "source": "cloudsplaining",
        "check_id": "PrivilegeEscalation",
        "resource": "arn:aws:iam::123456789012:role/CloudRole",
        "severity": "high",
        "title": "Cloudsplaining detected PrivilegeEscalation risk",
        "guideline": None,
    }]
    assert captured == [{
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": ["*"]},
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["arn:aws:s3:::example/*"]},
        ],
    }]


def test_cloudsplaining_reports_one_finding_per_category(monkeypatch):
    from app.scanners import run_cloudsplaining

    class FakePolicyDocument:
        def __init__(self, policy):
            self.allows_resource_exposure_actions = ["s3:PutObject"]

        allows_privilege_escalation = ["iam:PassRole"]
        allows_data_exfiltration_actions = ["s3:GetObject"]
        credentials_exposure = ["secretsmanager:GetSecretValue"]
        infrastructure_modification = ["ec2:RunInstances"]

    _install_fake_cloudsplaining(monkeypatch, FakePolicyDocument)
    result = run_cloudsplaining(_role_with_access_statements())

    assert [(finding.check_id, finding.severity) for finding in result.findings] == [
        ("CredentialsExposure", "high"),
        ("DataExfiltration", "medium"),
        ("InfrastructureModification", "medium"),
        ("PrivilegeEscalation", "high"),
        ("ResourceExposure", "medium"),
    ]
    assert all(finding.source == "cloudsplaining" for finding in result.findings)


def test_cloudsplaining_empty_or_missing_categories_emit_no_findings(monkeypatch):
    from app.scanners import run_cloudsplaining

    class EmptyPolicyDocument:
        def __init__(self, policy):
            pass

        allows_privilege_escalation = []
        allows_data_exfiltration_actions = ()
        credentials_exposure = None
        infrastructure_modification = {}
        allows_resource_exposure_actions = ""

    class MissingPolicyDocument:
        def __init__(self, policy):
            pass

    for policy_document in (EmptyPolicyDocument, MissingPolicyDocument):
        _install_fake_cloudsplaining(monkeypatch, policy_document)
        result = run_cloudsplaining(_role_with_access_statements())
        assert result.available is True
        assert result.findings == []


def test_cloudsplaining_supports_data_exfiltration_and_resource_aliases(monkeypatch):
    from app.scanners import run_cloudsplaining

    class FakePolicyDocument:
        def __init__(self, policy):
            pass

        allows_privilege_escalation = []
        allows_data_exfiltration = ["s3:GetObject"]
        credentials_exposure = []
        infrastructure_modification = []
        resource_exposure = ["s3:PutObject"]

    _install_fake_cloudsplaining(monkeypatch, FakePolicyDocument)
    result = run_cloudsplaining(_role_with_access_statements())

    assert [(finding.check_id, finding.severity) for finding in result.findings] == [
        ("DataExfiltration", "medium"),
        ("ResourceExposure", "medium"),
    ]
    assert all(finding.resource == "arn:aws:iam::123456789012:role/CloudRole" for finding in result.findings)


def test_cloudsplaining_import_error_is_unavailable(monkeypatch, infra):
    import builtins

    real_import = builtins.__import__

    def import_without_cloudsplaining(name, *args, **kwargs):
        if name == "cloudsplaining.scan.policy_document":
            raise ImportError("optional cloudsplaining is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_cloudsplaining)
    from app.scanners import run_cloudsplaining

    result = run_cloudsplaining(infra)
    assert result.available is False
    assert result.findings == []
