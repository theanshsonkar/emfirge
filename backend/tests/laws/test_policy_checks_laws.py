"""L62 AWS policy checks: opt-in IAM Access Analyzer evidence can only make a verdict stricter.

No network: the Access Analyzer client is a fake, STS is a recorder.
"""
import json
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import aws_policy_checks, branches, database, main, policy_checks
from app.demo_seed import DEMO_ROLE_ARN
from tests.incidents.synthetic_base import load_synthetic_base

ACCOUNT = "111122223333"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/EmfirgeReadOnly"
BUCKET = "dl-data-bucket"
CREDS = {"AccessKeyId": "x", "SecretAccessKey": "y", "SessionToken": "z"}
OPEN = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{BUCKET}/*"}]})
# A fixed foreign account: local logic says not public; the fake AWS can still say FAIL.
LOCAL_OK = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{BUCKET}/*"}]})
NOTE_NOT_RUN = "AWS policy check not run; local logic used"


class FakeAnalyzer:
    def __init__(self, answers=None, error=None):
        self.answers, self.error, self.calls, self.default = answers or {}, error, [], "PASS"

    def check_no_public_access(self, policyDocument, resourceType):
        self.calls.append((resourceType, policyDocument))
        if self.error:
            err = self.error.pop(0) if isinstance(self.error, list) else self.error
            if err:
                raise err
        return {"result": self.answers.get(policyDocument, self.default), "reasons": []}


def client_error(code, extra=None):
    response = {"Error": {"Code": code, "Message": "m"}}
    response.update(extra or {})
    return ClientError(response, "CheckNoPublicAccess")


class Sts:
    def __init__(self):
        self.calls, self.account = [], ACCOUNT

    def assume(self, role_arn, _caller, _db):
        self.calls.append(role_arn)
        return CREDS, self.account


@pytest.fixture
def env(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'pc.sqlite'}")
    database.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    for module in (database, branches, policy_checks):
        monkeypatch.setattr(module, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_infrastructure_for_analysis", lambda _: load_synthetic_base("delete"))
    monkeypatch.setattr(main, "_check_branch_rate_limit", lambda _: None)
    sts = Sts()
    monkeypatch.setattr(main, "assume_role_credentials", sts.assume)
    main.app.dependency_overrides[main.require_api_key] = lambda: None
    session = factory()
    session.add(database.AnalysisLog(aws_account_id=ACCOUNT, findings_json=json.dumps({"analysis_id": "an-pc"})))
    session.commit()
    session.close()
    analyzer = FakeAnalyzer()
    monkeypatch.setattr(aws_policy_checks, "_default_client", lambda creds, region: analyzer)
    monkeypatch.setattr(aws_policy_checks.time, "sleep", lambda _: None)
    yield TestClient(main.app), sts, analyzer
    main.app.dependency_overrides.pop(main.require_api_key, None)
    engine.dispose()


def new_branch(client, policy=None):
    branch_id = client.post("/branches", json={"base_analysis_id": "an-pc", "name": "pc"}).json()["branch_id"]
    if policy is not None:
        response = client.post(f"/branches/{branch_id}/changes", json={"op": "modify", "resource_type": "s3_bucket", "resource_id": BUCKET, "fields": {"policy": policy}})
        assert response.status_code == 200, response.text
    return branch_id


def run(client, branch_id, **over):
    estimate = client.get(f"/branches/{branch_id}/policy-checks/estimate").json()
    body = {"role_arn": ROLE, "approve": True, "accept_estimate_id": estimate["estimate_id"]}
    body.update(over)
    return client.post(f"/branches/{branch_id}/policy-checks", json=body)


def verdict(client, branch_id):
    response = client.get(f"/branches/{branch_id}/verdict")
    assert response.status_code == 200, response.text
    return response.json()


def test_L62a_estimate_lists_only_changed_policies_and_calls_nothing(env):
    client, sts, analyzer = env
    unchanged = new_branch(client)
    assert client.get(f"/branches/{unchanged}/policy-checks/estimate").json()["policies"] == []
    changed = new_branch(client, LOCAL_OK)
    estimate = client.get(f"/branches/{changed}/policy-checks/estimate").json()
    assert [(p["resource_id"], p["side"], p["aws_resource_type"]) for p in estimate["policies"]] == [(BUCKET, "branch", "AWS::S3::Bucket")]
    assert estimate["call_count"] == 1 and estimate["approximate_cost_usd"] == pytest.approx(0.002)
    assert estimate["pricing_url"] == "https://aws.amazon.com/iam/access-analyzer/pricing/"
    assert "document" not in estimate["policies"][0]
    assert analyzer.calls == [] and sts.calls == []
    # Once the base also has a policy, both sides are listed.
    second = client.post(f"/branches/{changed}/changes", json={"op": "modify", "resource_type": "s3_bucket", "resource_id": BUCKET, "fields": {"policy": OPEN}})
    assert second.status_code == 200
    assert analyzer.calls == []


def test_L62b_demo_arn_and_wrong_account_are_rejected(env):
    client, sts, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    assert run(client, branch_id, role_arn=DEMO_ROLE_ARN).status_code == 422
    assert run(client, branch_id, role_arn="arn:aws:iam::444455556666:role/Other").status_code == 409
    sts.account = "444455556666"
    assert run(client, branch_id).status_code == 409
    assert analyzer.calls == []


def test_L62c_aws_fail_where_local_passes_is_treated_as_public(env):
    client, sts, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    before = verdict(client, branch_id)
    assert not before["newly_exposed"] and NOTE_NOT_RUN in before["coverage_warnings"]
    analyzer.answers[LOCAL_OK] = "FAIL"
    result = run(client, branch_id)
    assert result.status_code == 200 and result.json()["aws_calls_made"] == 1
    assert analyzer.calls[0][0] == "AWS::S3::Bucket"
    after = verdict(client, branch_id)
    assert any(f"AWS Access Analyzer reports s3_bucket {BUCKET} public; local logic disagreed" == w for w in after["coverage_warnings"])
    assert NOTE_NOT_RUN not in after["coverage_warnings"]
    assert BUCKET in json.dumps(after["newly_exposed"]) or any(BUCKET in json.dumps(f) for f in after["native_added"])
    rank = {"pass": 0, "warn": 1, "block": 2}
    assert rank[after["verdict"]] >= rank[before["verdict"]]


def test_L62d_aws_pass_where_local_is_public_keeps_local(env):
    client, sts, analyzer = env
    branch_id = new_branch(client, OPEN)
    without = verdict(client, branch_id)
    analyzer.answers[OPEN] = "PASS"
    assert run(client, branch_id).status_code == 200
    with_evidence = verdict(client, branch_id)
    assert with_evidence["verdict"] == without["verdict"]
    assert with_evidence["newly_exposed"] == without["newly_exposed"]
    assert with_evidence["native_added"] == without["native_added"]
    assert any("reports s3_bucket" in w and "not public" in w and "stricter" in w for w in with_evidence["coverage_warnings"])


def test_L62e_no_evidence_adds_coverage_warning_only_when_a_policy_changed(env):
    client, _, analyzer = env
    plain = verdict(client, new_branch(client))
    assert NOTE_NOT_RUN not in plain["coverage_warnings"]
    changed = verdict(client, new_branch(client, LOCAL_OK))
    assert NOTE_NOT_RUN in changed["coverage_warnings"]
    assert changed["verdict"] == plain["verdict"] and changed["newly_exposed"] == plain["newly_exposed"]
    assert analyzer.calls == []


def test_L62f_evidence_for_an_older_revision_is_ignored(env):
    client, _, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    analyzer.answers[LOCAL_OK] = "FAIL"
    assert run(client, branch_id).status_code == 200
    client.post(f"/branches/{branch_id}/changes", json={"op": "modify", "resource_type": "s3_bucket", "resource_id": BUCKET, "fields": {"versioning_enabled": True}})
    after = verdict(client, branch_id)
    assert not any("local logic disagreed" in w for w in after["coverage_warnings"])
    assert NOTE_NOT_RUN in after["coverage_warnings"]
    assert any("older branch revision" in w for w in after["coverage_warnings"])


@pytest.mark.parametrize("code", ["ThrottlingException", "AccessDeniedException", "ValidationException"])
def test_L62g_per_policy_failures_are_reported_and_verdict_falls_back_to_local(env, code):
    client, _, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    base = verdict(client, branch_id)
    analyzer.error = client_error(code, {"retryAfterSeconds": 1})
    result = run(client, branch_id)
    assert result.status_code == 200
    record = result.json()["records"][0]
    assert record["provider_answer"] == "unknown" and record["status"] in {"throttled", "denied", "invalid"}
    if code == "ThrottlingException":
        assert len(analyzer.calls) == aws_policy_checks.MAX_ATTEMPTS
    after = verdict(client, branch_id)
    assert after["verdict"] == base["verdict"] and after["newly_exposed"] == base["newly_exposed"]
    assert any("did not complete" in w and "local logic used" in w for w in after["coverage_warnings"])


def test_L62g_throttle_then_success_retries(env):
    client, _, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    analyzer.error = [client_error("ThrottlingException", {"retryAfterSeconds": 1}), None]
    record = run(client, branch_id).json()["records"][0]
    assert record["status"] == "ok" and len(analyzer.calls) == 2


def test_L62h_nothing_is_sent_without_approval(env):
    client, sts, analyzer = env
    branch_id = new_branch(client, LOCAL_OK)
    estimate = client.get(f"/branches/{branch_id}/policy-checks/estimate").json()
    for body in ({"role_arn": ROLE}, {"role_arn": ROLE, "approve": False, "accept_estimate_id": estimate["estimate_id"]}):
        response = client.post(f"/branches/{branch_id}/policy-checks", json=body)
        assert response.status_code == 409
    assert client.post(f"/branches/{branch_id}/policy-checks", json={"role_arn": ROLE, "approve": True, "accept_estimate_id": "0" * 64}).status_code == 409
    assert analyzer.calls == [] and sts.calls == []


def test_L62i_trust_policy_is_checked_on_the_branch_side_with_the_assume_role_type(env):
    client, _, analyzer = env
    branch_id = new_branch(client)
    role = "arn:aws:iam::000000000000:role/DlAppRole"
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"}, "Action": "sts:AssumeRole"}]}
    response = client.post(f"/branches/{branch_id}/changes", json={"op": "modify", "resource_type": "iam_role", "resource_id": role, "fields": {"trust_policy": trust}})
    assert response.status_code == 200, response.text
    estimate = client.get(f"/branches/{branch_id}/policy-checks/estimate").json()
    assert [(p["resource_type"], p["side"], p["aws_resource_type"]) for p in estimate["policies"]] == [("iam_role", "branch", "AWS::IAM::AssumeRolePolicyDocument")]
    analyzer.default = "FAIL"
    assert run(client, branch_id).status_code == 200
    assert analyzer.calls[0][0] == "AWS::IAM::AssumeRolePolicyDocument"
    after = verdict(client, branch_id)
    assert any("disagreed" in w and role in w for w in after["coverage_warnings"])
    assert any(item.get("rule_id") == "EMFIRGE-IAM-009" for item in after["native_added"])
