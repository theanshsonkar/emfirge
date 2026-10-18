from app.mutations import Change, apply_change
from app.mutations import Change, apply_change
from app.verdict import _plan_reasons, combined_verdict
from tests.incidents.synthetic_base import load_synthetic_base
from tests.laws.test_w1c_wildcard_bucket_laws import _infra, _role, _verdict, _reason


def _reason_by(result, code):
    return next(item for item in result.reasons if item["code"] == code)


def test_new_internet_reachability_names_instance(monkeypatch):
    result = _verdict(_infra(), _infra(public=True), monkeypatch)
    assert "i-orders" in _reason_by(result, "newly_internet_reachable")["resources"]


def test_deleted_rds_without_recovery_names_store():
    base = load_synthetic_base("delete")
    branch = apply_change(base, Change(op="delete", resource_type="rds_instance", resource_id="db-dl-prod", fields={"skip_final_snapshot": True}))
    result = combined_verdict(base, branch, run_scanners=False)
    assert _reason_by(result, "data_store_deleted_no_recovery_point")["resources"] == ["db-dl-prod"]


def test_introduced_critical_finding_names_resource(monkeypatch):
    base = _infra()
    branch = _infra(public=True, role=_role("*"))
    result = _verdict(base, branch, monkeypatch)
    reason = _reason_by(result, "introduced_critical_finding")
    assert "i-orders" in reason["resources"]


def test_plan_unmodeled_delete_names_address():
    reasons = _plan_reasons([{"unmodeled": [{"address": "aws_foo.bar", "type": "aws_foo", "actions": ["delete"], "provider_name": "registry.terraform.io/hashicorp/aws"}]}])
    assert reasons[0]["resources"] == ["aws_foo.bar"]


def test_internet_broad_access_keeps_path_order(monkeypatch):
    result = _verdict(_infra(), _infra(public=True, role=_role("arn:aws:s3:::cust-apps-*")), monkeypatch)
    assert _reason(result)["resources"] == ["i-orders", "iam-role-OrdersRole", "cust-apps-a", "cust-apps-b"]


def test_reason_resource_cap():
    reasons = _plan_reasons([{"unmodeled": [{"address": f"aws_foo.r{n}", "type": "aws_foo", "actions": ["update"], "provider_name": "registry.terraform.io/hashicorp/aws"} for n in range(51)]}])
    # Each plan item emits a reason; cap is exercised directly by the reason helper.
    from app.verdict import _reason
    reason = _reason("warn", "capacity", "x", [f"r{n}" for n in range(51)])
    assert len(reason["resources"]) == 50 and reason["resources_total"] == 51


def test_reason_resources_are_existing_ids(monkeypatch):
    base = _infra()
    branch = _infra(public=True, role=_role("arn:aws:s3:::cust-apps-*"))
    result = _verdict(base, branch, monkeypatch)
    known = {"INTERNET", "i-orders", "sg-orders", "iam-role-OrdersRole", "cust-apps-a", "cust-apps-b", "payroll"}
    for reason in result.reasons:
        assert set(reason.get("resources", [])) <= known


def test_deleted_role_reason_excludes_unrelated_rds(monkeypatch):
    base = load_synthetic_base("delete", {"collection": {"iam_role_last_used": "denied"}})
    branch = apply_change(base, Change(op="delete", resource_type="iam_role", resource_id="arn:aws:iam::000000000000:role/DlAppRole", fields={}))
    branch = apply_change(branch, Change(op="delete", resource_type="rds_instance", resource_id="db-dl-prod", fields={"skip_final_snapshot": True}))
    result = combined_verdict(base, branch, run_scanners=False)
    reason = _reason_by(result, "usage_unknown")
    assert reason["resources"] == ["arn:aws:iam::000000000000:role/DlAppRole"]
    assert "db-dl-prod" not in reason["resources"]


def test_recovery_point_removed_names_snapshot_not_other_deletion(monkeypatch):
    base = load_synthetic_base("delete")
    branch = apply_change(base, Change(op="delete", resource_type="ebs_snapshot", resource_id="snap-dl-root", fields={}))
    branch = apply_change(branch, Change(op="delete", resource_type="rds_instance", resource_id="db-dl-reports", fields={"skip_final_snapshot": True}))
    result = combined_verdict(base, branch, run_scanners=False)
    reason = _reason_by(result, "recovery_point_removed")
    assert reason["resources"] == ["snap-dl-root"]
    assert "db-dl-reports" not in reason["resources"]
