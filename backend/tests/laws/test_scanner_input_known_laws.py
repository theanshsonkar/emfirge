"""L64 scanner checks only on collected input: a Checkov check that reads an attribute the serializer omitted (value not collected) is skipped and reported, never presented as a finding on the resource."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from app import scanners
from app.aws_collector import collect_ec2, collect_rds
from app.models import AWSInfrastructure, EC2Data, EC2Instance, RDSData, RDSInstance
from app.serializer import FIELD_MAP, TF_TO_EMFIRGE, build_terraform, attribute_fields

KEYS = ("key", "secret", "token", "ap-south-1")


def _rds_infra(**fields) -> AWSInfrastructure:
    return AWSInfrastructure(region="us-east-1", rds=RDSData(rds_instances=[RDSInstance(id="db-1", **fields)]))


def _stub_checkov(monkeypatch, infra, check_id):
    scanners.clear_scan_cache()
    name = next(iter(build_terraform(infra).names))
    stdout = json.dumps({"results": {"failed_checks": [{
        "check_id": check_id, "resource": f"aws_db_instance.{name}", "check_name": "stub",
    }]}})
    monkeypatch.setattr("app.scanners.subprocess.run", lambda *a, **k: SimpleNamespace(stdout=stdout, returncode=1))


def test_L64a_every_reads_attribute_is_one_the_serializer_can_emit():
    rows = [row for row in scanners._crosswalk_rows().values() if "reads" in row]
    assert any(row["check_id"] == "CKV_AWS_157" for row in rows)
    for row in rows:
        assert row["tf_type"] in TF_TO_EMFIRGE, row["check_id"]
        emitted = attribute_fields(row["tf_type"])
        assert row["reads"] and set(row["reads"]) <= set(emitted), row["check_id"]
        assert all(FIELD_MAP[TF_TO_EMFIRGE[row["tf_type"]]][f][0] == "emit" for a in row["reads"] for f in emitted[a])


def test_L64b_unknown_input_is_skipped_and_reported_known_input_is_kept(monkeypatch):
    unknown = _rds_infra()  # multi_az None
    _stub_checkov(monkeypatch, unknown, "CKV_AWS_157")
    result = scanners.run_checkov(unknown)
    assert result.findings == []
    assert result.skipped == [
        {"check_id": "CKV_AWS_157", "resource_type": "rds_instance", "id": "db-1", "inputs": ["multi_az"]}
    ]
    known = _rds_infra(multi_az=False)
    _stub_checkov(monkeypatch, known, "CKV_AWS_157")
    result = scanners.run_checkov(known)
    assert [f.check_id for f in result.findings] == ["CKV_AWS_157"]
    assert result.skipped == []


def test_L64b_skipped_checks_surface_in_the_verdict_coverage():
    from app.verdict import CombinedVerdict

    assert CombinedVerdict.model_fields["scanner_skipped"].default_factory() == []


def test_L64c_collector_maps_new_rds_and_ec2_fields(mocker):
    rds = MagicMock()
    rds.describe_db_instances.return_value = {"DBInstances": [
        {"DBInstanceIdentifier": "a", "MultiAZ": True, "EnabledCloudwatchLogsExports": ["postgresql"],
         "IAMDatabaseAuthenticationEnabled": False, "MonitoringInterval": 60, "AutoMinorVersionUpgrade": True},
        {"DBInstanceIdentifier": "b"},
    ]}
    rds.get_paginator.return_value.paginate.return_value = [{}]
    mocker.patch("app.aws_collector.boto3.client", return_value=rds)
    first, second = collect_rds(*KEYS, []).rds_instances
    assert (first.multi_az, first.log_exports, first.iam_auth_enabled, first.monitoring_interval,
            first.auto_minor_version_upgrade) == (True, ["postgresql"], False, 60, True)
    assert (second.multi_az, second.log_exports, second.iam_auth_enabled, second.monitoring_interval,
            second.auto_minor_version_upgrade) == (None, [], None, None, None)

    ec2 = MagicMock()
    states = {"i-1": {"State": "enabled"}, "i-2": {"State": "disabled"}, "i-3": {"State": "pending"}, "i-4": None}
    ec2.describe_instances.return_value = {"Reservations": [{"Instances": [
        {"InstanceId": i, "InstanceType": "t3.micro", "State": {"Name": "running"},
         **({"Monitoring": m} if m is not None else {})} for i, m in states.items()
    ]}]}
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_addresses.return_value = {"Addresses": []}
    ec2.get_paginator.return_value.paginate.return_value = [{}]
    other = MagicMock()
    other.describe_load_balancers.return_value = {"LoadBalancers": []}
    other.describe_auto_scaling_groups.return_value = {"AutoScalingGroups": []}
    mocker.patch("app.aws_collector.boto3.client", side_effect=lambda service, **_: ec2 if service == "ec2" else other)
    data = collect_ec2(*KEYS, [])
    assert [i.detailed_monitoring for i in data.instances] == [True, False, None, None]


def test_L64d_serializer_emits_known_values_and_reports_unknown():
    known = build_terraform(_rds_infra(
        multi_az=False, log_exports=[], iam_auth_enabled=True, monitoring_interval=0, auto_minor_version_upgrade=False,
    ))
    args = next(iter(known.tf["resource"]["aws_db_instance"].values()))
    assert (args["multi_az"], args["enabled_cloudwatch_logs_exports"], args["iam_database_authentication_enabled"],
            args["monitoring_interval"], args["auto_minor_version_upgrade"]) == (False, [], True, 0, False)
    unknown = build_terraform(_rds_infra())
    args = next(iter(unknown.tf["resource"]["aws_db_instance"].values()))
    attrs = ("multi_az", "enabled_cloudwatch_logs_exports", "iam_database_authentication_enabled",
             "monitoring_interval", "auto_minor_version_upgrade")
    assert not set(attrs) & set(args)
    omitted = {e["field"] for e in unknown.loss if e["kind"] == "omitted_field"}
    assert {"multi_az", "log_exports", "iam_auth_enabled", "monitoring_interval", "auto_minor_version_upgrade"} <= omitted

    ec2 = lambda **kw: build_terraform(AWSInfrastructure(  # noqa: E731
        region="r", ec2=EC2Data(instances=[EC2Instance(id="i-1", type="t3.micro", state="running", **kw)])))
    assert next(iter(ec2(detailed_monitoring=False).tf["resource"]["aws_instance"].values()))["monitoring"] is False
    out = ec2()
    assert "monitoring" not in next(iter(out.tf["resource"]["aws_instance"].values()))
    assert any(e.get("field") == "detailed_monitoring" for e in out.loss)


def test_L64e_instance_profile_is_emitted_as_the_profile_name():
    arn = "arn:aws:iam::123456789012:instance-profile/path/app-profile"
    out = build_terraform(AWSInfrastructure(region="r", ec2=EC2Data(instances=[
        EC2Instance(id="i-1", type="t3.micro", state="running", instance_profile_arn=arn)])))
    assert next(iter(out.tf["resource"]["aws_instance"].values()))["iam_instance_profile"] == "app-profile"
    assert not any(e.get("field") == "instance_profile_arn" for e in out.loss)
    role = build_terraform(AWSInfrastructure(region="r", ec2=EC2Data(instances=[
        EC2Instance(id="i-1", type="t3.micro", state="running", instance_profile_arn="arn:aws:iam::1:role/r")])))
    assert "iam_instance_profile" not in next(iter(role.tf["resource"]["aws_instance"].values()))
    assert any(e.get("field") == "instance_profile_arn" for e in role.loss)


def test_L64f_absent_log_exports_means_none_enabled_and_the_check_is_kept(monkeypatch):
    infra = _rds_infra(log_exports=[])
    assert next(iter(build_terraform(infra).tf["resource"]["aws_db_instance"].values()))["enabled_cloudwatch_logs_exports"] == []
    _stub_checkov(monkeypatch, infra, "CKV_AWS_129")
    result = scanners.run_checkov(infra)
    assert [f.check_id for f in result.findings] == ["CKV_AWS_129"] and result.skipped == []


def test_L64g_unknown_input_on_one_side_skips_the_check_on_both(monkeypatch):
    from app.verdict import combined_verdict

    base, branch = _rds_infra(multi_az=False), _rds_infra()
    name = next(iter(build_terraform(base).names))
    stdout = json.dumps({"results": {"failed_checks": [{
        "check_id": "CKV_AWS_157", "resource": f"aws_db_instance.{name}", "check_name": "stub"}]}})
    monkeypatch.setattr("app.scanners.subprocess.run", lambda *a, **k: SimpleNamespace(stdout=stdout, returncode=1))
    scanners.clear_scan_cache()
    verdict = combined_verdict(base, branch)
    assert not [f for f in verdict.scanner_added + verdict.scanner_removed if f.get("check_id") == "CKV_AWS_157"]
    assert [(e["check_id"], e["id"]) for e in verdict.scanner_skipped] == [("CKV_AWS_157", "db-1")]
