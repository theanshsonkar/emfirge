"""The deploy keeps the S3 role template equal to the repo's (the stale-template incident, 2026-11-08)."""
import importlib.util
from pathlib import Path

import boto3
from moto import mock_aws

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sync_role_template", ROOT / "scripts" / "sync_role_template.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_uploads_when_different_and_skips_when_current():
    template = ROOT / "cloudformation" / "iam-role.yaml"
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="tpl")
        s3.put_object(Bucket="tpl", Key=mod.KEY, Body=b"old template")
        assert mod.sync(template, s3, "tpl") == "updated"
        assert s3.get_object(Bucket="tpl", Key=mod.KEY)["Body"].read() == template.read_bytes()
        assert mod.sync(template, s3, "tpl") == "current"
