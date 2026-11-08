"""A Jarvis-shaped account (invented ids and names) produced by the REAL collectors under moto.

Shape (from the field notes): an S3 feed bucket served by a CloudFront distribution through origin access
control (behavior ``feed.xml`` on CachingOptimized, which does not forward Host), a DynamoDB table, three
Lambdas (publisher, door, sentinel) whose execution roles allow dynamodb Get/Put/DeleteItem on the table, and
EventBridge Scheduler schedules that are all DISABLED and target those Lambdas.

Everything the collectors read comes from moto, except what moto does not implement: CloudFront cache / origin
request policies and the origin access control on an origin are answered from canned provider-shaped responses
(the same technique tests/laws/test_cloudfront_laws.py uses). The account id is the invented 111122223333.
"""
from __future__ import annotations

import copy
import io
import json
import zipfile

import boto3
from botocore.client import BaseClient
from moto import mock_aws

from app.aws_collector import (
    collect_dynamodb, collect_iam, collect_lambda, collect_s3, collect_scheduler,
)
from app.cloudfront_distribution import collect_cloudfront
from app.models import AWSInfrastructure
from tests.laws.test_cloudfront_laws import (
    CACHING_OPTIMIZED, USE_ORIGIN_CACHE_CONTROL, _METHODS, _stub_policy_reads,
)

REGION = "ap-south-1"
ACCOUNT = "111122223333"
BUCKET = "acme-demo-feed-bucket"
TABLE = "acme-demo-episodes"
TABLE_ARN = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"
OAC = "E3OACDEMO00001"
ETAG = "E1ETAGDEMO0001"
FEED = "feed.xml"
LAMBDAS = {"publisher": "acme-demo-publisher", "door": "acme-demo-door", "sentinel": "acme-demo-sentinel"}
ROLES = {k: f"acme-demo-{k}-role" for k in LAMBDAS}
SCHEDULER_ROLE = "acme-demo-scheduler-role"
SCHEDULES = {"publisher": "acme-demo-publish-daily", "door": "acme-demo-door-hourly", "sentinel": "acme-demo-sentinel-watch"}
SCHEDULE_EXPRESSIONS = {"publisher": "cron(0 6 * * ? *)", "door": "rate(1 hour)", "sentinel": "rate(5 minutes)"}
DDB_ACTIONS = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]

ENV = {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
       "AWS_DEFAULT_REGION": REGION, "MOTO_ACCOUNT_ID": ACCOUNT}


def lambda_arn(kind):
    return f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{LAMBDAS[kind]}"


def role_arn(kind):
    return f"arn:aws:iam::{ACCOUNT}:role/{ROLES[kind]}"


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("handler.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def distribution_config(policy=CACHING_OPTIMIZED):
    behavior = {"TargetOriginId": "s3-feed", "ViewerProtocolPolicy": "redirect-to-https", "CachePolicyId": policy,
                "AllowedMethods": copy.deepcopy(_METHODS), "Compress": True}
    return {
        "CallerReference": "acme-demo-feed-1", "Comment": "demo podcast feed", "Enabled": True,
        "Aliases": {"Quantity": 1, "Items": ["feeds.acme-demo.example"]},
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3-feed", "DomainName": f"{BUCKET}.s3.{REGION}.amazonaws.com", "OriginAccessControlId": OAC,
            "S3OriginConfig": {"OriginAccessIdentity": ""}}]},
        "DefaultCacheBehavior": {**copy.deepcopy(behavior), "CachePolicyId": CACHING_OPTIMIZED},
        "CacheBehaviors": {"Quantity": 1, "Items": [{"PathPattern": FEED, **copy.deepcopy(behavior)}]},
        "PriceClass": "PriceClass_All", "WebACLId": "",
    }


def _trust(service):
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": f"{service}.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def build_aws(monkeypatch) -> AWSInfrastructure:
    """Create the account in moto and run the real collectors over it."""
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_bucket_tagging(Bucket=BUCKET, Tagging={"TagSet": [{"Key": "project", "Value": "demo"}]})
        s3.put_object(Bucket=BUCKET, Key=FEED, Body=b"<rss/>")

        ddb = boto3.client("dynamodb", region_name=REGION)
        ddb.create_table(TableName=TABLE, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")

        iam = boto3.client("iam", region_name=REGION)
        statement = [{"Effect": "Allow", "Action": DDB_ACTIONS, "Resource": TABLE_ARN}]
        for kind, name in ROLES.items():
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=_trust("lambda"))
            iam.put_role_policy(RoleName=name, PolicyName="table-access", PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statement}))
        iam.create_role(RoleName=SCHEDULER_ROLE, AssumeRolePolicyDocument=_trust("scheduler"))

        lam = boto3.client("lambda", region_name=REGION)
        for kind, name in LAMBDAS.items():
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn(kind), Handler="handler.handler",
                                Code={"ZipFile": _zip()}, Timeout=30)

        sch = boto3.client("scheduler", region_name=REGION)
        for kind, name in SCHEDULES.items():
            sch.create_schedule(Name=name, ScheduleExpression=SCHEDULE_EXPRESSIONS[kind], FlexibleTimeWindow={"Mode": "OFF"},
                                State="DISABLED", Target={"Arn": lambda_arn(kind),
                                                          "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/{SCHEDULER_ROLE}"})

        cf = boto3.client("cloudfront", region_name="us-east-1")
        config = distribution_config()
        created = cf.create_distribution_with_tags(DistributionConfigWithTags={"DistributionConfig": config, "Tags": {
            "Items": [{"Key": "project", "Value": "demo"}]}})["Distribution"]
        # moto drops origin access control; policy reads are not implemented: answer from canned provider-shaped data
        _stub_policy_reads(monkeypatch)
        real = BaseClient._make_api_call
        monkeypatch.setattr(BaseClient, "_make_api_call", lambda self, op, params: (
            {"DistributionConfig": {**config, "CallerReference": "acme-demo-feed-1"}, "ETag": ETAG}
            if op == "GetDistributionConfig" else real(self, op, params)))

        warnings: list[str] = []
        args = ("testing", "testing", "testing", REGION, warnings)
        s3_data, iam_data, lambda_data = collect_s3(*args), collect_iam(*args), collect_lambda(*args)
        ddb_data, sched_data, cf_data = collect_dynamodb(*args), collect_scheduler(*args), collect_cloudfront(*args)
        status = {}
        for part in (s3_data, iam_data, lambda_data, ddb_data, sched_data, cf_data):
            status.update(getattr(part, "collection_status", None) or {})
        infra = AWSInfrastructure(s3=s3_data, iam=iam_data, lambda_data=lambda_data, dynamodb=ddb_data, scheduler=sched_data,
                                  cloudfront=cf_data, collection=status, region=REGION, warnings=warnings,
                                  collected_at="2026-11-07T00:00:00+00:00")
    return infra
