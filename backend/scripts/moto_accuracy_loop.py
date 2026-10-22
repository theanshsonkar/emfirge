"""Accuracy loop against a Moto account: predict on a branch, apply for real, re-scan, compare.

Moto stores configuration but does not simulate networking or IAM evaluation, so this
measures shape accuracy (did the account end up as the branch predicted) and verdict
consistency (does the re-scanned account get the predicted verdict). It does not measure
verdict correctness; that still needs a real throwaway account (ACCURACY-LOOP-PLAN.md).

The real change is applied with plain boto3 calls, never with Emfirge's own hand-back,
so the prediction is checked against an independent path.

Run from backend/: python -m scripts.moto_accuracy_loop
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable

REGION = "ap-south-1"
_CREDS = ("testing", "testing", "testing")

# Fields the branch model claims to predict, per resource type. Anything outside this
# list is not part of the shape claim.
_SHAPE_FIELDS = {
    "ec2_instance": ("type", "subnet_id", "sg_ids", "state", "has_public_ip"),
    "security_group": ("name", "rules", "egress_rules"),
    "iam_role": ("access_statements", "trusted_services", "trusted_role_arns"),
    "s3_bucket": ("is_public", "policy", "acl_public", "policy_public", "block_public_acls",
                  "ignore_public_acls", "block_public_policy", "restrict_public_buckets"),
}


def _client(service: str):
    import boto3
    return boto3.client(service, region_name=REGION)


def _scan():
    from app.aws_collector import collect_ec2, collect_iam, collect_s3, collect_vpc
    from app.models import AWSInfrastructure
    warnings: list = []
    return AWSInfrastructure(
        region=REGION,
        ec2=collect_ec2(*_CREDS, REGION, warnings),
        vpc=collect_vpc(*_CREDS, REGION, warnings),
        iam=collect_iam(*_CREDS, REGION, warnings),
        s3=collect_s3(*_CREDS, REGION, warnings),
    )


def _build_account() -> dict[str, str]:
    """A small account: public subnet with an IGW route, a web server, a role, a bucket."""
    ec2, iam, s3 = _client("ec2"), _client("iam"), _client("s3")
    vpc = ec2.create_vpc(CidrBlock="10.50.0.0/16")["Vpc"]["VpcId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    public = ec2.create_subnet(VpcId=vpc, CidrBlock="10.50.1.0/24", AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    private = ec2.create_subnet(VpcId=vpc, CidrBlock="10.50.2.0/24", AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=public, MapPublicIpOnLaunch={"Value": True})
    table = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=table, SubnetId=public)
    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    unused = ec2.create_security_group(GroupName="unused", Description="unused", VpcId=vpc)["GroupId"]
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.create_instance_profile(InstanceProfileName="app")
    iam.add_role_to_instance_profile(InstanceProfileName="app", RoleName="app")
    instance = ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
                                 SubnetId=public, SecurityGroupIds=[web],
                                 IamInstanceProfile={"Name": "app"})["Instances"][0]["InstanceId"]
    s3.create_bucket(Bucket="acc-data", CreateBucketConfiguration={"LocationConstraint": REGION})
    return {"vpc": vpc, "public": public, "private": private, "web": web, "unused": unused,
            "role_arn": role_arn, "instance": instance, "bucket": "acc-data"}


def _sg_rules(base, group_id: str) -> list[dict]:
    group = next(item for item in base.ec2.security_groups if item.id == group_id)
    return [dict(rule) if isinstance(rule, dict) else rule.model_dump() for rule in group.rules]


_SSH_WORLD = {"protocol": "tcp", "from_port": 22, "to_port": 22, "ip_ranges": ["0.0.0.0/0"], "source_sg_ids": []}
_PUBLIC_POLICY = lambda bucket: json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]})


def _scenarios() -> list[dict[str, Any]]:
    """The six-scenario matrix from ACCURACY-LOOP-PLAN.md; each gives the branch change and the real apply."""
    from app.mutations import Change

    def open_ssh(ids, base):
        change = Change(op="modify", resource_type="security_group", resource_id=ids["web"],
                        fields={"rules": _sg_rules(base, ids["web"]) + [_SSH_WORLD]})
        def real():
            _client("ec2").authorize_security_group_ingress(GroupId=ids["web"], IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        return [change], real

    def close_ssh(ids, base):
        open_ssh(ids, base)[1]()  # start from the opened state, then close it
        return None

    def admin_policy(ids, base):
        change = Change(op="modify", resource_type="iam_role_policy", resource_id=ids["role_arn"], fields={
            "access_statements": [{"effect": "allow", "actions": ["*"], "resources": ["*"]}]})
        def real():
            _client("iam").attach_role_policy(RoleName="app", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        return [change], real

    def public_bucket(ids, base):
        policy = _PUBLIC_POLICY(ids["bucket"])
        change = Change(op="modify", resource_type="s3_bucket", resource_id=ids["bucket"], fields={"policy": policy})
        def real():
            _client("s3").put_bucket_policy(Bucket=ids["bucket"], Policy=policy)
        return [change], real

    def second_instance(ids, base):
        change = Change(op="add", resource_type="ec2_instance", resource_id="", fields={
            "type": "t3.micro", "subnet_id": ids["private"], "sg_ids": [ids["web"]], "state": "running",
            "has_public_ip": False})
        def real():
            _client("ec2").run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
                                         SubnetId=ids["private"], SecurityGroupIds=[ids["web"]])
        return [change], real

    def delete_unused_sg(ids, base):
        change = Change(op="delete", resource_type="security_group", resource_id=ids["unused"], fields={})
        def real():
            _client("ec2").delete_security_group(GroupId=ids["unused"])
        return [change], real

    def close_ssh_change(ids, base):
        rules = [rule for rule in _sg_rules(base, ids["web"]) if rule.get("from_port") != 22]
        change = Change(op="modify", resource_type="security_group", resource_id=ids["web"], fields={"rules": rules})
        def real():
            _client("ec2").revoke_security_group_ingress(GroupId=ids["web"], IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        return [change], real

    return [
        {"id": 1, "name": "Open SG ingress 22 to 0.0.0.0/0", "lens": "reachability / security", "plan": open_ssh},
        {"id": 2, "name": "Close that SG rule again", "lens": "reachability", "setup": close_ssh, "plan": close_ssh_change},
        {"id": 3, "name": "Attach an admin policy to a role", "lens": "IAM privilege escalation", "plan": admin_policy},
        {"id": 4, "name": "Make an S3 bucket public", "lens": "security / reachability", "plan": public_bucket},
        {"id": 5, "name": "Add a second EC2 in another subnet", "lens": "shape only", "plan": second_instance},
        {"id": 6, "name": "Delete an unused SG", "lens": "shape / blast radius", "plan": delete_unused_sg},
    ]


def _normal(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, list):
        return sorted((_normal(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, dict):
        return {key: _normal(item) for key, item in sorted(value.items())}
    if isinstance(value, str) and value.startswith("{"):
        try:
            return _normal(json.loads(value))
        except ValueError:
            return value
    return value


def _inventory(infra, base) -> dict[str, dict[str, Any]]:
    """Every modeled resource with its shape fields; ids not in the base are keyed by content."""
    rows = []
    for item in infra.ec2.instances:
        rows.append(("ec2_instance", item.id, item))
    for item in infra.ec2.security_groups:
        rows.append(("security_group", item.id, item))
    for item in infra.iam.role_policies:
        rows.append(("iam_role", item.role_arn, item))
    for item in infra.s3.buckets:
        rows.append(("s3_bucket", item.name, item))
    base_ids = {key for key in _inventory_keys(base)}
    result: dict[str, dict[str, Any]] = {}
    for typ, ident, item in rows:
        fields = {field: _normal(getattr(item, field, None)) for field in _SHAPE_FIELDS[typ]}
        key = f"{typ}:{ident}" if f"{typ}:{ident}" in base_ids else f"{typ}:new:{json.dumps(fields, sort_keys=True)}"
        result[key] = fields
    return result


def _inventory_keys(infra) -> set[str]:
    return ({f"ec2_instance:{x.id}" for x in infra.ec2.instances}
            | {f"security_group:{x.id}" for x in infra.ec2.security_groups}
            | {f"iam_role:{x.role_arn}" for x in infra.iam.role_policies}
            | {f"s3_bucket:{x.name}" for x in infra.s3.buckets})


def _shape_diff(predicted: dict, actual: dict) -> list[str]:
    problems = []
    for key in sorted(set(predicted) | set(actual)):
        if key not in actual:
            problems.append(f"predicted but missing after apply: {key}")
        elif key not in predicted:
            problems.append(f"appeared after apply but not predicted: {key}")
        else:
            for field in sorted(predicted[key]):
                if predicted[key][field] != actual[key][field]:
                    problems.append(f"{key}.{field}: predicted {predicted[key][field]!r}, actual {actual[key][field]!r}")
    return problems


def _verdict_summary(base, after) -> dict[str, Any]:
    from app.verdict import combined_verdict
    result = combined_verdict(base, after, run_scanners=False)
    return {"verdict": result.verdict, "reasons": sorted({item["code"] for item in result.reasons})}


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Run one scenario in a fresh Moto account and report shape and verdict agreement."""
    from moto import mock_aws
    from app.mutations import apply_changes

    os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        ids = _build_account()
        if scenario.get("setup"):
            scenario["setup"](ids, _scan())
        base = _scan()
        changes, real = scenario["plan"](ids, base)
        predicted = apply_changes(base, changes)
        predicted_verdict = _verdict_summary(base, predicted)
        real()
        actual = _scan()
        actual_verdict = _verdict_summary(base, actual)
        problems = _shape_diff(_inventory(predicted, base), _inventory(actual, base))
    return {
        "id": scenario["id"], "name": scenario["name"], "lens": scenario["lens"],
        "shape_match": not problems, "shape_problems": problems,
        "predicted_verdict": predicted_verdict, "actual_verdict": actual_verdict,
        "verdict_consistent": predicted_verdict == actual_verdict,
        # Moto cannot probe whether a port is reachable or a policy really escalates.
        "verdict_correctness": "not measurable in Moto",
    }


def run() -> list[dict[str, Any]]:
    return [run_scenario(scenario) for scenario in _scenarios()]


def report(results: list[dict[str, Any]]) -> str:
    shape = sum(item["shape_match"] for item in results)
    consistent = sum(item["verdict_consistent"] for item in results)
    lines = [
        f"Shape accuracy (Moto): {shape}/{len(results)}",
        f"Verdict consistency (Moto): {consistent}/{len(results)}",
        "Verdict correctness: not measured (Moto does not simulate reachability or IAM evaluation)",
        "",
        "| # | Change | Lens | Shape | Predicted verdict | Re-scanned verdict |",
        "|---|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(f"| {item['id']} | {item['name']} | {item['lens']} | {'match' if item['shape_match'] else 'MISMATCH'} | "
                     f"{item['predicted_verdict']['verdict']} {item['predicted_verdict']['reasons']} | "
                     f"{item['actual_verdict']['verdict']} {item['actual_verdict']['reasons']} |")
        for problem in item["shape_problems"]:
            lines.append(f"|   |   |   | {problem} | | |")
    return "\n".join(lines)


def _offline_env() -> None:
    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                       "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        os.environ[key] = value


if __name__ == "__main__":
    _offline_env()
    print(report(run()))
