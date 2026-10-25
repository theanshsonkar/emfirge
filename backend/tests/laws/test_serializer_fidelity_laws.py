"""L60 serializer fidelity: the Terraform handed to scanners links resources by
reference, names them from (type, id) alone, maps results back to Emfirge
resources, and reports everything it omits or synthesizes."""
from __future__ import annotations

from app.models import (
    AWSInfrastructure, EC2Data, EC2Instance, RDSData, RDSInstance, S3Bucket, S3Data, SecurityGroup,
)
from app.serializer import (
    EC2_INSTANCE, EMITTED_COLLECTIONS, FIELD_MAP, RDS_INSTANCE, S3_BUCKET, SECURITY_GROUP,
    build_terraform, collections, terraform_name,
)
from tests.incidents.synthetic_base import load_synthetic_base

MODELS = {EC2_INSTANCE: EC2Instance, SECURITY_GROUP: SecurityGroup, S3_BUCKET: S3Bucket, RDS_INSTANCE: RDSInstance}
TAGS = {"env": "prod"}


def _full_infra() -> AWSInfrastructure:
    return AWSInfrastructure(
        ec2=EC2Data(
            instances=[EC2Instance(
                id="i-1", type="t3.micro", state="running", subnet_id="subnet-1", sg_ids=["sg-1"],
                imdsv2_required=True, has_public_ip=False, instance_profile_arn="arn:aws:iam::1:instance-profile/p", detailed_monitoring=True, tags=TAGS,
            )],
            security_groups=[SecurityGroup(
                id="sg-1", name="web", attached_to=["i-1"], tags=TAGS, egress_rules=[{"protocol": "-1", "ip_ranges": ["0.0.0.0/0"]}],
                rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "ip_ranges": ["0.0.0.0/0"]}],
            )],
        ),
        s3=S3Data(buckets=[S3Bucket(
            name="b.1", is_public=False, policy='{"Version":"2012-10-17"}', encrypted=True, versioning_enabled=True,
            acl_public=False, policy_public=False, block_public_acls=True, ignore_public_acls=True,
            block_public_policy=True, restrict_public_buckets=True, tags=TAGS,
        )]),
        rds=RDSData(rds_instances=[RDSInstance(
            id="db-1", sg_ids=["sg-1"], subnet_id="subnet-1", publicly_accessible=False, encrypted=True,
            engine="postgres", port=5432, backup_retention_days=7, deletion_protection=True,
            multi_az=True, log_exports=["postgresql"], iam_auth_enabled=True, monitoring_interval=60,
            auto_minor_version_upgrade=True, tags=TAGS,
        )]),
    )


def _all_args(tf):
    return {arg for group in tf["resource"].values() for args in group.values() for arg in args} | set(tf["resource"])


def test_L60a_every_model_field_is_emitted_or_reported():
    for resource_type, model in MODELS.items():
        # A new model field must be classified in FIELD_MAP before this passes.
        assert set(model.model_fields) == set(FIELD_MAP[resource_type]), resource_type
    out = build_terraform(_full_infra())
    emitted = _all_args(out.tf)
    reported = {(e["resource_type"], e.get("field")) for e in out.loss if e.get("kind") == "omitted_field"}
    for resource_type, fields in FIELD_MAP.items():
        for field_name, spec in fields.items():
            if spec[0] == "loss":
                assert (resource_type, field_name) in reported, (resource_type, field_name)
            elif spec[0] == "emit":
                assert spec[1] in emitted, (resource_type, field_name)
                assert (resource_type, field_name) not in reported, (resource_type, field_name)
    # Unknown (None) values on report_none fields are reported, not guessed.
    bare = AWSInfrastructure(
        ec2=EC2Data(instances=[EC2Instance(id="i-2", type="t3.micro", state="running")]),
        rds=RDSData(rds_instances=[RDSInstance(id="db-2")]),
    )
    gaps = {(e["resource_type"], e["field"]) for e in build_terraform(bare).loss if e.get("kind") == "omitted_field"}
    assert (EC2_INSTANCE, "has_public_ip") in gaps and (EC2_INSTANCE, "tags") in gaps
    assert (RDS_INSTANCE, "port") in gaps and (RDS_INSTANCE, "backup_retention_days") in gaps


def test_L60b_every_unemitted_collected_resource_is_reported():
    base = load_synthetic_base("delete")
    out = build_terraform(base)
    reported = {(e["resource_type"], e["id"]) for e in out.loss if e.get("kind") == "omitted_resource"}
    seen = 0
    for section, list_name, items in collections(base):
        if (section, list_name) in EMITTED_COLLECTIONS:
            continue
        resource_type = f"{section}.{list_name}" if section else list_name
        count = sum(1 for e in out.loss if e.get("kind") == "omitted_resource" and e["resource_type"] == resource_type)
        assert count == len(items), resource_type
        seen += len(items)
    assert seen > 0 and len(reported) > 0


def test_L60c_names_are_deterministic_and_independent_of_other_resources():
    infra = _full_infra()
    first = build_terraform(infra)
    assert first.tf == build_terraform(infra).tf
    bigger = _full_infra()
    bigger.ec2.instances.insert(0, EC2Instance(id="i/1", type="t3.micro", state="running"))
    bigger.ec2.instances.append(EC2Instance(id="i_1", type="t3.micro", state="running"))
    bigger.s3.buckets.insert(0, S3Bucket(name="b-1"))
    second = build_terraform(bigger)
    assert set(first.names) <= set(second.names)
    for name in first.names:
        assert second.names[name] == first.names[name]
    # Ids that sanitize alike still get distinct names; types never collide.
    assert terraform_name("aws_instance", EC2_INSTANCE, "i/1") != terraform_name("aws_instance", EC2_INSTANCE, "i_1")
    assert len(second.names) == len(set(second.names))


def test_L60d_links_are_references_when_target_is_in_input():
    out = build_terraform(_full_infra())
    res = out.tf["resource"]
    (bucket_name,) = res["aws_s3_bucket"]
    (sg_name,) = res["aws_security_group"]
    for tf_type in (
        "aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_versioning", "aws_s3_bucket_policy",
    ):
        (args,) = res[tf_type].values()
        assert args["bucket"] == f"${{aws_s3_bucket.{bucket_name}.id}}"
    ref = [f"${{aws_security_group.{sg_name}.id}}"]
    assert next(iter(res["aws_instance"].values()))["vpc_security_group_ids"] == ref
    assert next(iter(res["aws_db_instance"].values()))["vpc_security_group_ids"] == ref
    # A group outside the input stays a literal id.
    lone = AWSInfrastructure(ec2=EC2Data(instances=[EC2Instance(id="i-3", type="t", state="running", sg_ids=["sg-x"])]))
    assert next(iter(build_terraform(lone).tf["resource"]["aws_instance"].values()))["vpc_security_group_ids"] == ["sg-x"]


def test_L60e_name_mapping_round_trips():
    out = build_terraform(load_synthetic_base("delete"))
    emitted = {(t, n) for t, group in out.tf["resource"].items() for n in group}
    assert {n for _, n in emitted} == set(out.names)
    for _, name in emitted:
        resource_type, rid = out.names[name]
        assert resource_type in MODELS
        assert name.endswith(terraform_name("aws_instance", resource_type, rid)[-8:])


def test_L60f_known_bpa_flags_exact_unknown_absent_and_reported():
    flags = {"block_public_acls": True, "ignore_public_acls": False}
    infra = AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(name="p", **flags)]))
    out = build_terraform(infra)
    (pab,) = out.tf["resource"]["aws_s3_bucket_public_access_block"].values()
    assert {k: v for k, v in pab.items() if k != "bucket"} == flags
    missing = {e["field"] for e in out.loss if e.get("kind") == "omitted_field" and e["resource_type"] == S3_BUCKET}
    assert {"block_public_policy", "restrict_public_buckets"} <= missing
    assert not ({"block_public_acls", "ignore_public_acls"} & missing)
    none_known = build_terraform(AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(name="q")])))
    assert "aws_s3_bucket_public_access_block" not in none_known.tf["resource"]
    assert set(_f for _f in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")) <= {
        e["field"] for e in none_known.loss if e.get("kind") == "omitted_field"
    }


def test_L60g_dropped_rule_keys_are_reported():
    infra = AWSInfrastructure(ec2=EC2Data(security_groups=[
        SecurityGroup(id="sg-9", name="n", rules=[{"protocol": "tcp", "source_sg_ids": ["sg-1"]}])
    ]))
    reasons = [e["reason"] for e in build_terraform(infra).loss if e.get("field") == "rules"]
    assert any("source_sg_ids" in r for r in reasons)
