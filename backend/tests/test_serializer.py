import json

import json

from app.models import AWSInfrastructure, EC2Data, EC2Instance, RDSData, RDSInstance, S3Bucket, S3Data, SecurityGroup
from app.serializer import EC2_INSTANCE, SECURITY_GROUP, S3_BUCKET, RDS_INSTANCE, serialize_to_terraform, terraform_name, to_terraform_json_string


def _n(tf_type, rtype, rid):
    return terraform_name(tf_type, rtype, rid)


def test_ec2_serializes_security_groups_and_imdsv2():
    infra = AWSInfrastructure(
        ec2=EC2Data(
            instances=[
                EC2Instance(
                    id="i-123",
                    type="t3.micro",
                    state="running",
                    subnet_id="subnet-1",
                    sg_ids=["sg-1"],
                    imdsv2_required=True,
                    has_public_ip=False,
                )
            ]
        )
    )

    result = serialize_to_terraform(infra)
    instance = result["resource"]["aws_instance"][_n("aws_instance", EC2_INSTANCE, "i-123")]
    assert instance["instance_type"] == "t3.micro"
    assert instance["subnet_id"] == "subnet-1"
    assert instance["vpc_security_group_ids"] == ["sg-1"]
    assert instance["metadata_options"] == [{"http_tokens": "required"}]
    assert instance["associate_public_ip_address"] is False


def test_security_group_ingress_rule_is_mapped_and_sorted():
    infra = AWSInfrastructure(
        ec2=EC2Data(
            security_groups=[
                SecurityGroup(
                    id="sg-web",
                    name="web",
                    rules=[
                        {
                            "from_port": 443,
                            "to_port": 443,
                            "protocol": "tcp",
                            "ip_ranges": ["10.0.0.0/8"],
                        },
                        {
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "ip_ranges": ["0.0.0.0/0"],
                            "ignored": "not emitted",
                        },
                    ],
                )
            ]
        )
    )

    result = serialize_to_terraform(infra)
    group = result["resource"]["aws_security_group"][_n("aws_security_group", SECURITY_GROUP, "sg-web")]
    assert group["name"] == "web"
    assert group["ingress"] == [
        {
            "from_port": 22,
            "to_port": 22,
            "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"],
        },
        {
            "from_port": 443,
            "to_port": 443,
            "protocol": "tcp",
            "cidr_blocks": ["10.0.0.0/8"],
        },
    ]
    assert "egress" not in group


def test_public_s3_emits_only_known_public_access_flags():
    infra = AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(
        name="public.data", is_public=True, block_public_acls=False, restrict_public_buckets=False)]))

    resources = serialize_to_terraform(infra)["resource"]
    bname = _n("aws_s3_bucket", S3_BUCKET, "public.data")
    assert resources["aws_s3_bucket"][bname] == {"bucket": "public.data"}
    assert resources["aws_s3_bucket_public_access_block"][_n("aws_s3_bucket_public_access_block", S3_BUCKET, "public.data")] == {
        "bucket": "${aws_s3_bucket.%s.id}" % bname,
        "block_public_acls": False,
        "restrict_public_buckets": False,
    }
    assert "aws_s3_bucket_server_side_encryption_configuration" not in resources
    assert "aws_s3_bucket_versioning" not in resources


def test_s3_enabled_states_emit_companions_referencing_the_bucket():
    infra = AWSInfrastructure(
        s3=S3Data(
            buckets=[
                S3Bucket(name="customer.data", encrypted=True, versioning_enabled=True),
                S3Bucket(name="customer-data", encrypted=False, versioning_enabled=None),
            ]
        )
    )

    resources = serialize_to_terraform(infra)["resource"]
    dotted = _n("aws_s3_bucket", S3_BUCKET, "customer.data")
    dashed = _n("aws_s3_bucket", S3_BUCKET, "customer-data")
    assert dotted != dashed
    assert resources["aws_s3_bucket"][dotted] == {"bucket": "customer.data"}
    assert resources["aws_s3_bucket"][dashed] == {"bucket": "customer-data"}
    ref = "${aws_s3_bucket.%s.id}" % dotted
    sse = resources["aws_s3_bucket_server_side_encryption_configuration"]
    assert sse[_n("aws_s3_bucket_server_side_encryption_configuration", S3_BUCKET, "customer.data")] == {
        "bucket": ref,
        "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
    }
    versioning = resources["aws_s3_bucket_versioning"]
    assert versioning[_n("aws_s3_bucket_versioning", S3_BUCKET, "customer.data")] == {
        "bucket": ref,
        "versioning_configuration": [{"status": "Enabled"}],
    }
    assert len(sse) == 1 and len(versioning) == 1


def test_rds_serializes_public_and_encryption_state():
    infra = AWSInfrastructure(
        rds=RDSData(
            rds_instances=[RDSInstance(id="prod-db", publicly_accessible=True, encrypted=True)]
        )
    )

    database = serialize_to_terraform(infra)["resource"]["aws_db_instance"][_n("aws_db_instance", RDS_INSTANCE, "prod-db")]
    assert database == {"publicly_accessible": True, "storage_encrypted": True}
    assert "identifier" not in database


def test_json_round_trip_has_top_level_resource():
    encoded = to_terraform_json_string(AWSInfrastructure())
    decoded = json.loads(encoded)
    assert list(decoded) == ["resource"]
    assert decoded == serialize_to_terraform(AWSInfrastructure())


def test_repeated_serialization_is_deterministic():
    infra = AWSInfrastructure(
        ec2=EC2Data(
            instances=[
                EC2Instance(id="id/one", type="t3.micro", state="running"),
                EC2Instance(id="id_one", type="t3.small", state="running"),
            ]
        )
    )
    first = serialize_to_terraform(infra)
    second = serialize_to_terraform(infra)
    assert first == second
    assert sorted(first["resource"]["aws_instance"]) == sorted(
        [_n("aws_instance", EC2_INSTANCE, "id/one"), _n("aws_instance", EC2_INSTANCE, "id_one")]
    )
    assert to_terraform_json_string(infra) == to_terraform_json_string(infra)


def test_optional_instance_fields_are_omitted_when_unset():
    instance = EC2Instance(id="i-empty", type="t3.micro", state="stopped", imdsv2_required=False)
    result = serialize_to_terraform(AWSInfrastructure(ec2=EC2Data(instances=[instance])))
    args = result["resource"]["aws_instance"][_n("aws_instance", EC2_INSTANCE, "i-empty")]
    assert "metadata_options" not in args
    assert "subnet_id" not in args
    assert "vpc_security_group_ids" not in args
    assert "associate_public_ip_address" not in args
