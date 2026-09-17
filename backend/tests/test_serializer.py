import json

import json

from app.models import AWSInfrastructure, EC2Data, EC2Instance, RDSData, RDSInstance, S3Bucket, S3Data, SecurityGroup
from app.serializer import serialize_to_terraform, to_terraform_json_string


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
    instance = result["resource"]["aws_instance"]["i_123"]
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
    group = result["resource"]["aws_security_group"]["sg_web"]
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


def test_public_s3_has_public_access_companion_without_unknown_features():
    infra = AWSInfrastructure(s3=S3Data(buckets=[S3Bucket(name="public.data", is_public=True)]))

    resources = serialize_to_terraform(infra)["resource"]
    assert resources["aws_s3_bucket"]["public_data"] == {"bucket": "public.data"}
    assert resources["aws_s3_bucket_public_access_block"]["public_data"] == {
        "bucket": "public.data",
        "block_public_acls": False,
        "block_public_policy": False,
        "ignore_public_acls": False,
        "restrict_public_buckets": False,
    }
    assert "aws_s3_bucket_server_side_encryption_configuration" not in resources
    assert "aws_s3_bucket_versioning" not in resources


def test_s3_enabled_states_emit_companions_with_literal_bucket_names():
    infra = AWSInfrastructure(
        s3=S3Data(
            buckets=[
                S3Bucket(name="customer.data", encrypted=True, versioning_enabled=True),
                S3Bucket(name="customer-data", encrypted=False, versioning_enabled=None),
            ]
        )
    )

    resources = serialize_to_terraform(infra)["resource"]
    assert resources["aws_s3_bucket"]["customer_data"] == {"bucket": "customer.data"}
    assert resources["aws_s3_bucket"]["customer_data_1"] == {"bucket": "customer-data"}
    assert resources["aws_s3_bucket_server_side_encryption_configuration"]["customer_data"] == {
        "bucket": "customer.data",
        "rule": [
            {
                "apply_server_side_encryption_by_default": [
                    {"sse_algorithm": "AES256"}
                ]
            }
        ],
    }
    assert resources["aws_s3_bucket_versioning"]["customer_data"] == {
        "bucket": "customer.data",
        "versioning_configuration": [{"status": "Enabled"}],
    }
    assert "customer_data_1" not in resources["aws_s3_bucket_server_side_encryption_configuration"]
    assert "customer_data_1" not in resources["aws_s3_bucket_versioning"]


def test_rds_serializes_public_and_encryption_state():
    infra = AWSInfrastructure(
        rds=RDSData(
            rds_instances=[RDSInstance(id="prod-db", publicly_accessible=True, encrypted=True)]
        )
    )

    database = serialize_to_terraform(infra)["resource"]["aws_db_instance"]["prod_db"]
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
    assert list(first["resource"]["aws_instance"]) == ["id_one", "id_one_1"]
    assert to_terraform_json_string(infra) == to_terraform_json_string(infra)


def test_optional_instance_fields_are_omitted_when_unset():
    instance = EC2Instance(id="i-empty", type="t3.micro", state="stopped", imdsv2_required=False)
    result = serialize_to_terraform(AWSInfrastructure(ec2=EC2Data(instances=[instance])))
    args = result["resource"]["aws_instance"]["i_empty"]
    assert "metadata_options" not in args
    assert "subnet_id" not in args
    assert "vpc_security_group_ids" not in args
    assert "associate_public_ip_address" not in args
