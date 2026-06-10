"""Tests for app/tf_parser.py — PR diff parsing and component config conversion."""
import pytest
from app.tf_parser import (
    parse_pr_diff,
    tf_change_to_component_config,
    TFChange,
    _clean_tf_value,
)


# -- SAMPLE DIFFS --------------------------------------------------

DIFF_ADD_SG = '''\
@@ -0,0 +1,15 @@
+resource "aws_security_group" "allow_ssh" {
+  name        = "allow-ssh"
+  description = "Allow SSH from anywhere"
+  vpc_id      = var.vpc_id
+
+  ingress {
+    from_port   = 22
+    to_port     = 22
+    protocol    = "tcp"
+    cidr_blocks = ["0.0.0.0/0"]
+  }
+
+  tags = {
+    Name = "allow-ssh"
+  }
+}
'''

DIFF_ADD_S3_PUBLIC = '''\
@@ -0,0 +1,5 @@
+resource "aws_s3_bucket" "public_assets" {
+  bucket = "my-public-assets"
+  acl    = "public-read"
+}
'''

DIFF_MODIFY_RDS = '''\
@@ -1,8 +1,8 @@
 resource "aws_db_instance" "main" {
   identifier          = "prod-db"
   engine              = "postgres"
-  publicly_accessible = false
+  publicly_accessible = true
   storage_encrypted   = true
   multi_az            = true
 }
'''

DIFF_DELETE_SG = '''\
@@ -1,10 +0,0 @@
-resource "aws_security_group" "old_sg" {
-  name = "old-sg"
-  ingress {
-    from_port   = 22
-    to_port     = 22
-    protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
-  }
-}
'''

DIFF_ADD_EC2_NO_IMDSV2 = '''\
@@ -0,0 +1,8 @@
+resource "aws_instance" "worker" {
+  ami           = "ami-abc123"
+  instance_type = "t3.large"
+
+  metadata_options {
+    http_tokens = "optional"
+  }
+}
'''


# -- PARSE TESTS ---------------------------------------------------

class TestParsePRDiff:
    def test_parse_added_sg(self):
        changes = parse_pr_diff(DIFF_ADD_SG, "security-groups.tf")
        assert len(changes) == 1
        assert changes[0].action == "add"
        assert changes[0].resource_type == "aws_security_group"
        assert changes[0].resource_name == "allow_ssh"
        assert changes[0].file_path == "security-groups.tf"
        assert changes[0].attributes.get("name") == "allow-ssh"

    def test_parse_added_s3_public(self):
        changes = parse_pr_diff(DIFF_ADD_S3_PUBLIC, "s3.tf")
        assert len(changes) == 1
        assert changes[0].action == "add"
        assert changes[0].resource_type == "aws_s3_bucket"
        assert changes[0].attributes.get("bucket") == "my-public-assets"
        assert changes[0].attributes.get("acl") == "public-read"

    def test_parse_modified_rds(self):
        changes = parse_pr_diff(DIFF_MODIFY_RDS, "rds.tf")
        assert len(changes) == 1
        assert changes[0].action == "modify"
        assert changes[0].resource_type == "aws_db_instance"
        assert changes[0].resource_name == "main"
        assert changes[0].attributes.get("publicly_accessible") == "true"

    def test_parse_deleted_sg(self):
        changes = parse_pr_diff(DIFF_DELETE_SG, "old.tf")
        assert len(changes) == 1
        assert changes[0].action == "delete"
        assert changes[0].resource_type == "aws_security_group"
        assert changes[0].resource_name == "old_sg"

    def test_parse_empty_diff(self):
        changes = parse_pr_diff("", "empty.tf")
        assert changes == []

    def test_parse_non_tf_changes(self):
        diff = '''\
@@ -1,3 +1,3 @@
 variable "region" {
-  default = "us-east-1"
+  default = "us-west-2"
 }
'''
        changes = parse_pr_diff(diff, "vars.tf")
        assert changes == []


# -- COMPONENT CONFIG CONVERSION -----------------------------------

class TestTFChangeToComponentConfig:
    def test_sg_to_component(self):
        change = TFChange(
            action="add",
            resource_type="aws_security_group",
            resource_name="allow_ssh",
            file_path="sg.tf",
            attributes={"name": "allow-ssh", "from_port": "22", "cidr_blocks": '["0.0.0.0/0"]'},
        )
        config = tf_change_to_component_config(change)
        assert config is not None
        assert config["component_type"] == "security_group"
        assert config["tf_source"]["resource_name"] == "allow_ssh"
        assert config["tf_source"]["action"] == "add"

    def test_s3_public_to_component(self):
        change = TFChange(
            action="add",
            resource_type="aws_s3_bucket",
            resource_name="public_assets",
            file_path="s3.tf",
            attributes={"bucket": "my-public-assets", "acl": "public-read"},
        )
        config = tf_change_to_component_config(change)
        assert config is not None
        assert config["component_type"] == "s3_bucket"
        assert config["config"]["is_public"] is True

    def test_rds_to_component(self):
        change = TFChange(
            action="modify",
            resource_type="aws_db_instance",
            resource_name="main",
            file_path="rds.tf",
            attributes={"publicly_accessible": "true", "storage_encrypted": "true"},
        )
        config = tf_change_to_component_config(change)
        assert config is not None
        assert config["component_type"] == "rds_instance"
        assert config["config"]["publicly_accessible"] is True
        assert config["config"]["encrypted"] is True

    def test_ec2_to_component(self):
        change = TFChange(
            action="add",
            resource_type="aws_instance",
            resource_name="worker",
            file_path="ec2.tf",
            attributes={"instance_type": "t3.large", "http_tokens": "optional"},
        )
        config = tf_change_to_component_config(change)
        assert config is not None
        assert config["component_type"] == "ec2_instance"
        assert config["config"]["instance_type"] == "t3.large"
        assert config["config"]["imdsv2_required"] is False

    def test_lambda_to_component(self):
        change = TFChange(
            action="add",
            resource_type="aws_lambda_function",
            resource_name="processor",
            file_path="lambda.tf",
            attributes={"function_name": "data-processor", "runtime": "python3.11"},
        )
        config = tf_change_to_component_config(change)
        assert config is not None
        assert config["component_type"] == "lambda_function"
        assert config["config"]["function_name"] == "data-processor"

    def test_unknown_resource_type_returns_none(self):
        change = TFChange(
            action="add",
            resource_type="aws_route53_zone",
            resource_name="main",
            file_path="dns.tf",
            attributes={"name": "example.com"},
        )
        config = tf_change_to_component_config(change)
        assert config is None


# -- UTILITY TESTS -------------------------------------------------

class TestCleanTFValue:
    def test_removes_quotes(self):
        assert _clean_tf_value('"hello"') == "hello"

    def test_removes_trailing_comment(self):
        assert _clean_tf_value('"value" # comment') == "value"

    def test_removes_trailing_comma(self):
        assert _clean_tf_value('"value",') == "value"

    def test_strips_whitespace(self):
        assert _clean_tf_value('  "value"  ') == "value"

    def test_plain_value(self):
        assert _clean_tf_value("true") == "true"
