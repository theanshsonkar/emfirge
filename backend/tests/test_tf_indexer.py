"""Tests for app/tf_indexer.py — TF file parsing and resource matching."""
import pytest
from app.tf_indexer import (
    parse_tf_content,
    find_resource_match,
    TFResource,
    _extract_block,
    _extract_identifiers,
)


# -- SAMPLE TF CONTENT ---------------------------------------------

SAMPLE_SG_TF = '''
resource "aws_security_group" "ssh_open" {
  name        = "ssh-open-sg"
  description = "Allow SSH from anywhere"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ssh-open-sg"
    Env  = "prod"
  }
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Allow HTTPS"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

SAMPLE_S3_TF = '''
resource "aws_s3_bucket" "prod_data" {
  bucket = "prod-data-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  tags = {
    Name = "prod-data"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "company-logs-2024"
}
'''

SAMPLE_RDS_TF = '''
resource "aws_db_instance" "main_db" {
  identifier          = "prod-postgres"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = false
  storage_encrypted   = true
  multi_az            = true
}
'''

SAMPLE_EC2_TF = '''
resource "aws_instance" "web_server" {
  ami           = "ami-0123456789"
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.public.id

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "web-server-prod"
  }
}
'''

SAMPLE_LAMBDA_TF = '''
resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  runtime       = "python3.11"
  handler       = "main.handler"
  role          = aws_iam_role.lambda_role.arn
}
'''


# -- PARSE TESTS ---------------------------------------------------

class TestParseTFContent:
    def test_parse_security_groups(self):
        resources = parse_tf_content(SAMPLE_SG_TF, "security-groups.tf")
        assert len(resources) == 2
        assert resources[0].resource_type == "aws_security_group"
        assert resources[0].resource_name == "ssh_open"
        assert resources[0].file_path == "security-groups.tf"
        assert resources[0].identifiers.get("name") == "ssh-open-sg"

    def test_parse_s3_buckets(self):
        resources = parse_tf_content(SAMPLE_S3_TF, "s3.tf")
        assert len(resources) == 2
        assert resources[0].resource_type == "aws_s3_bucket"
        assert resources[0].resource_name == "prod_data"
        assert resources[0].identifiers.get("bucket") == "prod-data-bucket"
        assert resources[1].identifiers.get("bucket") == "company-logs-2024"

    def test_parse_rds(self):
        resources = parse_tf_content(SAMPLE_RDS_TF, "rds.tf")
        assert len(resources) == 1
        assert resources[0].resource_type == "aws_db_instance"
        assert resources[0].identifiers.get("identifier") == "prod-postgres"

    def test_parse_ec2_with_tags(self):
        resources = parse_tf_content(SAMPLE_EC2_TF, "ec2.tf")
        assert len(resources) == 1
        assert resources[0].resource_type == "aws_instance"
        assert resources[0].resource_name == "web_server"
        assert resources[0].identifiers.get("tags.Name") == "web-server-prod"

    def test_parse_lambda(self):
        resources = parse_tf_content(SAMPLE_LAMBDA_TF, "lambda.tf")
        assert len(resources) == 1
        assert resources[0].identifiers.get("function_name") == "data-processor"

    def test_parse_empty_content(self):
        resources = parse_tf_content("", "empty.tf")
        assert resources == []

    def test_parse_no_resources(self):
        content = '''
variable "vpc_id" {
  type = string
}

output "sg_id" {
  value = aws_security_group.ssh_open.id
}
'''
        resources = parse_tf_content(content, "vars.tf")
        assert resources == []

    def test_line_numbers_correct(self):
        resources = parse_tf_content(SAMPLE_SG_TF, "sg.tf")
        # First resource starts at line 2 (1-indexed, after blank line)
        assert resources[0].line_number == 2
        # Second resource starts later
        assert resources[1].line_number > resources[0].line_number

    def test_block_content_captured(self):
        resources = parse_tf_content(SAMPLE_RDS_TF, "rds.tf")
        assert "prod-postgres" in resources[0].block_content
        assert "db.t3.medium" in resources[0].block_content


# -- MATCHING TESTS ------------------------------------------------

class TestFindResourceMatch:
    @pytest.fixture
    def index(self):
        """Build a sample index from all sample TF files."""
        resources = []
        resources.extend(parse_tf_content(SAMPLE_SG_TF, "security-groups.tf"))
        resources.extend(parse_tf_content(SAMPLE_S3_TF, "s3.tf"))
        resources.extend(parse_tf_content(SAMPLE_RDS_TF, "rds.tf"))
        resources.extend(parse_tf_content(SAMPLE_EC2_TF, "ec2.tf"))
        resources.extend(parse_tf_content(SAMPLE_LAMBDA_TF, "lambda.tf"))
        return resources

    def test_exact_match_sg_name(self, index):
        match = find_resource_match(index, "ssh-open-sg")
        assert match is not None
        assert match.resource_name == "ssh_open"
        assert match.file_path == "security-groups.tf"

    def test_exact_match_s3_bucket(self, index):
        match = find_resource_match(index, "prod-data-bucket")
        assert match is not None
        assert match.resource_type == "aws_s3_bucket"

    def test_exact_match_rds_identifier(self, index):
        match = find_resource_match(index, "prod-postgres")
        assert match is not None
        assert match.resource_type == "aws_db_instance"

    def test_exact_match_lambda_function_name(self, index):
        match = find_resource_match(index, "data-processor")
        assert match is not None
        assert match.resource_type == "aws_lambda_function"

    def test_partial_match_s3(self, index):
        # "prod-data" is contained in "prod-data-bucket"
        match = find_resource_match(index, "prod-data")
        assert match is not None
        assert match.resource_type == "aws_s3_bucket"

    def test_tag_name_match_ec2(self, index):
        match = find_resource_match(index, "web-server-prod")
        assert match is not None
        assert match.resource_type == "aws_instance"

    def test_resource_name_fallback(self, index):
        # "web-sg" matches the resource_name "web" after normalization
        match = find_resource_match(index, "web-sg")
        assert match is not None
        assert match.resource_name == "web"

    def test_no_match_returns_none(self, index):
        match = find_resource_match(index, "nonexistent-resource-xyz")
        assert match is None

    def test_aws_service_filter(self, index):
        # Should find the S3 bucket when aws_service="s3"
        match = find_resource_match(index, "logs-2024", aws_service="s3")
        assert match is not None
        assert match.resource_type == "aws_s3_bucket"

    def test_case_insensitive_match(self, index):
        match = find_resource_match(index, "SSH-OPEN-SG")
        assert match is not None
        assert match.resource_name == "ssh_open"


# -- EDGE CASES ----------------------------------------------------

class TestEdgeCases:
    def test_nested_braces(self):
        content = '''
resource "aws_security_group" "complex" {
  name = "complex-sg"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        resources = parse_tf_content(content, "complex.tf")
        assert len(resources) == 1
        assert "egress" in resources[0].block_content

    def test_multiple_files_same_resource_type(self):
        content1 = 'resource "aws_s3_bucket" "a" {\n  bucket = "bucket-a"\n}\n'
        content2 = 'resource "aws_s3_bucket" "b" {\n  bucket = "bucket-b"\n}\n'
        r1 = parse_tf_content(content1, "a.tf")
        r2 = parse_tf_content(content2, "b.tf")
        index = r1 + r2
        match = find_resource_match(index, "bucket-b")
        assert match is not None
        assert match.file_path == "b.tf"

    def test_resource_with_count(self):
        content = '''
resource "aws_instance" "web" {
  count         = 3
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    Name = "web-server"
  }
}
'''
        resources = parse_tf_content(content, "ec2.tf")
        assert len(resources) == 1
        assert resources[0].identifiers.get("tags.Name") == "web-server"
