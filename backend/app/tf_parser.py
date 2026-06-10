"""
Terraform Parser — converts TF resource definitions from PR diffs into
Emfirge-compatible component configs for simulation.

Used by Phase 3 (CI/CD Gate) to parse what resources are being added/modified
in a PR, then simulate them against the last scan.
"""

import re
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class TFChange:
    """A resource change detected in a PR diff."""
    action: str                 # "add" | "modify" | "delete"
    resource_type: str          # e.g. "aws_security_group"
    resource_name: str          # e.g. "allow_ssh"
    file_path: str              # e.g. "infra/security-groups.tf"
    attributes: dict = field(default_factory=dict)
    # For "modify": only the changed attributes
    # For "add": all attributes in the new block


# Maps TF resource types to Emfirge component_type for simulation
TF_TO_EMFIRGE_TYPE = {
    "aws_security_group": "security_group",
    "aws_s3_bucket": "s3_bucket",
    "aws_s3_bucket_public_access_block": "s3_bucket",
    "aws_s3_bucket_versioning": "s3_bucket",
    "aws_s3_bucket_server_side_encryption_configuration": "s3_bucket",
    "aws_db_instance": "rds_instance",
    "aws_instance": "ec2_instance",
    "aws_lambda_function": "lambda_function",
    "aws_lb": "load_balancer",
    "aws_alb": "load_balancer",
    "aws_wafv2_web_acl": "waf",
    "aws_guardduty_detector": "guardduty",
    "aws_iam_role": "iam_role",
    "aws_iam_user": "iam_user",
    "aws_vpc": "vpc",
    "aws_subnet": "subnet",
}

# Regex for unified diff hunk headers
_HUNK_RE = re.compile(r'^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@')

# Regex for resource block start in diff context
_RESOURCE_RE = re.compile(r'^[+\- ]?resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')

# Regex for added resource block (only matches + prefixed lines)
_ADDED_RESOURCE_RE = re.compile(r'^\+resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')

# Regex for deleted resource block (only matches - prefixed lines)
_DELETED_RESOURCE_RE = re.compile(r'^-resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')

# Regex for attribute in diff (added lines)
_ADDED_ATTR_RE = re.compile(r'^\+\s*(\w+)\s*=\s*(.+)$')

# Regex for removed attribute lines
_REMOVED_ATTR_RE = re.compile(r'^-\s*(\w+)\s*=\s*(.+)$')


def parse_pr_diff(diff_text: str, file_path: str) -> list[TFChange]:
    """
    Parse a unified diff of a .tf file and extract resource changes.
    Returns a list of TFChange objects representing added/modified/deleted resources.
    """
    changes = []
    lines = diff_text.split('\n')

    i = 0
    while i < len(lines):
        line = lines[i]

        # Look for resource block starts in added lines
        if line.startswith('+') and not line.startswith('+++'):
            resource_match = _ADDED_RESOURCE_RE.match(line)
            if resource_match:
                resource_type = resource_match.group(1)
                resource_name = resource_match.group(2)
                # This is a new resource being added - collect its attributes
                attrs, end_idx = _collect_added_block(lines, i + 1)
                changes.append(TFChange(
                    action="add",
                    resource_type=resource_type,
                    resource_name=resource_name,
                    file_path=file_path,
                    attributes=attrs,
                ))
                i = end_idx
                continue

        # Look for deleted resource blocks
        if line.startswith('-') and not line.startswith('---'):
            resource_match = _DELETED_RESOURCE_RE.match(line)
            if resource_match:
                resource_type = resource_match.group(1)
                resource_name = resource_match.group(2)
                changes.append(TFChange(
                    action="delete",
                    resource_type=resource_type,
                    resource_name=resource_name,
                    file_path=file_path,
                ))
                # Skip past the deleted block
                i = _skip_deleted_block(lines, i + 1)
                continue

        # Look for resource blocks in context (existing) that have modifications inside
        if not line.startswith('+') and not line.startswith('-'):
            resource_match = _RESOURCE_RE.match(line)
            if resource_match:
                resource_type = resource_match.group(1)
                resource_name = resource_match.group(2)
                # Check if there are modifications inside this block
                modified_attrs, end_idx = _collect_modified_block(lines, i + 1)
                if modified_attrs:
                    changes.append(TFChange(
                        action="modify",
                        resource_type=resource_type,
                        resource_name=resource_name,
                        file_path=file_path,
                        attributes=modified_attrs,
                    ))
                i = end_idx
                continue

        i += 1

    return changes


def _collect_added_block(lines: list[str], start: int) -> tuple[dict, int]:
    """Collect attributes from an added resource block (lines starting with +)."""
    attrs = {}
    depth = 1
    i = start

    while i < len(lines) and depth > 0:
        line = lines[i]
        if line.startswith('+'):
            content = line[1:].strip()
            if '{' in content:
                depth += content.count('{')
            if '}' in content:
                depth -= content.count('}')
            # Extract attribute
            attr_match = re.match(r'(\w+)\s*=\s*(.+)', content)
            if attr_match and depth >= 1:
                key = attr_match.group(1)
                value = _clean_tf_value(attr_match.group(2))
                attrs[key] = value
        elif line.startswith(' ') or line.startswith('\t'):
            # Context line inside the block
            content = line.strip()
            if '{' in content:
                depth += content.count('{')
            if '}' in content:
                depth -= content.count('}')
        else:
            # Hit a removed line or end of hunk
            if line.startswith('-'):
                pass  # skip removed lines
            elif line.startswith('@@') or line.startswith('diff'):
                break
        i += 1

    return attrs, i


def _collect_modified_block(lines: list[str], start: int) -> tuple[dict, int]:
    """Collect modified attributes from an existing resource block."""
    attrs = {}
    depth = 1
    i = start

    while i < len(lines) and depth > 0:
        line = lines[i]

        if line.startswith('@@') or line.startswith('diff'):
            break

        content = line[1:] if line and line[0] in ('+', '-', ' ') else line
        stripped = content.strip()

        if '{' in stripped:
            depth += stripped.count('{')
        if '}' in stripped:
            depth -= stripped.count('}')

        # Capture added attributes (the "new" values)
        if line.startswith('+'):
            attr_match = re.match(r'\s*(\w+)\s*=\s*(.+)', content)
            if attr_match and depth >= 1:
                key = attr_match.group(1)
                value = _clean_tf_value(attr_match.group(2))
                attrs[key] = value

        i += 1

    return attrs, i


def _skip_deleted_block(lines: list[str], start: int) -> int:
    """Skip past a deleted resource block."""
    depth = 1
    i = start
    while i < len(lines) and depth > 0:
        line = lines[i]
        if line.startswith('-'):
            content = line[1:]
            depth += content.count('{')
            depth -= content.count('}')
        elif not line.startswith('+'):
            # Context line
            content = line[1:] if line else ""
            depth += content.count('{')
            depth -= content.count('}')
        i += 1
    return i


def _clean_tf_value(value: str) -> str:
    """Clean a Terraform attribute value (remove quotes, trailing comments)."""
    value = value.strip()
    # Remove trailing comments
    if '#' in value:
        value = value[:value.index('#')].strip()
    if '//' in value:
        value = value[:value.index('//')].strip()
    # Remove trailing comma
    if value.endswith(','):
        value = value[:-1].strip()
    # Remove surrounding quotes
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value


def tf_change_to_component_config(change: TFChange) -> Optional[dict]:
    """
    Convert a TFChange into an Emfirge component config dict
    suitable for the /simulate/component endpoint.
    """
    component_type = TF_TO_EMFIRGE_TYPE.get(change.resource_type)
    if not component_type:
        return None

    config = {"name": change.resource_name}

    # Map TF attributes to Emfirge component config based on type
    if component_type == "security_group":
        config.update(_map_sg_attrs(change.attributes))
    elif component_type == "s3_bucket":
        config.update(_map_s3_attrs(change.attributes))
    elif component_type == "rds_instance":
        config.update(_map_rds_attrs(change.attributes))
    elif component_type == "ec2_instance":
        config.update(_map_ec2_attrs(change.attributes))
    elif component_type == "lambda_function":
        config.update(_map_lambda_attrs(change.attributes))

    return {
        "component_type": component_type,
        "config": config,
        "tf_source": {
            "file_path": change.file_path,
            "resource_type": change.resource_type,
            "resource_name": change.resource_name,
            "action": change.action,
        }
    }


def _map_sg_attrs(attrs: dict) -> dict:
    """Map TF security group attributes to Emfirge config."""
    config = {}
    if "name" in attrs:
        config["name"] = attrs["name"]
    # Ingress rules would need deeper parsing of ingress blocks
    # For now, flag if cidr_blocks contains 0.0.0.0/0
    for key, val in attrs.items():
        if "cidr" in key and "0.0.0.0/0" in val:
            config["open_to_internet"] = True
        if "from_port" in key:
            config["from_port"] = int(val) if val.isdigit() else 0
        if "to_port" in key:
            config["to_port"] = int(val) if val.isdigit() else 0
    return config


def _map_s3_attrs(attrs: dict) -> dict:
    """Map TF S3 bucket attributes to Emfirge config."""
    config = {}
    if "bucket" in attrs:
        config["bucket_name"] = attrs["bucket"]
    if "acl" in attrs:
        config["is_public"] = attrs["acl"] in ("public-read", "public-read-write")
    if "versioning" in attrs:
        config["versioning_enabled"] = attrs.get("enabled", "false") == "true"
    return config


def _map_rds_attrs(attrs: dict) -> dict:
    """Map TF RDS attributes to Emfirge config."""
    config = {}
    if "identifier" in attrs:
        config["db_identifier"] = attrs["identifier"]
    if "publicly_accessible" in attrs:
        config["publicly_accessible"] = attrs["publicly_accessible"].lower() == "true"
    if "storage_encrypted" in attrs:
        config["encrypted"] = attrs["storage_encrypted"].lower() == "true"
    if "multi_az" in attrs:
        config["multi_az"] = attrs["multi_az"].lower() == "true"
    if "deletion_protection" in attrs:
        config["deletion_protection"] = attrs["deletion_protection"].lower() == "true"
    return config


def _map_ec2_attrs(attrs: dict) -> dict:
    """Map TF EC2 instance attributes to Emfirge config."""
    config = {}
    if "instance_type" in attrs:
        config["instance_type"] = attrs["instance_type"]
    if "subnet_id" in attrs:
        config["subnet_id"] = attrs["subnet_id"]
    # IMDSv2 check
    if "http_tokens" in attrs:
        config["imdsv2_required"] = attrs["http_tokens"] == "required"
    return config


def _map_lambda_attrs(attrs: dict) -> dict:
    """Map TF Lambda attributes to Emfirge config."""
    config = {}
    if "function_name" in attrs:
        config["function_name"] = attrs["function_name"]
    if "runtime" in attrs:
        config["runtime"] = attrs["runtime"]
    if "role" in attrs:
        config["role_arn"] = attrs["role"]
    return config


# -- RAW HCL PARSER (for Claude-generated fixes) ----------------------

# Regex for resource block in raw HCL (no diff prefix)
_RAW_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_RAW_ATTR_RE = re.compile(r'^\s*(\w+)\s*=\s*(.+)$')


def parse_hcl_block(hcl: str) -> Optional[TFChange]:
    """
    Parse a raw HCL block (from Claude's terraform generation) into a TFChange.

    Unlike parse_pr_diff which expects unified diff format, this handles
    plain HCL resource blocks. Extracts the first resource block found
    and its top-level + nested attributes.

    Args:
        hcl: Raw HCL string (may include comments, multiple blocks)

    Returns:
        TFChange with action="modify", or None if no resource block found.
    """
    lines = hcl.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]
        # Skip comments and empty lines
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            i += 1
            continue

        # Look for resource block
        match = _RAW_RESOURCE_RE.search(line)
        if match:
            resource_type = match.group(1)
            resource_name = match.group(2)
            attrs = _collect_raw_block_attrs(lines, i + 1)
            return TFChange(
                action="modify",
                resource_type=resource_type,
                resource_name=resource_name,
                file_path="generated",
                attributes=attrs,
            )
        i += 1

    return None


def _collect_raw_block_attrs(lines: list, start: int) -> dict:
    """
    Collect all attributes from a raw HCL resource block (including nested blocks).

    Flattens nested blocks: metadata_options { http_tokens = "required" }
    becomes {"http_tokens": "required"} in the output.
    """
    attrs = {}
    depth = 1
    i = start

    while i < len(lines) and depth > 0:
        line = lines[i]
        stripped = line.strip()

        # Skip comments
        if stripped.startswith('#') or stripped.startswith('//'):
            i += 1
            continue

        # Track braces
        depth += stripped.count('{')
        depth -= stripped.count('}')

        if depth <= 0:
            break

        # Extract attribute (key = value)
        attr_match = _RAW_ATTR_RE.match(line)
        if attr_match:
            key = attr_match.group(1).strip()
            value = _clean_tf_value(attr_match.group(2))
            # Skip meta-arguments and block labels
            if key not in ('resource', 'provider', 'terraform', 'variable', 'output', 'locals', 'data', 'module'):
                attrs[key] = value

        i += 1

    return attrs


def parse_hcl_to_component(hcl: str) -> Optional[dict]:
    """
    Convenience function: parse raw HCL → TFChange → component config.

    Returns the same component config dict that tf_change_to_component_config produces,
    or None if parsing fails.
    """
    tf_change = parse_hcl_block(hcl)
    if not tf_change:
        return None
    return tf_change_to_component_config(tf_change)
