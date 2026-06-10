"""
Terraform Indexer — scans a GitHub repo for .tf files, parses resource blocks,
and builds an index mapping AWS resource identifiers to file paths + line numbers.

Used by Phase 1 (Context-Aware PRs) to find the exact TF file that defines a
broken resource, enabling surgical diffs instead of standalone HCL dumps.
"""

import re
from typing import Optional
from dataclasses import dataclass, field
from github import Github


@dataclass
class TFResource:
    """A single Terraform resource block found in a repo."""
    resource_type: str          # e.g. "aws_security_group"
    resource_name: str          # e.g. "ssh_open"
    file_path: str              # e.g. "infra/security-groups.tf"
    line_number: int            # line where `resource "..." "..." {` starts
    identifiers: dict = field(default_factory=dict)
    # identifiers maps attribute names to values, e.g.:
    # {"name": "ssh-open-sg", "bucket": "prod-data", "identifier": "prod-db"}
    block_content: str = ""     # raw HCL of the resource block


# Maps TF resource types to the attributes that serve as identifiers
# These are the attributes we extract to match against AWS resource IDs/names
IDENTIFIER_ATTRIBUTES = {
    "aws_security_group": ["name", "name_prefix"],
    "aws_s3_bucket": ["bucket"],
    "aws_db_instance": ["identifier"],
    "aws_instance": ["tags.Name", "tags.name"],
    "aws_lambda_function": ["function_name"],
    "aws_lb": ["name"],
    "aws_alb": ["name"],
    "aws_vpc": ["tags.Name", "cidr_block"],
    "aws_subnet": ["tags.Name", "cidr_block"],
    "aws_iam_role": ["name"],
    "aws_iam_user": ["name"],
    "aws_iam_policy": ["name"],
    "aws_cloudwatch_log_group": ["name"],
    "aws_wafv2_web_acl": ["name"],
    "aws_guardduty_detector": [],
    "aws_kms_key": ["alias"],
    "aws_secretsmanager_secret": ["name"],
    "aws_dynamodb_table": ["name"],
    "aws_sqs_queue": ["name"],
    "aws_ebs_volume": ["tags.Name"],
    "aws_eip": ["tags.Name"],
    "aws_nat_gateway": ["tags.Name"],
    "aws_internet_gateway": ["tags.Name"],
}

# Regex to find resource blocks: resource "type" "name" {
_RESOURCE_BLOCK_RE = re.compile(
    r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE
)

# Regex to extract simple attribute assignments: key = "value"
_ATTR_RE = re.compile(r'^\s*(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)

# Regex to extract tags block content
_TAGS_BLOCK_RE = re.compile(r'tags\s*=\s*\{([^}]*)\}', re.DOTALL)


def parse_tf_content(content: str, file_path: str) -> list[TFResource]:
    """
    Parse a .tf file's content and extract all resource blocks with their identifiers.
    Returns a list of TFResource objects.
    """
    resources = []
    lines = content.split('\n')

    for match in _RESOURCE_BLOCK_RE.finditer(content):
        resource_type = match.group(1)
        resource_name = match.group(2)
        block_start = match.start()

        # Calculate line number (1-indexed)
        line_number = content[:block_start].count('\n') + 1

        # Extract the full block content (find matching closing brace)
        block_content = _extract_block(content, match.end() - 1)

        # Extract identifiers based on resource type
        identifiers = _extract_identifiers(resource_type, block_content)

        resources.append(TFResource(
            resource_type=resource_type,
            resource_name=resource_name,
            file_path=file_path,
            line_number=line_number,
            identifiers=identifiers,
            block_content=block_content,
        ))

    return resources


def _extract_block(content: str, open_brace_pos: int) -> str:
    """Extract content between matching braces starting at open_brace_pos."""
    depth = 0
    i = open_brace_pos
    while i < len(content):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                return content[open_brace_pos:i + 1]
        i += 1
    # If no matching brace found, return from open brace to end
    return content[open_brace_pos:]


def _extract_identifiers(resource_type: str, block_content: str) -> dict:
    """Extract identifier attributes from a resource block."""
    identifiers = {}

    # Get the list of attributes to look for
    attrs_to_find = IDENTIFIER_ATTRIBUTES.get(resource_type, [])

    # Extract simple top-level attributes
    for attr_match in _ATTR_RE.finditer(block_content):
        attr_name = attr_match.group(1)
        attr_value = attr_match.group(2)
        if attr_name in attrs_to_find:
            identifiers[attr_name] = attr_value

    # Extract tags.X attributes from tags block
    tags_match = _TAGS_BLOCK_RE.search(block_content)
    if tags_match:
        tags_content = tags_match.group(1)
        for attr_match in _ATTR_RE.finditer(tags_content):
            tag_key = attr_match.group(1)
            tag_value = attr_match.group(2)
            full_key = f"tags.{tag_key}"
            if full_key in attrs_to_find:
                identifiers[full_key] = tag_value

    return identifiers


def index_repo(gh: Github, repo_full_name: str) -> list[TFResource]:
    """
    Scan a GitHub repo for all .tf files and build a resource index.
    Uses the Git tree API for efficiency (single API call to list all files).
    """
    repo = gh.get_repo(repo_full_name)
    default_branch = repo.default_branch

    # Get the full tree recursively (1 API call)
    tree = repo.get_git_tree(sha=default_branch, recursive=True)

    tf_files = [
        item.path for item in tree.tree
        if item.path.endswith('.tf') and item.type == 'blob'
    ]

    resources = []
    for file_path in tf_files:
        try:
            file_content = repo.get_contents(file_path, ref=default_branch)
            content = file_content.decoded_content.decode('utf-8')
            file_resources = parse_tf_content(content, file_path)
            resources.extend(file_resources)
        except Exception as e:
            print(f"[tf_indexer] Error reading {file_path}: {e}")
            continue

    return resources


def find_resource_match(
    index: list[TFResource],
    resource_id: str,
    resource_type: str = "",
    aws_service: str = "",
) -> Optional[TFResource]:
    """
    Given an AWS resource_id (e.g. "prod-data-bucket" or "ssh-open-sg"),
    find the matching TFResource in the index.

    Matching strategy (in priority order):
    1. Exact match on any identifier value
    2. Identifier value contained in resource_id (or vice versa)
    3. TF resource_name matches resource_id pattern
    """
    # Normalize for comparison
    resource_id_lower = resource_id.lower().strip()

    # Strategy 1: Exact identifier match
    for tf_res in index:
        for attr_name, attr_value in tf_res.identifiers.items():
            if attr_value.lower() == resource_id_lower:
                return tf_res

    # Strategy 2: Partial match (identifier in resource_id or vice versa)
    for tf_res in index:
        for attr_name, attr_value in tf_res.identifiers.items():
            val_lower = attr_value.lower()
            if len(val_lower) >= 3:  # avoid matching tiny strings
                if val_lower in resource_id_lower or resource_id_lower in val_lower:
                    return tf_res

    # Strategy 3: TF resource name matches
    for tf_res in index:
        name_lower = tf_res.resource_name.lower().replace('_', '-')
        if name_lower == resource_id_lower or name_lower in resource_id_lower:
            return tf_res

    # Strategy 4: Filter by AWS service → TF resource type mapping, then match
    if aws_service:
        type_prefix = _aws_service_to_tf_prefix(aws_service)
        if type_prefix:
            filtered = [r for r in index if r.resource_type.startswith(type_prefix)]
            for tf_res in filtered:
                name_lower = tf_res.resource_name.lower().replace('_', '-')
                if name_lower in resource_id_lower or resource_id_lower in name_lower:
                    return tf_res

    return None


def _aws_service_to_tf_prefix(aws_service: str) -> str:
    """Map Emfirge aws_service field to Terraform resource type prefix."""
    mapping = {
        "ec2": "aws_instance",
        "s3": "aws_s3",
        "rds": "aws_db_instance",
        "lambda": "aws_lambda",
        "iam": "aws_iam",
        "vpc": "aws_vpc",
        "security_group": "aws_security_group",
        "elb": "aws_lb",
        "waf": "aws_wafv2",
        "guardduty": "aws_guardduty",
        "cloudwatch": "aws_cloudwatch",
        "kms": "aws_kms",
        "secrets": "aws_secretsmanager",
        "dynamodb": "aws_dynamodb",
        "sqs": "aws_sqs",
    }
    return mapping.get(aws_service.lower(), "")


def build_index_for_installation(gh: Github, installation_id: int, repo_full_name: str) -> list[dict]:
    """
    Build and return a serializable index for storage in the database.
    Each entry is a dict ready for DB insertion.
    """
    resources = index_repo(gh, repo_full_name)

    return [
        {
            "installation_id": installation_id,
            "repo_full_name": repo_full_name,
            "resource_type": r.resource_type,
            "resource_name": r.resource_name,
            "file_path": r.file_path,
            "line_number": r.line_number,
            "identifiers": r.identifiers,
            "block_content": r.block_content,
        }
        for r in resources
    ]
