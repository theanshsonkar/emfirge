import re
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = [ROOT / 'iam-role.yaml', ROOT / 'backend' / 'cloudformation' / 'iam-role.yaml']


def test_iam_templates_are_identical_and_use_account_scoped_trust():
    first, second = (path.read_bytes() for path in TEMPLATES)
    assert first == second
    text = first.decode()
    assert 'aws-risk-agent' not in text
    assert 'sts:ExternalId: !Ref ExternalId' in text
    assert '${TrustedAccountId}' in text
    external_id = re.search(r'(?ms)^  ExternalId:\n(?P<body>.*?)(?=^\S)', text)
    assert external_id
    assert 'Default:' not in external_id.group('body')


def test_hosted_external_ids_match_template_constraints():
    text = TEMPLATES[0].read_text()
    pattern = re.search(r"AllowedPattern: '([^']+)'", text)
    minimum = re.search(r'(?ms)^  ExternalId:\n.*?^    MinLength: (\d+)', text)
    assert pattern and minimum
    allowed = re.compile(pattern.group(1))
    min_length = int(minimum.group(1))
    values = [secrets.token_urlsafe(32) for _ in range(200)]
    assert all(len(value) >= min_length and allowed.fullmatch(value) for value in values)
