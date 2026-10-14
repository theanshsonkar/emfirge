import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_shared_external_id_is_absent_and_sts_is_centralized():
    for base in (ROOT / 'app', ROOT.parent / 'mcp' / 'src'):
        if base.exists():
            for path in base.rglob('*'):
                if path.is_file() and 'aws-risk-agent' in path.read_text(errors='ignore'):
                    raise AssertionError(f'legacy shared external id in {path}')
    for path in (ROOT / 'app').glob('*.py'):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'assume_role':
                assert path.name == 'role_access.py'
