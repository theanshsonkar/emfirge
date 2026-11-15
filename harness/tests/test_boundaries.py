"""The one dependency rule, checked on the source (README: 'Modules and the one dependency rule').

core imports nothing of ours; branch, graph, lenses and gate import only emfirge.core and the standard library;
only emfirge.aws may import boto3 or botocore. The branch also carries no AWS words in its strings.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / 'src' / 'emfirge'
NEUTRAL = ('branch', 'graph', 'lenses', 'gate')
AWS_WORDS = re.compile(r"""['"](arn:|lambda|botocore|boto3)""")


def modules(package: str = '') -> list[Path]:
    root = SRC / package if package else SRC
    return sorted(p for p in root.rglob('*.py') if '__pycache__' not in p.parts)


def imports(path: Path) -> set[str]:
    """Absolute module names a file imports (relative imports resolved against its package)."""
    tree = ast.parse(path.read_text())
    package = ['emfirge', *path.relative_to(SRC).parent.parts]
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[:len(package) - node.level + 1]
                out.add('.'.join(base + ([node.module] if node.module else [])))
            else:
                out.add(node.module or '')
    return out


def top(name: str) -> str:
    return name.split('.')[0]


def ours(name: str) -> str | None:
    """The emfirge package a module belongs to ('core', 'branch', ...), or None for anything else."""
    parts = name.split('.')
    return parts[1] if parts[0] == 'emfirge' and len(parts) > 1 else None


@pytest.mark.parametrize('path', modules('core'), ids=str)
def test_core_imports_nothing_of_ours(path):
    bad = {m for m in imports(path) if ours(m) not in (None, 'core')}
    assert not bad, f'{path} imports {bad}'


@pytest.mark.parametrize('path', [p for pkg in NEUTRAL for p in modules(pkg)], ids=str)
def test_cloud_neutral_packages_import_only_core_and_the_standard_library(path):
    pkg = path.relative_to(SRC).parts[0]
    bad = set()
    for m in imports(path):
        if ours(m) is not None:
            if ours(m) not in ('core', pkg):
                bad.add(m)
        elif top(m) != 'emfirge' and top(m) not in sys.stdlib_module_names and top(m) != '__future__':
            bad.add(m)
    assert not bad, f'{path} imports {bad}'


@pytest.mark.parametrize('path', modules('branch'), ids=str)
def test_the_branch_carries_no_aws_words(path):
    assert not AWS_WORDS.search(path.read_text()), f'{path} has an AWS word in a string'


@pytest.mark.parametrize('path', [p for p in modules() if p.relative_to(SRC).parts[0] != 'aws'], ids=str)
def test_only_aws_imports_the_aws_sdk(path):
    bad = {m for m in imports(path) if top(m) in ('boto3', 'botocore')}
    assert not bad, f'{path} imports {bad}'


def test_the_rule_is_checked_on_real_files():
    assert modules('core') and modules('branch')


SESSION_MAY_IMPORT = ('core', 'branch', 'graph', 'lenses', 'gate', 'session')


@pytest.mark.parametrize('path', modules('session'), ids=str)
def test_the_session_is_cloud_neutral(path):
    """The session wires core, branch, graph, lenses and gate; cloud parts come in by injection."""
    bad = set()
    for m in imports(path):
        if ours(m) is not None:
            if ours(m) not in SESSION_MAY_IMPORT:
                bad.add(m)
        elif top(m) != 'emfirge' and top(m) not in sys.stdlib_module_names and top(m) != '__future__':
            bad.add(m)
    assert not bad, f'{path} imports {bad}'
