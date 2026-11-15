"""The runner: every lens, in order; a failing lens is an unknown, never a crash and never silence. And the lens
package stays cloud-neutral: one cloud's words only in patterns.py."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from emfirge.core.model import Finding, Unknown
from emfirge.lenses import LensResult, LensView, run_lenses

LENSES = Path(__file__).resolve().parents[2] / 'src' / 'emfirge' / 'lenses'


class Says:
    def __init__(self, name, *codes):
        self.name, self.codes = name, codes

    def look(self, view):
        return LensResult(tuple(Finding(self.name, c, c) for c in self.codes))


class Breaks:
    name = 'broken'

    def look(self, view):
        raise RuntimeError('boom')


class Mumbles:
    name = 'mumbles'

    def look(self, view):
        return None


def test_lenses_run_in_the_given_order_and_duplicates_are_one_fact():
    r = run_lenses([Says('b', 'b.1'), Says('a', 'a.1', 'a.1')], LensView(()))
    assert [f.code for f in r.findings] == ['b.1', 'a.1']


def test_a_failing_lens_becomes_an_unknown_and_the_others_still_run():
    r = run_lenses([Breaks(), Says('a', 'a.1'), Mumbles()], LensView(()))
    assert [f.code for f in r.findings] == ['a.1']
    assert r.unknowns == (Unknown('the broken lens failed: RuntimeError: boom', 'lens:broken'),
                          Unknown('the mumbles lens gave no answer', 'lens:mumbles'))


def test_no_service_is_named_in_lens_code():
    """The dead end is code per service. Only patterns.py may hold one cloud's words, and only as data: no string in
    any other lens module names a service or an AWS-only value (docstrings may give examples)."""
    service = re.compile(r"\b(s3|ec2|iam|rds|dynamodb|lambda|sqs|sns|kms|eks|ecr|cloudfront|aws|AllUsers|0\.0\.0\.0)\b", re.I)
    for path in LENSES.rglob('*.py'):
        if path.name == 'patterns.py' or '__pycache__' in path.parts:
            continue
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr)}
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]
        bad = [s for s in strings if service.search(s)]
        assert not bad, f'{path.name}: {bad}'
