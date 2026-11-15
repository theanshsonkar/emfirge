"""The graph stays fast on a big account, and stays cloud-neutral."""
import ast
import pathlib
import re
import time

from emfirge.core.model import Change, ChangeType
from emfirge.graph import Graph, ReferenceIndex

from acme_cloud import VOCAB, b64, policy, ref, urn

GRAPH_SRC = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'emfirge' / 'graph'


def big_account(n: int) -> dict:
    """n resources in groups of five: a store, a grant on it, a job using the grant, a timer, a box with a script."""
    states = {}
    for g in range(n // 5):
        store = f'store-{g:05d}-data'
        states[ref('store', store)] = {'name': store, 'tags': {f'k{i}': f'value {i} of group {g}' for i in range(10)}}
        states[ref('grant', f'grant-{g:05d}')] = {'doc': policy({'allow': ['store:get', 'store:put'], 'on': [urn('store', store) + '/*']},
                                                                  {'allow': 'log:*', 'on': '*'})}
        states[ref('job', f'job-{g:05d}')] = {'grant': urn('grant', f'grant-{g:05d}'), 'env': {'OUT': store, 'MODE': 'live'},
                                              'settings': {f's{i}': f'setting-{i}' for i in range(10)}}
        states[ref('timer', f'timer-{g:05d}')] = {'target': urn('job', f'job-{g:05d}'), 'rate': 'rate(7 days)'}
        states[ref('box', f'box-{g:010x}')] = {'startup': b64(f'#!/bin/sh\nsync acme://{store}/in /srv\nstart\n'),
                                               'net': [{'addr': f'10.0.{g % 250}.{g % 200}'}]}
    return states


def test_index_of_5000_resources_takes_seconds_not_minutes():
    states = big_account(5000)
    t = time.perf_counter()
    index = ReferenceIndex.build(states, VOCAB)
    seconds = time.perf_counter() - t
    assert len(index.refs) == 5000 and index.edge_count() >= 4 * 1000
    assert seconds < 10, f'index took {seconds:.1f}s'


def test_a_change_on_a_big_account_is_judged_in_seconds():
    states = big_account(5000)
    t = time.perf_counter()
    report = Graph(VOCAB).affects([Change(ref('store', 'store-00042-data'), ChangeType.DELETED)], states)
    seconds = time.perf_counter() - t
    found = {i.ref for i in report.changes[0].affected}
    assert {ref('grant', 'grant-00042'), ref('job', 'job-00042'), ref('timer', 'timer-00042'), ref('box', f'box-{42:010x}')} <= found
    assert seconds < 20, f'two indexes and the reach took {seconds:.1f}s'


def test_graph_imports_only_core_and_the_standard_library():
    allowed_prefixes = ('emfirge.core', '.')
    for path in GRAPH_SRC.glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                name = '.' * node.level + (node.module or '')
                assert name.startswith(allowed_prefixes) or _stdlib(name), f'{path.name} imports {name}'
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert _stdlib(alias.name), f'{path.name} imports {alias.name}'


def test_graph_code_names_no_cloud():
    cloud = re.compile(r'\b(aws|amazon|arn:|s3|iam|ec2|cloudfront|boto3?|botocore|gcp|azure)\b')
    for path in GRAPH_SRC.glob('*.py'):
        assert not cloud.findall(path.read_text().lower()), f'{path.name} names a cloud word'


def _stdlib(name: str) -> bool:
    import sys
    return name.split('.')[0] in sys.stdlib_module_names or name == '__future__'
