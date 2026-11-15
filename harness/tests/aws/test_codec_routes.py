"""Every REST operation that shares a method and path template with another one, across all of botocore's REST
services, is sent the way the SDK sends it and decoded back. The codec must tell them apart by what each requires
(query keys, query members, headers). The only allowed mix-ups are true wire twins: operations that require exactly
the same, where the codec picks the successor of a deprecated one, or two reads (a mix-up of reads changes nothing
on the branch). No network."""
from __future__ import annotations

import datetime
import re
from collections import defaultdict

import botocore.session
import pytest

from emfirge.aws.codec import AwsCodec
from emfirge.aws.curated.kinds import kind_of

SESSION = botocore.session.get_session()
CODEC = AwsCodec('us-west-2')


def dummy(shape, depth: int = 0):
    """The smallest valid value: required members only."""
    t = shape.type_name
    if t == 'structure':
        return {m: dummy(shape.members[m], depth + 1) for m in shape.required_members} if depth < 6 else {}
    if t == 'list':
        return [dummy(shape.member, depth + 1)]
    simple = {'map': {}, 'integer': 1, 'long': 1, 'double': 1.0, 'float': 1.0, 'boolean': True, 'blob': b'x',
              'timestamp': datetime.datetime(2026, 1, 1)}
    if t in simple:
        return simple[t]
    return shape.enum[0] if getattr(shape, 'enum', None) else 'x1'


def shared_paths() -> list[tuple[str, str, tuple[str, ...]]]:
    out = []
    for service in SESSION.get_available_services():
        model = SESSION.get_service_model(service)
        protocols = model.metadata.get('protocols') or [model.metadata['protocol']]
        if not {'rest-json', 'rest-xml'} & set(protocols):
            continue
        groups = defaultdict(list)
        for op in model.operation_names:
            http = model.operation_model(op).http
            groups[(http.get('method', 'POST'), re.sub(r'\{[^}]+\}', '{}', http.get('requestUri', '/').split('?')[0]))].append(op)
        out += [(service, op, tuple(ops)) for ops in groups.values() if len(ops) > 1 for op in ops]
    return out


def requirements(service: str, op: str) -> tuple[frozenset, frozenset]:
    route = next(r for r in CODEC._rest_routes(service) if r[2] == op)
    return frozenset(route[3].items()), frozenset(route[4])


CASES = shared_paths()


def test_the_survey_found_the_known_families():
    names = {(s, o) for s, o, _ in CASES}
    assert {('s3', 'DeleteObject'), ('s3', 'AbortMultipartUpload'), ('s3', 'GetObject'), ('s3', 'ListParts')} <= names
    assert len(CASES) > 150


@pytest.mark.parametrize('service,op,group', CASES, ids=[f'{s}.{o}' for s, o, _ in CASES])
def test_operations_on_one_path_are_told_apart(service, op, group):
    model = SESSION.get_service_model(service)
    opm = model.operation_model(op)
    wire = CODEC._serialized(service, op, dummy(opm.input_shape) if opm.input_shape else {})   # the bare wire shape
    got = CODEC.decode(wire)
    assert got is not None
    if got.operation == op:
        return
    assert requirements(service, op) == requirements(service, got.operation), f'{op} decoded as {got.operation}'
    other = model.operation_model(got.operation)
    twins_by_age = opm.deprecated and not other.deprecated
    both_read = kind_of(op).reads_only and kind_of(got.operation).reads_only
    assert twins_by_age or both_read, f'{op} and {got.operation} look the same and are not both reads'
