"""What the prover asks of AWS's own API models (botocore): names, shapes, and answers read as the SDK reads them.

Why botocore and not the plain data the branch keeps: planning an inverse call needs the old value under the name the
call's input uses. The branch keeps answers as they came over the wire (XML tags, wrapper elements, URL-encoded policy
documents). Read through botocore's own parser, every answer has the model's member names, whatever the protocol.
The comparison itself stays on the wire data (compare.py), because a parser drops fields the model does not know.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from functools import lru_cache
from typing import Any

import botocore.parsers
from botocore.model import OperationModel, ServiceModel, Shape

from emfirge.branch.baseline import Answer
from emfirge.core.model import Call, WireResponse

from ..codec import AwsCodec

READ = re.compile(r'^(Get|List|Describe|Head)[A-Z]')
IDENT = re.compile(r'(Name|Id|Arn|ARN|Url|UUID|Bucket|Key|Resource|Rule|Identifier)$')
NOUN_SUFFIX = re.compile(r'(Name|Id|Arn|ARN|Url|UUID|Identifier)$')
WORDS = re.compile(r'[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+')
MISSING: Any = object()
"""No value: distinct from None, which a service may return."""


def verb_noun(operation: str) -> tuple[str, str]:
    """'PutRetentionPolicy' -> ('Put', 'RetentionPolicy'): AWS names every operation verb first."""
    m = re.match(r'^[A-Z][a-z]+', operation)
    verb = m.group(0) if m else ''
    return verb, operation[len(verb):]


def words(name: str) -> list[str]:
    return WORDS.findall(name)


class Models:
    """botocore's models, through the codec that already loads them."""

    def __init__(self, codec: AwsCodec) -> None:
        self._codec = codec
        self.state_names = lru_cache(maxsize=None)(self._state_names)

    def service(self, service: str) -> ServiceModel:
        return self._codec.model(service)

    def has(self, service: str, operation: str) -> bool:
        return operation in self.service(service).operation_names

    def operation(self, service: str, operation: str) -> OperationModel:
        return self.service(service).operation_model(operation)

    def input(self, service: str, operation: str) -> Shape | None:
        return self.operation(service, operation).input_shape

    def _state_names(self, service: str) -> frozenset[str]:
        """Every member name any read of the service can answer with: the names of state. A request member whose
        name is not among them is something no read shows."""
        names: set[str] = set()
        for op in self.service(service).operation_names:
            if READ.match(op):
                _walk_names(self.operation(service, op).output_shape, names, set())
        return frozenset(names)

    def identifying(self, service: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        """The members that name what the call acts on: bound to the URL, or a string named ...Name/Id/Arn/Url."""
        shape = self.input(service, operation)
        out = {}
        for k, v in params.items():
            member = shape.members.get(k) if shape else None
            if member is not None and (member.serialization.get('location') == 'uri' or
                                       (isinstance(v, str) and IDENT.search(k))):
                out[k] = v
        return out

    def parsed(self, call: Call, answer: Answer) -> Any:
        """The answer as botocore's parser reads it (member names, typed values), or MISSING when it cannot be."""
        if not answer.ok:
            return MISSING
        opm = self.operation(call.service, call.operation)
        if opm.output_shape is None:
            return {}
        raw = self._codec.render(call, WireResponse(answer.status, {}, b''), answer.body).body
        try:
            out = botocore.parsers.create_parser(self._codec.wire_protocol(call)).parse(
                {'status_code': answer.status, 'headers': {}, 'body': raw}, opm.output_shape)
        except Exception:   # a parser failure means no member-named view, not a failed proof
            return MISSING
        out.pop('ResponseMetadata', None)
        return decoded(out)


def _walk_names(shape: Shape | None, names: set[str], seen: set[str]) -> None:
    if shape is None or shape.name in seen:
        return
    seen.add(shape.name)
    if shape.type_name == 'structure':
        for k, v in shape.members.items():
            names.add(k)
            _walk_names(v, names, seen)
    elif shape.type_name == 'list':
        _walk_names(shape.member, names, seen)
    elif shape.type_name == 'map':
        _walk_names(shape.value, names, seen)


def decoded(o: Any) -> Any:
    """Policy documents some services return URL-encoded ('%7B%22Version...') as the text they were written as."""
    if isinstance(o, dict):
        return {k: decoded(v) for k, v in o.items()}
    if isinstance(o, list):
        return [decoded(v) for v in o]
    if isinstance(o, str) and o.startswith('%7B'):
        return urllib.parse.unquote(o)
    return o


def coerce(shape: Shape, v: Any) -> Any:
    """Fit a value read back from AWS into an input shape: drop fields the input does not have, write documents as
    JSON, wrap scalars for lists. MISSING when it does not fit."""
    if v is None or v is MISSING:
        return MISSING
    return _COERCE.get(shape.type_name, _as_is)(shape, v)


def _as_is(shape: Shape, v: Any) -> Any:
    return v


def _structure(shape: Shape, v: Any) -> Any:
    if not isinstance(v, dict):
        return MISSING
    out = {k: coerce(shape.members[k], x) for k, x in v.items() if k in shape.members}
    out = {k: x for k, x in out.items() if x is not MISSING}
    return out or MISSING


def _list(shape: Shape, v: Any) -> Any:
    items = [coerce(shape.member, x) for x in (v if isinstance(v, list) else [v])]
    return [x for x in items if x is not MISSING]


def _map(shape: Shape, v: Any) -> Any:
    if not isinstance(v, dict):
        return MISSING
    out = {k: coerce(shape.value, x) for k, x in v.items()}
    return {k: x for k, x in out.items() if x is not MISSING}


def _string(shape: Shape, v: Any) -> Any:
    if isinstance(v, list) and len(v) == 1 and isinstance(v[0], str):
        return v[0]
    if isinstance(v, dict):
        return json.dumps(v)
    if isinstance(v, bytes):
        return v.decode(errors='replace')
    if isinstance(v, bool):
        return str(v).lower()
    return str(v) if isinstance(v, (str, int, float)) else MISSING


def _integer(shape: Shape, v: Any) -> Any:
    try:
        return int(v)
    except (TypeError, ValueError):
        return MISSING


def _float(shape: Shape, v: Any) -> Any:
    try:
        return float(v)
    except (TypeError, ValueError):
        return MISSING


def _boolean(shape: Shape, v: Any) -> Any:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ('true', 'false'):
        return v.lower() == 'true'
    return MISSING


def _blob(shape: Shape, v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return v.encode() if isinstance(v, str) else MISSING


_COERCE = {'structure': _structure, 'list': _list, 'map': _map, 'string': _string, 'integer': _integer,
           'long': _integer, 'float': _float, 'double': _float, 'boolean': _boolean, 'blob': _blob}
