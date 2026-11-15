"""Fill an operation's input from read answers, by member names and shapes (botocore models). Pure: no I/O.

Why: AWS names a setting the same way in the call that writes it and in the answer that shows it (Timeout in
CreateFunction and in GetFunction's Configuration). So a resource can be rebuilt from its reads without code per
type. The rules, the same for every service:

  * a member is looked up by its exact name (case does not count) in the answers' top level, then one level down
    (GetFunction's Configuration, DescribeTable's Table), then by the same words under another designator
    (FunctionName <- FunctionArn) or by a longer or shorter name with the same last words (PolicyDocument <-
    Document, VersionId <- DefaultVersionId);
  * a value is shaped to the input: unknown members of a structure are dropped, lists are shaped item by item, a
    map and a list of key/value pairs convert into each other, a document the SDK decoded becomes JSON text again,
    a structure that carries one ARN gives the ARN where a string is wanted;
  * a structure that no answer names is filled from the answers' own top level (CreateBucketConfiguration from
    GetBucketLocation's LocationConstraint);
  * a blob that no answer carries, inside a structure whose answer holds a download address, becomes a Fetch (a
    function's code: the answer gives a URL, the create takes the bytes);
  * empty values ('', [], {}, None) are left out, like a value that was never set.

What cannot be filled is reported, never invented: Filled.missing lists the required members nobody answered.
"""
from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from botocore.model import Shape, StructureShape

from ..catalog.names import split
from ..resource_words import list_word, names_type

URL = re.compile(r'^https?://\S+$')


class _Missing:
    """No value: the member is left out."""

    def __repr__(self) -> str:
        return 'MISSING'


MISSING: Any = _Missing()


@dataclass(frozen=True)
class Fetch:
    """A blob the read handed out as a download address; the copier downloads it through the real account's door."""
    url: str


@dataclass
class Filled:
    params: dict[str, Any]
    missing: list[str] = field(default_factory=list)     # required members nobody answered
    fetches: list[tuple[str, ...]] = field(default_factory=list)


def unwrap(body: Mapping[str, Any], type_: str | None = None) -> dict[str, Any]:
    """An answer's own record: into a member named after the type (Role, Table, KeyMetadata), or into the only
    member when there is one (a structure, or a list holding one structure: DescribeVpcs' Vpcs)."""
    cur: Any = dict(body)
    for _ in range(4):
        members = {k: v for k, v in cur.items() if not empty(v)}
        named = [k for k in members if type_ and any(names_type(w, type_) for w in list_word(k))]
        key = named[0] if len(named) == 1 else (next(iter(members)) if len(members) == 1 else None)
        value = members.get(key) if key else None
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
            value = value[0]
        if not isinstance(value, dict):
            return cur
        cur = value
    return cur


def empty(value: Any) -> bool:
    return value is None or value == '' or value == [] or value == {}


def fill(shape: StructureShape | None, sources: Iterable[Mapping[str, Any]], wrap: bool = True) -> Filled:
    """The input for `shape`, from `sources` (the strongest first). `wrap`: a structure member no source names may
    be filled from the sources' top level (one level only: inside such a structure, members are looked up)."""
    sources = [s for s in sources if isinstance(s, Mapping)]
    out = Filled({})
    if shape is None:
        return out
    for name, member in shape.members.items():
        if member.serialization.get('location') in ('header', 'headers') and name not in shape.required_members:
            continue      # checksums, request payers, expected owners: request plumbing, not a setting
        if not wrap and not split(name).words:
            continue      # inside a wrapper filled from the top: a bare Arn or Name there is the resource's own
        value = _member(name, member, sources, out, (name,), wrap)
        if value is MISSING:
            if name in shape.required_members:
                out.missing.append(name)
            continue
        out.params[name] = value
    return out


def _member(name: str, shape: Shape, sources: list[Mapping[str, Any]], out: Filled, path: tuple[str, ...],
            wrap: bool) -> Any:
    found = lookup(name, sources)
    if found is not MISSING:
        value = adapt(found, shape, out, path)
        if value is not MISSING:
            return value
    if wrap and shape.type_name == 'structure':   # a wrapper the answers do not have: fill it from their top level
        inner = fill(shape, sources, wrap=False)
        if inner.params and not inner.missing:
            out.fetches += inner.fetches
            return inner.params
    return MISSING


def lookup(name: str, sources: list[Mapping[str, Any]]) -> Any:
    """The value of `name` in the sources: exact name at the top, then one level down, then a variant name."""
    key = name.lower()
    for depth in (0, 1):
        for src in sources:
            for scope in ([src] if depth == 0 else [v for v in src.values() if isinstance(v, Mapping)]):
                for k, v in scope.items():
                    if k.lower() == key and not empty(v):
                        return v
    words = split(name)
    if not words.words:
        return MISSING
    for src in sources:
        for k, v in src.items():
            if not empty(v) and _variant(words, split(k)):
                return v
    return MISSING


def _variant(want: Any, have: Any) -> bool:
    """Same words, an ARN where a name or id is wanted (FunctionName <- FunctionArn: AWS takes the ARN for the name),
    or one name is the other's tail (Document <-> PolicyDocument)."""
    if want.words == have.words:
        return have.designator == 'arn' and want.designator in ('name', 'id', None)
    if want.designator != have.designator or not have.words:
        return False
    short, long_ = sorted((want.words, have.words), key=len)
    return long_[-len(short):] == short


def adapt(value: Any, shape: Shape, out: Filled, path: tuple[str, ...]) -> Any:
    """`value` in the form the input shape takes, or MISSING."""
    if empty(value):
        return MISSING
    kind = shape.type_name
    if kind == 'structure':
        return _structure(value, shape, out, path)
    if kind == 'list':
        return _list(value, shape, out, path)
    if kind == 'map':
        return _map(value, shape)
    if kind == 'string':
        return _string(value, shape)
    if kind in ('integer', 'long'):
        return _integer(value)
    if kind == 'boolean':
        return value if isinstance(value, bool) else {'true': True, 'false': False}.get(str(value).lower(), MISSING)
    if kind in ('double', 'float'):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else MISSING
    if kind == 'timestamp':
        return value if isinstance(value, datetime.datetime) else MISSING
    if kind == 'blob':
        return value if isinstance(value, (bytes, bytearray)) else MISSING
    return MISSING


def _structure(value: Any, shape: StructureShape, out: Filled, path: tuple[str, ...]) -> Any:
    if not isinstance(value, Mapping):
        return MISSING
    params = {}
    for name, member in shape.members.items():
        got = lookup(name, [value]) if name.lower() in {k.lower() for k in value} else MISSING
        got = adapt(got, member, out, path + (name,)) if got is not MISSING else MISSING
        if got is not MISSING:
            params[name] = got
    for name, member in shape.members.items():   # a download address for a blob nobody answered (code)
        if name not in params and member.type_name == 'blob':
            urls = [v for v in value.values() if isinstance(v, str) and URL.match(v)]
            if len(urls) == 1:
                params[name] = Fetch(urls[0])
                out.fetches.append(path + (name,))
    if any(r not in params for r in shape.required_members) or not params:
        return MISSING
    return params


def _list(value: Any, shape: Shape, out: Filled, path: tuple[str, ...]) -> Any:
    item = shape.member
    if isinstance(value, Mapping) and item.type_name == 'structure' and len(item.members) >= 2:
        k, v = list(item.members)[:2]            # a map where pairs are wanted: Tags {a: b} -> [{Key: a, Value: b}]
        value = [{k: key, v: val} for key, val in value.items()]
    if not isinstance(value, list):
        return MISSING
    items = [adapt(v, item, out, path) for v in value]
    items = [v for v in items if v is not MISSING]
    return items or MISSING


def _map(value: Any, shape: Shape) -> Any:
    if isinstance(value, list) and value and all(isinstance(v, Mapping) and len(v) == 2 for v in value):
        value = {list(v.values())[0]: list(v.values())[1] for v in value}   # [{Key: a, Value: b}] -> {a: b}
    if not isinstance(value, Mapping):
        return MISSING
    return {k: v for k, v in value.items() if not empty(v)} or MISSING


def _string(value: Any, shape: Shape) -> Any:
    if isinstance(value, (dict, list)):
        arn = _only_arn(value)
        value = arn if arn is not None else json.dumps(value)   # the SDK decoded a policy document: back to text
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return MISSING
    value = str(value)
    if shape.enum and value not in shape.enum:
        return MISSING
    return value


def _only_arn(value: Any) -> str | None:
    """A structure that carries exactly one ARN, where a string is wanted (PermissionsBoundary -> its ARN)."""
    if not isinstance(value, Mapping):
        return None
    arns = [v for v in value.values() if isinstance(v, str) and v.startswith('arn:')]
    return arns[0] if len(arns) == 1 else None


def _integer(value: Any) -> Any:
    if isinstance(value, bool):
        return MISSING
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip('-').isdigit():
        return int(value)
    return MISSING
