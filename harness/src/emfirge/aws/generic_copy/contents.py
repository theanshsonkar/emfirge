"""The data a resource holds (a bucket's objects, a table's items), found and replayed with no code per type. Pure
except for the reads the caller makes.

Why: the catalog's reads show a resource's state, not its contents (it leaves data-plane reads out on purpose). A copy
without its contents answers some later calls wrong: deleting a bucket that is not empty succeeds, a scan counts too
few. So for a type that holds data (the catalog says so), the reads that act on it, need nothing but its ids and are
not among the catalog's reads, are its contents reads (ListObjectsV2, Scan). Each list they answer is replayed item by
item with the write named after the read or after the list's items (PutObject, PutItem). Contents that cannot be read
in full or cannot be written back make the copy a refusal.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from botocore.model import ServiceModel

from emfirge.core.model import Kind, Refs, ResourceRef

from ..catalog.names import split
from ..resource_words import noun_of, verb_of
from .plan import CREATE_VERBS

PAGE = re.compile(r'^(Next|LastEvaluated|NextMarker$|Marker$|IsTruncated$|ContinuationToken$)', re.I)


def contents_reads(model: ServiceModel, service: str, ref: ResourceRef, ids: dict[str, Any], known: set[str],
                   kind: Callable[[str, str], Kind], refs: Callable[[str, str, dict[str, Any]], Refs | None]) -> list[tuple[str, dict[str, Any]]]:
    """(operation, params) of the reads that act on `ref`, need only its ids, and are not among `known`."""
    out = []
    for op in model.operation_names:
        shape = model.operation_model(op).input_shape
        required = set(shape.required_members) if shape is not None else set()
        if op in known or not required or not required <= set(ids) or not kind(service, op).reads_only:
            continue
        params = {k: ids[k] for k in required}
        named = refs(service, op, params)
        if named is not None and ref in named.primary:
            out.append((op, params))
    return out


def more_pages(body: dict[str, Any]) -> bool:
    """The answer is one page of several (a token or a truncated flag is set)."""
    return any(PAGE.search(k) and v not in (None, '', False, 'false') for k, v in body.items())


def lists(body: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    return [(k, v) for k, v in body.items() if isinstance(v, list) and v]


def item_write(model: ServiceModel, read: str, key: str) -> str | None:
    """The write that puts back one item of the list `key` that `read` answered: named after the read's noun
    (ListObjectsV2 -> PutObject) or after the items (Scan's Items -> PutItem)."""
    nouns = [n for n in (noun_of(read), split(key).joined) if n]
    for noun in nouns:
        for op in model.operation_names:
            if verb_of(op) in CREATE_VERBS and noun_of(op) == noun:
                return op
    return None


def data_reads(model: ServiceModel, service: str, ref: ResourceRef, ids: dict[str, Any], known: set[str],
               kind: Callable[[str, str], Kind], refs: Callable[[str, str, dict[str, Any]], Refs | None]) -> list[str]:
    """The reads that act on `ref` and are not among `known`, whatever else they need (GetItem's Key, HeadObject's
    Key): the reads of its data. Members other than its ids are filled with placeholders, only to place the call."""
    out = []
    for op in model.operation_names:
        shape = model.operation_model(op).input_shape
        if op in known or shape is None or not set(shape.required_members) & set(ids) or not kind(service, op).reads_only:
            continue
        params = {k: ids[k] if k in ids else PLACEHOLDER.get(shape.members[k].type_name, 'x')
                  for k in shape.required_members}
        named = refs(service, op, params)
        if named is not None and ref in named.primary:
            out.append(op)
    return out


PLACEHOLDER: dict[str, Any] = {'structure': {}, 'map': {}, 'list': [], 'integer': 1, 'long': 1, 'boolean': False}
