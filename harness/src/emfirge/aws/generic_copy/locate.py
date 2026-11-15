"""Reads for a resource the catalog cannot build one for, found through the resource's own list. No code per type.

Why: the catalog names some resources by part of their ARN only (an IAM policy by its name, without its path), so it
cannot build the ARN its reads take. The type's list (ListPolicies) carries each item's full ARN; the Get named after
the type that takes just that ARN (GetPolicy) then reads it.
"""
from __future__ import annotations

from typing import Any, Callable, Iterator

from botocore.model import ServiceModel

from emfirge.core.model import ResourceRef

from ..catalog.names import split
from ..resource_words import noun_of, type_word, verb_of


def arn_of(pages: Iterator[dict[str, Any]], ref: ResourceRef, parse: Callable[[str], ResourceRef | None]) -> str | None:
    """The ARN of `ref` in a list's pages: an item field holding an ARN that names it."""
    for page in pages:
        for value in page.values():
            for item in value if isinstance(value, list) else []:
                for v in item.values() if isinstance(item, dict) else []:
                    if isinstance(v, str) and v.startswith('arn:') and parse(v) == ref:
                        return v
    return None


def reads_by_arn(model: ServiceModel, type_: str, arn: str) -> list[tuple[str, dict[str, Any]]]:
    """Gets named after the type whose only required member takes an ARN (GetPolicy's PolicyArn)."""
    out = []
    word = type_word(type_)
    for op in model.operation_names:
        shape = model.operation_model(op).input_shape
        required = list(shape.required_members) if shape is not None else []
        if verb_of(op) == 'Get' and noun_of(op) == word and len(required) == 1 and split(required[0]).designator == 'arn':
            out.append((op, {required[0]: arn}))
    return out
