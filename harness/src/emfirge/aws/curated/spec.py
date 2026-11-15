"""What one hand-written resource type says about itself (ported from experiment 09's hydrators).

Naming (the part a generic catalog replaces): which request members carry its key, how its ARN, bare id or URL
looks, which list answers show it. Copying (the part a generic copier would replace): which reads show its state and
how to rebuild it in the engine. ResourceRef types use AWS's Service Authorization Reference names
('lambda:function'); ids are the variable part of the ARN (a name, or an id).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:
    from .context import CopyContext

Read = tuple[str, dict[str, Any]]


@dataclass(frozen=True)
class Where:
    """Region and account id, for ARNs and URLs a type builds."""
    region: str
    account: str


def _same(value: str, params: Mapping[str, Any]) -> str | None:
    return value


def _group1(m: re.Match, value: str) -> str:
    return m.group(1)


@dataclass(frozen=True)
class TypeSpec:
    type: str                                   # '<iam prefix>:<resource name>'
    service: str                                # botocore's service name
    params: tuple[str, ...] = ()                # request members that carry its key
    arn: str | None = None                      # regex on the ARN's resource part; group 1 is the key
    arn_service: str | None = None              # the ARN's service, when it is not `service`
    id: str | None = None                       # regex for a bare id (EC2 style)
    url: str | None = None                      # regex for a URL that names it
    ops: str | None = None                      # only operations matching this take a plain value in `params` as its key
    lists: tuple[tuple[str, str, str | None], ...] = ()   # (list operation, answer member, item field with its key)
    service_ids: bool = False                   # its id is given out by the service, not chosen by the caller
    removed_by: tuple[str, ...] = ()            # operations that delete it (even when the service finishes later)
    canon: Callable[[str, Mapping[str, Any]], str | None] = _same
    key_from_arn: Callable[[re.Match, str], str] = _group1
    reads: Callable[[Where, str], list[Read]] = lambda where, key: []
    copy: Callable[['CopyContext', str], bool] | None = None   # False when the real account does not have it


def pick(d: Mapping[str, Any], *names: str) -> dict[str, Any]:
    """The named settings that are set (copy only what the real resource has)."""
    return {k: d[k] for k in names if d.get(k) not in (None, '', [], {})}
