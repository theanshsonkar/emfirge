"""Which resource a value names, from the hand-written types (experiment 09's rule). The part the generic catalog
replaces: it says the same from AWS's published ARN formats."""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from emfirge.core.model import ResourceRef

from .spec import TypeSpec

ARN = re.compile(r'^arn:aws[\w-]*:([\w-]+):([\w-]*):(\d{12}|aws|):(.+)$')
NAMING = re.compile(r'(Name|Id|Arn|Url|Identifier)s?$')


class Unplaced:
    """An ARN in this account of a type no hand-written type knows."""

    def __init__(self, value: str) -> None:
        self.value = value


class Naming:
    def __init__(self, specs: Iterable[TypeSpec]) -> None:
        self.specs = {s.type: s for s in specs}

    def of_service(self, service: str) -> list[TypeSpec]:
        return [s for s in self.specs.values() if s.service == service]

    def recognize(self, value: Any, service: str | None = None, param: str | None = None,
                  params: Mapping[str, Any] | None = None, operation: str = '') -> ResourceRef | Unplaced | None:
        if not isinstance(value, str) or not value:
            return None
        m = ARN.match(value)
        if m:
            return self._arn(value, m)
        params = params or {}
        for s in self.specs.values():
            if s.id and re.fullmatch(s.id, value):
                return ResourceRef(s.type, value)
            if s.url and re.fullmatch(s.url, value):
                key = s.canon(value, params)
                return ResourceRef(s.type, key) if key else None
        for s in self.specs.values():
            if param and s.service == service and param in s.params and (not s.ops or re.search(s.ops, operation)):
                key = s.canon(value, params)
                return ResourceRef(s.type, key) if key else None
        return None

    def _arn(self, value: str, m: re.Match) -> ResourceRef | Unplaced | None:
        service, _, account, resource = m.groups()
        if account == 'aws':
            return None   # owned by AWS (managed policies, runtimes): nothing to copy
        for s in self.specs.values():
            if s.arn and (s.arn_service or s.service) == service:
                mm = re.fullmatch(s.arn, resource)
                if mm:
                    return ResourceRef(s.type, s.key_from_arn(mm, value))
        return Unplaced(value)

    def item_ref(self, spec: TypeSpec, value: str) -> ResourceRef | None:
        """The resource a list item's key field names."""
        if value.startswith('arn:'):
            r = self.recognize(value)
            return r if isinstance(r, ResourceRef) and r.type == spec.type else None
        key = spec.canon(value, {})
        return ResourceRef(spec.type, key) if key else None

    def naming_members(self, service: str, input_shape: Any) -> list[str]:
        """Request members that say which resource a call acts on: path members, required names and ids, and the
        members a hand-written type declares."""
        if input_shape is None:
            return []
        members = input_shape.members
        out = [n for n, s in members.items() if s.serialization.get('location') == 'uri']
        out += [n for n in input_shape.required_members if n not in out and NAMING.search(n)]
        out += [n for n in members if n not in out and any(s.service == service and n in s.params for s in self.specs.values())]
        return out
