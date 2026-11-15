"""The compiled catalog file and the overrides, decoded lazily: a service or an ARN service is decoded the first
time a call needs it, so starting Emfirge does not pay for 400 services."""
from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from .arns import ArnFormat, ArnIndex, compile_format

DATA = Path(__file__).resolve().parent.parent / 'data'


@dataclass(frozen=True)
class ResourceTypeInfo:
    """What AWS publishes about one resource type, for the modules that judge a change (undo, lenses)."""
    type: str
    arn_formats: tuple[str, ...]
    parent: str | None                      # the type it lives in, by ARN (s3:bucket for s3:object)
    cfn_type: str | None                    # the CloudFormation type that describes it, when one could be tied
    cfn_identifier: tuple[str, ...]         # that type's primaryIdentifier properties
    holds_data: bool                        # it, or a type inside it, has data-plane actions
    id_given_by_service: bool | None        # None: no CloudFormation schema says
    write_only_settings: tuple[str, ...]    # settings that can be written but never read back


@dataclass(frozen=True)
class Overrides:
    """overrides.json, indexed. Each entry is data with a 'why' and a test; see that file."""
    absent_means: dict[tuple[str, str], str]
    same_as_absent: dict[tuple[str, str], str]
    arn_suffix: dict[tuple[str, str], re.Pattern[str]]
    count: int

    @classmethod
    def load(cls, path: Path | None = None) -> 'Overrides':
        raw = json.loads((path or DATA / 'overrides.json').read_text())
        pair = lambda e: (e['type'], e['variable'])
        return cls({pair(e): e['value'] for e in raw.get('absent_means', [])},
                   {pair(e): e['value'] for e in raw.get('same_as_absent', [])},
                   {pair(e): re.compile(e['pattern']) for e in raw.get('arn_suffix', [])},
                   sum(len(v) for k, v in raw.items() if isinstance(v, list)))


class Store:
    """Lazy access to the compiled file. Not thread-safe for the first decode of a part; decoding twice is harmless."""

    def __init__(self, path: Path | None = None):
        self._path = path
        self._ops: dict[str, dict[str, Any]] = {}
        self._types: dict[str, dict[str, Any]] = {}
        self._formats: dict[str, list[ArnFormat]] = {}
        self._indexes: dict[str, ArnIndex] = {}

    @cached_property
    def _raw(self) -> dict[str, Any]:
        blob = (self._path or DATA / 'catalog.json.gz').read_bytes()
        return json.loads(gzip.decompress(blob))

    @property
    def built_from(self) -> dict[str, Any]:
        return self._raw['built_from']

    def services(self) -> list[str]:
        return sorted(self._raw['services'])

    def ops(self, service: str) -> dict[str, Any] | None:
        if service not in self._ops:
            text = self._raw['services'].get(service)
            if text is None:
                return None
            self._ops[service] = json.loads(text)
        return self._ops[service]

    def type_row(self, type_: str) -> dict[str, Any] | None:
        prefix, _, name = type_.partition(':')
        if prefix not in self._types:
            text = self._raw['types'].get(prefix)
            self._types[prefix] = json.loads(text) if text else {}
        return self._types[prefix].get(name)

    def formats(self, type_: str) -> list[ArnFormat]:
        if type_ not in self._formats:
            row = self.type_row(type_) or {}
            open_end = not row.get('k')
            self._formats[type_] = [f for f in (compile_format(type_, t, open_end) for t in row.get('f', [])) if f]
        return self._formats[type_]

    def arn_index(self, arn_service: str) -> ArnIndex | None:
        """Every format whose ARNs carry this service name, across the prefixes that define one."""
        if arn_service not in self._indexes:
            prefixes = self._raw['arn_services'].get(arn_service)
            if not prefixes:
                return None
            formats, parents = [], {}
            for prefix in prefixes:
                self.type_row(prefix + ':')
                for name, row in self._types[prefix].items():
                    tid = f'{prefix}:{name}'
                    formats += [f for f in self.formats(tid) if f.service == arn_service]
                    if 'p' in row:
                        parents[tid] = row['p']
            self._indexes[arn_service] = ArnIndex(formats, parents)
        return self._indexes[arn_service]

    def info(self, type_: str) -> ResourceTypeInfo | None:
        row = self.type_row(type_)
        if row is None:
            return None
        return ResourceTypeInfo(type_, tuple(row.get('f', [])), row.get('p'), row.get('cfn'), tuple(row.get('cfn_id', [])),
                                bool(row.get('d')), row.get('id_given_by_service'), tuple(row.get('write_only_settings', [])))
