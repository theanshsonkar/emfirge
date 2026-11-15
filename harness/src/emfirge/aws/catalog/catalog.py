"""AwsCatalog: the Catalog port for AWS, answered from the compiled catalog (see compile.py). No code per service.

refs(call) works in three steps, the same for every service:
  1 bindings   the compiled catalog says which request member fills which variable of a resource type's ARN.
               Each value is made canonical (an ARN, a URL, '/hostedzone/Z1', 'fn:qualifier' all give the
               plain id), so a resource named by name, by ARN, by URL or in a plural list gives the same ref.
  2 mentions   every ARN anywhere in the parameters (also inside JSON documents held in strings, such as
               policies) that names a known resource type and is not owned by AWS. The containers of the
               primary resources (the bucket of an object) are mentioned too: the call names them.
  3 complete   False when a changing call acts, by AWS's list, on a resource and none could be placed.
"""
from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

from emfirge.core.model import Call, Kind, Refs, ResourceRef

from . import kinds
from .arns import ARN_IN_TEXT, ArnFormat, Parsed, canonical_value, split_arn
from .store import Overrides, ResourceTypeInfo, Store

URL = re.compile(r'^https?://[^/]+/(?:[^?#]*/)?([^/?#]+)/?(?:[?#].*)?$')
TEMPLATE_VAR = re.compile(r'\$\{(\w+)\}')


class AwsCatalog:
    """What AWS publishes about its calls and resources. account / region / partition are only needed to build
    the ARNs some reads take (reads_of); refs() works without them."""

    def __init__(self, path: Path | None = None, overrides: Path | None = None,
                 account: str | None = None, region: str | None = None, partition: str = 'aws'):
        self._store = Store(path)
        self._overrides = Overrides.load(overrides)
        self._ambient = {'Partition': partition, 'Region': region, 'Account': account}

    @property
    def overrides_count(self) -> int:
        return self._overrides.count

    # ---------------------------------------------------------------- the port
    def kind(self, service: str, operation: str) -> Kind:
        """AWS's published kind, with the two-key read rule (kinds.py): a read must also be named like one."""
        entry = self._entry(service, operation)
        return kinds.two_key(Kind(entry['k']), operation) if entry else Kind.UNKNOWN

    def why_kind(self, service: str, operation: str) -> str:
        """Plain words on why kind() says what it says; for the branch's refusal message."""
        entry = self._entry(service, operation)
        return kinds.why(Kind(entry['k']) if entry else None, operation, (entry or {}).get('a', ''))

    def refs(self, call: Call) -> Refs:
        entry = self._entry(call.service, call.operation) or {'k': 'unknown'}
        kind = self.kind(call.service, call.operation)
        primary, secondary = self._bound(entry, call.params)
        primary = _unique(primary)
        mentioned = [r for r in _unique(secondary + self._containers(primary) + list(self._mentions(call.params)))
                     if r not in primary]
        return Refs(tuple(primary), tuple(mentioned), self._complete(entry, kind, primary))

    def reads_of(self, ref: ResourceRef) -> list[tuple[str, str, dict[str, Any]]]:
        row = self._store.type_row(ref.type)
        if not row:
            return []
        out = []
        for service, op, template in row.get('r', []):
            values = self._values_from_id(ref, _template_vars(template))
            params = _fill(template, {**self._ambient, **values}) if values is not None else None
            if params is not None and self.kind(service, op).reads_only:
                out.append((service, op, params))
        return out

    # ---------------------------------------------------------------- for other modules
    def resource_type(self, type_: str) -> ResourceTypeInfo | None:
        return self._store.info(type_)

    def parse_arn(self, value: str) -> ResourceRef | None:
        """An ARN -> the resource it names, or None (not an ARN, owned by AWS, or no known type fits)."""
        parsed = self._parse(value)
        return self._ref(parsed.type, parsed.format, parsed.values) if parsed else None

    # ---------------------------------------------------------------- step 1: bindings
    def _entry(self, service: str, operation: str) -> dict[str, Any] | None:
        ops = self._store.ops(service)
        return ops.get(operation) if ops else None

    def _bound(self, entry: dict[str, Any], params: dict[str, Any]) -> tuple[list[ResourceRef], list[ResourceRef]]:
        found = [(b, self._bind(b, params)) for b in entry.get('b', [])]
        found = [(b, refs, _members(b)) for b, refs in found if refs]
        primary: list[ResourceRef] = []
        secondary: list[ResourceRef] = []
        for b, refs, used in found:
            if any(used < other for _, _, other in found):
                continue    # a less specific reading of the same members (rule/<name> when the bus is named too)
            (primary if b['g'] else secondary).extend(refs)
        for b in entry.get('m', []):
            secondary.extend(self._bind(b, params))
        if 'arn' in entry:
            member, _ = entry['arn']
            primary += [r for r in (self.parse_arn(v) for v in _values(params.get(member))) if r]
        return primary, secondary

    def _bind(self, binding: dict[str, Any], params: dict[str, Any]) -> list[ResourceRef]:
        """The refs one binding gives: the first alternative (most variables first) whose members are all present,
        or can be filled by an 'absent_means' override."""
        type_ = binding['t']
        formats = self._store.formats(type_)
        for index, members in binding['alts']:
            if index >= len(formats):
                continue
            fmt = formats[index]
            given = {var: _values(params.get(m)) for var, (m, _) in members.items()}
            if any(self._overrides.same_as_absent.get((type_, v)) in vals for v, vals in given.items()):
                continue
            for var, vals in given.items():
                if not vals and (type_, var) in self._overrides.absent_means:
                    given[var] = [self._overrides.absent_means[(type_, var)]]
            if all(given.values()):
                return [r for combo in _combinations(given) if (r := self._resolve(fmt, combo))]
        return []

    def _resolve(self, fmt: ArnFormat, raw: dict[str, Any]) -> ResourceRef | None:
        """Bound values -> one ref. A value that is itself an ARN, or names another type of the service by its own
        prefix ('alias/x' for a KeyId), is that resource."""
        values = {}
        for var, value in raw.items():
            if not isinstance(value, str) or not value:
                return None
            got = self._canonical(fmt, var, value, single=len(raw) == 1)
            if isinstance(got, ResourceRef) or got is None:
                return got
            values[var] = got
        return self._ref(fmt.type, fmt, values)

    def _canonical(self, fmt: ArnFormat, var: str, value: str, single: bool) -> str | ResourceRef | None:
        if value.startswith('arn:'):
            parsed = self._parse(value)
            if parsed is None:
                return None
            if parsed.type == fmt.type or single and var not in parsed.values:
                return self._ref(parsed.type, parsed.format, parsed.values)
            return parsed.values.get(var)
        url = URL.match(value)
        if url:
            value = url.group(1)
        value = canonical_value(var, value)
        before = fmt.literal_before(var)
        if re.search('[A-Za-z]', before) and before in value:
            value = value.rsplit(before, 1)[1]      # '/hostedzone/Z1' for ${Id} after 'hostedzone/'
        if single:
            other = self._other_type(fmt, value)
            if other:
                return other
        if var not in fmt.open_variables and ':' in value:
            value = value.split(':', 1)[0]           # 'fn:live' names the function, as fn's ARN would
        return value or None

    def _other_type(self, fmt: ArnFormat, value: str) -> ResourceRef | None:
        index = self._store.arn_index(fmt.service)
        parsed = index.parse(value) if index else None
        if parsed and parsed.type != fmt.type and parsed.format.literal and \
                not parsed.format.resource.startswith('${'):
            return self._ref(parsed.type, parsed.format, parsed.values)
        return None

    # ---------------------------------------------------------------- ARNs and ids
    def _parse(self, value: str) -> Parsed | None:
        arn = split_arn(value)
        if arn is None or arn.account == 'aws':
            return None     # owned by AWS (managed policies, public layers): not a resource of this account
        index = self._store.arn_index(arn.service)
        parsed = index.parse(arn.resource) if index else None
        if parsed is None:
            return None
        values = {v: self._strip_suffix(parsed.type, v, x) for v, x in parsed.values.items()}
        return Parsed(parsed.type, values, parsed.format)

    def _strip_suffix(self, type_: str, var: str, value: str) -> str:
        rx = self._overrides.arn_suffix.get((type_, var))
        return rx.sub('', value) if rx else value

    @staticmethod
    def _ref(type_: str, fmt: ArnFormat, values: dict[str, str]) -> ResourceRef | None:
        parts = [values.get(v) for v in fmt.variables]
        if not parts or not all(parts):
            return None
        return ResourceRef(type_, '/'.join(parts))

    def _values_from_id(self, ref: ResourceRef, wanted: set[str]) -> dict[str, str] | None:
        """The id split back into variables, by the type's formats that hold every wanted variable. When two
        formats fit and disagree on the names, nothing: a read with the wrong variable would show another thing."""
        wanted = wanted - set(self._ambient)
        fits = [f for f in self._store.formats(ref.type) if wanted <= set(f.variables)]
        splits = [s for s in (_split_id(f, ref.id) for f in fits) if s is not None]
        if not splits or any({k: s[k] for k in wanted} != {k: splits[0][k] for k in wanted} for s in splits):
            return None
        return splits[0]

    # ---------------------------------------------------------------- step 2: mentions
    def _mentions(self, params: Any) -> Iterator[ResourceRef]:
        for text in _strings(params):
            for m in ARN_IN_TEXT.finditer(text):
                ref = self.parse_arn(m.group(0))
                if ref:
                    yield ref

    def _containers(self, refs: list[ResourceRef]) -> list[ResourceRef]:
        """The types each ref lives in (the bucket of an object), from the ref's own id."""
        out = []
        for ref in refs:
            row = self._store.type_row(ref.type) or {}
            parent = row.get('p')
            pformats = self._store.formats(parent) if parent else []
            for child in self._store.formats(ref.type):
                values = _split_id(child, ref.id)
                pf = next((f for f in pformats if values and set(f.variables) <= set(values)), None)
                if pf:
                    pref = self._ref(parent, pf, values)
                    if pref:
                        out.append(pref)
                    break
        return out

    # ---------------------------------------------------------------- step 3: complete
    @staticmethod
    def _complete(entry: dict[str, Any], kind: Kind, primary: list[ResourceRef]) -> bool:
        """A changing call that AWS says acts on a resource must be placed. A create of a thing whose id the
        service gives (CreateSecurityGroup, RunInstances) cannot name it, and is complete without it."""
        if kind == Kind.UNKNOWN:
            return False
        if kind.reads_only or not entry.get('n') or primary:
            return True
        return bool(entry.get('c'))


# -------------------------------------------------------------------- helpers
def _members(binding: dict[str, Any]) -> frozenset[str]:
    """The request members a binding's first alternative reads."""
    return frozenset(m for m, _ in binding['alts'][0][1].values()) if binding['alts'] else frozenset()


def _values(value: Any) -> list[Any]:
    if value is None or value == '' or value == []:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _combinations(given: dict[str, list[Any]]) -> Iterator[dict[str, Any]]:
    keys = list(given)
    for combo in itertools.product(*(given[k] for k in keys)):
        yield dict(zip(keys, combo))


def _unique(refs: Iterable[ResourceRef]) -> list[ResourceRef]:
    return list(dict.fromkeys(refs))


def _strings(value: Any) -> Iterator[str]:
    """Every string anywhere in nested parameters. JSON documents held in strings are scanned as text: an ARN
    inside them is found by the same pattern."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _split_id(fmt: ArnFormat, id_: str) -> dict[str, str] | None:
    """An id back into its variables. Only the last variable may hold '/', unless the format has a single one."""
    n = len(fmt.variables)
    if n == 0:
        return None
    parts = id_.split('/', n - 1) if n > 1 else [id_]
    return dict(zip(fmt.variables, parts)) if len(parts) == n and all(parts) else None


def _template_vars(template: Any) -> set[str]:
    return set(TEMPLATE_VAR.findall(str(template)))


def _fill(template: Any, values: dict[str, str | None]) -> Any:
    """Fill '${Var}' in a read's parameters; None when a needed value is unknown (no account given, ...)."""
    if isinstance(template, dict):
        out = {k: _fill(v, values) for k, v in template.items()}
        return None if any(v is None for v in out.values()) else out
    if isinstance(template, list):
        out = [_fill(v, values) for v in template]
        return None if any(v is None for v in out) else out
    missing = [v for v in TEMPLATE_VAR.findall(template) if not values.get(v)]
    if missing:
        return None
    return TEMPLATE_VAR.sub(lambda m: values[m.group(1)], template)
