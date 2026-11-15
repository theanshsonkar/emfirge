"""ARN formats, as AWS publishes them, turned into parsers.

A format is 'arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}'. Its resource part (after the
fifth ':') becomes a regular expression with one group per variable. The rules are the same for every service:

  * a variable followed by more text stops at ':' and at the next literal character ('schedule/${Group}/${Name}');
  * the last variable runs to the end after a '/' (paths: role/${RoleNameWithPath}, ${Bucket}/${ObjectName}),
    unless the type has types inside it (table/${TableName} has table/${TableName}/index/...); it stops at ':'
    otherwise (function:${FunctionName} is not function:${FunctionName}:${Alias});
  * an ARN that matches no format fully, but whose start matches one up to a ':' or '/', names the thing it starts
    with (function:f:$LATEST is the function, log-group:g:* is the log group);
  * an ARN that ends in a wildcard segment ('/*', ':*') names the thing before it (a bucket policy's 'b/*').

The id of a resource is its variables' values joined by '/', each made canonical by its variable's own name:
${...WithPath} keeps the last segment (a role is named by its name, whatever its path), and
${...WithoutLeadingSlash} drops a leading '/'.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

VAR = re.compile(r'\$\{(\w+)\}')
AMBIENT = frozenset({'Partition', 'Region', 'Account'})
ARN_IN_TEXT = re.compile(r'arn:aws[\w-]*:[\w-]+:[^\s"\'<>,;\]\[{}()\\]*')


@dataclass(frozen=True)
class ArnFormat:
    """One published ARN format of one resource type."""
    type: str
    text: str
    service: str
    resource: str                   # the resource part, with ${Var}s
    variables: tuple[str, ...]
    literal: int                    # how many literal characters the resource part has (more = more specific)
    regex: Pattern[str]
    prefix_regex: Pattern[str]      # the same, allowed to be followed by ':...' or '/...'
    open_variables: frozenset[str]  # variables that run to the end (may hold ':' and '/')

    def literal_before(self, variable: str) -> str:
        """The literal text right before a variable ('hostedzone/' before ${Id})."""
        head = self.resource.split('${' + variable + '}', 1)[0]
        return re.split(r'\$\{\w+\}', head)[-1]


@dataclass(frozen=True)
class Arn:
    partition: str
    service: str
    region: str
    account: str
    resource: str


def split_arn(value: str) -> Arn | None:
    if not isinstance(value, str) or not value.startswith('arn:'):
        return None
    parts = value.split(':', 5)
    if len(parts) != 6 or not parts[2]:
        return None
    return Arn(parts[1], parts[2], parts[3], parts[4], parts[5])


def resource_regex(template: str, open_end: bool = True) -> str:
    """The resource part of a format as a regex, one named group per variable (see module docstring).
    open_end=False for a type that has types inside it (a table has indexes): its last variable stops at '/'."""
    pieces = re.split(r'(\$\{\w+\})', template)
    out = []
    for i, piece in enumerate(pieces):
        m = VAR.fullmatch(piece)
        if not m:
            out.append(re.escape(piece))
            continue
        following = next((p for p in pieces[i + 1:] if p), '')
        preceding = pieces[i - 1] if i else ''
        if following:
            stop = re.escape(following[0]) if following[0] != ':' else ''
            out.append(f'(?P<{m.group(1)}>[^:{stop}]+)')
        elif preceding.endswith('/') and open_end:
            out.append(f'(?P<{m.group(1)}>.+)')
        elif preceding.endswith('/'):
            out.append(f'(?P<{m.group(1)}>[^:/]+)')
        else:
            out.append(f'(?P<{m.group(1)}>[^:]+)')
    return ''.join(out)


def compile_format(type_: str, text: str, open_end: bool = True) -> ArnFormat | None:
    """None for formats this parser cannot use (a variable in the service field, or a broken format)."""
    parts = text.split(':', 5)
    if len(parts) != 6 or '$' in parts[2]:
        return None
    resource = parts[5]
    variables = tuple(v for v in VAR.findall(resource) if v not in AMBIENT)
    if len(set(VAR.findall(resource))) != len(VAR.findall(resource)):
        return None   # a variable twice: the regex would need back references; no such format is common
    body = resource_regex(resource, open_end)
    try:
        regex = re.compile(body + r'\Z')
        prefix = re.compile(body + r'(?=[:/])')
    except re.error:
        return None
    open_vars = frozenset(re.findall(r'\(\?P<(\w+)>\.\+\)', body))
    return ArnFormat(type_, text, parts[2], resource, variables, len(VAR.sub('', resource)), regex, prefix, open_vars)


def canonical_value(variable: str, value: str) -> str:
    """One variable's value, the same whichever way it was given."""
    if variable.endswith('WithPath'):
        return value.rstrip('/').rsplit('/', 1)[-1]
    if variable.endswith('WithoutLeadingSlash'):
        return value.lstrip('/')
    return value


def strip_wildcard(resource: str) -> str | None:
    """'b/*' -> 'b', 'g:*' -> 'g'; a wildcard anywhere else makes a pattern, not a name -> None."""
    if not any(c in resource for c in '*?'):
        return resource
    m = re.fullmatch(r'(.+?)[:/][*?]+', resource)
    if m and not any(c in m.group(1) for c in '*?'):
        return m.group(1)
    return None


@dataclass(frozen=True)
class Parsed:
    type: str
    values: dict[str, str]          # variable -> canonical value
    format: ArnFormat


class ArnIndex:
    """All formats of the ARN services seen so far, and the parent relation between types (bucket <- object)."""

    def __init__(self, formats: list[ArnFormat], parents: dict[str, str]):
        self.formats = formats
        self.parents = parents

    def parse(self, resource: str) -> Parsed | None:
        """The resource part of an ARN -> the type it names. Most literal characters win. Two types that match
        equally (a lambda alias and a version look the same) give their common parent, or nothing."""
        resource = strip_wildcard(resource)
        if resource is None:
            return None
        hit = self._best([f for f in self.formats if f.regex.match(resource)], resource, full=True)
        if hit is None:
            hit = self._best([f for f in self.formats if f.prefix_regex.match(resource)], resource, full=False)
        return hit

    def _best(self, candidates: list[ArnFormat], resource: str, full: bool) -> Parsed | None:
        if not candidates:
            return None
        if not full:   # the longest start wins: function:f:$LATEST is a function, not a layer
            top = max(len(f.prefix_regex.match(resource).group(0)) for f in candidates)
            candidates = [f for f in candidates if len(f.prefix_regex.match(resource).group(0)) == top]
        top = max(f.literal for f in candidates)
        best = [f for f in candidates if f.literal == top]
        types = {f.type for f in best}
        if len(types) == 1:
            f = best[0]
            m = (f.regex if full else f.prefix_regex).match(resource)
            return Parsed(f.type, {v: canonical_value(v, m.group(v)) for v in f.variables}, f)
        parents = {self.parents.get(t) for t in types}
        if len(parents) == 1 and None not in parents:
            parent = parents.pop()
            for f in self.formats:
                if f.type == parent:
                    m = f.prefix_regex.match(resource)
                    if m:
                        return Parsed(parent, {v: canonical_value(v, m.group(v)) for v in f.variables}, f)
        return None


def parent_of(fmt: ArnFormat, others: list[ArnFormat]) -> str | None:
    """The type whose format is the longest proper start of this one, cut at ':' or '/' (bucket for object)."""
    best, best_len = None, 0
    for o in others:
        if o.type == fmt.type or o.service != fmt.service:
            continue
        if fmt.resource.startswith(o.resource) and fmt.resource[len(o.resource):len(o.resource) + 1] in (':', '/') \
                and len(o.resource) > best_len:
            best, best_len = o.type, len(o.resource)
    return best
