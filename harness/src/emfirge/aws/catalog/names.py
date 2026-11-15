"""Name matching: which request parameter carries which part of a resource's ARN.

AWS names the variables of its ARN formats (${FunctionName}, ${RoleNameWithPath}, ${Id}) and the members of its
requests (FunctionName, RoleName, HostedZoneId, QueueUrl) in the same words, mostly. This module compares the
words only. It holds no knowledge of any one service: the same rules run for all of them.

Used by the compile step only; the runtime catalog reads the compiled result.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Words that say how a thing is designated, not what it is. Mapped to a designator class.
DESIGNATORS = {
    'name': 'name', 'names': 'name', 'id': 'id', 'ids': 'id', 'identifier': 'identifier',
    'identifiers': 'identifier', 'arn': 'arn', 'arns': 'arn', 'url': 'url', 'urls': 'url',
}
# Words that carry no meaning for matching ('RoleNameWithPath', 'ParameterNameWithoutLeadingSlash', 'ResourceArn').
NOISE = {'with', 'without', 'path', 'leading', 'slash', 'resource'}

# A name and an id are different things (EC2: GroupName is not GroupId). 'identifier' is used for both.
_COMPATIBLE = {
    ('name', 'id'): False, ('id', 'name'): False,
    ('name', 'url'): True, ('url', 'name'): True,
}

_WORD = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+')


@dataclass(frozen=True)
class Words:
    """A parameter or variable name, split: its meaning words and how it designates (name, id, arn, url)."""
    words: tuple[str, ...]
    designator: str | None

    @property
    def joined(self) -> str:
        return ''.join(self.words)


def singular(word: str) -> str:
    """Plural and singular must compare equal (InstanceIds <-> InstanceId, Policies <-> Policy)."""
    if word.endswith('ies') and len(word) > 4:
        return word[:-3] + 'y'
    if word.endswith('s') and not word.endswith(('ss', 'us')) and len(word) > 3:
        return word[:-1]
    return word


def split(name: str) -> Words:
    """CamelCase, snake_case, kebab-case or spaced -> meaning words (singular, lower case) and a designator."""
    raw = [w.lower() for w in _WORD.findall(re.sub(r'[^A-Za-z0-9]+', ' ', name))]
    designator = None
    words = []
    for w in raw:
        if w in DESIGNATORS:
            designator = DESIGNATORS[w]
        elif w not in NOISE:
            words.append(singular(w))
    return Words(tuple(words), designator)


def compatible(var: str | None, param: str | None) -> bool:
    if var is None or param is None:
        return True
    return _COMPATIBLE.get((var, param), True)


def related(a: str, b: str) -> bool:
    """Two joined word strings name the same thing: equal, or one is the tail of the other."""
    return bool(a) and bool(b) and (a == b or a.endswith(b) or b.endswith(a))


@dataclass(frozen=True)
class Member:
    """One request member, as the compile step sees it."""
    name: str
    is_list: bool
    required: bool
    in_uri: bool
    doc: str            # first sentence of botocore's documentation, lower case, no markup


def score(var: str, resource: str, member: Member) -> int:
    """How well a request member fits an ARN variable; 0 = not at all. Rules, strongest first:
    5  same words                     FunctionName <-> FunctionName, DbInstanceName <-> DBInstanceIdentifier
    4  the member's words are the tail of the variable's      SecurityGroupId <-> GroupId
    4  the variable is a bare designator (${Id}) and the member is named after the resource   HostedZoneId
    3  the member's words are some of the variable's, in order, and name the resource
                                      DbClusterInstanceName <-> DBClusterIdentifier (resource 'cluster')
    2  the member is a bare designator (Name, Id) and the variable is named after the resource  RuleName <-> Name
    1  a required path member whose documentation names the resource              ObjectName <-> Key ('Object key ...')
    Arn members are not bound to variables: they carry a whole ARN (see arn_member)."""
    v, m, r = split(var), split(member.name), split(resource)
    if m.designator == 'arn' or not compatible(v.designator, m.designator):
        return 0
    if m.words and m.words == v.words:
        return 5
    if m.words and v.words and len(m.words) < len(v.words) and v.words[-len(m.words):] == m.words:
        return 4
    if not v.words and m.words and related(r.joined, m.joined) and r.joined.endswith(m.joined):
        return 4
    if m.words and v.words and _subsequence(m.words, v.words) and r.joined and r.joined in m.joined:
        return 3
    if not m.words and m.designator and (not v.words or set(v.words) <= set(r.words) or related(r.joined, v.joined)):
        return 2
    if member.required and member.in_uri and not m.designator and _doc_names(member.doc, v, r):
        return 1
    return 0


def _subsequence(short: tuple[str, ...], long: tuple[str, ...]) -> bool:
    it = iter(long)
    return len(short) < len(long) and all(w in it for w in short)


def _doc_names(doc: str, var: Words, resource: Words) -> bool:
    first = doc.split('. ')[0]
    words = set(singular(w) for w in re.findall(r'[a-z0-9]+', first))
    want = var.words or resource.words
    return bool(want) and set(want) <= words and first.startswith(want[0])


def bind_vars(variables: list[str], resource: str, members: list[Member]) -> dict[str, Member]:
    """Variable -> member, by the best score, each member used once. Variables without a fitting member are left out."""
    out: dict[str, Member] = {}
    taken: set[str] = set()
    for var in variables:
        best, best_score = None, 0
        for m in members:
            if m.name in taken:
                continue
            s = score(var, resource, m)
            if s > best_score:
                best, best_score = m, s
        if best is not None:
            out[var] = best
            taken.add(best.name)
    return out


def arn_member(resources: list[str], members: list[Member]) -> Member | None:
    """A member that carries a whole ARN of the resource: a bare Arn / ResourceArn / Resource, or <Resource>Arn."""
    named = [split(r).joined for r in resources]
    for m in members:
        w = split(m.name)
        if w.designator == 'arn' and (not w.words or any(related(n, w.joined) or n.startswith(w.joined) for n in named)):
            return m
    for m in members:
        if m.name.lower() == 'resource':
            return m
    return None
