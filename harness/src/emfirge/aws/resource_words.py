"""Words shared by the generic outcomes and the generic copier: what an operation's name and an answer's field names
say about resource types. The same rules run for every service; they compare words only (see catalog/names.py).
"""
from __future__ import annotations

import re
from functools import lru_cache

from .catalog.arns import ArnFormat, canonical_value, compile_format
from .catalog.names import Member, score, split

QUALIFIER = 'by'                                     # ListTargetsByRule: the noun ends before 'By'
INTO = 'to'                                          # AddRoleToInstanceProfile: a role into a profile
NOISE = frozenset({'list', 'entry', 'summary', 'detail', 'metadata', 'configuration', 'info', 'set', 'item'})
_TRAILER = re.compile(r'^(v?\d+|v)$')              # ListObjectsV2


def verb_of(operation: str) -> str:
    """The first word of an operation's name ('Put' for PutBucketPolicy)."""
    m = re.match(r'[A-Z][a-z]*', operation)
    return m.group(0) if m else operation


def noun_of(operation: str) -> str:
    """What an operation is about, as one joined word: its name without the verb, a 'By...' qualifier or a version
    trailer. PutBucketPolicy and GetBucketPolicy -> 'bucketpolicy'; ListTargetsByRule -> 'target'."""
    words = list(split(operation).words)[1:]
    if QUALIFIER in words:
        words = words[:words.index(QUALIFIER)]
    while words and _TRAILER.match(words[-1]):
        words.pop()
    return ''.join(words)


def into(operation: str) -> tuple[str, str] | None:
    """'X To Y' in an operation's name, as two joined words: AddRoleToInstanceProfile -> ('role', 'instanceprofile')."""
    words = list(split(operation).words)[1:]
    if INTO not in words or words.index(INTO) in (0, len(words) - 1):
        return None
    i = words.index(INTO)
    return ''.join(words[:i]), ''.join(words[i + 1:])


def type_word(type_: str) -> str:
    """A resource type's name as one joined word ('ec2:security-group' -> 'securitygroup')."""
    return split(type_.split(':', 1)[1]).joined


def names_type(word: str, type_: str) -> bool:
    """A joined word names the type: equal, it ends with the type's name ('attachedpolicy' -> policy), or the type's
    name starts with it ('rule' -> rule-on-default-event-bus). Not a type whose name only ends with it: 'query' is
    not a 'scheduled-query'."""
    t = type_word(type_)
    return bool(word) and bool(t) and (word == t or word.endswith(t) or t.startswith(word))


def list_word(member: str, item_shape: str | None = None) -> tuple[str, ...]:
    """What a list in an answer holds, from its member name and its items' shape name, without noise words
    ('SecretList' -> 'secret', 'TableNames' -> 'table')."""
    out = []
    for name in (member, item_shape or ''):
        words = [w for w in split(name).words if w not in NOISE]
        if words:
            out.append(''.join(words))
    return tuple(dict.fromkeys(out))


@lru_cache(maxsize=4096)
def formats(type_: str, texts: tuple[str, ...]) -> tuple[ArnFormat, ...]:
    return tuple(f for f in (compile_format(type_, t) for t in texts) if f)


def binds(field: str, type_: str, texts: tuple[str, ...], strong: int = 4) -> str | None:
    """The ARN variable of the type that a field named `field` carries (GroupId -> ${SecurityGroupId}), when the
    type has a single-variable format and the field fits it at least as well as `strong` (catalog/names.score)."""
    member = Member(field, False, False, False, '')
    for f in formats(type_, texts):
        if len(f.variables) == 1 and score(f.variables[0], type_.split(':', 1)[1], member) >= strong:
            return f.variables[0]
    return None


def canonical(fmt_texts: tuple[str, ...], type_: str, variable: str, value: str) -> str:
    """A bare value of one variable, the way the catalog writes ids: '/hostedzone/Z1' -> 'Z1' (the literal before
    the variable), '/app/x' -> 'app/x' for ${...WithoutLeadingSlash}."""
    value = canonical_value(variable, value)
    for f in formats(type_, fmt_texts):
        if variable in f.variables:
            before = f.literal_before(variable)
            if re.search('[A-Za-z]', before) and before in value:
                value = value.rsplit(before, 1)[1]
            break
    return value
