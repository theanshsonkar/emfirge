"""Plan the calls that put one changing call back, from AWS's models alone (ported from experiment 11's undo layer).

  G1  the same operation with the old values (Update/Put/Set/Modify/Change/Replace). Each value the call set is
      looked up under the same name in the resource's reads at copy time. The reads at the end of the session must
      show the value the call set at that place: otherwise a comparison could not see whether it came back, and the
      plan is refused.
  G2  the inverse operation, found by name from a table of verb pairs (Attach/Detach, Create/Delete, Put-on-nothing/
      Delete, Tag/Untag, ...). Values come from the call, from the ids the service gave what the call created, and
      (to restore something taken away) from the reads at copy time.

There is no code per service and no table per call. Where neither strategy applies the answer is NoPlan with the
reason; the prover turns it into "unknown". A call whose payload is the customer's data (an object body) is never
planned: no read shows data itself, so no comparison could prove it came back.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from botocore.model import Shape

from emfirge.branch.journal import Entry
from emfirge.core.model import ResourceRef

from .model import IDENT, MISSING, NOUN_SUFFIX, Models, coerce, verb_noun, words

UPDATE_VERBS = ('Update', 'Put', 'Set', 'Modify', 'Change', 'Replace')
INVERSE: dict[str, tuple[str, ...]] = {
    'Attach': ('Detach',), 'Detach': ('Attach',), 'Add': ('Remove',), 'Remove': ('Add', 'Put'),
    'Enable': ('Disable',), 'Disable': ('Enable',), 'Tag': ('Untag',), 'Untag': ('Tag',),
    'Authorize': ('Revoke',), 'Revoke': ('Authorize',), 'Create': ('Delete',), 'Delete': ('Create', 'Put'),
    'Put': ('Delete',), 'Subscribe': ('Unsubscribe',), 'Unsubscribe': ('Subscribe',), 'Publish': ('Delete',),
    'Associate': ('Disassociate',), 'Disassociate': ('Associate',), 'Register': ('Deregister',),
    'Deregister': ('Register',), 'Start': ('Stop',), 'Stop': ('Start',), 'Schedule': ('Cancel',)}
"""Verb pairs that hold across AWS's APIs. Only the verbs: the operation is the inverse verb plus the same noun."""
RESTORE_FROM_SNAPSHOT = frozenset({'Delete', 'Remove', 'Untag', 'Unsubscribe', 'Deregister', 'Revoke', 'Detach',
                                   'Disassociate'})
"""Verbs that take something away: their inverse needs the old values, from the reads at copy time."""

Names = Callable[[str, str, dict[str, Any]], tuple[ResourceRef, ...]]
"""(service, operation, args) -> the resources such a call acts on (the branch's own catalog says)."""


@dataclass(frozen=True)
class Read:
    """One read of a resource the call named, as botocore parses it."""
    operation: str
    body: Any
    listed: bool = False      # a list of many resources: only its items that mention the resource count


@dataclass(frozen=True)
class View:
    """The reads of the resources a call named, at one moment, and the ids that pick their items out of lists."""
    reads: tuple[Read, ...]
    ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Step:
    """One inverse call. `optional` members may be dropped when the engine refuses the call; `narrowed` is the same
    call with each map cut to the keys the original call set, tried when the whole map is refused."""
    service: str
    operation: str
    args: Mapping[str, Any]
    optional: tuple[str, ...] = ()
    narrowed: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Plan:
    strategy: str                       # 'G1' | 'G2'
    steps: tuple[Step, ...]
    sources: tuple[str, ...] = field(default=())   # where old values came from


class NoPlan(Exception):
    """No inverse could be planned; the message says why in plain words."""


class NothingBefore(NoPlan):
    """G1 found none of the values the call set in the reads at copy time: the call made something new."""


def plan(entry: Entry, before: View, after: View, models: Models, names: Names) -> Plan:
    """The inverse of one successful changing call. Raises NoPlan with every strategy's reason."""
    if _writes_data(models, entry.service, entry.operation):
        raise NoPlan(f'{entry.call} writes data: no read shows data itself, so whether it came back cannot be seen')
    why = []
    nothing_before = False
    try:
        return g1(entry, before, after, models)
    except NothingBefore as e:
        nothing_before = True
        why.append(f'G1: {e}')
    except NoPlan as e:
        why.append(f'G1: {e}')
    try:
        return g2(entry, before, models, names, nothing_before)
    except NoPlan as e:
        why.append(f'G2: {e}')
    raise NoPlan('; '.join(why))


# ---------------------------------------------------------------------- G1: the same operation, old values
def g1(entry: Entry, before: View, after: View, models: Models) -> Plan:
    verb, _ = verb_noun(entry.operation)
    if verb not in UPDATE_VERBS:
        raise NoPlan(f'{verb} is not an update verb')
    shape = models.input(entry.service, entry.operation)
    params = dict(entry.params)
    ident = models.identifying(entry.service, entry.operation, params)
    pairs = _pairs(params)
    args: dict[str, Any] = {k: v for k, v in ident.items() if k not in pairs.values()}
    found, sources, gaps = 0, [], []
    for k, sent in params.items():
        member = shape.members.get(k) if shape else None
        if k in args or member is None or member.metadata.get('idempotencyToken'):
            continue
        if k in pairs.values() or (k not in pairs and _option(models, entry, k, member)):
            args[k] = sent
            continue
        old, where, gap = (_pair_value(before, after, params[pairs[k]], sent) if k in pairs
                           else _setting_value(models, entry, before, after, k, member, sent))
        if old is MISSING:
            gaps.append(gap or f'no old value under the same name for {k}')
            continue
        if gap:
            gaps.append(gap)
        args[k], found, sources = old, found + 1, sources + where
    if not found:
        raise NothingBefore('none of the values it sets was in the reads at copy time')
    if gaps:
        raise NoPlan('; '.join(gaps))
    return Plan('G1', (Step(entry.service, entry.operation, args, narrowed=_narrowed(shape, args, params)),),
                tuple(sources))


def _pairs(params: dict[str, Any]) -> dict[str, str]:
    """AttributeValue -> AttributeName: a member pair that sets one key of a map."""
    return {k: k[:-5] + 'Name' for k in params if k.endswith('Value') and len(k) > 5 and k[:-5] + 'Name' in params}


Found = tuple[Any, list[str], str]
"""(old value or MISSING, where it was found, why it cannot be used or '')."""


def _pair_value(before: View, after: View, key: Any, sent: Any) -> Found:
    old = _find_key(before, key) if isinstance(key, str) else MISSING
    if old is MISSING:
        return MISSING, [], ''
    if not shows(_find_key(after, key), sent):
        return old, [], f'the reads do not show the value the call set for {key}, so whether it came back cannot be seen'
    return old, [f'map key {key}'], ''


def _setting_value(models: Models, entry: Entry, before: View, after: View, k: str, member: Shape,
                   sent: Any) -> Found:
    """The old value of one setting the call changed, and whether the reads would show it coming back."""
    if not _named_in_state(models, entry, k, sent):
        return MISSING, [], f'{k} is a setting no read of {entry.service} shows: whether it came back cannot be seen'
    old, where = value_for(before, k, member, sent, entry.operation)
    if old is MISSING:
        return MISSING, [], ''
    now, _ = value_for(after, k, member, sent, entry.operation)
    if not shows(now, sent):
        return old, [], f'the reads do not show the value the call set for {k}, so whether it came back cannot be seen'
    return old, where, ''


def _option(models: Models, entry: Entry, name: str, member: Shape) -> bool:
    """A request option (Overwrite, DryRun): a flag no read ever returns. Kept as the call sent it."""
    return member.type_name == 'boolean' and not _named_in_state(models, entry, name, None)


def _named_in_state(models: Models, entry: Entry, name: str, value: Any) -> bool:
    """Some read of the service returns a field of this name (or noun-qualified: PolicyDocument as
    AssumeRolePolicyDocument), or, for a structure, one of the fields the call set inside it."""
    state = models.state_names(entry.service)
    if any(n in state for n in qualified(name, entry.operation)):
        return True
    return isinstance(value, dict) and any(k in state for k in value)


def _narrowed(shape: Shape | None, args: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
    """The args with each top-level map cut to the keys the call set (a map read back whole carries read-only keys)."""
    if shape is None:
        return None
    out = dict(args)
    for k, v in args.items():
        if shape.members[k].type_name == 'map' and isinstance(v, dict) and isinstance(params.get(k), dict):
            out[k] = {kk: vv for kk, vv in v.items() if kk in params[k]}
    return out if out != args else None


# ---------------------------------------------------------------------- G2: the inverse by name
def g2(entry: Entry, before: View, models: Models, names: Names, nothing_before: bool) -> Plan:
    verb, noun = verb_noun(entry.operation)
    if verb not in INVERSE:
        raise NoPlan(f'no inverse verb for {verb}')
    if verb == 'Put' and not nothing_before:
        raise NoPlan('Put changed something that existed; its inverse is not a delete')
    inverse = next((iv + noun for iv in INVERSE[verb] if models.has(entry.service, iv + noun)), None)
    if inverse is None:
        raise NoPlan(f'no operation {"/".join(iv + noun for iv in INVERSE[verb])} in the {entry.service} model')
    if _writes_data(models, entry.service, inverse):
        raise NoPlan(f'its inverse {inverse} would write data, which no read shows')
    src = sources(models, entry)
    retag: dict[str, Any] = {}
    if verb == 'Tag':
        src['TagKeys'], retag = _tag_keys(entry, before)
    args, optional = _inverse_args(entry, inverse, src, before, models, names, verb in RESTORE_FROM_SNAPSHOT)
    steps = []
    if not (verb == 'Tag' and not args.get('TagKeys')):
        steps.append(Step(entry.service, inverse, args, tuple(optional)))
    if retag:
        again = {k: v for k, v in models.identifying(entry.service, entry.operation, dict(entry.params)).items()}
        steps.append(Step(entry.service, entry.operation, dict(again, Tags=_tags_like(entry.params.get('Tags'), retag))))
    return Plan('G2', tuple(steps))


def sources(models: Models, entry: Entry) -> dict[str, Any]:
    """Values an inverse call can take from the original call: its parameters, plus the name in an ARN or URL."""
    params = dict(entry.params)
    src = {k: v for k, v in params.items() if isinstance(v, (str, dict, list, int, bool))}
    for k, v in params.items():
        if isinstance(v, str) and re.search(r'(Arn|ARN|Url)$', k) and re.search(r'[/:]', v):
            last = re.split(r'[/:]', v.rstrip('/'))[-1]
            src.setdefault(NOUN_SUFFIX.sub('', k) + 'Name', last)
            src.setdefault('Name', last)
    return src


def _inverse_args(entry: Entry, inverse: str, src: dict[str, Any], before: View, models: Models, names: Names,
                  from_snapshot: bool) -> tuple[dict[str, Any], list[str]]:
    shape = models.input(entry.service, inverse)
    args: dict[str, Any] = {}
    optional, missing = [], []
    for name, member in (shape.members.items() if shape else ()):
        if member.metadata.get('idempotencyToken'):
            args[name] = str(uuid.uuid4())     # a fresh token: an old one would make the service skip the call
            continue
        value = coerce(member, src[name]) if name in src else MISSING
        if value is MISSING and from_snapshot:
            value, _ = value_for(before, name, member, None, inverse)
        if value is MISSING:
            continue
        args[name] = value
        if name not in shape.required_members:
            optional.append(name)
    _fill_born(entry, inverse, shape, args, names)
    missing = [m for m in (shape.required_members if shape else ()) if m not in args]
    if missing:
        raise NoPlan(f'{inverse}: no value for {", ".join(missing)}')
    return args, [o for o in optional if o in args]


def _fill_born(entry: Entry, inverse: str, shape: Shape | None, args: dict[str, Any], names: Names) -> None:
    """Members that name a resource the call created with an id the service gave out: filled with that id, when the
    catalog confirms the inverse then acts on exactly that resource."""
    if shape is None:
        return
    for ref in entry.born:
        for name, member in shape.members.items():
            if name in args or not IDENT.search(name) or member.type_name not in ('string', 'list'):
                continue
            value: Any = ref.id if member.type_name == 'string' else [ref.id]
            if ref in names(entry.service, inverse, dict(args, **{name: value})):
                args[name] = value
                break


def _tag_keys(entry: Entry, before: View) -> tuple[list[str], dict[str, Any]]:
    """The keys to take off are the keys the call put on that did not exist; keys that existed get their old value."""
    tags = entry.params.get('Tags')
    keys = list(tags) if isinstance(tags, dict) else [t.get('Key') for t in tags or [] if isinstance(t, dict)]
    old_found, _ = find_before(before, 'Tags', entry.operation)
    old = _as_map(old_found)
    sent = _as_map(tags)
    return [k for k in keys if k not in old], {k: old[k] for k in keys if k in old and sent.get(k) != old[k]}


def _as_map(tags: Any) -> dict[str, Any]:
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        return {t['Key']: t.get('Value') for t in tags if isinstance(t, dict) and 'Key' in t}
    return {}


def _tags_like(sent: Any, tags: dict[str, Any]) -> Any:
    """Tags in the form the call used (a map, or a list of Key/Value)."""
    return tags if isinstance(sent, dict) else [{'Key': k, 'Value': v} for k, v in tags.items()]


def _writes_data(models: Models, service: str, operation: str) -> bool:
    """The call's request payload is raw bytes: the customer's data."""
    shape = models.input(service, operation)
    payload = shape.serialization.get('payload') if shape is not None else None
    return bool(payload and shape.members[payload].type_name == 'blob')


# ---------------------------------------------------------------------- finding a value in the reads
def qualified(name: str, operation: str) -> list[str]:
    """A member's name, and the same name qualified by the operation's noun (PolicyDocument in
    UpdateAssumeRolePolicy -> AssumeRolePolicyDocument)."""
    w = words(verb_noun(operation)[1])
    return [name] + [''.join(w[:i]) + name for i in range(1, len(w) + 1) if not name.startswith(''.join(w[:i]))]


def find_before(view: View, name: str, operation: str) -> tuple[Any, str]:
    """(first value of a field called `name`, where). The read paired with the operation by name comes first, then
    reads of the resource itself, then list reads (only their items that mention the resource)."""
    paired = _paired(view, operation)
    order = sorted(view.reads, key=lambda r: (r.operation != paired, r.listed, r.operation))
    for n in qualified(name, operation):
        for read in order:
            ok, value = deep_find(read.body, n, view.ids, read.listed)
            if ok:
                return value, f'{read.operation}.{n}'
    return MISSING, ''


def value_for(view: View, name: str, member: Shape, sent: Any, operation: str) -> tuple[Any, list[str]]:
    """The value of one input member in `view`: found whole under its name, or built from its sub-members."""
    found, where = find_before(view, name, operation)
    if found is not MISSING:
        value = coerce(member, found)
        if value is not MISSING:
            return value, [where]
    if member.type_name == 'structure' and isinstance(sent, dict):
        out, wh = {}, []
        for k, sub in sent.items():
            if k not in member.members:
                continue
            x, w = value_for(view, k, member.members[k], sub, operation)
            if x is MISSING:
                return MISSING, []
            out[k], wh = x, wh + w
        return (out, wh) if out else (MISSING, [])
    if member.type_name == 'structure' and sent is None:
        out, wh = {}, []
        for k, sub in member.members.items():
            if sub.type_name in ('structure', 'list', 'map'):
                continue
            x, w = find_before(view, k, operation)
            if coerce(sub, x) is not MISSING:
                out[k], wh = coerce(sub, x), wh + [w]
        if out:
            return out, wh
    return MISSING, []


def _paired(view: View, operation: str) -> str | None:
    """The read that pairs with a write by name: PutRetentionPolicy -> GetRetentionPolicy, DescribeRetention..."""
    noun = re.sub(r'^(Update|Put|Modify|Set|Delete|Remove|Create|Enable|Disable|Change|Replace)', '', operation)
    have = {r.operation for r in view.reads}
    for n in (noun, re.sub(r'(Configuration|Config|Policy|Attributes|Code)$', '', noun)):
        for verb in ('Get', 'Describe'):
            for suffix in ('', 'Configuration', 'Config', 's'):
                if f'{verb}{n}{suffix}' in have:
                    return f'{verb}{n}{suffix}'
    return None


def _find_key(view: View, key: str) -> Any:
    for read in view.reads:
        ok, value = deep_find(read.body, key, view.ids, read.listed)
        if ok:
            return value
    return MISSING


def deep_find(o: Any, name: str, ids: tuple[str, ...], need_match: bool) -> tuple[bool, Any]:
    """First value of a field called `name`. Inside a list answer, only items that mention the resource count."""
    if isinstance(o, dict):
        if name in o:
            return True, o[name]
        for v in o.values():
            ok, r = deep_find(v, name, ids, need_match)
            if ok:
                return ok, r
    elif isinstance(o, list):
        for v in o:
            if need_match and (not isinstance(v, (dict, list)) or not mentions(v, ids)):
                continue
            ok, r = deep_find(v, name, ids, need_match and not isinstance(v, dict))
            if ok:
                return ok, r
    return False, None


def mentions(o: Any, ids: tuple[str, ...]) -> bool:
    if isinstance(o, str):
        return any(o == i or o.endswith(':' + i) or o.endswith('/' + i) for i in ids)
    if isinstance(o, dict):
        return any(mentions(v, ids) for v in o.values())
    if isinstance(o, list):
        return any(mentions(v, ids) for v in o)
    return False


# ---------------------------------------------------------------------- does a read show what the call sent
def shows(seen: Any, sent: Any) -> bool:
    """The value read back holds the value the call sent (maps and lists may hold more: a merge, other items)."""
    return seen is not MISSING and _contains(_canon(seen), _canon(sent))


def _contains(seen: Any, sent: Any) -> bool:
    if isinstance(sent, dict):
        return isinstance(seen, dict) and all(k in seen and _contains(seen[k], v) for k, v in sent.items())
    if isinstance(sent, list):
        return isinstance(seen, list) and all(any(_contains(x, y) for x in seen) for y in sent)
    return seen == sent


def _canon(o: Any) -> Any:
    """Values as text, documents parsed, so that '120' and 120, or two spellings of one policy, compare equal."""
    if isinstance(o, dict):
        return {k: _canon(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_canon(v) for v in o]
    if isinstance(o, bool):
        return str(o).lower()
    if isinstance(o, float) and o.is_integer():
        return str(int(o))
    if isinstance(o, bytes):
        return o.decode(errors='replace')
    if isinstance(o, str) and o[:1] in '{[':
        try:
            return _canon(json.loads(o))
        except ValueError:
            return o
    return o if isinstance(o, str) else str(o) if o is not None else None
