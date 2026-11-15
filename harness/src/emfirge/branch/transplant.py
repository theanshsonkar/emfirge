"""Structural difference and lay-over on plain nested data (dicts, lists, scalars). Pure.

Why: at copy time the branch keeps the engine's answer E0 and, later, gets E1. The branch's own change is E0 -> E1.
Laying that change over the real account's live answer R gives an answer in which every value the branch did not
change comes live from the real account, even where the copy lost or altered it.
Lists are whole values: an item list changed on the branch replaces the real one as a whole.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

Path = tuple[Any, ...]


@dataclass(frozen=True)
class Op:
    """One step of a difference: set `path` to `value`, or remove `path`."""
    path: Path
    value: Any = None
    remove: bool = False


def diff(a: Any, b: Any, path: Path = ()) -> list[Op]:
    """What turns a into b."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = [Op(path + (k,), remove=True) for k in a if k not in b]
        for k in b:
            out += [Op(path + (k,), b[k])] if k not in a else diff(a[k], b[k], path + (k,))
        return out
    return [] if a == b else [Op(path, b)]


def apply(ops: list[Op], base: Any, source: Any) -> Any:
    """`base` with `ops` laid over it. Where `base` has no room for a change (a value where the change needs a
    mapping), the whole subtree is taken from `source`, the answer the change came from."""
    out = copy.deepcopy(base)
    for op in ops:
        if not op.path:
            out = out if op.remove else copy.deepcopy(op.value)
            continue
        out = _apply_one(op, out, source)
    return out


def _apply_one(op: Op, out: Any, source: Any) -> Any:
    cur, src = out, source
    for k in op.path[:-1]:
        src = src.get(k) if isinstance(src, dict) else None
        nxt = cur.get(k) if isinstance(cur, dict) else None
        if not isinstance(nxt, dict):
            if op.remove or not isinstance(cur, dict):
                return out
            if nxt is not None:
                cur[k] = copy.deepcopy(src)
                return out
            cur[k] = nxt = {}
        cur = nxt
    if op.remove:
        cur.pop(op.path[-1], None)
    else:
        cur[op.path[-1]] = copy.deepcopy(op.value)
    return out


def lay(e0: Any, e1: Any, real: Any) -> Any:
    """The real answer with the engine's change e0 -> e1 laid over it. A list the change touches is laid item by
    item where its items can be paired with the real ones (see lay_items); otherwise it is replaced whole."""
    ops = []
    for op in diff(e0, e1):
        before, now = _get(e0, op.path), _get(real, op.path)
        if not op.remove and any(isinstance(v, list) for v in (op.value, before, now)):
            # a list of one may arrive as its single item (an XML answer cannot tell them apart)
            items = lay_items(*(v if isinstance(v, list) else [v] for v in (before, op.value, now)))
            if items is not None:
                op = Op(op.path, items)
        ops.append(op)
    return apply(ops, real, e1)


def lay_items(e0: Any, e1: Any, real: Any) -> list | None:
    """A list changed on the branch, laid over the real list item by item. Items the branch did not change are the
    real ones (with whatever the copy lacked); an item it changed is its real twin with the change laid over; an
    item it added is the engine's; an item it removed is gone. Items are paired by the fields they share (scalars:
    by value). None when the pairing is not clear, so the caller does not guess. A side that is missing is an empty
    list; a single item stands for a list of one."""
    e0, e1, real = (v if isinstance(v, list) else [] if v is None else [v] for v in (e0, e1, real))
    if not all(isinstance(i, dict) for i in e0 + e1 + real):
        if any(isinstance(i, (dict, list)) for i in e0 + e1 + real):
            return None
        gone = [i for i in e0 if i not in e1]
        return [i for i in real if i not in gone] + [i for i in e1 if i not in e0 and i not in real]
    twin = _pairs(e0, real)
    if twin is None:
        return None
    out, used = [], set()
    for item in e1:
        if item in e0:
            j = twin[e0.index(item)]
            out.append(real[j])
            used.add(j)
            continue
        k = _best(item, e0)
        if k is not None and twin[k] not in used:
            out.append(lay(e0[k], item, real[twin[k]]))
            used.add(twin[k])
        else:
            out.append(item)
    return out


def _pairs(a: list[dict], b: list[dict]) -> dict[int, int] | None:
    """Each item of `a` with the one item of `b` it shares the most fields with (more than half); None unless that
    is one to one."""
    out: dict[int, int] = {}
    for i, item in enumerate(a):
        j = _best(item, b)
        if j is None or j in out.values():
            return None
        out[i] = j
    return out


def _best(item: dict, among: list[dict]) -> int | None:
    def score(other: dict) -> int:
        return sum(1 for k in item.keys() & other.keys() if item[k] == other[k])
    scores = [score(o) for o in among]
    if not scores:
        return None
    top = max(scores)
    if top * 2 <= len(item) or scores.count(top) > 1:
        return None
    return scores.index(top)


def carried_loss(e0: Any, e1: Any, r0: Any, noise: frozenset[str] = frozenset()) -> list[str]:
    """Lists where the copy already differed from the real account (E0 against R0, order aside), whose items cannot
    be paired with the real ones, and that the branch's change (E0 -> E1) touches. Such a list is laid over whole, so
    the engine's list, with what the copy lacks (an object's bytes, an item's field), would replace the real one:
    that lay-over cannot be trusted."""
    dotted = lambda path: '.'.join(map(str, path))
    lossy = [dotted(p) for p in _lossy_lists(e0, r0)
             if not any(dotted(p) == n or dotted(p).startswith(n + '.') for n in noise)
             and lay_items(_get(e0, p), _get(e0, p), _get(r0, p)) is None]
    touched = [dotted(op.path) for op in diff(e0, e1)]
    return [p for p in lossy for t in touched if t == p or p.startswith(t + '.') or t.startswith(p + '.') or not t]


def _lossy_lists(a: Any, b: Any, path: Path = ()) -> list[Path]:
    if isinstance(a, dict) and isinstance(b, dict):
        return [p for k in a.keys() & b.keys() for p in _lossy_lists(a[k], b[k], path + (k,))]
    if isinstance(a, list) and isinstance(b, list) and _bag(a) != _bag(b):
        return [path]
    return []


def _bag(items: list) -> list[str]:
    return sorted(json.dumps(i, sort_keys=True, default=str) for i in items)


def structured(*bodies: Any) -> bool:
    """True when every body is nested data of the same kind (all mappings, or all lists): only then can a change be
    laid over another answer."""
    kinds = {type(b) for b in bodies}
    return len(kinds) == 1 and kinds <= {dict, list}


def changed_paths(a: Any, b: Any) -> list[tuple[str, Any, Any]]:
    """(dotted path, before, after) for each place a and b differ."""
    out = []
    for op in diff(a, b):
        before = _get(a, op.path)
        out.append(('.'.join(map(str, op.path)), before, None if op.remove else op.value))
    return out


def leaves(body: Any, path: Path = ()) -> list[tuple[str, Any]]:
    """(dotted path, value) for each leaf of nested data; lists are whole values, as in diff."""
    if isinstance(body, dict) and body:
        return [leaf for k, v in body.items() for leaf in leaves(v, path + (k,))]
    return [('.'.join(map(str, path)), body)] if path else []


def without(paths: frozenset[str], changes: list[tuple[str, Any, Any]]) -> list[tuple[str, Any, Any]]:
    """Drop changes at (or under) any of `paths`."""
    return [c for c in changes if not any(c[0] == p or c[0].startswith(p + '.') for p in paths)]


def _get(d: Any, path: Path) -> Any:
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d
