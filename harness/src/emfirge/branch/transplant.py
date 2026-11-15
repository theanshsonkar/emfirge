"""Structural difference and lay-over on plain nested data (dicts, lists, scalars). Pure.

Why: at copy time the branch keeps the engine's answer E0 and, later, gets E1. The branch's own change is E0 -> E1.
Laying that change over the real account's live answer R gives an answer in which every value the branch did not
change comes live from the real account, even where the copy lost or altered it.
Lists are whole values: an item list changed on the branch replaces the real one as a whole.
"""
from __future__ import annotations

import copy
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
    """The real answer with the engine's change e0 -> e1 laid over it."""
    return apply(diff(e0, e1), real, e1)


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


def without(paths: frozenset[str], changes: list[tuple[str, Any, Any]]) -> list[tuple[str, Any, Any]]:
    """Drop changes at (or under) any of `paths`."""
    return [c for c in changes if not any(c[0] == p or c[0].startswith(p + '.') for p in paths)]


def _get(d: Any, path: Path) -> Any:
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d
