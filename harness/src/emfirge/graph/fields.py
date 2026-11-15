"""Which fields of a resource's settings a change touched, in the same path notation as the index's evidence.

The graph uses this to tell a change that moves a reference (a new target in an environment variable) from one that
does not touch any reference (a memory size): only the first makes what the resource points at news.
"""
from __future__ import annotations

from typing import Any


def changed_paths(before: Any, after: Any, path: str = '') -> set[str]:
    """Paths whose value differs, at the deepest level where both sides still have the same shape."""
    if isinstance(before, dict) and isinstance(after, dict):
        out: set[str] = set()
        for key in before.keys() | after.keys():
            sub = f'{path}.{key}' if path else str(key)
            if key not in before or key not in after:
                out.add(sub)
            else:
                out |= changed_paths(before[key], after[key], sub)
        return out
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return {p for i, (a, b) in enumerate(zip(before, after)) for p in changed_paths(a, b, f'{path}[{i}]')}
    return set() if before == after else {path}


def under(path: str, changed: set[str]) -> bool:
    """True when path is one of the changed paths or inside one (a packed string, a nested field)."""
    return any(path == p or path.startswith((p + '.', p + '[', p + '<')) for p in changed)
