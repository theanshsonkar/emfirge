import json
from pathlib import Path


def merge_patch(target, patch):
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict):
            result[key] = merge_patch(result.get(key), value)
        else:
            result[key] = value
    return result


def load_synthetic_base(name: str, patch: dict | None = None):
    path = Path(__file__).with_name(f"{name}_base.json")
    base = json.loads(path.read_text())
    if patch is not None:
        base = merge_patch(base, patch)
    raise NotImplementedError("Phase D: synthetic base loader not built yet")
