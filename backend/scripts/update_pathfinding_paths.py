#!/usr/bin/env python3
"""Vendor AWS privilege-escalation paths from pathfinding.cloud."""
from __future__ import annotations
import json, subprocess, tempfile
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "app" / "data"
SOURCE = "https://github.com/DataDog/pathfinding.cloud"

def main() -> None:
    commit = subprocess.check_output(["gh", "api", "repos/DataDog/pathfinding.cloud/commits/main", "--jq", ".sha"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="pathfinding-") as tmp:
        repo = Path(tmp) / "repo"
        subprocess.run(["git", "clone", "--depth", "1", "https://github.com/DataDog/pathfinding.cloud", str(repo)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "fetch", "--depth", "1", "origin", commit], cwd=repo, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", "--detach", commit], cwd=repo, check=True, stdout=subprocess.DEVNULL)
        paths = []
        for file in sorted((repo / "data" / "paths" / "aws").rglob("*.yaml")):
            item = yaml.safe_load(file.read_text()) or {}
            required = []
            for permission in (item.get("permissions") or {}).get("required") or []:
                value = permission.get("permission") if isinstance(permission, dict) else permission
                if isinstance(value, str) and value:
                    required.append(value)
            paths.append({"id": item["id"], "name": item.get("name", ""), "category": item.get("category", ""), "required": required})
        paths.sort(key=lambda item: item["id"])
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "pathfinding_paths.json").write_text(json.dumps({"source": SOURCE, "commit": commit, "license": "Apache-2.0", "schema_version": 1, "paths": paths}, indent=2) + "\n")
        third_party = DATA / "third_party" / "pathfinding.cloud"
        third_party.mkdir(parents=True, exist_ok=True)
        for name in ("LICENSE", "NOTICE"):
            (third_party / name).write_text((repo / name).read_text())
        print(f"{commit} paths={len(paths)} single_permission={sum(len(p['required']) == 1 for p in paths)}")

if __name__ == "__main__":
    main()
