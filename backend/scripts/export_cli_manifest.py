"""Write the CLI manifest into the npm package source, so the bundled copy can be committed.

Run from backend/:  python scripts/export_cli_manifest.py
A law test (L88) fails when the committed copy differs from what the server returns.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.cli_manifest import build_manifest  # noqa: E402

TARGET = Path(__file__).resolve().parents[2] / "mcp" / "src" / "cli" / "bundled-manifest.json"


def main() -> None:
    TARGET.write_text(json.dumps(build_manifest(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {TARGET}")


if __name__ == "__main__":
    main()
