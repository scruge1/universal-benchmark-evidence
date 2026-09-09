"""Compile an absent-only public-key snapshot from append-only key events."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_exchange import derive_key_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        raise ValueError("output must be absent")
    policy = json.loads((root / "policy" / "software-release.json").read_text(encoding="utf-8"))
    snapshot = derive_key_snapshot(root, int(policy["max_compact_bytes"]))
    output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(output), "revision": snapshot["revision"], "key_count": len(snapshot["keys"]), "authority": "derived_snapshot_candidate_only"}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
