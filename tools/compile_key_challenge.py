"""Compile an absent-only public-key possession challenge."""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

from key_ceremony import build_challenge, normalize_public_key_file, write_content_addressed
from verify_exchange import derive_key_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--role", action="append", required=True)
    parser.add_argument("--issued-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    public_key, _ = normalize_public_key_file(args.public_key.resolve(strict=True))
    policy = json.loads((root / "policy" / "software-release.json").read_text(encoding="utf-8"))
    snapshot = derive_key_snapshot(root, int(policy["max_compact_bytes"]))
    nonce = secrets.token_bytes(32)
    challenge = build_challenge(
        policy_revision=snapshot["revision"],
        event_sha256=snapshot["event_sha256"],
        principal_id=args.principal_id,
        roles=args.role,
        public_key=public_key,
        issued_at=args.issued_at,
        expires_at=args.expires_at,
        nonce=nonce,
    )
    output = write_content_addressed(args.output_dir, challenge)
    print(json.dumps({"authority": "proof_of_possession_challenge_only", "output": str(output), "key_id": challenge["key_id"], "policy_revision": challenge["policy_revision"]}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
