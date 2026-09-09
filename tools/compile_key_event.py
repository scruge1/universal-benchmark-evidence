"""Verify SSHSIG possession proof and compile an absent-only enrollment event."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from key_ceremony import EVENT_SCHEMA, KeyCeremonyError, load_canonical_challenge, validate_enrollment_event, verify_sshsig, write_content_addressed
from universal_benchmark_registry import canonical_json_bytes
from verify_exchange import derive_key_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--event-at", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    if args.output_dir.resolve(strict=True) == (root / "policy" / "key-events").resolve(strict=True):
        raise KeyCeremonyError("compile into a separate candidate directory before review")
    challenge = load_canonical_challenge(args.challenge.resolve(strict=True))
    signature_path = args.signature.resolve(strict=True)
    if signature_path.is_symlink() or not signature_path.is_file() or signature_path.stat().st_size > 16_384:
        raise KeyCeremonyError("signature must be a compact regular non-link file")
    signature = signature_path.read_text(encoding="ascii")
    signature = verify_sshsig(
        canonical_json_bytes(challenge),
        signature,
        base64.b64decode(challenge["public_key"], validate=True),
    )
    policy = json.loads((root / "policy" / "software-release.json").read_text(encoding="utf-8"))
    snapshot = derive_key_snapshot(root, int(policy["max_compact_bytes"]))
    if snapshot["revision"] != challenge["policy_revision"] or snapshot["event_sha256"] != challenge["event_sha256"]:
        raise KeyCeremonyError("challenge is stale for the current public-key policy")
    if challenge["key_id"] in snapshot["keys"]:
        raise KeyCeremonyError("public key is already known")
    principal_roles = {role for item in snapshot["principals"].values() if item["principal_id"] == challenge["principal_id"] for role in item["roles"]}
    if "contributor" in principal_roles | set(challenge["roles"]) and "validator" in principal_roles | set(challenge["roles"]):
        raise KeyCeremonyError("one reviewed principal cannot be contributor and validator")
    event = {
        "schema": EVENT_SCHEMA,
        "event_type": "enroll",
        "effective_revision": snapshot["revision"] + 1,
        "event_at": args.event_at,
        "key_id": challenge["key_id"],
        "principal_id": challenge["principal_id"],
        "roles": challenge["roles"],
        "public_key": challenge["public_key"],
        "possession_proof": {"challenge": challenge, "sshsig": signature},
        "reason": args.reason,
        "authority": "maintainer_reviewed_key_lifecycle_event_only",
    }
    validate_enrollment_event(event, snapshot["event_sha256"])
    output = write_content_addressed(args.output_dir, event)
    print(json.dumps({"authority": "reviewed_enrollment_event_candidate_only", "output": str(output), "key_id": event["key_id"], "effective_revision": event["effective_revision"]}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
