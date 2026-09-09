from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from verify_exchange import (  # noqa: E402
    ExchangeVerificationError,
    RAW_MANIFEST_SCHEMA,
    _changed_entries,
    _require_role,
    derive_key_snapshot,
    verify_contributor_paths,
    verify_exchange,
    verify_pull_request_changes,
)
from universal_benchmark_registry import canonical_json_bytes  # noqa: E402
from universal_model_router import canonical_sha256  # noqa: E402
from key_ceremony import (  # noqa: E402
    KeyCeremonyError,
    SSHSIG_NAMESPACE,
    build_challenge,
)


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def sshsig(private_key: Ed25519PrivateKey, message: bytes, *, namespace: str = SSHSIG_NAMESPACE) -> str:
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public_blob = ssh_string(b"ssh-ed25519") + ssh_string(public_key)
    namespace_bytes = namespace.encode("ascii")
    signed = b"SSHSIG" + ssh_string(namespace_bytes) + ssh_string(b"") + ssh_string(b"sha256") + ssh_string(hashlib.sha256(message).digest())
    signature_blob = ssh_string(b"ssh-ed25519") + ssh_string(private_key.sign(signed))
    blob = b"SSHSIG" + struct.pack(">I", 1) + ssh_string(public_blob) + ssh_string(namespace_bytes) + ssh_string(b"") + ssh_string(b"sha256") + ssh_string(signature_blob)
    encoded = base64.b64encode(blob).decode("ascii")
    body = "\n".join(encoded[index : index + 76] for index in range(0, len(encoded), 76))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n"


def raw_manifest(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": RAW_MANIFEST_SCHEMA,
        "generated_at": "2026-09-09T00:00:00Z",
        "submission_id": "synthetic-submission",
        "artifacts": [
            {
                "artifact_id": "raw-run",
                "locator": "https://example.invalid/artifacts/sha256/abc",
                "sha256": hashlib.sha256(b"raw").hexdigest(),
                "size_bytes": 3,
                "media_type": "application/json",
                "disclosure": "synthetic_public_test_only",
                "retention": "retained_for_test_contract_lifetime",
            }
        ],
        "authority": "external_raw_artifact_references_only",
    }
    value.update(changes)
    return value


class ExchangeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="exchange-guard-test-")
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _queue_path(self, area: str, document: dict[str, object], *, canonical: bool = True) -> Path:
        digest = canonical_sha256(document)
        path = self.root / "queue" / area / f"{digest}.json"
        value = canonical_json_bytes(document) if canonical else json.dumps(document, indent=2).encode("utf-8")
        path.write_bytes(value)
        return path

    def _key_event(self, event_type: str, revision: int, principal: str, roles: list[str], label: str) -> tuple[str, str]:
        private_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("private-" + label).encode()).digest())
        public_bytes = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = hashlib.sha256(public_bytes).hexdigest()
        encoded = base64.b64encode(public_bytes).decode("ascii")
        possession_proof = None
        if event_type == "enroll":
            snapshot = derive_key_snapshot(self.root, 1_048_576)
            challenge = build_challenge(
                policy_revision=snapshot["revision"],
                event_sha256=snapshot["event_sha256"],
                principal_id=principal,
                roles=roles,
                public_key=public_bytes,
                issued_at="2026-09-09T00:00:00Z",
                expires_at="2026-09-10T00:00:00Z",
                nonce=hashlib.sha256(("nonce-" + label).encode()).digest(),
            )
            possession_proof = {"challenge": challenge, "sshsig": sshsig(private_key, canonical_json_bytes(challenge))}
        document = {
            "schema": "universal-benchmark-key-event/v2",
            "event_type": event_type,
            "effective_revision": revision,
            "event_at": f"2026-09-09T00:00:{revision:02d}Z",
            "key_id": key_id,
            "principal_id": principal,
            "roles": roles if event_type == "enroll" else [],
            "public_key": encoded if event_type == "enroll" else None,
            "possession_proof": possession_proof,
            "reason": "synthetic contract test",
            "authority": "maintainer_reviewed_key_lifecycle_event_only",
        }
        digest = canonical_sha256(document)
        (self.root / "policy" / "key-events" / f"{digest}.json").write_bytes(canonical_json_bytes(document))
        return key_id, encoded

    def _refresh_key_snapshot(self) -> dict[str, object]:
        snapshot = derive_key_snapshot(self.root, 1_048_576)
        (self.root / "policy" / "public-keys.json").write_bytes(json.dumps(snapshot, indent=2).encode("utf-8"))
        return snapshot

    def test_empty_offline_candidate_passes_without_any_real_authority(self) -> None:
        report = verify_exchange(self.root)
        self.assertEqual(0, report["public_key_count"])
        self.assertEqual("offline_reviewed_queue_verification_only_no_blessing_or_publication", report["authority"])
        self.assertTrue(all(count == 0 for count in report["queue_counts"].values()))

    def test_contributor_changes_are_queue_only_json(self) -> None:
        path = "queue/results/" + "a" * 64 + ".json"
        verify_contributor_paths([path])
        self.assertEqual("queue_additions", verify_pull_request_changes([("A", path)]))
        for path in (
            "tools/verify_exchange.py",
            "queue/README.md",
            "queue/results/nested/" + "a" * 64 + ".json",
            "queue/results/not-a-digest.json",
            "../escape.json",
        ):
            with self.subTest(path=path), self.assertRaises(ExchangeVerificationError):
                verify_contributor_paths([path])

    def test_queue_pull_requests_are_add_only_and_cannot_mix_policy(self) -> None:
        queue_path = "queue/results/" + "a" * 64 + ".json"
        for status in ("M", "D", "T"):
            with self.subTest(status=status), self.assertRaises(ExchangeVerificationError):
                verify_pull_request_changes([(status, queue_path)])
        with self.assertRaises(ExchangeVerificationError):
            verify_pull_request_changes(
                [("A", queue_path), ("M", "policy/public-keys.json")]
            )

    def test_exact_key_lifecycle_pull_request_shape_passes(self) -> None:
        event_path = "policy/key-events/" + "a" * 64 + ".json"
        self.assertEqual(
            "key_lifecycle",
            verify_pull_request_changes(
                [("A", event_path), ("M", "policy/public-keys.json")]
            ),
        )

    def test_inexact_key_lifecycle_pull_request_shapes_fail(self) -> None:
        event_path = "policy/key-events/" + "a" * 64 + ".json"
        invalid_entries = (
            [],
            [("A", event_path)],
            [("A", event_path), ("A", "policy/public-keys.json")],
            [("M", event_path), ("M", "policy/public-keys.json")],
            [("D", event_path), ("M", "policy/public-keys.json")],
            [("A", "policy/key-events/not-a-digest.json"), ("M", "policy/public-keys.json")],
            [("A", "policy/key-events/nested/" + "a" * 64 + ".json"), ("M", "policy/public-keys.json")],
            [("A", event_path), ("M", "policy/exchange-policy.json")],
            [("A", event_path), ("M", "policy/public-keys.json"), ("M", "README.md")],
            [("R", event_path), ("M", "policy/public-keys.json")],
        )
        for entries in invalid_entries:
            with self.subTest(entries=entries), self.assertRaises(ExchangeVerificationError):
                verify_pull_request_changes(entries)

    def test_real_git_diff_reaches_full_key_lifecycle_verification(self) -> None:
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Synthetic Test"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "synthetic@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=self.root, check=True)
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        self._key_event("enroll", 2, "synthetic-issuer", ["issuer"], "git-diff")
        self._refresh_key_snapshot()
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "synthetic enrollment"], cwd=self.root, check=True)

        entries = _changed_entries(self.root, f"{base}..HEAD")
        self.assertEqual("key_lifecycle", verify_pull_request_changes(entries))
        report = verify_exchange(self.root)
        self.assertEqual(1, report["public_key_count"])

    def test_wrong_content_address_fails(self) -> None:
        document = raw_manifest()
        path = self.root / "queue" / "raw-manifests" / ("0" * 64 + ".json")
        path.write_bytes(canonical_json_bytes(document))
        with self.assertRaisesRegex(ExchangeVerificationError, "filename must equal"):
            verify_exchange(self.root)

    def test_noncanonical_queue_bytes_fail(self) -> None:
        self._queue_path("raw-manifests", raw_manifest(), canonical=False)
        with self.assertRaisesRegex(ExchangeVerificationError, "canonical JSON"):
            verify_exchange(self.root)

    def test_private_key_marker_fails_before_intake(self) -> None:
        document = raw_manifest(retention="-----BEGIN PRIVATE KEY-----")
        self._queue_path("raw-manifests", document)
        with self.assertRaisesRegex(ExchangeVerificationError, "private key or credential"):
            verify_exchange(self.root)

    def test_raw_artifact_requires_exact_fields(self) -> None:
        document = raw_manifest()
        del document["artifacts"][0]["retention"]  # type: ignore[index]
        self._queue_path("raw-manifests", document)
        with self.assertRaisesRegex(ExchangeVerificationError, "exact keys"):
            verify_exchange(self.root)

    def test_mutable_raw_locator_fails(self) -> None:
        document = raw_manifest()
        document["artifacts"][0]["locator"] = "https://example.invalid/latest/run.json"  # type: ignore[index]
        self._queue_path("raw-manifests", document)
        with self.assertRaisesRegex(ExchangeVerificationError, "immutable HTTPS or IPFS"):
            verify_exchange(self.root)

    def test_orphan_raw_manifest_fails(self) -> None:
        self._queue_path("raw-manifests", raw_manifest())
        with self.assertRaisesRegex(ExchangeVerificationError, "orphan raw manifests"):
            verify_exchange(self.root)

    def test_unenrolled_or_malformed_contribution_fails_closed(self) -> None:
        document = {
            "schema": "universal-benchmark-contribution/v1",
            "submission_id": "untrusted",
            "evidence": {"raw_manifest_sha256": "0" * 64},
        }
        self._queue_path("contributions", document)
        with self.assertRaisesRegex(ExchangeVerificationError, "active contributor key enrollment"):
            verify_exchange(self.root)

    def test_public_key_map_cannot_bind_wrong_identity(self) -> None:
        path = self.root / "policy" / "public-keys.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["keys"] = {"0" * 64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "snapshot differs"):
            verify_exchange(self.root)

    def test_distinct_role_enrollments_derive_exact_snapshot(self) -> None:
        self._key_event("enroll", 2, "issuer-person", ["issuer"], "issuer")
        self._key_event("enroll", 3, "contributor-person", ["contributor"], "contributor")
        self._key_event("enroll", 4, "validator-person", ["validator"], "validator")
        snapshot = self._refresh_key_snapshot()
        report = verify_exchange(self.root)
        self.assertEqual(3, report["public_key_count"])
        self.assertEqual(4, snapshot["revision"])

    def test_one_key_cannot_hold_contributor_and_validator_roles(self) -> None:
        with self.assertRaisesRegex(KeyCeremonyError, "one key"):
            self._key_event("enroll", 2, "one-person", ["contributor", "validator"], "one")

    def test_one_principal_cannot_split_contributor_and_validator_keys(self) -> None:
        self._key_event("enroll", 2, "one-person", ["contributor"], "first")
        self._key_event("enroll", 3, "one-person", ["validator"], "second")
        with self.assertRaisesRegex(ExchangeVerificationError, "one principal"):
            derive_key_snapshot(self.root, 1_048_576)

    def test_revocation_removes_active_key_without_removing_events(self) -> None:
        key_id, _ = self._key_event("enroll", 2, "retired-person", ["contributor"], "retired")
        document = {
            "schema": "universal-benchmark-key-event/v2",
            "event_type": "revoke",
            "effective_revision": 3,
            "event_at": "2026-09-09T00:00:03Z",
            "key_id": key_id,
            "principal_id": "retired-person",
            "roles": [],
            "public_key": None,
            "possession_proof": None,
            "reason": "synthetic retirement",
            "authority": "maintainer_reviewed_key_lifecycle_event_only",
        }
        digest = canonical_sha256(document)
        (self.root / "policy" / "key-events" / f"{digest}.json").write_bytes(canonical_json_bytes(document))
        snapshot = self._refresh_key_snapshot()
        self.assertIn(key_id, snapshot["keys"])
        self.assertEqual("revoked", snapshot["principals"][key_id]["status"])
        self.assertEqual(2, len(snapshot["event_sha256"]))
        verify_exchange(self.root)

    def test_revocation_preserves_historical_role_but_rejects_later_use(self) -> None:
        key_id, _ = self._key_event("enroll", 2, "retired-person", ["contributor"], "retired")
        self._key_event("revoke", 3, "retired-person", [], "retired")
        snapshot = self._refresh_key_snapshot()

        metadata = _require_role(
            key_id,
            "contributor",
            snapshot["principals"],
            "$historical_contribution.contributor",
            "2026-09-09T00:00:02.500000Z",
        )
        self.assertEqual("revoked", metadata["status"])

        with self.assertRaisesRegex(ExchangeVerificationError, "revoked at document time"):
            _require_role(
                key_id,
                "contributor",
                snapshot["principals"],
                "$later_contribution.contributor",
                "2026-09-09T00:00:03Z",
            )

    def test_key_event_revision_gap_fails(self) -> None:
        self._key_event("enroll", 3, "late-person", ["issuer"], "late")
        with self.assertRaisesRegex(ExchangeVerificationError, "contiguous"):
            derive_key_snapshot(self.root, 1_048_576)

    def test_unproved_v1_enrollment_fails(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        document = {
            "schema": "universal-benchmark-key-event/v1",
            "event_type": "enroll",
            "effective_revision": 2,
            "event_at": "2026-09-09T00:00:02Z",
            "key_id": hashlib.sha256(public_key).hexdigest(),
            "principal_id": "unproved-owner",
            "roles": ["issuer"],
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "reason": "synthetic bypass attempt",
            "authority": "maintainer_reviewed_key_lifecycle_event_only",
        }
        digest = canonical_sha256(document)
        (self.root / "policy" / "key-events" / f"{digest}.json").write_bytes(canonical_json_bytes(document))
        with self.assertRaisesRegex(ExchangeVerificationError, "exact keys"):
            derive_key_snapshot(self.root, 1_048_576)

    def test_router_version_drift_fails(self) -> None:
        path = self.root / "policy" / "software-release.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["router"]["version"] = "0.0.0"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "installed router version differs"):
            verify_exchange(self.root)

    def test_pull_request_target_fails(self) -> None:
        path = self.root / ".github" / "workflows" / "validate.yml"
        text = path.read_text(encoding="utf-8").replace("pull_request:", "pull_request_target:")
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "pull_request_target"):
            verify_exchange(self.root)

    def test_unpinned_action_fails(self) -> None:
        path = self.root / ".github" / "workflows" / "validate.yml"
        text = path.read_text(encoding="utf-8").replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "exact commit SHA"):
            verify_exchange(self.root)

    def test_submitted_branch_cannot_replace_pull_request_guard(self) -> None:
        path = self.root / ".github" / "workflows" / "validate.yml"
        text = path.read_text(encoding="utf-8").replace(
            "python trusted-base/tools/verify_exchange.py",
            "python submitted/tools/verify_exchange.py",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "trusted base guard"):
            verify_exchange(self.root)

    def test_write_permission_fails(self) -> None:
        path = self.root / ".github" / "workflows" / "validate.yml"
        text = path.read_text(encoding="utf-8").replace("contents: read", "contents: write")
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "read-only contents permission"):
            verify_exchange(self.root)


if __name__ == "__main__":
    unittest.main()
