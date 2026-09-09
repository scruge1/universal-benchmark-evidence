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

from key_ceremony import (  # noqa: E402
    EVENT_SCHEMA,
    KeyCeremonyError,
    SSHSIG_NAMESPACE,
    build_challenge,
    load_canonical_challenge,
    normalize_public_key_file,
    validate_enrollment_event,
    verify_sshsig,
    write_content_addressed,
)
from universal_benchmark_registry import canonical_json_bytes  # noqa: E402
from verify_exchange import derive_key_snapshot, verify_exchange  # noqa: E402


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


class KeyCeremonyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="key-ceremony-test-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "repo"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def challenge(self) -> dict[str, object]:
        return build_challenge(
            policy_revision=1,
            event_sha256=[],
            principal_id="test-owner-01",
            roles=["issuer"],
            public_key=self.public_key,
            issued_at="2026-09-09T12:00:00Z",
            expires_at="2026-09-10T12:00:00Z",
            nonce=hashlib.sha256(b"test nonce").digest(),
        )

    def event(self, challenge: dict[str, object], signature: str, *, event_at: str = "2026-09-09T12:01:00Z") -> dict[str, object]:
        return {
            "schema": EVENT_SCHEMA,
            "event_type": "enroll",
            "effective_revision": 2,
            "event_at": event_at,
            "key_id": challenge["key_id"],
            "principal_id": challenge["principal_id"],
            "roles": challenge["roles"],
            "public_key": challenge["public_key"],
            "possession_proof": {"challenge": challenge, "sshsig": signature},
            "reason": "synthetic ceremony test",
            "authority": "maintainer_reviewed_key_lifecycle_event_only",
        }

    def test_openssh_public_key_is_normalized_without_comment(self) -> None:
        path = self.base / "owner.pub"
        encoded = self.private_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        path.write_bytes(encoded + b" untrusted-email@example.invalid\n")
        raw, normalized = normalize_public_key_file(path)
        self.assertEqual(self.public_key, raw)
        self.assertNotIn("@", normalized)
        self.assertEqual(2, len(normalized.split()))

    def test_private_or_non_ed25519_input_fails(self) -> None:
        private = self.base / "private"
        private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key\n", encoding="ascii")
        with self.assertRaisesRegex(KeyCeremonyError, "public key"):
            normalize_public_key_file(private)
        wrong = self.base / "wrong.pub"
        wrong.write_text("ssh-rsa AAAA", encoding="ascii")
        with self.assertRaisesRegex(KeyCeremonyError, "ssh-ed25519"):
            normalize_public_key_file(wrong)

    def test_personal_or_overlapping_role_input_fails(self) -> None:
        with self.assertRaisesRegex(KeyCeremonyError, "pseudonym"):
            build_challenge(policy_revision=1, event_sha256=[], principal_id="person@example.invalid", roles=["issuer"], public_key=self.public_key, issued_at="2026-09-09T12:00:00Z", expires_at="2026-09-10T12:00:00Z", nonce=b"n" * 32)
        with self.assertRaisesRegex(KeyCeremonyError, "one key"):
            build_challenge(policy_revision=1, event_sha256=[], principal_id="test-owner-01", roles=["contributor", "validator"], public_key=self.public_key, issued_at="2026-09-09T12:00:00Z", expires_at="2026-09-10T12:00:00Z", nonce=b"n" * 32)

    def test_valid_proof_compiles_and_replays(self) -> None:
        challenge = self.challenge()
        signature = sshsig(self.private_key, canonical_json_bytes(challenge))
        event = self.event(challenge, signature)
        validate_enrollment_event(event, [])
        candidate_dir = self.base / "candidate"
        candidate_dir.mkdir()
        event_path = write_content_addressed(candidate_dir, event)
        shutil.copyfile(event_path, self.root / "policy" / "key-events" / event_path.name)
        snapshot = derive_key_snapshot(self.root, 1_048_576)
        (self.root / "policy" / "public-keys.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        report = verify_exchange(self.root)
        self.assertEqual(1, report["public_key_count"])

    def test_wrong_namespace_key_or_message_fails(self) -> None:
        challenge = self.challenge()
        message = canonical_json_bytes(challenge)
        with self.assertRaisesRegex(KeyCeremonyError, "namespace"):
            validate_enrollment_event(self.event(challenge, sshsig(self.private_key, message, namespace="file")), [])
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(KeyCeremonyError, "differs"):
            validate_enrollment_event(self.event(challenge, sshsig(other, message)), [])
        changed = dict(challenge)
        changed["nonce"] = base64.b64encode(b"x" * 32).decode("ascii")
        with self.assertRaisesRegex(KeyCeremonyError, "invalid"):
            validate_enrollment_event(self.event(changed, sshsig(self.private_key, message)), [])

    def test_expired_or_stale_challenge_fails(self) -> None:
        challenge = self.challenge()
        signature = sshsig(self.private_key, canonical_json_bytes(challenge))
        with self.assertRaisesRegex(KeyCeremonyError, "outside"):
            validate_enrollment_event(self.event(challenge, signature, event_at="2026-09-10T12:00:00Z"), [])
        with self.assertRaisesRegex(KeyCeremonyError, "stale"):
            validate_enrollment_event(self.event(challenge, signature), ["0" * 64])

    def test_challenge_must_be_canonical_and_content_addressed(self) -> None:
        challenge = self.challenge()
        output = self.base / "challenge"
        output.mkdir()
        path = write_content_addressed(output, challenge)
        self.assertEqual(challenge, dict(load_canonical_challenge(path)))
        path.write_text(json.dumps(challenge, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(KeyCeremonyError, "canonical content-addressed"):
            load_canonical_challenge(path)

    def test_content_addressed_output_is_absent_only(self) -> None:
        output = self.base / "candidate"
        output.mkdir()
        challenge = self.challenge()
        write_content_addressed(output, challenge)
        with self.assertRaisesRegex(KeyCeremonyError, "already exists"):
            write_content_addressed(output, challenge)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is not installed")
    def test_real_openssh_sshsig_interoperability(self) -> None:
        key_path = self.base / "interop-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True, capture_output=True)
        public_key, _ = normalize_public_key_file(key_path.with_suffix(".pub"))
        challenge = build_challenge(policy_revision=1, event_sha256=[], principal_id="interop-owner", roles=["issuer"], public_key=public_key, issued_at="2026-09-09T12:00:00Z", expires_at="2026-09-10T12:00:00Z", nonce=b"i" * 32)
        challenge_path = self.base / "interop-challenge.json"
        challenge_path.write_bytes(canonical_json_bytes(challenge))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", SSHSIG_NAMESPACE, "-O", "hashalg=sha256", str(challenge_path)], check=True, capture_output=True)
        signature = challenge_path.with_suffix(".json.sig").read_text(encoding="ascii")
        normalized = verify_sshsig(canonical_json_bytes(challenge), signature, public_key)
        self.assertTrue(normalized.startswith("-----BEGIN SSH SIGNATURE-----"))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is not installed")
    def test_generated_sshsig_is_accepted_by_openssh(self) -> None:
        challenge = self.challenge()
        message = canonical_json_bytes(challenge)
        signature_path = self.base / "generated.sig"
        signature_path.write_text(sshsig(self.private_key, message), encoding="ascii")
        public_line = self.private_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        allowed_signers = self.base / "allowed_signers"
        allowed_signers.write_bytes(b"test-owner " + public_line + b"\n")
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", "test-owner", "-n", SSHSIG_NAMESPACE, "-s", str(signature_path)],
            input=message,
            capture_output=True,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", errors="replace"))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH ssh-keygen is not installed")
    def test_public_key_only_cli_path(self) -> None:
        key_path = self.base / "cli-key"
        challenge_dir = self.base / "challenge-candidate"
        event_dir = self.base / "event-candidate"
        challenge_dir.mkdir()
        event_dir.mkdir()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True, capture_output=True)
        challenge_result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "compile_key_challenge.py"),
                "--root",
                str(self.root),
                "--public-key",
                str(key_path.with_suffix(".pub")),
                "--principal-id",
                "cli-owner-01",
                "--role",
                "issuer",
                "--issued-at",
                "2026-09-09T12:00:00Z",
                "--expires-at",
                "2026-09-10T12:00:00Z",
                "--output-dir",
                str(challenge_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, challenge_result.returncode, challenge_result.stderr)
        challenge_path = next(challenge_dir.glob("*.json"))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", SSHSIG_NAMESPACE, "-O", "hashalg=sha256", str(challenge_path)], check=True, capture_output=True)
        event_result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "compile_key_event.py"),
                "--root",
                str(self.root),
                "--challenge",
                str(challenge_path),
                "--signature",
                str(Path(str(challenge_path) + ".sig")),
                "--event-at",
                "2026-09-09T12:01:00Z",
                "--reason",
                "synthetic CLI ceremony",
                "--output-dir",
                str(event_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, event_result.returncode, event_result.stderr)
        event_path = next(event_dir.glob("*.json"))
        event = json.loads(event_path.read_text(encoding="utf-8"))
        self.assertEqual(EVENT_SCHEMA, event["schema"])
        self.assertEqual("cli-owner-01", event["principal_id"])


if __name__ == "__main__":
    unittest.main()
