"""Public-key-only helpers for reviewed Ed25519 enrollment ceremonies."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from universal_benchmark_registry import canonical_json_bytes, sha256_bytes, strict_json_bytes


CHALLENGE_SCHEMA = "universal-benchmark-key-possession-challenge/v1"
EVENT_SCHEMA = "universal-benchmark-key-event/v2"
REPOSITORY = "https://github.com/scruge1/universal-benchmark-evidence"
SSHSIG_NAMESPACE = "universal-benchmark-key-enrollment"
ROLES = {"issuer", "contributor", "validator"}
PRINCIPAL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)


class KeyCeremonyError(ValueError):
    """A key-ceremony input is unsafe, malformed, stale, or inconsistent."""


def _exact(value: Any, keys: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KeyCeremonyError(f"{path}: object is required")
    missing = sorted(keys - set(value))
    extra = sorted(set(value) - keys)
    if missing or extra:
        raise KeyCeremonyError(f"{path}: exact keys required; missing={missing!r} extra={extra!r}")
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise KeyCeremonyError(f"{path}: UTC timestamp ending in Z is required")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise KeyCeremonyError(f"{path}: invalid timestamp") from exc
    return result.astimezone(timezone.utc)


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _read_ssh_string(blob: bytes, offset: int, path: str) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise KeyCeremonyError(f"{path}: truncated SSH string length")
    length = struct.unpack(">I", blob[offset : offset + 4])[0]
    start = offset + 4
    end = start + length
    if end > len(blob):
        raise KeyCeremonyError(f"{path}: truncated SSH string")
    return blob[start:end], end


def normalize_public_key_file(path: Path) -> tuple[bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise KeyCeremonyError("public key must be a regular non-link file")
    value = path.read_bytes()
    if len(value) > 16_384 or any(marker in value for marker in PRIVATE_MARKERS):
        raise KeyCeremonyError("only a compact OpenSSH public key is accepted")
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) != 1:
        raise KeyCeremonyError("public key file must contain exactly one non-empty line")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != b"ssh-ed25519":
        raise KeyCeremonyError("only self-describing OpenSSH ssh-ed25519 public keys are accepted")
    normalized = b" ".join(fields[:2])
    try:
        key = serialization.load_ssh_public_key(normalized)
    except (ValueError, TypeError) as exc:
        raise KeyCeremonyError("invalid OpenSSH public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyCeremonyError("only Ed25519 public keys are accepted")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, normalized.decode("ascii")


def validate_roles(roles: list[str]) -> list[str]:
    if not isinstance(roles, list) or not roles or any(not isinstance(role, str) for role in roles) or len(roles) != len(set(roles)) or not set(roles) <= ROLES:
        raise KeyCeremonyError("roles must be a unique non-empty allowed set")
    if {"contributor", "validator"} <= set(roles):
        raise KeyCeremonyError("one key cannot be contributor and validator")
    return sorted(roles)


def build_challenge(
    *,
    policy_revision: int,
    event_sha256: list[str],
    principal_id: str,
    roles: list[str],
    public_key: bytes,
    issued_at: str,
    expires_at: str,
    nonce: bytes,
) -> dict[str, Any]:
    if not isinstance(principal_id, str) or not PRINCIPAL_RE.fullmatch(principal_id):
        raise KeyCeremonyError("principal ID must be a 3-64 character lowercase pseudonym")
    selected_roles = validate_roles(roles)
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise KeyCeremonyError("Ed25519 public key must be 32 bytes")
    if not isinstance(policy_revision, int) or isinstance(policy_revision, bool) or policy_revision < 1:
        raise KeyCeremonyError("policy revision must be positive")
    if not isinstance(event_sha256, list) or len(event_sha256) != policy_revision - 1 or any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in event_sha256):
        raise KeyCeremonyError("policy event ancestry does not match its revision")
    issued = _timestamp(issued_at, "$challenge.issued_at")
    expires = _timestamp(expires_at, "$challenge.expires_at")
    if expires <= issued or (expires - issued).total_seconds() > 604_800:
        raise KeyCeremonyError("challenge lifetime must be positive and no more than seven days")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise KeyCeremonyError("challenge nonce must be 32 bytes")
    encoded = base64.b64encode(public_key).decode("ascii")
    return {
        "schema": CHALLENGE_SCHEMA,
        "repository": REPOSITORY,
        "policy_revision": policy_revision,
        "event_sha256": list(event_sha256),
        "principal_id": principal_id,
        "roles": selected_roles,
        "public_key": encoded,
        "key_id": hashlib.sha256(public_key).hexdigest(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "authority": "proof_of_possession_challenge_only_no_identity_or_role_authority",
    }


def validate_challenge(value: Any) -> Mapping[str, Any]:
    challenge = _exact(
        value,
        {
            "schema",
            "repository",
            "policy_revision",
            "event_sha256",
            "principal_id",
            "roles",
            "public_key",
            "key_id",
            "issued_at",
            "expires_at",
            "nonce",
            "authority",
        },
        "$challenge",
    )
    if challenge["schema"] != CHALLENGE_SCHEMA or challenge["repository"] != REPOSITORY:
        raise KeyCeremonyError("challenge schema or repository drift")
    try:
        public_key = base64.b64decode(challenge["public_key"], validate=True)
        nonce = base64.b64decode(challenge["nonce"], validate=True)
    except (TypeError, ValueError) as exc:
        raise KeyCeremonyError("challenge public key or nonce encoding is invalid") from exc
    expected = build_challenge(
        policy_revision=challenge["policy_revision"],
        event_sha256=challenge["event_sha256"],
        principal_id=challenge["principal_id"],
        roles=challenge["roles"],
        public_key=public_key,
        issued_at=challenge["issued_at"],
        expires_at=challenge["expires_at"],
        nonce=nonce,
    )
    if dict(challenge) != expected:
        raise KeyCeremonyError("challenge contains non-canonical or inconsistent values")
    return challenge


def _decode_sshsig(text: str) -> bytes:
    header = "-----BEGIN SSH SIGNATURE-----"
    footer = "-----END SSH SIGNATURE-----"
    if not isinstance(text, str):
        raise KeyCeremonyError("detached signature text is required")
    lines = text.replace("\r\n", "\n").splitlines()
    if len(lines) < 3 or lines[0] != header or lines[-1] != footer:
        raise KeyCeremonyError("detached signature must use exact SSHSIG armor")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise KeyCeremonyError("invalid SSHSIG base64 armor") from exc


def _encode_sshsig(blob: bytes) -> str:
    value = base64.b64encode(blob).decode("ascii")
    body = "\n".join(value[index : index + 76] for index in range(0, len(value), 76))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n"


def verify_sshsig(message: bytes, signature_text: str, expected_public_key: bytes) -> str:
    blob = _decode_sshsig(signature_text)
    if not blob.startswith(b"SSHSIG") or len(blob) < 10:
        raise KeyCeremonyError("invalid SSHSIG preamble")
    version = struct.unpack(">I", blob[6:10])[0]
    if version != 1:
        raise KeyCeremonyError("unsupported SSHSIG version")
    offset = 10
    public_blob, offset = _read_ssh_string(blob, offset, "$sshsig.public_key")
    namespace, offset = _read_ssh_string(blob, offset, "$sshsig.namespace")
    reserved, offset = _read_ssh_string(blob, offset, "$sshsig.reserved")
    hash_algorithm, offset = _read_ssh_string(blob, offset, "$sshsig.hash_algorithm")
    signature_blob, offset = _read_ssh_string(blob, offset, "$sshsig.signature")
    if offset != len(blob):
        raise KeyCeremonyError("trailing SSHSIG bytes are forbidden")
    key_algorithm, key_offset = _read_ssh_string(public_blob, 0, "$sshsig.public_key.algorithm")
    public_key, key_offset = _read_ssh_string(public_blob, key_offset, "$sshsig.public_key.value")
    if key_offset != len(public_blob) or key_algorithm != b"ssh-ed25519" or len(public_key) != 32:
        raise KeyCeremonyError("SSHSIG must embed one Ed25519 public key")
    signature_algorithm, signature_offset = _read_ssh_string(signature_blob, 0, "$sshsig.signature.algorithm")
    signature, signature_offset = _read_ssh_string(signature_blob, signature_offset, "$sshsig.signature.value")
    if signature_offset != len(signature_blob) or signature_algorithm != b"ssh-ed25519" or len(signature) != 64:
        raise KeyCeremonyError("SSHSIG must contain one Ed25519 signature")
    if namespace != SSHSIG_NAMESPACE.encode() or reserved != b"" or hash_algorithm != b"sha256":
        raise KeyCeremonyError("SSHSIG namespace, reserved field, or hash algorithm is not allowed")
    if public_key != expected_public_key:
        raise KeyCeremonyError("SSHSIG public key differs from the enrollment challenge")
    signed = b"SSHSIG" + _ssh_string(namespace) + _ssh_string(reserved) + _ssh_string(hash_algorithm) + _ssh_string(hashlib.sha256(message).digest())
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed)
    except InvalidSignature as exc:
        raise KeyCeremonyError("SSHSIG proof of possession is invalid") from exc
    return _encode_sshsig(blob)


def validate_enrollment_event(event: Mapping[str, Any], prior_event_sha256: list[str]) -> None:
    proof = _exact(event.get("possession_proof"), {"challenge", "sshsig"}, "$key_event.possession_proof")
    challenge = validate_challenge(proof["challenge"])
    if challenge["policy_revision"] != event["effective_revision"] - 1 or challenge["event_sha256"] != prior_event_sha256:
        raise KeyCeremonyError("enrollment proof is stale for the current policy ancestry")
    for field in ("key_id", "principal_id", "roles", "public_key"):
        if challenge[field] != event[field]:
            raise KeyCeremonyError(f"enrollment proof does not bind event field {field}")
    event_at = _timestamp(event["event_at"], "$key_event.event_at")
    if event_at < _timestamp(challenge["issued_at"], "$challenge.issued_at") or event_at >= _timestamp(challenge["expires_at"], "$challenge.expires_at"):
        raise KeyCeremonyError("enrollment event is outside the signed challenge window")
    public_key = base64.b64decode(challenge["public_key"], validate=True)
    normalized = verify_sshsig(canonical_json_bytes(challenge), proof["sshsig"], public_key)
    if proof["sshsig"] != normalized:
        raise KeyCeremonyError("SSHSIG armor is not canonical")


def load_canonical_challenge(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise KeyCeremonyError("challenge must be a regular non-link file")
    value = path.read_bytes()
    if len(value) > 1_048_576 or any(marker in value for marker in PRIVATE_MARKERS):
        raise KeyCeremonyError("challenge is unsafe or too large")
    challenge = validate_challenge(strict_json_bytes(value))
    canonical = canonical_json_bytes(challenge)
    if value != canonical or path.stem != sha256_bytes(canonical):
        raise KeyCeremonyError("challenge must use canonical content-addressed bytes")
    return challenge


def write_content_addressed(output_dir: Path, document: Mapping[str, Any]) -> Path:
    output_dir = output_dir.resolve(strict=True)
    if not output_dir.is_dir():
        raise KeyCeremonyError("output directory is required")
    value = canonical_json_bytes(document)
    path = output_dir / f"{sha256_bytes(value)}.json"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise KeyCeremonyError("content-addressed output already exists") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    return path
