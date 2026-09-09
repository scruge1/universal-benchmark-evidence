"""Verify a reviewed Universal Benchmark Router evidence exchange.

This verifier reads saved files only. It does not use the network, execute
submitted content, publish a catalog, or operate a model host.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from universal_benchmark_exchange import (
    ACK_SCHEMA,
    CONTRIBUTION_SCHEMA,
    REQUEST_SCHEMA,
    RESULT_ENVELOPE_SCHEMA,
)
from universal_benchmark_registry import (
    FileRegistry,
    canonical_json_bytes,
    sha256_bytes,
    strict_json_bytes,
)
from universal_model_router import canonical_sha256


RAW_MANIFEST_SCHEMA = "universal-benchmark-raw-manifest/v1"
POLICY_SCHEMA = "universal-benchmark-exchange-software-policy/v1"
KEY_MAP_SCHEMA = "universal-benchmark-public-key-map/v1"
DOCUMENT_AREAS = {
    REQUEST_SCHEMA: "requests",
    CONTRIBUTION_SCHEMA: "contributions",
    RESULT_ENVELOPE_SCHEMA: "results",
    ACK_SCHEMA: "acknowledgements",
    RAW_MANIFEST_SCHEMA: "raw-manifests",
}
CONTRIBUTOR_PREFIXES = tuple(f"queue/{area}/" for area in DOCUMENT_AREAS.values())
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"ghp_",
    b"github_pat_",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_PIN_RE = re.compile(r"^\s*uses:\s*[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


class ExchangeVerificationError(ValueError):
    """The hosted exchange candidate is unsafe, incomplete, or inconsistent."""


def _exact(value: Any, keys: set[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExchangeVerificationError(f"{path}: object is required")
    missing = sorted(keys - set(value))
    extra = sorted(set(value) - keys)
    if missing or extra:
        raise ExchangeVerificationError(
            f"{path}: exact keys required; missing={missing!r} extra={extra!r}"
        )
    return value


def _load_json(path: Path, *, max_bytes: int | None = None) -> Any:
    if path.is_symlink():
        raise ExchangeVerificationError(f"links are forbidden: {path}")
    value = path.read_bytes()
    if max_bytes is not None and len(value) > max_bytes:
        raise ExchangeVerificationError(f"compact document exceeds {max_bytes} bytes: {path}")
    if any(marker.lower() in value.lower() for marker in PRIVATE_MARKERS):
        raise ExchangeVerificationError(f"private key or credential marker is forbidden: {path}")
    try:
        return strict_json_bytes(value)
    except Exception as exc:
        raise ExchangeVerificationError(f"strict UTF-8 JSON is required: {path}") from exc


def _validate_policy(root: Path) -> tuple[Mapping[str, Any], Mapping[str, str]]:
    policy = _exact(
        _load_json(root / "policy" / "software-release.json"),
        {"schema", "router", "max_compact_bytes", "minimum_distinct_contributors", "authority"},
        "$policy",
    )
    if policy["schema"] != POLICY_SCHEMA:
        raise ExchangeVerificationError("$policy.schema: unsupported policy")
    router = _exact(
        policy["router"],
        {"repository", "version", "tag", "commit", "wheel_sha256", "source_sha256", "certificate_identity"},
        "$policy.router",
    )
    if not isinstance(router["commit"], str) or not GIT_COMMIT_RE.fullmatch(router["commit"]):
        raise ExchangeVerificationError("$policy.router.commit: lowercase 40-character Git object ID is required")
    for field in ("wheel_sha256", "source_sha256"):
        if not isinstance(router[field], str) or not SHA256_RE.fullmatch(router[field]):
            raise ExchangeVerificationError(f"$policy.router.{field}: lowercase SHA-256 is required")
    if importlib.metadata.version("universal-benchmark-router") != router["version"]:
        raise ExchangeVerificationError("installed router version differs from pinned policy")
    if not isinstance(policy["max_compact_bytes"], int) or not 1 <= policy["max_compact_bytes"] <= 1_048_576:
        raise ExchangeVerificationError("$policy.max_compact_bytes: range is 1..1048576")
    if not isinstance(policy["minimum_distinct_contributors"], int) or policy["minimum_distinct_contributors"] < 2:
        raise ExchangeVerificationError("$policy.minimum_distinct_contributors: at least two are required")

    key_doc = _exact(
        _load_json(root / "policy" / "public-keys.json"),
        {"schema", "revision", "effective_at", "keys", "authority"},
        "$public_keys",
    )
    if key_doc["schema"] != KEY_MAP_SCHEMA or not isinstance(key_doc["revision"], int) or key_doc["revision"] < 1:
        raise ExchangeVerificationError("$public_keys: supported schema and positive revision are required")
    keys = key_doc["keys"]
    if not isinstance(keys, Mapping):
        raise ExchangeVerificationError("$public_keys.keys: object is required")
    for key_id, encoded in keys.items():
        if not isinstance(key_id, str) or not SHA256_RE.fullmatch(key_id) or not isinstance(encoded, str):
            raise ExchangeVerificationError("$public_keys.keys: SHA-256 to base64 map is required")
        try:
            public_bytes = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ExchangeVerificationError(f"invalid public key encoding: {key_id}") from exc
        if len(public_bytes) != 32 or hashlib.sha256(public_bytes).hexdigest() != key_id:
            raise ExchangeVerificationError(f"public key identity drift: {key_id}")
    return policy, dict(keys)


def _validate_raw_manifest(document: Mapping[str, Any]) -> None:
    manifest = _exact(
        document,
        {"schema", "generated_at", "submission_id", "artifacts", "authority"},
        "$raw_manifest",
    )
    if manifest["schema"] != RAW_MANIFEST_SCHEMA:
        raise ExchangeVerificationError("$raw_manifest.schema: unsupported schema")
    if not isinstance(manifest["submission_id"], str) or not manifest["submission_id"]:
        raise ExchangeVerificationError("$raw_manifest.submission_id: non-empty value is required")
    if manifest["authority"] != "external_raw_artifact_references_only":
        raise ExchangeVerificationError("$raw_manifest.authority: reference-only authority is required")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ExchangeVerificationError("$raw_manifest.artifacts: non-empty array is required")
    seen: set[str] = set()
    for index, item in enumerate(artifacts):
        artifact = _exact(
            item,
            {"artifact_id", "locator", "sha256", "size_bytes", "media_type", "disclosure", "retention"},
            f"$raw_manifest.artifacts[{index}]",
        )
        if not isinstance(artifact["artifact_id"], str) or not artifact["artifact_id"] or artifact["artifact_id"] in seen:
            raise ExchangeVerificationError("raw artifact identities must be non-empty and unique")
        seen.add(artifact["artifact_id"])
        locator = artifact["locator"]
        if not isinstance(locator, str):
            raise ExchangeVerificationError("raw artifact locator must be a string")
        parsed = urlsplit(locator)
        if parsed.scheme not in {"https", "ipfs"} or parsed.username or parsed.password or "latest" in locator.lower():
            raise ExchangeVerificationError("raw artifact locator must be immutable HTTPS or IPFS without credentials")
        if not isinstance(artifact["sha256"], str) or not SHA256_RE.fullmatch(artifact["sha256"]):
            raise ExchangeVerificationError("raw artifact SHA-256 is required")
        if not isinstance(artifact["size_bytes"], int) or artifact["size_bytes"] < 1:
            raise ExchangeVerificationError("raw artifact positive byte size is required")
        for field in ("media_type", "disclosure", "retention"):
            if not isinstance(artifact[field], str) or not artifact[field]:
                raise ExchangeVerificationError(f"raw artifact {field} is required")


def _queue_documents(root: Path, max_bytes: int) -> dict[str, dict[str, Mapping[str, Any]]]:
    queue = root / "queue"
    output: dict[str, dict[str, Mapping[str, Any]]] = {area: {} for area in DOCUMENT_AREAS.values()}
    for path in sorted(queue.rglob("*")):
        if path.is_symlink():
            raise ExchangeVerificationError(f"links are forbidden: {path}")
        if not path.is_file() or path.name.startswith(".") or path.name == "README.md":
            continue
        relative = path.relative_to(root).as_posix()
        if path.suffix != ".json" or len(path.relative_to(queue).parts) != 2:
            raise ExchangeVerificationError(f"queue files must be direct JSON documents in an allowed area: {relative}")
        area = path.parent.name
        if area not in output:
            raise ExchangeVerificationError(f"unsupported queue area: {relative}")
        document = _load_json(path, max_bytes=max_bytes)
        if not isinstance(document, Mapping):
            raise ExchangeVerificationError(f"queue document must be an object: {relative}")
        expected_area = DOCUMENT_AREAS.get(document.get("schema"))
        if expected_area != area:
            raise ExchangeVerificationError(f"document schema does not match queue area: {relative}")
        canonical = canonical_json_bytes(document)
        digest = sha256_bytes(canonical)
        if path.stem != digest:
            raise ExchangeVerificationError(f"filename must equal canonical document SHA-256: {relative}")
        if path.read_bytes() != canonical:
            raise ExchangeVerificationError(f"queue document bytes must be canonical JSON: {relative}")
        if digest in output[area]:
            raise ExchangeVerificationError(f"duplicate queue digest: {digest}")
        if area == "raw-manifests":
            _validate_raw_manifest(document)
        output[area][digest] = document
    return output


def _audit_workflows(root: Path) -> None:
    workflow_root = root / ".github" / "workflows"
    for path in sorted(workflow_root.glob("*.y*ml")):
        if path.is_symlink():
            raise ExchangeVerificationError(f"links are forbidden: {path}")
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        if "pull_request_target" in lowered:
            raise ExchangeVerificationError(f"pull_request_target is forbidden: {path.name}")
        if "secrets." in lowered or "write-all" in lowered or re.search(r"permissions\s*:\s*write", lowered):
            raise ExchangeVerificationError(f"workflow secrets or write permission are forbidden: {path.name}")
        if "permissions:\n  contents: read" not in text:
            raise ExchangeVerificationError(f"explicit read-only contents permission is required: {path.name}")
        for line in text.splitlines():
            if line.lstrip().startswith("uses:") and not ACTION_PIN_RE.fullmatch(line):
                raise ExchangeVerificationError(f"workflow action must use an exact commit SHA: {path.name}: {line.strip()}")
        if path.name == "validate.yml":
            required = (
                "ref: ${{ github.event.pull_request.base.sha }}",
                "python trusted-base/tools/verify_exchange.py",
                "--root submitted",
                "--changed-range",
                "universal_benchmark_router-0.3.0-py3-none-any.whl#sha256=957b5100af942b90c7480bd9403b3168b100f256a54f7d1bc3e3658d9036a04b",
            )
            if any(marker not in text for marker in required):
                raise ExchangeVerificationError("pull requests must use the trusted base guard and exact router wheel")
            if "--requirement requirements-ci.txt" in text:
                raise ExchangeVerificationError("pull-request dependencies cannot come from submitted requirements")


def _package_json(name: str) -> Mapping[str, Any]:
    value = importlib.resources.files("router").joinpath(name).read_bytes()
    document = strict_json_bytes(value)
    if not isinstance(document, Mapping):
        raise ExchangeVerificationError(f"packaged router asset must be an object: {name}")
    return document


def verify_exchange(root: Path) -> dict[str, Any]:
    root = root.resolve()
    _audit_workflows(root)
    policy, public_keys = _validate_policy(root)
    documents = _queue_documents(root, int(policy["max_compact_bytes"]))
    contract = _package_json("benchmark-capability-contract-v2.json")
    suite = _package_json("standard-task-suite-v1.json")
    requests = documents["requests"]
    contributions = documents["contributions"]
    results = documents["results"]
    acknowledgements = documents["acknowledgements"]
    raw_manifests = documents["raw-manifests"]
    used_raw_manifests: set[str] = set()

    requests_by_id: dict[str, Mapping[str, Any]] = {}
    contributions_by_id: dict[str, Mapping[str, Any]] = {}
    result_submission_hashes: set[str] = set()
    for document in requests.values():
        request_id = document.get("request_id")
        if isinstance(request_id, str):
            requests_by_id[request_id] = document
    for digest, document in contributions.items():
        submission_id = document.get("submission_id")
        if isinstance(submission_id, str):
            contributions_by_id[submission_id] = document
        evidence = document.get("evidence")
        raw_digest = evidence.get("raw_manifest_sha256") if isinstance(evidence, Mapping) else None
        manifest = raw_manifests.get(raw_digest) if isinstance(raw_digest, str) else None
        if manifest is None or manifest.get("submission_id") != submission_id:
            raise ExchangeVerificationError(f"contribution {digest} requires its exact raw manifest")
        used_raw_manifests.add(raw_digest)
    if set(raw_manifests) != used_raw_manifests:
        raise ExchangeVerificationError("orphan raw manifests are forbidden")

    with tempfile.TemporaryDirectory(prefix="universal-exchange-registry-") as temporary:
        registry = FileRegistry.initialize(Path(temporary) / "registry")
        for digest, document in sorted(requests.items()):
            registry.ingest_request(document, contract, public_keys, source_sha256=digest)
        for digest, document in sorted(contributions.items()):
            registry.ingest_contribution(document, suite, public_keys, source_sha256=digest)
        for digest, document in sorted(results.items()):
            request = requests_by_id.get(document.get("request_id"))
            embedded = document.get("contribution")
            submission_id = embedded.get("submission_id") if isinstance(embedded, Mapping) else None
            contribution = contributions_by_id.get(submission_id) if isinstance(submission_id, str) else None
            if request is None or contribution is None or canonical_sha256(embedded) != canonical_sha256(contribution):
                raise ExchangeVerificationError(f"result {digest} has an absent or drifting dependency")
            registry.ingest_result(document, request, contract, suite, public_keys, source_sha256=digest)
            result_submission_hashes.add(canonical_sha256(contribution))
        for digest, document in sorted(acknowledgements.items()):
            contribution = contributions_by_id.get(document.get("submission_id"))
            if contribution is None or canonical_sha256(contribution) not in result_submission_hashes:
                raise ExchangeVerificationError(f"acknowledgement {digest} requires an accepted result")
            registry.ingest_acknowledgement(document, contribution, suite, public_keys, source_sha256=digest)
        audit = registry.audit()

    return {
        "schema": "universal-benchmark-evidence-exchange-audit/v1",
        "router_version": policy["router"]["version"],
        "policy_sha256": canonical_sha256(policy),
        "public_key_count": len(public_keys),
        "queue_counts": {area: len(items) for area, items in sorted(documents.items())},
        "registry_audit_sha256": canonical_sha256(audit),
        "authority": "offline_reviewed_queue_verification_only_no_blessing_or_publication",
        "hosted_activation": "requires_queue_only_protected_ruleset_and_trusted_base_verifier",
    }


def _changed_paths(root: Path, changed_range: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", changed_range],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip().replace("\\", "/") for line in completed.stdout.splitlines() if line.strip()]


def verify_contributor_paths(paths: list[str]) -> None:
    if not paths:
        raise ExchangeVerificationError("contributor change set must not be empty")
    for path in paths:
        if path.startswith("/") or ".." in Path(path).parts or not path.endswith(".json"):
            raise ExchangeVerificationError(f"unsafe contributor path: {path}")
        if not path.startswith(CONTRIBUTOR_PREFIXES):
            raise ExchangeVerificationError(f"contributor changes are queue-only: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--changed-range")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.changed_range:
        verify_contributor_paths(_changed_paths(root, args.changed_range))
    print(json.dumps(verify_exchange(root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
