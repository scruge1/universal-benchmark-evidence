from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from verify_exchange import (  # noqa: E402
    ExchangeVerificationError,
    RAW_MANIFEST_SCHEMA,
    verify_contributor_paths,
    verify_exchange,
)
from universal_benchmark_registry import canonical_json_bytes  # noqa: E402
from universal_model_router import canonical_sha256  # noqa: E402


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

    def test_empty_offline_candidate_passes_without_any_real_authority(self) -> None:
        report = verify_exchange(self.root)
        self.assertEqual(0, report["public_key_count"])
        self.assertEqual("offline_reviewed_queue_verification_only_no_blessing_or_publication", report["authority"])
        self.assertTrue(all(count == 0 for count in report["queue_counts"].values()))

    def test_contributor_changes_are_queue_only_json(self) -> None:
        verify_contributor_paths(["queue/results/" + "a" * 64 + ".json"])
        for path in ("tools/verify_exchange.py", "queue/README.md", "../escape.json"):
            with self.subTest(path=path), self.assertRaises(ExchangeVerificationError):
                verify_contributor_paths([path])

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
        with self.assertRaisesRegex(ExchangeVerificationError, "exact raw manifest"):
            verify_exchange(self.root)

    def test_public_key_map_cannot_bind_wrong_identity(self) -> None:
        path = self.root / "policy" / "public-keys.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["keys"] = {"0" * 64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ExchangeVerificationError, "public key identity drift"):
            verify_exchange(self.root)

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
