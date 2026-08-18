"""Fail-closed tests for evidence-gated Production lifecycle state."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_production_lifecycle as lifecycle

NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
SOURCE_COMMIT = "1" * 40
POLICY_DIGEST = "sha256:" + "a" * 64


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_policy() -> dict:
    return json.loads(
        (ROOT / "production-lifecycle-policy.json").read_text(encoding="utf-8")
    )


def flow_release() -> dict:
    artifacts = [
        {
            "name": "openadapt_flow-2.0.0.tar.gz",
            "kind": "sdist",
            "url": "https://files.example.test/"
            + "2" * 64
            + "/openadapt_flow-2.0.0.tar.gz",
            "sha256": "sha256:" + "2" * 64,
            "size_bytes": 200,
        },
        {
            "name": "openadapt_flow-2.0.0-py3-none-any.whl",
            "kind": "wheel",
            "url": "https://files.example.test/"
            + "3" * 64
            + "/openadapt_flow-2.0.0-py3-none-any.whl",
            "sha256": "sha256:" + "3" * 64,
            "size_bytes": 300,
        },
    ]
    return {
        "kind": "public_package",
        "version": "2.0.0",
        "tag": "v2.0.0",
        "source_commit": SOURCE_COMMIT,
        "immutable_release_url": (
            "https://github.com/OpenAdaptAI/openadapt-flow/commit/" + SOURCE_COMMIT
        ),
        "artifacts": artifacts,
    }


def cloud_release() -> dict:
    return {
        "kind": "private_deployment",
        "deployment_release_id": "cloud-production-2026-08-18.1",
        "deployment_release_sha256": "sha256:" + "4" * 64,
        "manifest_sha256": "sha256:" + "5" * 64,
    }


def docs_release() -> dict:
    artifacts = [
        {
            "name": "deployment-manifest.json",
            "kind": "deployment-manifest",
            "url": "https://docs.openadapt.ai/releases/" + "8" * 64 + "/manifest.json",
            "sha256": "sha256:" + "8" * 64,
            "size_bytes": 80,
        },
        {
            "name": "docs-site.tar.zst",
            "kind": "site-archive",
            "url": "https://docs.openadapt.ai/releases/"
            + "9" * 64
            + "/docs-site.tar.zst",
            "sha256": "sha256:" + "9" * 64,
            "size_bytes": 900,
        },
    ]
    return {
        "kind": "public_deployment",
        "deployment_id": "docs-production-2026-08-18.1",
        "deployment_sha256": "sha256:" + "d" * 64,
        "source_commit": SOURCE_COMMIT,
        "immutable_release_url": (
            "https://github.com/OpenAdaptAI/openadapt-ops/commit/" + SOURCE_COMMIT
        ),
        "artifacts": artifacts,
    }


def build_case(
    target: str = "flow", release: dict | None = None
) -> tuple[dict, dict, dict[str, bytes]]:
    release = copy.deepcopy(release or flow_release())
    evidence = json.dumps(
        {
            "schema_version": "openadapt.evals-derived-production-acceptance/v1",
            "verdict": "accepted",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evidence_digest = digest_bytes(evidence)
    evidence_url = (
        "https://evidence.openadapt.ai/objects/"
        + evidence_digest.removeprefix("sha256:")
        + "/manifest.json"
    )
    summary = {
        "schema_version": lifecycle.SUMMARY_SCHEMA,
        "target": target,
        "verdict": "accepted",
        "release_sha256": lifecycle._canonical_digest(release),
        "artifact_inventory_sha256": lifecycle._canonical_digest(
            release.get("artifacts", [])
        ),
        "private_certificate_binding": {
            "schema_version": "openadapt.execute-live-acceptance-record/v2",
            "sha256": "sha256:" + "6" * 64,
            "signer_provenance_sha256": "sha256:" + "7" * 64,
        },
        "evidence_manifest": {
            "schema_version": "openadapt.evals-derived-production-acceptance/v1",
            "url": evidence_url,
            "sha256": evidence_digest,
        },
        "issued_at": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-20T11:00:00Z",
        "revoked_at": None,
    }
    summary_bytes = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
    summary_digest = digest_bytes(summary_bytes)
    bundle_bytes = b"synthetic-attestation-bundle"
    bundle_digest = digest_bytes(bundle_bytes)
    summary_url = (
        "https://github.com/OpenAdaptAI/openadapt-evals/raw/"
        + SOURCE_COMMIT
        + "/evidence/"
        + summary_digest.removeprefix("sha256:")
        + ".json"
    )
    bundle_url = (
        "https://github.com/OpenAdaptAI/openadapt-evals/raw/"
        + SOURCE_COMMIT
        + "/evidence/"
        + bundle_digest.removeprefix("sha256:")
        + ".sigstore.json"
    )
    admission = {
        "admission_id": f"production:{target}:2026-08-18.1",
        "target": target,
        "policy_revision": 1,
        "release": release,
        "acceptance_evidence": {
            "summary_url": summary_url,
            "summary_sha256": summary_digest,
            "attestation_bundle_url": bundle_url,
            "attestation_bundle_sha256": bundle_digest,
            "authority_source_commit": SOURCE_COMMIT,
        },
        "issued_at": summary["issued_at"],
        "expires_at": summary["expires_at"],
        "revoked_at": None,
    }
    admissions = {
        "$schema": "schemas/production-lifecycle-admissions.schema.json",
        "schema_version": lifecycle.ADMISSIONS_SCHEMA,
        "policy_sha256": POLICY_DIGEST,
        "admissions": [admission],
    }
    remote = {
        summary_url: summary_bytes,
        bundle_url: bundle_bytes,
        evidence_url: evidence,
    }
    return admissions, summary, remote


def empty_admissions() -> dict:
    return {
        "$schema": "schemas/production-lifecycle-admissions.schema.json",
        "schema_version": lifecycle.ADMISSIONS_SCHEMA,
        "policy_sha256": POLICY_DIGEST,
        "admissions": [],
    }


def validate_case(
    admissions: dict,
    remote: dict[str, bytes] | None = None,
    repositories: list[str] | None = None,
    surfaces: list[str] | None = None,
    attestation_valid: bool = True,
) -> dict[str, str]:
    attestation_calls: list[tuple[bytes, bytes]] = []

    def fetch(url: str) -> bytes:
        assert remote is not None
        return remote[url]

    def verify(
        summary: bytes, bundle: bytes, _authority: dict, _source_commit: str
    ) -> None:
        if not attestation_valid:
            raise lifecycle.LifecycleError("synthetic attestation failure")
        attestation_calls.append((summary, bundle))

    repository_lifecycle, surface_lifecycle = lifecycle.load_lifecycle()
    repository_lifecycle = copy.deepcopy(repository_lifecycle)
    surface_lifecycle = copy.deepcopy(surface_lifecycle)
    repository_lifecycle["production"] = list(repositories or [])
    surface_lifecycle["production"] = list(surfaces or [])
    for subject in repositories or []:
        for group, subjects in repository_lifecycle.items():
            if group != "production" and subject in subjects:
                subjects.remove(subject)
    for subject in surfaces or []:
        for group, subjects in surface_lifecycle.items():
            if group != "production" and subject in subjects:
                subjects.remove(subject)

    result = lifecycle.validate(
        load_policy(),
        admissions,
        repository_lifecycle,
        surface_lifecycle,
        policy_sha256=POLICY_DIGEST,
        now=NOW,
        fetch=fetch,
        verify_attestation=verify,
    )
    if admissions["admissions"]:
        assert len(attestation_calls) == 1
    return result


class ProductionLifecycleTests(unittest.TestCase):
    def test_current_registry_has_no_production_admissions(self) -> None:
        self.assertEqual(validate_case(empty_admissions()), {})

    def test_valid_exact_public_package_admission(self) -> None:
        admissions, _summary, remote = build_case()
        self.assertEqual(
            validate_case(admissions, remote, repositories=["openadapt-flow"]),
            {"flow": "production:flow:2026-08-18.1"},
        )

    def test_private_cloud_uses_opaque_release_without_public_url(self) -> None:
        admissions, _summary, remote = build_case("cloud", cloud_release())
        self.assertEqual(
            validate_case(admissions, remote, repositories=["openadapt-cloud"]),
            {"cloud": "production:cloud:2026-08-18.1"},
        )
        serialized = json.dumps(admissions["admissions"][0]["release"])
        self.assertNotIn("url", serialized.lower())

    def test_valid_exact_docs_deployment_admission(self) -> None:
        admissions, _summary, remote = build_case("docs", docs_release())
        self.assertEqual(
            validate_case(admissions, remote, surfaces=["docs.openadapt.ai"]),
            {"docs": "production:docs:2026-08-18.1"},
        )

    def test_registry_membership_without_admission_is_refused(self) -> None:
        with self.assertRaisesRegex(lifecycle.LifecycleError, "memberships differ"):
            validate_case(empty_admissions(), repositories=["openadapt-flow"])

    def test_admission_without_registry_membership_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        with self.assertRaisesRegex(lifecycle.LifecycleError, "memberships differ"):
            validate_case(admissions, remote)

    def test_policy_digest_mismatch_is_refused(self) -> None:
        admissions = empty_admissions()
        admissions["policy_sha256"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(lifecycle.LifecycleError, "policy digest differs"):
            validate_case(admissions)

    def test_expired_admission_is_refused_before_remote_fetch(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["expires_at"] = "2026-08-18T11:59:59Z"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "is expired"):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_revoked_admission_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["revoked_at"] = "2026-08-18T11:30:00Z"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "is revoked"):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_summary_digest_mismatch_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        summary_url = admissions["admissions"][0]["acceptance_evidence"]["summary_url"]
        remote[summary_url] += b"tampered"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "summary digest changed"):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_invalid_summary_attestation_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        with self.assertRaisesRegex(lifecycle.LifecycleError, "attestation failure"):
            validate_case(
                admissions,
                remote,
                repositories=["openadapt-flow"],
                attestation_valid=False,
            )

    def test_evidence_manifest_digest_mismatch_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        remote[summary["evidence_manifest"]["url"]] += b"tampered"
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "evidence manifest digest changed"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_release_digest_mismatch_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        summary["release_sha256"] = "sha256:" + "f" * 64
        summary_bytes = json.dumps(
            summary, sort_keys=True, separators=(",", ":")
        ).encode()
        reference = admissions["admissions"][0]["acceptance_evidence"]
        old_url = reference["summary_url"]
        new_digest = digest_bytes(summary_bytes)
        new_url = (
            "https://evidence.openadapt.ai/objects/"
            + new_digest.removeprefix("sha256:")
            + "/summary.json"
        )
        reference["summary_url"] = new_url
        reference["summary_sha256"] = new_digest
        remote[new_url] = summary_bytes
        del remote[old_url]
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "summary release digest differs"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_missing_required_artifact_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["release"]["artifacts"] = [
            admissions["admissions"][0]["release"]["artifacts"][1]
        ]
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "missing required artifact"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_unbound_evidence_url_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["acceptance_evidence"]["summary_url"] = (
            "https://evidence.openadapt.ai/latest/summary.json"
        )
        with self.assertRaisesRegex(lifecycle.LifecycleError, "not bound"):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_schema_files_are_valid_json(self) -> None:
        for path in sorted((ROOT / "schemas").glob("production-lifecycle-*.json")):
            self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)


if __name__ == "__main__":
    unittest.main()
