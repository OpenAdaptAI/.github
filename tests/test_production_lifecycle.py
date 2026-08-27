"""Fail-closed tests for evidence-gated Production lifecycle state."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_production_lifecycle as lifecycle  # noqa: E402

NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
SOURCE_COMMIT = "1" * 40
POLICY_DIGEST = "sha256:" + "a" * 64


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class LegacyRegistryError(ValueError):
    pass


def legacy_entry_digest(entry: dict) -> str:
    projection = {
        field: entry[field]
        for field in (
            "kind", "prior_entry_sha256", "recorded_at", "sequence",
            "sha256", "size_bytes", "url",
        )
    }
    return digest_bytes(
        b"OpenAdapt production evidence registry entry v1\0"
        + json.dumps(
            projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    )


def legacy_build_entry(**fields: object) -> dict:
    entry = dict(fields)
    entry["entry_sha256"] = legacy_entry_digest(entry)
    return entry


def legacy_registry_adapter() -> types.SimpleNamespace:
    def validate_registry(value: object) -> list[dict]:
        if not isinstance(value, dict) or set(value) != {
            "$schema", "schema_version", "head_entry_sha256", "entries"
        }:
            raise LegacyRegistryError("evidence registry object is not closed")
        if value["schema_version"] != "openadapt.production-evidence-registry/v1":
            raise LegacyRegistryError("evidence registry schema is not supported")
        entries = value["entries"]
        if not isinstance(entries, list):
            raise LegacyRegistryError("evidence registry entries must be a list")
        prior = None
        for index, entry in enumerate(entries):
            if (
                entry["sequence"] != index + 1
                or entry["prior_entry_sha256"] != prior
                or entry["entry_sha256"] != legacy_entry_digest(entry)
            ):
                raise LegacyRegistryError("evidence registry chain is invalid")
            prior = entry["entry_sha256"]
        if value["head_entry_sha256"] != prior:
            raise LegacyRegistryError("evidence registry head digest is stale")
        return entries

    def require_registered(
        entries: list[dict], *, url: str, sha256: str, kind: str, label: str
    ) -> None:
        matches = [
            entry for entry in entries
            if entry["url"] == url and entry["sha256"] == sha256
        ]
        if len(matches) != 1:
            raise LegacyRegistryError(
                f"{label} is not registered in the central evidence registry"
            )
        if matches[0]["kind"] != kind:
            raise LegacyRegistryError(f"{label} is registered with the wrong kind")

    return types.SimpleNamespace(
        EvidenceRegistryError=LegacyRegistryError,
        validate_registry=validate_registry,
        require_registered=require_registered,
    )


def load_policy() -> dict:
    # The first v2 migration PR retains the v1 validator for recovery only.
    # Keep these tests on its own closed contract instead of feeding it v2 bytes.
    return {
        "$schema": "schemas/production-lifecycle-policy.schema.json",
        "schema_version": lifecycle.POLICY_SCHEMA,
        "revision": 1,
        "maximum_admission_days": 30,
        "summary_authority": copy.deepcopy(lifecycle.EXPECTED_AUTHORITY),
        "targets": [
            {"id": target, **copy.deepcopy(contract)}
            for target, contract in lifecycle.EXPECTED_TARGETS.items()
        ],
    }


def flow_release() -> dict:
    artifacts = [
        {
            "name": "openadapt_flow-2.0.0.tar.gz",
            "kind": "sdist",
            "authority": "pypi",
            "url": "https://files.pythonhosted.org/packages/"
            + "2" * 64
            + "/openadapt_flow-2.0.0.tar.gz",
            "sha256": "sha256:" + "2" * 64,
            "size_bytes": 200,
        },
        {
            "name": "openadapt_flow-2.0.0-py3-none-any.whl",
            "kind": "wheel",
            "authority": "pypi",
            "url": "https://files.pythonhosted.org/packages/"
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


def next_flow_release() -> dict:
    release = flow_release()
    release["version"] = "2.0.1"
    release["tag"] = "v2.0.1"
    release["source_commit"] = "f" * 40
    release["immutable_release_url"] = (
        "https://github.com/OpenAdaptAI/openadapt-flow/commit/" + "f" * 40
    )
    for artifact in release["artifacts"]:
        artifact["name"] = artifact["name"].replace("2.0.0", "2.0.1")
    return release


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
            "authority": "managed_evidence",
            "url": "https://evidence.openadapt.ai/objects/"
            + "8" * 64
            + "/manifest.json",
            "sha256": "sha256:" + "8" * 64,
            "size_bytes": 80,
        },
        {
            "name": "docs-site.tar.zst",
            "kind": "site-archive",
            "authority": "managed_evidence",
            "url": "https://evidence.openadapt.ai/objects/"
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
    target: str = "flow",
    release: dict | None = None,
    *,
    release_sequence: int = 1,
    previous_admission_sha256: str | None = None,
    issued_at: str = "2026-08-18T11:00:00Z",
    expires_at: str = "2026-08-20T11:00:00Z",
) -> tuple[dict, dict, dict[str, bytes]]:
    release = copy.deepcopy(release or flow_release())
    policy = load_policy()
    claim_scope = next(
        item["required_claim_scope"]
        for item in policy["targets"]
        if item["id"] == target
    )
    acceptance_policy_digest = policy["summary_authority"]["acceptance_policy_sha256"]
    release_digest = lifecycle._target_release_digest(target, claim_scope, release)
    artifact_digest = lifecycle._artifact_inventory_digest(
        target, claim_scope, release.get("artifacts", [])
    )
    release_identity = {
        "schema_version": lifecycle.RELEASE_IDENTITY_SCHEMA,
        "channel": "production",
        "sequence": release_sequence,
        "previous_admission_sha256": previous_admission_sha256,
    }
    evidence_identity = "sha256:" + "c" * 64
    evidence = json.dumps(
        {
            "schema_version": "openadapt.production-acceptance/v1",
            "target": target,
            "claim_scope": claim_scope,
            "verdict": "accepted",
            "acceptance_policy_sha256": acceptance_policy_digest,
            "lifecycle_policy_sha256": POLICY_DIGEST,
            "target_release_sha256": release_digest,
            "target_artifact_inventory_sha256": artifact_digest,
            "evidence_identity_sha256": evidence_identity,
            "source_evidence": {
                "source_result_sha256": "sha256:" + "0" * 64,
                "certificate_sha256": "sha256:" + "6" * 64,
                "campaign_sha256": "sha256:" + "b" * 64,
                "qualification_admission_sha256": "sha256:" + "a" * 64,
                "attestation_sha256": "sha256:" + "c" * 64,
                "attestation_bundle_sha256": "sha256:" + "d" * 64,
            },
            "qualification": {
                "campaign_contract_sha256": "sha256:" + "b" * 64,
                "campaign_outcomes_sha256": "sha256:" + "c" * 64,
                "oracle_contract_sha256": "sha256:" + "d" * 64,
                "task_count": 1,
                "condition_count": 1,
                "required_trial_count": 3,
                "observed_trial_count": 3,
                "minimum_trials_per_condition": 3,
                "excluded_trial_count": 0,
                "task_condition_inventory_sha256": "sha256:" + "e" * 64,
            },
            "failure_taxonomy_counts": {
                "collateral_effect": 0,
                "duplicate_effect": 0,
                "healthy_path_model_call": 0,
                "operator_intervention": 0,
                "over_halt": 0,
                "platform_failure": 0,
                "safe_halt": 0,
                "silent_incorrect_success": 0,
                "uncertain_delivery": 0,
                "verified": 3,
                "wrong_record": 0,
            },
            "reliability": {
                "silent_incorrect_success_count": 0,
                "over_halt_count": 0,
                "wrong_record_count": 0,
                "duplicate_effect_count": 0,
                "collateral_effect_count": 0,
                "operator_intervention_count": 0,
                "uncertain_delivery_count": 0,
                "model_call_count": 0,
            },
            "retention": {
                "receipt_id": "retention:" + "f" * 32,
                "ciphertext_sha256": "sha256:" + "1" * 64,
                "candidate_sha256": "sha256:" + "2" * 64,
                "private_envelope_sha256": "sha256:" + "3" * 64,
                "store_attestation_sha256": "sha256:" + "4" * 64,
                "storage_identity_sha256": "sha256:" + "5" * 64,
                "object_version_sha256": "sha256:" + "6" * 64,
                "private_locator_version_sha256": "sha256:" + "7" * 64,
                "kms_key_identity_sha256": "sha256:" + "8" * 64,
                "uploader_identity_sha256": "sha256:" + "9" * 64,
                "retention_mode": "COMPLIANCE",
                "retention_until": "2027-08-18T10:00:00.000Z",
                "retained_at": "2026-08-18T10:00:00.000Z",
                "upload_verified": True,
                "head_verified": True,
                "object_lock_verified": True,
                "private_locator_recorded": True,
                "acceptance_verified_at": "2026-08-18T09:59:59.500Z",
                "provenance_attestation": "github-artifact-attestation-v4",
            },
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
        "claim_scope": claim_scope,
        "acceptance_policy_sha256": acceptance_policy_digest,
        "lifecycle_policy_sha256": POLICY_DIGEST,
        "release_identity": release_identity,
        "release_sha256": release_digest,
        "artifact_inventory_sha256": artifact_digest,
        "evidence_identity_sha256": evidence_identity,
        "private_certificate_binding": {
            "schema_version": "openadapt.execute-live-acceptance-record/v2",
            "sha256": "sha256:" + "6" * 64,
            "signer_provenance_sha256": "sha256:" + "7" * 64,
            "evidence_identity_sha256": evidence_identity,
            "target": target,
            "target_release_sha256": release_digest,
            "target_artifact_inventory_sha256": artifact_digest,
        },
        "evidence_manifest": {
            "schema_version": "openadapt.production-acceptance/v1",
            "url": evidence_url,
            "sha256": evidence_digest,
        },
        "issued_at": issued_at,
        "expires_at": expires_at,
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
        "admission_id": f"production:{target}:{release_sequence}",
        "target": target,
        "claim_scope": claim_scope,
        "release_identity": release_identity,
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
    pypi_artifacts = [
        item for item in release.get("artifacts", []) if item["authority"] == "pypi"
    ]
    if pypi_artifacts:
        project = next(
            item["package_index_project"]
            for item in policy["targets"]
            if item["id"] == target
        )
        metadata_url = f"https://pypi.org/pypi/{project}/{release['version']}/json"
        remote[metadata_url] = json.dumps(
            {
                "info": {"version": release["version"]},
                "urls": [
                    {
                        "filename": item["name"],
                        "url": item["url"],
                        "size": item["size_bytes"],
                        "digests": {"sha256": item["sha256"].removeprefix("sha256:")},
                        "yanked": False,
                    }
                    for item in pypi_artifacts
                ],
            }
        ).encode()
    for artifact in release.get("artifacts", []):
        if artifact["authority"] != "managed_evidence":
            continue
        metadata_url = (
            "https://evidence.openadapt.ai/api/v1/objects/sha256/"
            + artifact["sha256"].removeprefix("sha256:")
        )
        remote[metadata_url] = json.dumps(
            {
                "schema_version": "openadapt.managed-artifact-head/v1",
                "exists": True,
                "artifact_url": artifact["url"],
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "object_version_sha256": "sha256:" + "a" * 64,
                "head_verified": True,
            }
        ).encode()
    return admissions, summary, remote


def empty_admissions() -> dict:
    return {
        "$schema": "schemas/production-lifecycle-admissions.schema.json",
        "schema_version": lifecycle.ADMISSIONS_SCHEMA,
        "policy_sha256": POLICY_DIGEST,
        "admissions": [],
    }


def replace_summary(admissions: dict, summary: dict, remote: dict[str, bytes]) -> None:
    summary_bytes = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
    reference = admissions["admissions"][-1]["acceptance_evidence"]
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


def replace_manifest(
    admissions: dict, summary: dict, remote: dict[str, bytes], manifest: dict
) -> None:
    old_url = summary["evidence_manifest"]["url"]
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode()
    manifest_digest = digest_bytes(manifest_bytes)
    manifest_url = (
        "https://evidence.openadapt.ai/objects/"
        + manifest_digest.removeprefix("sha256:")
        + "/manifest.json"
    )
    summary["evidence_manifest"]["url"] = manifest_url
    summary["evidence_manifest"]["sha256"] = manifest_digest
    remote[manifest_url] = manifest_bytes
    del remote[old_url]
    replace_summary(admissions, summary, remote)


def build_registry(admissions: dict, remote: dict[str, bytes]) -> dict | None:
    """Build a valid central evidence registry for the given admissions."""

    entries = []
    seen_references: set[tuple[str, str, str]] = set()
    prior: str | None = None
    sequence = 0
    for admission in admissions.get("admissions", []):
        reference = admission["acceptance_evidence"]
        for kind, url_key, digest_key in (
            ("evidence-summary", "summary_url", "summary_sha256"),
            ("attestation-bundle", "attestation_bundle_url", "attestation_bundle_sha256"),
        ):
            identity = (kind, reference[url_key], reference[digest_key])
            if identity in seen_references:
                continue
            seen_references.add(identity)
            sequence += 1
            entry = legacy_build_entry(
                sequence=sequence,
                kind=kind,
                url=reference[url_key],
                sha256=reference[digest_key],
                # Fixture tolerance: some cases reference URLs that are
                # deliberately absent from the synthetic remote map.
                size_bytes=len(remote.get(reference[url_key], b"")) or 1,
                recorded_at="2026-08-18T10:00:00.000Z",
                prior_entry_sha256=prior,
            )
            prior = entry["entry_sha256"]
            entries.append(entry)
    if not entries:
        return None
    return {
        "$schema": "schemas/evidence-registry.schema.json",
        "schema_version": "openadapt.production-evidence-registry/v1",
        "head_entry_sha256": prior,
        "entries": entries,
    }


def validate_case(
    admissions: dict,
    remote: dict[str, bytes] | None = None,
    repositories: list[str] | None = None,
    surfaces: list[str] | None = None,
    attestation_valid: bool = True,
    registry: dict | None = None,
) -> dict[str, str]:
    attestation_calls: list[tuple[bytes, bytes]] = []

    def fetch(url: str) -> bytes:
        assert remote is not None
        try:
            return remote[url]
        except KeyError as exc:
            raise OSError(f"synthetic URL is absent: {url}") from exc

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

    with mock.patch.object(
        lifecycle, "evidence_registry", legacy_registry_adapter()
    ):
        result = lifecycle.validate(
            load_policy(),
            admissions,
            repository_lifecycle,
            surface_lifecycle,
            policy_sha256=POLICY_DIGEST,
            now=NOW,
            fetch=fetch,
            verify_attestation=verify,
            registry_value=(
                registry
                if registry is not None
                else build_registry(admissions, remote or {})
            ),
        )
    return result


class ProductionLifecycleTests(unittest.TestCase):
    def test_current_registry_has_no_production_admissions(self) -> None:
        self.assertEqual(validate_case(empty_admissions()), {})

    def test_valid_exact_public_package_admission(self) -> None:
        admissions, _summary, remote = build_case()
        self.assertEqual(
            validate_case(admissions, remote),
            {"flow": "production:flow:1"},
        )

    def test_private_cloud_uses_opaque_release_without_public_url(self) -> None:
        admissions, _summary, remote = build_case("cloud", cloud_release())
        self.assertEqual(
            validate_case(admissions, remote),
            {"cloud": "production:cloud:1"},
        )
        serialized = json.dumps(admissions["admissions"][0]["release"])
        self.assertNotIn("url", serialized.lower())

    def test_valid_exact_docs_deployment_admission(self) -> None:
        admissions, _summary, remote = build_case("docs", docs_release())
        self.assertEqual(
            validate_case(admissions, remote),
            {"docs": "production:docs:1"},
        )

    def test_registry_membership_without_admission_is_refused(self) -> None:
        with self.assertRaisesRegex(lifecycle.LifecycleError, "static Production"):
            validate_case(empty_admissions(), repositories=["openadapt-flow"])

    def test_static_repository_lifecycle_for_target_is_refused(self) -> None:
        repositories, surfaces = lifecycle.load_lifecycle()
        repositories = copy.deepcopy(repositories)
        repositories["beta"].append("openadapt-flow")
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "static lifecycle membership"
        ):
            lifecycle.validate(
                load_policy(),
                empty_admissions(),
                repositories,
                surfaces,
                policy_sha256=POLICY_DIGEST,
                now=NOW,
            )

    def test_static_public_surface_lifecycle_for_target_is_refused(self) -> None:
        repositories, surfaces = lifecycle.load_lifecycle()
        surfaces = copy.deepcopy(surfaces)
        surfaces["beta"].append("docs.openadapt.ai")
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "static lifecycle membership"
        ):
            lifecycle.validate(
                load_policy(),
                empty_admissions(),
                repositories,
                surfaces,
                policy_sha256=POLICY_DIGEST,
                now=NOW,
            )

    def test_current_public_support_repositories_remain_classified(self) -> None:
        repositories, _surfaces = lifecycle.load_lifecycle()
        self.assertGreaterEqual(
            set(repositories["support"]),
            {".github", "openadapt-web", "openadapt-ops", "openadapt-blog"},
        )

    def test_admission_derives_production_without_static_membership(self) -> None:
        admissions, _summary, remote = build_case()
        self.assertEqual(
            validate_case(admissions, remote), {"flow": "production:flow:1"}
        )

    def test_policy_digest_mismatch_is_refused(self) -> None:
        admissions = empty_admissions()
        admissions["policy_sha256"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(lifecycle.LifecycleError, "policy digest differs"):
            validate_case(admissions)

    def test_expired_latest_admission_removes_derived_production(self) -> None:
        admissions, _summary, remote = build_case(
            issued_at="2026-08-17T11:00:00Z",
            expires_at="2026-08-18T11:59:59Z",
        )
        self.assertEqual(validate_case(admissions, remote), {})

    def test_revoked_latest_admission_removes_derived_production(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["revoked_at"] = "2026-08-18T11:30:00Z"
        self.assertEqual(validate_case(admissions, remote), {})

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

    def test_rejected_evidence_manifest_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["verdict"] = "rejected"
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "verdict differs"):
            validate_case(admissions, remote)

    def test_incomplete_failure_taxonomy_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["failure_taxonomy_counts"]["verified"] = 0
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "every trial"):
            validate_case(admissions, remote)

    def test_governed_repair_model_calls_remain_informational(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["reliability"]["model_call_count"] = 2
        replace_manifest(admissions, summary, remote, manifest)
        self.assertEqual(
            validate_case(admissions, remote), {"flow": "production:flow:1"}
        )

    def test_healthy_path_model_call_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["failure_taxonomy_counts"]["healthy_path_model_call"] = 1
        manifest["failure_taxonomy_counts"]["verified"] = 2
        manifest["reliability"]["model_call_count"] = 1
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "Production failure"):
            validate_case(admissions, remote)

    def test_future_retention_verification_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["retention"]["acceptance_verified_at"] = "2026-08-19T09:59:59.000Z"
        manifest["retention"]["retained_at"] = "2026-08-19T10:00:00.000Z"
        manifest["retention"]["retention_until"] = "2027-08-19T10:00:00.000Z"
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(lifecycle.LifecycleError, "in the future"):
            validate_case(admissions, remote)

    def test_whole_second_retention_timestamp_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["retention"]["retained_at"] = "2026-08-18T10:00:00Z"
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "retained time must be a millisecond UTC"
        ):
            validate_case(admissions, remote)

    def test_offset_retention_timestamp_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["retention"]["retention_until"] = "2027-08-18T10:00:00.000+00:00"
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "retention end must be a millisecond UTC"
        ):
            validate_case(admissions, remote)

    def test_observed_trials_below_condition_minimum_are_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["qualification"]["minimum_trials_per_condition"] = 4
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "observed trial total is too small"
        ):
            validate_case(admissions, remote)

    def test_required_trials_below_policy_floor_are_refused(self) -> None:
        admissions, summary, remote = build_case()
        manifest = json.loads(remote[summary["evidence_manifest"]["url"]])
        manifest["qualification"]["condition_count"] = 2
        replace_manifest(admissions, summary, remote, manifest)
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "required trial total is too small"
        ):
            validate_case(admissions, remote)

    def test_evidence_manifest_schema_mismatch_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        summary["evidence_manifest"]["schema_version"] = "unbound/v1"
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
            lifecycle.LifecycleError, "evidence manifest schema is not supported"
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

    def test_private_identity_target_binding_mismatch_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        summary["private_certificate_binding"]["target"] = "cloud"
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
            lifecycle.LifecycleError, "private evidence target"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_private_identity_release_binding_mismatch_is_refused(self) -> None:
        admissions, summary, remote = build_case()
        summary["private_certificate_binding"]["target_release_sha256"] = (
            "sha256:" + "f" * 64
        )
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
            lifecycle.LifecycleError, "private release binding"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_target_claim_scope_mismatch_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["claim_scope"] = "qualified_native_recorder_release"
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "claim scope differs from policy"
        ):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_signer_provenance_domain_mismatch_is_refused(self) -> None:
        policy = load_policy()
        policy["summary_authority"]["signer_provenance_digest_domain"] = (
            "OpenAdapt production certificate signer provenance v2\0"
        )
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "signer provenance digest domain"
        ):
            lifecycle.validate(
                policy,
                empty_admissions(),
                *lifecycle.load_lifecycle(),
                policy_sha256=POLICY_DIGEST,
                now=NOW,
            )

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

    def test_artifact_url_outside_pinned_authority_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        admissions["admissions"][0]["release"]["artifacts"][0]["url"] = (
            "https://downloads.example.test/" + SOURCE_COMMIT + "/artifact.tar.gz"
        )
        with self.assertRaisesRegex(lifecycle.LifecycleError, "not a PyPI artifact"):
            validate_case(admissions, remote, repositories=["openadapt-flow"])

    def test_pypi_metadata_digest_mismatch_is_refused(self) -> None:
        admissions, _summary, remote = build_case()
        metadata_url = "https://pypi.org/pypi/openadapt-flow/2.0.0/json"
        metadata = json.loads(remote[metadata_url])
        metadata["urls"][0]["digests"]["sha256"] = "0" * 64
        remote[metadata_url] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(lifecycle.LifecycleError, "PyPI does not verify"):
            validate_case(admissions, remote)

    def test_missing_managed_evidence_metadata_is_refused(self) -> None:
        admissions, _summary, remote = build_case("docs", docs_release())
        metadata_url = "https://evidence.openadapt.ai/api/v1/objects/sha256/" + "8" * 64
        del remote[metadata_url]
        with self.assertRaisesRegex(
            lifecycle.LifecycleError, "managed evidence object metadata"
        ):
            validate_case(admissions, remote)

    def test_monotonic_latest_release_is_derived(self) -> None:
        first, _first_summary, first_remote = build_case(
            issued_at="2026-08-17T10:00:00Z"
        )
        predecessor = lifecycle._canonical_digest(first["admissions"][0])
        second, _second_summary, second_remote = build_case(
            release=next_flow_release(),
            release_sequence=2,
            previous_admission_sha256=predecessor,
            issued_at="2026-08-18T11:00:00Z",
        )
        first["admissions"].extend(second["admissions"])
        first_remote.update(second_remote)
        self.assertEqual(
            validate_case(first, first_remote), {"flow": "production:flow:2"}
        )

    def test_expired_latest_release_does_not_fall_back(self) -> None:
        first, _first_summary, first_remote = build_case(
            issued_at="2026-08-17T10:00:00Z"
        )
        predecessor = lifecycle._canonical_digest(first["admissions"][0])
        second, _second_summary, second_remote = build_case(
            release=next_flow_release(),
            release_sequence=2,
            previous_admission_sha256=predecessor,
            issued_at="2026-08-17T11:00:00Z",
            expires_at="2026-08-18T11:59:59Z",
        )
        first["admissions"].extend(second["admissions"])
        first_remote.update(second_remote)
        self.assertEqual(validate_case(first, first_remote), {})

    def test_release_chain_truncation_is_refused_by_history_gate(self) -> None:
        first, _summary, _remote = build_case()
        predecessor = lifecycle._canonical_digest(first["admissions"][0])
        second, _summary, _remote = build_case(
            release=next_flow_release(),
            release_sequence=2,
            previous_admission_sha256=predecessor,
            issued_at="2026-08-18T11:30:00Z",
        )
        previous = copy.deepcopy(first)
        previous["admissions"].extend(second["admissions"])
        with self.assertRaisesRegex(lifecycle.LifecycleError, "cannot remove"):
            lifecycle.validate_append_only_history(previous, first)

    def test_history_gate_allows_one_way_revocation_per_target(self) -> None:
        flow, _summary, _remote = build_case()
        docs, _summary, _remote = build_case("docs", docs_release())
        previous = copy.deepcopy(flow)
        previous["admissions"].extend(docs["admissions"])
        current = copy.deepcopy(previous)
        current["admissions"][0]["revoked_at"] = "2026-08-18T11:30:00Z"
        lifecycle.validate_append_only_history(previous, current)

    def test_history_gate_refuses_revocation_rollback(self) -> None:
        previous, _summary, _remote = build_case()
        previous["admissions"][0]["revoked_at"] = "2026-08-18T11:30:00Z"
        current = copy.deepcopy(previous)
        current["admissions"][0]["revoked_at"] = None
        with self.assertRaisesRegex(lifecycle.LifecycleError, "only append"):
            lifecycle.validate_append_only_history(previous, current)

    def test_pinned_target_map_refuses_subject_substitution(self) -> None:
        policy = load_policy()
        next(item for item in policy["targets"] if item["id"] == "flow")[
            "lifecycle_subject"
        ] = "openadapt-evals"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "pinned target map"):
            lifecycle.validate(
                policy,
                empty_admissions(),
                *lifecycle.load_lifecycle(),
                policy_sha256=POLICY_DIGEST,
                now=NOW,
            )

    def test_pinned_attestation_authority_refuses_substitution(self) -> None:
        policy = load_policy()
        authority = policy["summary_authority"]
        authority["repository"] = "OpenAdaptAI/attacker"
        authority["certificate_identity"] = (
            "https://github.com/OpenAdaptAI/attacker/"
            + authority["workflow"]
            + "@refs/heads/main"
        )
        with self.assertRaisesRegex(lifecycle.LifecycleError, "pinned trust root"):
            lifecycle.validate(
                policy,
                empty_admissions(),
                *lifecycle.load_lifecycle(),
                policy_sha256=POLICY_DIGEST,
                now=NOW,
            )

    def test_schema_files_are_valid_json(self) -> None:
        for path in sorted((ROOT / "schemas").glob("production-lifecycle-*.json")):
            self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)


if __name__ == "__main__":
    unittest.main()
