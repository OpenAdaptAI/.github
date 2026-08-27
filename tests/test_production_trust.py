"""Fail-closed tests for release, workflow, and lifecycle trust contracts."""

from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import validate_evidence_registry as registry  # noqa: E402


def sha(character: str) -> str:
    return "sha256:" + character * 64


def reference(kind: str, object_character: str, *, subject: str | None = None) -> dict:
    schema, media = registry.OBJECT_KIND_CONTRACTS[kind]
    object_sha = sha(object_character)
    digest_hex = object_sha.removeprefix("sha256:")
    entry = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha,
        "size_bytes": 100,
        "object_media_type": media,
        "semantic_identity_sha256": sha("9"),
        "subject_sha256": subject,
    }
    return {
        "schema_version": registry.REFERENCE_SCHEMA,
        "repository": registry.REPOSITORY,
        "repository_id": registry.REPOSITORY_ID,
        "repository_owner_id": registry.REPOSITORY_OWNER_ID,
        "registry_source_commit": "a" * 40,
        "registry_revision": 3,
        "registry_head_sha256": sha("8"),
        "registry_entry_sha256": registry.entry_digest(entry),
        **entry,
    }


def pair(kind: str, regular_character: str, bundle_character: str) -> tuple[dict, dict]:
    regular = reference(kind, regular_character)
    bundle = reference(
        f"{kind}-sigstore-bundle",
        bundle_character,
        subject=regular["object_sha256"],
    )
    return regular, bundle


def campaign_summary() -> dict:
    result = {}
    for campaign_class in trust.CAMPAIGN_CLASSES:
        counts = {field: 0 for field in trust.CAMPAIGN_COUNT_FIELDS}
        counts.update(
            task_condition_cell_count=1,
            minimum_trials_per_cell=3,
            observed_trial_count=3,
        )
        if campaign_class == "uncertain_delivery":
            counts["reconciliation_required_count"] = 3
        if campaign_class == "declared_attended":
            counts["authenticated_bound_decision_count"] = 3
            counts["live_target_revalidation_count"] = 3
        if campaign_class == "governed_repair":
            for field in (
                "policy_approved_repair_count",
                "approved_repair_count",
                "retained_repair_evidence_count",
                "live_target_revalidation_count",
            ):
                counts[field] = 3
        result[campaign_class] = counts
    return result


def rulesets() -> list[dict]:
    common = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    }
    return [
        {
            **common,
            "name": "OpenAdapt policy: release tag creation",
            "role": "creation_authority",
            "ruleset_id": "10",
            "bypass_actors": [
                {
                    "actor_id": "4730708",
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ],
            "rules": [{"type": "creation"}],
        },
        {
            **common,
            "name": "OpenAdapt policy: immutable release tags",
            "role": "immutability",
            "ruleset_id": "11",
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                },
            ],
        },
    ]


def release_admission() -> dict:
    artifacts = [
        {
            "name": "openadapt-capture-extension-1.0.0.zip",
            "kind": "chrome-extension-zip",
            "sha256": sha("1"),
            "size_bytes": 4,
            "media_type": "application/zip",
            "publish_destinations": ["github-release"],
        },
        {
            "name": "openadapt_capture-1.0.0.tar.gz",
            "kind": "python-sdist",
            "sha256": sha("2"),
            "size_bytes": 4,
            "media_type": "application/gzip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": "openadapt_capture-1.0.0-py3-none-any.whl",
            "kind": "python-wheel",
            "sha256": sha("3"),
            "size_bytes": 4,
            "media_type": "application/zip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": "openadapt-capture-1.0.0.spdx.json",
            "kind": "spdx-sbom",
            "sha256": sha("4"),
            "size_bytes": 4,
            "media_type": "application/spdx+json",
            "publish_destinations": ["github-release"],
        },
    ]
    normalized_rulesets = rulesets()
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "draft_release_id": "20",
        "tag": "v1.0.0",
        "target_commitish": "b" * 40,
        "draft": True,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": [
            {
                "asset_id": str(30 + index),
                "name": artifact["name"],
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "kind": artifact["kind"],
                "media_type": artifact["media_type"],
                "publish_destinations": artifact["publish_destinations"],
                "uploader_id": "321543906",
                "uploader_login": "openadapt-release[bot]",
            }
            for index, artifact in enumerate(sorted(artifacts, key=lambda item: item["name"]))
        ],
        "immutable_releases": {"enabled": True, "enforced_by_owner": False},
        "immutable_releases_sha256": trust.digest_bytes(
            trust.IMMUTABLE_RELEASES_DOMAIN,
            {"enabled": True, "enforced_by_owner": False},
        ),
        "tag_rulesets": normalized_rulesets,
        "tag_rulesets_sha256": trust.digest_bytes(
            trust.TAG_RULESETS_DOMAIN, normalized_rulesets
        ),
        "tag_ref_state": {"ref": "refs/tags/v1.0.0", "exists": False},
        "tag_ref_state_sha256": trust.digest_bytes(
            trust.TAG_REF_STATE_DOMAIN,
            {"ref": "refs/tags/v1.0.0", "exists": False},
        ),
        "observed_at": "2026-08-27T12:00:00Z",
    }
    release = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-capture",
        "source_repository_id": "1115283835",
        "source_commit": "b" * 40,
        "version": "1.0.0",
        "tag": "v1.0.0",
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": artifacts,
    }
    summary, summary_bundle = pair("production-acceptance-summary", "2", "3")
    value = {
        "schema_version": "openadapt.qualification-release/v1",
        "admission_id_sha256": sha("0"),
        "target": "capture",
        "verdict": "accepted",
        "claim_scope": "production_capture",
        "release_identity": {
            "schema_version": "openadapt.monotonic-production-release/v1",
            "channel": "production",
            "sequence": 1,
            "previous_admission_sha256": None,
        },
        "release": release,
        "release_sha256": trust.digest_bytes(
            trust.RELEASE_DOMAIN,
            {
                "target": "capture",
                "claim_scope": "production_capture",
                "release": release,
            },
        ),
        "artifact_inventory_sha256": trust.digest_bytes(
            trust.ARTIFACT_INVENTORY_DOMAIN,
            {
                "target": "capture",
                "claim_scope": "production_capture",
                "artifacts": artifacts,
            },
        ),
        "publication_staging": staging,
        "publication_staging_sha256": trust.staging_digest(staging),
        "production_acceptance_summary_reference": summary,
        "production_acceptance_summary_bundle_reference": summary_bundle,
        "authority_state_sha256": sha("4"),
        "revocation_state_sha256": sha("5"),
        "signer_registry_sha256": sha("6"),
        "publication_policy_sha256": sha("7"),
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-09-03T12:00:00Z",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-release-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": "c" * 40,
            "environment": "production-release-admission",
        },
    }
    projection = dict(value)
    projection.pop("admission_id_sha256")
    value["admission_id_sha256"] = trust.digest_bytes(
        trust.RELEASE_ADMISSION_DOMAIN, projection
    )
    return value


def cloud_handoff() -> dict:
    authorization, authorization_bundle = pair(
        "production-cloud-deploy-authorization", "a", "b"
    )
    source_commit = "d" * 40
    source_commitment = "sha256:" + hashlib.sha256(
        trust.CLOUD_SOURCE_COMMIT_DOMAIN + source_commit.encode("ascii")
    ).hexdigest()
    request = {
        "schema_version": "openadapt.production-secret-source-proof-request/v2",
        "authorization_sha256": "1" * 64,
        "cloud_source_commit": source_commit,
        "expected_live_attestation_sha256": "2" * 64,
        "expires_at": "2026-08-27T12:05:00Z",
        "issued_at": "2026-08-27T12:00:00Z",
        "nonce": "A" * 43,
        "production_origin": "https://app.openadapt.ai",
        "profile_commit": "e" * 40,
        "profile_environment": "production-cloud-deploy",
        "profile_repository": "OpenAdaptAI/.github",
        "profile_workflow_ref": (
            "OpenAdaptAI/.github/.github/workflows/"
            "production-cloud-deploy.yml@refs/heads/main"
        ),
        "run_attempt": "1",
        "run_id": "100",
        "site_id": "ccf1a48a-d934-48ea-a9a8-36cbddf27cb5",
        "source_names": list(trust.CLOUD_LIVE_SOURCE_NAMES),
    }
    request_sha_raw = hashlib.sha256(
        trust.CLOUD_SOURCE_PROOF_REQUEST_DOMAIN + trust.canonical(request)
    ).hexdigest()
    request_sha = "sha256:" + request_sha_raw
    public_values = {trust.CLOUD_PUBLIC_SOURCE_NAME: "answer_v1"}
    response = {
        "schema_version": "openadapt.production-secret-source-proof-response/v2",
        "request_sha256": request_sha_raw,
        "authorization_sha256": request["authorization_sha256"],
        "live_attestation_sha256": "4" * 64,
        "live_deployment": {
            "build_id": sha("5"),
            "source_commit": source_commit,
        },
        "oidc_identity_sha256": "6" * 64,
        "production_origin": request["production_origin"],
        "proofs": {
            name: hashlib.sha256(name.encode("ascii")).hexdigest()
            for name in trust.CLOUD_SECRET_SOURCE_NAMES
        },
        "public_values": public_values,
        "site_id": request["site_id"],
    }
    provider_idempotency_key = "cloud-deploy:" + hashlib.sha256(
        trust.CLOUD_PROVIDER_IDEMPOTENCY_DOMAIN
        + trust.canonical(
            {
                "authorization_sha256": "sha256:" + request["authorization_sha256"],
                "source_proof_request_sha256": request_sha,
                "profile_run_id": request["run_id"],
                "profile_run_attempt": request["run_attempt"],
            }
        )
    ).hexdigest()
    value = {
        "schema_version": "openadapt.production-cloud-deployment-result/v1",
        "handoff_id_sha256": sha("0"),
        "authorization_reference": authorization,
        "authorization_bundle_reference": authorization_bundle,
        "authorization_sha256": "sha256:" + request["authorization_sha256"],
        "cloud_source_commitment_sha256": source_commitment,
        "profile_commit": request["profile_commit"],
        "profile_run_id": request["run_id"],
        "profile_run_attempt": request["run_attempt"],
        "source_proof_request": request,
        "source_proof_request_sha256": request_sha,
        "source_proof_response": response,
        "source_proof_response_sha256": "sha256:"
        + hashlib.sha256(trust.canonical(response)).hexdigest(),
        "reviewed_public_values_sha256": trust.digest_bytes(
            trust.CLOUD_PUBLIC_VALUES_DOMAIN, public_values
        ),
        "expected_live_attestation_sha256": "sha256:"
        + request["expected_live_attestation_sha256"],
        "live_attestation_sha256": "sha256:"
        + response["live_attestation_sha256"],
        "provider_idempotency_key": provider_idempotency_key,
        "audience": "openadapt-private-cloud-production-deploy",
        "signer_registry_sha256": sha("8"),
        "revocation_state_sha256": sha("9"),
        "verdict": "accepted",
        "issued_at": request["issued_at"],
        "not_before": request["issued_at"],
        "expires_at": request["expires_at"],
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/production-cloud-deploy.yml",
            "ref": "refs/heads/main",
            "source_commit": "f" * 40,
            "environment": "production-cloud-deploy",
        },
    }
    projection = dict(value)
    projection.pop("handoff_id_sha256")
    value["handoff_id_sha256"] = trust.digest_bytes(
        trust.CLOUD_HANDOFF_DOMAIN, projection
    )
    return value


def rotation_fixture() -> tuple[dict, dict, dict, dict]:
    signer_registry = {
        "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
        "revision": 4,
        "generated_at": "2026-08-27T11:00:00Z",
        "expires_at": "2026-08-27T14:00:00Z",
        "signers": [],
    }
    signer_raw = registry.canonical(signer_registry) + b"\n"
    signer_sha = "sha256:" + hashlib.sha256(signer_raw).hexdigest()
    signer_hex = signer_sha.removeprefix("sha256:")
    pointer = {
        "schema_version": registry.SIGNER_POINTER_SCHEMA,
        "object_path": (
            "production-evidence/signer-registries/sha256/"
            f"{signer_hex[:2]}/{signer_hex}.qualification-signer-registry.json"
        ),
        "object_sha256": signer_sha,
        "registry_identity_sha256": registry.signer_registry_identity_digest(
            signer_registry
        ),
        "registry_revision": 4,
    }
    common = {
        "registry_source_commit": "a" * 40,
        "registry_revision": 9,
        "registry_head_sha256": sha("2"),
        "signer_registry": pointer,
    }
    older = {
        **common,
        "checkpoint_id_sha256": sha("3"),
        "checkpoint_revision": 8,
        "previous_checkpoint_sha256": sha("4"),
        "generated_at": "2026-08-27T11:15:00Z",
        "not_before": "2026-08-27T11:30:00Z",
        "expires_at": "2026-08-27T12:30:00Z",
        "signature": "older-wrapper",
    }
    older_sha = "sha256:" + hashlib.sha256(
        trust.canonical(older) + b"\n"
    ).hexdigest()
    newer = {
        **common,
        "checkpoint_id_sha256": sha("5"),
        "checkpoint_revision": 9,
        "previous_checkpoint_sha256": older_sha,
        "generated_at": "2026-08-27T11:45:00Z",
        "not_before": "2026-08-27T12:30:00Z",
        "expires_at": "2026-08-27T13:30:00Z",
        "signature": "newer-wrapper",
    }

    def checkpoint_reference(checkpoint: dict) -> dict:
        return {
            "object_sha256": "sha256:" + hashlib.sha256(
                trust.canonical(checkpoint) + b"\n"
            ).hexdigest(),
            "semantic_identity_sha256": checkpoint["checkpoint_id_sha256"],
            "registry_source_commit": checkpoint["registry_source_commit"],
            "registry_revision": checkpoint["registry_revision"],
            "registry_head_sha256": checkpoint["registry_head_sha256"],
        }

    feed = {
        **common,
        "feed_revision": 12,
        "generated_at": "2026-08-27T12:00:00Z",
        "expires_at": "2026-08-27T13:00:00Z",
        "checkpoints": [
            {
                "checkpoint_reference": checkpoint_reference(newer),
                "checkpoint_bundle_reference": {},
            },
            {
                "checkpoint_reference": checkpoint_reference(older),
                "checkpoint_bundle_reference": {},
            },
        ],
    }
    return feed, newer, older, signer_registry


class ProductionTrustTests(unittest.TestCase):
    def test_feed_expiry_boundary_is_exclusive(self) -> None:
        checkpoint_reference, checkpoint_bundle_reference = pair(
            "production-lifecycle-checkpoint", "1", "2"
        )
        feed = {
            "schema_version": "openadapt.production-lifecycle-feed/v1",
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "ref": "refs/heads/production-lifecycle-feed",
            "feed_revision": 1,
            "generated_at": "2026-08-27T12:00:00Z",
            "expires_at": "2026-08-27T13:00:00Z",
            "registry_source_commit": "a" * 40,
            "registry_revision": 3,
            "registry_head_sha256": sha("8"),
            "signer_registry": {},
            "checkpoints": [
                {
                    "checkpoint_reference": checkpoint_reference,
                    "checkpoint_bundle_reference": checkpoint_bundle_reference,
                }
            ],
        }
        trust.validate_feed(
            feed,
            now=trust.require_timestamp("2026-08-27T12:59:59Z", "test time"),
        )
        with self.assertRaisesRegex(trust.TrustError, "not current"):
            trust.validate_feed(
                feed,
                now=trust.require_timestamp(
                    "2026-08-27T13:00:00Z", "test time"
                ),
            )

    def test_future_checkpoint_rotation_has_one_exact_boundary(self) -> None:
        feed, newer, older, signer_registry = rotation_fixture()
        with (
            mock.patch.object(trust, "validate_feed", return_value=feed),
            mock.patch.object(trust, "validate_checkpoint", side_effect=lambda item, **_: item),
            mock.patch.object(
                registry, "validate_signer_registry", return_value=signer_registry
            ),
        ):
            trust.validate_feed_expiry_containment(
                feed,
                checkpoints=[newer, older],
                signer_registry=signer_registry,
                now=trust.require_timestamp(
                    "2026-08-27T12:29:59Z", "test time"
                ),
            )
            trust.validate_feed_expiry_containment(
                feed,
                checkpoints=[newer, older],
                signer_registry=signer_registry,
                now=trust.require_timestamp(
                    "2026-08-27T12:30:00Z", "test time"
                ),
            )

    def test_checkpoint_rotation_refuses_overlap_gap_fork_and_reorder(self) -> None:
        for defect in ("overlap", "gap", "fork", "skip", "reorder"):
            with self.subTest(defect=defect):
                feed, newer, older, signer_registry = rotation_fixture()
                checkpoints = [newer, older]
                if defect == "overlap":
                    older["expires_at"] = "2026-08-27T12:30:01Z"
                elif defect == "gap":
                    older["expires_at"] = "2026-08-27T12:29:59Z"
                elif defect == "fork":
                    newer["previous_checkpoint_sha256"] = sha("6")
                elif defect == "skip":
                    newer["checkpoint_revision"] = 10
                else:
                    checkpoints.reverse()
                    feed["checkpoints"].reverse()
                for pair_value, checkpoint in zip(
                    feed["checkpoints"], checkpoints, strict=True
                ):
                    pair_value["checkpoint_reference"]["object_sha256"] = (
                        "sha256:" + hashlib.sha256(
                            trust.canonical(checkpoint) + b"\n"
                        ).hexdigest()
                    )
                with (
                    mock.patch.object(trust, "validate_feed", return_value=feed),
                    mock.patch.object(
                        trust,
                        "validate_checkpoint",
                        side_effect=lambda item, **_: item,
                    ),
                    mock.patch.object(
                        registry,
                        "validate_signer_registry",
                        return_value=signer_registry,
                    ),
                    self.assertRaises(trust.TrustError),
                ):
                    trust.validate_feed_expiry_containment(
                        feed,
                        checkpoints=checkpoints,
                        signer_registry=signer_registry,
                    )

    def test_checkpoint_reference_binds_the_exact_signed_wrapper(self) -> None:
        feed, newer, older, signer_registry = rotation_fixture()
        newer["signature"] = "alternate-wrapper"
        with (
            mock.patch.object(trust, "validate_feed", return_value=feed),
            mock.patch.object(trust, "validate_checkpoint", side_effect=lambda item, **_: item),
            mock.patch.object(
                registry, "validate_signer_registry", return_value=signer_registry
            ),
            self.assertRaisesRegex(trust.TrustError, "bytes differ"),
        ):
            trust.validate_feed_expiry_containment(
                feed,
                checkpoints=[newer, older],
                signer_registry=signer_registry,
            )

    def test_feed_transition_refuses_rollback_or_skipped_history(self) -> None:
        previous, newer, older, _ = rotation_fixture()
        previous["checkpoints"] = [previous["checkpoints"][1]]
        previous["feed_revision"] = 11
        previous["generated_at"] = "2026-08-27T11:50:00Z"
        current, _, _, _ = rotation_fixture()
        with mock.patch.object(trust, "validate_feed", side_effect=lambda item: item):
            trust.validate_feed_transition(previous, current)
            rollback = copy.deepcopy(current)
            rollback["checkpoints"] = [rollback["checkpoints"][1]]
            rollback["feed_revision"] = 13
            rollback["generated_at"] = "2026-08-27T12:10:00Z"
            with self.assertRaisesRegex(trust.TrustError, "skips or forks"):
                trust.validate_feed_transition(current, rollback)
            skipped_revision = copy.deepcopy(current)
            skipped_revision["feed_revision"] = 13
            with self.assertRaisesRegex(trust.TrustError, "revision"):
                trust.validate_feed_transition(previous, skipped_revision)

    def test_feed_expiry_cannot_outlive_checkpoint_or_signer_registry(self) -> None:
        signer_registry = {
            "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
            "revision": 4,
            "generated_at": "2026-08-27T11:00:00Z",
            "expires_at": "2026-08-27T13:00:00Z",
            "signers": [],
        }
        signer_raw = registry.canonical(signer_registry) + b"\n"
        signer_sha = "sha256:" + hashlib.sha256(signer_raw).hexdigest()
        signer_hex = signer_sha.removeprefix("sha256:")
        pointer = {
            "schema_version": registry.SIGNER_POINTER_SCHEMA,
            "object_path": (
                "production-evidence/signer-registries/sha256/"
                f"{signer_hex[:2]}/{signer_hex}.qualification-signer-registry.json"
            ),
            "object_sha256": signer_sha,
            "registry_identity_sha256": registry.signer_registry_identity_digest(
                signer_registry
            ),
            "registry_revision": 4,
        }
        checkpoint = {
            "checkpoint_id_sha256": sha("1"),
            "checkpoint_revision": 8,
            "previous_checkpoint_sha256": None,
            "registry_source_commit": "a" * 40,
            "registry_revision": 9,
            "registry_head_sha256": sha("2"),
            "signer_registry": pointer,
            "generated_at": "2026-08-27T11:15:00Z",
            "not_before": "2026-08-27T11:30:00Z",
            "expires_at": "2026-08-27T12:30:00Z",
        }
        checkpoint_sha = "sha256:" + hashlib.sha256(
            trust.canonical(checkpoint) + b"\n"
        ).hexdigest()
        feed = {
            "generated_at": "2026-08-27T12:00:00Z",
            "expires_at": "2026-08-27T12:30:00Z",
            "registry_source_commit": checkpoint["registry_source_commit"],
            "registry_revision": checkpoint["registry_revision"],
            "registry_head_sha256": checkpoint["registry_head_sha256"],
            "signer_registry": pointer,
            "checkpoints": [
                {
                    "checkpoint_reference": {
                        "object_sha256": checkpoint_sha,
                        "registry_source_commit": checkpoint[
                            "registry_source_commit"
                        ],
                        "registry_revision": checkpoint["registry_revision"],
                        "registry_head_sha256": checkpoint[
                            "registry_head_sha256"
                        ],
                    },
                    "checkpoint_bundle_reference": {},
                }
            ],
        }
        with (
            mock.patch.object(trust, "validate_feed", return_value=feed),
            mock.patch.object(
                trust, "validate_checkpoint", return_value=checkpoint
            ),
            mock.patch.object(
                registry, "validate_signer_registry", return_value=signer_registry
            ),
        ):
            trust.validate_feed_expiry_containment(
                feed, checkpoints=[checkpoint], signer_registry=signer_registry
            )
            feed["expires_at"] = "2026-08-27T12:30:01Z"
            with self.assertRaisesRegex(trust.TrustError, "checkpoint"):
                trust.validate_feed_expiry_containment(
                    feed,
                    checkpoints=[checkpoint],
                    signer_registry=signer_registry,
                )

    def test_cloud_handoff_binds_remote_safe_request_and_response(self) -> None:
        value = cloud_handoff()
        trust.validate_cloud_deployment_handoff(value)
        invalid = copy.deepcopy(value)
        invalid["source_proof_response"]["proofs"][
            "BUSINESS_DECISION_ANSWER_HMAC_KEY"
        ] = "a" * 64
        with self.assertRaisesRegex(trust.TrustError, "response digest"):
            trust.validate_cloud_deployment_handoff(invalid)

    def test_campaign_requires_reconciliation_without_replay(self) -> None:
        value = campaign_summary()
        trust.validate_campaign_summary(value)
        value["uncertain_delivery"]["replay_dispatch_count"] = 1
        with self.assertRaisesRegex(trust.TrustError, "replay"):
            trust.validate_campaign_summary(value)

    def test_release_binds_exact_draft_assets_and_two_rulesets(self) -> None:
        value = release_admission()
        trust.validate_release(value)
        invalid = copy.deepcopy(value)
        invalid["publication_staging"]["tag_rulesets"][1]["bypass_actors"] = [
            {
                "actor_id": "4730708",
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
        with self.assertRaisesRegex(trust.TrustError, "bypass"):
            trust.validate_release(invalid)

    def test_local_artifact_inventory_refuses_extra_file(self) -> None:
        value = release_admission()
        artifacts = value["release"]["artifacts"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for artifact in artifacts:
                path = root / artifact["name"]
                path.write_bytes(b"test")
                artifact["sha256"] = (
                    "sha256:" + hashlib.sha256(b"test").hexdigest()
                )
            trust.verify_local_artifacts(root, artifacts)
            (root / "SHA256SUMS").write_text("not admitted")
            with self.assertRaisesRegex(trust.TrustError, "extra"):
                trust.verify_local_artifacts(root, artifacts)

    def test_v2_reference_ids_are_strings_and_digests_are_prefixed(self) -> None:
        regular, bundle = pair("qualification-release", "4", "5")
        trust.validate_reference_pair(regular, bundle, kind="qualification-release")
        regular["repository_id"] = 858454062
        with self.assertRaisesRegex(trust.TrustError, "repository"):
            trust.validate_reference_pair(regular, bundle, kind="qualification-release")


if __name__ == "__main__":
    unittest.main()
