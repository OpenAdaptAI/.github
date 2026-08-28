"""Focused fail-closed tests for Support releases and publication recovery."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import validate_evidence_registry as registry  # noqa: E402


NOW = datetime(2026, 8, 27, 12, 4, 59, tzinfo=timezone.utc)


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def evidence_entry(
    kind: str,
    *,
    label: str,
    subject_sha256: str | None = None,
) -> dict:
    schema, media = registry.OBJECT_KIND_CONTRACTS[kind]
    object_sha256 = sha(f"object:{label}")
    digest_hex = object_sha256.removeprefix("sha256:")
    entry = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha256,
        "size_bytes": 100,
        "object_media_type": media,
        "semantic_identity_sha256": sha(f"identity:{label}"),
        "subject_sha256": subject_sha256,
    }
    entry["registry_entry_sha256"] = registry.entry_digest(entry)
    return entry


def evidence_reference(
    kind: str = "qualification-release",
    *,
    object_sha256: str | None = None,
    object_value: object | None = None,
) -> dict:
    entry = evidence_entry(kind, label=f"reference:{kind}")
    if object_sha256 is not None:
        entry["object_sha256"] = object_sha256
        digest_hex = object_sha256.removeprefix("sha256:")
        entry["object_path"] = (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        )
        if object_value is not None:
            entry["semantic_identity_sha256"] = registry.semantic_identity_digest(
                kind=kind,
                object_schema_version=entry["object_schema_version"],
                object_value=object_value,
                object_sha256=object_sha256,
            )
        entry["registry_entry_sha256"] = registry.entry_digest(entry)
    return {
        "schema_version": registry.REFERENCE_SCHEMA,
        "repository": registry.REPOSITORY,
        "repository_id": registry.REPOSITORY_ID,
        "repository_owner_id": registry.REPOSITORY_OWNER_ID,
        "registry_source_commit": "a" * 40,
        "registry_revision": 3,
        "registry_head_sha256": sha("registry-head"),
        **entry,
    }


def tag_rulesets(
    repository: str = "OpenAdaptAI/openadapt-tray",
    repository_id: str = "1136122737",
) -> list[dict]:
    common = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": repository,
        "repository_id": repository_id,
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    }
    return [
        {
            **common,
            "role": "creation_authority",
            "ruleset_id": "10",
            "name": "OpenAdapt policy: release tag creation",
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
            "role": "immutability",
            "ruleset_id": "11",
            "name": "OpenAdapt policy: immutable release tags",
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


def support_artifacts() -> list[dict]:
    return [
        {
            "name": "openadapt_tray-1.0.0.tar.gz",
            "kind": "python-sdist",
            "sha256": sha("tray-sdist"),
            "size_bytes": 101,
            "media_type": "application/gzip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": "openadapt_tray-1.0.0-py3-none-any.whl",
            "kind": "python-wheel",
            "sha256": sha("tray-wheel"),
            "size_bytes": 102,
            "media_type": "application/zip",
            "publish_destinations": ["github-release", "pypi"],
        },
    ]


def refresh_staging(staging: dict) -> None:
    staging["immutable_releases_sha256"] = trust.digest_bytes(
        trust.IMMUTABLE_RELEASES_DOMAIN, staging["immutable_releases"]
    )
    staging["tag_rulesets_sha256"] = trust.digest_bytes(
        trust.TAG_RULESETS_DOMAIN, staging["tag_rulesets"]
    )
    staging["tag_ref_state_sha256"] = trust.digest_bytes(
        trust.TAG_REF_STATE_DOMAIN, staging["tag_ref_state"]
    )


def refresh_support_admission(admission: dict) -> None:
    release = admission["release"]
    admission["release_sha256"] = trust.digest_bytes(
        trust.SUPPORT_RELEASE_DOMAIN,
        {
            "support_target": admission["support_target"],
            "claim_scope": admission["claim_scope"],
            "release": release,
        },
    )
    admission["artifact_inventory_sha256"] = trust.digest_bytes(
        trust.SUPPORT_ARTIFACT_INVENTORY_DOMAIN,
        {
            "support_target": admission["support_target"],
            "claim_scope": admission["claim_scope"],
            "artifacts": release["artifacts"],
        },
    )
    refresh_staging(admission["publication_staging"])
    admission["publication_staging_sha256"] = trust.staging_digest(
        admission["publication_staging"]
    )
    projection = dict(admission)
    projection.pop("admission_id_sha256", None)
    admission["admission_id_sha256"] = trust.digest_bytes(
        trust.SUPPORT_RELEASE_ADMISSION_DOMAIN, projection
    )


def support_admission() -> dict:
    artifacts = support_artifacts()
    staged_assets = [
        {
            "asset_id": str(30 + index),
            **artifact,
            "uploader_id": "321543906",
            "uploader_login": "openadapt-release[bot]",
        }
        for index, artifact in enumerate(
            sorted(artifacts, key=lambda item: item["name"])
        )
    ]
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "repository": "OpenAdaptAI/openadapt-tray",
        "repository_id": "1136122737",
        "draft_release_id": "20",
        "tag": "v1.0.0",
        "target_commitish": "b" * 40,
        "draft": True,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": staged_assets,
        "immutable_releases": {"enabled": True, "enforced_by_owner": False},
        "immutable_releases_sha256": sha("placeholder"),
        "tag_rulesets": tag_rulesets(),
        "tag_rulesets_sha256": sha("placeholder"),
        "tag_ref_state": {"ref": "refs/tags/v1.0.0", "exists": False},
        "tag_ref_state_sha256": sha("placeholder"),
        "observed_at": "2026-08-27T12:00:00Z",
    }
    release = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-tray",
        "source_repository_id": "1136122737",
        "source_commit": "b" * 40,
        "version": "1.0.0",
        "tag": "v1.0.0",
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": artifacts,
    }
    admission = {
        "schema_version": "openadapt.support-release-admission/v1",
        "admission_id_sha256": sha("placeholder"),
        "lifecycle_state": "Support",
        "support_target": "openadapt-tray",
        "verdict": "accepted",
        "claim_scope": "support_openadapt_tray",
        "release_identity": {
            "schema_version": "openadapt.monotonic-support-release/v1",
            "channel": "support",
            "sequence": 1,
            "previous_admission_sha256": None,
        },
        "release": release,
        "release_sha256": sha("placeholder"),
        "artifact_inventory_sha256": sha("placeholder"),
        "publication_staging": staging,
        "publication_staging_sha256": sha("placeholder"),
        "authority_state_sha256": sha("authority-current"),
        "revocation_state_sha256": sha("revocation-current"),
        "signer_registry_sha256": sha("signer-current"),
        "support_policy_sha256": trust.digest_bytes(
            trust.SUPPORT_POLICY_DOMAIN,
            json.loads((ROOT / "support-release-policy.json").read_text()),
        ),
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-09-03T12:00:00Z",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-support-release-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": "c" * 40,
            "environment": "support-release-admission",
        },
    }
    refresh_support_admission(admission)
    return admission


def refresh_recovery_authorization(authorization: dict) -> None:
    projection = {
        "qualification_release_object_sha256": authorization[
            "qualification_release_object_sha256"
        ],
        "repository": authorization["repository"],
        "repository_id": authorization["repository_id"],
        "target": authorization["target"],
        "tag": authorization["tag"],
        "tag_ref": authorization["tag_ref"],
        "tag_object_id": authorization["tag_object_id"],
        "target_commit": authorization["target_commit"],
        "draft_release_id": authorization["draft_release_id"],
        "release_sha256": authorization["release_sha256"],
        "artifact_inventory_sha256": authorization["artifact_inventory_sha256"],
        "publication_staging_sha256": authorization["publication_staging_sha256"],
        "run_id": authorization["run_id"],
        "run_attempt": authorization["run_attempt"],
        "dispatcher_actor_id": authorization["dispatcher_actor_id"],
        "requested_effect": authorization["requested_effect"],
        "environment": authorization["environment"],
        "release_app": authorization["release_app"],
    }
    authorization["idempotency_key"] = "publication-recovery:" + hashlib.sha256(
        trust.PUBLICATION_RECOVERY_IDEMPOTENCY_DOMAIN + trust.canonical(projection)
    ).hexdigest()
    identity_projection = dict(authorization)
    identity_projection.pop("authorization_id_sha256", None)
    authorization["authorization_id_sha256"] = trust.digest_bytes(
        trust.PUBLICATION_RECOVERY_AUTHORIZATION_DOMAIN, identity_projection
    )


def recovery_authorization() -> dict:
    release_reference = evidence_reference()
    authorization = {
        "schema_version": (
            "openadapt.production-publication-recovery-authorization/v1"
        ),
        "authorization_id_sha256": sha("placeholder"),
        "qualification_release_reference": release_reference,
        "qualification_release_object_sha256": release_reference["object_sha256"],
        "release_sha256": sha("capture-release"),
        "artifact_inventory_sha256": sha("capture-inventory"),
        "publication_staging_sha256": sha("capture-staging"),
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "target": "capture",
        "tag": "v1.0.0",
        "tag_ref": "refs/tags/v1.0.0",
        "tag_object_id": "d" * 40,
        "target_commit": "b" * 40,
        "draft_release_id": "20",
        "requested_effect": "publish-github-release",
        "run_id": "100",
        "run_attempt": "1",
        "dispatcher_actor_id": "774615",
        "environment": "release-identity",
        "release_app": {
            "app_id": "4730708",
            "installation_id": "156835568",
            "bot_user_id": "321543906",
            "bot_login": "openadapt-release[bot]",
        },
        "idempotency_key": "publication-recovery:" + "0" * 64,
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-08-27T12:05:00Z",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-production-publication-recovery.yml"
            ),
            "ref": "refs/heads/main",
            "source_commit": "c" * 40,
            "environment": "release-identity",
        },
    }
    refresh_recovery_authorization(authorization)
    return authorization


class SupportReleaseAdmissionTests(unittest.TestCase):
    def test_exact_tray_wheel_and_sdist_app_staged_draft_is_valid(self) -> None:
        value = support_admission()
        self.assertEqual(trust.validate_support_release(value, now=NOW), value)
        self.assertEqual(
            [item["kind"] for item in value["release"]["artifacts"]],
            ["python-sdist", "python-wheel"],
        )
        self.assertTrue(value["publication_staging"]["draft"])
        self.assertEqual(
            {
                item["uploader_login"]
                for item in value["publication_staging"]["assets"]
            },
            {"openadapt-release[bot]"},
        )

    def test_support_is_not_an_eighth_production_target(self) -> None:
        self.assertNotIn("openadapt-tray", trust.TARGETS)
        value = support_admission()
        value.pop("lifecycle_state")
        value.pop("support_target")
        value["schema_version"] = "openadapt.qualification-release/v1"
        value["evidence_class"] = "remote-safe-synthetic"
        value["target"] = "openadapt-tray"
        value["production_acceptance_summary_reference"] = evidence_reference(
            "production-acceptance-summary"
        )
        summary_bundle = evidence_reference(
            "production-acceptance-summary-sigstore-bundle"
        )
        summary_bundle["subject_sha256"] = value[
            "production_acceptance_summary_reference"
        ]["object_sha256"]
        projection = {
            field: summary_bundle[field] for field in registry.ENTRY_FIELDS
        }
        summary_bundle["registry_entry_sha256"] = registry.entry_digest(projection)
        value["production_acceptance_summary_bundle_reference"] = summary_bundle
        value["publication_policy_sha256"] = value.pop("support_policy_sha256")
        with self.assertRaisesRegex(trust.TrustError, "target is invalid"):
            trust.validate_release(value)

    def test_missing_extra_and_cross_profile_artifacts_are_refused(self) -> None:
        cases: list[tuple[str, object]] = [
            (
                "missing wheel",
                lambda value: value["release"]["artifacts"].pop(),
            ),
            (
                "extra wheel",
                lambda value: value["release"]["artifacts"].append(
                    {
                        "name": "extra.whl",
                        "kind": "python-wheel",
                        "sha256": sha("extra"),
                        "size_bytes": 1,
                        "media_type": "application/zip",
                        "publish_destinations": ["github-release", "pypi"],
                    }
                ),
            ),
            (
                "wheel media",
                lambda value: value["release"]["artifacts"][1].__setitem__(
                    "media_type", "application/gzip"
                ),
            ),
            (
                "sdist destination",
                lambda value: value["release"]["artifacts"][0].__setitem__(
                    "publish_destinations", ["github-release"]
                ),
            ),
            (
                "foreign kind",
                lambda value: value["release"]["artifacts"][0].__setitem__(
                    "kind", "spdx-sbom"
                ),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = support_admission()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_support_release(value)

    def test_staged_inventory_must_exactly_match_admitted_inventory(self) -> None:
        value = support_admission()
        value["publication_staging"]["assets"][0]["sha256"] = sha(
            "other-staged-bytes"
        )
        refresh_support_admission(value)
        with self.assertRaisesRegex(trust.TrustError, "staged assets differ"):
            trust.validate_support_release(value)

    def test_wrong_app_ruleset_tag_and_staging_state_are_refused(self) -> None:
        cases: list[tuple[str, object]] = [
            (
                "release App",
                lambda value: value["publication_staging"].__setitem__(
                    "release_app_id", "1"
                ),
            ),
            (
                "asset uploader",
                lambda value: value["publication_staging"]["assets"][0].__setitem__(
                    "uploader_id", "1"
                ),
            ),
            (
                "creation ruleset",
                lambda value: value["publication_staging"]["tag_rulesets"][0][
                    "bypass_actors"
                ][0].__setitem__("actor_id", "1"),
            ),
            (
                "immutability ruleset",
                lambda value: value["publication_staging"]["tag_rulesets"][1][
                    "rules"
                ].pop(),
            ),
            (
                "existing tag",
                lambda value: value["publication_staging"]["tag_ref_state"].__setitem__(
                    "exists", True
                ),
            ),
            (
                "immutable releases disabled",
                lambda value: value["publication_staging"][
                    "immutable_releases"
                ].__setitem__("enabled", False),
            ),
            (
                "not a draft",
                lambda value: value["publication_staging"].__setitem__(
                    "draft", False
                ),
            ),
            (
                "prerelease",
                lambda value: value["publication_staging"].__setitem__(
                    "prerelease", True
                ),
            ),
            (
                "wrong repository",
                lambda value: value["publication_staging"].__setitem__(
                    "repository", "OpenAdaptAI/openadapt-flow"
                ),
            ),
            (
                "wrong target commit",
                lambda value: value["publication_staging"].__setitem__(
                    "target_commitish", "d" * 40
                ),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = support_admission()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_support_release(value)

    def test_window_is_half_open_and_limited_to_seven_days(self) -> None:
        value = support_admission()
        trust.validate_support_release(
            value,
            now=datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(trust.TrustError, "not active"):
            trust.validate_support_release(
                value,
                now=datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc),
            )
        value["expires_at"] = "2026-09-03T12:00:01Z"
        refresh_support_admission(value)
        with self.assertRaisesRegex(trust.TrustError, "validity window"):
            trust.validate_support_release(value)

    def test_signer_and_revocation_digests_are_admission_identity_bound(self) -> None:
        for field in (
            "authority_state_sha256",
            "revocation_state_sha256",
            "signer_registry_sha256",
        ):
            with self.subTest(field=field):
                value = support_admission()
                value[field] = sha(f"changed:{field}")
                with self.assertRaisesRegex(trust.TrustError, "admission id"):
                    trust.validate_support_release(value)

    def test_support_release_requires_exact_current_trust_state(self) -> None:
        value = support_admission()
        signer_registry = {
            "schema_version": "test-signer-registry",
            "revision": 7,
            "signers": [
                {
                    "status": "active",
                    "public_key_sha256": sha("current-signer-key"),
                }
            ],
        }
        signer_identity = registry.signer_registry_identity_digest(signer_registry)
        signer_raw_sha = "sha256:" + hashlib.sha256(
            registry.canonical(signer_registry) + b"\n"
        ).hexdigest()
        authority = {
            "authority_state_sha256": sha("current-authority"),
            "signer_registry_sha256": signer_raw_sha,
            "signer_registry_identity_sha256": signer_identity,
            "signer_registry_revision": 7,
        }
        revocation = {
            "revocation_state_sha256": sha("current-revocation"),
            "authority_state_sha256": authority["authority_state_sha256"],
            "signer_registry_sha256": signer_identity,
            "revocations": [],
        }
        value["authority_state_sha256"] = authority["authority_state_sha256"]
        value["revocation_state_sha256"] = revocation[
            "revocation_state_sha256"
        ]
        value["signer_registry_sha256"] = signer_identity
        refresh_support_admission(value)
        object_sha256 = "sha256:" + hashlib.sha256(
            trust.canonical(value) + b"\n"
        ).hexdigest()
        admission_reference = evidence_reference(
            "support-release-admission",
            object_sha256=object_sha256,
            object_value=value,
        )
        patches = (
            mock.patch.object(
                registry, "validate_signer_registry", return_value=signer_registry
            ),
            mock.patch.object(
                trust, "validate_authority_state", return_value=authority
            ),
            mock.patch.object(
                trust, "validate_revocation_state", return_value=revocation
            ),
            mock.patch.object(trust, "verify_embedded_signature"),
        )
        with patches[0], patches[1], patches[2], patches[3]:
            self.assertEqual(
                trust.validate_admission_current_state(
                    value,
                    admission_reference=admission_reference,
                    authority_state=authority,
                    revocation_state=revocation,
                    signer_registry=signer_registry,
                    now=NOW,
                ),
                value,
            )
            for field in (
                "authority_state_sha256",
                "revocation_state_sha256",
                "signer_registry_sha256",
            ):
                with self.subTest(field=field):
                    changed = copy.deepcopy(value)
                    changed[field] = sha(f"not-current:{field}")
                    refresh_support_admission(changed)
                    changed_sha = "sha256:" + hashlib.sha256(
                        trust.canonical(changed) + b"\n"
                    ).hexdigest()
                    changed_reference = evidence_reference(
                        "support-release-admission",
                        object_sha256=changed_sha,
                        object_value=changed,
                    )
                    with self.assertRaisesRegex(trust.TrustError, "current"):
                        trust.validate_admission_current_state(
                            changed,
                            admission_reference=changed_reference,
                            authority_state=authority,
                            revocation_state=revocation,
                            signer_registry=signer_registry,
                            now=NOW,
                        )

            changed_identity_reference = copy.deepcopy(admission_reference)
            changed_identity_reference["semantic_identity_sha256"] = sha(
                "unbound-admission-identity"
            )
            projection = {
                field: changed_identity_reference[field]
                for field in registry.ENTRY_FIELDS
            }
            changed_identity_reference["registry_entry_sha256"] = (
                registry.entry_digest(projection)
            )
            with self.assertRaisesRegex(
                trust.TrustError, "semantic identity|reference differs"
            ):
                trust.validate_admission_current_state(
                    value,
                    admission_reference=changed_identity_reference,
                    authority_state=authority,
                    revocation_state=revocation,
                    signer_registry=signer_registry,
                    now=NOW,
                )

            revocation["revocations"] = [
                {
                    "subject_kind": "support-release-admission",
                    "subject_id": admission_reference[
                        "semantic_identity_sha256"
                    ],
                }
            ]
            with self.assertRaisesRegex(trust.TrustError, "admission is revoked"):
                trust.validate_admission_current_state(
                    value,
                    admission_reference=admission_reference,
                    authority_state=authority,
                    revocation_state=revocation,
                    signer_registry=signer_registry,
                    now=NOW,
                )
            revocation["revocations"] = [
                {
                    "subject_kind": "qualification-signer-key",
                    "subject_id": signer_registry["signers"][0][
                        "public_key_sha256"
                    ],
                }
            ]
            with self.assertRaisesRegex(trust.TrustError, "signer key is revoked"):
                trust.validate_admission_current_state(
                    value,
                    admission_reference=admission_reference,
                    authority_state=authority,
                    revocation_state=revocation,
                    signer_registry=signer_registry,
                    now=NOW,
                )

    def test_support_release_refuses_stale_staging_observation(self) -> None:
        boundary = support_admission()
        boundary["publication_staging"]["observed_at"] = "2026-08-27T11:00:00Z"
        refresh_support_admission(boundary)
        trust.validate_support_release(boundary, now=NOW)

        for observed_at in (
            "2026-08-27T10:59:59Z",
            "2026-08-27T12:00:01Z",
        ):
            with self.subTest(observed_at=observed_at):
                value = support_admission()
                value["publication_staging"]["observed_at"] = observed_at
                refresh_support_admission(value)
                with self.assertRaisesRegex(
                    trust.TrustError, "staging observation.*stale"
                ):
                    trust.validate_support_release(value, now=NOW)


class PublicationRecoveryAuthorizationTests(unittest.TestCase):
    def test_exact_five_minute_single_attempt_authorization_is_valid(self) -> None:
        value = recovery_authorization()
        self.assertEqual(
            trust.validate_publication_recovery_authorization(value, now=NOW),
            value,
        )

    def test_five_minute_window_is_half_open_and_cannot_be_longer(self) -> None:
        value = recovery_authorization()
        with self.assertRaisesRegex(trust.TrustError, "not active"):
            trust.validate_publication_recovery_authorization(
                value,
                now=datetime(2026, 8, 27, 12, 5, 0, tzinfo=timezone.utc),
            )
        value["expires_at"] = "2026-08-27T12:05:01Z"
        refresh_recovery_authorization(value)
        with self.assertRaisesRegex(trust.TrustError, "validity window"):
            trust.validate_publication_recovery_authorization(value)

    def test_attempt_dispatcher_environment_and_issuer_are_exact(self) -> None:
        cases: list[tuple[str, object]] = [
            ("attempt", lambda value: value.__setitem__("run_attempt", "2")),
            (
                "dispatcher",
                lambda value: value.__setitem__("dispatcher_actor_id", "1"),
            ),
            (
                "environment",
                lambda value: value.__setitem__("environment", "pypi"),
            ),
            (
                "issuer workflow",
                lambda value: value["issuer"].__setitem__(
                    "workflow", ".github/workflows/release.yml"
                ),
            ),
            (
                "issuer environment",
                lambda value: value["issuer"].__setitem__("environment", "pypi"),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = recovery_authorization()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_publication_recovery_authorization(value)

    def test_release_app_identity_is_exact(self) -> None:
        for field in ("app_id", "installation_id", "bot_user_id", "bot_login"):
            with self.subTest(field=field):
                value = recovery_authorization()
                value["release_app"][field] = "1"
                with self.assertRaisesRegex(trust.TrustError, "release App"):
                    trust.validate_publication_recovery_authorization(value)

    def test_repository_target_and_release_reference_profiles_are_exact(self) -> None:
        cases: list[tuple[str, object]] = [
            (
                "repository",
                lambda value: value.__setitem__(
                    "repository", "OpenAdaptAI/openadapt-flow"
                ),
            ),
            (
                "repository id",
                lambda value: value.__setitem__("repository_id", "1"),
            ),
            ("deployment target", lambda value: value.__setitem__("target", "cloud")),
            (
                "reference kind",
                lambda value: value.__setitem__(
                    "qualification_release_reference",
                    evidence_reference("support-release-admission"),
                ),
            ),
            (
                "reference object",
                lambda value: value.__setitem__(
                    "qualification_release_object_sha256", sha("other-release")
                ),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = recovery_authorization()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_publication_recovery_authorization(value)

    def test_tag_and_staging_bindings_are_closed(self) -> None:
        cases: list[tuple[str, object]] = [
            ("tag", lambda value: value.__setitem__("tag", "1.0.0")),
            (
                "tag ref",
                lambda value: value.__setitem__("tag_ref", "refs/tags/v2.0.0"),
            ),
            (
                "tag object",
                lambda value: value.__setitem__("tag_object_id", "main"),
            ),
            (
                "target commit",
                lambda value: value.__setitem__("target_commit", "main"),
            ),
            (
                "draft release",
                lambda value: value.__setitem__("draft_release_id", "0"),
            ),
            (
                "staging digest",
                lambda value: value.__setitem__(
                    "publication_staging_sha256", "not-a-digest"
                ),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = recovery_authorization()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_publication_recovery_authorization(value)

        malformed = recovery_authorization()
        malformed["tag"] = "vbad/path"
        malformed["tag_ref"] = "refs/tags/vbad/path"
        refresh_recovery_authorization(malformed)
        with self.assertRaisesRegex(trust.TrustError, "tag"):
            trust.validate_publication_recovery_authorization(malformed)

    def test_effect_environment_and_idempotency_key_are_exact(self) -> None:
        cases: list[tuple[str, object]] = [
            ("empty", lambda value: value.__setitem__("requested_effect", "")),
            (
                "unknown",
                lambda value: value.__setitem__("requested_effect", "docker"),
            ),
            (
                "PyPI environment",
                lambda value: (
                    value.__setitem__("requested_effect", "publish-pypi"),
                    value.__setitem__("environment", "release-identity"),
                ),
            ),
            (
                "MCP environment",
                lambda value: (
                    value.__setitem__("target", "agent"),
                    value.__setitem__("repository", "OpenAdaptAI/openadapt-agent"),
                    value.__setitem__("repository_id", "1136136670"),
                    value.__setitem__("requested_effect", "publish-mcp-registry"),
                    value.__setitem__("environment", "release-identity"),
                ),
            ),
            (
                "idempotency mismatch",
                lambda value: value.__setitem__(
                    "idempotency_key", "publication-recovery:" + "0" * 64
                ),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                value = recovery_authorization()
                mutate(value)
                with self.assertRaises(trust.TrustError):
                    trust.validate_publication_recovery_authorization(value)

    def test_each_single_effect_has_one_exact_environment(self) -> None:
        profiles = {
            "stage-draft-assets": "release-identity",
            "publish-pypi": "pypi",
            "publish-github-release": "release-identity",
        }
        for effect, environment in profiles.items():
            with self.subTest(effect=effect):
                value = recovery_authorization()
                value["requested_effect"] = effect
                value["environment"] = environment
                value["issuer"]["environment"] = environment
                refresh_recovery_authorization(value)
                trust.validate_publication_recovery_authorization(value, now=NOW)

        agent = recovery_authorization()
        agent["target"] = "agent"
        agent["repository"] = "OpenAdaptAI/openadapt-agent"
        agent["repository_id"] = "1136136670"
        agent["requested_effect"] = "publish-mcp-registry"
        agent["environment"] = "mcp-registry"
        agent["issuer"]["environment"] = "mcp-registry"
        refresh_recovery_authorization(agent)
        trust.validate_publication_recovery_authorization(agent, now=NOW)

    def test_replay_key_binds_every_effect_critical_recovery_field(self) -> None:
        first = recovery_authorization()
        mutations: list[tuple[str, object]] = [
            ("target commit", lambda value: value.__setitem__("target_commit", "e" * 40)),
            ("draft", lambda value: value.__setitem__("draft_release_id", "21")),
            (
                "release",
                lambda value: value.__setitem__(
                    "release_sha256", sha("different-release")
                ),
            ),
            (
                "inventory",
                lambda value: value.__setitem__(
                    "artifact_inventory_sha256", sha("different-inventory")
                ),
            ),
            (
                "staging",
                lambda value: value.__setitem__(
                    "publication_staging_sha256", sha("different-staging")
                ),
            ),
            ("effect", lambda value: value.__setitem__("requested_effect", "stage-draft-assets")),
            ("App", lambda value: value["release_app"].__setitem__("installation_id", "1")),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                second = copy.deepcopy(first)
                mutate(second)
                refresh_recovery_authorization(second)
                self.assertNotEqual(first["idempotency_key"], second["idempotency_key"])

    def test_replay_accepts_exact_bytes_and_refuses_one_use_conflict(self) -> None:
        first = recovery_authorization()
        self.assertEqual(
            trust.validate_publication_recovery_replay(
                first, copy.deepcopy(first), now=NOW
            ),
            first,
        )
        conflict = copy.deepcopy(first)
        conflict["draft_release_id"] = "21"
        refresh_recovery_authorization(conflict)
        with self.assertRaisesRegex(trust.TrustError, "one-use claim conflicts"):
            trust.validate_publication_recovery_replay(first, conflict, now=NOW)

        next_tag = copy.deepcopy(first)
        next_tag["tag"] = "v1.0.1"
        next_tag["tag_ref"] = "refs/tags/v1.0.1"
        next_tag["tag_object_id"] = "e" * 40
        next_tag["target_commit"] = "e" * 40
        next_tag["draft_release_id"] = "21"
        next_tag["run_id"] = "101"
        refresh_recovery_authorization(next_tag)
        self.assertEqual(
            trust.validate_publication_recovery_replay(first, next_tag, now=NOW),
            next_tag,
        )

        with self.assertRaisesRegex(trust.TrustError, "not active"):
            trust.validate_publication_recovery_replay(
                first,
                copy.deepcopy(first),
                now=datetime(2026, 8, 27, 12, 5, 0, tzinfo=timezone.utc),
            )


class EvidenceKindProfileTests(unittest.TestCase):
    def registry_document(self, entries: list[dict]) -> dict:
        signer = {
            "schema_version": registry.SIGNER_POINTER_SCHEMA,
            "object_path": (
                "production-evidence/signer-registries/sha256/"
                + sha("signer-object").removeprefix("sha256:")[:2]
                + "/"
                + sha("signer-object").removeprefix("sha256:")
                + ".qualification-signer-registry.json"
            ),
            "object_sha256": sha("signer-object"),
            "registry_identity_sha256": sha("signer-identity"),
            "registry_revision": 1,
        }
        value = {
            "$schema": "schemas/evidence-registry.schema.json",
            "schema_version": registry.REGISTRY_SCHEMA,
            "repository": registry.REPOSITORY,
            "repository_id": registry.REPOSITORY_ID,
            "repository_owner_id": registry.REPOSITORY_OWNER_ID,
            "revision": 1,
            "previous_registry_head_sha256": None,
            "registry_head_sha256": sha("placeholder"),
            "signer_registry": signer,
            "signer_registry_history": [signer],
            "entries": entries,
        }
        value["registry_head_sha256"] = registry.registry_head_digest(value)
        return value

    def test_all_17_regular_kinds_have_adjacent_bound_bundle_profiles(self) -> None:
        entries: list[dict] = []
        for kind in registry.REGULAR_KIND_CONTRACTS:
            regular = evidence_entry(kind, label=f"regular:{kind}")
            bundle = evidence_entry(
                f"{kind}-sigstore-bundle",
                label=f"bundle:{kind}",
                subject_sha256=regular["object_sha256"],
            )
            entries.extend((regular, bundle))
        self.assertEqual(len(entries), 34)
        self.assertEqual(registry.validate_registry(self.registry_document(entries)), entries)

    def test_profile_and_adjacency_substitution_are_refused_for_every_kind(self) -> None:
        kinds = list(registry.REGULAR_KIND_CONTRACTS)
        for index, kind in enumerate(kinds):
            other_kind = kinds[(index + 1) % len(kinds)]
            with self.subTest(kind=kind, substitution="regular profile"):
                regular = evidence_entry(kind, label=f"regular:{kind}")
                regular["object_schema_version"], regular["object_media_type"] = (
                    registry.REGULAR_KIND_CONTRACTS[other_kind]
                )
                regular["registry_entry_sha256"] = registry.entry_digest(regular)
                bundle = evidence_entry(
                    f"{kind}-sigstore-bundle",
                    label=f"bundle:{kind}",
                    subject_sha256=regular["object_sha256"],
                )
                with self.assertRaisesRegex(
                    registry.EvidenceRegistryError, "schema or media type"
                ):
                    registry.validate_registry(self.registry_document([regular, bundle]))
            with self.subTest(kind=kind, substitution="bundle adjacency"):
                regular = evidence_entry(kind, label=f"regular:{kind}")
                substituted_bundle = evidence_entry(
                    f"{other_kind}-sigstore-bundle",
                    label=f"substitute:{kind}",
                    subject_sha256=regular["object_sha256"],
                )
                with self.assertRaisesRegex(
                    registry.EvidenceRegistryError, "immediately follow"
                ):
                    registry.validate_registry(
                        self.registry_document([regular, substituted_bundle])
                    )


if __name__ == "__main__":
    unittest.main()
