"""Structural tests for the public Production trust JSON schemas."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"


EXPECTED_TOP_LEVEL_FIELDS = {
    "production-public-trust-signing-statement.schema.json": {
        "schema_version",
        "object_kind",
        "object_schema_version",
        "object_media_type",
        "object_sha256",
        "object_size_bytes",
        "semantic_identity_sha256",
        "source_issuer",
        "signer_registry_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "request_id_sha256",
        "signing_authority",
        "key_id",
        "signature_profile",
    },
    "production-public-trust-dsse-bundle.schema.json": {
        "mediaType",
        "verificationMaterial",
        "dsseEnvelope",
    },
    "qualification-worker-admission.schema.json": {
        "schema_version",
        "admission_id_sha256",
        "provider_identity_sha256",
        "worker_identity_sha256",
        "live_provider_observation_sha256",
        "admitted_runtime_sha256",
        "worker_image_sha256",
        "baseline_sha256",
        "host_identity_sha256",
        "tls_identity_sha256",
        "egress_policy_sha256",
        "campaign_permit_sha256",
        "capability_handle_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "qualification-worker-admission-verifier-result.schema.json": {
        "schema_version",
        "verdict",
        "admission_object_sha256",
        "provider_identity_sha256",
        "worker_identity_sha256",
        "live_provider_observation_sha256",
        "admitted_runtime_sha256",
        "worker_image_sha256",
        "baseline_sha256",
        "host_identity_sha256",
        "tls_identity_sha256",
        "egress_policy_sha256",
        "campaign_permit_sha256",
        "capability_handle_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "not_before",
        "expires_at",
        "verified_at",
        "verifier",
    },
    "qualification-worker-dispatch.schema.json": {
        "schema_version",
        "dispatch_id_sha256",
        "worker_admission_sha256",
        "provider_identity_sha256",
        "worker_identity_sha256",
        "live_provider_observation_sha256",
        "admitted_runtime_sha256",
        "run_id",
        "run_attempt",
        "start_id_sha256",
        "task_id_sha256",
        "task_condition_sha256",
        "campaign_artifact_sha256",
        "process_lease_sha256",
        "capability_handle_sha256",
        "idempotency_key",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "qualification-worker-terminal-receipt.schema.json": {
        "schema_version",
        "receipt_id_sha256",
        "worker_admission_sha256",
        "dispatch_id_sha256",
        "provider_identity_sha256",
        "worker_identity_sha256",
        "live_provider_observation_sha256",
        "admitted_runtime_sha256",
        "run_id",
        "run_attempt",
        "start_id_sha256",
        "task_id_sha256",
        "task_condition_sha256",
        "capability_handle_sha256",
        "launch_attempt",
        "launch_attempt_sha256",
        "process",
        "oracle_sha256",
        "result_sha256",
        "log_sha256",
        "burned_identities_sha256",
        "burn_ledger_revision",
        "burn_receipt_sha256",
        "burned_at",
        "ledger_readback_sha256",
        "effect_started",
        "delivery_state",
        "terminal_state",
        "exit_code",
        "uncertainty_sha256",
        "quarantine",
        "completed_at",
        "issuer",
    },
    "support-release-policy.schema.json": {
        "$schema",
        "schema_version",
        "lifecycle_state",
        "production_projection",
        "maximum_admission_days",
        "release_authority",
        "targets",
    },
    "qualification-trial-receipt-authority-policy.schema.json": {
        "$schema",
        "schema_version",
        "repository",
        "repository_id",
        "repository_owner_id",
        "workflow",
        "ref",
        "trigger",
        "input",
        "signing",
        "authorities",
    },
    "support-release-admission.schema.json": {
        "schema_version",
        "admission_id_sha256",
        "lifecycle_state",
        "support_target",
        "verdict",
        "claim_scope",
        "release_identity",
        "release",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "support_policy_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-release-authority-policy.schema.json": {
        "$schema",
        "schema_version",
        "release_app",
        "repository_selection",
        "permissions",
        "repositories",
        "tag_rulesets",
        "support_release_authorities",
    },
    "production-publication-recovery-authorization.schema.json": {
        "schema_version",
        "authorization_id_sha256",
        "qualification_release_reference",
        "qualification_release_object_sha256",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging_sha256",
        "repository",
        "repository_id",
        "target",
        "tag",
        "tag_ref",
        "tag_object_id",
        "target_commit",
        "draft_release_id",
        "requested_effect",
        "run_id",
        "run_attempt",
        "dispatcher_actor_id",
        "environment",
        "release_app",
        "idempotency_key",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-cloud-deploy-authorization.schema.json": {
        "schema_version",
        "authorization_sha256",
        "deployment_intent_sha256",
        "profile_repository",
        "profile_repository_id",
        "profile_commit",
        "profile_workflow",
        "profile_run_id",
        "profile_run_attempt",
        "cloud_source_commitment_sha256",
        "expected_live_attestation_sha256",
        "provider_idempotency_key",
        "audience",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-cloud-deployment-result.schema.json": {
        "schema_version",
        "handoff_id_sha256",
        "authorization_reference",
        "authorization_bundle_reference",
        "authorization_sha256",
        "cloud_source_commitment_sha256",
        "profile_commit",
        "profile_run_id",
        "profile_run_attempt",
        "source_proof_request",
        "source_proof_request_sha256",
        "source_proof_response",
        "source_proof_response_sha256",
        "reviewed_public_values_sha256",
        "expected_live_attestation_sha256",
        "live_attestation_sha256",
        "provider_idempotency_key",
        "audience",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-lifecycle-evidence-manifest.schema.json": {
        "schema_version",
        "target",
        "verdict",
        "claim_scope",
        "acceptance_policy_sha256",
        "lifecycle_policy_sha256",
        "release_identity",
        "release",
        "release_sha256",
        "artifact_inventory",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "qualification_evidence_decision_receipt_reference",
        "qualification_evidence_decision_receipt_bundle_reference",
        "qualification_admission_reference",
        "qualification_admission_bundle_reference",
        "campaign_summary",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-current-default.schema.json": {
        "schema_version",
        "default_set_revision",
        "previous_default_set_sha256",
        "targets",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-evidence-object-reference.schema.json": {
        "schema_version",
        "repository",
        "repository_id",
        "repository_owner_id",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "registry_entry_sha256",
        "kind",
        "object_schema_version",
        "object_path",
        "object_sha256",
        "size_bytes",
        "object_media_type",
        "semantic_identity_sha256",
        "subject_sha256",
    },
    "production-evidence-verification-policy.schema.json": {
        "schema_version",
        "repository",
        "repository_id",
        "repository_owner_id",
        "reference_schema_version",
        "transport",
        "signer_registry_schema_version",
        "embedded_signatures",
        "message_signature",
        "sigstore",
        "public_trust_dsse",
        "public_trust_software_ed25519",
    },
    "production-lifecycle-checkpoint.schema.json": {
        "schema_version",
        "checkpoint_id_sha256",
        "checkpoint_revision",
        "previous_checkpoint_sha256",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "signer_registry",
        "lifecycle_policy_sha256",
        "current_default_reference",
        "current_default_bundle_reference",
        "lifecycle_projection",
        "lifecycle_projection_sha256",
        "release_admissions",
        "release_admission_set_sha256",
        "workflow_admissions",
        "workflow_admission_set_sha256",
        "authority_state_reference",
        "authority_state_bundle_reference",
        "authority_state_sha256",
        "revocation_state_reference",
        "revocation_state_bundle_reference",
        "revocation_state_sha256",
        "generated_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-lifecycle-evidence-summary.schema.json": {
        "schema_version",
        "target",
        "verdict",
        "claim_scope",
        "acceptance_policy_sha256",
        "lifecycle_policy_sha256",
        "release_identity",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "evidence_identity_sha256",
        "qualification_evidence_decision_receipt_reference",
        "qualification_evidence_decision_receipt_bundle_reference",
        "qualification_admission_reference",
        "qualification_admission_bundle_reference",
        "production_acceptance_manifest_reference",
        "production_acceptance_manifest_bundle_reference",
        "campaign_summary",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "production-lifecycle-feed.schema.json": {
        "schema_version",
        "repository",
        "repository_id",
        "repository_owner_id",
        "ref",
        "feed_revision",
        "generated_at",
        "expires_at",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "signer_registry",
        "checkpoints",
    },
    "production-lifecycle-feed-update.schema.json": {
        "schema_version",
        "event_type",
        "source_repository",
        "source_repository_id",
        "source_ref",
        "source_commit",
        "target_repository",
        "target_repository_id",
        "target_ref",
        "expected_old_commit",
        "new_commit",
        "feed_path",
        "feed_sha256",
        "checkpoint_sha256",
        "registry_head_sha256",
        "expires_at",
        "idempotency_key",
    },
    "production-lifecycle-policy.schema.json": {
        "$schema",
        "schema_version",
        "revision",
        "admission_validity",
        "maximum_release_admission_days",
        "maximum_workflow_admission_days",
        "object_reference_schema_version",
        "release_admission_schema_version",
        "workflow_admission_schema_version",
        "lifecycle_checkpoint_schema_version",
        "lifecycle_feed_schema_version",
        "lifecycle_feed_ref",
        "targets",
    },
    "production-release-artifact-inventory.schema.json": {
        "schema_version",
        "target",
        "claim_scope",
        "artifacts",
    },
    "qualification-admission.schema.json": {
        "schema_version",
        "admission_id_sha256",
        "evidence_class",
        "organization_id_sha256",
        "workflow_id_sha256",
        "workflow_version_id_sha256",
        "bundle_version",
        "bundle_sha256",
        "admitted_runtime_sha256",
        "application_contract_sha256",
        "environment_contract_sha256",
        "input_contract_sha256",
        "action_contract_sha256",
        "identity_contract_sha256",
        "effect_contract_sha256",
        "policy_contract_sha256",
        "evidence_authority_sha256",
        "campaign_artifact_sha256",
        "campaign_permit_sha256",
        "decision_receipt_reference",
        "decision_receipt_bundle_reference",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "entity_class",
        "campaign_summary",
        "local_identity_opening",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "qualification-evidence-decision-receipt.schema.json": {
        "schema_version",
        "evidence_class",
        "decision_identity_sha256",
        "decision_revision",
        "decision_commitment_sha256",
        "evidence_manifest_sha256",
        "evidence_manifest_readback_sha256",
        "organization_id_sha256",
        "workflow_id_sha256",
        "workflow_version_id_sha256",
        "bundle_version",
        "bundle_sha256",
        "admitted_runtime_sha256",
        "application_contract_sha256",
        "environment_contract_sha256",
        "input_contract_sha256",
        "action_contract_sha256",
        "identity_contract_sha256",
        "effect_contract_sha256",
        "policy_contract_sha256",
        "evidence_authority_contract_sha256",
        "campaign_permit_sha256",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "entity_class",
        "campaign_summary",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "algorithm",
        "signing_statement",
        "signature",
        "campaign_artifact_sha256",
        "issuer",
    },
    "qualification-release.schema.json": {
        "schema_version",
        "admission_id_sha256",
        "evidence_class",
        "target",
        "verdict",
        "claim_scope",
        "release_identity",
        "release",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "production_acceptance_summary_reference",
        "production_acceptance_summary_bundle_reference",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "publication_policy_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    },
    "qualification-release-verification-receipt.schema.json": {
        "schema_version",
        "verification_id_sha256",
        "verdict",
        "evidence_class",
        "target",
        "claim_scope",
        "admission_object_sha256",
        "admission_bundle_object_sha256",
        "admission_id_sha256",
        "release_sha256",
        "artifact_inventory_sha256",
        "release_identity",
        "source_repository",
        "source_repository_id",
        "source_commit",
        "version",
        "tag",
        "draft_release_id",
        "publication_staging_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "acceptance_summary_object_sha256",
        "acceptance_manifest_object_sha256",
        "decision_receipt_object_sha256",
        "qualification_admission_object_sha256",
        "qualification_admission_id_sha256",
        "workflow_version_id_sha256",
        "workflow_bundle_sha256",
        "admitted_runtime_sha256",
        "verified_at",
        "expires_at",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "trust_state_source_commit",
    },
    "qualification-release-verification-receipt-v2.schema.json": {
        "schema_version",
        "verification_id_sha256",
        "verdict",
        "evidence_class",
        "target",
        "claim_scope",
        "admission_object_sha256",
        "admission_bundle_object_sha256",
        "admission_id_sha256",
        "release_sha256",
        "artifact_inventory_sha256",
        "release_identity",
        "release_kind",
        "source_repository",
        "source_repository_id",
        "source_commit",
        "version",
        "tag",
        "deployment_id",
        "deployment_sha256",
        "draft_release_id",
        "publication_staging_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "acceptance_summary_object_sha256",
        "acceptance_manifest_object_sha256",
        "decision_receipt_object_sha256",
        "qualification_admission_object_sha256",
        "qualification_admission_id_sha256",
        "workflow_version_id_sha256",
        "workflow_bundle_sha256",
        "admitted_runtime_sha256",
        "verified_at",
        "expires_at",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "trust_state_source_commit",
    },
}


def iter_nodes(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from iter_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_nodes(child)


class PublicTrustSchemaTests(unittest.TestCase):
    def test_remote_safe_flow_verification_fixture_matches_closed_schema(self) -> None:
        resources = []
        for path in SCHEMA_ROOT.glob("*.schema.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            resources.append((value["$id"], Resource.from_contents(value)))
        registry = Registry().with_resources(resources)
        schema = json.loads(
            (
                SCHEMA_ROOT / "qualification-release-verification-receipt.schema.json"
            ).read_text(encoding="utf-8")
        )
        fixture = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "remote-safe-synthetic-flow-release-verification.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, registry=registry).validate(fixture)

    def test_release_verification_fixture_binds_all_product_target_identities(
        self,
    ) -> None:
        resources = []
        for path in SCHEMA_ROOT.glob("*.schema.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            resources.append((value["$id"], Resource.from_contents(value)))
        registry = Registry().with_resources(resources)
        schema = json.loads(
            (
                SCHEMA_ROOT
                / "qualification-release-verification-receipt-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema, registry=registry)
        fixture = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "remote-safe-synthetic-flow-release-verification.json"
            ).read_text(encoding="utf-8")
        )
        fixture.update(
            schema_version=(
                "openadapt.qualification-release-verification-receipt/v2"
            ),
            release_kind="package",
            deployment_id=None,
            deployment_sha256=None,
        )
        targets = {
            "agent": (
                "production_agent",
                "OpenAdaptAI/openadapt-agent",
                "1136136670",
                "package",
            ),
            "capture": (
                "production_capture",
                "OpenAdaptAI/openadapt-capture",
                "1115283835",
                "package",
            ),
            "cloud": (
                "production_cloud",
                "OpenAdaptAI/openadapt-cloud",
                "1300570990",
                "deployment",
            ),
            "desktop": (
                "production_desktop",
                "OpenAdaptAI/openadapt-desktop",
                "1171291730",
                "hybrid",
            ),
            "docs": (
                "production_docs",
                "OpenAdaptAI/openadapt-ops",
                "1172011294",
                "deployment",
            ),
            "flow": (
                "production_flow",
                "OpenAdaptAI/openadapt-flow",
                "1291376938",
                "package",
            ),
            "openadapt": (
                "production_openadapt",
                "OpenAdaptAI/OpenAdapt",
                "627024850",
                "package",
            ),
        }
        for target, (claim, repository, repository_id, release_kind) in targets.items():
            with self.subTest(target=target):
                candidate = copy.deepcopy(fixture)
                packaged = release_kind in {"package", "hybrid"}
                deployed = release_kind in {"deployment", "hybrid"}
                candidate.update(
                    target=target,
                    claim_scope=claim,
                    source_repository=repository,
                    source_repository_id=repository_id,
                    release_kind=release_kind,
                    version="1.35.0" if packaged else None,
                    tag="v1.35.0" if packaged else None,
                    deployment_id="42" if deployed else None,
                    deployment_sha256=(
                        "sha256:" + "4" * 64 if deployed else None
                    ),
                )
                self.assertTrue(validator.is_valid(candidate))
                wrong_claim = copy.deepcopy(candidate)
                wrong_claim["claim_scope"] = "production_flow"
                if target != "flow":
                    self.assertFalse(validator.is_valid(wrong_claim))
                wrong_repository = copy.deepcopy(candidate)
                wrong_repository["source_repository"] = "OpenAdaptAI/wrong"
                self.assertFalse(validator.is_valid(wrong_repository))
                wrong_shape = copy.deepcopy(candidate)
                wrong_shape["version"] = None if packaged else "1.35.0"
                self.assertFalse(validator.is_valid(wrong_shape))
                wrong_deployment = copy.deepcopy(candidate)
                wrong_deployment["deployment_id"] = None if deployed else "42"
                self.assertFalse(validator.is_valid(wrong_deployment))

    def test_every_schema_parses_and_declared_objects_are_closed(self) -> None:
        paths = sorted(SCHEMA_ROOT.glob("*.schema.json"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                for node in iter_nodes(schema):
                    if not isinstance(node, dict):
                        continue
                    if node.get("type") != "object" or "properties" not in node:
                        continue
                    self.assertIs(node.get("additionalProperties"), False)
                    self.assertEqual(
                        set(node.get("required", [])), set(node["properties"])
                    )

    def test_frozen_top_level_contracts_are_exact(self) -> None:
        for filename, expected in EXPECTED_TOP_LEVEL_FIELDS.items():
            with self.subTest(path=filename):
                schema = json.loads(
                    (SCHEMA_ROOT / filename).read_text(encoding="utf-8")
                )
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(set(schema["required"]), expected)
                self.assertEqual(set(schema["properties"]), expected)

    def test_v2_reference_has_no_url_transport_field(self) -> None:
        schema = json.loads(
            (
                SCHEMA_ROOT / "production-evidence-object-reference.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(len(schema["required"]), 16)
        self.assertNotIn("url", schema["properties"])
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            "openadapt.production-evidence-object-reference/v2",
        )

    def test_current_default_and_checkpoint_bind_complete_signed_issuers(self) -> None:
        current = json.loads(
            (SCHEMA_ROOT / "production-current-default.schema.json").read_text()
        )
        checkpoint = json.loads(
            (SCHEMA_ROOT / "production-lifecycle-checkpoint.schema.json").read_text()
        )
        common = {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        }
        current_issuer = current["$defs"]["issuer"]
        checkpoint_issuer = checkpoint["$defs"]["issuer"]
        self.assertEqual(set(current_issuer["required"]), common)
        self.assertEqual(
            current_issuer["properties"]["repository_owner_id"]["const"],
            "132681217",
        )
        self.assertEqual(
            current_issuer["properties"]["environment"]["const"],
            "production-current-default",
        )
        self.assertEqual(
            set(checkpoint_issuer["required"]),
            common
            | {
                "policy_repository",
                "policy_repository_id",
                "policy_source_commit",
                "policy_path",
            },
        )
        self.assertEqual(
            checkpoint_issuer["properties"]["environment"]["const"],
            "production-lifecycle-checkpoint",
        )

    def test_release_artifacts_bind_publish_destinations(self) -> None:
        schema = json.loads(
            (SCHEMA_ROOT / "qualification-release.schema.json").read_text(
                encoding="utf-8"
            )
        )
        artifact = schema["$defs"]["artifact"]
        staged = schema["$defs"]["staged_asset"]
        projection = {
            "name",
            "kind",
            "sha256",
            "size_bytes",
            "media_type",
            "publish_destinations",
        }
        self.assertEqual(set(artifact["required"]), projection)
        self.assertEqual(
            set(staged["required"]),
            projection | {"asset_id", "uploader_id", "uploader_login"},
        )
        self.assertEqual(
            schema["$defs"]["publication_staging"]["properties"]["tag_rulesets"][
                "minItems"
            ],
            2,
        )
        self.assertEqual(
            schema["$defs"]["publication_staging"]["properties"]["tag_rulesets"][
                "maxItems"
            ],
            2,
        )
        self.assertEqual(
            schema["$defs"]["publication_staging"]["properties"]["publication_mode"][
                "enum"
            ],
            ["draft-before-tag", "already-published-pypi"],
        )
        self.assertIn(
            "publication_mode",
            schema["$defs"]["publication_staging"]["required"],
        )

    def test_verification_policy_keeps_sigstore_and_freezes_future_kms_profile(
        self,
    ) -> None:
        policy = json.loads(
            (ROOT / "production-evidence-policy.json").read_text(encoding="utf-8")
        )
        identities = policy["sigstore"]["certificate_identities"]
        self.assertEqual(
            [item["kind"] for item in identities],
            sorted(item["kind"] for item in identities),
        )
        profiles = {
            (item["kind"], item["evidence_class"]): item["bundle_profile"]
            for item in identities
        }
        self.assertEqual(
            profiles[("qualification-evidence-decision-receipt", "private-customer")],
            "sigstore-message-signature",
        )
        self.assertEqual(
            profiles[
                (
                    "qualification-evidence-decision-receipt",
                    "remote-safe-synthetic",
                )
            ],
            "github-attestation",
        )
        self.assertEqual(
            profiles[("qualification-release", "not-applicable")],
            "github-attestation",
        )
        message = policy["message_signature"]
        self.assertEqual(message["version"], "3.1.3")
        self.assertEqual(message["runner"], "ubuntu-24.04")
        self.assertEqual(message["architecture"], "linux-amd64")
        kms = policy["public_trust_dsse"]
        self.assertEqual(kms["profile"], "aws-kms-p256-dsse-v1")
        self.assertEqual(kms["aws_account_id"], "992382684924")
        self.assertEqual(kms["kms_key_spec"], "ECC_NIST_P256")
        self.assertEqual(kms["kms_signing_algorithm"], "ECDSA_SHA_256")
        self.assertEqual(kms["kms_message_type"], "DIGEST")
        self.assertIs(kms["offline_verification_required"], True)
        self.assertIs(kms["alias_allowed"], False)
        self.assertEqual(kms["allowed_kinds"], sorted(kms["allowed_kinds"]))
        self.assertEqual(len(kms["allowed_kinds"]), 17)
        software = policy["public_trust_software_ed25519"]
        self.assertEqual(software["profile"], "software-ed25519-dsse-v1")
        self.assertEqual(software["algorithm"], "ed25519")
        self.assertEqual(software["key_origin"], "software")
        self.assertIs(software["aws_required"], False)
        self.assertEqual(
            software["github_secret_name"],
            "OPENADAPT_QUALIFICATION_ED25519_PRIVATE_KEY",
        )
        self.assertEqual(
            software["keychain_service"], "openadapt-qualification-ed25519"
        )
        self.assertEqual(
            software["signing_environment"],
            "synthetic-qualification-evidence-decision",
        )
        self.assertEqual(software["allowed_kinds"], kms["allowed_kinds"])

    def test_support_policy_cannot_enter_the_production_projection(self) -> None:
        policy = json.loads((ROOT / "support-release-policy.json").read_text())
        self.assertEqual(policy["lifecycle_state"], "Support")
        self.assertIs(policy["production_projection"], False)
        self.assertEqual([item["id"] for item in policy["targets"]], ["openadapt-tray"])
        production_targets = {
            "openadapt",
            "flow",
            "cloud",
            "desktop",
            "capture",
            "agent",
            "docs",
        }
        self.assertTrue(production_targets.isdisjoint({"openadapt-tray"}))

    def test_trial_receipt_authorities_are_fixed_per_receipt_type(self) -> None:
        policy = json.loads(
            (ROOT / "qualification-trial-receipt-authority-policy.json").read_text()
        )
        self.assertEqual(policy["repository"], "OpenAdaptAI/openadapt-evals")
        self.assertEqual(
            policy["workflow"],
            ".github/workflows/issue-qualification-trial-receipts.yml",
        )
        self.assertEqual(policy["trigger"], "workflow_dispatch")
        self.assertEqual(len(policy["authorities"]), 8)
        self.assertEqual(
            len({item["environment"] for item in policy["authorities"]}), 8
        )
        for item in policy["authorities"]:
            self.assertEqual(
                item["runner_labels"],
                ["self-hosted", "evidence-authority", item["environment"]],
            )

    def test_worker_contracts_pin_central_authority_and_terminal_uncertainty(
        self,
    ) -> None:
        admission = json.loads(
            (SCHEMA_ROOT / "qualification-worker-admission.schema.json").read_text()
        )
        dispatch = json.loads(
            (SCHEMA_ROOT / "qualification-worker-dispatch.schema.json").read_text()
        )
        terminal = json.loads(
            (
                SCHEMA_ROOT / "qualification-worker-terminal-receipt.schema.json"
            ).read_text()
        )
        self.assertEqual(
            admission["$defs"]["issuer"]["properties"]["repository"]["const"],
            "OpenAdaptAI/.github",
        )
        self.assertEqual(dispatch["properties"]["run_attempt"]["const"], "1")
        self.assertEqual(
            dispatch["$defs"]["issuer"]["properties"]["workflow"]["const"],
            ".github/workflows/issue-qualification-worker-dispatch.yml",
        )
        process_schema = terminal["properties"]["process"]["oneOf"][0]
        self.assertEqual(
            set(process_schema["required"]),
            {
                "pid",
                "process_group_id",
                "process_start_ticks",
                "launched_at",
                "executable_sha256",
                "process_start_identity_sha256",
            },
        )
        prelaunch = terminal["allOf"][0]["then"]["properties"]
        self.assertIs(prelaunch["effect_started"]["const"], False)
        self.assertEqual(prelaunch["delivery_state"]["const"], "not_started")
        self.assertEqual(prelaunch["terminal_state"]["const"], "PRELAUNCH_QUARANTINED")
        self.assertIs(prelaunch["quarantine"]["properties"]["active"]["const"], True)
        uncertain = next(
            rule["then"]["properties"]
            for rule in terminal["allOf"]
            if rule["if"]["properties"].get("delivery_state") == {"const": "uncertain"}
        )
        self.assertIs(uncertain["effect_started"]["const"], True)
        self.assertEqual(
            uncertain["terminal_state"]["enum"],
            ["RECONCILIATION_REQUIRED", "QUARANTINED"],
        )
        self.assertIs(uncertain["quarantine"]["properties"]["active"]["const"], True)


if __name__ == "__main__":
    unittest.main()
