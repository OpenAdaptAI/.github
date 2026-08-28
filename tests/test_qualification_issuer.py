"""Focused tests for the inactive canonical qualification issuer lane."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import qualification_issuer as issuer  # noqa: E402
import qualification_kms_ed25519 as kms  # noqa: E402
import validate_evidence_registry as evidence  # noqa: E402
import verify_production_release_admission as release_verifier  # noqa: E402


NOW = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(days=7)
KMS_ARN = "arn:aws:kms:us-east-1:992382684924:key/12345678-1234-1234-1234-123456789abc"
WORKFLOW_REGISTRY_COMMIT = "1" * 40
RELEASE_REGISTRY_COMMIT = "2" * 40


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def utc(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def ed25519_material(seed: int) -> tuple[Ed25519PrivateKey, bytes, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(seed, seed + 32)))
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    spki = bytes.fromhex("302a300506032b6570032100") + raw
    return private, raw, spki


def ordinary_signer(
    private: Ed25519PrivateKey,
    *,
    usage: str,
    repository: str,
    workflow: str,
) -> dict:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    spki = bytes.fromhex("302a300506032b6570032100") + raw
    return {
        "algorithm": "ed25519",
        "key_id": "qa-ed25519-" + hashlib.sha256(raw).hexdigest()[:16],
        "public_key": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "public_key_spki_der_base64": base64.b64encode(spki).decode(),
        "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
        "statement_schema_versions": [
            "openadapt.qualification-evidence-signing-statement/v1"
        ],
        "allowed_usages": [usage],
        "allowed_workflows": [
            f"https://github.com/{repository}/.github/workflows/{workflow}"
            "@refs/heads/main"
        ],
        "allowed_ref_prefixes": ["refs/heads/main"],
        "status": "active",
        "revoked_at": None,
    }


def sign_embedded(
    value: dict,
    private: Ed25519PrivateKey,
    *,
    schema: str,
    domain: bytes,
) -> None:
    value["signing_statement"] = trust.signing_statement(
        value, object_schema_version=schema, signature_domain=domain
    )
    value["signature"] = base64.b64encode(
        private.sign(trust.canonical(value["signing_statement"]) + b"\n")
    ).decode()


def campaign_classes() -> dict:
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
            counts["policy_approved_repair_count"] = 3
            counts["approved_repair_count"] = 3
            counts["retained_repair_evidence_count"] = 3
            counts["live_target_revalidation_count"] = 3
        result[campaign_class] = counts
    return result


def reference_pair(
    kind: str, value: dict, *, registry_source_commit: str = WORKFLOW_REGISTRY_COMMIT
) -> tuple[dict, dict]:
    raw = evidence.canonical(value) + b"\n"
    object_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    digest_hex = object_sha256.removeprefix("sha256:")
    schema, media = evidence.OBJECT_KIND_CONTRACTS[kind]
    entry = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha256,
        "size_bytes": len(raw),
        "object_media_type": media,
        "semantic_identity_sha256": evidence.semantic_identity_digest(
            kind=kind,
            object_schema_version=schema,
            object_value=value,
            object_sha256=object_sha256,
        ),
        "subject_sha256": None,
    }
    entry["registry_entry_sha256"] = evidence.entry_digest(entry)
    regular = {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": registry_source_commit,
        "registry_revision": 4,
        "registry_head_sha256": sha("registry-head"),
        **entry,
    }
    bundle_kind = f"{kind}-sigstore-bundle"
    bundle_sha256 = sha(f"bundle:{kind}:{object_sha256}")
    bundle_hex = bundle_sha256.removeprefix("sha256:")
    bundle_entry = {
        "kind": bundle_kind,
        "object_schema_version": evidence.BUNDLE_MEDIA_TYPE,
        "object_path": (
            f"production-evidence/objects/sha256/{bundle_hex[:2]}/"
            f"{bundle_hex}.{bundle_kind}.json"
        ),
        "object_sha256": bundle_sha256,
        "size_bytes": 100,
        "object_media_type": evidence.BUNDLE_MEDIA_TYPE,
        "semantic_identity_sha256": evidence.semantic_identity_digest(
            kind=bundle_kind,
            object_schema_version=evidence.BUNDLE_MEDIA_TYPE,
            object_value=object_sha256,
            object_sha256=bundle_sha256,
        ),
        "subject_sha256": object_sha256,
    }
    bundle_entry["registry_entry_sha256"] = evidence.entry_digest(bundle_entry)
    bundle = {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": registry_source_commit,
        "registry_revision": 4,
        "registry_head_sha256": sha("registry-head"),
        **bundle_entry,
    }
    return regular, bundle


class RecordingConsumer:
    def __init__(self) -> None:
        self.handles: set[str] = set()
        self.effects: set[str] = set()
        self.calls: list[dict] = []

    def commit_once(self, **value) -> dict:
        if (
            value["request_handle"] in self.handles
            or value["effect_sha256"] in self.effects
        ):
            raise issuer.IssuerError(
                "request handle or semantic effect was already consumed"
            )
        self.handles.add(value["request_handle"])
        self.effects.add(value["effect_sha256"])
        self.calls.append(value)
        return value

    def reconcile(self, *, request_handle: str) -> dict:
        return next(
            call for call in self.calls if call["request_handle"] == request_handle
        )


class RecordingResolver:
    def __init__(self, fixture: dict) -> None:
        self.fixture = fixture
        self.objects: dict[str, issuer.ResolvedEvidence] = {}
        self.calls: list[tuple[str, str]] = []
        self.add(
            "qualification-evidence-decision-receipt",
            fixture["receipt"],
            fixture["receipt_ref"],
            fixture["receipt_bundle_ref"],
        )
        authority_ref, authority_bundle = reference_pair(
            "qualification-authority-state-receipt", fixture["authority"]
        )
        revocation_ref, revocation_bundle = reference_pair(
            "qualification-revocation-state-receipt", fixture["revocation"]
        )
        self.authority = self.add(
            "qualification-authority-state-receipt",
            fixture["authority"],
            authority_ref,
            authority_bundle,
        )
        self.revocation = self.add(
            "qualification-revocation-state-receipt",
            fixture["revocation"],
            revocation_ref,
            revocation_bundle,
        )

    def add(
        self, kind: str, value: dict, reference: dict, bundle_reference: dict
    ) -> issuer.ResolvedEvidence:
        resolved: issuer.ResolvedEvidence = {
            "value": value,
            "reference": reference,
            "bundle_reference": bundle_reference,
            "bound_signer_registry": self.fixture["registry"],
            "current_signer_registry": self.fixture["registry"],
        }
        self.objects[reference["object_sha256"]] = resolved
        return resolved

    def resolve(self, reference: dict, *, kind: str) -> issuer.ResolvedEvidence:
        self.calls.append((kind, reference["object_sha256"]))
        resolved = self.objects[reference["object_sha256"]]
        if resolved["reference"] != reference or reference["kind"] != kind:
            raise issuer.IssuerError("test resolver reference differs")
        return resolved

    def current_trust_state(
        self, *, registry_source_commit: str
    ) -> tuple[issuer.ResolvedEvidence, issuer.ResolvedEvidence]:
        self.calls.append(("current-trust-state", registry_source_commit))
        return self.authority, self.revocation


def trust_fixture() -> dict:
    decision_key, _decision_raw, decision_spki = ed25519_material(1)
    authority_key, _authority_raw, _authority_spki = ed25519_material(33)
    revocation_key, _revocation_raw, _revocation_spki = ed25519_material(65)
    private_decision_key, _private_raw, _private_spki = ed25519_material(97)
    decision_registry = kms.signer_registry_candidate(
        kms_public_key_projection={
            "KeyId": KMS_ARN,
            "PublicKey": base64.b64encode(decision_spki).decode(),
            "KeySpec": "ECC_NIST_EDWARDS25519",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ED25519_SHA_512"],
        },
        revision=1,
        generated_at=NOW,
        expires_at=EXPIRES,
    )
    registry = copy.deepcopy(decision_registry["proposed_registry"])
    registry["signers"].extend(
        [
            ordinary_signer(
                authority_key,
                usage="qualification-authority-state-receipt",
                repository="OpenAdaptAI/openadapt-ops",
                workflow="qualification-authority-state.yml",
            ),
            ordinary_signer(
                revocation_key,
                usage="qualification-revocation-state-receipt",
                repository="OpenAdaptAI/openadapt-ops",
                workflow="qualification-revocation-state.yml",
            ),
            ordinary_signer(
                private_decision_key,
                usage="qualification-evidence-decision-receipt",
                repository="OpenAdaptAI/openadapt-internal",
                workflow="issue-private-qualification-evidence-decision.yml",
            ),
        ]
    )
    evidence.validate_signer_registry(registry)
    registry_identity = evidence.signer_registry_identity_digest(registry)
    registry_raw_sha256 = (
        "sha256:" + hashlib.sha256(evidence.canonical(registry) + b"\n").hexdigest()
    )

    authority = {
        "schema_version": "openadapt.qualification-authority-state-receipt/v2",
        "authority_state_sha256": sha("placeholder-authority"),
        "status": "active",
        "signer_registry_sha256": registry_raw_sha256,
        "signer_registry_identity_sha256": registry_identity,
        "signer_registry_revision": registry["revision"],
        "evidence_authority_sha256": sha("synthetic-evidence-authority"),
        "observed_at": utc(NOW),
        "not_before": utc(NOW),
        "expires_at": utc(EXPIRES),
        "issuer_key_id": registry["signers"][1]["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-authority-state.yml",
            "ref": "refs/heads/main",
            "source_commit": "b" * 40,
            "environment": "qualification-authority-state",
        },
    }
    projection = dict(authority)
    projection.pop("authority_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    authority["authority_state_sha256"] = trust.digest_bytes(
        trust.AUTHORITY_STATE_IDENTITY_DOMAIN, projection
    )
    sign_embedded(
        authority,
        authority_key,
        schema="openadapt.qualification-authority-state-receipt/v2",
        domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
    )

    revocation = {
        "schema_version": "openadapt.qualification-revocation-state-receipt/v1",
        "revocation_state_sha256": sha("placeholder-revocation"),
        "previous_revocation_state_sha256": None,
        "revision": 1,
        "status": "current",
        "authority_state_sha256": authority["authority_state_sha256"],
        "signer_registry_sha256": registry_identity,
        "revocations": [],
        "observed_at": utc(NOW),
        "not_before": utc(NOW),
        "expires_at": utc(EXPIRES),
        "issuer_key_id": registry["signers"][2]["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-revocation-state.yml",
            "ref": "refs/heads/main",
            "source_commit": "c" * 40,
            "environment": "qualification-revocation-state",
        },
    }
    projection = dict(revocation)
    projection.pop("revocation_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    revocation["revocation_state_sha256"] = trust.digest_bytes(
        trust.REVOCATION_STATE_IDENTITY_DOMAIN, projection
    )
    sign_embedded(
        revocation,
        revocation_key,
        schema="openadapt.qualification-revocation-state-receipt/v1",
        domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
    )

    receipt = {
        "schema_version": "openadapt.qualification-evidence-decision-receipt/v2",
        "evidence_class": "remote-safe-synthetic",
        "decision_identity_sha256": sha("decision-series"),
        "decision_revision": 1,
        "decision_commitment_sha256": sha("decision"),
        "evidence_manifest_sha256": sha("evidence-manifest"),
        "evidence_manifest_readback_sha256": sha("manifest-readback"),
        "campaign_artifact_sha256": sha("campaign-artifact"),
        "organization_id_sha256": sha("organization"),
        "workflow_id_sha256": sha("workflow"),
        "workflow_version_id_sha256": sha("workflow-version"),
        "bundle_version": "1.0.0",
        "bundle_sha256": sha("sealed-workflow-bundle"),
        "admitted_runtime_sha256": sha("flow-runtime"),
        "application_contract_sha256": sha("application-contract"),
        "environment_contract_sha256": sha("environment-contract"),
        "input_contract_sha256": sha("input-contract"),
        "action_contract_sha256": sha("action-contract"),
        "identity_contract_sha256": sha("identity-contract"),
        "effect_contract_sha256": sha("effect-contract"),
        "policy_contract_sha256": sha("policy-contract"),
        "evidence_authority_contract_sha256": authority["evidence_authority_sha256"],
        "campaign_permit_sha256": sha("campaign-permit"),
        "signer_registry_sha256": registry_identity,
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "entity_class": "record",
        "campaign_summary": {
            "schema_version": (
                "openadapt.qualification-evidence-decision-campaign-summary/v1"
            ),
            "minimum_trials_per_task_condition": 3,
            "task_count": 1,
            "classes": campaign_classes(),
        },
        "verdict": "ADMIT",
        "issued_at": utc(NOW),
        "not_before": utc(NOW),
        "expires_at": utc(EXPIRES),
        "issuer_key_id": registry["signers"][0]["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-synthetic-qualification-evidence-decision.yml"
            ),
            "ref": "refs/heads/main",
            "source_commit": "d" * 40,
            "environment": "synthetic-qualification-evidence-decision",
        },
    }
    sign_embedded(
        receipt,
        decision_key,
        schema="openadapt.qualification-evidence-decision-receipt/v2",
        domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
    )
    receipt_ref, receipt_bundle_ref = reference_pair(
        "qualification-evidence-decision-receipt", receipt
    )
    return {
        "decision_key": decision_key,
        "decision_spki": decision_spki,
        "authority_key": authority_key,
        "revocation_key": revocation_key,
        "private_decision_key": private_decision_key,
        "registry": registry,
        "authority": authority,
        "revocation": revocation,
        "receipt": receipt,
        "receipt_ref": receipt_ref,
        "receipt_bundle_ref": receipt_bundle_ref,
    }


def workflow_request(fixture: dict, handle: str = "qair_" + "A" * 43) -> dict:
    return {
        "schema_version": "openadapt.qualification-admission-issue-request/v1",
        "request_handle": handle,
        "evidence_class": "remote-safe-synthetic",
        "decision_receipt_reference": fixture["receipt_ref"],
    }


def flow_release_inputs(
    fixture: dict,
    admission: dict,
    resolver: RecordingResolver,
    *,
    target: str = "flow",
) -> dict:
    admission_ref, admission_bundle_ref = reference_pair(
        "qualification-admission", admission
    )
    artifacts = [
        {
            "name": "openadapt_flow-1.35.0.tar.gz",
            "kind": "python-sdist",
            "sha256": sha("flow-sdist"),
            "size_bytes": 101,
            "media_type": "application/gzip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": "openadapt_flow-1.35.0-py3-none-any.whl",
            "kind": "python-wheel",
            "sha256": sha("flow-wheel"),
            "size_bytes": 102,
            "media_type": "application/zip",
            "publish_destinations": ["github-release", "pypi"],
        },
    ]
    common_ruleset = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    }
    rulesets = [
        {
            **common_ruleset,
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
            **common_ruleset,
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
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "draft_release_id": "20",
        "tag": "v1.35.0",
        "target_commitish": "e" * 40,
        "draft": True,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": [
            {
                "asset_id": str(30 + index),
                **artifact,
                "uploader_id": "321543906",
                "uploader_login": "openadapt-release[bot]",
            }
            for index, artifact in enumerate(
                sorted(artifacts, key=lambda item: item["name"])
            )
        ],
        "immutable_releases": {"enabled": True, "enforced_by_owner": False},
        "immutable_releases_sha256": trust.digest_bytes(
            trust.IMMUTABLE_RELEASES_DOMAIN,
            {"enabled": True, "enforced_by_owner": False},
        ),
        "tag_rulesets": rulesets,
        "tag_rulesets_sha256": trust.digest_bytes(trust.TAG_RULESETS_DOMAIN, rulesets),
        "tag_ref_state": {"ref": "refs/tags/v1.35.0", "exists": False},
        "tag_ref_state_sha256": trust.digest_bytes(
            trust.TAG_REF_STATE_DOMAIN,
            {"ref": "refs/tags/v1.35.0", "exists": False},
        ),
        "observed_at": utc(NOW),
    }
    candidate = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-flow",
        "source_repository_id": "1291376938",
        "source_commit": "e" * 40,
        "version": "1.35.0",
        "tag": "v1.35.0",
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": artifacts,
    }
    release_identity = {
        "schema_version": "openadapt.monotonic-production-release/v1",
        "channel": "production",
        "sequence": 1,
        "previous_admission_sha256": None,
    }
    release_sha256 = trust.digest_bytes(
        trust.RELEASE_DOMAIN,
        {"target": "flow", "claim_scope": "production_flow", "release": candidate},
    )
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": "flow",
        "claim_scope": "production_flow",
        "artifacts": artifacts,
    }
    inventory_sha256 = trust.artifact_inventory_digest(inventory)
    common = {
        "target": "flow",
        "verdict": "accepted",
        "claim_scope": "production_flow",
        "acceptance_policy_sha256": sha("acceptance-policy"),
        "lifecycle_policy_sha256": sha("lifecycle-policy"),
        "release_identity": release_identity,
        "release_sha256": release_sha256,
        "artifact_inventory_sha256": inventory_sha256,
        "publication_staging": staging,
        "publication_staging_sha256": trust.staging_digest(staging),
        "qualification_evidence_decision_receipt_reference": fixture["receipt_ref"],
        "qualification_evidence_decision_receipt_bundle_reference": fixture[
            "receipt_bundle_ref"
        ],
        "qualification_admission_reference": admission_ref,
        "qualification_admission_bundle_reference": admission_bundle_ref,
        "campaign_summary": fixture["receipt"]["campaign_summary"]["classes"],
        "authority_state_sha256": fixture["authority"]["authority_state_sha256"],
        "revocation_state_sha256": fixture["revocation"]["revocation_state_sha256"],
        "signer_registry_sha256": evidence.signer_registry_identity_digest(
            fixture["registry"]
        ),
        "issued_at": utc(NOW),
        "not_before": utc(NOW),
        "expires_at": utc(EXPIRES),
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-evals",
            "repository_id": "1135998197",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-acceptance.yml",
            "ref": "refs/heads/main",
            "source_commit": "f" * 40,
            "environment": "production-acceptance",
        },
    }
    manifest = {
        "schema_version": "openadapt.production-acceptance/v3",
        **common,
        "release": candidate,
        "artifact_inventory": inventory,
    }
    if target != "flow":
        contract = trust.TARGET_CONTRACTS[target]
        version = "1.35.0" if contract["release_kind"] != "deployment" else None
        tag = "v1.35.0" if version is not None else None
        deployment_id = (
            "42" if contract["release_kind"] in {"deployment", "hybrid"} else None
        )
        deployment_sha256 = (
            sha(f"{target}-deployment") if deployment_id is not None else None
        )
        metadata_names = {
            "verification-metadata-linux-x86-64": (
                f"OpenAdapt-Desktop-v{version}-linux-x86_64-verification.json"
            ),
            "verification-metadata-macos-arm64": (
                f"OpenAdapt-Desktop-v{version}-macos-arm64-verification.json"
            ),
            "verification-metadata-macos-x86-64": (
                f"OpenAdapt-Desktop-v{version}-macos-x86_64-verification.json"
            ),
            "verification-metadata-windows-x86-64": (
                f"OpenAdapt-Desktop-v{version}-windows-x86_64-verification.json"
            ),
        }
        artifacts = []
        for index, (kind, (media_type, destinations)) in enumerate(
            sorted(contract["artifacts"].items())
        ):
            artifacts.append(
                {
                    "name": metadata_names.get(kind, f"{target}-1.35.0-{kind}"),
                    "kind": kind,
                    "sha256": sha(f"{target}-{kind}"),
                    "size_bytes": 200 + index,
                    "media_type": media_type,
                    "publish_destinations": list(destinations),
                }
            )
        staging_tag = tag or f"v0.0.0-deployment.{deployment_id}"
        target_rulesets = copy.deepcopy(rulesets)
        for ruleset in target_rulesets:
            ruleset["repository"] = contract["repository"]
            ruleset["repository_id"] = contract["repository_id"]
        staging = {
            **staging,
            "repository": contract["repository"],
            "repository_id": contract["repository_id"],
            "tag": staging_tag,
            "assets": [
                {
                    "asset_id": str(130 + index),
                    **artifact,
                    "uploader_id": "321543906",
                    "uploader_login": "openadapt-release[bot]",
                }
                for index, artifact in enumerate(
                    sorted(artifacts, key=lambda item: item["name"])
                )
            ],
            "tag_rulesets": target_rulesets,
            "tag_rulesets_sha256": trust.digest_bytes(
                trust.TAG_RULESETS_DOMAIN, target_rulesets
            ),
            "tag_ref_state": {"ref": f"refs/tags/{staging_tag}", "exists": False},
            "tag_ref_state_sha256": trust.digest_bytes(
                trust.TAG_REF_STATE_DOMAIN,
                {"ref": f"refs/tags/{staging_tag}", "exists": False},
            ),
        }
        candidate = {
            **candidate,
            "kind": contract["release_kind"],
            "source_repository": contract["repository"],
            "source_repository_id": contract["repository_id"],
            "version": version,
            "tag": tag,
            "deployment_id": deployment_id,
            "deployment_sha256": deployment_sha256,
            "artifacts": artifacts,
        }
        inventory = {
            "schema_version": "openadapt.production-release-artifact-inventory/v1",
            "target": target,
            "claim_scope": contract["claim_scope"],
            "artifacts": artifacts,
        }
        common.update(
            target=target,
            claim_scope=contract["claim_scope"],
            release_sha256=trust.digest_bytes(
                trust.RELEASE_DOMAIN,
                {
                    "target": target,
                    "claim_scope": contract["claim_scope"],
                    "release": candidate,
                },
            ),
            artifact_inventory_sha256=trust.artifact_inventory_digest(inventory),
            publication_staging=staging,
            publication_staging_sha256=trust.staging_digest(staging),
        )
        manifest = {
            "schema_version": "openadapt.production-acceptance/v3",
            **common,
            "release": candidate,
            "artifact_inventory": inventory,
        }
    manifest_ref, manifest_bundle_ref = reference_pair(
        "production-acceptance-manifest", manifest
    )
    summary = {
        "schema_version": "openadapt.production-lifecycle-evidence-summary/v3",
        **common,
        "evidence_identity_sha256": sha("placeholder-evidence-identity"),
        "production_acceptance_manifest_reference": manifest_ref,
        "production_acceptance_manifest_bundle_reference": manifest_bundle_ref,
    }
    summary["evidence_identity_sha256"] = trust.acceptance_summary_identity(summary)
    summary_ref, summary_bundle_ref = reference_pair(
        "production-acceptance-summary",
        summary,
        registry_source_commit=RELEASE_REGISTRY_COMMIT,
    )
    resolver.add(
        "qualification-admission", admission, admission_ref, admission_bundle_ref
    )
    resolver.add(
        "production-acceptance-manifest", manifest, manifest_ref, manifest_bundle_ref
    )
    resolver.add(
        "production-acceptance-summary", summary, summary_ref, summary_bundle_ref
    )
    return {
        "schema_version": "openadapt.qualification-release-issue-request/v1",
        "request_handle": "qair_" + "B" * 43,
        "evidence_class": "remote-safe-synthetic",
        "production_acceptance_summary_reference": summary_ref,
    }


class QualificationIssuerTests(unittest.TestCase):
    def test_public_issue_request_contains_only_one_semantic_reference(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "qualification-issuer-request.schema.json").read_text()
        )
        workflow = schema["$defs"]["workflow_request"]
        release = schema["$defs"]["release_request"]
        self.assertFalse(workflow["additionalProperties"])
        self.assertFalse(release["additionalProperties"])
        self.assertEqual(
            set(workflow["required"]),
            {
                "schema_version",
                "request_handle",
                "evidence_class",
                "decision_receipt_reference",
            },
        )
        self.assertEqual(set(workflow["properties"]), set(workflow["required"]))
        self.assertEqual(
            set(release["required"]),
            {
                "schema_version",
                "request_handle",
                "evidence_class",
                "production_acceptance_summary_reference",
            },
        )
        self.assertEqual(set(release["properties"]), set(release["required"]))

    def test_kms_candidate_and_sign_request_are_offline_and_exact(self) -> None:
        fixture = trust_fixture()
        registry = fixture["registry"]
        signer = registry["signers"][0]
        self.assertEqual(signer["kms_key_arn"], KMS_ARN)
        self.assertEqual(signer["allowed_environments"], [kms.ENVIRONMENT])
        unsigned_receipt = copy.deepcopy(fixture["receipt"])
        unsigned_receipt["signature"] = ""
        statement = unsigned_receipt["signing_statement"]
        request = kms.kms_sign_request(
            unsigned_receipt,
            signer_registry=registry,
            kms_key_arn=KMS_ARN,
        )
        self.assertEqual(request["MessageType"], "RAW")
        self.assertEqual(request["SigningAlgorithm"], "ED25519_SHA_512")
        self.assertEqual(
            base64.b64decode(request["Message"]), trust.canonical(statement) + b"\n"
        )
        signature = fixture["decision_key"].sign(trust.canonical(statement) + b"\n")
        self.assertEqual(
            kms.verify_kms_signature(
                statement=statement,
                signature=signature,
                spki_der=fixture["decision_spki"],
            ),
            base64.b64encode(signature).decode(),
        )
        invalid_signature = bytearray(signature)
        invalid_signature[0] ^= 1
        with self.assertRaisesRegex(
            kms.KmsEd25519Error, "signature verification failed"
        ):
            kms.verify_kms_signature(
                statement=statement,
                signature=bytes(invalid_signature),
                spki_der=fixture["decision_spki"],
            )
        private_receipt = copy.deepcopy(unsigned_receipt)
        private_receipt["evidence_class"] = "private-customer"
        private_receipt["signing_statement"] = trust.signing_statement(
            private_receipt,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v2"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        with self.assertRaisesRegex(kms.KmsEd25519Error, "issuer differs"):
            kms.kms_sign_request(
                private_receipt,
                signer_registry=registry,
                kms_key_arn=KMS_ARN,
            )
        with self.assertRaisesRegex(kms.KmsEd25519Error, "fields differ"):
            kms.signer_registry_candidate(
                kms_public_key_projection={"KeyId": KMS_ARN},
                revision=1,
                generated_at=NOW,
                expires_at=EXPIRES,
            )
        invalid_projection = {
            "KeyId": 1,
            "PublicKey": base64.b64encode(fixture["decision_spki"]).decode(),
            "KeySpec": "ECC_NIST_EDWARDS25519",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ED25519_SHA_512"],
        }
        with self.assertRaisesRegex(kms.KmsEd25519Error, "exact key ARN"):
            kms.signer_registry_candidate(
                kms_public_key_projection=invalid_projection,
                revision=1,
                generated_at=NOW,
                expires_at=EXPIRES,
            )

    def test_github_resolver_delegates_to_registered_outer_bundle_verifier(
        self,
    ) -> None:
        fixture = trust_fixture()
        policy = {"sigstore": {"certificate_identities": []}}
        resolver = issuer.GitHubEvidenceResolver(policy)
        with (
            mock.patch.object(
                issuer.verifier,
                "derive_bundle_reference",
                return_value=fixture["receipt_bundle_ref"],
            ) as derive,
            mock.patch.object(
                issuer.verifier,
                "resolve_pair",
                return_value=(
                    fixture["receipt"],
                    fixture["registry"],
                    fixture["registry"],
                ),
            ) as resolve,
        ):
            resolved = resolver.resolve(
                fixture["receipt_ref"],
                kind="qualification-evidence-decision-receipt",
            )
        derive.assert_called_once_with(fixture["receipt_ref"])
        resolve.assert_called_once_with(
            fixture["receipt_ref"],
            fixture["receipt_bundle_ref"],
            kind="qualification-evidence-decision-receipt",
            policy=policy,
        )
        self.assertEqual(resolved["value"], fixture["receipt"])

    def test_release_verifier_uses_current_protected_main_state(self) -> None:
        fixture = trust_fixture()
        resolver = RecordingResolver(fixture)
        admission = issuer.issue_workflow_admission(
            workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        request = flow_release_inputs(fixture, admission, resolver)
        release = issuer.issue_release_admission(
            request,
            resolver=resolver,
            issuer_source_commit=RELEASE_REGISTRY_COMMIT,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        release_reference, _ = reference_pair(
            "qualification-release",
            release,
            registry_source_commit=RELEASE_REGISTRY_COMMIT,
        )
        authority_reference = {"kind": "qualification-authority-state-receipt"}
        revocation_reference = {"kind": "qualification-revocation-state-receipt"}
        with (
            mock.patch.object(
                release_verifier,
                "protected_main_commit",
                return_value=RELEASE_REGISTRY_COMMIT,
            ),
            mock.patch.object(
                release_verifier,
                "current_registered_reference",
                side_effect=[authority_reference, revocation_reference],
            ),
            mock.patch.object(
                release_verifier,
                "derive_bundle_reference",
                side_effect=[
                    {"kind": "authority-bundle"},
                    {"kind": "revocation-bundle"},
                ],
            ),
            mock.patch.object(
                release_verifier,
                "resolve_pair",
                side_effect=[
                    (fixture["authority"], fixture["registry"], fixture["registry"]),
                    (
                        fixture["revocation"],
                        fixture["registry"],
                        fixture["registry"],
                    ),
                ],
            ),
            mock.patch.object(
                release_verifier.trust,
                "validate_admission_current_state",
                wraps=release_verifier.trust.validate_admission_current_state,
            ) as validate_current,
        ):
            commit, authority, revocation, registry = (
                release_verifier.current_admission_state(
                    release,
                    admission_reference=release_reference,
                    policy={},
                    now=NOW,
                )
            )
        self.assertEqual(commit, RELEASE_REGISTRY_COMMIT)
        self.assertEqual(authority, fixture["authority"])
        self.assertEqual(revocation, fixture["revocation"])
        self.assertEqual(registry, fixture["registry"])
        validate_current.assert_called_once()

    def test_oidc_contract_is_exact_and_inactive(self) -> None:
        contract = kms.interface_contract()
        self.assertEqual(contract["activation_state"], "inactive")
        self.assertEqual(issuer.interface_contract()["activation_state"], "inactive")
        self.assertEqual(contract["aws_account_id"], "992382684924")
        commit = "a" * 40
        claims = {
            "iss": contract["oidc_issuer"],
            "aud": contract["oidc_audience"],
            "sub": contract["oidc_subject"],
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "job_workflow_ref": contract["workflow"],
            "job_workflow_sha": commit,
            "runner_environment": "github-hosted",
        }
        kms.validate_oidc_claims(claims, workflow_source_commit=commit)
        claims["sub"] = "repo:OpenAdaptAI/.github:ref:refs/heads/main"
        with self.assertRaisesRegex(kms.KmsEd25519Error, "OIDC claim sub"):
            kms.validate_oidc_claims(claims, workflow_source_commit=commit)

    def test_workflow_admission_derives_every_binding_and_consumes_once(self) -> None:
        fixture = trust_fixture()
        request = workflow_request(fixture)
        resolver = RecordingResolver(fixture)
        consumer = RecordingConsumer()
        admission = issuer.issue_workflow_admission(
            request,
            resolver=resolver,
            issuer_source_commit="1" * 40,
            now=NOW,
            consumer=consumer,
        )
        self.assertEqual(
            admission["bundle_sha256"], fixture["receipt"]["bundle_sha256"]
        )
        self.assertEqual(
            admission["admitted_runtime_sha256"],
            fixture["receipt"]["admitted_runtime_sha256"],
        )
        self.assertEqual(admission["evidence_class"], "remote-safe-synthetic")
        self.assertEqual(admission["expires_at"], utc(EXPIRES))
        self.assertEqual(len(consumer.calls), 1)
        self.assertEqual(
            consumer.calls[0]["operation"], "issue-qualification-admission"
        )
        with self.assertRaisesRegex(issuer.IssuerError, "already consumed"):
            issuer.issue_workflow_admission(
                request,
                resolver=resolver,
                issuer_source_commit="1" * 40,
                now=NOW,
                consumer=consumer,
            )
        different_handle = workflow_request(fixture, "qair_" + "C" * 43)
        with self.assertRaisesRegex(issuer.IssuerError, "already consumed"):
            issuer.issue_workflow_admission(
                different_handle,
                resolver=resolver,
                issuer_source_commit="1" * 40,
                now=NOW,
                consumer=consumer,
            )

    def test_workflow_root_must_be_in_the_issuer_source_commit(self) -> None:
        fixture = trust_fixture()
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = reference_pair(
            "qualification-evidence-decision-receipt",
            fixture["receipt"],
            registry_source_commit="f" * 40,
        )
        with self.assertRaisesRegex(issuer.IssuerError, "issuer source registry"):
            issuer.issue_workflow_admission(
                workflow_request(fixture),
                resolver=RecordingResolver(fixture),
                issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_receipt_must_bind_the_active_evidence_authority(self) -> None:
        fixture = trust_fixture()
        fixture["receipt"]["evidence_authority_contract_sha256"] = sha(
            "wrong-authority"
        )
        sign_embedded(
            fixture["receipt"],
            fixture["decision_key"],
            schema="openadapt.qualification-evidence-decision-receipt/v2",
            domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = reference_pair(
            "qualification-evidence-decision-receipt", fixture["receipt"]
        )
        with self.assertRaisesRegex(issuer.IssuerError, "current trust state"):
            issuer.issue_workflow_admission(
                workflow_request(fixture),
                resolver=RecordingResolver(fixture),
                issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_private_customer_receipt_is_refused(self) -> None:
        fixture = trust_fixture()
        private_request = workflow_request(fixture)
        fixture["receipt"]["evidence_class"] = "private-customer"
        fixture["receipt"]["issuer_key_id"] = fixture["registry"]["signers"][3][
            "key_id"
        ]
        fixture["receipt"]["issuer"] = {
            "repository": "OpenAdaptAI/openadapt-internal",
            "repository_id": "1170060695",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-private-qualification-evidence-decision.yml"
            ),
            "ref": "refs/heads/main",
            "source_commit": "d" * 40,
            "environment": "private-qualification-evidence-decision",
        }
        sign_embedded(
            fixture["receipt"],
            fixture["private_decision_key"],
            schema="openadapt.qualification-evidence-decision-receipt/v2",
            domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = reference_pair(
            "qualification-evidence-decision-receipt", fixture["receipt"]
        )
        private_request["decision_receipt_reference"] = fixture["receipt_ref"]
        with self.assertRaisesRegex(issuer.IssuerError, "cannot accept private"):
            issuer.issue_workflow_admission(
                private_request,
                resolver=RecordingResolver(fixture),
                issuer_source_commit="1" * 40,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_revoked_decision_receipt_is_refused(self) -> None:
        fixture = trust_fixture()
        revocation = fixture["revocation"]
        revocation["previous_revocation_state_sha256"] = revocation[
            "revocation_state_sha256"
        ]
        revocation["revision"] = 2
        revocation["revocations"] = [
            {
                "subject_kind": "qualification-evidence-decision-receipt",
                "subject_id": fixture["receipt_ref"]["semantic_identity_sha256"],
                "revoked_at": utc(NOW),
                "reason_code": "test_revocation",
            }
        ]
        projection = dict(revocation)
        projection.pop("revocation_state_sha256")
        projection.pop("signature")
        projection.pop("signing_statement")
        revocation["revocation_state_sha256"] = trust.digest_bytes(
            trust.REVOCATION_STATE_IDENTITY_DOMAIN, projection
        )
        sign_embedded(
            revocation,
            fixture["revocation_key"],
            schema="openadapt.qualification-revocation-state-receipt/v1",
            domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
        )
        fixture["receipt"]["revocation_state_sha256"] = revocation[
            "revocation_state_sha256"
        ]
        sign_embedded(
            fixture["receipt"],
            fixture["decision_key"],
            schema="openadapt.qualification-evidence-decision-receipt/v2",
            domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = reference_pair(
            "qualification-evidence-decision-receipt", fixture["receipt"]
        )
        with self.assertRaisesRegex(
            issuer.IssuerError, "qualification-evidence-decision-receipt is revoked"
        ):
            issuer.issue_workflow_admission(
                workflow_request(fixture),
                resolver=RecordingResolver(fixture),
                issuer_source_commit="1" * 40,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_blind_retry_is_refused(self) -> None:
        fixture = trust_fixture()
        counts = fixture["receipt"]["campaign_summary"]["classes"]["uncertain_delivery"]
        counts["blind_retry_count"] = 1
        sign_embedded(
            fixture["receipt"],
            fixture["decision_key"],
            schema="openadapt.qualification-evidence-decision-receipt/v2",
            domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = reference_pair(
            "qualification-evidence-decision-receipt", fixture["receipt"]
        )
        with self.assertRaisesRegex(trust.TrustError, "forbidden failure"):
            issuer.issue_workflow_admission(
                workflow_request(fixture),
                resolver=RecordingResolver(fixture),
                issuer_source_commit="1" * 40,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_release_admission_binds_flow_artifacts_and_full_chain(self) -> None:
        fixture = trust_fixture()
        resolver = RecordingResolver(fixture)
        admission = issuer.issue_workflow_admission(
            workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit="1" * 40,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        request = flow_release_inputs(fixture, admission, resolver)
        consumer = RecordingConsumer()
        release = issuer.issue_release_admission(
            request,
            resolver=resolver,
            issuer_source_commit="2" * 40,
            now=NOW,
            consumer=consumer,
        )
        self.assertEqual(release["target"], "flow")
        self.assertEqual(release["evidence_class"], "remote-safe-synthetic")
        self.assertEqual(
            [item["kind"] for item in release["release"]["artifacts"]],
            ["python-sdist", "python-wheel"],
        )
        # The schema permits 30 days. The seven-day evidence chain contains it.
        self.assertEqual(release["expires_at"], utc(EXPIRES))
        self.assertEqual(consumer.calls[0]["operation"], "issue-qualification-release")

        tampered_resolver = RecordingResolver(fixture)
        flow_release_inputs(fixture, admission, tampered_resolver)
        summary_value = tampered_resolver.objects[
            request["production_acceptance_summary_reference"]["object_sha256"]
        ]["value"]
        manifest_sha256 = summary_value["production_acceptance_manifest_reference"][
            "object_sha256"
        ]
        tampered_resolver.objects[manifest_sha256]["value"]["release"]["artifacts"][0][
            "sha256"
        ] = sha("tampered-sdist")
        with self.assertRaises(issuer.IssuerError):
            issuer.issue_release_admission(
                request,
                resolver=tampered_resolver,
                issuer_source_commit="2" * 40,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_release_admission_accepts_every_policy_target_with_full_chain(self) -> None:
        for target in trust.TARGETS:
            with self.subTest(target=target):
                fixture = trust_fixture()
                resolver = RecordingResolver(fixture)
                workflow_admission = issuer.issue_workflow_admission(
                    workflow_request(fixture),
                    resolver=resolver,
                    issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
                    now=NOW,
                    consumer=RecordingConsumer(),
                )
                request = flow_release_inputs(
                    fixture,
                    workflow_admission,
                    resolver,
                    target=target,
                )
                release = issuer.issue_release_admission(
                    request,
                    resolver=resolver,
                    issuer_source_commit=RELEASE_REGISTRY_COMMIT,
                    now=NOW,
                    consumer=RecordingConsumer(),
                )
                contract = trust.TARGET_CONTRACTS[target]
                self.assertEqual(release["target"], target)
                self.assertEqual(release["claim_scope"], contract["claim_scope"])
                self.assertEqual(
                    release["release"]["source_repository"], contract["repository"]
                )
                self.assertEqual(
                    release["release"]["source_repository_id"],
                    contract["repository_id"],
                )
                self.assertEqual(
                    release["release"]["kind"], contract["release_kind"]
                )
                self.assertEqual(
                    release["expires_at"], workflow_admission["expires_at"]
                )
                release_reference, release_bundle_reference = reference_pair(
                    "qualification-release",
                    release,
                    registry_source_commit=RELEASE_REGISTRY_COMMIT,
                )
                summary = resolver.objects[
                    request["production_acceptance_summary_reference"][
                        "object_sha256"
                    ]
                ]["value"]
                verification = release_verifier.verification_receipt(
                    admission=release,
                    admission_reference=release_reference,
                    admission_bundle_reference=release_bundle_reference,
                    summary=summary,
                    qualification_admission=workflow_admission,
                    verified_at=NOW,
                    trust_state_source_commit=RELEASE_REGISTRY_COMMIT,
                )
                self.assertEqual(verification["target"], target)
                self.assertEqual(
                    verification["source_repository"], contract["repository"]
                )
                self.assertEqual(
                    verification["workflow_bundle_sha256"],
                    workflow_admission["bundle_sha256"],
                )

    def test_verifier_closes_package_deployment_and_hybrid_caller_identity(
        self,
    ) -> None:
        cases = {
            "package": {
                "version": "1.2.3",
                "tag": "v1.2.3",
                "deployment_id": None,
                "deployment_sha256": None,
            },
            "deployment": {
                "version": None,
                "tag": None,
                "deployment_id": "42",
                "deployment_sha256": sha("deployment"),
            },
            "hybrid": {
                "version": "1.2.3",
                "tag": "v1.2.3",
                "deployment_id": "42",
                "deployment_sha256": sha("hybrid-deployment"),
            },
        }
        for kind, identity in cases.items():
            with self.subTest(kind=kind):
                release = {
                    "kind": kind,
                    "source_repository": "OpenAdaptAI/example",
                    "source_repository_id": "100",
                    "source_commit": "a" * 40,
                    **identity,
                }
                args = argparse.Namespace(
                    expected_repository=release["source_repository"],
                    expected_repository_id=release["source_repository_id"],
                    expected_source_commit=release["source_commit"],
                    expected_version=identity["version"] or "",
                    expected_tag=identity["tag"] or "",
                    expected_deployment_id=identity["deployment_id"] or "",
                    expected_deployment_sha256=(
                        identity["deployment_sha256"] or ""
                    ),
                )
                expected, actual = release_verifier.caller_release_identity(
                    args, release, target="flow"
                )
                self.assertEqual(expected, actual)
                args.expected_source_commit = "b" * 40
                expected, actual = release_verifier.caller_release_identity(
                    args, release, target="flow"
                )
                self.assertNotEqual(expected, actual)

    def test_verifier_refuses_incomplete_caller_identity(self) -> None:
        release = {
            "kind": "deployment",
            "source_repository": "OpenAdaptAI/openadapt-cloud",
            "source_repository_id": "1300570990",
            "source_commit": "a" * 40,
            "version": None,
            "tag": None,
            "deployment_id": "42",
            "deployment_sha256": sha("deployment"),
        }
        args = argparse.Namespace(
            expected_repository=release["source_repository"],
            expected_repository_id=release["source_repository_id"],
            expected_source_commit=release["source_commit"],
            expected_version="",
            expected_tag="",
            expected_deployment_id="",
            expected_deployment_sha256=release["deployment_sha256"],
        )
        with self.assertRaisesRegex(trust.TrustError, "deployment identity"):
            release_verifier.caller_release_identity(args, release, target="cloud")

    def test_closed_flow_release_verification_receipt_matches_fixture(self) -> None:
        fixture = trust_fixture()
        resolver = RecordingResolver(fixture)
        admission = issuer.issue_workflow_admission(
            workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        request = flow_release_inputs(fixture, admission, resolver)
        release = issuer.issue_release_admission(
            request,
            resolver=resolver,
            issuer_source_commit=RELEASE_REGISTRY_COMMIT,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        release_reference, release_bundle_reference = reference_pair(
            "qualification-release",
            release,
            registry_source_commit=RELEASE_REGISTRY_COMMIT,
        )
        summary = resolver.objects[
            request["production_acceptance_summary_reference"]["object_sha256"]
        ]["value"]
        verification = release_verifier.verification_receipt(
            admission=release,
            admission_reference=release_reference,
            admission_bundle_reference=release_bundle_reference,
            summary=summary,
            qualification_admission=admission,
            verified_at=NOW,
            trust_state_source_commit=RELEASE_REGISTRY_COMMIT,
        )
        expected = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "remote-safe-synthetic-flow-release-verification.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(verification, expected)
        projection = dict(verification)
        verification_id = projection.pop("verification_id_sha256")
        self.assertEqual(
            verification_id,
            trust.digest_bytes(
                release_verifier.VERIFICATION_RECEIPT_DOMAIN, projection
            ),
        )
        self.assertEqual(verification["evidence_class"], "remote-safe-synthetic")
        self.assertEqual(verification["target"], "flow")
        self.assertEqual(verification["claim_scope"], "production_flow")

    def test_release_refuses_signed_nested_bundle_other_than_verified_pair(
        self,
    ) -> None:
        fixture = trust_fixture()
        resolver = RecordingResolver(fixture)
        admission = issuer.issue_workflow_admission(
            workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit=WORKFLOW_REGISTRY_COMMIT,
            now=NOW,
            consumer=RecordingConsumer(),
        )
        fake_bundle = copy.deepcopy(admission["decision_receipt_bundle_reference"])
        fake_bundle_sha256 = sha("unregistered-receipt-bundle")
        digest_hex = fake_bundle_sha256.removeprefix("sha256:")
        fake_bundle.update(
            object_path=(
                f"production-evidence/objects/sha256/{digest_hex[:2]}/"
                f"{digest_hex}.qualification-evidence-decision-receipt-"
                "sigstore-bundle.json"
            ),
            object_sha256=fake_bundle_sha256,
            size_bytes=101,
            semantic_identity_sha256=evidence.semantic_identity_digest(
                kind="qualification-evidence-decision-receipt-sigstore-bundle",
                object_schema_version=evidence.BUNDLE_MEDIA_TYPE,
                object_value=fixture["receipt_ref"]["object_sha256"],
                object_sha256=fake_bundle_sha256,
            ),
        )
        entry = {
            key: fake_bundle[key]
            for key in (
                "kind",
                "object_schema_version",
                "object_path",
                "object_sha256",
                "size_bytes",
                "object_media_type",
                "semantic_identity_sha256",
                "subject_sha256",
            )
        }
        fake_bundle["registry_entry_sha256"] = evidence.entry_digest(entry)
        admission["decision_receipt_bundle_reference"] = fake_bundle
        projection = dict(admission)
        projection.pop("admission_id_sha256")
        admission["admission_id_sha256"] = trust.digest_bytes(
            trust.ADMISSION_DOMAIN, projection
        )
        request = flow_release_inputs(fixture, admission, resolver)
        with self.assertRaisesRegex(
            issuer.IssuerError,
            "nested reference differs from the verified pair",
        ):
            issuer.issue_release_admission(
                request,
                resolver=resolver,
                issuer_source_commit=RELEASE_REGISTRY_COMMIT,
                now=NOW,
                consumer=RecordingConsumer(),
            )

    def test_sqlite_effect_commit_is_atomic_and_reconcilable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            consumer = issuer.SqliteOneUseConsumer(Path(temporary) / "effects.sqlite3")
            values = {
                "request_handle": "qair_" + "Z" * 43,
                "operation": "issue-qualification-admission",
                "request_sha256": sha("request"),
                "effect_sha256": sha("effect"),
                "result": b'{"result":"accepted"}\n',
            }
            consumer.commit_once(**values)
            record = consumer.reconcile(request_handle=values["request_handle"])
            self.assertEqual(record["retry_policy"], "reconcile-never-retry")
            self.assertEqual(
                base64.b64decode(record["result_base64"]), values["result"]
            )
            with self.assertRaisesRegex(issuer.IssuerError, "already consumed"):
                consumer.commit_once(**values)
            alternate_handle = dict(values)
            alternate_handle["request_handle"] = "qair_" + "Y" * 43
            with self.assertRaisesRegex(issuer.IssuerError, "already consumed"):
                consumer.commit_once(**alternate_handle)
            with sqlite3.connect(consumer.database) as connection:
                connection.execute(
                    "UPDATE one_use_effects SET result = ? WHERE request_handle = ?",
                    (b'{"result":"different"}\n', values["request_handle"]),
                )
                connection.commit()
            with self.assertRaisesRegex(
                issuer.IssuerError, "stored one-use result binding differs"
            ):
                consumer.reconcile(request_handle=values["request_handle"])


if __name__ == "__main__":
    unittest.main()
