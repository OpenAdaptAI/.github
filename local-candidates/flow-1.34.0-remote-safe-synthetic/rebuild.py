#!/usr/bin/env python3
"""Build unpublished Flow 1.34.0 remote-safe-synthetic admission objects.

Reads the founder-provisioned Keychain item openadapt-qualification-ed25519.
Does not print the private key. Does not generate a key. Does not write main.

The campaign_summary is synthetic (1 cell x 3 trials per class). It is not the
MockMed 1.34.0 evals set. evals production_acceptance stays false.

If validate_staging still requires tag exists:false, this script stops before
acceptance/release objects and does not fake a draft as openadapt-release[bot].
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import inspect
import json
import secrets
import sqlite3
import string
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import public_trust_kms as public_trust  # noqa: E402
import qualification_issuer as issuer  # noqa: E402
import qualification_software_ed25519 as software  # noqa: E402
import validate_evidence_registry as evidence  # noqa: E402

EXPECTED_INNER_KEY_ID = "qa-ed25519-9cf4bca214c01d79"
FLOW_VERSION = "1.34.0"
FLOW_TAG = "v1.34.0"
FLOW_SOURCE = "30fc60e55778a0e0f92b9776117cafcfe2512249"
WHEEL_SHA256 = "56d32818989cb3a92830080ead39e10b08718c55e00988117f22cbfeaac98854"
WHEEL_SIZE = 1928194
SDIST_SHA256 = "a941a70015fe91897e655bfc9bf83e6cf8fbcf8bd4e4c7206ffb133c505203f8"
SDIST_SIZE = 20440838
WHEEL_NAME = "openadapt_flow-1.34.0-py3-none-any.whl"
SDIST_NAME = "openadapt_flow-1.34.0.tar.gz"
POLICY_COMMIT = "d8a2d5d76344e36dd51504166dc751d9c3091b74"
OPS_COMMIT = "e323249e3a7c1af9d7651312e0afe1f12c38c977"
SYNTHETIC_DOMAIN = b"OpenAdapt remote-safe-synthetic flow 1.34.0 local candidate v1\0"
EXPECTED_PUBLIC_KEY = "vHPUDLG2WD2BnTLaKYnZd9GxvUKfjpd68gJ9HubIEH8"


def campaign_classes() -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
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


def ts(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SystemExit("timestamp must use UTC")
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def labeled(name: str) -> str:
    return trust.digest_bytes(
        SYNTHETIC_DOMAIN,
        {
            "label": "remote-safe-synthetic",
            "flow_version": FLOW_VERSION,
            "name": name,
            "mockmed_1_34_0_evals_set_is_this_summary": False,
            "evals_production_acceptance": False,
        },
    )


def write_json(path: Path, value: Any) -> bytes:
    raw = evidence.canonical(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def object_rel(kind: str, object_sha256: str) -> str:
    digest_hex = object_sha256.removeprefix("sha256:")
    return (
        f"production-evidence/objects/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.{kind}.json"
    )


def signer_rel(object_sha256: str) -> str:
    digest_hex = object_sha256.removeprefix("sha256:")
    return (
        f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.qualification-signer-registry.json"
    )


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def request_handle() -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "qair_" + "".join(secrets.choice(alphabet) for _ in range(43))


def inspect_days(fn: Any, fallback: int = 7) -> int:
    source = inspect.getsource(fn)
    if "timedelta(days=30)" in source and "timedelta(days=7)" not in source:
        return 30
    if "timedelta(days=30)" in source:
        return 30 if "seven days" not in source.lower() else fallback
    return fallback


def detect_windows(inner: dict[str, Any], outer: dict[str, Any], now: datetime) -> dict[str, int]:
    registry_days = 7
    for days in (30, 7):
        probe = {
            "schema_version": "openadapt.qualification-signer-registry/v2",
            "revision": 1,
            "generated_at": ts(now),
            "expires_at": ts(now + timedelta(days=days)),
            "signers": [inner, outer],
        }
        try:
            evidence.validate_signer_registry(probe)
            registry_days = days
            break
        except evidence.EvidenceRegistryError:
            continue
    receipt_days = 7
    source = inspect.getsource(trust.validate_authority_state)
    if "timedelta(days=30)" in source:
        receipt_days = 30
    workflow_days = 7
    issuer_source = inspect.getsource(issuer.issue_workflow_admission)
    if "timedelta(days=30)" in issuer_source and "timedelta(days=7)" not in issuer_source:
        workflow_days = 30
    return {
        "registry": registry_days,
        "receipt": receipt_days,
        "workflow": workflow_days,
    }


def sign_embedded(
    value: dict[str, Any],
    private_key: Any,
    *,
    schema: str,
    domain: bytes,
) -> None:
    value["signing_statement"] = trust.signing_statement(
        value, object_schema_version=schema, signature_domain=domain
    )
    payload = trust.canonical(value["signing_statement"]) + b"\n"
    value["signature"] = base64.b64encode(private_key.sign(payload)).decode("ascii")


def make_inner(material: dict[str, str]) -> dict[str, Any]:
    signer = software.signer_from_public_material(material)
    signer["allowed_usages"] = sorted(
        {
            "qualification-authority-state-receipt",
            "qualification-evidence-decision-receipt",
            "qualification-revocation-state-receipt",
        }
    )
    signer["allowed_workflows"] = sorted(
        {
            (
                "https://github.com/OpenAdaptAI/.github/.github/workflows/"
                "issue-synthetic-qualification-evidence-decision.yml@refs/heads/main"
            ),
            (
                "https://github.com/OpenAdaptAI/openadapt-ops/.github/workflows/"
                "qualification-authority-state.yml@refs/heads/main"
            ),
            (
                "https://github.com/OpenAdaptAI/openadapt-ops/.github/workflows/"
                "qualification-revocation-state.yml@refs/heads/main"
            ),
        }
    )
    return signer


def make_entry(kind: str, raw: bytes, value: Any) -> dict[str, Any]:
    object_sha256 = sha256_bytes(raw)
    schema, media = evidence.OBJECT_KIND_CONTRACTS[kind]
    if kind.endswith("-sigstore-bundle"):
        identity_value = value
    else:
        identity_value = value
    entry = {
        "kind": kind,
        "object_schema_version": schema if not kind.endswith("-sigstore-bundle") else evidence.BUNDLE_MEDIA_TYPE,
        "object_path": object_rel(kind, object_sha256),
        "object_sha256": object_sha256,
        "size_bytes": len(raw),
        "object_media_type": media,
        "semantic_identity_sha256": evidence.semantic_identity_digest(
            kind=kind,
            object_schema_version=(
                evidence.BUNDLE_MEDIA_TYPE
                if kind.endswith("-sigstore-bundle")
                else schema
            ),
            object_value=identity_value,
            object_sha256=object_sha256,
        ),
        "subject_sha256": (
            None if not kind.endswith("-sigstore-bundle") else identity_value
        ),
    }
    entry["registry_entry_sha256"] = evidence.entry_digest(entry)
    return entry


def reference_from_entry(
    entry: dict[str, Any],
    *,
    registry_source_commit: str,
    registry_revision: int,
    registry_head_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": registry_source_commit,
        "registry_revision": registry_revision,
        "registry_head_sha256": registry_head_sha256,
        **entry,
    }


class LocalResolver:
    def __init__(self, registry: dict[str, Any]) -> None:
        self.registry = registry
        self.objects: dict[str, issuer.ResolvedEvidence] = {}
        self.authority: issuer.ResolvedEvidence | None = None
        self.revocation: issuer.ResolvedEvidence | None = None

    def add(
        self,
        kind: str,
        value: dict[str, Any],
        reference: dict[str, Any],
        bundle_reference: dict[str, Any],
    ) -> issuer.ResolvedEvidence:
        resolved: issuer.ResolvedEvidence = {
            "value": value,
            "reference": reference,
            "bundle_reference": bundle_reference,
            "bound_signer_registry": self.registry,
            "current_signer_registry": self.registry,
        }
        self.objects[reference["object_sha256"]] = resolved
        return resolved

    def resolve(self, reference: dict[str, Any], *, kind: str) -> issuer.ResolvedEvidence:
        resolved = self.objects[reference["object_sha256"]]
        if resolved["reference"] != reference or reference["kind"] != kind:
            raise issuer.IssuerError("local resolver reference differs")
        return resolved

    def current_trust_state(
        self, *, registry_source_commit: str
    ) -> tuple[issuer.ResolvedEvidence, issuer.ResolvedEvidence]:
        if self.authority is None or self.revocation is None:
            raise issuer.IssuerError("current authority or revocation receipt is absent")
        return self.authority, self.revocation


def dsse_bundle(
    *,
    private_key: Any,
    signer: dict[str, Any],
    kind: str,
    value: dict[str, Any],
    raw: bytes,
    now: datetime,
    expires: datetime,
    registry_sha256: str,
    authority_state_sha256: str,
    revocation_state_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    schema, media = evidence.OBJECT_KIND_CONTRACTS[kind]
    semantic = evidence.semantic_identity_digest(
        kind=kind,
        object_schema_version=schema,
        object_value=value,
        object_sha256=sha256_bytes(raw),
    )
    issuer_fields = {
        field: value["issuer"][field] for field in public_trust.ISSUER_FIELDS
    }
    statement = {
        "schema_version": public_trust.STATEMENT_SCHEMA,
        "object_kind": kind,
        "object_schema_version": schema,
        "object_media_type": media,
        "object_sha256": sha256_bytes(raw),
        "object_size_bytes": len(raw),
        "semantic_identity_sha256": semantic,
        "source_issuer": issuer_fields,
        "signer_registry_sha256": registry_sha256,
        "authority_state_sha256": authority_state_sha256,
        "revocation_state_sha256": revocation_state_sha256,
        "issued_at": ts(now),
        "not_before": ts(now),
        "expires_at": ts(expires),
        "request_id_sha256": labeled(f"dsse-request:{kind}"),
        "signing_authority": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": public_trust.SOFTWARE_WORKFLOW_PATH,
            "ref": "refs/heads/main",
            "source_commit": source_commit,
            "environment": public_trust.SOFTWARE_ENVIRONMENT,
            "key_origin": "software",
        },
        "key_id": signer["key_id"],
        "signature_profile": public_trust.SOFTWARE_SIGNATURE_PROFILE,
    }
    public_trust.validate_statement_object_binding(
        statement,
        object_raw=raw,
        object_value=value,
        object_kind=kind,
        object_schema_version=schema,
        object_media_type=media,
        semantic_identity_sha256=semantic,
        expected_signer_registry_sha256=registry_sha256,
        expected_authority_state_sha256=authority_state_sha256,
        expected_revocation_state_sha256=revocation_state_sha256,
    )
    return public_trust.sign_software_bundle(
        statement, private_key=private_key, signer=signer, now=now
    )


def unsigned_inventory() -> dict[str, Any]:
    artifacts = [
        {
            "name": SDIST_NAME,
            "kind": "python-sdist",
            "sha256": "sha256:" + SDIST_SHA256,
            "size_bytes": SDIST_SIZE,
            "media_type": "application/gzip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": WHEEL_NAME,
            "kind": "python-wheel",
            "sha256": "sha256:" + WHEEL_SHA256,
            "size_bytes": WHEEL_SIZE,
            "media_type": "application/zip",
            "publish_destinations": ["github-release", "pypi"],
        },
    ]
    artifacts = sorted(artifacts, key=lambda item: (item["kind"], item["name"], item["sha256"]))
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": "flow",
        "claim_scope": "production_flow",
        "artifacts": artifacts,
    }
    return trust.validate_artifact_inventory(inventory)


def staging_blocked_record() -> dict[str, Any]:
    honest = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "draft_release_id": "1",
        "tag": FLOW_TAG,
        "target_commitish": FLOW_SOURCE,
        "draft": False,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": [],
        "immutable_releases": {"enabled": True, "enforced_by_owner": False},
        "immutable_releases_sha256": "sha256:" + "0" * 64,
        "tag_rulesets": [],
        "tag_rulesets_sha256": "sha256:" + "0" * 64,
        "tag_ref_state": {"ref": f"refs/tags/{FLOW_TAG}", "exists": True},
        "tag_ref_state_sha256": "sha256:" + "0" * 64,
        "observed_at": ts(datetime.now(timezone.utc)),
    }
    error = None
    try:
        trust.validate_staging(honest)
    except trust.TrustError as exc:
        error = str(exc)
    exists_false_required = False
    if error and "must not exist" in error:
        exists_false_required = True
    elif error is None:
        exists_false_required = False
    else:
        exists_false_required = "exists" in error or "draft" in error or "differ" in error
    return {
        "live_tag": FLOW_TAG,
        "live_tag_exists": True,
        "live_release_is_draft": False,
        "live_release_author": "openadapt-release[bot]",
        "live_pypi": True,
        "validate_staging_error_on_honest_published_release": error,
        "validate_staging_requires_exists_false": exists_false_required or (
            error == "release tag must not exist when the draft is staged"
        ),
        "did_not_fake_draft_as_openadapt_release_bot": True,
        "acceptance_manifest_issued": False,
        "acceptance_summary_issued": False,
        "release_admission_issued": False,
        "evals_production_acceptance": False,
        "mockmed_1_34_0_evals_set_is_this_summary": False,
    }


def load_receipts(out: Path) -> dict[str, Any]:
    return json.loads((out / "phase1-state.json").read_text(encoding="utf-8"))


def build_phase1(out: Path, *, private_key: Any, now: datetime) -> dict[str, Any]:
    material = software.public_material(private_key)
    if material["key_id"] != EXPECTED_INNER_KEY_ID:
        raise SystemExit(
            f"Keychain public key id is {material['key_id']}, not {EXPECTED_INNER_KEY_ID}"
        )
    if material["public_key"] != EXPECTED_PUBLIC_KEY:
        raise SystemExit("Keychain public key does not match the provisioned inner key")
    write_json(out / "public-material.json", material)

    inner = make_inner(material)
    outer = public_trust.software_public_signer(private_key.public_key())
    windows = detect_windows(inner, outer, now)
    registry_days = windows["registry"]
    receipt_days = min(windows["receipt"], windows["registry"])
    generated = now.replace(microsecond=0)
    registry_expires = generated + timedelta(days=registry_days)
    receipt_expires = generated + timedelta(days=receipt_days)

    unsigned_local = software.unsigned_local_registry_candidate(
        public_material_value=material, revision=1
    )
    local_candidate = software.verify_local_registry_candidate(
        software.sign_local_registry_candidate(unsigned_local, private_key=private_key)
    )
    write_json(out / "signer-registry-local-candidate.json", local_candidate)

    timed_candidate = None
    timed_error = None
    try:
        timed_candidate = software.signer_registry_candidate(
            public_material_value=material,
            revision=1,
            generated_at=generated,
            expires_at=generated + timedelta(days=30),
        )
    except software.SoftwareEd25519Error as exc:
        timed_error = str(exc)
        timed_candidate = software.signer_registry_candidate(
            public_material_value=material,
            revision=1,
            generated_at=generated,
            expires_at=registry_expires,
        )
    if timed_candidate is not None:
        timed_candidate["proposed_registry"]["signers"] = [inner, outer]
        timed_candidate["proposed_registry"] = evidence.validate_signer_registry(
            timed_candidate["proposed_registry"]
        )
        write_json(out / "signer-registry-candidate.json", timed_candidate)

    registry = {
        "schema_version": "openadapt.qualification-signer-registry/v2",
        "revision": 1,
        "generated_at": ts(generated),
        "expires_at": ts(registry_expires),
        "signers": [inner, outer],
    }
    registry = evidence.validate_signer_registry(registry)
    registry_raw = write_json(out / "signer-registry.json", registry)
    registry_raw_sha256 = sha256_bytes(registry_raw)
    registry_identity = evidence.signer_registry_identity_digest(registry)
    write_json(out / signer_rel(registry_raw_sha256).replace("production-evidence/", "production-evidence/"), registry)
    signer_path = out / signer_rel(registry_raw_sha256)
    signer_path.parent.mkdir(parents=True, exist_ok=True)
    signer_path.write_bytes(registry_raw)

    evidence_authority = labeled("evidence-authority")
    authority = {
        "schema_version": "openadapt.qualification-authority-state-receipt/v2",
        "authority_state_sha256": labeled("placeholder-authority"),
        "status": "active",
        "signer_registry_sha256": registry_raw_sha256,
        "signer_registry_identity_sha256": registry_identity,
        "signer_registry_revision": 1,
        "evidence_authority_sha256": evidence_authority,
        "observed_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": ts(receipt_expires),
        "issuer_key_id": inner["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-authority-state.yml",
            "ref": "refs/heads/main",
            "source_commit": OPS_COMMIT,
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
        private_key,
        schema="openadapt.qualification-authority-state-receipt/v2",
        domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
    )
    trust.validate_authority_state(authority, now=now)
    trust.verify_embedded_signature(
        authority,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-authority-state-receipt/v2",
        signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
        usage="qualification-authority-state-receipt",
        now=now,
    )

    revocation = {
        "schema_version": "openadapt.qualification-revocation-state-receipt/v1",
        "revocation_state_sha256": labeled("placeholder-revocation"),
        "previous_revocation_state_sha256": None,
        "revision": 1,
        "status": "current",
        "authority_state_sha256": authority["authority_state_sha256"],
        "signer_registry_sha256": registry_identity,
        "revocations": [],
        "observed_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": ts(receipt_expires),
        "issuer_key_id": inner["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-revocation-state.yml",
            "ref": "refs/heads/main",
            "source_commit": OPS_COMMIT,
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
        private_key,
        schema="openadapt.qualification-revocation-state-receipt/v1",
        domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
    )
    trust.validate_revocation_state(revocation, now=now)
    trust.verify_embedded_signature(
        revocation,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-revocation-state-receipt/v1",
        signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
        usage="qualification-revocation-state-receipt",
        now=now,
    )

    summary = {
        "schema_version": "openadapt.qualification-evidence-decision-campaign-summary/v1",
        "minimum_trials_per_task_condition": 3,
        "task_count": 1,
        "classes": campaign_classes(),
    }
    unsigned_receipt = {
        "schema_version": "openadapt.qualification-evidence-decision-receipt/v2",
        "evidence_class": "remote-safe-synthetic",
        "decision_identity_sha256": labeled("decision-series"),
        "decision_revision": 1,
        "decision_commitment_sha256": labeled("decision"),
        "evidence_manifest_sha256": labeled("evidence-manifest"),
        "evidence_manifest_readback_sha256": labeled("manifest-readback"),
        "campaign_artifact_sha256": labeled("campaign-artifact"),
        "organization_id_sha256": labeled("organization"),
        "workflow_id_sha256": labeled("workflow"),
        "workflow_version_id_sha256": labeled("workflow-version"),
        "bundle_version": "0.0.0-synthetic",
        "bundle_sha256": labeled("sealed-workflow-bundle"),
        "admitted_runtime_sha256": "sha256:" + WHEEL_SHA256,
        "application_contract_sha256": labeled("application-contract"),
        "environment_contract_sha256": labeled("environment-contract"),
        "input_contract_sha256": labeled("input-contract"),
        "action_contract_sha256": labeled("action-contract"),
        "identity_contract_sha256": labeled("identity-contract"),
        "effect_contract_sha256": labeled("effect-contract"),
        "policy_contract_sha256": labeled("policy-contract"),
        "evidence_authority_contract_sha256": evidence_authority,
        "campaign_permit_sha256": labeled("campaign-permit"),
        "signer_registry_sha256": registry_identity,
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "entity_class": "record",
        "campaign_summary": summary,
        "verdict": "ADMIT",
        "issued_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": ts(receipt_expires),
        "issuer_key_id": inner["key_id"],
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
            "source_commit": POLICY_COMMIT,
            "environment": "synthetic-qualification-evidence-decision",
        },
    }
    receipt = software.sign_receipt(
        unsigned_receipt, private_key=private_key, signer_registry=registry
    )
    trust.validate_receipt(receipt, signer_registry=registry, now=now)

    inventory = unsigned_inventory()
    write_json(out / "artifact-inventory.json", inventory)

    objects: dict[str, tuple[str, dict[str, Any], bytes]] = {}
    authority_raw = evidence.canonical(authority) + b"\n"
    revocation_raw = evidence.canonical(revocation) + b"\n"
    receipt_raw = evidence.canonical(receipt) + b"\n"
    objects["qualification-authority-state-receipt"] = (
        "qualification-authority-state-receipt",
        authority,
        authority_raw,
    )
    objects["qualification-revocation-state-receipt"] = (
        "qualification-revocation-state-receipt",
        revocation,
        revocation_raw,
    )
    objects["qualification-evidence-decision-receipt"] = (
        "qualification-evidence-decision-receipt",
        receipt,
        receipt_raw,
    )

    bundles: dict[str, dict[str, Any]] = {}
    for kind, value, raw in objects.values():
        if kind == "qualification-authority-state-receipt":
            statement_registry = value["signer_registry_sha256"]
        else:
            statement_registry = value["signer_registry_sha256"]
        bundles[kind] = dsse_bundle(
            private_key=private_key,
            signer=outer,
            kind=kind,
            value=value,
            raw=raw,
            now=generated,
            expires=receipt_expires,
            registry_sha256=statement_registry,
            authority_state_sha256=authority["authority_state_sha256"],
            revocation_state_sha256=revocation["revocation_state_sha256"],
            source_commit=POLICY_COMMIT,
        )

    entries: list[dict[str, Any]] = []
    for kind, value, raw in objects.values():
        path = out / object_rel(kind, sha256_bytes(raw))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        write_json(out / f"{kind}.json", value)
        regular_entry = make_entry(kind, raw, value)
        bundle = bundles[kind]
        bundle_raw = evidence.canonical(bundle) + b"\n"
        bundle_kind = f"{kind}-sigstore-bundle"
        bundle_path = out / object_rel(bundle_kind, sha256_bytes(bundle_raw))
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(bundle_raw)
        write_json(out / f"{bundle_kind}.json", bundle)
        bundle_entry = make_entry(
            bundle_kind, bundle_raw, sha256_bytes(raw)
        )
        entries.append(regular_entry)
        entries.append(bundle_entry)

    signer_pointer = {
        "schema_version": evidence.SIGNER_POINTER_SCHEMA,
        "object_path": signer_rel(registry_raw_sha256),
        "object_sha256": registry_raw_sha256,
        "registry_identity_sha256": registry_identity,
        "registry_revision": 1,
    }
    local_registry = {
        "$schema": "schemas/evidence-registry.schema.json",
        "schema_version": evidence.REGISTRY_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "revision": 1,
        "previous_registry_head_sha256": None,
        "registry_head_sha256": "sha256:" + "0" * 64,
        "signer_registry": signer_pointer,
        "signer_registry_history": [signer_pointer],
        "entries": entries,
    }
    local_registry["registry_head_sha256"] = evidence.registry_head_digest(local_registry)
    evidence.validate_registry(local_registry, root=out)
    write_json(out / "evidence-registry.json", local_registry)

    blocked = staging_blocked_record()
    write_json(out / "staging-blocked.json", blocked)

    state = {
        "generated_at": ts(generated),
        "registry_days": registry_days,
        "receipt_days": receipt_days,
        "workflow_days": windows["workflow"],
        "timed_candidate_30_day_error": timed_error,
        "registry_raw_sha256": registry_raw_sha256,
        "registry_identity": registry_identity,
        "registry_head_sha256": local_registry["registry_head_sha256"],
        "registry_revision": 1,
        "authority_state_sha256": authority["authority_state_sha256"],
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "inner_key_id": inner["key_id"],
        "outer_key_id": outer["key_id"],
        "windows": windows,
        "campaign_label": "remote-safe-synthetic",
        "mockmed_1_34_0_evals_set_is_this_summary": False,
        "evals_production_acceptance": False,
        "staging": blocked,
        "policy_commit": POLICY_COMMIT,
        "flow_source": FLOW_SOURCE,
        "wheel_sha256": WHEEL_SHA256,
        "sdist_sha256": SDIST_SHA256,
    }
    write_json(out / "phase1-state.json", state)
    return state


def build_phase2(
    out: Path,
    *,
    private_key: Any,
    now: datetime,
    registry_source_commit: str,
) -> dict[str, Any]:
    state = load_receipts(out)
    registry = json.loads((out / "signer-registry.json").read_text(encoding="utf-8"))
    authority = json.loads(
        (out / "qualification-authority-state-receipt.json").read_text(encoding="utf-8")
    )
    revocation = json.loads(
        (out / "qualification-revocation-state-receipt.json").read_text(encoding="utf-8")
    )
    receipt = json.loads(
        (out / "qualification-evidence-decision-receipt.json").read_text(encoding="utf-8")
    )
    local_registry = json.loads(
        (out / "evidence-registry.json").read_text(encoding="utf-8")
    )
    authority_bundle = json.loads(
        (out / "qualification-authority-state-receipt-sigstore-bundle.json").read_text(
            encoding="utf-8"
        )
    )
    revocation_bundle = json.loads(
        (out / "qualification-revocation-state-receipt-sigstore-bundle.json").read_text(
            encoding="utf-8"
        )
    )
    receipt_bundle = json.loads(
        (out / "qualification-evidence-decision-receipt-sigstore-bundle.json").read_text(
            encoding="utf-8"
        )
    )
    head = local_registry["registry_head_sha256"]
    revision = local_registry["revision"]
    entries_by_kind = {entry["kind"]: entry for entry in local_registry["entries"]}

    resolver = LocalResolver(registry)
    resolver.authority = resolver.add(
        "qualification-authority-state-receipt",
        authority,
        reference_from_entry(
            entries_by_kind["qualification-authority-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            entries_by_kind["qualification-authority-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    resolver.revocation = resolver.add(
        "qualification-revocation-state-receipt",
        revocation,
        reference_from_entry(
            entries_by_kind["qualification-revocation-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            entries_by_kind["qualification-revocation-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    receipt_ref = reference_from_entry(
        entries_by_kind["qualification-evidence-decision-receipt"],
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    receipt_bundle_ref = reference_from_entry(
        entries_by_kind["qualification-evidence-decision-receipt-sigstore-bundle"],
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    resolver.add(
        "qualification-evidence-decision-receipt",
        receipt,
        receipt_ref,
        receipt_bundle_ref,
    )

    handle = request_handle()
    request = {
        "schema_version": "openadapt.qualification-admission-issue-request/v1",
        "request_handle": handle,
        "evidence_class": "remote-safe-synthetic",
        "decision_receipt_reference": receipt_ref,
    }
    db_path = out / "one-use-effects.sqlite"
    if db_path.exists():
        db_path.unlink()
    consumer = issuer.SqliteOneUseConsumer(db_path)
    admission = issuer.issue_workflow_admission(
        request,
        resolver=resolver,
        issuer_source_commit=registry_source_commit,
        now=now,
        consumer=consumer,
    )
    trust.validate_qualification_admission(admission, now=now)
    effect = consumer.reconcile(request_handle=handle)
    write_json(out / "qualification-admission.json", admission)
    write_json(out / "one-use-effect.json", effect)

    outer = public_trust.software_public_signer(private_key.public_key())
    admission_raw = evidence.canonical(admission) + b"\n"
    generated = datetime.strptime(state["generated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    receipt_expires = generated + timedelta(days=state["receipt_days"])
    admission_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="qualification-admission",
        value=admission,
        raw=admission_raw,
        now=now.replace(microsecond=0),
        expires=min(now.replace(microsecond=0) + timedelta(days=state["workflow_days"]), receipt_expires),
        registry_sha256=admission["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=POLICY_COMMIT,
    )
    path = out / object_rel("qualification-admission", sha256_bytes(admission_raw))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(admission_raw)
    bundle_raw = evidence.canonical(admission_bundle) + b"\n"
    bundle_kind = "qualification-admission-sigstore-bundle"
    bundle_path = out / object_rel(bundle_kind, sha256_bytes(bundle_raw))
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_bytes(bundle_raw)
    write_json(out / f"{bundle_kind}.json", admission_bundle)

    write_json(
        out / "workflow-issue-request.json",
        request,
    )
    return {
        "request_handle": handle,
        "admission_id_sha256": admission["admission_id_sha256"],
        "registry_source_commit": registry_source_commit,
        "expires_at": admission["expires_at"],
    }


def write_build_record(out: Path, extra: dict[str, Any]) -> None:
    state_path = out / "phase1-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    record = {
        "schema_version": "openadapt.local-flow-134-admission-build-record/v1",
        "target": "flow",
        "flow_version": FLOW_VERSION,
        "flow_tag": FLOW_TAG,
        "flow_source": FLOW_SOURCE,
        "evidence_class": "remote-safe-synthetic",
        "campaign": {
            "label": "remote-safe-synthetic",
            "task_count": 1,
            "cells_per_class": 1,
            "trials_per_cell": 3,
            "classes": list(trust.CAMPAIGN_CLASSES),
            "mockmed_1_34_0_evals_set_is_this_summary": False,
        },
        "evals_production_acceptance": False,
        "keychain_service": software.KEYCHAIN_SERVICE,
        "inner_key_id": EXPECTED_INNER_KEY_ID,
        "did_not_generate_key": True,
        "policy_commit": POLICY_COMMIT,
        "thirty_day_policy_merged": False,
        **state,
        **extra,
    }
    write_json(out / "build-record.json", record)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(HERE))
    parser.add_argument("--admit")
    args = parser.parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    private_key = software.load_private_key_from_sources(
        pem_file=None, use_keychain=True, use_env=False
    )
    material = software.public_material(private_key)
    if material["key_id"] != EXPECTED_INNER_KEY_ID:
        print(
            f"REFUSED: Keychain key id {material['key_id']} != {EXPECTED_INNER_KEY_ID}",
            file=sys.stderr,
        )
        return 1
    if args.admit:
        phase2 = build_phase2(
            out,
            private_key=private_key,
            now=now,
            registry_source_commit=args.admit,
        )
        write_build_record(
            out,
            {
                "phase": "admission",
                "workflow_admission": phase2,
                "release_admission_issued": False,
            },
        )
        print(json.dumps({"phase": "admission", **phase2}, sort_keys=True))
        return 0
    state = build_phase1(out, private_key=private_key, now=now)
    write_build_record(
        out,
        {
            "phase": "receipts",
            "workflow_admission": None,
            "release_admission_issued": False,
        },
    )
    print(
        json.dumps(
            {
                "phase": "receipts",
                "inner_key_id": state["inner_key_id"],
                "outer_key_id": state["outer_key_id"],
                "registry_days": state["registry_days"],
                "receipt_days": state["receipt_days"],
                "timed_candidate_30_day_error": state["timed_candidate_30_day_error"],
                "staging_requires_exists_false": state["staging"][
                    "validate_staging_requires_exists_false"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
