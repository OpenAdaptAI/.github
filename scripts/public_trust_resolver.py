"""Resolve and verify one content-addressed public-trust object pair."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import public_trust_kms as kms
import validate_evidence_registry as evidence


class PublicTrustResolutionError(ValueError):
    """The reference pair, raw bytes, current state, or signature is invalid."""


def _parse_canonical(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublicTrustResolutionError(f"{label} is not JSON") from exc
    if not isinstance(value, dict) or raw != evidence.canonical(value) + b"\n":
        raise PublicTrustResolutionError(
            f"{label} must be canonical JSON followed by one LF"
        )
    return value


def _verify_raw_reference(
    raw: bytes, reference_value: Any, *, label: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        reference = evidence.validate_reference(reference_value)
    except evidence.EvidenceRegistryError as exc:
        raise PublicTrustResolutionError(f"{label} reference is invalid: {exc}") from exc
    expected = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected != reference["object_sha256"] or len(raw) != reference["size_bytes"]:
        raise PublicTrustResolutionError(f"{label} bytes or size differ from the reference")
    return reference, _parse_canonical(raw, label)


def verify_registered_public_trust_pair(
    *,
    object_raw: bytes,
    object_reference: Any,
    bundle_raw: bytes,
    bundle_reference: Any,
    signer_registry_raw: bytes,
    expected_signer_registry_sha256: str,
    expected_authority_state_sha256: str,
    expected_revocation_state_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify raw referenced object bytes and the adjacent offline DSSE bundle."""

    object_ref, object_value = _verify_raw_reference(
        object_raw, object_reference, label="public-trust object"
    )
    bundle_ref, bundle_value = _verify_raw_reference(
        bundle_raw, bundle_reference, label="public-trust bundle"
    )
    if (
        bundle_ref["kind"] != object_ref["kind"] + "-sigstore-bundle"
        or bundle_ref["subject_sha256"] != object_ref["object_sha256"]
        or object_ref["subject_sha256"] is not None
        or any(
            object_ref[field] != bundle_ref[field]
            for field in (
                "repository", "repository_id", "repository_owner_id",
                "registry_source_commit", "registry_revision",
                "registry_head_sha256",
            )
        )
    ):
        raise PublicTrustResolutionError("public-trust reference pair is not adjacent and bound")
    expected_object_identity = evidence.semantic_identity_digest(
        kind=object_ref["kind"],
        object_schema_version=object_ref["object_schema_version"],
        object_value=object_value,
        object_sha256=object_ref["object_sha256"],
    )
    expected_bundle_identity = evidence.semantic_identity_digest(
        kind=bundle_ref["kind"],
        object_schema_version=bundle_ref["object_schema_version"],
        object_value=bundle_ref["subject_sha256"],
        object_sha256=bundle_ref["object_sha256"],
    )
    if (
        object_ref["semantic_identity_sha256"] != expected_object_identity
        or bundle_ref["semantic_identity_sha256"] != expected_bundle_identity
    ):
        raise PublicTrustResolutionError("public-trust semantic identity differs")
    registry_value = _parse_canonical(signer_registry_raw, "signer registry")
    try:
        registry = evidence.validate_signer_registry(registry_value)
    except evidence.EvidenceRegistryError as exc:
        raise PublicTrustResolutionError(f"signer registry is invalid: {exc}") from exc
    registry_identity = evidence.signer_registry_identity_digest(registry)
    if registry_identity != expected_signer_registry_sha256:
        raise PublicTrustResolutionError("signer registry identity is not current")
    instant = now or datetime.now(timezone.utc)
    generated_at = evidence._timestamp(registry["generated_at"], "registry generated_at")
    expires_at = evidence.optional_timestamp(registry["expires_at"], "registry expires_at")
    if instant < generated_at or (expires_at is not None and instant >= expires_at):
        raise PublicTrustResolutionError("signer registry is not active")
    try:
        statement = kms.statement_from_bundle(bundle_value)
    except kms.PublicTrustKmsError as exc:
        raise PublicTrustResolutionError(f"public-trust bundle is invalid: {exc}") from exc
    profile = statement["signature_profile"]
    if profile == kms.SIGNATURE_PROFILE:
        expected_algorithm = "ecdsa-p256-sha256"
    elif profile == kms.SOFTWARE_SIGNATURE_PROFILE:
        expected_algorithm = "ed25519"
    else:
        raise PublicTrustResolutionError("public-trust signature profile is invalid")
    matches = [
        signer for signer in registry["signers"]
        if signer.get("key_id") == statement["key_id"]
        and signer.get("algorithm") == expected_algorithm
    ]
    if len(matches) != 1:
        raise PublicTrustResolutionError("public-trust bundle does not select one registry signer")
    signer = matches[0]
    try:
        kms.validate_statement_object_binding(
            statement,
            object_raw=object_raw,
            object_value=object_value,
            object_kind=object_ref["kind"],
            object_schema_version=object_ref["object_schema_version"],
            object_media_type=object_ref["object_media_type"],
            semantic_identity_sha256=object_ref["semantic_identity_sha256"],
            expected_signer_registry_sha256=expected_signer_registry_sha256,
            expected_authority_state_sha256=expected_authority_state_sha256,
            expected_revocation_state_sha256=expected_revocation_state_sha256,
        )
        kms.verify_bundle(
            bundle_value,
            expected_statement=statement,
            signer=signer,
            now=instant,
        )
    except kms.PublicTrustKmsError as exc:
        raise PublicTrustResolutionError(f"public-trust verification failed: {exc}") from exc
    return {
        "object": object_value,
        "object_reference": object_ref,
        "bundle_reference": bundle_ref,
        "signing_statement": statement,
        "signer_registry_sha256": registry_identity,
        "verified_at": instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
