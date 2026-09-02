#!/usr/bin/env python3
"""Validate the public, content-addressed production evidence registry.

The registry never accepts a caller-supplied transport URL. A consumer derives
the supported transport from the pinned repository identity, an exact
40-character registry commit, and the registered object path.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import itertools
import json
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from public_trust_kms import PublicTrustKmsError, validate_public_signer

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "evidence-registry.json"

REGISTRY_SCHEMA = "openadapt.production-evidence-registry/v2"
REFERENCE_SCHEMA = "openadapt.production-evidence-object-reference/v2"
SIGNER_POINTER_SCHEMA = "openadapt.qualification-signer-registry-pointer/v1"
SIGNER_REGISTRY_SCHEMA = "openadapt.qualification-signer-registry/v2"
ENTRY_DIGEST_DOMAIN = b"OpenAdapt production evidence registry entry v1\0"
HEAD_DIGEST_DOMAIN = b"OpenAdapt production evidence registry head v2\0"
SEMANTIC_IDENTITY_DOMAIN = b"OpenAdapt production evidence semantic identity v1\0"
BUNDLE_IDENTITY_DOMAIN = b"OpenAdapt production evidence Sigstore bundle identity v1\0"
SIGNER_REGISTRY_IDENTITY_DOMAIN = b"OpenAdapt qualification signer registry v2\0"
SIGNER_USAGES = {
    "private-qualification-evidence-manifest",
    "private-qualification-evidence-decision-request",
    "qualification-campaign-permit",
    "qualification-source-evidence-manifest",
    "qualification-trial-receipt",
    "private-qualification-evidence-decision",
    "private-qualification-evidence-decision-storage-seal",
    "private-qualification-evidence-decision-final-manifest",
    "private-qualification-evidence-recovery-receipt",
    "qualification-evidence-decision-receipt",
    "qualification-authority-state-receipt",
    "qualification-revocation-state-receipt",
}
RECOVERY_SIGNER_USAGE = "private-qualification-evidence-recovery-receipt"
DECISION_RECEIPT_IDENTITY_DOMAIN = (
    b"OpenAdapt qualification decision receipt series identity v1\0"
)
REPOSITORY = "OpenAdaptAI/.github"
REPOSITORY_ID = "858454062"
REPOSITORY_OWNER_ID = "132681217"
RAW_GITHUB_ORIGIN = "https://raw.githubusercontent.com"

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
KIND = re.compile(r"^[a-z][a-z0-9-]{1,95}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
KEY_ID = re.compile(r"^qa-ed25519-[0-9a-f]{16}$")
KMS_ED25519_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:992382684924:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
WORKFLOW_IDENTITY = re.compile(
    r"^https://github\.com/OpenAdaptAI/[A-Za-z0-9_.-]+/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml@refs/heads/[A-Za-z0-9._/-]+$"
)
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

REGULAR_KIND_CONTRACTS: dict[str, tuple[str, str]] = {
    "production-acceptance-manifest": (
        "openadapt.production-acceptance/v3",
        "application/vnd.openadapt.production-acceptance+json;version=3",
    ),
    "production-acceptance-summary": (
        "openadapt.production-lifecycle-evidence-summary/v3",
        "application/vnd.openadapt.production-lifecycle-evidence-summary+json;version=3",
    ),
    "production-cloud-deploy-authorization": (
        "openadapt.production-cloud-deploy-authorization/v1",
        "application/vnd.openadapt.production-cloud-deploy-authorization+json;version=1",
    ),
    "production-cloud-deployment-result": (
        "openadapt.production-cloud-deployment-result/v1",
        "application/vnd.openadapt.production-cloud-deployment-result+json;version=1",
    ),
    "production-current-default": (
        "openadapt.production-current-default/v1",
        "application/vnd.openadapt.production-current-default+json;version=1",
    ),
    "production-deployment-observation": (
        "openadapt.production-deployment-observation/v1",
        "application/vnd.openadapt.production-deployment-observation+json;version=1",
    ),
    "production-lifecycle-checkpoint": (
        "openadapt.production-lifecycle-checkpoint/v2",
        "application/vnd.openadapt.production-lifecycle-checkpoint+json;version=2",
    ),
    "qualification-admission": (
        "openadapt.qualification-admission/v4",
        "application/vnd.openadapt.qualification-admission+json;version=4",
    ),
    "qualification-authority-state-receipt": (
        "openadapt.qualification-authority-state-receipt/v2",
        "application/vnd.openadapt.qualification-authority-state-receipt+json;version=2",
    ),
    "qualification-campaign-permit": (
        "openadapt.qualification-campaign-permit/v3",
        "application/vnd.openadapt.qualification-campaign-permit+json;version=3",
    ),
    "qualification-campaign-permit-policy": (
        "openadapt.qualification-campaign-permit-policy/v3",
        "application/vnd.openadapt.qualification-campaign-permit-policy+json;version=3",
    ),
    "qualification-campaign-permit-receipt": (
        "openadapt.qualification-campaign-permit-receipt/v3",
        "application/vnd.openadapt.qualification-campaign-permit-receipt+json;version=3",
    ),
    "qualification-campaign-permit-request": (
        "openadapt.qualification-campaign-permit-request/v3",
        "application/vnd.openadapt.qualification-campaign-permit-request+json;version=3",
    ),
    "qualification-evidence-decision-receipt": (
        "openadapt.qualification-evidence-decision-receipt/v2",
        "application/vnd.openadapt.qualification-evidence-decision-receipt+json;version=2",
    ),
    "qualification-release": (
        "openadapt.qualification-release/v2",
        "application/vnd.openadapt.qualification-release+json;version=2",
    ),
    "qualification-revocation-state-receipt": (
        "openadapt.qualification-revocation-state-receipt/v1",
        "application/vnd.openadapt.qualification-revocation-state-receipt+json;version=1",
    ),
    "support-release-admission": (
        "openadapt.support-release-admission/v1",
        "application/vnd.openadapt.support-release-admission+json;version=1",
    ),
}
OBJECT_KIND_CONTRACTS: dict[str, tuple[str, str]] = dict(REGULAR_KIND_CONTRACTS)
for _kind in tuple(REGULAR_KIND_CONTRACTS):
    OBJECT_KIND_CONTRACTS[f"{_kind}-sigstore-bundle"] = (
        BUNDLE_MEDIA_TYPE,
        BUNDLE_MEDIA_TYPE,
    )

ENTRY_FIELDS = {
    "kind",
    "object_media_type",
    "object_path",
    "object_schema_version",
    "object_sha256",
    "semantic_identity_sha256",
    "size_bytes",
    "subject_sha256",
}
REFERENCE_FIELDS = {
    "schema_version",
    "repository",
    "repository_id",
    "repository_owner_id",
    "registry_source_commit",
    "registry_revision",
    "registry_head_sha256",
    "registry_entry_sha256",
    *ENTRY_FIELDS,
}


class EvidenceRegistryError(ValueError):
    """The registry, object, or exact-commit reference is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise EvidenceRegistryError(
            f"{label} must contain exactly {sorted(keys)}; got {actual}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EvidenceRegistryError(f"{label} must be a lowercase sha256 digest")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise EvidenceRegistryError(f"{label} must be a positive integer")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise EvidenceRegistryError(f"{label} must be an exact UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise EvidenceRegistryError(f"{label} is not a calendar timestamp") from exc


def optional_timestamp(value: Any, label: str) -> datetime | None:
    if value is None:
        return None
    return _timestamp(value, label)


def _revocation_in_lifetime(
    generated_at: datetime, revoked_at: datetime, expires_at: datetime | None
) -> bool:
    if revoked_at < generated_at:
        return False
    if expires_at is not None and revoked_at > expires_at:
        return False
    return True


def semantic_identity_digest(
    *, kind: str, object_schema_version: str, object_value: Any, object_sha256: str
) -> str:
    if kind.endswith("-sigstore-bundle"):
        payload = {
            "kind": kind,
            "object_sha256": object_sha256,
            "subject_sha256": object_value,
        }
        domain = BUNDLE_IDENTITY_DOMAIN
    elif kind == "qualification-evidence-decision-receipt":
        if not isinstance(object_value, dict):
            raise EvidenceRegistryError("decision receipt identity object is invalid")
        decision_identity = object_value.get("decision_identity_sha256")
        decision_revision = object_value.get("decision_revision")
        evidence_class = object_value.get("evidence_class")
        _digest(decision_identity, "decision identity")
        _positive_integer(decision_revision, "decision revision")
        if evidence_class not in {
            "private-customer",
            "remote-safe-synthetic",
        }:
            raise EvidenceRegistryError("decision evidence class is invalid")
        payload = {
            "decision_identity_sha256": decision_identity,
            "decision_revision": decision_revision,
        }
        payload["evidence_class"] = evidence_class
        domain = DECISION_RECEIPT_IDENTITY_DOMAIN
    elif kind in {
        "qualification-authority-state-receipt",
        "qualification-revocation-state-receipt",
    }:
        if not isinstance(object_value, dict):
            raise EvidenceRegistryError("qualification state identity object is invalid")
        identity_field = (
            "authority_state_sha256"
            if kind == "qualification-authority-state-receipt"
            else "revocation_state_sha256"
        )
        identity = object_value.get(identity_field)
        _digest(identity, f"{kind} identity")
        return identity
    else:
        payload = {
            "kind": kind,
            "object_schema_version": object_schema_version,
            "object": object_value,
        }
        domain = SEMANTIC_IDENTITY_DOMAIN
    return "sha256:" + hashlib.sha256(domain + canonical(payload)).hexdigest()


def signer_registry_identity_digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        SIGNER_REGISTRY_IDENTITY_DOMAIN + canonical(value)
    ).hexdigest()


def validate_signer_registry(value: Any) -> dict[str, Any]:
    registry = _closed(
        value,
        {"schema_version", "revision", "generated_at", "expires_at", "signers"},
        "signer registry",
    )
    if registry["schema_version"] != SIGNER_REGISTRY_SCHEMA:
        raise EvidenceRegistryError("signer registry schema is not supported")
    _positive_integer(registry["revision"], "signer registry revision")
    generated_at = _timestamp(registry["generated_at"], "signer registry generated_at")
    expires_at = optional_timestamp(registry["expires_at"], "signer registry expires_at")
    if expires_at is not None and not generated_at < expires_at:
        raise EvidenceRegistryError(
            "signer registry expiry must be after generated_at"
        )
    signers = registry["signers"]
    if not isinstance(signers, list) or not signers:
        raise EvidenceRegistryError("signer registry must contain at least one signer")
    seen_ids: set[str] = set()
    for index, signer_value in enumerate(signers):
        label = f"signer registry signer {index}"
        if not isinstance(signer_value, dict):
            raise EvidenceRegistryError(f"{label} must be an object")
        if signer_value.get("algorithm") == "ecdsa-p256-sha256" or (
            signer_value.get("algorithm") == "ed25519"
            and signer_value.get("key_origin") == "software"
        ):
            try:
                signer = validate_public_signer(signer_value)
            except PublicTrustKmsError as exc:
                raise EvidenceRegistryError(f"{label}: {exc}") from exc
            key_id = signer["key_id"]
            if key_id in seen_ids:
                raise EvidenceRegistryError("signer registry key ids must be unique")
            seen_ids.add(key_id)
            if signer["status"] == "revoked":
                revoked_at = _timestamp(signer["revoked_at"], f"{label} revoked_at")
                if not _revocation_in_lifetime(generated_at, revoked_at, expires_at):
                    raise EvidenceRegistryError(
                        f"{label} revocation time is outside the registry lifetime"
                    )
            continue
        kms_ed25519 = (
            signer_value.get("algorithm") == "ed25519"
            and signer_value.get("key_origin") == "aws-kms"
        )
        signer_fields = {
            "algorithm",
            "key_id",
            "public_key",
            "public_key_spki_der_base64",
            "public_key_sha256",
            "statement_schema_versions",
            "allowed_usages",
            "allowed_workflows",
            "allowed_ref_prefixes",
            "status",
            "revoked_at",
        }
        if kms_ed25519:
            signer_fields.update(
                {
                    "key_origin",
                    "kms_key_arn",
                    "signature_encoding",
                    "allowed_environments",
                }
            )
        signer = _closed(signer_value, signer_fields, label)
        if signer["algorithm"] != "ed25519":
            raise EvidenceRegistryError(f"{label} algorithm must be ed25519")
        key_id = signer["key_id"]
        if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
            raise EvidenceRegistryError(f"{label} key id is invalid")
        if key_id in seen_ids:
            raise EvidenceRegistryError("signer registry key ids must be unique")
        seen_ids.add(key_id)
        public_key = signer["public_key"]
        if not isinstance(public_key, str) or "=" in public_key:
            raise EvidenceRegistryError(
                f"{label} public key must be unpadded base64url"
            )
        try:
            key_bytes = base64.urlsafe_b64decode(
                public_key + "=" * (-len(public_key) % 4)
            )
        except (ValueError, binascii.Error) as exc:
            raise EvidenceRegistryError(f"{label} public key is invalid") from exc
        canonical_key = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
        if len(key_bytes) != 32 or canonical_key != public_key:
            raise EvidenceRegistryError(
                f"{label} public key must encode 32 canonical bytes"
            )
        expected_key_id = "qa-ed25519-" + hashlib.sha256(key_bytes).hexdigest()[:16]
        if key_id != expected_key_id:
            raise EvidenceRegistryError(
                f"{label} key id does not bind the public key"
            )
        spki = bytes.fromhex("302a300506032b6570032100") + key_bytes
        expected_spki = base64.b64encode(spki).decode()
        if signer["public_key_spki_der_base64"] != expected_spki:
            raise EvidenceRegistryError(
                f"{label} SPKI does not bind the public key"
            )
        if signer["public_key_sha256"] != (
            "sha256:" + hashlib.sha256(spki).hexdigest()
        ):
            raise EvidenceRegistryError(
                f"{label} public key fingerprint does not bind the public key"
            )
        if signer["statement_schema_versions"] != [
            "openadapt.qualification-evidence-signing-statement/v1"
        ]:
            raise EvidenceRegistryError(
                f"{label} signing statement schema is invalid"
            )
        usages = signer["allowed_usages"]
        if (
            not isinstance(usages, list)
            or not usages
            or usages != sorted(set(usages))
            or any(item not in SIGNER_USAGES for item in usages)
        ):
            raise EvidenceRegistryError(f"{label} usage allowlist is invalid")
        if RECOVERY_SIGNER_USAGE in usages and usages != [RECOVERY_SIGNER_USAGE]:
            raise EvidenceRegistryError(
                f"{label} recovery usage must use a distinct signer"
            )
        if kms_ed25519 and (
            signer["kms_key_arn"] is None
            or not isinstance(signer["kms_key_arn"], str)
            or KMS_ED25519_ARN.fullmatch(signer["kms_key_arn"]) is None
            or signer["signature_encoding"]
            != "raw-64-base64-rfc4648-padded"
            or usages != ["qualification-evidence-decision-receipt"]
        ):
            raise EvidenceRegistryError(f"{label} AWS KMS Ed25519 profile differs")
        workflows = signer["allowed_workflows"]
        if (
            not isinstance(workflows, list)
            or not workflows
            or workflows != sorted(set(workflows))
            or any(
                not isinstance(item, str)
                or WORKFLOW_IDENTITY.fullmatch(item) is None
                for item in workflows
            )
        ):
            raise EvidenceRegistryError(f"{label} workflow allowlist is invalid")
        prefixes = signer["allowed_ref_prefixes"]
        if (
            not isinstance(prefixes, list)
            or not prefixes
            or prefixes != sorted(set(prefixes))
            or any(
                not isinstance(item, str)
                or not item.startswith("refs/")
                or ".." in item
                for item in prefixes
            )
        ):
            raise EvidenceRegistryError(f"{label} ref-prefix allowlist is invalid")
        if kms_ed25519:
            expected_workflow = (
                "https://github.com/OpenAdaptAI/.github/.github/workflows/"
                "issue-synthetic-qualification-evidence-decision.yml"
                "@refs/heads/main"
            )
            if (
                workflows != [expected_workflow]
                or prefixes != ["refs/heads/main"]
                or signer["allowed_environments"]
                != ["synthetic-qualification-evidence-decision"]
            ):
                raise EvidenceRegistryError(
                    f"{label} AWS KMS Ed25519 authority differs"
                )
        if signer["status"] == "active":
            if signer["revoked_at"] is not None:
                raise EvidenceRegistryError(
                    f"{label} active signer cannot have revoked_at"
                )
        elif signer["status"] == "revoked":
            revoked_at = _timestamp(signer["revoked_at"], f"{label} revoked_at")
            if not _revocation_in_lifetime(generated_at, revoked_at, expires_at):
                raise EvidenceRegistryError(
                    f"{label} revocation time is outside the registry lifetime"
                )
        else:
            raise EvidenceRegistryError(f"{label} status is invalid")
    recovery_signers = [
        signer
        for signer in signers
        if RECOVERY_SIGNER_USAGE in signer.get("allowed_usages", [])
    ]
    if recovery_signers and sum(
        signer["status"] == "active" for signer in recovery_signers
    ) != 1:
        raise EvidenceRegistryError(
            "signer registry must identify exactly one active recovery signer"
        )
    return registry


def require_active_signer_for_usage(
    value: Any, usage: str
) -> dict[str, Any]:
    """Select the one active signer for a closed private signing usage."""

    if usage not in SIGNER_USAGES:
        raise EvidenceRegistryError("requested signer usage is invalid")
    registry = validate_signer_registry(value)
    matches = [
        signer
        for signer in registry["signers"]
        if signer["status"] == "active" and usage in signer["allowed_usages"]
    ]
    if len(matches) != 1:
        raise EvidenceRegistryError(
            f"signer registry must identify exactly one active signer for {usage}"
        )
    return matches[0]


def _object_path(value: Any, kind: str, object_sha256: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise EvidenceRegistryError("object path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceRegistryError("object path must be a relative normalized path")
    digest_hex = object_sha256.removeprefix("sha256:")
    expected = (
        f"production-evidence/objects/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.{kind}.json"
    )
    if value != expected:
        raise EvidenceRegistryError(
            f"object path must be the content-addressed path {expected}"
        )
    return value


def _validate_entry_projection(value: Any, label: str) -> dict[str, Any]:
    entry = _closed(value, ENTRY_FIELDS, label)
    kind = entry["kind"]
    if not isinstance(kind, str) or KIND.fullmatch(kind) is None:
        raise EvidenceRegistryError(f"{label} kind is invalid")
    contract = OBJECT_KIND_CONTRACTS.get(kind)
    if contract is None:
        raise EvidenceRegistryError(f"{label} kind is not registered: {kind}")
    if (entry["object_schema_version"], entry["object_media_type"]) != contract:
        raise EvidenceRegistryError(f"{label} schema or media type differs from policy")
    object_sha256 = _digest(entry["object_sha256"], f"{label} object digest")
    _digest(entry["semantic_identity_sha256"], f"{label} semantic identity")
    _positive_integer(entry["size_bytes"], f"{label} size")
    _object_path(entry["object_path"], kind, object_sha256)
    subject = entry["subject_sha256"]
    if kind.endswith("-sigstore-bundle"):
        _digest(subject, f"{label} bundle subject")
    elif subject is not None:
        raise EvidenceRegistryError(f"{label} regular object subject must be null")
    return entry


def entry_digest(entry: Mapping[str, Any]) -> str:
    projection = {field: entry[field] for field in ENTRY_FIELDS}
    return "sha256:" + hashlib.sha256(
        ENTRY_DIGEST_DOMAIN + canonical(projection)
    ).hexdigest()


def registry_head_digest(document: Mapping[str, Any]) -> str:
    payload = {
        "schema_version": document["schema_version"],
        "repository": document["repository"],
        "repository_id": document["repository_id"],
        "repository_owner_id": document["repository_owner_id"],
        "revision": document["revision"],
        "previous_registry_head_sha256": document["previous_registry_head_sha256"],
        "signer_registry": document["signer_registry"],
        "signer_registry_history": document["signer_registry_history"],
        "entry_sha256s": [
            entry["registry_entry_sha256"] for entry in document["entries"]
        ],
    }
    return "sha256:" + hashlib.sha256(
        HEAD_DIGEST_DOMAIN + canonical(payload)
    ).hexdigest()


def raw_github_url(reference: Mapping[str, Any]) -> str:
    """Derive the immutable raw GitHub URL from a validated reference."""

    validated = validate_reference(reference)
    return (
        f"{RAW_GITHUB_ORIGIN}/{validated['repository']}/"
        f"{validated['registry_source_commit']}/{validated['object_path']}"
    )


def validate_reference(value: Any) -> dict[str, Any]:
    reference = _closed(value, REFERENCE_FIELDS, "production evidence reference")
    if reference["schema_version"] != REFERENCE_SCHEMA:
        raise EvidenceRegistryError("object reference schema is not supported")
    if (
        reference["repository"],
        reference["repository_id"],
        reference["repository_owner_id"],
    ) != (REPOSITORY, REPOSITORY_ID, REPOSITORY_OWNER_ID):
        raise EvidenceRegistryError("object reference repository identity differs")
    if not isinstance(reference["registry_source_commit"], str) or HEX40.fullmatch(
        reference["registry_source_commit"]
    ) is None:
        raise EvidenceRegistryError("registry source commit must be exact lowercase hex")
    _positive_integer(reference["registry_revision"], "registry revision")
    _digest(reference["registry_head_sha256"], "registry head")
    projection = {field: reference[field] for field in ENTRY_FIELDS}
    _validate_entry_projection(projection, "production evidence reference")
    if reference["registry_entry_sha256"] != entry_digest(projection):
        raise EvidenceRegistryError("object reference entry digest is invalid")
    return reference


def _validate_signer_pointer(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    pointer = _closed(
        value,
        {
            "schema_version",
            "object_path",
            "object_sha256",
            "registry_identity_sha256",
            "registry_revision",
        },
        "signer registry pointer",
    )
    if pointer["schema_version"] != SIGNER_POINTER_SCHEMA:
        raise EvidenceRegistryError("signer registry pointer schema is not supported")
    digest = _digest(pointer["object_sha256"], "signer registry object digest")
    _digest(pointer["registry_identity_sha256"], "signer registry identity")
    _positive_integer(pointer["registry_revision"], "signer registry revision")
    digest_hex = digest.removeprefix("sha256:")
    expected = (
        f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.qualification-signer-registry.json"
    )
    if pointer["object_path"] != expected:
        raise EvidenceRegistryError("signer registry pointer path is not content-addressed")
    return pointer


def validate_registry(value: Any, *, root: Path | None = None) -> list[dict[str, Any]]:
    document = _closed(
        value,
        {
            "$schema",
            "schema_version",
            "repository",
            "repository_id",
            "repository_owner_id",
            "revision",
            "previous_registry_head_sha256",
            "registry_head_sha256",
            "signer_registry",
            "signer_registry_history",
            "entries",
        },
        "evidence registry",
    )
    if document["$schema"] != "schemas/evidence-registry.schema.json":
        raise EvidenceRegistryError("evidence registry $schema is invalid")
    if document["schema_version"] != REGISTRY_SCHEMA:
        raise EvidenceRegistryError("evidence registry schema is not supported")
    if (
        document["repository"],
        document["repository_id"],
        document["repository_owner_id"],
    ) != (REPOSITORY, REPOSITORY_ID, REPOSITORY_OWNER_ID):
        raise EvidenceRegistryError("evidence registry repository identity differs")
    _positive_integer(document["revision"], "registry revision")
    previous = document["previous_registry_head_sha256"]
    if previous is not None:
        _digest(previous, "previous registry head")
    signer_pointer = _validate_signer_pointer(document["signer_registry"])
    history_value = document["signer_registry_history"]
    if not isinstance(history_value, list):
        raise EvidenceRegistryError("signer registry history must be a list")
    signer_history = [_validate_signer_pointer(item) for item in history_value]
    if any(item is None for item in signer_history):
        raise EvidenceRegistryError("signer registry history cannot contain null")
    typed_history = [item for item in signer_history if item is not None]
    revisions = [item["registry_revision"] for item in typed_history]
    if revisions != sorted(set(revisions)) or any(
        current != previous + 1
        for previous, current in itertools.pairwise(revisions)
    ):
        raise EvidenceRegistryError(
            "signer registry history must use unique consecutive revisions"
        )
    if (signer_pointer is None) != (not typed_history) or (
        signer_pointer is not None and signer_pointer != typed_history[-1]
    ):
        raise EvidenceRegistryError(
            "current signer registry must be the last historical pointer"
        )
    entries = document["entries"]
    if not isinstance(entries, list):
        raise EvidenceRegistryError("registry entries must be a list")
    if entries and signer_pointer is None:
        raise EvidenceRegistryError("a non-empty registry requires a signer registry pointer")

    seen_entries: set[str] = set()
    seen_paths: set[str] = set()
    seen_regular_identities: set[tuple[str, str]] = set()
    previous_regular: dict[str, Any] | None = None
    validated: list[dict[str, Any]] = []
    for index, value_entry in enumerate(entries):
        entry = _closed(
            value_entry,
            {"registry_entry_sha256", *ENTRY_FIELDS},
            f"registry entry {index}",
        )
        projection = {field: entry[field] for field in ENTRY_FIELDS}
        _validate_entry_projection(projection, f"registry entry {index}")
        computed = entry_digest(projection)
        if entry["registry_entry_sha256"] != computed:
            raise EvidenceRegistryError(f"registry entry {index} digest is invalid")
        if computed in seen_entries or entry["object_path"] in seen_paths:
            raise EvidenceRegistryError("registry entries must be unique")
        seen_entries.add(computed)
        seen_paths.add(entry["object_path"])
        if entry["kind"].endswith("-sigstore-bundle"):
            expected_regular_kind = entry["kind"].removesuffix("-sigstore-bundle")
            if (
                previous_regular is None
                or previous_regular["kind"] != expected_regular_kind
                or entry["subject_sha256"] != previous_regular["object_sha256"]
            ):
                raise EvidenceRegistryError(
                    "a Sigstore bundle must immediately follow and bind its regular object"
                )
            previous_regular = None
        else:
            regular_identity = (
                entry["kind"], entry["semantic_identity_sha256"]
            )
            if regular_identity in seen_regular_identities:
                raise EvidenceRegistryError(
                    "a regular semantic identity can be registered only once"
                )
            seen_regular_identities.add(regular_identity)
            if previous_regular is not None:
                raise EvidenceRegistryError(
                    "every regular object must be immediately followed by its Sigstore bundle"
                )
            previous_regular = entry
        if root is not None:
            path = root / entry["object_path"]
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise EvidenceRegistryError(f"registered object is missing: {path}") from exc
            actual = "sha256:" + hashlib.sha256(raw).hexdigest()
            if actual != entry["object_sha256"] or len(raw) != entry["size_bytes"]:
                raise EvidenceRegistryError(f"registered object bytes differ: {path}")
            try:
                object_value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise EvidenceRegistryError(
                    f"registered object is not JSON: {path}"
                ) from exc
            if entry["kind"].endswith("-sigstore-bundle"):
                identity_value: Any = entry["subject_sha256"]
            else:
                if (
                    not isinstance(object_value, dict)
                    or object_value.get("schema_version")
                    != entry["object_schema_version"]
                ):
                    raise EvidenceRegistryError(
                        f"registered object schema differs: {path}"
                    )
                if raw != canonical(object_value) + b"\n":
                    raise EvidenceRegistryError(
                        f"registered regular object is not canonical JSON plus LF: {path}"
                    )
                identity_value = object_value
            expected_identity = semantic_identity_digest(
                kind=entry["kind"],
                object_schema_version=entry["object_schema_version"],
                object_value=identity_value,
                object_sha256=entry["object_sha256"],
            )
            if entry["semantic_identity_sha256"] != expected_identity:
                raise EvidenceRegistryError(
                    f"registered object semantic identity differs: {path}"
                )
        validated.append(entry)

    if previous_regular is not None:
        raise EvidenceRegistryError(
            "every regular object must be immediately followed by its Sigstore bundle"
        )

    if document["registry_head_sha256"] != registry_head_digest(document):
        raise EvidenceRegistryError("registry head digest is invalid")
    if root is not None:
        for historical_pointer in typed_history:
            signer_path = root / historical_pointer["object_path"]
            try:
                signer_raw = signer_path.read_bytes()
                signer_value = json.loads(signer_raw)
            except (OSError, json.JSONDecodeError) as exc:
                raise EvidenceRegistryError(
                    "signer registry object is missing or invalid"
                ) from exc
            if (
                "sha256:" + hashlib.sha256(signer_raw).hexdigest()
                != historical_pointer["object_sha256"]
            ):
                raise EvidenceRegistryError("signer registry object digest differs")
            historical_registry = validate_signer_registry(signer_value)
            if (
                historical_registry["revision"]
                != historical_pointer["registry_revision"]
                or signer_registry_identity_digest(historical_registry)
                != historical_pointer["registry_identity_sha256"]
            ):
                raise EvidenceRegistryError("signer registry identity differs")
    return validated


def require_registered(
    entries: list[dict[str, Any]], *, reference: Mapping[str, Any], label: str
) -> dict[str, Any]:
    wanted = validate_reference(reference)
    for entry in entries:
        if entry["registry_entry_sha256"] == wanted["registry_entry_sha256"]:
            for field in ENTRY_FIELDS:
                if entry[field] != wanted[field]:
                    raise EvidenceRegistryError(f"{label} differs from its registry entry")
            return entry
    raise EvidenceRegistryError(f"{label} is not registered")


def validate_append_only_history(previous_value: object, current_value: object) -> None:
    if isinstance(previous_value, dict) and previous_value.get("schema_version") == (
        "openadapt.production-evidence-registry/v1"
    ):
        expected_empty_v1 = {
            "$schema": "schemas/evidence-registry.schema.json",
            "schema_version": "openadapt.production-evidence-registry/v1",
            "head_entry_sha256": None,
            "entries": [],
        }
        if previous_value != expected_empty_v1:
            raise EvidenceRegistryError(
                "only the exact empty v1 registry can migrate to v2"
            )
        current = validate_registry(current_value)
        assert isinstance(current_value, dict)
        if (
            current_value["revision"] != 1
            or current_value["previous_registry_head_sha256"] is not None
            or current_value["signer_registry"] is not None
            or current_value["signer_registry_history"] != []
            or current != []
        ):
            raise EvidenceRegistryError(
                "the v1-to-v2 migration must create the exact empty v2 genesis"
            )
        return
    previous = validate_registry(previous_value)
    current = validate_registry(current_value)
    previous_doc = previous_value
    current_doc = current_value
    assert isinstance(previous_doc, dict) and isinstance(current_doc, dict)
    if current_doc == previous_doc:
        # An untouched registry is not a rollback. Only a changed registry has to
        # bump the revision, bind the previous head, and append to the history.
        return
    if current_doc["revision"] != previous_doc["revision"] + 1:
        raise EvidenceRegistryError("registry revision must increase by exactly one")
    if current_doc["previous_registry_head_sha256"] != previous_doc["registry_head_sha256"]:
        raise EvidenceRegistryError("registry revision does not bind the previous head")
    if len(current) < len(previous) or current[: len(previous)] != previous:
        raise EvidenceRegistryError("registry history must be an exact append")
    previous_signers = previous_doc["signer_registry_history"]
    current_signers = current_doc["signer_registry_history"]
    if (
        len(current_signers) < len(previous_signers)
        or current_signers[: len(previous_signers)] != previous_signers
    ):
        raise EvidenceRegistryError(
            "signer registry pointer history must be an exact append"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=str(REGISTRY_PATH))
    parser.add_argument("--previous-registry")
    parser.add_argument("--skip-object-readback", action="store_true")
    args = parser.parse_args(argv)
    registry_path = Path(args.registry)
    try:
        value = json.loads(registry_path.read_text(encoding="utf-8"))
        validate_registry(
            value,
            root=None if args.skip_object_readback else registry_path.resolve().parent,
        )
        if args.previous_registry:
            previous = json.loads(Path(args.previous_registry).read_text(encoding="utf-8"))
            validate_append_only_history(previous, value)
    except (OSError, json.JSONDecodeError, EvidenceRegistryError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print("production evidence registry v2 is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
