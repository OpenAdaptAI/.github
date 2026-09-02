"""Build and verify the offline OpenAdapt public-trust DSSE profiles.

Two closed profiles share the same statement schema and Sigstore bundle shape:

- ``aws-kms-p256-dsse-v1``: AWS KMS ECDSA P-256 over DSSE PAE digest.
- ``software-ed25519-dsse-v1``: GitHub+Keychain Ed25519 over the same DSSE PAE.

The software profile uses the founder-provisioned qualification Ed25519 key
(same PEM, same Keychain item) with a distinct public-trust key-id prefix so
inner receipts and outer bundles can coexist in one signer registry.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

STATEMENT_SCHEMA = "openadapt.production-public-trust-signing-statement/v1"
STATEMENT_MEDIA_TYPE = (
    "application/vnd.openadapt.production-public-trust-signing-statement+json;version=1"
)
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
SIGNATURE_PROFILE = "aws-kms-p256-dsse-v1"
SOFTWARE_SIGNATURE_PROFILE = "software-ed25519-dsse-v1"
KMS_ACCOUNT_ID = "992382684924"
KMS_REGION = "us-east-1"
KMS_ALGORITHM = "ECDSA_SHA_256"
KMS_MESSAGE_TYPE = "DIGEST"
KMS_KEY_SPEC = "ECC_NIST_P256"
KMS_ROLE_ARN = (
    "arn:aws:iam::992382684924:role/openadapt-public-trust-signer"
)
SOFTWARE_KEY_ORIGIN = "software"
SOFTWARE_GITHUB_SECRET_NAME = "OPENADAPT_QUALIFICATION_ED25519_PRIVATE_KEY"
SOFTWARE_KEYCHAIN_SERVICE = "openadapt-qualification-ed25519"
SOFTWARE_ENVIRONMENT = "synthetic-qualification-evidence-decision"
SOFTWARE_WORKFLOW_PATH = (
    ".github/workflows/sign-production-evidence-software.yml"
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
KIND = re.compile(r"^[a-z][a-z0-9-]{1,95}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
KMS_KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:992382684924:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
KEY_ID = re.compile(r"^oa-public-trust-p256-[0-9a-f]{16}$")
SOFTWARE_KEY_ID = re.compile(r"^oa-public-trust-ed25519-[0-9a-f]{16}$")
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)

STATEMENT_FIELDS = {
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
}
ISSUER_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "source_commit",
    "environment",
}
AUTHORITY_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "source_commit",
    "environment",
    "aws_account_id",
    "aws_region",
    "kms_key_arn",
    "kms_key_spec",
    "kms_signing_algorithm",
    "kms_message_type",
    "role_arn",
}
SOFTWARE_AUTHORITY_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "source_commit",
    "environment",
    "key_origin",
}
PUBLIC_SIGNER_FIELDS = {
    "algorithm",
    "key_id",
    "key_origin",
    "kms_key_arn",
    "public_key",
    "public_key_spki_der_base64",
    "public_key_sha256",
    "signature_encoding",
    "statement_schema_versions",
    "allowed_usages",
    "allowed_kinds",
    "allowed_workflows",
    "allowed_ref_prefixes",
    "allowed_environments",
    "status",
    "revoked_at",
}
SOFTWARE_SIGNER_FIELDS = {
    "algorithm",
    "key_id",
    "key_origin",
    "public_key",
    "public_key_spki_der_base64",
    "public_key_sha256",
    "signature_encoding",
    "statement_schema_versions",
    "allowed_usages",
    "allowed_kinds",
    "allowed_workflows",
    "allowed_ref_prefixes",
    "allowed_environments",
    "status",
    "revoked_at",
}
PUBLIC_EVIDENCE_KINDS = {
    "production-acceptance-manifest",
    "production-acceptance-summary",
    "production-cloud-deploy-authorization",
    "production-cloud-deployment-result",
    "production-current-default",
    "production-deployment-observation",
    "production-lifecycle-checkpoint",
    "qualification-admission",
    "qualification-authority-state-receipt",
    "qualification-campaign-permit",
    "qualification-campaign-permit-policy",
    "qualification-campaign-permit-receipt",
    "qualification-campaign-permit-request",
    "qualification-evidence-decision-receipt",
    "qualification-release",
    "qualification-revocation-state-receipt",
    "support-release-admission",
}
PUBLIC_SIGNING_WORKFLOW = (
    "https://github.com/OpenAdaptAI/.github/"
    ".github/workflows/sign-production-evidence.yml@refs/heads/main"
)
SOFTWARE_SIGNING_WORKFLOW = (
    "https://github.com/OpenAdaptAI/.github/"
    + SOFTWARE_WORKFLOW_PATH
    + "@refs/heads/main"
)


class PublicTrustKmsError(ValueError):
    """The public-trust signing statement, signer, or bundle is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_lf(value: Any) -> bytes:
    return canonical(value) + b"\n"


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise PublicTrustKmsError(
            f"{label} must contain exactly {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise PublicTrustKmsError(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise PublicTrustKmsError(f"{label} must be an exact UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise PublicTrustKmsError(f"{label} is not a calendar timestamp") from exc


def _canonical_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise PublicTrustKmsError(f"{label} must be canonical padded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PublicTrustKmsError(f"{label} is not valid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise PublicTrustKmsError(f"{label} must be canonical padded base64")
    return decoded


def _canonical_base64url(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise PublicTrustKmsError(f"{label} must be canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise PublicTrustKmsError(f"{label} is not valid base64url") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise PublicTrustKmsError(f"{label} must be canonical unpadded base64url")
    return decoded


def public_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "oa-public-trust-p256-" + hashlib.sha256(spki).hexdigest()[:16]


def software_public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "oa-public-trust-ed25519-" + hashlib.sha256(raw).hexdigest()[:16]


def software_interface_contract() -> dict[str, Any]:
    """Return the inactive software Ed25519 public-trust signing interface."""

    return {
        "schema_version": "openadapt.public-trust-software-ed25519-interface/v1",
        "activation_state": "inactive",
        "aws_required": False,
        "algorithm": "ed25519",
        "key_format": "pkcs8-pem-unencrypted",
        "signature_profile": SOFTWARE_SIGNATURE_PROFILE,
        "key_id_prefix": "oa-public-trust-ed25519-",
        "key_origin": SOFTWARE_KEY_ORIGIN,
        "github_repository": "OpenAdaptAI/.github",
        "github_environment": SOFTWARE_ENVIRONMENT,
        "github_secret_name": SOFTWARE_GITHUB_SECRET_NAME,
        "keychain_service": SOFTWARE_KEYCHAIN_SERVICE,
        "custody": ["github-environment-secret", "local-keychain-backup"],
        "restore_path": "keychain-to-github-only",
        "workflow": SOFTWARE_SIGNING_WORKFLOW,
        "allowed_usage": "production-public-evidence",
        "statement_schema_version": STATEMENT_SCHEMA,
        "bundle_media_type": BUNDLE_MEDIA_TYPE,
    }


def _validate_public_signer_allowlists(
    signer: Mapping[str, Any],
    *,
    workflows: list[str],
    environments: list[str],
) -> None:
    for field in (
        "allowed_kinds",
        "allowed_workflows",
        "allowed_ref_prefixes",
        "allowed_environments",
    ):
        values = signer[field]
        if (
            not isinstance(values, list)
            or not values
            or values != sorted(set(values))
            or not all(isinstance(item, str) and item for item in values)
        ):
            raise PublicTrustKmsError(
                f"public-trust signer {field} must be sorted and unique"
            )
    if any(kind not in PUBLIC_EVIDENCE_KINDS for kind in signer["allowed_kinds"]):
        raise PublicTrustKmsError("public-trust signer object-kind allowlist is invalid")
    if signer["allowed_workflows"] != workflows:
        raise PublicTrustKmsError("public-trust signer workflow allowlist is invalid")
    if signer["allowed_ref_prefixes"] != ["refs/heads/main"]:
        raise PublicTrustKmsError("public-trust signer ref allowlist is invalid")
    if signer["allowed_environments"] != environments:
        raise PublicTrustKmsError("public-trust signer environment allowlist is invalid")
    if signer["status"] not in {"active", "revoked"}:
        raise PublicTrustKmsError("public-trust signer status is invalid")
    if signer["status"] == "active" and signer["revoked_at"] is not None:
        raise PublicTrustKmsError("an active public-trust signer cannot be revoked")
    if signer["status"] == "revoked":
        _timestamp(signer["revoked_at"], "public-trust signer revoked_at")


def _validate_kms_public_signer(value: Any) -> dict[str, Any]:
    signer = _closed(value, PUBLIC_SIGNER_FIELDS, "public-trust signer")
    if signer["algorithm"] != "ecdsa-p256-sha256":
        raise PublicTrustKmsError("public-trust signer algorithm is not supported")
    if signer["key_origin"] != "aws-kms":
        raise PublicTrustKmsError("public-trust signer must use AWS KMS")
    if (
        not isinstance(signer["kms_key_arn"], str)
        or KMS_KEY_ARN.fullmatch(signer["kms_key_arn"]) is None
    ):
        raise PublicTrustKmsError("public-trust signer KMS key ARN is invalid")
    key_bytes = _canonical_base64url(signer["public_key"], "public key")
    if len(key_bytes) != 65 or key_bytes[:1] != b"\x04":
        raise PublicTrustKmsError("public key must be an uncompressed P-256 point")
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), key_bytes
        )
    except ValueError as exc:
        raise PublicTrustKmsError("public key is not a valid P-256 point") from exc
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if _canonical_base64(
        signer["public_key_spki_der_base64"], "public key SPKI"
    ) != spki:
        raise PublicTrustKmsError("public key SPKI does not bind the public key")
    if signer["public_key_sha256"] != "sha256:" + hashlib.sha256(spki).hexdigest():
        raise PublicTrustKmsError("public key fingerprint does not bind the public key")
    expected_key_id = public_key_id(public_key)
    if signer["key_id"] != expected_key_id:
        raise PublicTrustKmsError("public-trust key id does not bind the public key")
    if signer["signature_encoding"] != "asn1-der-low-s-base64-rfc4648-padded":
        raise PublicTrustKmsError("public-trust signature encoding is not supported")
    if signer["statement_schema_versions"] != [STATEMENT_SCHEMA]:
        raise PublicTrustKmsError("public-trust statement schema is not supported")
    if signer["allowed_usages"] != ["production-public-evidence"]:
        raise PublicTrustKmsError("public-trust signer usage is not supported")
    _validate_public_signer_allowlists(
        signer,
        workflows=[PUBLIC_SIGNING_WORKFLOW],
        environments=["public-trust-signing"],
    )
    return signer


def _validate_software_public_signer(value: Any) -> dict[str, Any]:
    signer = _closed(value, SOFTWARE_SIGNER_FIELDS, "public-trust signer")
    if signer["algorithm"] != "ed25519":
        raise PublicTrustKmsError("public-trust signer algorithm is not supported")
    if signer["key_origin"] != SOFTWARE_KEY_ORIGIN:
        raise PublicTrustKmsError("public-trust Ed25519 signer must be software")
    key_bytes = _canonical_base64url(signer["public_key"], "public key")
    if len(key_bytes) != 32:
        raise PublicTrustKmsError("public key must encode 32 canonical Ed25519 bytes")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:
        raise PublicTrustKmsError("public key is not a valid Ed25519 key") from exc
    spki = ED25519_SPKI_PREFIX + key_bytes
    if _canonical_base64(
        signer["public_key_spki_der_base64"], "public key SPKI"
    ) != spki:
        raise PublicTrustKmsError("public key SPKI does not bind the public key")
    if signer["public_key_sha256"] != "sha256:" + hashlib.sha256(spki).hexdigest():
        raise PublicTrustKmsError("public key fingerprint does not bind the public key")
    if signer["key_id"] != software_public_key_id(public_key):
        raise PublicTrustKmsError("public-trust key id does not bind the public key")
    if signer["signature_encoding"] != "raw-64-base64-rfc4648-padded":
        raise PublicTrustKmsError("public-trust signature encoding is not supported")
    if signer["statement_schema_versions"] != [STATEMENT_SCHEMA]:
        raise PublicTrustKmsError("public-trust statement schema is not supported")
    if signer["allowed_usages"] != ["production-public-evidence"]:
        raise PublicTrustKmsError("public-trust signer usage is not supported")
    _validate_public_signer_allowlists(
        signer,
        workflows=[SOFTWARE_SIGNING_WORKFLOW],
        environments=[SOFTWARE_ENVIRONMENT],
    )
    return signer


def validate_public_signer(value: Any) -> dict[str, Any]:
    if (
        isinstance(value, dict)
        and value.get("algorithm") == "ed25519"
        and value.get("key_origin") == SOFTWARE_KEY_ORIGIN
    ):
        return _validate_software_public_signer(value)
    return _validate_kms_public_signer(value)


def validate_signing_statement(
    value: Any,
    *,
    signer: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    statement = _closed(value, STATEMENT_FIELDS, "public-trust signing statement")
    if statement["schema_version"] != STATEMENT_SCHEMA:
        raise PublicTrustKmsError("public-trust signing statement schema is not supported")
    if not isinstance(statement["object_kind"], str) or KIND.fullmatch(statement["object_kind"]) is None:
        raise PublicTrustKmsError("public-trust object kind is invalid")
    for field in ("object_schema_version", "object_media_type"):
        if not isinstance(statement[field], str) or not statement[field]:
            raise PublicTrustKmsError(f"public-trust {field} is invalid")
    for field in (
        "object_sha256",
        "semantic_identity_sha256",
        "signer_registry_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "request_id_sha256",
    ):
        _digest(statement[field], field)
    if (
        not isinstance(statement["object_size_bytes"], int)
        or isinstance(statement["object_size_bytes"], bool)
        or statement["object_size_bytes"] < 1
    ):
        raise PublicTrustKmsError("public-trust object size must be positive")
    issuer = _closed(statement["source_issuer"], ISSUER_FIELDS, "source issuer")
    for field in ("repository", "repository_id", "repository_owner_id", "workflow", "ref", "environment"):
        if not isinstance(issuer[field], str) or not issuer[field]:
            raise PublicTrustKmsError(f"source issuer {field} is invalid")
    if not isinstance(issuer["source_commit"], str) or HEX40.fullmatch(issuer["source_commit"]) is None:
        raise PublicTrustKmsError("source issuer commit is invalid")
    profile = statement["signature_profile"]
    if profile == SIGNATURE_PROFILE:
        authority = _validate_kms_statement_authority(statement)
    elif profile == SOFTWARE_SIGNATURE_PROFILE:
        authority = _validate_software_statement_authority(statement)
    else:
        raise PublicTrustKmsError("public-trust signature profile is invalid")
    issued_at = _timestamp(statement["issued_at"], "statement issued_at")
    not_before = _timestamp(statement["not_before"], "statement not_before")
    expires_at = _timestamp(statement["expires_at"], "statement expires_at")
    if not not_before <= issued_at < expires_at:
        raise PublicTrustKmsError("public-trust statement validity is invalid")
    if now is not None and not not_before <= now < expires_at:
        raise PublicTrustKmsError("public-trust signing statement is not active")
    if signer is not None:
        _bind_statement_to_signer(statement, signer, authority)
    return statement


def _shared_authority_identity(authority: Mapping[str, Any]) -> None:
    expected_identity = {
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "ref": "refs/heads/main",
    }
    for field, expected in expected_identity.items():
        if authority[field] != expected:
            raise PublicTrustKmsError(f"signing authority {field} is invalid")
    if not isinstance(authority["source_commit"], str) or HEX40.fullmatch(
        authority["source_commit"]
    ) is None:
        raise PublicTrustKmsError("signing authority commit is invalid")
    if not isinstance(authority["environment"], str) or not authority["environment"]:
        raise PublicTrustKmsError("signing authority environment is invalid")


def _validate_kms_statement_authority(statement: Mapping[str, Any]) -> dict[str, Any]:
    authority = _closed(
        statement["signing_authority"], AUTHORITY_FIELDS, "signing authority"
    )
    _shared_authority_identity(authority)
    expected_authority = {
        "workflow": ".github/workflows/sign-production-evidence.yml",
        "aws_account_id": KMS_ACCOUNT_ID,
        "aws_region": KMS_REGION,
        "kms_key_spec": KMS_KEY_SPEC,
        "kms_signing_algorithm": KMS_ALGORITHM,
        "kms_message_type": KMS_MESSAGE_TYPE,
        "role_arn": KMS_ROLE_ARN,
    }
    for field, expected in expected_authority.items():
        if authority[field] != expected:
            raise PublicTrustKmsError(f"signing authority {field} is invalid")
    if not isinstance(authority["kms_key_arn"], str) or KMS_KEY_ARN.fullmatch(
        authority["kms_key_arn"]
    ) is None:
        raise PublicTrustKmsError("signing authority KMS key ARN is invalid")
    if not isinstance(statement["key_id"], str) or KEY_ID.fullmatch(
        statement["key_id"]
    ) is None:
        raise PublicTrustKmsError("public-trust key id is invalid")
    return authority


def _validate_software_statement_authority(
    statement: Mapping[str, Any],
) -> dict[str, Any]:
    authority = _closed(
        statement["signing_authority"],
        SOFTWARE_AUTHORITY_FIELDS,
        "signing authority",
    )
    _shared_authority_identity(authority)
    if authority["workflow"] != SOFTWARE_WORKFLOW_PATH:
        raise PublicTrustKmsError("signing authority workflow is invalid")
    if authority["key_origin"] != SOFTWARE_KEY_ORIGIN:
        raise PublicTrustKmsError("signing authority key origin is invalid")
    if not isinstance(statement["key_id"], str) or SOFTWARE_KEY_ID.fullmatch(
        statement["key_id"]
    ) is None:
        raise PublicTrustKmsError("public-trust key id is invalid")
    return authority


def _bind_statement_to_signer(
    statement: Mapping[str, Any],
    signer: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> None:
    validated_signer = validate_public_signer(signer)
    if validated_signer["status"] != "active":
        raise PublicTrustKmsError("public-trust signer is not active")
    if statement["key_id"] != validated_signer["key_id"]:
        raise PublicTrustKmsError("statement key id does not match the signer")
    if statement["object_kind"] not in validated_signer["allowed_kinds"]:
        raise PublicTrustKmsError("signer is not authorized for this object kind")
    workflow_identity = (
        "https://github.com/OpenAdaptAI/.github/"
        + authority["workflow"]
        + "@"
        + authority["ref"]
    )
    if workflow_identity not in validated_signer["allowed_workflows"]:
        raise PublicTrustKmsError("signer is not authorized for this workflow")
    if not any(
        authority["ref"].startswith(prefix)
        for prefix in validated_signer["allowed_ref_prefixes"]
    ):
        raise PublicTrustKmsError("signer is not authorized for this ref")
    if authority["environment"] not in validated_signer["allowed_environments"]:
        raise PublicTrustKmsError("signer is not authorized for this environment")
    if validated_signer["algorithm"] == "ecdsa-p256-sha256":
        if statement["signature_profile"] != SIGNATURE_PROFILE:
            raise PublicTrustKmsError("statement profile does not match the signer")
        if authority["kms_key_arn"] != validated_signer["kms_key_arn"]:
            raise PublicTrustKmsError("statement KMS key does not match the signer")
        return
    if (
        validated_signer["algorithm"] == "ed25519"
        and validated_signer["key_origin"] == SOFTWARE_KEY_ORIGIN
    ):
        if statement["signature_profile"] != SOFTWARE_SIGNATURE_PROFILE:
            raise PublicTrustKmsError("statement profile does not match the signer")
        if authority.get("key_origin") != SOFTWARE_KEY_ORIGIN:
            raise PublicTrustKmsError("statement key origin does not match the signer")
        return
    raise PublicTrustKmsError("public-trust signer algorithm is not supported")


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    if not isinstance(payload_type, str) or not payload_type:
        raise PublicTrustKmsError("DSSE payload type is invalid")
    payload_type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(payload_type_bytes)).encode("ascii")
        + b" "
        + payload_type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def kms_message_digest(statement: Mapping[str, Any]) -> bytes:
    payload = canonical_lf(statement)
    return hashlib.sha256(dsse_pae(STATEMENT_MEDIA_TYPE, payload)).digest()


def verify_bundle(
    bundle_value: Any,
    *,
    expected_statement: Mapping[str, Any],
    signer: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    validated_signer = validate_public_signer(signer)
    statement = validate_signing_statement(
        expected_statement, signer=validated_signer, now=now
    )
    bundle = _closed(
        bundle_value,
        {"mediaType", "verificationMaterial", "dsseEnvelope"},
        "public-trust DSSE bundle",
    )
    if bundle["mediaType"] != BUNDLE_MEDIA_TYPE:
        raise PublicTrustKmsError("public-trust bundle media type is invalid")
    verification_material = _closed(
        bundle["verificationMaterial"], {"publicKey"}, "verification material"
    )
    public_key_hint = _closed(
        verification_material["publicKey"], {"hint"}, "public key hint"
    )
    if public_key_hint["hint"] != validated_signer["key_id"]:
        raise PublicTrustKmsError("public key hint does not match the signer")
    envelope = _closed(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        "DSSE envelope",
    )
    if envelope["payloadType"] != STATEMENT_MEDIA_TYPE:
        raise PublicTrustKmsError("DSSE payload type is invalid")
    payload = _canonical_base64(envelope["payload"], "DSSE payload")
    expected_payload = canonical_lf(statement)
    if payload != expected_payload:
        raise PublicTrustKmsError("DSSE payload does not match the signing statement")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise PublicTrustKmsError("DSSE envelope must contain exactly one signature")
    signature_entry = _closed(
        signatures[0], {"keyid", "sig"}, "DSSE signature"
    )
    if signature_entry["keyid"] != validated_signer["key_id"]:
        raise PublicTrustKmsError("DSSE signature key id does not match the signer")
    signature = _canonical_base64(signature_entry["sig"], "DSSE signature")
    pae = dsse_pae(STATEMENT_MEDIA_TYPE, payload)
    public_key_bytes = _canonical_base64url(
        validated_signer["public_key"], "public key"
    )
    if validated_signer["algorithm"] == "ed25519":
        if len(signature) != 64:
            raise PublicTrustKmsError("Ed25519 DSSE signature must be 64 bytes")
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(signature, pae)
        except InvalidSignature as exc:
            raise PublicTrustKmsError("DSSE signature verification failed") from exc
        return bundle
    try:
        _, signature_s = decode_dss_signature(signature)
    except ValueError as exc:
        raise PublicTrustKmsError("DSSE signature is not canonical ASN.1 DER") from exc
    if signature_s > P256_ORDER // 2:
        raise PublicTrustKmsError("DSSE signature must use canonical low-S form")
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )
    try:
        public_key.verify(signature, pae, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise PublicTrustKmsError("DSSE signature verification failed") from exc
    return bundle


def statement_from_bundle(bundle_value: Any) -> dict[str, Any]:
    bundle = _closed(
        bundle_value,
        {"mediaType", "verificationMaterial", "dsseEnvelope"},
        "public-trust DSSE bundle",
    )
    envelope = _closed(
        bundle["dsseEnvelope"],
        {"payload", "payloadType", "signatures"},
        "DSSE envelope",
    )
    if envelope["payloadType"] != STATEMENT_MEDIA_TYPE:
        raise PublicTrustKmsError("DSSE payload type is invalid")
    payload = _canonical_base64(envelope["payload"], "DSSE payload")
    if payload[-1:] != b"\n":
        raise PublicTrustKmsError("DSSE payload must end with exactly one LF")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PublicTrustKmsError("DSSE payload is not JSON") from exc
    if payload != canonical_lf(value):
        raise PublicTrustKmsError("DSSE payload is not canonical JSON plus LF")
    return validate_signing_statement(value)


def validate_statement_object_binding(
    statement_value: Any,
    *,
    object_raw: bytes,
    object_value: Mapping[str, Any],
    object_kind: str,
    object_schema_version: str,
    object_media_type: str,
    semantic_identity_sha256: str,
    expected_signer_registry_sha256: str,
    expected_authority_state_sha256: str,
    expected_revocation_state_sha256: str,
) -> dict[str, Any]:
    statement = validate_signing_statement(statement_value)
    if object_raw != canonical_lf(object_value):
        raise PublicTrustKmsError("public-trust object must be canonical JSON plus LF")
    bindings = {
        "object_kind": object_kind,
        "object_schema_version": object_schema_version,
        "object_media_type": object_media_type,
        "object_sha256": "sha256:" + hashlib.sha256(object_raw).hexdigest(),
        "object_size_bytes": len(object_raw),
        "semantic_identity_sha256": semantic_identity_sha256,
    }
    for field, expected in bindings.items():
        if statement[field] != expected:
            raise PublicTrustKmsError(f"public-trust statement {field} binding differs")
    source_issuer = object_value.get("issuer")
    if not isinstance(source_issuer, dict):
        raise PublicTrustKmsError("public-trust object has no signed issuer")
    projected_issuer = {field: source_issuer[field] for field in ISSUER_FIELDS if field in source_issuer}
    if set(projected_issuer) != ISSUER_FIELDS or statement["source_issuer"] != projected_issuer:
        raise PublicTrustKmsError("public-trust statement source issuer binding differs")
    expected_trust_state = {
        "signer_registry_sha256": expected_signer_registry_sha256,
        "authority_state_sha256": expected_authority_state_sha256,
        "revocation_state_sha256": expected_revocation_state_sha256,
    }
    for field, expected in expected_trust_state.items():
        _digest(expected, f"expected {field}")
        if statement[field] != expected:
            raise PublicTrustKmsError(f"public-trust statement {field} binding differs")
        if field in object_value and object_value[field] != expected:
            raise PublicTrustKmsError(f"public-trust object {field} binding differs")
    return statement


def software_public_signer(
    public_key: Ed25519PublicKey,
    *,
    allowed_kinds: list[str] | None = None,
    status: str = "active",
    revoked_at: str | None = None,
) -> dict[str, Any]:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    spki = ED25519_SPKI_PREFIX + raw
    kinds = sorted(PUBLIC_EVIDENCE_KINDS) if allowed_kinds is None else list(allowed_kinds)
    return validate_public_signer(
        {
            "algorithm": "ed25519",
            "key_id": software_public_key_id(public_key),
            "key_origin": SOFTWARE_KEY_ORIGIN,
            "public_key": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
            "public_key_spki_der_base64": base64.b64encode(spki).decode("ascii"),
            "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
            "signature_encoding": "raw-64-base64-rfc4648-padded",
            "statement_schema_versions": [STATEMENT_SCHEMA],
            "allowed_usages": ["production-public-evidence"],
            "allowed_kinds": kinds,
            "allowed_workflows": [SOFTWARE_SIGNING_WORKFLOW],
            "allowed_ref_prefixes": ["refs/heads/main"],
            "allowed_environments": [SOFTWARE_ENVIRONMENT],
            "status": status,
            "revoked_at": revoked_at,
        }
    )


def load_software_private_key(
    *,
    pem: bytes | None = None,
    pem_file: str | os.PathLike[str] | None = None,
    use_keychain: bool = False,
    use_env: bool = False,
) -> Ed25519PrivateKey:
    """Load PKCS8 PEM the same way ``qualification_software_ed25519`` does.

    macOS ``security -w`` hex-encodes a PEM that contains newlines. GitHub
    stores UTF-8 PEM. The inner signer decoder accepts both.
    """

    import qualification_software_ed25519 as software

    if pem is not None:
        return software.load_private_key(pem)
    return software.load_private_key_from_sources(
        pem_file=Path(pem_file) if pem_file is not None else None,
        use_keychain=use_keychain,
        use_env=use_env,
    )


def sign_software_bundle(
    statement_value: Mapping[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    signer: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign one public-trust statement with the software Ed25519 key."""

    validated_signer = (
        validate_public_signer(signer)
        if signer is not None
        else software_public_signer(private_key.public_key())
    )
    if (
        validated_signer["algorithm"] != "ed25519"
        or validated_signer["key_origin"] != SOFTWARE_KEY_ORIGIN
    ):
        raise PublicTrustKmsError("software bundle requires a software Ed25519 signer")
    expected_key_id = software_public_key_id(private_key.public_key())
    if validated_signer["key_id"] != expected_key_id:
        raise PublicTrustKmsError("signer key id does not match the private key")
    statement = validate_signing_statement(
        statement_value, signer=validated_signer, now=now
    )
    if statement["signature_profile"] != SOFTWARE_SIGNATURE_PROFILE:
        raise PublicTrustKmsError("statement is not the software Ed25519 profile")
    payload = canonical_lf(statement)
    signature = private_key.sign(dsse_pae(STATEMENT_MEDIA_TYPE, payload))
    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {"publicKey": {"hint": statement["key_id"]}},
        "dsseEnvelope": {
            "payload": base64.b64encode(payload).decode("ascii"),
            "payloadType": STATEMENT_MEDIA_TYPE,
            "signatures": [
                {
                    "keyid": statement["key_id"],
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
    }
    return verify_bundle(
        bundle,
        expected_statement=statement,
        signer=validated_signer,
        now=now,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("software-interface")

    sign_parser = subparsers.add_parser("sign-software")
    sign_parser.add_argument("--statement", required=True)
    sign_parser.add_argument("--signer")
    sign_parser.add_argument("--pem-file")
    sign_parser.add_argument("--from-env", action="store_true")
    sign_parser.add_argument("--from-keychain", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "software-interface":
            result: Any = software_interface_contract()
        else:
            sources = [args.pem_file, args.from_env, args.from_keychain]
            if sum(bool(item) for item in sources) != 1:
                raise PublicTrustKmsError("choose one private key source")
            private_key = load_software_private_key(
                pem_file=args.pem_file,
                use_keychain=args.from_keychain,
                use_env=args.from_env,
            )
            statement = json.loads(Path(args.statement).read_text(encoding="utf-8"))
            signer = None
            if args.signer:
                signer = json.loads(Path(args.signer).read_text(encoding="utf-8"))
            result = sign_software_bundle(
                statement, private_key=private_key, signer=signer
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
