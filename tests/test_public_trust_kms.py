"""Tests for the offline AWS KMS P-256 public-trust DSSE profile."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_trust_kms as kms

NOW = datetime(2026, 8, 27, 12, 0, 30, tzinfo=timezone.utc)
KMS_ARN = (
    "arn:aws:kms:us-east-1:992382684924:key/"
    "12345678-1234-4abc-8def-1234567890ab"
)


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def private_key() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(
        int("2f29c1f30c9db50a15e08ddd4f5f49d1f5c621d40ad72835d11065448148d8c7", 16),
        ec.SECP256R1(),
    )


def signer(*, status: str = "active") -> dict:
    public_key = private_key().public_key()
    point = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "algorithm": "ecdsa-p256-sha256",
        "key_id": kms.public_key_id(public_key),
        "key_origin": "aws-kms",
        "kms_key_arn": KMS_ARN,
        "public_key": base64.urlsafe_b64encode(point).decode().rstrip("="),
        "public_key_spki_der_base64": base64.b64encode(spki).decode(),
        "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
        "signature_encoding": "asn1-der-low-s-base64-rfc4648-padded",
        "statement_schema_versions": [kms.STATEMENT_SCHEMA],
        "allowed_usages": ["production-public-evidence"],
        "allowed_kinds": ["qualification-release"],
        "allowed_workflows": [
            (
                "https://github.com/OpenAdaptAI/.github/"
                ".github/workflows/sign-production-evidence.yml@refs/heads/main"
            )
        ],
        "allowed_ref_prefixes": ["refs/heads/main"],
        "allowed_environments": ["public-trust-signing"],
        "status": status,
        "revoked_at": "2026-08-27T11:59:00Z" if status == "revoked" else None,
    }


def source_issuer() -> dict:
    return {
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "workflow": ".github/workflows/issue-production-release-admission.yml",
        "ref": "refs/heads/main",
        "source_commit": "a" * 40,
        "environment": "production-release-admission",
    }


def object_value() -> dict:
    return {
        "schema_version": "test/v1",
        "authority_state_sha256": sha("authority"),
        "revocation_state_sha256": sha("revocation"),
        "signer_registry_sha256": sha("registry"),
        "issuer": source_issuer(),
    }


def statement() -> dict:
    value = object_value()
    raw = kms.canonical_lf(value)
    active_signer = signer()
    return {
        "schema_version": kms.STATEMENT_SCHEMA,
        "object_kind": "qualification-release",
        "object_schema_version": "openadapt.qualification-release/v1",
        "object_media_type": "application/vnd.openadapt.qualification-release+json;version=1",
        "object_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "object_size_bytes": len(raw),
        "semantic_identity_sha256": sha("release-identity"),
        "source_issuer": source_issuer(),
        "signer_registry_sha256": sha("registry"),
        "authority_state_sha256": sha("authority"),
        "revocation_state_sha256": sha("revocation"),
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-08-27T12:05:00Z",
        "request_id_sha256": sha("request"),
        "signing_authority": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/sign-production-evidence.yml",
            "ref": "refs/heads/main",
            "source_commit": "b" * 40,
            "environment": "public-trust-signing",
            "aws_account_id": "992382684924",
            "aws_region": "us-east-1",
            "kms_key_arn": KMS_ARN,
            "kms_key_spec": "ECC_NIST_P256",
            "kms_signing_algorithm": "ECDSA_SHA_256",
            "kms_message_type": "DIGEST",
            "role_arn": "arn:aws:iam::992382684924:role/openadapt-public-trust-signer",
        },
        "key_id": active_signer["key_id"],
        "signature_profile": "aws-kms-p256-dsse-v1",
    }


def bundle(value: dict | None = None) -> dict:
    signed_statement = value or statement()
    payload = kms.canonical_lf(signed_statement)
    signature = private_key().sign(
        kms.dsse_pae(kms.STATEMENT_MEDIA_TYPE, payload), ec.ECDSA(hashes.SHA256())
    )
    signature_r, signature_s = decode_dss_signature(signature)
    if signature_s > kms.P256_ORDER // 2:
        signature_s = kms.P256_ORDER - signature_s
    signature = encode_dss_signature(signature_r, signature_s)
    key_id = signer()["key_id"]
    return {
        "mediaType": kms.BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {"publicKey": {"hint": key_id}},
        "dsseEnvelope": {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": kms.STATEMENT_MEDIA_TYPE,
            "signatures": [
                {"keyid": key_id, "sig": base64.b64encode(signature).decode()}
            ],
        },
    }


class PublicTrustKmsTests(unittest.TestCase):
    def test_fixed_key_and_dsse_pae_digest_vector(self) -> None:
        active_signer = signer()
        self.assertEqual(
            active_signer["key_id"], "oa-public-trust-p256-93dbc7899ed2892d"
        )
        self.assertEqual(
            active_signer["public_key_sha256"],
            "sha256:93dbc7899ed2892d0215567d8f8f7a2b00d44246d8c6a9f8cb40c4355c1234d3",
        )
        self.assertEqual(
            kms.kms_message_digest(statement()).hex(),
            "272b5a49125aac7591703c97fc50bc42cc31c678f762e557830279ba09772aa1",
        )

    def test_exact_statement_signer_and_bundle_verify_offline(self) -> None:
        active_signer = signer()
        signed_statement = statement()
        self.assertEqual(kms.validate_public_signer(active_signer), active_signer)
        self.assertEqual(
            kms.validate_signing_statement(
                signed_statement, signer=active_signer, now=NOW
            ),
            signed_statement,
        )
        signed_bundle = bundle(signed_statement)
        self.assertEqual(
            kms.verify_bundle(
                signed_bundle,
                expected_statement=signed_statement,
                signer=active_signer,
                now=NOW,
            ),
            signed_bundle,
        )

    def test_statement_binds_exact_canonical_object_and_signed_issuer(self) -> None:
        value = object_value()
        raw = kms.canonical_lf(value)
        self.assertEqual(
            kms.validate_statement_object_binding(
                statement(),
                object_raw=raw,
                object_value=value,
                object_kind="qualification-release",
                object_schema_version="openadapt.qualification-release/v1",
                object_media_type="application/vnd.openadapt.qualification-release+json;version=1",
                semantic_identity_sha256=sha("release-identity"),
                expected_signer_registry_sha256=sha("registry"),
                expected_authority_state_sha256=sha("authority"),
                expected_revocation_state_sha256=sha("revocation"),
            ),
            statement(),
        )
        with self.assertRaisesRegex(kms.PublicTrustKmsError, "canonical JSON"):
            kms.validate_statement_object_binding(
                statement(),
                object_raw=json.dumps(value, indent=2).encode() + b"\n",
                object_value=value,
                object_kind="qualification-release",
                object_schema_version="openadapt.qualification-release/v1",
                object_media_type="application/vnd.openadapt.qualification-release+json;version=1",
                semantic_identity_sha256=sha("release-identity"),
                expected_signer_registry_sha256=sha("registry"),
                expected_authority_state_sha256=sha("authority"),
                expected_revocation_state_sha256=sha("revocation"),
            )

    def test_kms_digest_is_sha256_of_exact_dsse_pae(self) -> None:
        value = statement()
        expected = hashlib.sha256(
            kms.dsse_pae(kms.STATEMENT_MEDIA_TYPE, kms.canonical_lf(value))
        ).digest()
        self.assertEqual(kms.kms_message_digest(value), expected)
        self.assertEqual(len(expected), 32)

    def test_tamper_profile_workflow_expiry_revocation_and_alias_fail(self) -> None:
        active_signer = signer()
        signed_statement = statement()
        signed_bundle = bundle(signed_statement)

        tampered = copy.deepcopy(signed_bundle)
        tampered["dsseEnvelope"]["payloadType"] = "application/json"
        with self.assertRaisesRegex(kms.PublicTrustKmsError, "payload type"):
            kms.verify_bundle(
                tampered,
                expected_statement=signed_statement,
                signer=active_signer,
            )

        wrong_profile = copy.deepcopy(signed_statement)
        wrong_profile["signature_profile"] = "github-attestation"
        with self.assertRaisesRegex(kms.PublicTrustKmsError, "profile"):
            kms.validate_signing_statement(wrong_profile)

        wrong_workflow = copy.deepcopy(signed_statement)
        wrong_workflow["signing_authority"]["workflow"] = ".github/workflows/release.yml"
        with self.assertRaisesRegex(kms.PublicTrustKmsError, "workflow"):
            kms.validate_signing_statement(wrong_workflow)

        with self.assertRaisesRegex(kms.PublicTrustKmsError, "not active"):
            kms.verify_bundle(
                signed_bundle,
                expected_statement=signed_statement,
                signer=active_signer,
                now=datetime(2026, 8, 27, 12, 5, 0, tzinfo=timezone.utc),
            )

        with self.assertRaisesRegex(kms.PublicTrustKmsError, "not active"):
            kms.verify_bundle(
                signed_bundle,
                expected_statement=signed_statement,
                signer=signer(status="revoked"),
                now=NOW,
            )

        alias_signer = signer()
        alias_signer["kms_key_arn"] = (
            "arn:aws:kms:us-east-1:992382684924:alias/openadapt-public-trust"
        )
        with self.assertRaisesRegex(kms.PublicTrustKmsError, "ARN"):
            kms.validate_public_signer(alias_signer)

    def test_bundle_rejects_profile_substitution_and_extra_fields(self) -> None:
        active_signer = signer()
        signed_statement = statement()
        for label, mutate in (
            (
                "message signature",
                lambda value: value.__setitem__("messageSignature", {}),
            ),
            (
                "keyless material",
                lambda value: value["verificationMaterial"].__setitem__(
                    "x509CertificateChain", {}
                ),
            ),
            (
                "second signature",
                lambda value: value["dsseEnvelope"]["signatures"].append(
                    copy.deepcopy(value["dsseEnvelope"]["signatures"][0])
                ),
            ),
        ):
            with self.subTest(label=label):
                changed = bundle(signed_statement)
                mutate(changed)
                with self.assertRaises(kms.PublicTrustKmsError):
                    kms.verify_bundle(
                        changed,
                        expected_statement=signed_statement,
                        signer=active_signer,
                    )


if __name__ == "__main__":
    unittest.main()
