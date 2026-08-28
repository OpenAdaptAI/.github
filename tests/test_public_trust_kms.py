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

import public_trust_kms as kms  # noqa: E402
import public_trust_resolver as resolver  # noqa: E402
import validate_evidence_registry as evidence  # noqa: E402

NOW = datetime(2026, 8, 27, 12, 0, 30, tzinfo=timezone.utc)
KMS_ARN = "arn:aws:kms:us-east-1:992382684924:key/12345678-1234-4abc-8def-1234567890ab"


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


def object_value(registry_sha256: str = sha("registry")) -> dict:
    return {
        "schema_version": "test/v1",
        "authority_state_sha256": sha("authority"),
        "revocation_state_sha256": sha("revocation"),
        "signer_registry_sha256": registry_sha256,
        "issuer": source_issuer(),
    }


def statement(registry_sha256: str = sha("registry")) -> dict:
    value = object_value(registry_sha256)
    raw = kms.canonical_lf(value)
    active_signer = signer()
    return {
        "schema_version": kms.STATEMENT_SCHEMA,
        "object_kind": "qualification-release",
        "object_schema_version": "openadapt.qualification-release/v2",
        "object_media_type": "application/vnd.openadapt.qualification-release+json;version=2",
        "object_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "object_size_bytes": len(raw),
        "semantic_identity_sha256": sha("release-identity"),
        "source_issuer": source_issuer(),
        "signer_registry_sha256": registry_sha256,
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


def reference(kind: str, raw: bytes, *, semantic: str, subject: str | None) -> dict:
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
        "semantic_identity_sha256": semantic,
        "subject_sha256": subject,
    }
    entry["registry_entry_sha256"] = evidence.entry_digest(entry)
    return {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": "c" * 40,
        "registry_revision": 5,
        "registry_head_sha256": sha("registry-head"),
        **entry,
    }


def registry_raw() -> bytes:
    value = {
        "schema_version": evidence.SIGNER_REGISTRY_SCHEMA,
        "revision": 5,
        "generated_at": "2026-08-27T11:00:00Z",
        "expires_at": "2026-08-27T13:00:00Z",
        "signers": [signer()],
    }
    return evidence.canonical(value) + b"\n"


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
            "f903b1f45b4f6f24e97c95309299e93587ee0489f76aacf23f144e6edada59fb",
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
                object_schema_version="openadapt.qualification-release/v2",
                object_media_type="application/vnd.openadapt.qualification-release+json;version=2",
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
                object_schema_version="openadapt.qualification-release/v2",
                object_media_type="application/vnd.openadapt.qualification-release+json;version=2",
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
        wrong_workflow["signing_authority"]["workflow"] = (
            ".github/workflows/release.yml"
        )
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

    def test_registered_pair_resolves_raw_bytes_and_current_state_offline(self) -> None:
        signer_registry_raw = registry_raw()
        registry_identity = evidence.signer_registry_identity_digest(
            json.loads(signer_registry_raw)
        )
        signed_object = object_value(registry_identity)
        object_raw = kms.canonical_lf(signed_object)
        semantic = evidence.semantic_identity_digest(
            kind="qualification-release",
            object_schema_version="openadapt.qualification-release/v2",
            object_value=signed_object,
            object_sha256="sha256:" + hashlib.sha256(object_raw).hexdigest(),
        )
        signed_statement = statement(registry_identity)
        signed_statement["object_sha256"] = (
            "sha256:" + hashlib.sha256(object_raw).hexdigest()
        )
        signed_statement["object_size_bytes"] = len(object_raw)
        signed_statement["semantic_identity_sha256"] = semantic
        signed_bundle = bundle(signed_statement)
        bundle_raw = kms.canonical_lf(signed_bundle)
        object_ref = reference(
            "qualification-release",
            object_raw,
            semantic=semantic,
            subject=None,
        )
        bundle_sha = "sha256:" + hashlib.sha256(bundle_raw).hexdigest()
        bundle_ref = reference(
            "qualification-release-sigstore-bundle",
            bundle_raw,
            semantic=evidence.semantic_identity_digest(
                kind="qualification-release-sigstore-bundle",
                object_schema_version="sigstore.bundle/v0.3",
                object_value=object_ref["object_sha256"],
                object_sha256=bundle_sha,
            ),
            subject=object_ref["object_sha256"],
        )
        result = resolver.verify_registered_public_trust_pair(
            object_raw=object_raw,
            object_reference=object_ref,
            bundle_raw=bundle_raw,
            bundle_reference=bundle_ref,
            signer_registry_raw=signer_registry_raw,
            expected_signer_registry_sha256=registry_identity,
            expected_authority_state_sha256=sha("authority"),
            expected_revocation_state_sha256=sha("revocation"),
            now=NOW,
        )
        self.assertEqual(result["object"], signed_object)
        self.assertEqual(result["signing_statement"], signed_statement)

    def test_registered_pair_refuses_raw_tamper_wrong_state_and_wrong_key(self) -> None:
        signer_registry_raw = registry_raw()
        registry_identity = evidence.signer_registry_identity_digest(
            json.loads(signer_registry_raw)
        )
        signed_object = object_value(registry_identity)
        object_raw = kms.canonical_lf(signed_object)
        semantic = evidence.semantic_identity_digest(
            kind="qualification-release",
            object_schema_version="openadapt.qualification-release/v2",
            object_value=signed_object,
            object_sha256="sha256:" + hashlib.sha256(object_raw).hexdigest(),
        )
        signed_statement = statement(registry_identity)
        signed_statement["object_sha256"] = (
            "sha256:" + hashlib.sha256(object_raw).hexdigest()
        )
        signed_statement["object_size_bytes"] = len(object_raw)
        signed_statement["semantic_identity_sha256"] = semantic
        signed_bundle = bundle(signed_statement)
        bundle_raw = kms.canonical_lf(signed_bundle)
        object_ref = reference(
            "qualification-release",
            object_raw,
            semantic=semantic,
            subject=None,
        )
        bundle_sha = "sha256:" + hashlib.sha256(bundle_raw).hexdigest()
        bundle_ref = reference(
            "qualification-release-sigstore-bundle",
            bundle_raw,
            semantic=evidence.semantic_identity_digest(
                kind="qualification-release-sigstore-bundle",
                object_schema_version="sigstore.bundle/v0.3",
                object_value=object_ref["object_sha256"],
                object_sha256=bundle_sha,
            ),
            subject=object_ref["object_sha256"],
        )
        base = {
            "object_raw": object_raw,
            "object_reference": object_ref,
            "bundle_raw": bundle_raw,
            "bundle_reference": bundle_ref,
            "signer_registry_raw": signer_registry_raw,
            "expected_signer_registry_sha256": registry_identity,
            "expected_authority_state_sha256": sha("authority"),
            "expected_revocation_state_sha256": sha("revocation"),
            "now": NOW,
        }
        for label, mutate, message in (
            (
                "object bytes",
                lambda value: value.__setitem__("object_raw", object_raw + b" "),
                "bytes or size",
            ),
            (
                "authority state",
                lambda value: value.__setitem__(
                    "expected_authority_state_sha256", sha("other-authority")
                ),
                "authority_state_sha256",
            ),
            (
                "registry identity",
                lambda value: value.__setitem__(
                    "expected_signer_registry_sha256", sha("other-registry")
                ),
                "not current",
            ),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(base)
                mutate(changed)
                with self.assertRaisesRegex(
                    resolver.PublicTrustResolutionError, message
                ):
                    resolver.verify_registered_public_trust_pair(**changed)


if __name__ == "__main__":
    unittest.main()
