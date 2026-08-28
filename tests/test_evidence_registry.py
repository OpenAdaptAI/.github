"""Fail-closed tests for production evidence object references v2."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_trust_kms as kms  # noqa: E402
import stage_production_evidence as stage  # noqa: E402
import validate_evidence_registry as registry  # noqa: E402


def sha(character: str) -> str:
    return "sha256:" + character * 64


def entry(kind: str = "production-acceptance-manifest", **overrides) -> dict:
    schema, media = registry.OBJECT_KIND_CONTRACTS[kind]
    object_sha = overrides.pop("object_sha256", sha("a"))
    digest_hex = object_sha.removeprefix("sha256:")
    value = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha,
        "size_bytes": 123,
        "object_media_type": media,
        "semantic_identity_sha256": sha("b"),
        "subject_sha256": None,
    }
    value.update(overrides)
    value["registry_entry_sha256"] = registry.entry_digest(value)
    return value


def document(entries: list[dict] | None = None, **overrides) -> dict:
    values = entries or []
    value = {
        "$schema": "schemas/evidence-registry.schema.json",
        "schema_version": registry.REGISTRY_SCHEMA,
        "repository": registry.REPOSITORY,
        "repository_id": registry.REPOSITORY_ID,
        "repository_owner_id": registry.REPOSITORY_OWNER_ID,
        "revision": 1,
        "previous_registry_head_sha256": None,
        "registry_head_sha256": sha("0"),
        "signer_registry": None,
        "signer_registry_history": [],
        "entries": values,
    }
    value.update(overrides)
    value["registry_head_sha256"] = registry.registry_head_digest(value)
    return value


def reference(value: dict, **overrides) -> dict:
    result = {
        "schema_version": registry.REFERENCE_SCHEMA,
        "repository": registry.REPOSITORY,
        "repository_id": registry.REPOSITORY_ID,
        "repository_owner_id": registry.REPOSITORY_OWNER_ID,
        "registry_source_commit": "c" * 40,
        "registry_revision": 7,
        "registry_head_sha256": sha("d"),
        **value,
    }
    result.update(overrides)
    return result


def ed25519_signer(
    key_byte: int,
    usage: str,
    *,
    status: str = "active",
) -> dict:
    key = bytes([key_byte]) * 32
    spki = bytes.fromhex("302a300506032b6570032100") + key
    return {
        "algorithm": "ed25519",
        "key_id": "qa-ed25519-" + hashlib.sha256(key).hexdigest()[:16],
        "public_key": base64.urlsafe_b64encode(key).decode().rstrip("="),
        "public_key_spki_der_base64": base64.b64encode(spki).decode(),
        "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
        "statement_schema_versions": [
            "openadapt.qualification-evidence-signing-statement/v1"
        ],
        "allowed_usages": [usage],
        "allowed_workflows": [
            (
                "https://github.com/OpenAdaptAI/openadapt-internal/"
                ".github/workflows/issue-private-qualification-evidence-decision.yml"
                "@refs/heads/main"
            )
        ],
        "allowed_ref_prefixes": ["refs/heads/main"],
        "status": status,
        "revoked_at": "2026-08-27T01:00:00Z" if status == "revoked" else None,
    }


def signer_registry(*signers: dict) -> dict:
    return {
        "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
        "revision": 1,
        "generated_at": "2026-08-27T00:00:00Z",
        "expires_at": "2026-09-03T00:00:00Z",
        "signers": list(signers),
    }


class EvidenceRegistryTests(unittest.TestCase):
    def test_kind_map_has_17_regular_and_17_bundle_kinds(self) -> None:
        self.assertEqual(len(registry.REGULAR_KIND_CONTRACTS), 17)
        self.assertEqual(len(registry.OBJECT_KIND_CONTRACTS), 34)
        self.assertEqual(
            registry.REGULAR_KIND_CONTRACTS["support-release-admission"],
            (
                "openadapt.support-release-admission/v1",
                "application/vnd.openadapt.support-release-admission+json;version=1",
            ),
        )
        self.assertNotIn(
            "openadapt-tray",
            {"agent", "capture", "cloud", "desktop", "docs", "flow", "openadapt"},
        )

    def test_repository_registry_is_valid_v2(self) -> None:
        value = json.loads((ROOT / "evidence-registry.json").read_text())
        self.assertEqual(registry.validate_registry(value, root=ROOT), [])

    def test_reference_has_exact_16_keys_and_derives_raw_url(self) -> None:
        value = reference(entry())
        self.assertEqual(set(value), registry.REFERENCE_FIELDS)
        registry.validate_reference(value)
        self.assertEqual(
            registry.raw_github_url(value),
            "https://raw.githubusercontent.com/OpenAdaptAI/.github/"
            + "c" * 40
            + "/"
            + value["object_path"],
        )

    def test_url_field_is_refused(self) -> None:
        value = reference(entry())
        value["url"] = "https://evidence.openadapt.ai/object.json"
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "exactly"):
            registry.validate_reference(value)

    def test_repository_id_and_commit_are_pinned(self) -> None:
        value = reference(entry(), repository_id="1")
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "repository"):
            registry.validate_reference(value)
        value = reference(entry(), registry_source_commit="main")
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "commit"):
            registry.validate_reference(value)

    def test_object_path_must_bind_digest_and_kind(self) -> None:
        value = entry()
        value["object_path"] = "production-evidence/objects/sha256/aa/wrong.json"
        value["registry_entry_sha256"] = registry.entry_digest(value)
        with self.assertRaisesRegex(
            registry.EvidenceRegistryError, "content-addressed"
        ):
            registry.validate_reference(reference(value))

    def test_bundle_must_immediately_follow_and_bind_regular_object(self) -> None:
        regular = entry()
        bundle = entry(
            "production-acceptance-manifest-sigstore-bundle",
            object_sha256=sha("e"),
            subject_sha256=regular["object_sha256"],
        )
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "signer registry"):
            registry.validate_registry(document([regular, bundle]))
        signer = {
            "schema_version": registry.SIGNER_POINTER_SCHEMA,
            "object_path": (
                "production-evidence/signer-registries/sha256/ff/"
                + "f" * 64
                + ".qualification-signer-registry.json"
            ),
            "object_sha256": sha("f"),
            "registry_identity_sha256": sha("1"),
            "registry_revision": 1,
        }
        valid = document(
            [regular, bundle],
            signer_registry=signer,
            signer_registry_history=[signer],
        )
        registry.validate_registry(valid)
        trailing = document(
            [regular], signer_registry=signer, signer_registry_history=[signer]
        )
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "every regular"):
            registry.validate_registry(trailing)
        invalid = copy.deepcopy(valid)
        invalid["entries"].reverse()
        invalid["registry_head_sha256"] = registry.registry_head_digest(invalid)
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "immediately"):
            registry.validate_registry(invalid)

    def test_registry_readback_binds_exact_bytes_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b'{"schema_version":"openadapt.production-acceptance/v3"}\n'
            object_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
            regular = entry(
                object_sha256=object_sha,
                size_bytes=len(raw),
                semantic_identity_sha256=registry.semantic_identity_digest(
                    kind="production-acceptance-manifest",
                    object_schema_version="openadapt.production-acceptance/v3",
                    object_value=json.loads(raw),
                    object_sha256=object_sha,
                ),
            )
            path = root / regular["object_path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            bundle_raw = (
                b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
            )
            bundle_sha = "sha256:" + hashlib.sha256(bundle_raw).hexdigest()
            bundle = entry(
                "production-acceptance-manifest-sigstore-bundle",
                object_sha256=bundle_sha,
                size_bytes=len(bundle_raw),
                subject_sha256=regular["object_sha256"],
                semantic_identity_sha256=registry.semantic_identity_digest(
                    kind="production-acceptance-manifest-sigstore-bundle",
                    object_schema_version=registry.BUNDLE_MEDIA_TYPE,
                    object_value=regular["object_sha256"],
                    object_sha256=bundle_sha,
                ),
            )
            bundle_path = root / bundle["object_path"]
            bundle_path.parent.mkdir(parents=True)
            bundle_path.write_bytes(bundle_raw)
            signer = {
                "schema_version": registry.SIGNER_POINTER_SCHEMA,
                "object_path": (
                    "production-evidence/signer-registries/sha256/ff/"
                    + "f" * 64
                    + ".qualification-signer-registry.json"
                ),
                "object_sha256": sha("f"),
                "registry_identity_sha256": sha("1"),
                "registry_revision": 1,
            }
            value = document(
                [regular, bundle],
                signer_registry=signer,
                signer_registry_history=[signer],
            )
            with self.assertRaisesRegex(
                registry.EvidenceRegistryError, "signer registry"
            ):
                registry.validate_registry(value, root=root)
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(registry.EvidenceRegistryError, "bytes differ"):
                registry.validate_registry(value, root=root)

    def test_signer_registry_key_id_binds_canonical_key(self) -> None:
        key = bytes(range(32))
        public_key = registry.base64.urlsafe_b64encode(key).decode().rstrip("=")
        spki = bytes.fromhex("302a300506032b6570032100") + key
        value = {
            "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
            "revision": 1,
            "generated_at": "2026-08-27T00:00:00Z",
            "expires_at": "2026-09-03T00:00:00Z",
            "signers": [
                {
                    "algorithm": "ed25519",
                    "key_id": "qa-ed25519-" + hashlib.sha256(key).hexdigest()[:16],
                    "public_key": public_key,
                    "public_key_spki_der_base64": registry.base64.b64encode(
                        spki
                    ).decode(),
                    "public_key_sha256": ("sha256:" + hashlib.sha256(spki).hexdigest()),
                    "statement_schema_versions": [
                        "openadapt.qualification-evidence-signing-statement/v1"
                    ],
                    "allowed_usages": ["qualification-evidence-decision-receipt"],
                    "allowed_workflows": [
                        (
                            "https://github.com/OpenAdaptAI/openadapt-internal/"
                            ".github/workflows/"
                            "issue-private-qualification-evidence-decision.yml"
                            "@refs/heads/main"
                        )
                    ],
                    "allowed_ref_prefixes": ["refs/heads/main"],
                    "status": "active",
                    "revoked_at": None,
                }
            ],
        }
        registry.validate_signer_registry(value)
        value["signers"][0]["key_id"] = "qa-ed25519-" + "0" * 16
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "bind"):
            registry.validate_signer_registry(value)

    def test_recovery_receipt_uses_one_distinct_active_signer(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/qualification-signer-registry.schema.json").read_text()
        )
        self.assertIn(
            registry.RECOVERY_SIGNER_USAGE,
            schema["$defs"]["ed25519_signer"]["properties"]["allowed_usages"]["items"][
                "enum"
            ],
        )
        recovery = ed25519_signer(17, registry.RECOVERY_SIGNER_USAGE)
        storage = ed25519_signer(
            18, "private-qualification-evidence-decision-storage-seal"
        )
        value = signer_registry(recovery, storage)
        self.assertEqual(registry.validate_signer_registry(value), value)
        self.assertEqual(
            registry.require_active_signer_for_usage(
                value, registry.RECOVERY_SIGNER_USAGE
            )["key_id"],
            recovery["key_id"],
        )
        self.assertNotEqual(recovery["public_key_sha256"], storage["public_key_sha256"])

    def test_recovery_signer_mismatch_revocation_and_reuse_fail_closed(self) -> None:
        mismatch = signer_registry(
            ed25519_signer(19, "qualification-evidence-decision-receipt")
        )
        with self.assertRaisesRegex(
            registry.EvidenceRegistryError, "exactly one active signer"
        ):
            registry.require_active_signer_for_usage(
                mismatch, registry.RECOVERY_SIGNER_USAGE
            )

        revoked = signer_registry(
            ed25519_signer(20, registry.RECOVERY_SIGNER_USAGE, status="revoked")
        )
        with self.assertRaisesRegex(
            registry.EvidenceRegistryError, "exactly one active recovery signer"
        ):
            registry.validate_signer_registry(revoked)

        reused = signer_registry(ed25519_signer(21, registry.RECOVERY_SIGNER_USAGE))
        reused["signers"][0]["allowed_usages"] = sorted(
            [
                registry.RECOVERY_SIGNER_USAGE,
                "private-qualification-evidence-decision-storage-seal",
            ]
        )
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "distinct signer"):
            registry.validate_signer_registry(reused)

    def test_signer_registry_accepts_only_exact_aws_kms_p256_profile(self) -> None:
        public_key = ec.derive_private_key(7, ec.SECP256R1()).public_key()
        point = public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        signer = {
            "algorithm": "ecdsa-p256-sha256",
            "key_id": kms.public_key_id(public_key),
            "key_origin": "aws-kms",
            "kms_key_arn": (
                "arn:aws:kms:us-east-1:992382684924:key/"
                "12345678-1234-4abc-8def-1234567890ab"
            ),
            "public_key": base64.urlsafe_b64encode(point).decode().rstrip("="),
            "public_key_spki_der_base64": base64.b64encode(spki).decode(),
            "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
            "signature_encoding": "asn1-der-low-s-base64-rfc4648-padded",
            "statement_schema_versions": [kms.STATEMENT_SCHEMA],
            "allowed_usages": ["production-public-evidence"],
            "allowed_kinds": ["qualification-release"],
            "allowed_workflows": [kms.PUBLIC_SIGNING_WORKFLOW],
            "allowed_ref_prefixes": ["refs/heads/main"],
            "allowed_environments": ["public-trust-signing"],
            "status": "active",
            "revoked_at": None,
        }
        value = {
            "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
            "revision": 1,
            "generated_at": "2026-08-27T00:00:00Z",
            "expires_at": "2026-09-03T00:00:00Z",
            "signers": [signer],
        }
        self.assertEqual(registry.validate_signer_registry(value), value)

        alias = copy.deepcopy(value)
        alias["signers"][0]["kms_key_arn"] = (
            "arn:aws:kms:us-east-1:992382684924:alias/openadapt-public-trust"
        )
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "ARN"):
            registry.validate_signer_registry(alias)

    def test_signer_registry_install_is_canonical_consecutive_and_append_only(
        self,
    ) -> None:
        key = bytes(range(32))
        spki = bytes.fromhex("302a300506032b6570032100") + key

        def signer_registry(revision: int) -> dict:
            return {
                "schema_version": registry.SIGNER_REGISTRY_SCHEMA,
                "revision": revision,
                "generated_at": f"2026-08-{26 + revision:02d}T00:00:00Z",
                "expires_at": f"2026-09-{2 + revision:02d}T00:00:00Z",
                "signers": [
                    {
                        "algorithm": "ed25519",
                        "key_id": (
                            "qa-ed25519-" + hashlib.sha256(key).hexdigest()[:16]
                        ),
                        "public_key": (
                            registry.base64.urlsafe_b64encode(key).decode().rstrip("=")
                        ),
                        "public_key_spki_der_base64": (
                            registry.base64.b64encode(spki).decode()
                        ),
                        "public_key_sha256": (
                            "sha256:" + hashlib.sha256(spki).hexdigest()
                        ),
                        "statement_schema_versions": [
                            "openadapt.qualification-evidence-signing-statement/v1"
                        ],
                        "allowed_usages": ["qualification-evidence-decision-receipt"],
                        "allowed_workflows": [
                            (
                                "https://github.com/OpenAdaptAI/"
                                "openadapt-internal/.github/workflows/"
                                "issue-private-qualification-evidence-decision.yml"
                                "@refs/heads/main"
                            )
                        ],
                        "allowed_ref_prefixes": ["refs/heads/main"],
                        "status": "active",
                        "revoked_at": None,
                    }
                ],
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = document()
            first = signer_registry(1)
            first_path = root / "signers-v1.json"
            first_path.write_bytes(registry.canonical(first) + b"\n")
            stage.install_signer_registry(value, first_path, root)
            self.assertEqual(
                value["signer_registry_history"], [value["signer_registry"]]
            )
            stage.install_signer_registry(value, first_path, root)
            self.assertEqual(len(value["signer_registry_history"]), 1)

            third = signer_registry(3)
            third_path = root / "signers-v3.json"
            third_path.write_bytes(registry.canonical(third) + b"\n")
            with self.assertRaisesRegex(registry.EvidenceRegistryError, "exactly one"):
                stage.install_signer_registry(value, third_path, root)

            second = signer_registry(2)
            second_path = root / "signers-v2.json"
            second_path.write_bytes(registry.canonical(second) + b"\n")
            stage.install_signer_registry(value, second_path, root)
            self.assertEqual(
                [
                    item["registry_revision"]
                    for item in value["signer_registry_history"]
                ],
                [1, 2],
            )
            self.assertEqual(
                value["signer_registry"], value["signer_registry_history"][-1]
            )

            noncanonical = root / "noncanonical.json"
            noncanonical.write_text(json.dumps(signer_registry(3), indent=2) + "\n")
            with self.assertRaisesRegex(registry.EvidenceRegistryError, "canonical"):
                stage.install_signer_registry(value, noncanonical, root)

    def test_append_only_revision_binds_previous_head(self) -> None:
        previous = document()
        current = document(
            revision=2,
            previous_registry_head_sha256=previous["registry_head_sha256"],
        )
        registry.validate_append_only_history(previous, current)
        current["previous_registry_head_sha256"] = sha("9")
        current["registry_head_sha256"] = registry.registry_head_digest(current)
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "previous head"):
            registry.validate_append_only_history(previous, current)

    def test_an_untouched_registry_is_not_a_rollback(self) -> None:
        previous = document()
        registry.validate_append_only_history(previous, copy.deepcopy(previous))

    def test_an_untouched_registry_still_has_to_be_valid(self) -> None:
        previous = document()
        broken = copy.deepcopy(previous)
        broken["registry_head_sha256"] = sha("9")
        with self.assertRaises(registry.EvidenceRegistryError):
            registry.validate_append_only_history(broken, broken)

    def test_a_revision_that_stands_still_while_the_registry_changes_is_refused(
        self,
    ) -> None:
        previous = document()
        current = document(previous_registry_head_sha256=sha("9"))
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "exactly one"):
            registry.validate_append_only_history(previous, current)

    def test_only_exact_empty_v1_registry_can_create_the_empty_v2_genesis(self) -> None:
        previous = {
            "$schema": "schemas/evidence-registry.schema.json",
            "schema_version": "openadapt.production-evidence-registry/v1",
            "head_entry_sha256": None,
            "entries": [],
        }
        current = document()
        registry.validate_append_only_history(previous, current)

        changed_previous = copy.deepcopy(previous)
        changed_previous["head_entry_sha256"] = sha("1")
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "exact empty"):
            registry.validate_append_only_history(changed_previous, current)

        changed_current = document(revision=2)
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "empty v2 genesis"):
            registry.validate_append_only_history(previous, changed_current)

    def test_decision_revision_semantic_identity_cannot_conflict(self) -> None:
        receipt_identity = {
            "evidence_class": "private-customer",
            "decision_identity_sha256": sha("1"),
            "decision_revision": 7,
        }
        semantic = registry.semantic_identity_digest(
            kind="qualification-evidence-decision-receipt",
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v2"
            ),
            object_value=receipt_identity,
            object_sha256=sha("2"),
        )
        first = entry(
            "qualification-evidence-decision-receipt",
            object_sha256=sha("2"),
            semantic_identity_sha256=semantic,
        )
        first_bundle = entry(
            "qualification-evidence-decision-receipt-sigstore-bundle",
            object_sha256=sha("3"),
            subject_sha256=first["object_sha256"],
        )
        conflicting = entry(
            "qualification-evidence-decision-receipt",
            object_sha256=sha("4"),
            semantic_identity_sha256=semantic,
        )
        conflicting_bundle = entry(
            "qualification-evidence-decision-receipt-sigstore-bundle",
            object_sha256=sha("5"),
            subject_sha256=conflicting["object_sha256"],
        )
        signer = {
            "schema_version": registry.SIGNER_POINTER_SCHEMA,
            "object_path": (
                "production-evidence/signer-registries/sha256/ff/"
                + "f" * 64
                + ".qualification-signer-registry.json"
            ),
            "object_sha256": sha("f"),
            "registry_identity_sha256": sha("6"),
            "registry_revision": 1,
        }
        value = document(
            [first, first_bundle, conflicting, conflicting_bundle],
            signer_registry=signer,
            signer_registry_history=[signer],
        )
        with self.assertRaisesRegex(
            registry.EvidenceRegistryError, "semantic identity"
        ):
            registry.validate_registry(value)


if __name__ == "__main__":
    unittest.main()
