"""Fail-closed tests for production evidence object references v2."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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


class EvidenceRegistryTests(unittest.TestCase):
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
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "content-addressed"):
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
        valid = document([regular, bundle], signer_registry=signer)
        registry.validate_registry(valid)
        invalid = copy.deepcopy(valid)
        invalid["entries"].reverse()
        invalid["registry_head_sha256"] = registry.registry_head_digest(invalid)
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "immediately"):
            registry.validate_registry(invalid)

    def test_registry_readback_binds_exact_bytes_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b'{"schema_version":"openadapt.production-acceptance/v2"}\n'
            object_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
            regular = entry(
                object_sha256=object_sha,
                size_bytes=len(raw),
                semantic_identity_sha256=registry.semantic_identity_digest(
                    kind="production-acceptance-manifest",
                    object_schema_version="openadapt.production-acceptance/v2",
                    object_value=json.loads(raw),
                    object_sha256=object_sha,
                ),
            )
            path = root / regular["object_path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
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
            value = document([regular], signer_registry=signer)
            with self.assertRaisesRegex(registry.EvidenceRegistryError, "signer registry"):
                registry.validate_registry(value, root=root)
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(registry.EvidenceRegistryError, "bytes differ"):
                registry.validate_registry(value, root=root)

    def test_signer_registry_key_id_binds_canonical_key(self) -> None:
        key = bytes(range(32))
        public_key = registry.base64.urlsafe_b64encode(key).decode().rstrip("=")
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
                    "allowed_workflows": [
                        "https://github.com/OpenAdaptAI/openadapt-internal/"
                        ".github/workflows/issue-private-qualification-evidence-decision.yml"
                        "@refs/heads/main"
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


if __name__ == "__main__":
    unittest.main()
