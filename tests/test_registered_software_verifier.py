"""Exercise the registered software route with retained, unchanged signatures."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust
import public_trust_kms as public_trust
import validate_evidence_registry as evidence
import verify_production_release_admission as verifier

# These committed public bytes retain the actual provisioned-key signatures.
RELEASE_SHA = "sha256:790122a25c87e456c6e45d25ebf5cd029b21b8511265b062fd9129b74aa1dd82"
AUTHORITY_SHA = "sha256:a22f9815ec0f7c56f7629aeabfd21d14bc6d739efcfb7f7a073ce9987e19479e"
REVOCATION_SHA = "sha256:18633b8cc243f686706606162bfa249a29733811563f63b9e68cc7c4a3507676"
SIGNER_SHA = "sha256:7a81bf3d213c74673f3c6b5fa179234cbee534c9432aaea6ae09e455562f96b6"
STORAGE_COMMIT = "f" * 40


def canonical(value: dict) -> bytes:
    return evidence.canonical(value) + b"\n"


class RegisteredSoftwareVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads((ROOT / "evidence-registry.json").read_bytes())
        retained = {RELEASE_SHA, AUTHORITY_SHA, REVOCATION_SHA}
        self.registry["entries"] = [
            entry for entry in self.registry["entries"]
            if entry["object_sha256"] in retained or entry["subject_sha256"] in retained
        ]
        pointer = next(pointer for pointer in self.registry["signer_registry_history"]
                       if pointer["object_sha256"] == SIGNER_SHA)
        self.registry.update(signer_registry=pointer, signer_registry_history=[pointer],
                             revision=1, previous_registry_head_sha256=None)
        self.refresh_registry()
        self.files = {entry["object_path"]: (ROOT / entry["object_path"]).read_bytes()
                      for entry in self.registry["entries"]}
        self.files[pointer["object_path"]] = (ROOT / pointer["object_path"]).read_bytes()
        self.policy = json.loads(verifier.POLICY_PATH.read_bytes())
        self.fetch = mock.patch.object(verifier, "fetch", side_effect=self.fetch_bytes)
        self.fetch.start()
        self.addCleanup(self.fetch.stop)
        self.keyless = mock.patch.object(verifier, "verify_sigstore")
        self.keyless_mock = self.keyless.start()
        self.addCleanup(self.keyless.stop)

    def refresh_registry(self) -> None:
        self.registry["registry_head_sha256"] = evidence.registry_head_digest(self.registry)
        evidence.validate_registry(self.registry)

    def fetch_bytes(self, url: str, **_kwargs) -> bytes:
        prefix = verifier.raw_url(STORAGE_COMMIT, "")
        if not url.startswith(prefix):
            raise AssertionError(f"unexpected network request: {url}")
        path = url.removeprefix(prefix)
        return canonical(self.registry) if path == "evidence-registry.json" else self.files[path]

    def reference(self, digest: str) -> dict:
        entry = next(entry for entry in self.registry["entries"]
                     if entry["object_sha256"] == digest)
        return {
            "schema_version": evidence.REFERENCE_SCHEMA,
            "repository": evidence.REPOSITORY,
            "repository_id": evidence.REPOSITORY_ID,
            "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
            "registry_source_commit": STORAGE_COMMIT,
            "registry_revision": self.registry["revision"],
            "registry_head_sha256": self.registry["registry_head_sha256"],
            **entry,
        }

    def resolve(self, digest: str = RELEASE_SHA) -> tuple:
        reference = self.reference(digest)
        return verifier.resolve_pair(reference, verifier.derive_bundle_reference(reference),
                                     kind=reference["kind"], policy=self.policy)

    def replace_bundle(self, digest: str, mutate) -> None:
        reference = self.reference(digest)
        bundle_ref = verifier.derive_bundle_reference(reference)
        bundle = json.loads(self.files[bundle_ref["object_path"]])
        mutate(bundle)
        raw = canonical(bundle)
        changed = next(entry for entry in self.registry["entries"]
                       if entry["object_sha256"] == bundle_ref["object_sha256"])
        changed["object_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        digest_hex = changed["object_sha256"].removeprefix("sha256:")
        changed["object_path"] = (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{changed['kind']}.json"
        )
        changed["size_bytes"] = len(raw)
        changed["semantic_identity_sha256"] = evidence.semantic_identity_digest(
            kind=changed["kind"], object_schema_version=changed["object_schema_version"],
            object_value=changed["subject_sha256"], object_sha256=changed["object_sha256"],
        )
        changed["registry_entry_sha256"] = evidence.entry_digest(changed)
        self.files[changed["object_path"]] = raw
        self.refresh_registry()

    def test_actual_release_authority_and_revocation_signatures_resolve(self) -> None:
        with mock.patch.object(verifier, "protected_main_commit",
                               side_effect=AssertionError("storage is not the live main tip")):
            for digest in (RELEASE_SHA, AUTHORITY_SHA, REVOCATION_SHA):
                with self.subTest(digest=digest):
                    value, bound, current = self.resolve(digest)
                    self.assertEqual(bound, current)
                    if digest == AUTHORITY_SHA:
                        self.assertEqual(value["signer_registry_sha256"], SIGNER_SHA)
                        self.assertEqual(value["signer_registry_identity_sha256"],
                                         evidence.signer_registry_identity_digest(bound))
                        self.assertNotEqual(value["signer_registry_sha256"],
                                            value["signer_registry_identity_sha256"])
        self.keyless_mock.assert_not_called()

    def test_corrupt_registered_outer_signature_never_falls_back(self) -> None:
        for digest in (RELEASE_SHA, AUTHORITY_SHA, REVOCATION_SHA):
            with self.subTest(digest=digest):
                self.replace_bundle(digest, lambda bundle: bundle["dsseEnvelope"]["signatures"][0].update(
                    sig=base64.b64encode(bytes(64)).decode()))
                with self.assertRaises(trust.TrustError):
                    self.resolve(digest)
        self.keyless_mock.assert_not_called()

    def test_profile_issuer_ref_environment_and_state_tampering_refuses(self) -> None:
        reference = self.reference(RELEASE_SHA)
        bundle_reference = verifier.derive_bundle_reference(reference)
        original_pair = verifier.fetch_pair(reference, bundle_reference)
        for field, replacement in (
            ("signature_profile", "unsupported-profile"),
            ("authority_state_sha256", "sha256:" + "1" * 64),
            ("source_issuer", {**original_pair[2]["issuer"], "ref": "refs/heads/other"}),
            ("signing_authority", {"ref": "refs/heads/other"}),
            ("signing_authority", {"environment": "unregistered-environment"}),
        ):
            with self.subTest(field=field, replacement=replacement):
                bundle = json.loads(original_pair[1])
                statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
                if field == "signing_authority":
                    statement[field].update(replacement)
                else:
                    statement[field] = replacement
                bundle["dsseEnvelope"]["payload"] = base64.b64encode(canonical(statement)).decode()
                pair = (original_pair[0], canonical(bundle), *original_pair[2:])
                with self.assertRaises(trust.TrustError):
                    verifier.verify_registered_signature(reference, bundle_reference, pair,
                                                          policy=self.policy)
        self.keyless_mock.assert_not_called()

    def test_corrupt_embedded_authority_signature_refuses_before_outer_validation(self) -> None:
        original_fetch_pair = verifier.fetch_pair

        def corrupt(reference, bundle_reference):
            pair = original_fetch_pair(reference, bundle_reference)
            if reference["kind"] == "qualification-authority-state-receipt":
                value = copy.deepcopy(pair[2])
                value["signature"] = base64.b64encode(bytes(64)).decode()
                return canonical(value), pair[1], value, pair[3], pair[4]
            return pair

        with mock.patch.object(verifier, "fetch_pair", side_effect=corrupt), \
                mock.patch.object(verifier, "_verify_software_pair") as outer:
            with self.assertRaises(trust.TrustError):
                self.resolve()
            outer.assert_not_called()
        self.keyless_mock.assert_not_called()

    def test_storage_current_revoked_outer_key_refuses(self) -> None:
        original_fetch_pair = verifier.fetch_pair

        def revoked(reference, bundle_reference):
            pair = original_fetch_pair(reference, bundle_reference)
            current = copy.deepcopy(pair[4])
            for signer in current["signers"]:
                if signer.get("key_origin") == "software":
                    signer.update(status="revoked", revoked_at="2026-09-03T00:00:00Z")
            return *pair[:4], current

        with mock.patch.object(verifier, "fetch_pair", side_effect=revoked):
            with self.assertRaises(trust.TrustError):
                self.resolve()
        self.keyless_mock.assert_not_called()

    def test_authority_rollover_selects_its_verified_historical_reverse_link(self) -> None:
        authority_ref = self.reference(AUTHORITY_SHA)
        authority_bundle = verifier.derive_bundle_reference(authority_ref)
        authority_pair = (authority_ref, authority_bundle,
                          verifier.fetch_pair(authority_ref, authority_bundle))
        revocation_ref = self.reference(REVOCATION_SHA)
        revocation_bundle = verifier.derive_bundle_reference(revocation_ref)
        original = (revocation_ref, revocation_bundle,
                    verifier.fetch_pair(revocation_ref, revocation_bundle))
        newer = copy.deepcopy(original)
        newer[2][2]["revocation_state_sha256"] = "sha256:" + "f" * 64
        newer[2][2]["revision"] = 2
        verified_candidates = []

        def verify_outer(reference, _bundle, _pair, *, authority, revocation, now):
            if reference["kind"] == "qualification-authority-state-receipt" and (
                revocation["revocation_state_sha256"]
                != original[2][2]["revocation_state_sha256"]
            ):
                raise trust.TrustError("authority keeps its original signed reverse link")

        # This isolates reverse-link selection. The retained-byte test above
        # exercises the real embedded and outer signature primitives.
        with mock.patch.object(verifier, "_registered_state_pairs", return_value=[original, newer]), \
                mock.patch.object(verifier, "_verify_embedded_state",
                                  side_effect=lambda candidate, **kwargs: verified_candidates.append(candidate)), \
                mock.patch.object(verifier, "_validate_registered_state_links"), \
                mock.patch.object(verifier, "_verify_software_pair", side_effect=verify_outer):
            chosen = verifier._verify_authority_pair(
                authority_pair, bound_registry=authority_pair[2][3],
                current_registry=authority_pair[2][4], now=datetime.now(timezone.utc),
            )
        self.assertEqual(chosen, original)
        self.assertEqual(verified_candidates, [original, newer])

    def test_authority_outer_checks_registry_window_at_statement_time(self) -> None:
        reference = self.reference(AUTHORITY_SHA)
        bundle_reference = verifier.derive_bundle_reference(reference)
        pair = verifier.fetch_pair(reference, bundle_reference)
        bundle = json.loads(pair[1])
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        statement.update(issued_at="2020-01-01T00:00:00Z", not_before="2020-01-01T00:00:00Z")
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(canonical(statement)).decode()
        changed = (pair[0], canonical(bundle), *pair[2:])
        revocation_ref = self.reference(REVOCATION_SHA)
        revocation = json.loads(self.files[revocation_ref["object_path"]])
        with self.assertRaisesRegex(trust.TrustError, "registry is not active at statement time"):
            verifier._verify_software_pair(
                reference, bundle_reference, changed, authority=pair[2],
                revocation=revocation, now=datetime.now(timezone.utc),
            )

    def test_non_public_bundle_retains_keyless_verifier(self) -> None:
        reference = self.reference(RELEASE_SHA)
        bundle_reference = verifier.derive_bundle_reference(reference)
        pair = verifier.fetch_pair(reference, bundle_reference)
        changed = (pair[0], b"{}", *pair[2:])
        verifier.verify_registered_signature(reference, bundle_reference, changed, policy=self.policy)
        self.keyless_mock.assert_called_once_with(
            pair[0], b"{}", kind=reference["kind"], object_value=pair[2], policy=self.policy,
        )

    def test_keyless_cli_version_pin_is_unchanged(self) -> None:
        self.keyless.stop()
        self.addCleanup(lambda: None)
        reference = self.reference(RELEASE_SHA)
        value = json.loads(self.files[reference["object_path"]])
        result = mock.Mock(stdout="gh version 99.0.0 (2099-01-01)\n")
        with mock.patch.object(verifier.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(trust.TrustError, "GitHub CLI version differs"):
                verifier.verify_sigstore(canonical(value), b"{}", kind=reference["kind"],
                                         object_value=value, policy=self.policy)


if __name__ == "__main__":
    unittest.main()
