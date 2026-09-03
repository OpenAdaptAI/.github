"""Tests for the GitHub+Keychain software Ed25519 qualification signer."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualification_software_ed25519 as software  # noqa: E402
import validate_evidence_registry as evidence  # noqa: E402


NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(days=7)


class SoftwareEd25519Tests(unittest.TestCase):
    def test_interface_is_inactive_and_does_not_require_aws(self) -> None:
        contract = software.interface_contract()
        self.assertEqual(contract["activation_state"], "inactive")
        self.assertIs(contract["aws_required"], False)
        self.assertEqual(
            contract["custody"],
            ["github-environment-secret", "local-keychain-backup"],
        )
        self.assertEqual(contract["restore_path"], "keychain-to-github-only")
        self.assertEqual(
            contract["github_secret_name"],
            "OPENADAPT_QUALIFICATION_ED25519_PRIVATE_KEY",
        )
        self.assertEqual(
            contract["keychain_service"], "openadapt-qualification-ed25519"
        )

    def test_registry_candidate_validates_without_kms_fields(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        material = software.public_material(private_key)
        candidate = software.signer_registry_candidate(
            public_material_value=material,
            revision=1,
            generated_at=NOW,
            expires_at=EXPIRES,
        )
        registry = candidate["proposed_registry"]
        evidence.validate_signer_registry(registry)
        signer = registry["signers"][0]
        self.assertEqual(signer["key_id"], material["key_id"])
        self.assertNotIn("key_origin", signer)
        self.assertNotIn("kms_key_arn", signer)
        self.assertEqual(candidate["activation_state"], "not-installed")
        self.assertEqual(
            candidate["custody"],
            ["github-environment-secret", "local-keychain-backup"],
        )

    def test_registry_candidate_accepts_null_expires_at(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        candidate = software.signer_registry_candidate(
            public_material_value=software.public_material(private_key),
            revision=1,
            generated_at=NOW,
            expires_at=None,
        )
        registry = candidate["proposed_registry"]
        self.assertIsNone(registry["expires_at"])
        evidence.validate_signer_registry(registry)

    def test_registry_candidate_accepts_window_over_seven_days(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        candidate = software.signer_registry_candidate(
            public_material_value=software.public_material(private_key),
            revision=1,
            generated_at=NOW,
            expires_at=NOW + timedelta(days=8),
        )
        evidence.validate_signer_registry(candidate["proposed_registry"])

    def test_registry_candidate_refuses_expiry_before_generated_at(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(
            software.SoftwareEd25519Error, "after generated_at"
        ):
            software.signer_registry_candidate(
                public_material_value=software.public_material(private_key),
                revision=1,
                generated_at=NOW,
                expires_at=NOW,
            )

    def test_sign_receipt_round_trip(self) -> None:
        from test_qualification_issuer import trust_fixture

        # sign_receipt verifies against wall-clock; until-revoked stays active.
        fixture = trust_fixture(decision_origin="software", expires_at=None)
        unsigned = dict(fixture["receipt"])
        unsigned["signature"] = ""
        signed = software.sign_receipt(
            unsigned,
            private_key=fixture["decision_key"],
            signer_registry=fixture["registry"],
        )
        self.assertEqual(len(signed["signature"]), 88)
        self.assertEqual(
            signed["issuer_key_id"], fixture["registry"]["signers"][0]["key_id"]
        )

    def test_sign_cli_from_pem_file(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        material = software.public_material(private_key)
        pem = software.private_key_pem(private_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pem_path = root / "key.pem"
            pem_path.write_bytes(pem)
            with mock.patch("sys.stdout"):
                code = software.main(["public", "--pem-file", str(pem_path)])
            self.assertEqual(code, 0)
            self.assertEqual(
                software.public_material(software.load_private_key(pem))["key_id"],
                material["key_id"],
            )

    def test_decode_keychain_secret_accepts_hex_pem_from_macos_security(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        pem = software.private_key_pem(private_key)
        hexed = pem.hex().encode("ascii") + b"\n"
        decoded = software.decode_keychain_secret(hexed)
        loaded = software.load_private_key(decoded)
        self.assertEqual(
            software.public_material(loaded)["key_id"],
            software.public_material(private_key)["key_id"],
        )
        plain = software.decode_keychain_secret(pem)
        self.assertEqual(
            software.public_material(software.load_private_key(plain))["key_id"],
            software.public_material(private_key)["key_id"],
        )

    def test_provision_refuses_existing_keychain(self) -> None:
        with mock.patch.object(
            software,
            "keychain_read",
            return_value=b"-----BEGIN PRIVATE KEY-----\n",
        ):
            with self.assertRaisesRegex(
                software.SoftwareEd25519Error, "already exists"
            ):
                software.provision(restore_github=False)

    def test_restore_github_reads_keychain_and_does_not_mint(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        pem = software.private_key_pem(private_key)
        with (
            mock.patch.object(software, "keychain_read", return_value=pem),
            mock.patch.object(software, "github_secret_write") as write,
        ):
            material = software.provision(restore_github=True)
        write.assert_called_once_with(pem)
        self.assertEqual(material["action"], "restored-github-from-keychain")
        self.assertEqual(material["key_id"], software.public_material(private_key)["key_id"])

    def test_main_interface_json(self) -> None:
        with mock.patch("sys.stdout"):
            code = software.main(["interface"])
        self.assertEqual(code, 0)

    def test_local_candidate_is_unpublished_and_has_no_registry_clock(self) -> None:
        import public_trust_kms as public_trust

        private_key = Ed25519PrivateKey.generate()
        unsigned = software.unsigned_local_registry_candidate(
            public_material_value=software.public_material(private_key),
            revision=1,
        )
        self.assertEqual(unsigned["activation_state"], "not-installed")
        self.assertEqual(unsigned["clock"], "unset")
        self.assertNotIn("generated_at", unsigned)
        self.assertNotIn("expires_at", unsigned)
        self.assertNotIn("proposed_registry", unsigned)
        signed = software.sign_local_registry_candidate(
            unsigned, private_key=private_key
        )
        verified = software.verify_local_registry_candidate(signed)
        self.assertEqual(verified["signature_key_id"], unsigned["qualification_signer"]["key_id"])
        self.assertTrue(verified["qualification_signer"]["key_id"].startswith("qa-ed25519-"))
        self.assertTrue(
            verified["public_trust_signer"]["key_id"].startswith("oa-public-trust-ed25519-")
        )
        self.assertEqual(
            verified["qualification_signer"]["public_key"],
            verified["public_trust_signer"]["public_key"],
        )
        public_trust.validate_public_signer(verified["public_trust_signer"])
        with self.assertRaisesRegex(software.SoftwareEd25519Error, "registry clock"):
            software.sign_local_registry_candidate(
                {**unsigned, "clock": "2026-09-02T12:00:00Z"},
                private_key=private_key,
            )

    def test_local_candidate_cli_from_pem_file(self) -> None:
        import io

        private_key = Ed25519PrivateKey.generate()
        pem = software.private_key_pem(private_key)
        with tempfile.TemporaryDirectory() as directory:
            pem_path = Path(directory) / "key.pem"
            pem_path.write_bytes(pem)
            stdout = io.StringIO()
            with mock.patch("sys.stdout", stdout):
                code = software.main(
                    ["local-candidate", "--revision", "1", "--pem-file", str(pem_path)]
                )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["activation_state"], "not-installed")
        self.assertEqual(payload["clock"], "unset")
        self.assertNotIn("generated_at", payload)
        self.assertNotIn("expires_at", payload)
        software.verify_local_registry_candidate(payload)

    def test_local_candidate_refuses_mismatched_key(self) -> None:
        first = Ed25519PrivateKey.generate()
        second = Ed25519PrivateKey.generate()
        unsigned = software.unsigned_local_registry_candidate(
            public_material_value=software.public_material(first),
            revision=1,
        )
        with self.assertRaisesRegex(software.SoftwareEd25519Error, "does not match"):
            software.sign_local_registry_candidate(unsigned, private_key=second)


if __name__ == "__main__":
    unittest.main()
