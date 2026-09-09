"""Version checks on retained, signed workflow admissions."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import validate_production_lifecycle as lifecycle  # noqa: E402


class RegisteredWorkflowVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((ROOT / "evidence-registry.json").read_bytes())
        cls.entries = lifecycle.evidence_registry.validate_registry(
            cls.registry, root=ROOT
        )
        rows = json.loads((ROOT / "production-workflow-admissions.json").read_bytes())[
            "admissions"
        ]
        # These are the real historical and measured reference objects. Their
        # original signatures must verify; a generated test key cannot prove it.
        expected = {
            "sha256:dcdb32a762aca87fbb1a7c9df5d346403b167ec5850d35fe47fd64d942684a04": (
                "0.0.0-synthetic"
            ),
            "sha256:947224523757df41127be021fc66adee5746f07ff1a0e913319c5461e430e34d": (
                "1.35.1-reference.1"
            ),
        }
        cls.cases = [
            (
                row,
                json.loads((ROOT / row["object_path"]).read_bytes()),
                expected[row["object_sha256"]],
            )
            for row in rows
            if row["object_sha256"] in expected
        ]
        if len(cls.cases) != len(expected):
            raise AssertionError("the two retained signed workflow rows are required")
        cls.now = max(
            datetime.fromisoformat(value[field].replace("Z", "+00:00"))
            for _, value, _ in cls.cases
            for field in ("issued_at", "not_before")
        ) + timedelta(seconds=1)

    def validate_row(self, row, root=None):
        return lifecycle._validate_v2_workflow_admission(
            row,
            index=0,
            root=ROOT if root is None else root,
            registry_document=self.registry,
            registry_entries=self.entries,
            now=self.now,
        )

    def test_actual_registered_old_and_reference_versions_verify(self):
        for row, expected_object, version in self.cases:
            with self.subTest(version=version):
                admission, active = self.validate_row(row)
                self.assertEqual(admission, expected_object)
                self.assertEqual(admission["bundle_version"], version)
                self.assertTrue(active)

    def test_malformed_versions_keep_the_canonical_schema_refusal(self):
        for _, original, version in self.cases:
            for invalid in (None, True, 1, "", "../private", "a" * 65):
                with self.subTest(version=version, invalid=invalid):
                    changed = copy.deepcopy(original)
                    changed["bundle_version"] = invalid
                    with self.assertRaisesRegex(
                        trust.TrustError, "bundle version is not canonical"
                    ):
                        trust.validate_qualification_admission(changed, now=self.now)

    def test_changed_valid_version_keeps_the_admission_digest_refusal(self):
        for _, original, version in self.cases:
            with self.subTest(version=version):
                changed = copy.deepcopy(original)
                changed["bundle_version"] = "1.35.1-reference.2"
                with self.assertRaisesRegex(
                    trust.TrustError, "qualification admission id is invalid"
                ):
                    trust.validate_qualification_admission(changed, now=self.now)

    def test_changed_signed_version_keeps_the_registered_bytes_refusal(self):
        for row, original, version in self.cases:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                changed = copy.deepcopy(original)
                changed["bundle_version"] = "1.35.1-reference.2"
                path = Path(tmp) / row["object_path"]
                path.parent.mkdir(parents=True)
                path.write_bytes(lifecycle.evidence_registry.canonical(changed) + b"\n")
                with self.assertRaisesRegex(
                    lifecycle.LifecycleError, "bytes differ from the registry"
                ):
                    self.validate_row(row, root=Path(tmp))


if __name__ == "__main__":
    unittest.main()
