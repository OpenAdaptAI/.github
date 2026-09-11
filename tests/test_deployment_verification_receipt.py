"""Test-only deployment output fixtures; no actual admission is issued."""

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import test_qualification_issuer as samples


def receipt_fixture(*, target="cloud", published=True):
    fixture = samples.trust_fixture()
    resolver = samples.RecordingResolver(fixture)
    workflow = samples.issuer.issue_workflow_admission(
        samples.workflow_request(fixture),
        resolver=resolver,
        issuer_source_commit=samples.WORKFLOW_REGISTRY_COMMIT,
        now=samples.NOW,
        consumer=samples.RecordingConsumer(),
    )
    request = samples.flow_release_inputs(fixture, workflow, resolver, target=target)
    admission = samples.issuer.issue_release_admission(
        request,
        resolver=resolver,
        issuer_source_commit=samples.RELEASE_REGISTRY_COMMIT,
        now=samples.NOW,
        consumer=samples.RecordingConsumer(),
    )
    if published:
        staging = {
            key: value
            for key, value in admission["publication_staging"].items()
            if key in samples.trust.DEPLOYMENT_STAGING_FIELDS
        }
        staging.update(
            publication_mode="already-published-deployment",
            draft=False,
            pypi_files=None,
            deployment_id=admission["release"]["deployment_id"],
            deployment_url="https://example.com/deployment/42",
        )
        samples.trust.validate_staging(staging)
        admission["publication_staging"] = staging
        admission["publication_staging_sha256"] = samples.trust.staging_digest(staging)
        projection = {
            key: value
            for key, value in admission.items()
            if key != "admission_id_sha256"
        }
        admission["admission_id_sha256"] = samples.trust.digest_bytes(
            samples.trust.RELEASE_ADMISSION_DOMAIN,
            projection,
        )
    samples.trust.validate_release(admission, now=samples.NOW)
    ref, bundle = samples.reference_pair("qualification-release", admission)
    receipt = samples.release_verifier.verification_receipt(
        admission=admission,
        admission_reference=ref,
        admission_bundle_reference=bundle,
        summary=resolver.objects[
            request["production_acceptance_summary_reference"]["object_sha256"]
        ]["value"],
        qualification_admission=workflow,
        verified_at=samples.NOW,
        trust_state_source_commit=samples.RELEASE_REGISTRY_COMMIT,
    )
    return admission, receipt


class DeploymentReceiptTests(unittest.TestCase):
    def validator(self):
        schemas = [
            json.loads(path.read_bytes())
            for path in (ROOT / "schemas").glob("*.schema.json")
        ]
        registry = Registry().with_resources(
            (item["$id"], Resource.from_contents(item)) for item in schemas
        )
        schema = next(
            item
            for item in schemas
            if item["$id"]
            == "qualification-release-verification-receipt-v2.schema.json"
        )
        return Draft202012Validator(schema, registry=registry)

    def test_actual_deployment_shape_needs_no_invented_draft_id(self):
        for target in ("cloud", "docs"):
            with self.subTest(target=target):
                admission, receipt = receipt_fixture(target=target)
                self.assertNotIn("draft_release_id", admission["publication_staging"])
                self.assertIsNone(receipt["draft_release_id"])
                self.assertEqual(
                    receipt["deployment_id"], admission["release"]["deployment_id"]
                )
                self.validator().validate(receipt)
                projection = {
                    key: value
                    for key, value in receipt.items()
                    if key != "verification_id_sha256"
                }
                self.assertEqual(
                    receipt["verification_id_sha256"],
                    samples.trust.digest_bytes(
                        samples.release_verifier.VERIFICATION_RECEIPT_V2_DOMAIN,
                        projection,
                    ),
                )

    def test_legacy_deployment_draft_id_is_preserved(self):
        admission, receipt = receipt_fixture(published=False)
        self.assertEqual(
            receipt["draft_release_id"],
            admission["publication_staging"]["draft_release_id"],
        )
        self.validator().validate(receipt)

    def test_package_and_hybrid_still_require_decimal_draft_id(self):
        _, package = receipt_fixture(target="agent", published=False)
        # Exercise the existing hybrid receipt grammar as a schema-only fixture.
        # Current Desktop target policy is package, so it cannot issue a hybrid.
        hybrid = {
            **package,
            "target": "desktop",
            "claim_scope": "production_desktop",
            "source_repository": "OpenAdaptAI/openadapt-desktop",
            "source_repository_id": "1171291730",
            "release_kind": "hybrid",
            "deployment_id": "42",
            "deployment_sha256": "sha256:" + "a" * 64,
        }
        for receipt in (package, hybrid):
            self.validator().validate(receipt)
            receipt["draft_release_id"] = None
            with (
                self.subTest(kind=receipt["release_kind"]),
                self.assertRaises(ValidationError),
            ):
                self.validator().validate(receipt)
        _, deployment = receipt_fixture()
        for value in (True, 0, "0", "", "not-a-release"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.validator().validate({**deployment, "draft_release_id": value})

    def test_null_requires_valid_published_deployment_in_builder(self):
        admission, _ = receipt_fixture()
        for kind in ("package", "hybrid"):
            changed = copy.deepcopy(admission)
            changed["release"]["kind"] = kind
            with self.subTest(kind=kind), self.assertRaises(samples.trust.TrustError):
                samples.release_verifier.verification_draft_release_id(changed)
        changed = copy.deepcopy(admission)
        changed["release"]["deployment_id"] = "43"
        with self.assertRaises(samples.trust.TrustError):
            samples.release_verifier.verification_draft_release_id(changed)
        changed = copy.deepcopy(admission)
        changed["publication_staging"]["draft_release_id"] = "20"
        with self.assertRaises(samples.trust.TrustError):
            samples.release_verifier.verification_draft_release_id(changed)
        changed, _ = receipt_fixture(published=False)
        changed["publication_staging"]["draft_release_id"] = None
        with self.assertRaises(samples.trust.TrustError):
            samples.release_verifier.verification_draft_release_id(changed)


if __name__ == "__main__":
    unittest.main()
