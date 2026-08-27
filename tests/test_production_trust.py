"""Fail-closed tests for release, workflow, and lifecycle trust contracts."""

from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import validate_evidence_registry as registry  # noqa: E402


def sha(character: str) -> str:
    return "sha256:" + character * 64


def reference(kind: str, object_character: str, *, subject: str | None = None) -> dict:
    schema, media = registry.OBJECT_KIND_CONTRACTS[kind]
    object_sha = sha(object_character)
    digest_hex = object_sha.removeprefix("sha256:")
    entry = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha,
        "size_bytes": 100,
        "object_media_type": media,
        "semantic_identity_sha256": sha("9"),
        "subject_sha256": subject,
    }
    return {
        "schema_version": registry.REFERENCE_SCHEMA,
        "repository": registry.REPOSITORY,
        "repository_id": registry.REPOSITORY_ID,
        "repository_owner_id": registry.REPOSITORY_OWNER_ID,
        "registry_source_commit": "a" * 40,
        "registry_revision": 3,
        "registry_head_sha256": sha("8"),
        "registry_entry_sha256": registry.entry_digest(entry),
        **entry,
    }


def pair(kind: str, regular_character: str, bundle_character: str) -> tuple[dict, dict]:
    regular = reference(kind, regular_character)
    bundle = reference(
        f"{kind}-sigstore-bundle",
        bundle_character,
        subject=regular["object_sha256"],
    )
    return regular, bundle


def campaign_summary() -> dict:
    result = {}
    for campaign_class in trust.CAMPAIGN_CLASSES:
        counts = {field: 0 for field in trust.CAMPAIGN_COUNT_FIELDS}
        counts.update(
            task_condition_cell_count=1,
            minimum_trials_per_cell=3,
            observed_trial_count=3,
        )
        if campaign_class == "uncertain_delivery":
            counts["reconciliation_required_count"] = 3
        if campaign_class == "declared_attended":
            counts["authenticated_bound_decision_count"] = 3
            counts["live_target_revalidation_count"] = 3
        if campaign_class == "governed_repair":
            for field in (
                "policy_approved_repair_count",
                "approved_repair_count",
                "retained_repair_evidence_count",
                "live_target_revalidation_count",
            ):
                counts[field] = 3
        result[campaign_class] = counts
    return result


def rulesets() -> list[dict]:
    common = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    }
    return [
        {
            **common,
            "name": "Production release tags: creation authority",
            "role": "creation_authority",
            "ruleset_id": "10",
            "bypass_actors": [
                {
                    "actor_id": "4730708",
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ],
            "rules": [{"type": "creation"}],
        },
        {
            **common,
            "name": "Production release tags: immutable",
            "role": "immutability",
            "ruleset_id": "11",
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                },
            ],
        },
    ]


def release_admission() -> dict:
    artifact = {
        "name": "openadapt_capture-1.0.0-py3-none-any.whl",
        "kind": "python-wheel",
        "sha256": sha("1"),
        "size_bytes": 4,
        "media_type": "application/zip",
        "publish_destinations": ["github-release", "pypi"],
    }
    normalized_rulesets = rulesets()
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "draft_release_id": "20",
        "tag": "v1.0.0",
        "target_commitish": "b" * 40,
        "draft": True,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": [
            {
                "asset_id": "30",
                "name": artifact["name"],
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "kind": artifact["kind"],
                "media_type": artifact["media_type"],
                "publish_destinations": artifact["publish_destinations"],
                "uploader_id": "321543906",
                "uploader_login": "openadapt-release[bot]",
            }
        ],
        "immutable_releases_enabled": True,
        "tag_rulesets": normalized_rulesets,
        "tag_rulesets_sha256": trust.digest_bytes(
            trust.TAG_RULESETS_DOMAIN, normalized_rulesets
        ),
        "observed_at": "2026-08-27T12:00:00Z",
    }
    release = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-capture",
        "source_repository_id": "1115283835",
        "source_commit": "b" * 40,
        "version": "1.0.0",
        "tag": "v1.0.0",
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": [artifact],
    }
    summary, summary_bundle = pair("production-acceptance-summary", "2", "3")
    value = {
        "schema_version": "openadapt.qualification-release/v1",
        "admission_id_sha256": sha("0"),
        "target": "capture",
        "verdict": "accepted",
        "claim_scope": "production_capture",
        "release_identity": {
            "schema_version": "openadapt.monotonic-production-release/v1",
            "channel": "production",
            "sequence": 1,
            "previous_admission_sha256": None,
        },
        "release": release,
        "release_sha256": trust.digest_bytes(
            trust.RELEASE_DOMAIN,
            {
                "target": "capture",
                "claim_scope": "production_capture",
                "release": release,
            },
        ),
        "artifact_inventory_sha256": trust.digest_bytes(
            trust.ARTIFACT_INVENTORY_DOMAIN,
            {
                "target": "capture",
                "claim_scope": "production_capture",
                "artifacts": [artifact],
            },
        ),
        "publication_staging": staging,
        "publication_staging_sha256": trust.staging_digest(staging),
        "production_acceptance_summary_reference": summary,
        "production_acceptance_summary_bundle_reference": summary_bundle,
        "authority_state_sha256": sha("4"),
        "revocation_state_sha256": sha("5"),
        "signer_registry_sha256": sha("6"),
        "publication_policy_sha256": sha("7"),
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-09-03T12:00:00Z",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-release-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": "c" * 40,
            "environment": "production-release-admission",
        },
    }
    projection = dict(value)
    projection.pop("admission_id_sha256")
    value["admission_id_sha256"] = trust.digest_bytes(
        trust.RELEASE_ADMISSION_DOMAIN, projection
    )
    return value


class ProductionTrustTests(unittest.TestCase):
    def test_campaign_requires_reconciliation_without_replay(self) -> None:
        value = campaign_summary()
        trust.validate_campaign_summary(value)
        value["uncertain_delivery"]["replay_dispatch_count"] = 1
        with self.assertRaisesRegex(trust.TrustError, "replay"):
            trust.validate_campaign_summary(value)

    def test_release_binds_exact_draft_assets_and_two_rulesets(self) -> None:
        value = release_admission()
        trust.validate_release(value)
        invalid = copy.deepcopy(value)
        invalid["publication_staging"]["tag_rulesets"][1]["bypass_actors"] = [
            {
                "actor_id": "4730708",
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
        with self.assertRaisesRegex(trust.TrustError, "bypass"):
            trust.validate_release(invalid)

    def test_local_artifact_inventory_refuses_extra_file(self) -> None:
        value = release_admission()
        artifacts = value["release"]["artifacts"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / artifacts[0]["name"]
            path.write_bytes(b"test")
            artifacts[0]["sha256"] = "sha256:" + hashlib.sha256(b"test").hexdigest()
            trust.verify_local_artifacts(root, artifacts)
            (root / "SHA256SUMS").write_text("not admitted")
            with self.assertRaisesRegex(trust.TrustError, "extra"):
                trust.verify_local_artifacts(root, artifacts)

    def test_v2_reference_ids_are_strings_and_digests_are_prefixed(self) -> None:
        regular, bundle = pair("qualification-release", "4", "5")
        trust.validate_reference_pair(regular, bundle, kind="qualification-release")
        regular["repository_id"] = 858454062
        with self.assertRaisesRegex(trust.TrustError, "repository"):
            trust.validate_reference_pair(regular, bundle, kind="qualification-release")


if __name__ == "__main__":
    unittest.main()
