"""Test-only hosted provenance. No real campaign, signature, or live call."""

import base64
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_measured_attestation_provenance import verified_result

SPEC = importlib.util.spec_from_file_location(
    "measured_cloud_admission", ROOT / "local-candidates/cloud-measured/issue.py"
)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def producer():
    return {
        "repository": adapter.PRODUCER_REPOSITORY,
        "repository_id": adapter.PRODUCER_REPOSITORY_ID,
        "repository_owner_id": adapter.PRODUCER_OWNER_ID,
        "workflow": adapter.PRODUCER_WORKFLOW,
        "ref": adapter.PRODUCER_REF,
        "source_commit": "a" * 40,
        "run_id": "123",
        "run_attempt": "2",
    }


class CloudProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.producer = p = producer()
        self.raw = b'{"test_only":true}\n'
        self.result = verified_result(
            self.raw, p["repository"], p["source_commit"], p["ref"]
        )
        predicate = self.result["statement"]["predicate"]
        predicate["buildDefinition"].update(
            buildType="https://actions.github.io/buildtypes/workflow/v1",
            externalParameters={
                "workflow": {
                    "repository": "https://github.com/" + p["repository"],
                    "path": p["workflow"],
                    "ref": p["ref"],
                }
            },
            internalParameters={
                "github": {
                    "repository_id": p["repository_id"],
                    "repository_owner_id": p["repository_owner_id"],
                    "event_name": "workflow_dispatch",
                    "runner_environment": "github-hosted",
                }
            },
        )
        predicate["runDetails"] = {
            "builder": {"id": adapter.PRODUCER_IDENTITY},
            "metadata": {
                "invocationId": (
                    "https://github.com/"
                    + p["repository"]
                    + "/actions/runs/123/attempts/2"
                )
            },
        }
        self.run = {
            "id": 123,
            "run_attempt": 2,
            "head_sha": p["source_commit"],
            "head_branch": "main",
            "path": p["workflow"],
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "repository": {
                "full_name": p["repository"],
                "id": int(p["repository_id"]),
                "owner": {"id": int(p["repository_owner_id"])},
            },
        }
        self.head = {"ref": p["ref"], "object": {"sha": p["source_commit"]}}
        self.source = b"# Test-only inert workflow source\n"
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.owner = Path(temporary.name) / "mapping.json"
        self.refs = {}
        for name, raw in {
            "attestation": b'{"test_only":"mocked cryptographic process"}',
            "workflow_source": self.source,
            "workflow_run": json.dumps(self.run).encode(),
            "protected_main": json.dumps(self.head).encode(),
        }.items():
            (self.owner.parent / name).write_bytes(raw)
            self.refs[name] = {
                "path": name,
                "sha256": adapter.shared.sha(raw),
                "size_bytes": len(raw),
            }

    def gh(self, endpoint):
        if "/git/ref/heads/main" in endpoint:
            return self.head
        if "/actions/runs/123/attempts/2" in endpoint:
            return self.run
        if "/contents/" in endpoint:
            return {
                "encoding": "base64",
                "type": "file",
                "path": self.producer["workflow"],
                "content": base64.b64encode(self.source).decode(),
            }
        raise AssertionError("unexpected live interface")

    def process(self, command, **_kwargs):
        if command == ["gh", "--version"]:
            return subprocess.CompletedProcess(
                command, 0, "gh version 2.98.0 (2026-08-20)\n", ""
            )
        for required in (
            adapter.PRODUCER_IDENTITY,
            "--deny-self-hosted-runners",
            "--no-public-good",
        ):
            self.assertIn(required, command)
        return subprocess.CompletedProcess(
            command, 0, json.dumps([{"verificationResult": self.result}]), ""
        )

    def verify(self, gh=None):
        with mock.patch.object(
            adapter.shared.verifier.subprocess, "run", side_effect=self.process
        ):
            return adapter.verify_derivative_provenance(
                self.owner,
                self.raw,
                self.producer,
                self.refs,
                gh=gh or self.gh,
            )

    def test_exact_fixed_workflow_passes_without_network(self):
        self.assertEqual(self.verify(), self.run)

    def test_verified_repo_workflow_ids_builder_run_attempt_refuse(self):
        original = copy.deepcopy(self.result)
        paths = (
            ("buildDefinition", "externalParameters", "workflow", "repository"),
            ("buildDefinition", "externalParameters", "workflow", "path"),
            ("buildDefinition", "externalParameters", "workflow", "ref"),
            ("buildDefinition", "internalParameters", "github", "repository_id"),
            ("buildDefinition", "internalParameters", "github", "repository_owner_id"),
            ("buildDefinition", "internalParameters", "github", "runner_environment"),
            ("buildDefinition", "internalParameters", "github", "event_name"),
            ("runDetails", "builder", "id"),
            ("runDetails", "metadata", "invocationId"),
        )
        for path in paths:
            self.result = copy.deepcopy(original)
            current = self.result["statement"]["predicate"]
            for part in path[:-1]:
                current = current[part]
            current[path[-1]] = "wrong"
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify()
        for suffix in ("124/attempts/2", "123/attempts/1"):
            self.result = copy.deepcopy(original)
            self.result["statement"]["predicate"]["runDetails"]["metadata"][
                "invocationId"
            ] = (
                "https://github.com/"
                + self.producer["repository"]
                + "/actions/runs/"
                + suffix
            )
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.verify()

    def test_verified_subject_and_source_refuse(self):
        self.result["signature"]["certificate"]["githubWorkflowSHA"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "source identity"):
            self.verify()
        self.result["signature"]["certificate"]["githubWorkflowSHA"] = self.producer[
            "source_commit"
        ]
        self.result["statement"]["subject"][0]["digest"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "subject"):
            self.verify()

    def test_actual_run_attempt_source_success_and_main_must_match(self):
        for key, value in (
            ("id", 124),
            ("run_attempt", 1),
            ("run_attempt", True),
            ("head_sha", "b" * 40),
            ("head_branch", "other"),
            ("path", "other.yml"),
            ("conclusion", "failure"),
        ):

            def gh(endpoint, key=key, value=value):
                return (
                    {**self.run, key: value}
                    if "/actions/runs/" in endpoint
                    else self.gh(endpoint)
                )

            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "actual hosted"),
            ):
                self.verify(gh)
        with self.assertRaisesRegex(ValueError, "protected main changed"):
            self.verify(lambda _endpoint: {"object": {"sha": "b" * 40}})

    def test_actual_workflow_byte_change_refuses(self):
        def gh(endpoint):
            value = self.gh(endpoint)
            if "/contents/" in endpoint:
                value["content"] = base64.b64encode(b"changed").decode()
            return value

        with self.assertRaisesRegex(ValueError, "workflow bytes"):
            self.verify(gh)

    def test_caller_identity_and_ambiguous_json_refuse(self):
        for key in (
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
        ):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "fixed workflow"),
            ):
                adapter.validate_producer({**self.producer, key: "other"})
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                adapter.strict_json(raw)

    def test_exponent_overflow_refuses_and_finite_json_numbers_pass(self):
        for raw in (b'{"x":1e999}', b'{"x":-1e999}'):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(ValueError, "non-finite JSON"),
            ):
                adapter.strict_json(raw)
        for raw, expected in (
            (b'{"x":1.5}', 1.5),
            (b'{"x":-2e2}', -200.0),
            (b'{"x":0}', 0),
        ):
            self.assertEqual(adapter.strict_json(raw), {"x": expected})


class MeasuredFixture:
    """Inert interface fixtures, not a native campaign or an admitted deployment."""

    def __init__(self, directory):
        from uuid import UUID

        self.directory = Path(directory).resolve()
        self.inventory = {}
        self.refs = []
        self.uu = lambda n: str(UUID(int=n))
        self.digest = lambda text: adapter.shared.sha(text.encode())[7:]
        self.source = "c" * 40
        self.wheel = self.add("runtime-wheel", b"test-only inert wheel")
        self.bundle = self.add("sealed-bundle", b"test-only inert sealed bundle")
        self.runtime = {
            "openadapt_flow": "1.35.1",
            "release_commit": "d" * 40,
            "wheel_sha256": self.wheel,
            "sdist_sha256": self.digest("sdist"),
            "wheel_url": "https://files.pythonhosted.org/test-only.whl",
            "runner_build": "report-v5",
            "runner_artifact_sha256": self.digest("runner"),
            "modal_sdk": "1.5.5",
            "fastapi": "0.141.1",
            "starlette": "1.6.0",
            "playwright": "1.62.0",
            "browser_base_image": "python:test@sha256:" + "a" * 64,
            "sandbox_network_policy": "modal-domain-allowlist-v1",
        }
        self.add("runtime_version", self.runtime)
        components = {
            "schema_version": "openadapt.runtime-component-manifest/v1",
            "components": [
                {"name": "test-only-runtime", "artifact_sha256": self.wheel},
            ],
        }
        self.build = {
            "schema_version": "openadapt.admitted-runtime-build/v1",
            "substrate": "web",
            "flow_version": self.runtime["openadapt_flow"],
            "flow_release_commit": self.runtime["release_commit"],
            "flow_wheel_sha256": self.wheel,
            "runner_build": self.runtime["runner_build"],
            "runner_artifact_sha256": self.runtime["runner_artifact_sha256"],
            "runtime_manifest": components,
            "runtime_manifest_sha256": adapter.semantic_digest(
                components, b"openadapt-runtime-component-manifest-v1\0"
            ),
            "managed_browser": {
                "playwright_version": self.runtime["playwright"],
                "browser_base_image": self.runtime["browser_base_image"],
            },
            "substrate_runtime": {
                "transport": "browser",
                "os_family": "linux",
                "runtime_boundary_sha256": adapter.semantic_digest(
                    {"environment": "test-only-boundary"}
                ),
            },
        }
        self.add("runtime_build_identity", self.build)
        self.workflow_raw = b"# Inert test-only deployment workflow\n"
        self.add("deployment_workflow_source", self.workflow_raw)
        self.validator_raw = b"# Inert test-only private verifier source\n"
        validator_hash = self.add("validator-source", self.validator_raw)
        source_inventory = self.add(
            "source-inventory",
            {
                "test_only": True,
                "files": [
                    {"path": "runner/qualification_issuer.py", "sha256": validator_hash}
                ],
            },
        )
        authority = {
            "repository": adapter.DEPLOYMENT_REPOSITORY,
            "workflow": adapter.DEPLOYMENT_WORKFLOW,
            "source_ref": "refs/heads/main",
            "source_commit": self.source,
            "workflow_ref": f"{adapter.DEPLOYMENT_REPOSITORY}/{adapter.DEPLOYMENT_WORKFLOW}@refs/heads/main",
            "certificate_identity": f"https://github.com/{adapter.DEPLOYMENT_REPOSITORY}/{adapter.DEPLOYMENT_WORKFLOW}@refs/heads/main",
            "workflow_sha256": adapter.shared.sha(self.workflow_raw),
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "job": "deploy",
            "environment": "production",
            "environment_scope": "openadapt-cloud-production-v1",
            "event_name": "workflow_dispatch",
            "run_id": "456",
            "run_attempt": "2",
        }
        host = {
            "provider": "netlify",
            "deploy_id": "a" * 24,
            "immutable_url": "https://" + "a" * 24 + "--test.netlify.app/",
            "created_at": "2026-09-11T00:00:00.000Z",
            "published_at": "2026-09-11T00:01:00.000Z",
            "site_identity_sha256": "sha256:"
            + adapter.semantic_digest(
                self.uu(1), b"OpenAdapt Netlify production site identity v1\0"
            ),
            "environment_contract_sha256": "sha256:" + self.digest("host environment"),
        }
        runner = {
            "provider": "modal",
            "environment": "production",
            "app_id": "ap-" + "a" * 22,
            "app_name": "test-only-runner",
            "app_version": "v2",
            "deployed_at": "2026-09-11T00:01:00.000Z",
            "endpoint_origin_sha256": "sha256:"
            + adapter.semantic_digest(
                "https://test-only.modal.run/",
                b"OpenAdapt Modal runner endpoint origin v1\0",
            ),
        }
        runtime = self.runtime
        self.manifest = {
            "schema_version": "openadapt.cloud-production-deployment-manifest/v1",
            "source": {
                "repository": adapter.DEPLOYMENT_REPOSITORY,
                "commit": self.source,
            },
            "build_authority": authority,
            "deployment": {"host": host, "runner": runner},
            "target": {
                "environment_digest": "sha256:" + self.digest("environment"),
                "sha256": "sha256:" + self.digest("target"),
            },
            "runtime": {
                "runtime_manifest_sha256": "sha256:" + adapter.semantic_digest(runtime),
                "runner_source_artifact_sha256": "sha256:"
                + runtime["runner_artifact_sha256"],
                "runner_build": runtime["runner_build"],
                "modal_sdk_version": runtime["modal_sdk"],
                "fastapi_version": runtime["fastapi"],
                "starlette_version": runtime["starlette"],
                "sandbox_network_policy": runtime["sandbox_network_policy"],
                "flow": {
                    "version": runtime["openadapt_flow"],
                    "release_commit": runtime["release_commit"],
                    "wheel_url": runtime["wheel_url"],
                    "wheel_sha256": "sha256:" + runtime["wheel_sha256"],
                    "sdist_sha256": "sha256:" + runtime["sdist_sha256"],
                },
                "browser": {
                    "playwright_version": runtime["playwright"],
                    "browser_base_image": runtime["browser_base_image"],
                    "runtime_contract_sha256": "sha256:"
                    + adapter.semantic_digest(
                        {
                            "python_base_image": runtime["browser_base_image"],
                            "playwright_version": runtime["playwright"],
                            "browser_install_command": "python -m playwright install --with-deps chromium",
                        },
                        b"OpenAdapt managed browser image contract v1\0",
                    ),
                },
            },
            "signature": "TEST ONLY: the attested private verifier is mocked",
        }
        manifest_hash = self.add("deployment-manifest", self.manifest)
        self.identity = {
            "schema_version": "openadapt.production-acceptance-evidence-identity/v2",
            "runtime_build_identity": self.build,
            "deployment_manifest_sha256": manifest_hash,
            "bundle_artifact_sha256": self.bundle,
            "bundle_content_digest": self.digest("native bundle"),
            "environment_digest": self.digest("environment"),
            "campaign_id": self.uu(2),
            "tenant_id": self.uu(3),
            "workflow_id": self.uu(4),
            "workflow_version_id": self.uu(5),
        }
        self.add("evidence_identity", self.identity)
        self.subject = {
            "source_commit": self.source,
            "deployment_manifest_sha256": manifest_hash,
            "runtime_build_identity_sha256": adapter.semantic_digest(
                self.build, b"openadapt-admitted-runtime-build-v1\0"
            ),
            "runtime_manifest_sha256": adapter.semantic_digest(runtime),
            "evidence_identity_sha256": adapter.semantic_digest(
                self.identity, b"OpenAdapt production acceptance evidence identity v2\0"
            ),
            "bundle_artifact_sha256": self.bundle,
            "bundle_content_digest": self.identity["bundle_content_digest"],
            "environment_digest": self.identity["environment_digest"],
            "runtime_wheel_sha256": self.wheel,
        }
        self.run = {
            "id": 456,
            "run_attempt": 2,
            "head_sha": self.source,
            "head_branch": "main",
            "path": adapter.DEPLOYMENT_WORKFLOW,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "repository": {
                "full_name": adapter.DEPLOYMENT_REPOSITORY,
                "id": int(adapter.trust.TARGET_CONTRACTS["cloud"]["repository_id"]),
                "owner": {"id": int(adapter.PRODUCER_OWNER_ID)},
            },
        }
        self.add("deployment_workflow_run", self.run)
        self.readback = {
            "schema_version": "openadapt.cloud-production-deployment-readback/v1",
            "observed_at": "2026-09-11T00:05:00.123Z",
            "source_commit": self.source,
            "manifest_sha256": "sha256:" + manifest_hash,
            "manifest_bytes_sha256": "sha256:" + manifest_hash,
            "target_attestation_sha256": self.manifest["target"]["sha256"],
            "admission_activated": False,
            "provider_observation": {
                "github": {
                    "run_id": "456",
                    "run_attempt": "2",
                    "source_commit": self.source,
                    "event": "workflow_dispatch",
                },
                "host": {
                    **{
                        key: host[key]
                        for key in (
                            "deploy_id",
                            "immutable_url",
                            "created_at",
                            "published_at",
                        )
                    },
                    "site_id": self.uu(1),
                },
                "modal": {
                    **{
                        key: runner[key]
                        for key in (
                            "environment",
                            "app_id",
                            "app_name",
                            "app_version",
                            "deployed_at",
                        )
                    },
                    "source_commit": self.source,
                    "source_dirty": False,
                    "sdk_version": runtime["modal_sdk"],
                    "endpoint_origin": "https://test-only.modal.run/",
                    "function_id": "fu-" + "a" * 22,
                    "function_definition_id": "test-only-definition",
                },
                "environment_contract_sha256": host["environment_contract_sha256"],
            },
            "observed_runtime_context": {
                "deployment_manifest_sha256": manifest_hash,
                "runtime_build_identity": self.build,
                "control_image_id": "im-test-only-control",
                "modal_image_id": "im-test-only-sandbox",
                "runtime_environment_sha256": adapter.semantic_digest(
                    {"environment": "test-only-boundary"}
                ),
            },
        }
        self.readback["function_readbacks"] = [
            {
                "function_tag": tag,
                "function_id": "test-only-" + tag,
                "function_definition_id": "test-only-definition-" + tag,
            }
            for tag in ("enqueue", "run_flow", "run_teach")
        ]
        self.add("deployment_readback", self.readback)
        commitments = {}
        manifest_opening = self.add(
            "evidence-manifest", {"test_only": "protected raw inventory"}
        )
        for key in sorted(adapter.shared.FILE_COMMITMENTS):
            if key in {
                "bundle_sha256",
                "admitted_runtime_sha256",
                "evidence_manifest_sha256",
            }:
                commitments[key] = {
                    "bundle_sha256": self.bundle,
                    "admitted_runtime_sha256": self.wheel,
                    "evidence_manifest_sha256": manifest_opening,
                }[key]
                continue
            opening = {"test_only_role": key, "admitted_subject": self.subject}
            field = {
                "organization_id_sha256": "tenant_id",
                "workflow_id_sha256": "workflow_id",
                "workflow_version_id_sha256": "workflow_version_id",
            }.get(key)
            if field:
                opening["id"] = self.identity[field]
            if key == "workflow_version_id_sha256":
                opening["bundle_version"] = "1.35.1-hosted-reference.1"
            if key == "decision_identity_sha256":
                opening.update(id=self.uu(6), decision_revision=1)
            if key in {
                "decision_commitment_sha256",
                "evidence_manifest_readback_sha256",
            }:
                opening["evidence_manifest_sha256"] = manifest_opening
            if key == "decision_commitment_sha256":
                opening.update(decision_id=self.uu(6), decision_revision=1)
            if key == "campaign_artifact_sha256":
                opening = {
                    "schema_version": "openadapt.qualification-campaign/v2",
                    "campaign_id": self.uu(2),
                    "evidence_identity_sha256": self.subject[
                        "evidence_identity_sha256"
                    ],
                }
            commitments[key] = self.add("opening-" + key, opening)
        groups = []
        conditions = [(name, name) for name in adapter.PHASES if name != "safe_halt"]
        conditions += [("safe_halt", f"safe_halt_{n}") for n in range(5)]
        for cell, (name, condition) in enumerate(
            sorted(conditions, key=lambda x: x[1])
        ):
            for ordinal in range(1, 4):
                trial = cell * 3 + ordinal
                run = self.digest("run" + str(trial))
                counts = dict.fromkeys(adapter.GROUP_COUNT_FIELDS, 0)
                if name == "uncertain_delivery":
                    counts["reconciliation_required_count"] = 1
                if name == "declared_attended":
                    counts.update(
                        authenticated_bound_decision_count=1,
                        live_target_revalidation_count=1,
                    )
                if name == "governed_repair":
                    counts.update(
                        policy_approved_repair_count=1,
                        approved_repair_count=1,
                        retained_repair_evidence_count=1,
                        live_target_revalidation_count=1,
                    )
                group = {
                    "trial_id": self.uu(100 + trial),
                    "task": "test-only-task",
                    "condition": condition,
                    "campaign_class": name,
                    "ordinal": ordinal,
                    "counts": counts,
                    "phases": [],
                    "observer_before_sha256": self.add(
                        f"before-{trial}", {"test_only_before": trial}
                    ),
                    "observer_after_sha256": self.add(
                        f"after-{trial}", {"test_only_after": trial}
                    ),
                }
                phase_names, _principal = adapter.PHASES[name]
                input_hash = self.add(f"input-{trial}", {"test_only_input": trial})
                for phase in sorted(phase_names):
                    phase_run = (
                        run
                        if phase != "replay" and phase != "repair_prior"
                        else self.digest(f"{run}/{phase}")
                    )
                    outcome = {
                        "safe_halt": "HALTED_BEFORE_EFFECT",
                        "uncertain_delivery": "RECONCILIATION_REQUIRED",
                    }.get(name, "VERIFIED")
                    report = {
                        "run_id_sha256": phase_run,
                        "bundle_content_digest": self.subject["bundle_content_digest"],
                        "qualification_evidence_only": phase != "replay",
                        "production_eligible": False,
                        "transaction_outcome": outcome,
                        "success": outcome == "VERIFIED",
                        "idempotency_key": "test-only-key-" + str(trial),
                        "phase": phase,
                    }
                    if phase == "repair_prior":
                        report["bundle_content_digest"] = self.digest("prior")
                    if phase == "replay":
                        report.update(
                            qualification_evidence_only=False,
                            success=False,
                            idempotent_replay=True,
                        )
                    group["phases"].append(
                        {
                            "phase": phase,
                            "qualification_run_id_sha256": phase_run,
                            "run_report_sha256": self.add(
                                f"report-{trial}-{phase}", report
                            ),
                            "input_sha256": input_hash,
                            "auxiliary_artifacts": [],
                            "runner_receipt_sha256": self.add(
                                f"receipt-{trial}-{phase}",
                                {"test_only": [trial, phase]},
                            ),
                        }
                    )
                groups.append(group)
        self.derivative = {
            "schema_version": "openadapt.hosted-qualification-derivative/v1",
            "target": "cloud",
            "scope": "hosted-synthetic-qualification",
            "producer": producer(),
            "validator": {
                "repository": adapter.DEPLOYMENT_REPOSITORY,
                "source_commit": self.source,
                "path": "runner/qualification_issuer.py",
                "sha256": validator_hash,
                "source_inventory_sha256": source_inventory,
            },
            "subject": self.subject,
            "campaign_id": self.uu(2),
            "receipt_commitments": commitments,
            "raw_evidence_refs": sorted(
                self.refs, key=lambda x: (x["role"], x["sha256"])
            ),
            "groups": groups,
        }
        artifact = {
            "name": "deployment.json",
            "kind": "deployment-manifest",
            "sha256": "sha256:" + manifest_hash,
            "size_bytes": len(self.inventory[manifest_hash][1]),
            "media_type": "application/vnd.openadapt.production-deployment-manifest+json;version=1",
            "publish_destinations": ["deployment"],
        }
        self.artifacts = {
            "schema_version": "openadapt.production-release-artifact-inventory/v1",
            "target": "cloud",
            "claim_scope": "production_cloud",
            "artifacts": [artifact],
        }
        self.release = {
            "schema_version": "openadapt.production-release-candidate/v1",
            "kind": "deployment",
            "source_repository": adapter.DEPLOYMENT_REPOSITORY,
            "source_repository_id": adapter.trust.TARGET_CONTRACTS["cloud"][
                "repository_id"
            ],
            "source_commit": self.source,
            "version": None,
            "tag": None,
            "deployment_id": "456",
            "deployment_sha256": "sha256:" + manifest_hash,
            "artifacts": [artifact],
        }
        self.staging = {
            "schema_version": "openadapt.production-release-staging-evidence/v1",
            "publication_mode": "already-published-deployment",
            "repository": adapter.DEPLOYMENT_REPOSITORY,
            "repository_id": self.release["source_repository_id"],
            "target_commitish": self.source,
            "draft": False,
            "prerelease": False,
            "pypi_files": None,
            "deployment_id": "456",
            "deployment_url": host["immutable_url"],
            "tag": "v0.0.0-deployment.456",
            "assets": [
                {
                    **artifact,
                    "asset_id": None,
                    "uploader_id": None,
                    "uploader_login": None,
                }
            ],
            "observed_at": "2026-09-11T00:05:00Z",
        }

    def add(self, role, value):
        raw = value if isinstance(value, bytes) else adapter.canonical_json(value)
        digest = adapter.shared.sha(raw)[7:]
        path = self.directory / f"{len(self.refs)}.json"
        path.write_bytes(raw)
        self.inventory[digest] = (path, raw)
        self.refs.append({"role": role, "sha256": digest})
        return digest

    def replace(self, digest, value):
        old_path, _ = self.inventory.pop(digest)
        raw = value if isinstance(value, bytes) else adapter.canonical_json(value)
        new = adapter.shared.sha(raw)[7:]
        old_path.write_bytes(raw)
        self.inventory[new] = old_path, raw

        def update(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    node[key] = new if item == digest else update(item)
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    node[index] = update(item)
            return node

        update(self.derivative)
        self.derivative["raw_evidence_refs"].sort(
            key=lambda x: (x["role"], x["sha256"])
        )
        return new

    def gh(self, endpoint):
        if "/actions/runs/" in endpoint:
            return self.run
        for path, raw in (
            (adapter.DEPLOYMENT_WORKFLOW, self.workflow_raw),
            ("runner/runtime-version.json", adapter.canonical_json(self.runtime)),
            ("runner/qualification_issuer.py", self.validator_raw),
        ):
            if f"/contents/{path}?ref={self.source}" in endpoint:
                return {
                    "type": "file",
                    "path": path,
                    "encoding": "base64",
                    "content": base64.b64encode(raw).decode(),
                }
        raise AssertionError("unexpected GitHub interface: " + endpoint)


class CloudMeasuredInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = MeasuredFixture(temporary.name)

    def test_counts_are_derived_for_ten_cells_without_fixed_total(self):
        f = self.fixture
        summary = adapter.verify_derivative(f.derivative, f.inventory)
        self.assertEqual(sum(c["observed_trial_count"] for c in summary.values()), 30)
        self.assertEqual(summary["safe_halt"]["task_condition_cell_count"], 5)
        self.assertEqual(summary["safe_halt"]["observed_trial_count"], 15)
        self.assertEqual(
            adapter.verify_subject_openings(f.derivative, f.inventory),
            ("1.35.1-hosted-reference.1", 1),
        )
        self.assertIsNone(
            adapter.verify_deployment(
                f.derivative, f.inventory, f.release, f.staging, gh=f.gh
            )
        )

    def test_wrong_scope_source_target_counts_and_missing_phase_refuse(self):
        original = copy.deepcopy(self.fixture.derivative)
        mutations = [
            lambda d: d.update(target="flow"),
            lambda d: d.update(scope="production_cloud"),
            lambda d: d["validator"].update(source_commit="e" * 40),
            lambda d: d["groups"][0]["counts"].update(model_call_count=True),
            lambda d: d["groups"][0]["counts"].pop("model_call_count"),
            lambda d: d["groups"][0]["phases"].pop(),
            lambda d: d["groups"].append(copy.deepcopy(d["groups"][0])),
            lambda d: d["receipt_commitments"].update(bundle_sha256="a" * 64),
        ]
        for mutation in mutations:
            value = copy.deepcopy(original)
            mutation(value)
            with (
                self.subTest(mutation=mutation),
                self.assertRaises((ValueError, KeyError)),
            ):
                adapter.verify_derivative(value, self.fixture.inventory)

    def test_native_outcome_bundle_scope_and_run_mismatch_refuse(self):
        f = self.fixture
        primary = next(
            g for g in f.derivative["groups"] if g["campaign_class"] == "healthy"
        )["phases"][0]
        original = adapter.evidence_json(f.inventory, primary["run_report_sha256"])
        for key, value in (
            ("success", False),
            ("transaction_outcome", "COMPLETED_UNVERIFIED"),
            ("qualification_evidence_only", False),
            ("production_eligible", True),
            ("bundle_content_digest", "a" * 64),
            ("run_id_sha256", "b" * 64),
        ):
            f.replace(primary["run_report_sha256"], {**original, key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapter.verify_derivative(f.derivative, f.inventory)
        f.replace(primary["run_report_sha256"], original)
        self.assertIsInstance(
            adapter.verify_derivative(f.derivative, f.inventory), dict
        )

    def test_replay_keeps_native_early_refusal_but_requires_same_key(self):
        f = self.fixture
        group = next(
            g
            for g in f.derivative["groups"]
            if g["campaign_class"] == "idempotency_replay"
        )
        replay = next(p for p in group["phases"] if p["phase"] == "replay")
        report = adapter.evidence_json(f.inventory, replay["run_report_sha256"])
        self.assertFalse(report["qualification_evidence_only"])
        for key, value in (
            ("idempotency_key", "other"),
            ("idempotency_key", None),
            ("idempotent_replay", False),
            ("success", True),
        ):
            f.replace(replay["run_report_sha256"], {**report, key: value})
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "replay lacks"),
            ):
                adapter.verify_derivative(f.derivative, f.inventory)
        f.replace(replay["run_report_sha256"], report)
        self.assertIsInstance(
            adapter.verify_derivative(f.derivative, f.inventory), dict
        )

    def test_per_group_attended_proof_cannot_hide_in_aggregate(self):
        d = self.fixture.derivative
        rows = [g for g in d["groups"] if g["campaign_class"] == "declared_attended"]
        rows[0]["counts"]["authenticated_bound_decision_count"] = 0
        rows[1]["counts"]["authenticated_bound_decision_count"] = 2
        with self.assertRaisesRegex(ValueError, "each attended"):
            adapter.verify_derivative(d, self.fixture.inventory)

    def test_archive_raw_hash_is_not_native_or_runtime_semantic_hash(self):
        f = self.fixture
        self.assertNotEqual(
            f.subject["bundle_artifact_sha256"], f.subject["bundle_content_digest"]
        )
        self.assertNotEqual(
            f.subject["runtime_build_identity_sha256"], adapter.semantic_digest(f.build)
        )
        self.assertNotEqual(
            f.subject["runtime_manifest_sha256"], f.build["runtime_manifest_sha256"]
        )
        for key in (
            "runtime_build_identity_sha256",
            "evidence_identity_sha256",
            "runtime_manifest_sha256",
        ):
            original = f.subject[key]
            f.subject[key] = "a" * 64
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "semantic runtime"),
            ):
                adapter.verify_subject_openings(f.derivative, f.inventory)
            f.subject[key] = original

    def test_deployment_source_attempt_readback_and_staging_mismatch_refuse(self):
        f = self.fixture
        for key, value in (
            ("deployment_id", "455"),
            ("source_commit", "d" * 40),
            ("deployment_sha256", "sha256:" + "a" * 64),
        ):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "deployment release"),
            ):
                adapter.verify_deployment(
                    f.derivative,
                    f.inventory,
                    {**f.release, key: value},
                    f.staging,
                    gh=f.gh,
                )
        for key, value in (
            ("run_attempt", 1),
            ("run_attempt", True),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("head_sha", "d" * 40),
        ):

            def gh(endpoint, key=key, value=value):
                return (
                    {**f.run, key: value}
                    if "/actions/runs/" in endpoint
                    else f.gh(endpoint)
                )

            with (
                self.subTest(key=key),
                self.assertRaisesRegex(ValueError, "successful protected"),
            ):
                adapter.verify_deployment(
                    f.derivative, f.inventory, f.release, f.staging, gh=gh
                )
        changed = copy.deepcopy(f.staging)
        changed["assets"][0]["sha256"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "publication staging differs"):
            adapter.verify_deployment(
                f.derivative, f.inventory, f.release, changed, gh=f.gh
            )
        self.assertIsNone(f.release["tag"])
        self.assertIsNone(f.release["version"])
        self.assertEqual(f.staging["tag"], "v0.0.0-deployment.456")

    def test_provider_runtime_and_omitted_readback_refuse(self):
        f = self.fixture
        digest = next(
            r["sha256"]
            for r in f.derivative["raw_evidence_refs"]
            if r["role"] == "deployment_readback"
        )
        changed = copy.deepcopy(f.readback)
        changed["provider_observation"]["modal"]["app_version"] = "v3"
        f.replace(digest, changed)
        with self.assertRaisesRegex(ValueError, "runner provider identity"):
            adapter.verify_deployment(
                f.derivative, f.inventory, f.release, f.staging, gh=f.gh
            )
        f.derivative["raw_evidence_refs"] = [
            r
            for r in f.derivative["raw_evidence_refs"]
            if r["role"] != "deployment_readback"
        ]
        with self.assertRaisesRegex(ValueError, "exactly one deployment_readback"):
            adapter.verify_deployment(
                f.derivative, f.inventory, f.release, f.staging, gh=f.gh
            )

    def test_inventory_actual_bytes_and_scope_refuse_before_issuer(self):
        f = self.fixture
        refs = [
            {"path": path.name, "sha256": "sha256:" + digest, "size_bytes": len(raw)}
            for digest, (path, raw) in f.inventory.items()
        ]
        self.assertEqual(
            adapter.retained_inventory(f.directory / "mapping.json", refs), f.inventory
        )
        path, raw = next(iter(f.inventory.values()))
        path.write_bytes(raw + b" ")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            adapter.retained_inventory(f.directory / "mapping.json", refs)
        for target, scope in (
            ("cloud", "all-seven-production"),
            ("docs", "production_docs"),
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                adapter.shared.prepared_target(
                    {
                        "release": f.release,
                        "artifact_inventory": {
                            **f.artifacts,
                            "target": target,
                            "claim_scope": scope,
                        },
                    }
                )

    def write_mapping(self):
        f = self.fixture

        def write(name, value):
            raw = adapter.canonical_json(value)
            (f.directory / name).write_bytes(raw)
            return {
                "path": name,
                "sha256": adapter.shared.sha(raw),
                "size_bytes": len(raw),
            }

        candidate = {
            "schema_version": "openadapt.measured-cloud-release-candidate/v1",
            "state": "ready-for-review",
            "target": "cloud",
            "release": f.release,
            "artifact_inventory": f.artifacts,
            "proposed_release_identity": {
                "schema_version": "openadapt.monotonic-production-release/v1",
                "channel": "production",
                "sequence": 2,
                "previous_admission_sha256": "sha256:" + "e" * 64,
            },
        }
        mapping = {
            "schema_version": "openadapt.measured-cloud-admission-mapping/v1",
            "candidate": write("candidate.json", candidate),
            "derivative": write("derivative.json", f.derivative),
            "publication_staging": write("staging.json", f.staging),
            "publication_observation": None,
            "provenance": {"test_only": "mocked after separate crypto tests"},
            "retained_files": [
                {
                    "path": path.name,
                    "sha256": "sha256:" + digest,
                    "size_bytes": len(raw),
                }
                for digest, (path, raw) in f.inventory.items()
            ],
        }
        reference = write("mapping.json", mapping)
        return f.directory / reference["path"], reference["sha256"]

    def test_prepare_composes_verified_inputs_without_issuer_or_signer(self):
        f = self.fixture
        path, digest = self.write_mapping()
        with (
            mock.patch.object(adapter, "verify_derivative_provenance") as provenance,
            mock.patch.object(
                adapter.shared,
                "current_context",
                side_effect=AssertionError("no issuer in input preparation"),
            ),
            mock.patch.object(
                adapter.shared.software,
                "keychain_read",
                side_effect=AssertionError("no signing"),
            ),
        ):
            result = adapter.prepare_inputs(path, digest, gh=f.gh)
        provenance.assert_called_once()
        self.assertEqual(
            provenance.call_args.args[1], (f.directory / "derivative.json").read_bytes()
        )
        self.assertEqual(result["release"], f.release)
        self.assertEqual(result["artifact_inventory"], f.artifacts)
        self.assertEqual(
            result["campaign_summary"],
            adapter.verify_derivative(f.derivative, f.inventory),
        )
        self.assertEqual(result["bundle_version"], "1.35.1-hosted-reference.1")
        self.assertEqual(result["mapping_sha256"], digest)
        self.assertEqual(set(result["commitments"]), adapter.shared.FILE_COMMITMENTS)
        self.assertNotIn("raw_evidence_refs", result)
        self.assertNotIn("admitted_subject", result)

    def test_prepare_requires_provenance_and_actual_candidate_bytes(self):
        path, digest = self.write_mapping()
        with (
            mock.patch.object(
                adapter,
                "verify_derivative_provenance",
                side_effect=ValueError("crypto refused"),
            ),
            self.assertRaisesRegex(ValueError, "crypto refused"),
        ):
            adapter.prepare_inputs(path, digest, gh=self.fixture.gh)
        (self.fixture.directory / "candidate.json").write_bytes(b"{}")
        with (
            mock.patch.object(adapter, "verify_derivative_provenance") as provenance,
            self.assertRaisesRegex(ValueError, "bytes differ"),
        ):
            adapter.prepare_inputs(path, digest, gh=self.fixture.gh)
        provenance.assert_not_called()

    def test_flow_cli_cannot_consume_cloud_inputs_or_request_another_target(self):
        from datetime import datetime, timezone

        path = self.fixture.directory / "request.json"
        request = {
            "phase": "receipt",
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_handle": "qair_" + "A" * 43,
            "issuer_source_commit": "a" * 40,
            "expires_at": None,
        }
        path.write_bytes(adapter.canonical_json(request))
        output = self.fixture.directory / "unsigned.json"
        args = [
            "--mapping",
            str(path),
            "--mapping-sha256",
            adapter.shared.sha(path.read_bytes()),
            "--phase-request",
            str(path),
            "--output",
            str(output),
        ]
        inputs = {
            "release": self.fixture.release,
            "artifact_inventory": self.fixture.artifacts,
        }
        with (
            mock.patch.object(
                adapter.shared, "prepare_inputs", return_value=inputs
            ) as prepare,
            mock.patch.object(adapter.shared, "current_context") as context,
            mock.patch.object(adapter.shared.software, "keychain_read") as key,
            mock.patch.object(adapter.shared, "persist_once") as state,
        ):
            self.assertEqual(adapter.shared.main(args), 1)
        prepare.assert_called_once()
        context.assert_not_called()
        key.assert_not_called()
        state.assert_not_called()
        self.assertFalse(output.exists())
        with self.assertRaises(SystemExit):
            adapter.shared.main(args + ["--target", "cloud"])


class CloudPublicationObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = f = MeasuredFixture(temporary.name)
        self.owner = f.directory / "mapping.json"
        self.derivative_raw = adapter.canonical_json(f.derivative)
        prior = f.readback["provider_observation"]
        context = f.readback["observed_runtime_context"]
        runtime = f.runtime
        self.observation = {
            "observed_at": "2026-09-11T01:00:00.123Z",
            "app_id": prior["modal"]["app_id"],
            "app_version": prior["modal"]["app_version"],
            "source_commit": f.source,
            "netlify_deploy_id": prior["host"]["deploy_id"],
            "runtime_boundary_id": "test-only-boundary",
            "deployment_manifest_sha256": f.subject["deployment_manifest_sha256"],
            "control_image_id": context["control_image_id"],
            "sandbox_image_id": context["modal_image_id"],
            "provider_observation": {key: prior[key] for key in ("host", "modal")},
            "health": {
                "ready": True,
                "service": "runner",
                "mode": "live",
                "boundary_id": "test-only-boundary",
                "flow_version": runtime["openadapt_flow"],
                "modal_sdk": runtime["modal_sdk"],
                "fastapi": runtime["fastapi"],
                "starlette": runtime["starlette"],
                "runner_build": runtime["runner_build"],
                "runner_artifact_sha256": runtime["runner_artifact_sha256"],
                "sandbox_network_policy": runtime["sandbox_network_policy"],
                "deployment_manifest_sha256": f.subject["deployment_manifest_sha256"],
                "runtime_build_identity": f.build,
                "runtime_environment_sha256": context["runtime_environment_sha256"],
                "function_readbacks": f.readback["function_readbacks"],
                "deployment_readback": {
                    "app_id": prior["modal"]["app_id"],
                    "app_version": prior["modal"]["app_version"],
                    "function_id": prior["modal"]["function_id"],
                    "function_definition_id": prior["modal"]["function_definition_id"],
                    "control_image_id": context["control_image_id"],
                    "sandbox_image_id": context["modal_image_id"],
                },
            },
        }
        self.run = {
            "run_started_at": "2026-09-11T00:59:00Z",
            "updated_at": "2026-09-11T01:01:00Z",
        }
        self.staging = {**f.staging, "observed_at": "2026-09-11T01:00:00Z"}

    def references(self, observation=None, **changes):
        f = self.fixture

        def write(name, value):
            raw = adapter.canonical_json(value)
            (f.directory / name).write_bytes(raw)
            return {
                "path": name,
                "sha256": adapter.shared.sha(raw),
                "size_bytes": len(raw),
            }

        observation = observation or self.observation
        raw_ref = write("fresh-readback.json", observation)
        proof = {
            "schema_version": "openadapt.hosted-publication-observation/v1",
            "producer": producer(),
            "qualification_derivative_sha256": adapter.shared.sha(self.derivative_raw)[
                7:
            ],
            "subject": f.subject,
            "observed_at": observation["observed_at"],
            "provider_readback_sha256": raw_ref["sha256"][7:],
            **changes,
        }
        return {
            "artifact": write("fresh-observation.json", proof),
            "provider_readback": raw_ref,
            "provenance": {"test_only": "separate fixed-workflow crypto tests"},
        }

    def verify(self, reference, staging=None):
        f = self.fixture
        return adapter.verify_publication_observation(
            self.owner,
            reference,
            f.derivative,
            self.derivative_raw,
            f.inventory,
            staging or self.staging,
            gh=f.gh,
        )

    def test_original_time_cannot_be_refreshed_without_new_observation(self):
        self.assertIsNone(self.verify(None, self.fixture.staging))
        with self.assertRaisesRegex(ValueError, "staging time differs"):
            self.verify(None)

    def test_separate_attested_refresh_preserves_original_bytes(self):
        f = self.fixture
        originals = {digest: raw for digest, (_, raw) in f.inventory.items()}
        reference = self.references()
        with mock.patch.object(
            adapter, "verify_derivative_provenance", return_value=self.run
        ) as verifier:
            self.assertIsNone(self.verify(reference))
        verifier.assert_called_once()
        self.assertEqual(
            verifier.call_args.args[1],
            (f.directory / reference["artifact"]["path"]).read_bytes(),
        )
        self.assertEqual(verifier.call_args.args[2], producer())
        self.assertEqual(
            {digest: path.read_bytes() for digest, (path, _) in f.inventory.items()},
            originals,
        )
        self.assertEqual(adapter.canonical_json(f.derivative), self.derivative_raw)

    def test_unverified_or_wrong_original_subject_and_bytes_refuse(self):
        reference = self.references()
        with (
            mock.patch.object(
                adapter,
                "verify_derivative_provenance",
                side_effect=ValueError("crypto refused"),
            ),
            self.assertRaisesRegex(ValueError, "crypto refused"),
        ):
            self.verify(reference)
        for changes in (
            {"qualification_derivative_sha256": "a" * 64},
            {"subject": {**self.fixture.subject, "source_commit": "b" * 40}},
            {"provider_readback_sha256": "a" * 64},
            {"observed_at": "2026-09-11T01:00:01.000Z"},
            {"extra": "not allowed"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.references(**changes))
        reference = self.references()
        (self.fixture.directory / reference["provider_readback"]["path"]).write_bytes(
            b"{}"
        )
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.verify(reference)

    def test_staging_and_millisecond_time_must_fit_authenticated_attempt(self):
        for observed_at in ("2026-09-11T00:58:59.999Z", "2026-09-11T01:01:01.000Z"):
            changed = {**self.observation, "observed_at": observed_at}
            with (
                self.subTest(observed_at=observed_at),
                mock.patch.object(
                    adapter, "verify_derivative_provenance", return_value=self.run
                ),
                self.assertRaisesRegex(ValueError, "outside its authenticated"),
            ):
                self.verify(self.references(changed))
        for value in (
            "2026-09-11T01:00:00Z",
            "2026-09-11T01:00:00.123000Z",
            "2026-09-11T01:00:00.123+00:00",
            "invalid",
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "UTC milliseconds"),
            ):
                self.verify(self.references({**self.observation, "observed_at": value}))
        with (
            mock.patch.object(
                adapter, "verify_derivative_provenance", return_value=self.run
            ),
            self.assertRaisesRegex(ValueError, "staging time differs"),
        ):
            self.verify(
                self.references(),
                {**self.staging, "observed_at": "2026-09-11T01:00:01Z"},
            )

    def test_changed_provider_image_build_or_health_refuses(self):
        for path, value in (
            (("source_commit",), "a" * 40),
            (("app_version",), "v3"),
            (("control_image_id",), "other"),
            (("sandbox_image_id",), "other"),
            (("netlify_deploy_id",), "b" * 24),
            (("provider_observation", "modal", "function_id"), "other"),
            (("health", "runtime_build_identity"), {}),
            (("health", "runtime_environment_sha256"), "a" * 64),
            (("health", "flow_version"), "1.34.0"),
            (("health", "ready"), 1),
            (("health", "function_readbacks", 1, "function_definition_id"), "other"),
            (("health", "deployment_readback", "function_definition_id"), "other"),
        ):
            changed = copy.deepcopy(self.observation)
            target = changed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with (
                self.subTest(path=path),
                mock.patch.object(
                    adapter, "verify_derivative_provenance", return_value=self.run
                ),
                self.assertRaises(ValueError),
            ):
                self.verify(self.references(changed))


if __name__ == "__main__":
    unittest.main()
