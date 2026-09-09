"""Admission adapter tests use temporary parser fixtures and test-only keys."""

import copy
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import test_measured_flow_candidate as samples
import test_qualification_issuer as signed_samples

SPEC = importlib.util.spec_from_file_location(
    "measured_flow_admission", ROOT / "local-candidates/flow-1.35.1-measured/issue.py"
)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def retain(path):
    return {
        "path": path.name,
        "sha256": adapter.sha(path.read_bytes()),
        "size_bytes": path.stat().st_size,
    }


def write(path, value):
    path.write_bytes(adapter.canonical(value))
    return retain(path)


def inputs_fixture(root):
    wheel, sdist = samples.archives(root)
    manifest_path, manifest = samples.manifest(root, wheel=wheel, version="1.35.1")
    subject = {
        key: adapter.sha(key.encode()).removeprefix("sha256:")
        for key in adapter.SUBJECT_FIELDS
    }
    manifest["admitted_subject"] = subject
    manifest["candidate_ready"] = True
    for trial in manifest["trials"]:
        observed_path = root / trial["observation"]["path"]
        observation = json.loads(observed_path.read_bytes())
        for ref in observation["reports"]:
            report_path = root / ref["path"]
            report = json.loads(report_path.read_bytes())
            report.update(subject)
            write(report_path, report)
            samples.update_references(observation, report_path)
            samples.update_references(manifest, report_path)
            ref["bundle_role"] = "admitted"
        source_ref = write(
            root / f"source-{trial['class']}-{trial['trial']}.json",
            [
                {
                    **{
                        k: trial[k]
                        for k in ("class", "task_id", "condition", "trial", "counters")
                    },
                    "runtime_version": "1.35.1",
                    "native_reports": [
                        {k: ref[k] for k in ("path", "role", "bundle_role")}
                        for ref in observation["reports"]
                    ],
                    "passed": True,
                    "errors": [],
                }
            ],
        )
        manifest["artifacts"].append(source_ref)
        observation["counter_source"] = {"observation": source_ref, "row_index": 0}
        if trial["class"] == "governed_repair":
            prior_digest = "e" * 64
            approval = write(
                root / f"repair-approval-{trial['trial']}.json",
                {
                    "prior_content_digest": prior_digest,
                    "proposed_content_digest": subject["bundle_content_digest"],
                    "approved_by": "test-only-reviewer",
                },
            )
            pointer = write(
                root / f"repair-pointer-{trial['trial']}.json",
                {"mode": "active", "active_digest": subject["bundle_content_digest"]},
            )
            transition = write(
                root / f"repair-transition-{trial['trial']}.json",
                {
                    "prior_bundle_content_digest": prior_digest,
                    "proposed_bundle_content_digest": subject["bundle_content_digest"],
                    "active_bundle_content_digest": subject["bundle_content_digest"],
                    "candidate_approval": approval,
                    "active_pointer": pointer,
                },
            )
            manifest["artifacts"].extend((approval, pointer, transition))
            observation["repair_transition_verification"] = transition
        write(observed_path, observation)
        samples.update_references(manifest, observed_path)
    write(manifest_path, manifest)
    archive = root / "encrypted-bundle.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("workflow.json.enc", b"test-only-encrypted-fixture")
    verifier_ref = write(root / "reviewed-verifier.json", {"test_only": True})
    proof = {
        "schema_version": "openadapt.measured-bundle-verification/v1",
        "verified": True,
        "bundle_archive_sha256": retain(archive)["sha256"],
        "admitted_subject": subject,
        "bundle_members": [
            {
                "path": "workflow.json.enc",
                "size_bytes": 27,
                "sha256": adapter.sha(b"test-only-encrypted-fixture"),
            }
        ],
        "verifier": verifier_ref,
    }
    proof["bundle_members"][0]["size_bytes"] = len(b"test-only-encrypted-fixture")
    proof_ref = write(root / "bundle-verification.json", proof)
    commitments = {}
    for field in adapter.FILE_COMMITMENTS:
        if field == "bundle_sha256":
            ref = retain(archive)
        elif field == "admitted_runtime_sha256":
            ref = retain(wheel)
        elif field == "evidence_manifest_sha256":
            ref = retain(manifest_path)
        else:
            ref = write(
                root / f"{field}.json",
                {
                    "test_only": True,
                    "field": field,
                    "evidence_manifest_sha256": retain(manifest_path)["sha256"],
                    "admitted_subject": subject,
                },
            )
        commitments[field] = ref
    bridge_ref = write(
        root / "contract-verification.json",
        {
            "schema_version": "openadapt.measured-contract-verification/v1",
            "verified": True,
            "admitted_subject": subject,
            "bundle_verification_sha256": proof_ref["sha256"],
            "receipt_commitments": {
                key: value["sha256"] for key, value in commitments.items()
            },
            "verifier": verifier_ref,
        },
    )
    summary, measured = adapter.measured.summarize(
        manifest_path, retain(wheel)["sha256"], version="1.35.1"
    )
    candidate = {
        "schema_version": "openadapt.unsigned-measured-release-candidate/v1",
        "target": "flow",
        "evidence_class": "remote-safe-synthetic",
        "admission_issued": False,
        "state": "ready-for-review",
        "campaign_summary": summary,
        "measured_evidence": measured,
        "measured_manifest_sha256": retain(manifest_path)["sha256"],
        "proposed_release_identity": {
            "schema_version": "openadapt.monotonic-production-release/v1",
            "channel": "production",
            "sequence": 2,
            "previous_admission_sha256": adapter.sha(b"test-previous"),
        },
        "release_observation": {
            "published": True,
            "version": "1.35.1",
            "source_commit": "a" * 40,
            "artifacts": [
                {
                    "kind": kind,
                    "name": path.name,
                    **{key: retain(path)[key] for key in ("sha256", "size_bytes")},
                }
                for kind, path in (("python-wheel", wheel), ("python-sdist", sdist))
            ],
        },
    }
    mapping = {
        "schema_version": "openadapt.measured-admission-mapping/v1",
        "admitted_subject": subject,
        "repair_prior_subject": {**subject, "bundle_content_digest": "e" * 64},
        "candidate": write(root / "candidate.json", candidate),
        "commitments": commitments,
        "bundle_verification": proof_ref,
        "contract_verification": bridge_ref,
        "publication_files": {p.name: retain(p) for p in (wheel, sdist)},
        "publication_staging": write(root / "staging.json", {"test_only": True}),
        "bundle_version": "1.0.1",
        "decision_revision": 1,
    }
    path = root / "mapping.json"
    write(path, mapping)
    return path, mapping, manifest_path, manifest


def trust_context():
    fixture = signed_samples.trust_fixture(decision_origin="software", expires_at=None)
    registry = fixture["registry"]
    registry["signers"].append(
        adapter.public_trust.software_public_signer(
            fixture["decision_key"].public_key()
        )
    )
    identity = adapter.evidence.signer_registry_identity_digest(registry)
    authority = fixture["authority"]
    authority["signer_registry_sha256"] = adapter.sha(adapter.canonical(registry))
    authority["signer_registry_identity_sha256"] = identity
    projection = {
        k: v
        for k, v in authority.items()
        if k not in {"authority_state_sha256", "signature", "signing_statement"}
    }
    authority["authority_state_sha256"] = adapter.trust.digest_bytes(
        adapter.trust.AUTHORITY_STATE_IDENTITY_DOMAIN, projection
    )
    signed_samples.sign_embedded(
        authority,
        fixture["authority_key"],
        schema=authority["schema_version"],
        domain=adapter.trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
    )
    revocation = fixture["revocation"]
    revocation.update(
        signer_registry_sha256=identity,
        authority_state_sha256=authority["authority_state_sha256"],
    )
    projection = {
        k: v
        for k, v in revocation.items()
        if k not in {"revocation_state_sha256", "signature", "signing_statement"}
    }
    revocation["revocation_state_sha256"] = adapter.trust.digest_bytes(
        adapter.trust.REVOCATION_STATE_IDENTITY_DOMAIN, projection
    )
    signed_samples.sign_embedded(
        revocation,
        fixture["revocation_key"],
        schema=revocation["schema_version"],
        domain=adapter.trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
    )
    fixture["receipt"].update(
        signer_registry_sha256=identity,
        revocation_state_sha256=revocation["revocation_state_sha256"],
    )
    fixture["receipt"] = adapter.software.sign_receipt(
        fixture["receipt"],
        private_key=fixture["decision_key"],
        signer_registry=registry,
    )
    fixture["receipt_ref"], fixture["receipt_bundle_ref"] = (
        signed_samples.reference_pair(adapter.KINDS["receipt"], fixture["receipt"])
    )
    resolver = signed_samples.RecordingResolver(fixture)
    return fixture, {
        "resolver": resolver,
        "registry": registry,
        "authority": authority,
        "revocation": revocation,
        "expiry": None,
        "acceptance_policy_sha256": adapter.sha(b"test policy"),
        "lifecycle_policy_sha256": adapter.sha(b"test lifecycle"),
        "authority_reference": resolver.authority["reference"],
        "revocation_reference": resolver.revocation["reference"],
    }


def request(phase, source="1" * 40, **references):
    return {
        "phase": phase,
        "issuer_source_commit": source,
        "issued_at": signed_samples.utc(signed_samples.NOW),
        "expires_at": None,
        "references": references,
        "request_handle": "qair_" + phase[0] * 43,
    }


class MeasuredAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path, self.mapping, self.manifest_path, self.manifest = inputs_fixture(
            self.root
        )

    def prepare(self):
        return adapter.prepare_inputs(
            self.path,
            adapter.sha(self.path.read_bytes()),
            publication_check=lambda *_args: None,
        )

    def test_one_task_counts_and_distinct_digest_meanings(self):
        value = self.prepare()
        self.assertEqual(
            value["campaign_summary"]["healthy"]["observed_trial_count"], 3
        )
        self.assertEqual(
            value["campaign_summary"]["governed_repair"]["approved_repair_count"], 3
        )
        self.assertNotEqual(
            value["commitments"]["bundle_sha256"],
            "sha256:" + self.mapping["admitted_subject"]["bundle_content_digest"],
        )
        self.assertNotIn("evidence_authority_contract_sha256", value["commitments"])

    def test_mutated_actual_contract_bytes_refuse(self):
        ref = self.mapping["commitments"]["action_contract_sha256"]
        (self.root / ref["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.prepare()

    def test_mutated_mapping_hash_refuses(self):
        with self.assertRaisesRegex(ValueError, "mapping bytes"):
            adapter.prepare_inputs(self.path, adapter.sha(b"wrong"))

    def test_semantically_changed_contract_rehash_still_requires_reviewed_bridge(self):
        ref = self.mapping["commitments"]["action_contract_sha256"]
        path = self.root / ref["path"]
        self.mapping["commitments"]["action_contract_sha256"] = write(
            path, {"different": True}
        )
        write(self.path, self.mapping)
        with self.assertRaisesRegex(ValueError, "contract mapping"):
            self.prepare()

    def test_second_task_cannot_reuse_old_campaign_counts(self):
        self.manifest["trials"][0]["task_id"] = "another-task"
        with self.assertRaisesRegex(ValueError, "one task"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_wrong_native_tuple_refuses_even_when_rehashed(self):
        trial = self.manifest["trials"][0]
        observation = json.loads(
            (self.root / trial["observation"]["path"]).read_bytes()
        )
        path = self.root / observation["reports"][0]["path"]
        report = json.loads(path.read_bytes())
        report["bundle_content_digest"] = "f" * 64
        write(path, report)
        samples.update_references(self.manifest, path)
        with self.assertRaisesRegex(ValueError, "exact declared bundle tuple"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def bind_source_reports(self, observation):
        ref = observation["counter_source"]["observation"]
        path = self.root / ref["path"]
        rows = json.loads(path.read_bytes())
        rows[observation["counter_source"]["row_index"]]["native_reports"] = [
            {k: r[k] for k in ("path", "role", "bundle_role")}
            for r in observation["reports"]
        ]
        write(path, rows)
        samples.update_references(observation, path)
        samples.update_references(self.manifest, path)

    def test_auxiliary_prior_is_only_allowed_for_governed_repair(self):
        trial = next(
            t for t in self.manifest["trials"] if t["class"] == "governed_repair"
        )
        path = self.root / trial["observation"]["path"]
        observation = json.loads(path.read_bytes())
        prior = {**self.mapping["admitted_subject"], "bundle_content_digest": "e" * 64}
        ref = write(
            self.root / "prior.json",
            {
                **prior,
                "success": False,
                "transaction_outcome": "RECONCILIATION_REQUIRED",
                "model_calls": 0,
            },
        )
        self.manifest["artifacts"].append(ref)
        observation["reports"].append(
            {**ref, "role": "discovery", "bundle_role": "repair-prior"}
        )
        self.bind_source_reports(observation)
        write(path, observation)
        samples.update_references(self.manifest, path)
        adapter.verify_subjects(
            self.manifest_path, self.manifest, self.mapping["admitted_subject"], prior
        )
        observation["reports"][0]["bundle_role"] = "repair-prior"
        self.bind_source_reports(observation)
        write(path, observation)
        samples.update_references(self.manifest, path)
        with self.assertRaisesRegex(ValueError, "bundle role"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                prior,
            )

    def test_symlink_and_traversal_refuse(self):
        file = self.root / "real"
        file.write_bytes(b"actual")
        link = self.root / "link"
        link.symlink_to(file)
        for ref in (
            {**retain(file), "path": "link"},
            {**retain(file), "path": "../real"},
        ):
            with self.assertRaises(ValueError):
                adapter.checked_file(self.path, ref)

    def test_plain_prepare_never_reads_key_or_changes_registry(self):
        with (
            mock.patch.object(
                adapter.software,
                "keychain_read",
                side_effect=AssertionError("secret access"),
            ),
            mock.patch.object(
                adapter.stage, "main", side_effect=AssertionError("registry mutation")
            ),
        ):
            self.prepare()

    def test_default_cli_rejects_signing_options(self):
        result = adapter.main(
            [
                "--mapping",
                str(self.path),
                "--mapping-sha256",
                adapter.sha(self.path.read_bytes()),
                "--phase-request",
                str(self.path),
                "--output",
                str(self.root / "plan"),
                "--state-dir",
                str(self.root / "state"),
            ]
        )
        self.assertEqual(result, 1)
        self.assertFalse((self.root / "state").exists())

    def test_branch_cannot_be_claimed_as_current_main(self):
        with (
            mock.patch.object(
                adapter.verifier, "protected_main_commit", return_value="1" * 40
            ),
            mock.patch.object(
                adapter.verifier,
                "fetch",
                side_effect=AssertionError("must refuse before read"),
            ),
            self.assertRaisesRegex(ValueError, "actual current protected main"),
        ):
            adapter.current_context("2" * 40, signed_samples.NOW)

    def test_receipt_signature_is_empty_until_real_test_key_signs(self):
        fixture, context = trust_context()
        value, issue = adapter.phase_object(self.prepare(), request("receipt"), context)
        self.assertEqual(value["signature"], "")
        self.assertIsNone(issue)
        plan = {"phase_request": request("receipt"), "unsigned_object": value}
        raw, bundle = adapter.sign_pair(
            value, plan, context, private_key=fixture["decision_key"]
        )
        signed = json.loads(raw)
        adapter.trust.validate_receipt(
            signed, signer_registry=fixture["registry"], now=signed_samples.NOW
        )
        self.assertEqual(signed["campaign_summary"]["task_count"], 1)
        self.assertEqual(
            signed["evidence_authority_contract_sha256"],
            context["authority"]["evidence_authority_sha256"],
        )
        self.assertTrue(json.loads(bundle)["dsseEnvelope"]["signatures"])

    def test_persistent_result_recovers_without_reissuing(self):
        plan = {
            "phase_request": request("receipt"),
            "issue_request": None,
            "inputs": self.prepare(),
            "unsigned_object": {"test_only": "result"},
        }
        calls = []

        def perform(_consumer):
            calls.append(1)
            return plan["unsigned_object"]

        state = self.root / "state"
        self.assertEqual(
            adapter.persist_once(plan, state, perform), plan["unsigned_object"]
        )
        self.assertEqual(
            adapter.persist_once(plan, state, lambda _: self.fail("retry")),
            plan["unsigned_object"],
        )
        self.assertEqual(calls, [1])
        changed = copy.deepcopy(plan)
        changed["phase_request"]["request_handle"] = "qair_" + "Z" * 43
        with self.assertRaisesRegex(ValueError, "existing durable file differs"):
            adapter.persist_once(
                changed, state, lambda _: self.fail("retry with new handle")
            )

    def test_unknown_result_never_retries_or_deletes_state(self):
        plan = {
            "phase_request": request("receipt"),
            "issue_request": None,
            "inputs": self.prepare(),
            "unsigned_object": {"test_only": "result"},
        }
        state = self.root / "state"
        with self.assertRaisesRegex(RuntimeError, "interruption"):
            adapter.persist_once(
                plan,
                state,
                lambda _: (_ for _ in ()).throw(RuntimeError("interruption")),
            )
        before = list(state.glob("*.request.json"))
        with self.assertRaises(adapter.issuer.IssuerError):
            adapter.persist_once(
                plan, state, lambda _: self.fail("unknown must not retry")
            )
        self.assertEqual(before, list(state.glob("*.request.json")))

    def test_normalizer_cannot_invent_counter_missing_from_actual_source(self):
        trial = self.manifest["trials"][0]
        observation_path = self.root / trial["observation"]["path"]
        observation = json.loads(observation_path.read_bytes())
        source_path = self.root / observation["counter_source"]["observation"]["path"]
        rows = json.loads(source_path.read_bytes())
        rows[0]["counters"].pop("silent_incorrect_success_count")
        observation["counter_source"]["observation"] = write(source_path, rows)
        samples.update_references(self.manifest, source_path)
        write(observation_path, observation)
        samples.update_references(self.manifest, observation_path)
        with self.assertRaisesRegex(ValueError, "normalized counters"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_repair_labels_cannot_hide_wrong_actual_active_pointer(self):
        trial = next(
            t for t in self.manifest["trials"] if t["class"] == "governed_repair"
        )
        observation_path = self.root / trial["observation"]["path"]
        observation = json.loads(observation_path.read_bytes())
        transition_path = (
            self.root / observation["repair_transition_verification"]["path"]
        )
        transition = json.loads(transition_path.read_bytes())
        pointer_path = self.root / transition["active_pointer"]["path"]
        transition["active_pointer"] = write(
            pointer_path,
            {
                "mode": "active",
                "active_digest": self.mapping["repair_prior_subject"][
                    "bundle_content_digest"
                ],
            },
        )
        samples.update_references(self.manifest, pointer_path)
        observation["repair_transition_verification"] = write(
            transition_path, transition
        )
        samples.update_references(self.manifest, transition_path)
        write(observation_path, observation)
        samples.update_references(self.manifest, observation_path)
        with self.assertRaisesRegex(
            ValueError, "actual repair approval and ACTIVE pointer"
        ):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def replay_fixture(self):
        trial = next(
            t for t in self.manifest["trials"] if t["class"] == "idempotency_replay"
        )
        path = self.root / trial["observation"]["path"]
        observation = json.loads(path.read_bytes())
        primary_path = self.root / observation["reports"][0]["path"]
        primary_report = json.loads(primary_path.read_bytes())
        primary_report.update(
            idempotency_key="test-same-key",
            run_id_sha256=adapter.sha(b"test-initial-run").removeprefix("sha256:"),
        )
        write(primary_path, primary_report)
        samples.update_references(observation, primary_path)
        samples.update_references(self.manifest, primary_path)
        base_fields = {
            "bundle_content_digest",
            "workflow_contract_sha256",
            "parameter_schema_sha256",
        }
        replay = {
            key: value if key in base_fields else None
            for key, value in self.mapping["admitted_subject"].items()
        }
        replay.update(
            idempotent_replay=True,
            idempotency_key="test-same-key",
            run_id_sha256=adapter.sha(b"test-replay-run").removeprefix("sha256:"),
            success=False,
            transaction_outcome="HALTED",
            model_calls=0,
        )
        ref = write(self.root / "replay.json", replay)
        self.manifest["artifacts"].append(ref)
        proof = {
            "schema_version": "openadapt.idempotent-replay-refusal-verification/v1",
            "report_sha256": ref["sha256"],
            "primary_report_sha256": observation["reports"][0]["sha256"],
            "same_key": True,
            "no_new_input": True,
        }
        for field in (
            "ledger_before",
            "ledger_after",
            "input_events_before",
            "input_events_after",
        ):
            snapshot_path = self.root / f"{field}.json"
            if field.startswith("ledger_"):
                with sqlite3.connect(snapshot_path) as connection:
                    connection.execute(
                        "CREATE TABLE ledger_metadata(singleton INTEGER PRIMARY KEY, schema_version TEXT, namespace TEXT, owner_path TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO ledger_metadata VALUES (1, 'openadapt.idempotency-ledger/v3', 'openadapt-flow-runtime/v1', '/test-only/original-ledger')"
                    )
                    connection.execute(
                        "CREATE TABLE reservations(namespace TEXT, reservation_key TEXT, run_id TEXT, reserved_at TEXT, outcome TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO reservations VALUES ('openadapt-flow-runtime/v1', 'test-same-key', 'test-initial-run', '2026-08-27T12:00:00Z', 'VERIFIED')"
                    )
                snapshot = retain(snapshot_path)
            else:
                snapshot = write(snapshot_path, {"fixture_events": []})
            self.manifest["artifacts"].append(snapshot)
            proof[field] = snapshot
        proof_ref = write(self.root / "replay-proof.json", proof)
        self.manifest["artifacts"].append(proof_ref)
        observation["replay_refusal_verification"] = proof_ref
        observation["reports"].append(
            {**ref, "role": "replay", "bundle_role": "admitted"}
        )
        self.bind_source_reports(observation)
        write(path, observation)
        samples.update_references(self.manifest, path)
        return path, observation, proof

    def update_replay_proof(self, observation_path, observation, proof):
        proof_path = self.root / observation["replay_refusal_verification"]["path"]
        observation["replay_refusal_verification"] = write(proof_path, proof)
        samples.update_references(self.manifest, proof_path)
        write(observation_path, observation)
        samples.update_references(self.manifest, observation_path)

    def test_replay_keys_must_be_present_nonempty_and_equal_in_native_reports(self):
        observation_path, observation, proof = self.replay_fixture()
        ref = next(r for r in observation["reports"] if r["role"] == "replay")
        path = self.root / ref["path"]
        original = json.loads(path.read_bytes())
        for value in (None, "", "different-native-key"):
            with self.subTest(key=value):
                report = {**original, "idempotency_key": value}
                write(path, report)
                samples.update_references(observation, path)
                samples.update_references(self.manifest, path)
                proof["report_sha256"] = retain(path)["sha256"]
                self.update_replay_proof(observation_path, observation, proof)
                with self.assertRaisesRegex(ValueError, "native idempotency keys"):
                    adapter.verify_subjects(
                        self.manifest_path,
                        self.manifest,
                        self.mapping["admitted_subject"],
                        self.mapping["repair_prior_subject"],
                    )

    def test_replay_primary_native_key_cannot_be_missing(self):
        observation_path, observation, proof = self.replay_fixture()
        path = self.root / observation["reports"][0]["path"]
        report = json.loads(path.read_bytes())
        report.pop("idempotency_key")
        write(path, report)
        samples.update_references(observation, path)
        samples.update_references(self.manifest, path)
        proof["primary_report_sha256"] = retain(path)["sha256"]
        self.update_replay_proof(observation_path, observation, proof)
        with self.assertRaisesRegex(ValueError, "native idempotency keys"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_replay_ledger_must_bind_the_actual_initial_run_digest(self):
        observation_path, observation, proof = self.replay_fixture()
        path = self.root / proof["ledger_after"]["path"]
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE reservations SET run_id = 'another-initial-run'")
        proof["ledger_after"] = retain(path)
        samples.update_references(self.manifest, path)
        self.update_replay_proof(observation_path, observation, proof)
        with self.assertRaisesRegex(ValueError, "same key to the verified initial run"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_same_subject_reports_cannot_move_between_counted_source_rows(self):
        trials = [
            next(t for t in self.manifest["trials"] if t["class"] == name)
            for name in ("healthy", "declared_attended")
        ]
        paths = [self.root / t["observation"]["path"] for t in trials]
        observations = [json.loads(p.read_bytes()) for p in paths]
        observations[0]["reports"], observations[1]["reports"] = (
            observations[1]["reports"],
            observations[0]["reports"],
        )
        for path, observation in zip(paths, observations):
            write(path, observation)
            samples.update_references(self.manifest, path)
        inventory = {item["path"]: item for item in self.manifest["artifacts"]}
        for trial in trials:
            adapter.measured.verify_trial_observation(
                trial,
                inventory,
                self.root,
                "1.35.1",
                self.manifest["runtime"]["wheel_sha256"],
                set(),
            )
        with self.assertRaisesRegex(
            ValueError, "do not belong to the counted source row"
        ):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_early_replay_refusal_preserves_real_missing_observations(self):
        self.replay_fixture()
        adapter.verify_subjects(
            self.manifest_path,
            self.manifest,
            self.mapping["admitted_subject"],
            self.mapping["repair_prior_subject"],
        )

    def test_replay_no_input_label_cannot_hide_actual_new_events(self):
        _, _, proof = self.replay_fixture()
        path = self.root / proof["input_events_after"]["path"]
        write(path, {"fixture_events": ["new input"]})
        samples.update_references(self.manifest, path)
        proof["input_events_after"] = retain(path)
        proof_path = self.root / "replay-proof.json"
        write(proof_path, proof)
        samples.update_references(self.manifest, proof_path)
        trial = next(
            t for t in self.manifest["trials"] if t["class"] == "idempotency_replay"
        )
        observation_path = self.root / trial["observation"]["path"]
        observation = json.loads(observation_path.read_bytes())
        observation["replay_refusal_verification"] = retain(proof_path)
        write(observation_path, observation)
        samples.update_references(self.manifest, observation_path)
        with self.assertRaisesRegex(ValueError, "new input events"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_replay_exception_does_not_allow_missing_primary_tuple(self):
        _, observation, _ = self.replay_fixture()
        path = self.root / observation["reports"][0]["path"]
        report = json.loads(path.read_bytes())
        report["observed_environment_digest"] = None
        write(path, report)
        samples.update_references(self.manifest, path)
        with self.assertRaisesRegex(ValueError, "exact declared bundle tuple"):
            adapter.verify_subjects(
                self.manifest_path,
                self.manifest,
                self.mapping["admitted_subject"],
                self.mapping["repair_prior_subject"],
            )

    def test_reconciliation_cli_never_reads_keys_network_or_calls_issuer(self):
        plan = {
            "phase_request": request("receipt"),
            "issue_request": None,
            "inputs": self.prepare(),
            "unsigned_object": {"test_only": "result"},
        }
        state = self.root / "state"
        adapter.persist_once(plan, state, lambda _: plan["unsigned_object"])
        journal = next(state.glob("*.request.json"))
        with (
            mock.patch.object(
                adapter.software,
                "keychain_read",
                side_effect=AssertionError("key read"),
            ),
            mock.patch.object(
                adapter.verifier, "fetch", side_effect=AssertionError("network")
            ),
            mock.patch.object(
                adapter, "phase_object", side_effect=AssertionError("issuer")
            ),
        ):
            status = adapter.main(
                [
                    "--reconcile-journal",
                    str(journal),
                    "--state-dir",
                    str(state),
                    "--output",
                    str(self.root / "reconciled.json"),
                ]
            )
        self.assertEqual(status, 0)
        self.assertTrue(
            json.loads((self.root / "reconciled.json").read_bytes())["unsigned_result"]
        )

    def publication_fixture(self):
        fixture, context = trust_context()
        resolver = context["resolver"]
        admission = adapter.issuer.issue_workflow_admission(
            signed_samples.workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit="1" * 40,
            now=signed_samples.NOW,
            consumer=adapter.PreviewConsumer(),
        )
        signed_samples.flow_release_inputs(fixture, admission, resolver)
        template = next(
            v["value"]
            for v in resolver.objects.values()
            if v["value"].get("schema_version") == "openadapt.production-acceptance/v3"
        )
        staging = copy.deepcopy(template["publication_staging"])
        inputs = self.prepare()
        staging.update(
            publication_mode="already-published-pypi",
            draft=False,
            target_commitish=inputs["release"]["source_commit"],
            tag=inputs["release"]["tag"],
        )
        staging["assets"] = [
            {
                "asset_id": str(i + 30),
                **a,
                "uploader_id": "321543906",
                "uploader_login": "openadapt-release[bot]",
            }
            for i, a in enumerate(
                sorted(
                    inputs["artifact_inventory"]["artifacts"], key=lambda a: a["name"]
                )
            )
        ]
        staging["pypi_files"] = adapter.trust.pypi_files_from_assets(staging["assets"])
        staging["tag_ref_state"] = {"ref": "refs/tags/v1.35.1", "exists": True}
        staging["tag_ref_state_sha256"] = adapter.trust.digest_bytes(
            adapter.trust.TAG_REF_STATE_DOMAIN, staging["tag_ref_state"]
        )
        candidate = json.loads(
            (self.root / self.mapping["candidate"]["path"]).read_bytes()
        )
        files = {
            name: (self.root / ref["path"]).read_bytes()
            for name, ref in self.mapping["publication_files"].items()
        }
        repo = "repos/OpenAdaptAI/openadapt-flow"
        responses = {
            f"{repo}/releases/tags/v1.35.1": {
                "id": 20,
                "draft": False,
                "prerelease": False,
                "tag_name": "v1.35.1",
                "author": {"login": "openadapt-release[bot]"},
                "assets": [],
            },
            f"{repo}/git/ref/tags/v1.35.1": {
                "object": {"type": "commit", "sha": inputs["release"]["source_commit"]}
            },
            f"{repo}/immutable-releases": staging["immutable_releases"],
        }
        downloads = {}
        pypi = {"urls": []}
        for asset in staging["assets"]:
            name = asset["name"]
            github_url = f"https://github.com/OpenAdaptAI/openadapt-flow/releases/download/v1.35.1/{name}"
            pypi_url = f"https://files.pythonhosted.org/packages/{name}"
            responses[f"{repo}/releases/tags/v1.35.1"]["assets"].append(
                {
                    "name": name,
                    "id": int(asset["asset_id"]),
                    "size": asset["size_bytes"],
                    "state": "uploaded",
                    "digest": asset["sha256"],
                    "uploader": {
                        "login": asset["uploader_login"],
                        "id": int(asset["uploader_id"]),
                    },
                    "browser_download_url": github_url,
                }
            )
            pypi["urls"].append(
                {
                    "filename": name,
                    "size": asset["size_bytes"],
                    "yanked": False,
                    "digests": {"sha256": asset["sha256"].removeprefix("sha256:")},
                    "url": pypi_url,
                }
            )
            downloads[github_url] = downloads[pypi_url] = files[name]
        for rule in staging["tag_rulesets"]:
            responses[f"{repo}/rulesets/{rule['ruleset_id']}"] = {
                "id": int(rule["ruleset_id"]),
                **{
                    k: rule[k]
                    for k in (
                        "name",
                        "target",
                        "enforcement",
                        "conditions",
                        "rules",
                        "bypass_actors",
                    )
                },
            }
        downloads["https://pypi.org/pypi/openadapt-flow/1.35.1/json"] = (
            adapter.canonical(pypi)
        )
        return candidate, staging, files, responses, downloads

    def test_publication_checks_actual_bytes_from_both_publishers(self):
        candidate, staging, files, api, downloads = self.publication_fixture()
        adapter.verify_publication(
            candidate, staging, files, api=api.__getitem__, fetch=downloads.__getitem__
        )
        key = next(key for key in downloads if key.startswith("https://github.com/"))
        downloads[key] = b"wrong immutable content"
        with self.assertRaisesRegex(ValueError, "actual published artifact bytes"):
            adapter.verify_publication(
                candidate,
                staging,
                files,
                api=api.__getitem__,
                fetch=downloads.__getitem__,
            )

    def test_publication_rejects_unpublished_and_changed_tag_source(self):
        candidate, staging, files, api, downloads = self.publication_fixture()
        candidate["release_observation"]["published"] = False
        with self.assertRaisesRegex(ValueError, "unpublished"):
            adapter.verify_publication(
                candidate,
                staging,
                files,
                api=api.__getitem__,
                fetch=downloads.__getitem__,
            )
        candidate["release_observation"]["published"] = True
        api["repos/OpenAdaptAI/openadapt-flow/git/ref/tags/v1.35.1"]["object"][
            "sha"
        ] = "b" * 40
        with self.assertRaisesRegex(ValueError, "tag source"):
            adapter.verify_publication(
                candidate,
                staging,
                files,
                api=api.__getitem__,
                fetch=downloads.__getitem__,
            )

    def test_all_five_objects_use_existing_signers_issuers_and_real_storage_edges(self):
        inputs = self.prepare()
        fixture, context = trust_context()
        resolver = context["resolver"]
        value, _ = adapter.phase_object(inputs, request("receipt"), context)
        raw, _ = adapter.sign_pair(
            value,
            {"phase_request": request("receipt")},
            context,
            private_key=fixture["decision_key"],
        )
        fixture["receipt"] = json.loads(raw)
        receipt_ref, receipt_bundle = signed_samples.reference_pair(
            adapter.KINDS["receipt"], fixture["receipt"]
        )
        fixture["receipt_ref"], fixture["receipt_bundle_ref"] = (
            receipt_ref,
            receipt_bundle,
        )
        resolver.add(
            adapter.KINDS["receipt"], fixture["receipt"], receipt_ref, receipt_bundle
        )
        workflow_request = request("workflow", receipt=receipt_ref)
        workflow, _ = adapter.phase_object(inputs, workflow_request, context)
        # Existing fixtures supply policy-complete staging. This test replaces
        # every package artifact with the temporary byte-verified candidate.
        signed_samples.flow_release_inputs(fixture, workflow, resolver)
        template = next(
            v["value"]
            for v in resolver.objects.values()
            if v["value"].get("schema_version") == "openadapt.production-acceptance/v3"
        )
        staging = copy.deepcopy(template["publication_staging"])
        staging.update(
            publication_mode="already-published-pypi",
            draft=False,
            target_commitish=inputs["release"]["source_commit"],
            tag=inputs["release"]["tag"],
        )
        staging["assets"] = [
            {
                "asset_id": str(i + 30),
                **a,
                "uploader_id": "321543906",
                "uploader_login": "openadapt-release[bot]",
            }
            for i, a in enumerate(
                sorted(
                    inputs["artifact_inventory"]["artifacts"], key=lambda a: a["name"]
                )
            )
        ]
        staging["pypi_files"] = adapter.trust.pypi_files_from_assets(staging["assets"])
        staging["tag_ref_state"] = {"ref": "refs/tags/v1.35.1", "exists": True}
        staging["tag_ref_state_sha256"] = adapter.trust.digest_bytes(
            adapter.trust.TAG_REF_STATE_DOMAIN, staging["tag_ref_state"]
        )
        inputs["publication_staging"] = staging
        workflow_ref, workflow_bundle = signed_samples.reference_pair(
            adapter.KINDS["workflow"], workflow, registry_source_commit="2" * 40
        )
        resolver.add(adapter.KINDS["workflow"], workflow, workflow_ref, workflow_bundle)
        manifest_request = request(
            "manifest", receipt=receipt_ref, workflow=workflow_ref
        )
        manifest_request["acceptance_issuer_source_commit"] = "a" * 40
        with mock.patch.object(
            adapter, "gh", return_value={"object": {"sha": "a" * 40}}
        ):
            manifest, _ = adapter.phase_object(inputs, manifest_request, context)
        manifest_ref, manifest_bundle = signed_samples.reference_pair(
            adapter.KINDS["manifest"], manifest, registry_source_commit="3" * 40
        )
        resolver.add(adapter.KINDS["manifest"], manifest, manifest_ref, manifest_bundle)
        summary_request = request("summary", manifest=manifest_ref)
        summary, _ = adapter.phase_object(inputs, summary_request, context)
        summary_ref, summary_bundle = signed_samples.reference_pair(
            adapter.KINDS["summary"], summary, registry_source_commit="4" * 40
        )
        resolver.add(adapter.KINDS["summary"], summary, summary_ref, summary_bundle)
        release_request = request("release", source="4" * 40, summary=summary_ref)
        release, _ = adapter.phase_object(inputs, release_request, context)
        for phase, value, phase_request in (
            ("workflow", workflow, workflow_request),
            ("manifest", manifest, manifest_request),
            ("summary", summary, summary_request),
            ("release", release, release_request),
        ):
            raw, bundle = adapter.sign_pair(
                value,
                {"phase_request": phase_request},
                context,
                private_key=fixture["decision_key"],
            )
            self.assertTrue(json.loads(bundle)["dsseEnvelope"]["signatures"])
            self.assertEqual(json.loads(raw)["schema_version"], value["schema_version"])
        self.assertEqual(
            manifest["qualification_admission_reference"]["registry_source_commit"],
            "2" * 40,
        )
        self.assertEqual(
            summary["production_acceptance_manifest_reference"][
                "registry_source_commit"
            ],
            "3" * 40,
        )
        self.assertEqual(release["issuer"]["source_commit"], "4" * 40)
        self.assertEqual(release["release"], inputs["release"])
        with self.assertRaisesRegex(ValueError, "immediate issuer dependency"):
            adapter.phase_object(
                inputs,
                request("workflow", source="2" * 40, receipt=receipt_ref),
                context,
            )


if __name__ == "__main__":
    unittest.main()
