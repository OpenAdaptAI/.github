"""The review candidate binds counted trials to exact retained bytes."""

import importlib.util
import json
import io
import tarfile
import zipfile
from pathlib import Path
import tempfile
import unittest
from unittest import mock

_PATH = (
    Path(__file__).resolve().parents[1]
    / "local-candidates/flow-1.35.0-measured/prepare.py"
)
_SPEC = importlib.util.spec_from_file_location("measured_flow_candidate", _PATH)
assert _SPEC and _SPEC.loader
candidate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(candidate)
WHEEL = "sha256:" + "a" * 64


def manifest(tmp_path, *, wheel=None, version="1.35.0"):
    if wheel is None:
        wheel, _ = archives(tmp_path, version, version)
    digest = candidate.sha(wheel.read_bytes())
    artifacts = []

    def retain(path):
        reference = {
            "path": path.name,
            "sha256": candidate.sha(path.read_bytes()),
            "size_bytes": path.stat().st_size,
        }
        artifacts.append(reference)
        return reference

    wheel_reference = retain(wheel)
    with zipfile.ZipFile(wheel) as archive:
        members = [
            {
                "path": name,
                "size_bytes": len(archive.read(name)),
                "wheel_sha256": candidate.sha(archive.read(name)),
                "installed_sha256": candidate.sha(archive.read(name)),
            }
            for name in archive.namelist()
            if name.startswith("openadapt_flow/")
        ]
    proof_path = tmp_path / "installed.json"
    proof_path.write_text(
        json.dumps(
            {
                "schema_version": "openadapt.installed-distribution-proof/v1",
                "distribution": "openadapt-flow",
                "version": version,
                "wheel": wheel_reference,
                "members": members,
                "installed_extra_files": [],
                "all_members_match": True,
            }
        )
    )
    proof = retain(proof_path)
    normalizer_path = tmp_path / "normalizer.py"
    normalizer_path.write_text("# Explicit parser fixture; no execution claim\n")
    normalizer = retain(normalizer_path)
    trials = []
    for name in candidate.trust.CAMPAIGN_CLASSES:
        counters = dict.fromkeys(candidate.COUNTERS, 0)
        if name == "uncertain_delivery":
            counters["reconciliation_required_count"] = 1
        if name == "declared_attended":
            counters["authenticated_bound_decision_count"] = 1
            counters["live_target_revalidation_count"] = 1
        if name == "governed_repair":
            for field in (
                "policy_approved_repair_count",
                "approved_repair_count",
                "retained_repair_evidence_count",
                "live_target_revalidation_count",
            ):
                counters[field] = 1
        for trial in range(3):
            success = name not in {"safe_halt", "uncertain_delivery"}
            report = {
                "fixture": True,
                "trial_identity": [name, trial],
                "success": success,
                "transaction_outcome": "VERIFIED"
                if success
                else "RECONCILIATION_REQUIRED",
                "model_calls": 0,
            }
            report_path = tmp_path / f"{name}-{trial}-report.json"
            report_path.write_text(json.dumps(report))
            report_reference = retain(report_path)
            observed = {
                "schema_version": "openadapt.observed-release-trial/v1",
                "class": name,
                "task_id": "test-fixture",
                "condition": "one",
                "trial": trial,
                "counters": counters.copy(),
                "runtime": {
                    "version": version,
                    "wheel_sha256": digest,
                    "installed_distribution_proof": proof,
                },
                "reports": [
                    {
                        **report_reference,
                        "role": "primary",
                        **{
                            k: report[k]
                            for k in ("success", "transaction_outcome", "model_calls")
                        },
                    }
                ],
                "verification_references": [
                    {**report_reference, "role": "explicit-parser-fixture"}
                ],
            }
            path = tmp_path / f"{name}-{trial}.json"
            path.write_text(json.dumps(observed))
            reference = retain(path)
            trials.append(
                {
                    "class": name,
                    "task_id": "test-fixture",
                    "condition": "one",
                    "trial": trial,
                    "runtime_version": version,
                    "observation": reference,
                    "artifacts": [reference, report_reference],
                    "counters": counters.copy(),
                }
            )
    value = {
        "schema_version": "openadapt.measured-release-evidence/v1",
        "evidence_class": "remote-safe-synthetic",
        "runtime": {"version": version, "wheel_sha256": digest},
        "normalizer": normalizer,
        "artifacts": artifacts,
        "trials": trials,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value))
    return (path, value)


def archives(tmp_path, wheel_version="1.35.1", sdist_version="1.35.1"):
    wheel = tmp_path / "candidate.whl"
    sdist = tmp_path / "candidate.tar.gz"
    with zipfile.ZipFile(wheel, "w") as output:
        output.writestr(
            "openadapt_flow/__init__.py", f'__version__ = "{wheel_version}"\n'
        )
        output.writestr(
            "openadapt_flow.dist-info/METADATA",
            f"Name: openadapt-flow\nVersion: {wheel_version}\n",
        )
    metadata = f"Name: openadapt-flow\nVersion: {sdist_version}\n".encode()
    with tarfile.open(sdist, "w:gz") as output:
        member = tarfile.TarInfo("openadapt_flow/PKG-INFO")
        member.size = len(metadata)
        output.addfile(member, io.BytesIO(metadata))
    return (wheel, sdist)


def update_references(value, path):
    """Rehash a deliberately modified fixture without hiding semantic changes."""
    digest = candidate.sha(path.read_bytes())

    def walk(node):
        if isinstance(node, dict):
            if node.get("path") == path.name:
                node["sha256"] = digest
                if "size_bytes" in node:
                    node["size_bytes"] = path.stat().st_size
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)


class MeasuredFlowCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp_path = Path(temporary.name)

    def test_counts_derive_from_unique_observed_trials(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        summary, evidence = candidate.summarize(path, value["runtime"]["wheel_sha256"])
        assert evidence["trial_count"] == 18
        assert evidence["manifest_sha256"] == candidate.sha(path.read_bytes())
        assert summary["governed_repair"]["approved_repair_count"] == 3
        assert summary["healthy"]["minimum_trials_per_cell"] == 3

    def _check_incomplete_or_unsafe_evidence_refuses(self, mutation):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        wheel_digest = value["runtime"]["wheel_sha256"]
        mutation(value)
        path.write_text(json.dumps(value))
        with self.assertRaises((ValueError, candidate.trust.TrustError)):
            candidate.summarize(path, wheel_digest)

    def test_incomplete_or_unsafe_evidence_refuses_0(self):
        self._check_incomplete_or_unsafe_evidence_refuses(lambda m: m["trials"].pop())

    def test_incomplete_or_unsafe_evidence_refuses_1(self):
        self._check_incomplete_or_unsafe_evidence_refuses(
            lambda m: m["trials"].append(m["trials"][0])
        )

    def test_incomplete_or_unsafe_evidence_refuses_2(self):
        self._check_incomplete_or_unsafe_evidence_refuses(
            lambda m: m["trials"][0]["counters"].pop("silent_incorrect_success_count")
        )

    def test_incomplete_or_unsafe_evidence_refuses_3(self):
        self._check_incomplete_or_unsafe_evidence_refuses(
            lambda m: m["trials"][0]["counters"].update(
                silent_incorrect_success_count=1
            )
        )

    def test_incomplete_or_unsafe_evidence_refuses_4(self):
        self._check_incomplete_or_unsafe_evidence_refuses(
            lambda m: m["runtime"].update(wheel_sha256="sha256:" + "b" * 64)
        )

    def test_incomplete_or_unsafe_evidence_refuses_5(self):
        self._check_incomplete_or_unsafe_evidence_refuses(
            lambda m: m["trials"][0]["artifacts"].clear()
        )

    def test_changed_artifact_bytes_refuse(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        (tmp_path / "healthy-0.json").write_text("changed")
        with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_reused_observation_cannot_count_as_another_trial(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        value["trials"][1]["artifacts"] = value["trials"][0]["artifacts"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "unique observed evidence"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_incomplete_input_writes_refusal_candidate(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        value["scope"] = "Explicit test fixture; no execution claim"
        value["limitations"] = ["Two classes were not measured"]
        value["trials"] = [
            t
            for t in value["trials"]
            if t["class"] not in {"declared_attended", "governed_repair"}
        ]
        path.write_text(json.dumps(value))
        self.enterContext(
            mock.patch.object(
                candidate,
                "observe_release",
                lambda: {
                    "artifacts": [
                        {
                            "kind": "python-wheel",
                            "sha256": value["runtime"]["wheel_sha256"],
                        }
                    ]
                },
            )
        )
        output = tmp_path / "candidate.json"
        self.enterContext(
            mock.patch.object(
                candidate.sys,
                "argv",
                ["prepare.py", "--measured-manifest", str(path), "--out", str(output)],
            )
        )
        assert candidate.main() == 1
        result = json.loads(output.read_text())
        assert result["state"] == "evidence-incomplete"
        assert result["admission_issued"] is False
        assert "declared_attended, governed_repair" in result["validation_errors"][0]
        assert result["limitations"] == value["limitations"]

    def _check_wrong_unpublished_package_versions_refuse(self, versions):
        tmp_path = self.tmp_path
        wheel, sdist = archives(tmp_path, *versions)
        with self.assertRaises(ValueError):
            candidate.observe_unpublished(wheel, sdist, "c" * 40)

    def test_wrong_unpublished_package_versions_refuse_0(self):
        self._check_wrong_unpublished_package_versions_refuse(("1.35.1", "1.35.0"))

    def test_wrong_unpublished_package_versions_refuse_1(self):
        self._check_wrong_unpublished_package_versions_refuse(("1.35.0", "1.35.0"))

    def test_unpublished_candidate_cannot_assert_admission_or_publication(self):
        tmp_path = self.tmp_path
        wheel, sdist = archives(tmp_path)
        path, value = manifest(tmp_path, wheel=wheel, version="1.35.1")
        value.update(
            candidate_ready=True, scope="Explicit test fixture; no execution claim"
        )
        value["runtime"] = {
            "version": "1.35.1",
            "wheel_sha256": candidate.sha(wheel.read_bytes()),
        }
        for trial in value["trials"]:
            trial["runtime_version"] = "1.35.1"
        path.write_text(json.dumps(value))
        output = tmp_path / "candidate.json"
        self.enterContext(
            mock.patch.object(
                candidate.sys,
                "argv",
                [
                    "prepare.py",
                    "--measured-manifest",
                    str(path),
                    "--out",
                    str(output),
                    "--unpublished-wheel",
                    str(wheel),
                    "--unpublished-sdist",
                    str(sdist),
                    "--source-commit",
                    "c" * 40,
                ],
            )
        )
        assert candidate.main() == 0
        result = json.loads(output.read_text())
        assert result["state"] == "ready-for-release-review"
        assert result["admission_issued"] is False
        assert result["release_observation"]["published"] is False
        assert result["release_observation"]["source_commit"] == "c" * 40
        assert len(result["release_observation"]["required_external_gates"]) == 4
        assert result["measured_evidence"]["trial_count"] == 18

    def test_partial_unpublished_inputs_refuse_before_network_observation(self):
        tmp_path = self.tmp_path
        self.enterContext(
            mock.patch.object(
                candidate.sys,
                "argv",
                [
                    "prepare.py",
                    "--out",
                    str(tmp_path / "out.json"),
                    "--unpublished-wheel",
                    str(tmp_path / "candidate.whl"),
                ],
            )
        )
        self.enterContext(
            mock.patch.object(
                candidate,
                "observe_release",
                lambda: self.fail("unexpected network request"),
            )
        )
        with self.assertRaises(SystemExit) as error:
            candidate.main()
        assert error.exception.code == 2

    def test_rehashed_observation_cannot_relabel_a_failed_trial(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        observed_path = tmp_path / "healthy-0.json"
        observed = json.loads(observed_path.read_text())
        observed["class"] = "safe_halt"
        observed["counters"]["unsafe_effect_count"] = 1
        observed_path.write_text(json.dumps(observed))
        update_references(value, observed_path)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "retained observation differs"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def _check_class_events_cannot_be_concentrated_in_one_trial(
        self, class_name, field
    ):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        selected = [trial for trial in value["trials"] if trial["class"] == class_name]
        for trial, count in zip(selected, [3, 0, 0]):
            trial["counters"][field] = count
            observed_path = tmp_path / trial["observation"]["path"]
            observed = json.loads(observed_path.read_text())
            observed["counters"][field] = count
            observed_path.write_text(json.dumps(observed))
            update_references(value, observed_path)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "each trial must satisfy"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_class_events_cannot_be_concentrated_in_one_trial_0(self):
        self._check_class_events_cannot_be_concentrated_in_one_trial(
            "uncertain_delivery", "reconciliation_required_count"
        )

    def test_class_events_cannot_be_concentrated_in_one_trial_1(self):
        self._check_class_events_cannot_be_concentrated_in_one_trial(
            "declared_attended", "authenticated_bound_decision_count"
        )

    def test_class_events_cannot_be_concentrated_in_one_trial_2(self):
        self._check_class_events_cannot_be_concentrated_in_one_trial(
            "governed_repair", "approved_repair_count"
        )

    def test_attended_decision_completion_cannot_replace_native_verified_effect(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        report_path = tmp_path / "declared_attended-0-report.json"
        report = json.loads(report_path.read_text())
        report.update(
            success=False,
            transaction_outcome="COMPLETED_UNVERIFIED",
            report_success=True,
        )
        report_path.write_text(json.dumps(report))
        update_references(value, report_path)
        observed_path = tmp_path / "declared_attended-0.json"
        observed = json.loads(observed_path.read_text())
        update_references(observed, report_path)
        observed["reports"][0].update(
            success=False, transaction_outcome="COMPLETED_UNVERIFIED"
        )
        observed_path.write_text(json.dumps(observed))
        update_references(value, observed_path)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "primary native outcome"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_rehashed_native_report_must_match_normalized_claim(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        report_path = tmp_path / "healthy-0-report.json"
        report = json.loads(report_path.read_text())
        report["model_calls"] = 9
        report_path.write_text(json.dumps(report))
        update_references(value, report_path)
        observed_path = tmp_path / "healthy-0.json"
        observed = json.loads(observed_path.read_text())
        update_references(observed, report_path)
        observed_path.write_text(json.dumps(observed))
        update_references(value, observed_path)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(
            ValueError, "native report differs from observed model_calls"
        ):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_installed_proof_cannot_omit_a_wheel_member(self):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        proof_path = tmp_path / "installed.json"
        proof = json.loads(proof_path.read_text())
        proof["members"] = []
        proof_path.write_text(json.dumps(proof))
        update_references(value, proof_path)
        for trial in value["trials"]:
            observed_path = tmp_path / trial["observation"]["path"]
            observed = json.loads(observed_path.read_text())
            update_references(observed, proof_path)
            observed_path.write_text(json.dumps(observed))
            update_references(value, observed_path)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(
            ValueError, "installed member proof does not cover"
        ):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def _check_missing_or_empty_normalizer_reference_refuses(self, reference):
        tmp_path = self.tmp_path
        path, value = manifest(tmp_path)
        if reference is None:
            value.pop("normalizer")
        else:
            value["normalizer"] = reference
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "measurement normalizer is absent"):
            candidate.summarize(path, value["runtime"]["wheel_sha256"])

    def test_missing_or_empty_normalizer_reference_refuses_0(self):
        self._check_missing_or_empty_normalizer_reference_refuses(None)

    def test_missing_or_empty_normalizer_reference_refuses_1(self):
        self._check_missing_or_empty_normalizer_reference_refuses({})

    def test_missing_or_empty_normalizer_reference_refuses_2(self):
        self._check_missing_or_empty_normalizer_reference_refuses(
            {"path": "", "sha256": ""}
        )
