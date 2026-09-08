"""The review candidate binds counted trials to exact retained bytes."""

import importlib.util
import json
from pathlib import Path

import pytest

_PATH = (
    Path(__file__).resolve().parents[1]
    / "local-candidates/flow-1.35.0-measured/prepare.py"
)
_SPEC = importlib.util.spec_from_file_location("measured_flow_candidate", _PATH)
assert _SPEC and _SPEC.loader
candidate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(candidate)
WHEEL = "sha256:" + "a" * 64


def manifest(tmp_path):
    artifact = tmp_path / "observed.json"
    artifact.write_text('{"fixture":true}\n')
    digest = candidate.sha(artifact.read_bytes())
    trials = []
    artifacts = []
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
            artifact = tmp_path / f"{name}-{trial}.json"
            artifact.write_text(
                json.dumps({"fixture": True, "class": name, "trial": trial})
            )
            digest = candidate.sha(artifact.read_bytes())
            artifacts.append(
                {
                    "path": artifact.name,
                    "sha256": digest,
                    "size_bytes": artifact.stat().st_size,
                }
            )
            trials.append(
                {
                    "class": name,
                    "task_id": "test-fixture",
                    "condition": "one",
                    "trial": trial,
                    "runtime_version": candidate.VERSION,
                    "artifacts": [{"path": artifact.name, "sha256": digest}],
                    "counters": counters.copy(),
                }
            )
    value = {
        "schema_version": "openadapt.measured-release-evidence/v1",
        "evidence_class": "remote-safe-synthetic",
        "runtime": {"version": candidate.VERSION, "wheel_sha256": WHEEL},
        "artifacts": artifacts,
        "trials": trials,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value))
    return path, value


def test_counts_derive_from_unique_observed_trials(tmp_path):
    path, _ = manifest(tmp_path)
    summary, evidence = candidate.summarize(path, WHEEL)
    assert evidence["trial_count"] == 18
    assert evidence["manifest_sha256"] == candidate.sha(path.read_bytes())
    assert summary["governed_repair"]["approved_repair_count"] == 3
    assert summary["healthy"]["minimum_trials_per_cell"] == 3


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: m["trials"].pop(),
        lambda m: m["trials"].append(m["trials"][0]),
        lambda m: m["trials"][0]["counters"].pop("silent_incorrect_success_count"),
        lambda m: m["trials"][0]["counters"].update(silent_incorrect_success_count=1),
        lambda m: m["runtime"].update(wheel_sha256="sha256:" + "b" * 64),
        lambda m: m["trials"][0]["artifacts"].clear(),
    ],
)
def test_incomplete_or_unsafe_evidence_refuses(tmp_path, mutation):
    path, value = manifest(tmp_path)
    mutation(value)
    path.write_text(json.dumps(value))
    with pytest.raises((ValueError, candidate.trust.TrustError)):
        candidate.summarize(path, WHEEL)


def test_changed_artifact_bytes_refuse(tmp_path):
    path, _ = manifest(tmp_path)
    (tmp_path / "healthy-0.json").write_text("changed")
    with pytest.raises(ValueError, match="artifact bytes differ"):
        candidate.summarize(path, WHEEL)


def test_reused_observation_cannot_count_as_another_trial(tmp_path):
    path, value = manifest(tmp_path)
    value["trials"][1]["artifacts"] = value["trials"][0]["artifacts"]
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="unique observed evidence"):
        candidate.summarize(path, WHEEL)


def test_incomplete_input_writes_refusal_candidate(tmp_path, monkeypatch):
    path, value = manifest(tmp_path)
    value["scope"] = "Explicit test fixture; no execution claim"
    value["limitations"] = ["Two classes were not measured"]
    value["trials"] = [
        t
        for t in value["trials"]
        if t["class"] not in {"declared_attended", "governed_repair"}
    ]
    path.write_text(json.dumps(value))
    monkeypatch.setattr(
        candidate,
        "observe_release",
        lambda: {"artifacts": [{"kind": "python-wheel", "sha256": WHEEL}]},
    )
    output = tmp_path / "candidate.json"
    monkeypatch.setattr(
        candidate.sys,
        "argv",
        ["prepare.py", "--measured-manifest", str(path), "--out", str(output)],
    )
    assert candidate.main() == 1
    result = json.loads(output.read_text())
    assert result["state"] == "evidence-incomplete"
    assert result["admission_issued"] is False
    assert "declared_attended, governed_repair" in result["validation_errors"][0]
    assert result["limitations"] == value["limitations"]
