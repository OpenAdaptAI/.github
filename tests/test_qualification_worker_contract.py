"""Tests for the qualification worker terminal authority contract."""

from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualification_worker_contract as worker


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def admission() -> dict:
    return {
        "admission_id_sha256": sha("admission"),
        "provider_identity_sha256": sha("provider"),
        "worker_identity_sha256": sha("worker"),
        "live_provider_observation_sha256": sha("observation"),
        "admitted_runtime_sha256": sha("runtime"),
        "host_identity_sha256": sha("host"),
        "capability_handle_sha256": sha("capability"),
    }


def dispatch() -> dict:
    return {
        "dispatch_id_sha256": sha("dispatch"),
        "worker_admission_sha256": sha("admission"),
        "provider_identity_sha256": sha("provider"),
        "worker_identity_sha256": sha("worker"),
        "live_provider_observation_sha256": sha("observation"),
        "admitted_runtime_sha256": sha("runtime"),
        "run_id": "100",
        "run_attempt": "1",
        "start_id_sha256": sha("start"),
        "task_id_sha256": sha("task"),
        "task_condition_sha256": sha("condition"),
        "capability_handle_sha256": sha("capability"),
    }


def terminal(*, process: bool = True) -> dict:
    value = {
        "schema_version": worker.TERMINAL_SCHEMA,
        "receipt_id_sha256": sha("pending"),
        "worker_admission_sha256": sha("admission"),
        "dispatch_id_sha256": sha("dispatch"),
        "provider_identity_sha256": sha("provider"),
        "worker_identity_sha256": sha("worker"),
        "live_provider_observation_sha256": sha("observation"),
        "admitted_runtime_sha256": sha("runtime"),
        "run_id": "100",
        "run_attempt": "1",
        "start_id_sha256": sha("start"),
        "task_id_sha256": sha("task"),
        "task_condition_sha256": sha("condition"),
        "capability_handle_sha256": sha("capability"),
        "launch_attempt": {
            "attempted_at": "2026-08-27T11:59:59Z",
            "host_identity_sha256": sha("host"),
            "executable_sha256": sha("executable"),
            "capability_handle_sha256": sha("capability"),
            "evidence_sha256": sha("launch-evidence"),
            "failure_classification": "PROCESS_START_FAILED" if not process else None,
        },
        "launch_attempt_sha256": sha("pending-launch"),
        "process": None,
        "oracle_sha256": sha("oracle"),
        "result_sha256": sha("result"),
        "log_sha256": sha("log"),
        "burned_identities_sha256": sha("burned"),
        "burn_ledger_revision": 7,
        "burn_receipt_sha256": sha("burn-receipt"),
        "burned_at": "2026-08-27T12:01:00Z",
        "ledger_readback_sha256": sha("readback"),
        "effect_started": False,
        "delivery_state": "not_started",
        "terminal_state": "SAFE_HALT" if process else "PRELAUNCH_QUARANTINED",
        "exit_code": None,
        "uncertainty_sha256": None,
        "quarantine": {
            "active": True,
            "reason_code": "PROCESS_START_FAILED" if not process else "SAFE_HALT",
            "evidence_sha256": sha("quarantine"),
        },
        "completed_at": "2026-08-27T12:01:01Z",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-qualification-worker-terminal-receipt.yml",
            "ref": "refs/heads/main",
            "source_commit": "a" * 40,
            "environment": "qualification-worker-terminal-receipt",
        },
    }
    if process:
        value["process"] = {
            "pid": 4242,
            "process_group_id": 4242,
            "process_start_ticks": "987654321",
            "launched_at": "2026-08-27T12:00:00Z",
            "executable_sha256": sha("executable"),
            "process_start_identity_sha256": sha("pending-process"),
        }
        value["process"]["process_start_identity_sha256"] = worker.digest(
            worker.PROCESS_START_DOMAIN, worker.process_start_projection(value)
        )
    value["launch_attempt_sha256"] = worker.digest(
        worker.LAUNCH_ATTEMPT_DOMAIN, worker.launch_attempt_projection(value)
    )
    value["receipt_id_sha256"] = worker.digest(
        worker.TERMINAL_RECEIPT_DOMAIN, worker.terminal_receipt_projection(value)
    )
    return value


def refresh(value: dict) -> None:
    if value["process"] is not None:
        value["process"]["process_start_identity_sha256"] = worker.digest(
            worker.PROCESS_START_DOMAIN, worker.process_start_projection(value)
        )
    value["launch_attempt_sha256"] = worker.digest(
        worker.LAUNCH_ATTEMPT_DOMAIN, worker.launch_attempt_projection(value)
    )
    value["receipt_id_sha256"] = worker.digest(
        worker.TERMINAL_RECEIPT_DOMAIN, worker.terminal_receipt_projection(value)
    )


class QualificationWorkerContractTests(unittest.TestCase):
    def test_terminal_binds_admission_dispatch_and_kernel_process_generation(self) -> None:
        value = terminal()
        self.assertEqual(
            worker.validate_terminal_bindings(
                value, admission=admission(), dispatch=dispatch()
            ),
            value,
        )
        self.assertEqual(value["process"]["process_start_ticks"], "987654321")

    def test_pid_reuse_or_process_start_tick_tamper_is_refused(self) -> None:
        original = terminal()
        tampered = copy.deepcopy(original)
        tampered["process"]["process_start_ticks"] = "987654322"
        with self.assertRaisesRegex(
            worker.QualificationWorkerContractError, "process start identity"
        ):
            worker.validate_terminal_receipt(tampered)

        conflicting = copy.deepcopy(original)
        conflicting["process"]["process_start_ticks"] = "987654322"
        refresh(conflicting)
        worker.validate_terminal_receipt(conflicting)
        with self.assertRaisesRegex(
            worker.QualificationWorkerContractError, "conflicting terminal"
        ):
            worker.validate_terminal_replay(original, conflicting)

    def test_prelaunch_failure_is_a_bound_quarantined_terminal_receipt(self) -> None:
        value = terminal(process=False)
        self.assertEqual(worker.validate_terminal_receipt(value), value)
        changed = copy.deepcopy(value)
        changed["quarantine"]["active"] = False
        refresh(changed)
        with self.assertRaisesRegex(
            worker.QualificationWorkerContractError, "prelaunch terminal"
        ):
            worker.validate_terminal_receipt(changed)

    def test_cross_contract_identity_drift_is_refused(self) -> None:
        changed_dispatch = dispatch()
        changed_dispatch["live_provider_observation_sha256"] = sha("other")
        with self.assertRaisesRegex(
            worker.QualificationWorkerContractError,
            "live_provider_observation_sha256 differs",
        ):
            worker.validate_terminal_bindings(
                terminal(), admission=admission(), dispatch=changed_dispatch
            )


if __name__ == "__main__":
    unittest.main()
