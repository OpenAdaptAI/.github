"""Validate the remote-safe qualification worker terminal contract."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

PROCESS_START_DOMAIN = b"OpenAdapt qualification worker process start v1\0"
LAUNCH_ATTEMPT_DOMAIN = b"OpenAdapt qualification worker launch attempt v1\0"
TERMINAL_RECEIPT_DOMAIN = b"OpenAdapt qualification worker terminal receipt v1\0"
TERMINAL_SCHEMA = "openadapt.qualification-worker-terminal-receipt/v1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DECIMAL = re.compile(r"^[1-9][0-9]*$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
TERMINAL_FIELDS = {
    "schema_version",
    "receipt_id_sha256",
    "worker_admission_sha256",
    "dispatch_id_sha256",
    "provider_identity_sha256",
    "worker_identity_sha256",
    "live_provider_observation_sha256",
    "admitted_runtime_sha256",
    "run_id",
    "run_attempt",
    "start_id_sha256",
    "task_id_sha256",
    "task_condition_sha256",
    "capability_handle_sha256",
    "launch_attempt",
    "launch_attempt_sha256",
    "process",
    "oracle_sha256",
    "result_sha256",
    "log_sha256",
    "burned_identities_sha256",
    "burn_ledger_revision",
    "burn_receipt_sha256",
    "burned_at",
    "ledger_readback_sha256",
    "effect_started",
    "delivery_state",
    "terminal_state",
    "exit_code",
    "uncertainty_sha256",
    "quarantine",
    "completed_at",
    "issuer",
}
PROCESS_FIELDS = {
    "pid",
    "process_group_id",
    "process_start_ticks",
    "launched_at",
    "executable_sha256",
    "process_start_identity_sha256",
}
LAUNCH_ATTEMPT_FIELDS = {
    "attempted_at",
    "host_identity_sha256",
    "executable_sha256",
    "capability_handle_sha256",
    "evidence_sha256",
    "failure_classification",
}
ISSUER_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "source_commit",
    "environment",
}


class QualificationWorkerContractError(ValueError):
    """The worker terminal receipt or replay is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(domain: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + canonical(value)).hexdigest()


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise QualificationWorkerContractError(
            f"{label} must contain exactly {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise QualificationWorkerContractError(
            f"{label} must be a lowercase sha256 digest"
        )
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise QualificationWorkerContractError(f"{label} is not an exact UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise QualificationWorkerContractError(
            f"{label} is not a calendar time"
        ) from exc


def process_start_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    process = receipt["process"]
    return {
        "provider_identity_sha256": receipt["provider_identity_sha256"],
        "worker_identity_sha256": receipt["worker_identity_sha256"],
        "live_provider_observation_sha256": receipt[
            "live_provider_observation_sha256"
        ],
        "admitted_runtime_sha256": receipt["admitted_runtime_sha256"],
        "run_id": receipt["run_id"],
        "run_attempt": receipt["run_attempt"],
        "start_id_sha256": receipt["start_id_sha256"],
        "dispatch_id_sha256": receipt["dispatch_id_sha256"],
        "pid": process["pid"],
        "process_group_id": process["process_group_id"],
        "process_start_ticks": process["process_start_ticks"],
        "launched_at": process["launched_at"],
        "executable_sha256": process["executable_sha256"],
    }


def launch_attempt_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "worker_admission_sha256": receipt["worker_admission_sha256"],
        "dispatch_id_sha256": receipt["dispatch_id_sha256"],
        "provider_identity_sha256": receipt["provider_identity_sha256"],
        "worker_identity_sha256": receipt["worker_identity_sha256"],
        "live_provider_observation_sha256": receipt[
            "live_provider_observation_sha256"
        ],
        "admitted_runtime_sha256": receipt["admitted_runtime_sha256"],
        "run_id": receipt["run_id"],
        "run_attempt": receipt["run_attempt"],
        "start_id_sha256": receipt["start_id_sha256"],
        "capability_handle_sha256": receipt["capability_handle_sha256"],
        "launch_attempt": receipt["launch_attempt"],
    }


def terminal_receipt_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    projection = dict(receipt)
    projection.pop("receipt_id_sha256", None)
    return projection


def validate_terminal_receipt(value: Any) -> dict[str, Any]:
    receipt = _closed(value, TERMINAL_FIELDS, "worker terminal receipt")
    if receipt["schema_version"] != TERMINAL_SCHEMA:
        raise QualificationWorkerContractError("terminal receipt schema is invalid")
    if receipt["run_attempt"] != "1" or not isinstance(receipt["run_id"], str) or DECIMAL.fullmatch(receipt["run_id"]) is None:
        raise QualificationWorkerContractError("terminal receipt run identity is invalid")
    for field in (
        "receipt_id_sha256",
        "worker_admission_sha256",
        "dispatch_id_sha256",
        "provider_identity_sha256",
        "worker_identity_sha256",
        "live_provider_observation_sha256",
        "admitted_runtime_sha256",
        "start_id_sha256",
        "task_id_sha256",
        "task_condition_sha256",
        "capability_handle_sha256",
        "launch_attempt_sha256",
        "oracle_sha256",
        "result_sha256",
        "log_sha256",
        "burned_identities_sha256",
        "burn_receipt_sha256",
        "ledger_readback_sha256",
    ):
        _digest(receipt[field], field)
    launch_attempt = _closed(
        receipt["launch_attempt"], LAUNCH_ATTEMPT_FIELDS, "worker launch attempt"
    )
    attempted_at = _timestamp(launch_attempt["attempted_at"], "launch attempted_at")
    for field in (
        "host_identity_sha256",
        "executable_sha256",
        "capability_handle_sha256",
        "evidence_sha256",
    ):
        _digest(launch_attempt[field], f"launch attempt {field}")
    if launch_attempt["capability_handle_sha256"] != receipt["capability_handle_sha256"]:
        raise QualificationWorkerContractError(
            "launch attempt capability differs from the terminal receipt"
        )
    if receipt["launch_attempt_sha256"] != digest(
        LAUNCH_ATTEMPT_DOMAIN, launch_attempt_projection(receipt)
    ):
        raise QualificationWorkerContractError("worker launch attempt identity differs")
    process_value = receipt["process"]
    process: dict[str, Any] | None
    if process_value is None:
        process = None
    else:
        process = _closed(process_value, PROCESS_FIELDS, "worker process")
        for field in ("pid", "process_group_id"):
            if (
                not isinstance(process[field], int)
                or isinstance(process[field], bool)
                or process[field] < 1
            ):
                raise QualificationWorkerContractError(
                    f"worker process {field} is invalid"
                )
        if (
            not isinstance(process["process_start_ticks"], str)
            or DECIMAL.fullmatch(process["process_start_ticks"]) is None
        ):
            raise QualificationWorkerContractError(
                "worker process start ticks are invalid"
            )
        _timestamp(process["launched_at"], "worker process launched_at")
        _digest(process["executable_sha256"], "worker process executable")
        _digest(process["process_start_identity_sha256"], "worker process identity")
        if process["process_start_identity_sha256"] != digest(
            PROCESS_START_DOMAIN, process_start_projection(receipt)
        ):
            raise QualificationWorkerContractError(
                "worker process start identity differs"
            )
    if not isinstance(receipt["burn_ledger_revision"], int) or isinstance(receipt["burn_ledger_revision"], bool) or receipt["burn_ledger_revision"] < 1:
        raise QualificationWorkerContractError("burn ledger revision is invalid")
    burned_at = _timestamp(receipt["burned_at"], "burned_at")
    completed_at = _timestamp(receipt["completed_at"], "completed_at")
    if process is not None:
        launched_at = _timestamp(process["launched_at"], "launched_at")
        if (
            launch_attempt["failure_classification"] is not None
            or launch_attempt["executable_sha256"] != process["executable_sha256"]
            or not attempted_at <= launched_at
        ):
            raise QualificationWorkerContractError(
                "completed process differs from its launch attempt"
            )
        earliest = launched_at
    else:
        earliest = attempted_at
    if not earliest <= burned_at <= completed_at:
        raise QualificationWorkerContractError("terminal receipt time order is invalid")
    if not isinstance(receipt["effect_started"], bool):
        raise QualificationWorkerContractError("effect_started must be boolean")
    if receipt["delivery_state"] not in {"not_started", "verified", "uncertain"}:
        raise QualificationWorkerContractError("delivery state is invalid")
    if receipt["terminal_state"] not in {
        "VERIFIED",
        "SAFE_HALT",
        "RECONCILIATION_REQUIRED",
        "QUARANTINED",
        "PRELAUNCH_QUARANTINED",
    }:
        raise QualificationWorkerContractError("terminal state is invalid")
    quarantine = _closed(
        receipt["quarantine"],
        {"active", "reason_code", "evidence_sha256"},
        "worker quarantine",
    )
    if not isinstance(quarantine["active"], bool):
        raise QualificationWorkerContractError("quarantine active must be boolean")
    if process is None:
        if (
            receipt["effect_started"]
            or receipt["delivery_state"] != "not_started"
            or receipt["terminal_state"] != "PRELAUNCH_QUARANTINED"
            or receipt["uncertainty_sha256"] is not None
            or not quarantine["active"]
            or not isinstance(quarantine["reason_code"], str)
            or launch_attempt["failure_classification"]
            not in {
                "PROCESS_START_REFUSED",
                "PROCESS_START_FAILED",
                "PROCESS_IDENTITY_UNAVAILABLE",
            }
            or quarantine["reason_code"]
            != launch_attempt["failure_classification"]
        ):
            raise QualificationWorkerContractError(
                "a prelaunch terminal receipt must quarantine without an effect"
            )
        _digest(quarantine["evidence_sha256"], "prelaunch quarantine evidence")
    if receipt["delivery_state"] == "uncertain":
        _digest(receipt["uncertainty_sha256"], "uncertainty")
        if (
            not receipt["effect_started"]
            or receipt["terminal_state"]
            not in {"RECONCILIATION_REQUIRED", "QUARANTINED"}
            or not quarantine["active"]
        ):
            raise QualificationWorkerContractError(
                "uncertain delivery must quarantine and require reconciliation"
            )
    if receipt["terminal_state"] == "VERIFIED" and (
        receipt["delivery_state"] != "verified"
        or receipt["uncertainty_sha256"] is not None
    ):
        raise QualificationWorkerContractError("VERIFIED terminal receipt is invalid")
    if receipt["terminal_state"] == "SAFE_HALT" and (
        receipt["effect_started"]
        or receipt["delivery_state"] != "not_started"
        or receipt["uncertainty_sha256"] is not None
    ):
        raise QualificationWorkerContractError("SAFE_HALT terminal receipt is invalid")
    issuer = _closed(receipt["issuer"], ISSUER_FIELDS, "terminal issuer")
    expected_issuer = {
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "workflow": ".github/workflows/issue-qualification-worker-terminal-receipt.yml",
        "ref": "refs/heads/main",
        "environment": "qualification-worker-terminal-receipt",
    }
    for field, expected in expected_issuer.items():
        if issuer[field] != expected:
            raise QualificationWorkerContractError("terminal issuer identity differs")
    if not isinstance(issuer["source_commit"], str) or re.fullmatch(r"[0-9a-f]{40}", issuer["source_commit"]) is None:
        raise QualificationWorkerContractError("terminal issuer commit is invalid")
    if receipt["receipt_id_sha256"] != digest(
        TERMINAL_RECEIPT_DOMAIN, terminal_receipt_projection(receipt)
    ):
        raise QualificationWorkerContractError("terminal receipt identity differs")
    return receipt


def validate_terminal_replay(previous_value: Any, current_value: Any) -> dict[str, Any]:
    previous = validate_terminal_receipt(previous_value)
    current = validate_terminal_receipt(current_value)
    if canonical(previous) == canonical(current):
        return current
    previous_dispatch = (
        previous["worker_admission_sha256"],
        previous["dispatch_id_sha256"],
        previous["run_id"],
        previous["start_id_sha256"],
    )
    current_dispatch = (
        current["worker_admission_sha256"],
        current["dispatch_id_sha256"],
        current["run_id"],
        current["start_id_sha256"],
    )
    if previous_dispatch == current_dispatch:
        raise QualificationWorkerContractError(
            "one worker dispatch has conflicting terminal receipts"
        )
    return current


def validate_terminal_bindings(
    receipt_value: Any,
    *,
    admission: Any,
    dispatch: Any,
) -> dict[str, Any]:
    receipt = validate_terminal_receipt(receipt_value)
    if not isinstance(admission, dict) or not isinstance(dispatch, dict):
        raise QualificationWorkerContractError(
            "worker admission and dispatch must be objects"
        )
    admission_bindings = {
        "worker_admission_sha256": admission.get("admission_id_sha256"),
        "provider_identity_sha256": admission.get("provider_identity_sha256"),
        "worker_identity_sha256": admission.get("worker_identity_sha256"),
        "live_provider_observation_sha256": admission.get(
            "live_provider_observation_sha256"
        ),
        "admitted_runtime_sha256": admission.get("admitted_runtime_sha256"),
        "capability_handle_sha256": admission.get("capability_handle_sha256"),
        "launch_attempt_host_identity_sha256": admission.get(
            "host_identity_sha256"
        ),
    }
    dispatch_bindings = {
        "worker_admission_sha256": dispatch.get("worker_admission_sha256"),
        "dispatch_id_sha256": dispatch.get("dispatch_id_sha256"),
        "provider_identity_sha256": dispatch.get("provider_identity_sha256"),
        "worker_identity_sha256": dispatch.get("worker_identity_sha256"),
        "live_provider_observation_sha256": dispatch.get(
            "live_provider_observation_sha256"
        ),
        "admitted_runtime_sha256": dispatch.get("admitted_runtime_sha256"),
        "run_id": dispatch.get("run_id"),
        "run_attempt": dispatch.get("run_attempt"),
        "start_id_sha256": dispatch.get("start_id_sha256"),
        "task_id_sha256": dispatch.get("task_id_sha256"),
        "task_condition_sha256": dispatch.get("task_condition_sha256"),
        "capability_handle_sha256": dispatch.get("capability_handle_sha256"),
    }
    for source, bindings in (
        ("admission", admission_bindings),
        ("dispatch", dispatch_bindings),
    ):
        for field, expected in bindings.items():
            actual = (
                receipt["launch_attempt"]["host_identity_sha256"]
                if field == "launch_attempt_host_identity_sha256"
                else receipt[field]
            )
            if actual != expected:
                raise QualificationWorkerContractError(
                    f"terminal receipt {field} differs from the {source}"
                )
    return receipt
