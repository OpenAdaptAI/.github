"""Validate remote-safe qualification worker task identities."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

TASK_SELECTOR_DOMAIN = b"OpenAdapt qualification worker task selector v1\0"
TASK_CONDITION_DOMAIN = b"OpenAdapt qualification worker task condition v1\0"
TASK_SELECTOR_SCHEMA = "openadapt.qualification-worker-task-selector/v1"
TASK_CONDITION_SCHEMA = "openadapt.qualification-worker-task-condition/v1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TASK_SELECTOR_FIELDS = {
    "schema_version",
    "campaign_artifact_sha256",
    "task_source_sha256",
    "task_ordinal",
    "task_id_sha256",
}
TASK_CONDITION_FIELDS = {
    "schema_version",
    "task_id_sha256",
    "condition_source_sha256",
    "condition_ordinal",
    "task_condition_sha256",
}


class QualificationWorkerTaskContractError(ValueError):
    """A remote-safe task selector or condition identity is invalid."""


def canonical(value: Any) -> bytes:
    """Return the canonical compact sorted UTF-8 JSON representation."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(domain: bytes, value: Any) -> str:
    """Return a prefixed lowercase SHA-256 digest for a domain and object."""

    return "sha256:" + hashlib.sha256(domain + canonical(value)).hexdigest()


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise QualificationWorkerTaskContractError(
            f"{label} must contain exactly {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise QualificationWorkerTaskContractError(
            f"{label} must be a lowercase sha256 digest"
        )
    return value


def _positive_ordinal(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise QualificationWorkerTaskContractError(
            f"{label} must be a positive integer"
        )
    return value


def task_selector_projection(selector: dict[str, Any]) -> dict[str, Any]:
    """Return the exact projection covered by the task identity digest."""

    return {
        "schema_version": selector["schema_version"],
        "campaign_artifact_sha256": selector["campaign_artifact_sha256"],
        "task_source_sha256": selector["task_source_sha256"],
        "task_ordinal": selector["task_ordinal"],
    }


def task_condition_projection(condition: dict[str, Any]) -> dict[str, Any]:
    """Return the exact projection covered by the task-condition digest."""

    return {
        "schema_version": condition["schema_version"],
        "task_id_sha256": condition["task_id_sha256"],
        "condition_source_sha256": condition["condition_source_sha256"],
        "condition_ordinal": condition["condition_ordinal"],
    }


def validate_task_selector(value: Any) -> dict[str, Any]:
    """Validate one closed remote-safe task selector and its identity."""

    selector = _closed(value, TASK_SELECTOR_FIELDS, "worker task selector")
    if selector["schema_version"] != TASK_SELECTOR_SCHEMA:
        raise QualificationWorkerTaskContractError(
            "worker task selector schema is invalid"
        )
    _digest(selector["campaign_artifact_sha256"], "campaign artifact identity")
    _digest(selector["task_source_sha256"], "task source identity")
    _positive_ordinal(selector["task_ordinal"], "task ordinal")
    _digest(selector["task_id_sha256"], "task identity")
    if selector["task_id_sha256"] != digest(
        TASK_SELECTOR_DOMAIN, task_selector_projection(selector)
    ):
        raise QualificationWorkerTaskContractError("worker task identity differs")
    return selector


def validate_task_condition(value: Any) -> dict[str, Any]:
    """Validate one closed remote-safe task condition and its identity."""

    condition = _closed(value, TASK_CONDITION_FIELDS, "worker task condition")
    if condition["schema_version"] != TASK_CONDITION_SCHEMA:
        raise QualificationWorkerTaskContractError(
            "worker task condition schema is invalid"
        )
    _digest(condition["task_id_sha256"], "task identity")
    _digest(condition["condition_source_sha256"], "condition source identity")
    _positive_ordinal(condition["condition_ordinal"], "condition ordinal")
    _digest(condition["task_condition_sha256"], "task condition identity")
    if condition["task_condition_sha256"] != digest(
        TASK_CONDITION_DOMAIN, task_condition_projection(condition)
    ):
        raise QualificationWorkerTaskContractError(
            "worker task condition identity differs"
        )
    return condition


def validate_task_condition_binding(
    selector_value: Any, condition_value: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require one condition to select the exact validated task identity."""

    selector = validate_task_selector(selector_value)
    condition = validate_task_condition(condition_value)
    if condition["task_id_sha256"] != selector["task_id_sha256"]:
        raise QualificationWorkerTaskContractError(
            "worker task condition selects a different task identity"
        )
    return selector, condition


def validate_task_contract(
    selector_value: Any,
    condition_value: Any,
    *,
    campaign_artifact_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind a task and condition to the expected campaign artifact."""

    expected_campaign = _digest(
        campaign_artifact_sha256, "expected campaign artifact identity"
    )
    selector, condition = validate_task_condition_binding(
        selector_value, condition_value
    )
    if selector["campaign_artifact_sha256"] != expected_campaign:
        raise QualificationWorkerTaskContractError(
            "worker task selector binds a different campaign artifact"
        )
    return selector, condition
