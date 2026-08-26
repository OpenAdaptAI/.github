#!/usr/bin/env python3
"""Prepare one exact, reviewable lifecycle state change.

The workflow that calls this script starts on the current ``main`` commit. It
binds the requested change to that commit with a domain-separated idempotency
digest, writes one candidate file, and leaves the result for normal pull
request review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import validate_evidence_registry as evidence_registry
import validate_production_lifecycle as lifecycle

ROOT = Path(__file__).resolve().parents[1]
ADMISSIONS_PATH = ROOT / "production-lifecycle-admissions.json"
REGISTRY_PATH = ROOT / "evidence-registry.json"

ACTIVATION_DOMAIN = b"OpenAdapt production lifecycle activation proposal v1\0"
AUTHORITY_DOMAIN = b"OpenAdapt qualification authority state proposal v1\0"
REVOCATION_DOMAIN = b"OpenAdapt qualification revocation state proposal v1\0"

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class CandidateError(ValueError):
    """The requested candidate is not an allowed lifecycle state change."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def proposal_digest(domain: bytes, payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical(payload)).hexdigest()


def _source_commit(value: str) -> str:
    if COMMIT_RE.fullmatch(value) is None:
        raise CandidateError("source commit must be a full lowercase commit ID")
    return value


def _idempotency_key(value: str, expected: str) -> str:
    if DIGEST_RE.fullmatch(value) is None:
        raise CandidateError("idempotency key must be a lowercase SHA-256 digest")
    if value != expected:
        raise CandidateError("idempotency key does not bind the exact candidate")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError(f"{path.name} is missing or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"{path.name} must contain a JSON object")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    temporary.replace(path)


def _review_branch(prefix: str, idempotency_key: str) -> str:
    return f"automation/{prefix}-{idempotency_key.removeprefix('sha256:')}"


def activate(
    *,
    root: Path,
    source_commit: str,
    admission_json: str,
    idempotency_key: str,
) -> str:
    source_commit = _source_commit(source_commit)
    try:
        admission = json.loads(admission_json)
    except json.JSONDecodeError as exc:
        raise CandidateError(f"candidate admission is invalid JSON: {exc}") from exc
    if not isinstance(admission, dict):
        raise CandidateError("candidate admission must be one JSON object")
    expected = proposal_digest(
        ACTIVATION_DOMAIN,
        {"source_commit": source_commit, "admission": admission},
    )
    key = _idempotency_key(idempotency_key, expected)

    path = root / ADMISSIONS_PATH.name
    previous = _load(path)
    current = json.loads(json.dumps(previous))
    admissions = current.get("admissions")
    if not isinstance(admissions, list):
        raise CandidateError("admission ledger must contain an admissions list")
    admission_id = admission.get("admission_id")
    if not isinstance(admission_id, str) or not admission_id:
        raise CandidateError("candidate admission needs an admission_id")
    if admission.get("revoked_at") is not None:
        raise CandidateError("a new Production admission cannot start revoked")
    if any(
        item.get("admission_id") == admission_id
        for item in admissions
        if isinstance(item, dict)
    ):
        raise CandidateError("candidate admission_id already exists")
    admissions.append(admission)
    lifecycle.validate_append_only_history(previous, current)
    _write(path, current)
    return _review_branch("production-lifecycle-activation", key)


def record_authority(
    *,
    root: Path,
    source_commit: str,
    kind: str,
    url: str,
    sha256: str,
    size_bytes: int,
    recorded_at: str,
    idempotency_key: str,
) -> str:
    source_commit = _source_commit(source_commit)
    path = root / REGISTRY_PATH.name
    previous = _load(path)
    entries = evidence_registry.validate_registry(previous)
    entry = evidence_registry.build_entry(
        sequence=len(entries) + 1,
        kind=kind,
        url=url,
        sha256=sha256,
        size_bytes=size_bytes,
        recorded_at=recorded_at,
        prior_entry_sha256=previous.get("head_entry_sha256"),
    )
    expected = proposal_digest(
        AUTHORITY_DOMAIN,
        {"source_commit": source_commit, "entry": entry},
    )
    key = _idempotency_key(idempotency_key, expected)

    current = json.loads(json.dumps(previous))
    current_entries = current.get("entries")
    if not isinstance(current_entries, list):
        raise CandidateError("evidence registry must contain an entries list")
    current_entries.append(entry)
    current["head_entry_sha256"] = entry["entry_sha256"]
    evidence_registry.validate_append_only_history(previous, current)
    _write(path, current)
    return _review_branch("qualification-authority-state", key)


def _whole_second_utc(value: str) -> str:
    if TIMESTAMP_RE.fullmatch(value) is None:
        raise CandidateError("revoked_at must be a whole-second UTC timestamp")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CandidateError("revoked_at is not a valid UTC timestamp") from exc
    return value


def revoke(
    *,
    root: Path,
    source_commit: str,
    admission_id: str,
    revoked_at: str,
    idempotency_key: str,
) -> str:
    source_commit = _source_commit(source_commit)
    if not admission_id or admission_id != admission_id.strip():
        raise CandidateError("admission_id must be a non-empty trimmed string")
    revoked_at = _whole_second_utc(revoked_at)
    expected = proposal_digest(
        REVOCATION_DOMAIN,
        {
            "source_commit": source_commit,
            "admission_id": admission_id,
            "revoked_at": revoked_at,
        },
    )
    key = _idempotency_key(idempotency_key, expected)

    path = root / ADMISSIONS_PATH.name
    previous = _load(path)
    current = json.loads(json.dumps(previous))
    admissions = current.get("admissions")
    if not isinstance(admissions, list):
        raise CandidateError("admission ledger must contain an admissions list")
    matches = [
        (index, item)
        for index, item in enumerate(admissions)
        if isinstance(item, dict) and item.get("admission_id") == admission_id
    ]
    if len(matches) != 1:
        raise CandidateError("admission_id must identify exactly one record")
    index, record = matches[0]
    if record.get("revoked_at") is not None:
        raise CandidateError("the admission is already revoked")
    target = record.get("target")
    latest_for_target = max(
        candidate_index
        for candidate_index, candidate in enumerate(admissions)
        if isinstance(candidate, dict) and candidate.get("target") == target
    )
    if index != latest_for_target:
        raise CandidateError("only the current admission for a target can be revoked")
    record["revoked_at"] = revoked_at
    lifecycle.validate_append_only_history(previous, current)
    _write(path, current)
    return _review_branch("qualification-revocation-state", key)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    activation = subparsers.add_parser("activate")
    activation.add_argument("--source-commit", required=True)
    activation.add_argument("--idempotency-key", required=True)

    authority = subparsers.add_parser("record-authority")
    authority.add_argument("--source-commit", required=True)
    authority.add_argument("--kind", required=True)
    authority.add_argument("--url", required=True)
    authority.add_argument("--sha256", required=True)
    authority.add_argument("--size-bytes", required=True, type=int)
    authority.add_argument("--recorded-at", required=True)
    authority.add_argument("--idempotency-key", required=True)

    revocation = subparsers.add_parser("revoke")
    revocation.add_argument("--source-commit", required=True)
    revocation.add_argument("--admission-id", required=True)
    revocation.add_argument("--revoked-at", required=True)
    revocation.add_argument("--idempotency-key", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.operation == "activate":
            admission_json = os.environ.get("CANDIDATE_ADMISSION_JSON", "")
            if not admission_json:
                raise CandidateError("CANDIDATE_ADMISSION_JSON is required")
            branch = activate(
                root=args.root,
                source_commit=args.source_commit,
                admission_json=admission_json,
                idempotency_key=args.idempotency_key,
            )
        elif args.operation == "record-authority":
            branch = record_authority(
                root=args.root,
                source_commit=args.source_commit,
                kind=args.kind,
                url=args.url,
                sha256=args.sha256,
                size_bytes=args.size_bytes,
                recorded_at=args.recorded_at,
                idempotency_key=args.idempotency_key,
            )
        else:
            branch = revoke(
                root=args.root,
                source_commit=args.source_commit,
                admission_id=args.admission_id,
                revoked_at=args.revoked_at,
                idempotency_key=args.idempotency_key,
            )
    except (
        CandidateError,
        evidence_registry.EvidenceRegistryError,
        lifecycle.LifecycleError,
    ) as exc:
        raise SystemExit(f"REFUSED: {exc}") from exc
    print(branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
