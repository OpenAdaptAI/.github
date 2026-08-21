#!/usr/bin/env python3
"""Content-addressed central evidence registry.

Every piece of remote-safe acceptance evidence that a Production admission can
reference must be registered here first, bound by its exact SHA-256 digest.
The registry is append-only and hash-chained: each entry commits to the digest
of the previous entry, so any reordering, removal, or edit of history breaks
the chain and validation fails closed.

The registry stores only public, privacy-safe references: an HTTPS URL, a
digest, a byte length, and recording metadata. It never stores report bodies,
frames, parameters, or any private certificate material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from collections.abc import Mapping
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "evidence-registry.json"

REGISTRY_SCHEMA = "openadapt.production-evidence-registry/v1"
ENTRY_DIGEST_DOMAIN = b"OpenAdapt production evidence registry entry v1\0"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MILLISECOND_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
ENTRY_KINDS = (
    "evidence-summary",
    "attestation-bundle",
    "evidence-manifest",
    "acceptance-run-record",
)


class EvidenceRegistryError(ValueError):
    """The evidence registry is invalid or does not bind the referenced object."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceRegistryError(f"{label} must be an object")
    unexpected = set(value) - keys
    missing = keys - set(value)
    if unexpected or missing:
        raise EvidenceRegistryError(
            f"{label} has unexpected fields {sorted(unexpected)} "
            f"and missing fields {sorted(missing)}"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise EvidenceRegistryError(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or MILLISECOND_UTC.fullmatch(value) is None:
        raise EvidenceRegistryError(f"{label} must be a millisecond UTC timestamp")
    return value


def _url(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("https://"):
        raise EvidenceRegistryError(f"{label} must be an HTTPS URL")
    parsed = value.split("?", 1)[0].split("#", 1)[0]
    if not parsed.startswith("https://") or len(value) > 2048:
        raise EvidenceRegistryError(f"{label} is not a bounded HTTPS URL")
    return value


def _size(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise EvidenceRegistryError(f"{label} must be a positive byte count")
    return value


def entry_digest(entry: Mapping[str, Any]) -> str:
    """Return the chained digest of one exact registry entry."""

    canonical = {
        "kind": entry["kind"],
        "prior_entry_sha256": entry["prior_entry_sha256"],
        "recorded_at": entry["recorded_at"],
        "sequence": entry["sequence"],
        "sha256": entry["sha256"],
        "size_bytes": entry["size_bytes"],
        "url": entry["url"],
    }
    return (
        "sha256:"
        + hashlib.sha256(ENTRY_DIGEST_DOMAIN + _canonical(canonical)).hexdigest()
    )


def build_entry(
    *,
    sequence: int,
    kind: str,
    url: str,
    sha256: str,
    size_bytes: int,
    recorded_at: str,
    prior_entry_sha256: str | None,
) -> dict[str, Any]:
    """Build one validated registry entry with its computed chain digest."""

    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise EvidenceRegistryError("entry sequence must be a positive integer")
    if kind not in ENTRY_KINDS:
        raise EvidenceRegistryError(f"entry kind is not supported: {kind!r}")
    entry = {
        "sequence": sequence,
        "kind": kind,
        "url": _url(url, "entry url"),
        "sha256": _digest(sha256, "entry digest"),
        "size_bytes": _size(size_bytes, "entry size"),
        "recorded_at": _timestamp(recorded_at, "entry recorded_at"),
        "prior_entry_sha256": (
            None if prior_entry_sha256 is None
            else _digest(prior_entry_sha256, "entry prior digest")
        ),
    }
    entry["entry_sha256"] = entry_digest(entry)
    return entry


def validate_registry(value: Any) -> list[dict[str, Any]]:
    """Validate the complete registry document and return its entries."""

    document = _closed(
        value,
        {"$schema", "schema_version", "head_entry_sha256", "entries"},
        "evidence registry",
    )
    if document["$schema"] != "schemas/evidence-registry.schema.json":
        raise EvidenceRegistryError("evidence registry $schema is invalid")
    if document["schema_version"] != REGISTRY_SCHEMA:
        raise EvidenceRegistryError("evidence registry schema is not supported")
    entries = document["entries"]
    if not isinstance(entries, list):
        raise EvidenceRegistryError("evidence registry entries must be a list")

    previous_digest: str | None = None
    for index, item in enumerate(entries):
        entry = _closed(
            item,
            {
                "sequence",
                "kind",
                "url",
                "sha256",
                "size_bytes",
                "recorded_at",
                "prior_entry_sha256",
                "entry_sha256",
            },
            f"registry entry {index}",
        )
        if entry["sequence"] != index + 1:
            raise EvidenceRegistryError(
                f"registry entry {index} sequence must be exactly {index + 1}"
            )
        expected_prior = previous_digest
        actual_prior = entry["prior_entry_sha256"]
        if expected_prior != actual_prior:
            raise EvidenceRegistryError(
                f"registry entry {index} does not chain to its predecessor"
            )
        if entry["kind"] not in ENTRY_KINDS:
            raise EvidenceRegistryError(
                f"registry entry {index} kind is not supported"
            )
        _url(entry["url"], f"registry entry {index} url")
        _digest(entry["sha256"], f"registry entry {index} digest")
        _size(entry["size_bytes"], f"registry entry {index} size")
        _timestamp(entry["recorded_at"], f"registry entry {index} recorded_at")
        computed = entry_digest(entry)
        if entry["entry_sha256"] != computed:
            raise EvidenceRegistryError(
                f"registry entry {index} chained digest is invalid"
            )
        previous_digest = computed

    head = document["head_entry_sha256"]
    if entries:
        if head != previous_digest:
            raise EvidenceRegistryError("evidence registry head digest is stale")
    elif head is not None:
        raise EvidenceRegistryError("empty evidence registry must have a null head")
    return entries


def require_registered(
    entries: list[dict[str, Any]],
    *,
    url: str,
    sha256: str,
    kind: str,
    label: str,
) -> None:
    """Fail closed unless the exact (url, digest) pair is registered."""

    wanted_url = _url(url, f"{label} url")
    wanted_digest = _digest(sha256, f"{label} digest")
    for entry in entries:
        if entry["url"] == wanted_url and entry["sha256"] == wanted_digest:
            if entry["kind"] != kind:
                raise EvidenceRegistryError(
                    f"{label} is registered with kind {entry['kind']!r}, "
                    f"not {kind!r}"
                )
            return
    raise EvidenceRegistryError(
        f"{label} is not registered in the central evidence registry"
    )


def validate_append_only_history(previous_value: object, current_value: object) -> None:
    """Reject registry rollback while allowing exact appends."""

    previous = validate_registry(previous_value)
    current = validate_registry(current_value)
    if len(current) < len(previous):
        raise EvidenceRegistryError("evidence registry history cannot remove entries")
    for index, old_entry in enumerate(previous):
        if current[index] != old_entry:
            raise EvidenceRegistryError(
                f"evidence registry entry {index} changed after recording"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the content-addressed evidence registry."
    )
    parser.add_argument(
        "--registry",
        default=str(REGISTRY_PATH),
        help="path to evidence-registry.json (default: repository root)",
    )
    parser.add_argument(
        "--previous-registry",
        help="optional trusted previous registry; the current one may only "
        "append exact entries",
    )
    args = parser.parse_args(argv)
    try:
        raw = Path(args.registry).read_text(encoding="utf-8")
        value = json.loads(raw)
        validate_registry(value)
        if args.previous_registry:
            previous_raw = Path(args.previous_registry).read_text(encoding="utf-8")
            validate_append_only_history(json.loads(previous_raw), value)
    except (OSError, json.JSONDecodeError, EvidenceRegistryError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print("evidence registry is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
