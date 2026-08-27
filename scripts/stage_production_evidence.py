#!/usr/bin/env python3
"""Append one regular object and its raw Sigstore bundle to the v2 registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

import validate_evidence_registry as registry


def entry_for(raw: bytes, *, kind: str, subject: str | None) -> dict:
    schema, media = registry.OBJECT_KIND_CONTRACTS[kind]
    object_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    digest_hex = object_sha.removeprefix("sha256:")
    if kind.endswith("-sigstore-bundle"):
        identity_value = subject
    else:
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema_version") != schema:
            raise registry.EvidenceRegistryError("regular object schema differs from kind")
        identity_value = value
    entry = {
        "kind": kind,
        "object_schema_version": schema,
        "object_path": (
            f"production-evidence/objects/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.{kind}.json"
        ),
        "object_sha256": object_sha,
        "size_bytes": len(raw),
        "object_media_type": media,
        "semantic_identity_sha256": registry.semantic_identity_digest(
            kind=kind,
            object_schema_version=schema,
            object_value=identity_value,
            object_sha256=object_sha,
        ),
        "subject_sha256": subject,
    }
    entry["registry_entry_sha256"] = registry.entry_digest(entry)
    return entry


def install_signer_registry(document: dict, source: Path, root: Path) -> None:
    raw = source.read_bytes()
    value = registry.validate_signer_registry(json.loads(raw))
    object_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    digest_hex = object_sha.removeprefix("sha256:")
    relative = (
        f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.qualification-signer-registry.json"
    )
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != raw:
        raise registry.EvidenceRegistryError("signer registry content address collides")
    target.write_bytes(raw)
    document["signer_registry"] = {
        "schema_version": registry.SIGNER_POINTER_SCHEMA,
        "object_path": relative,
        "object_sha256": object_sha,
        "registry_identity_sha256": registry.signer_registry_identity_digest(value),
        "registry_revision": value["revision"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=str(registry.REGISTRY_PATH))
    parser.add_argument("--kind", required=True)
    parser.add_argument("--object", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--signer-registry")
    args = parser.parse_args(argv)
    try:
        if args.kind not in registry.REGULAR_KIND_CONTRACTS:
            raise registry.EvidenceRegistryError("kind is not a regular registered kind")
        registry_path = Path(args.registry).resolve()
        root = registry_path.parent
        document = json.loads(registry_path.read_text(encoding="utf-8"))
        registry.validate_registry(document, root=root)
        previous_head = document["registry_head_sha256"]
        if args.signer_registry:
            install_signer_registry(document, Path(args.signer_registry), root)
        if document["signer_registry"] is None:
            raise registry.EvidenceRegistryError("signer registry must be installed first")
        regular_raw = Path(args.object).read_bytes()
        bundle_raw = Path(args.bundle).read_bytes()
        json.loads(bundle_raw)
        regular = entry_for(regular_raw, kind=args.kind, subject=None)
        bundle = entry_for(
            bundle_raw,
            kind=f"{args.kind}-sigstore-bundle",
            subject=regular["object_sha256"],
        )
        existing = {item["object_sha256"] for item in document["entries"]}
        if regular["object_sha256"] in existing or bundle["object_sha256"] in existing:
            raise registry.EvidenceRegistryError("object is already registered")
        for raw, item in ((regular_raw, regular), (bundle_raw, bundle)):
            target = root / item["object_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != raw:
                raise registry.EvidenceRegistryError("content-addressed object collides")
            target.write_bytes(raw)
        document["revision"] += 1
        document["previous_registry_head_sha256"] = previous_head
        document["entries"].extend((regular, bundle))
        document["registry_head_sha256"] = registry.registry_head_digest(document)
        registry_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        registry.validate_registry(document, root=root)
        print(json.dumps({"regular": regular, "bundle": bundle}, sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
