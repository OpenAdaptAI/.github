#!/usr/bin/env python3
"""Emit an exact-commit v2 reference for one registered entry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import validate_evidence_registry as registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=str(registry.REGISTRY_PATH))
    parser.add_argument("--registry-source-commit", required=True)
    parser.add_argument("--object-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        value = json.loads(Path(args.registry).read_text(encoding="utf-8"))
        entries = registry.validate_registry(value)
        matches = [item for item in entries if item["object_sha256"] == args.object_sha256]
        if len(matches) != 1:
            raise registry.EvidenceRegistryError("object digest does not select one entry")
        reference = {
            "schema_version": registry.REFERENCE_SCHEMA,
            "repository": registry.REPOSITORY,
            "repository_id": registry.REPOSITORY_ID,
            "repository_owner_id": registry.REPOSITORY_OWNER_ID,
            "registry_source_commit": args.registry_source_commit,
            "registry_revision": value["revision"],
            "registry_head_sha256": value["registry_head_sha256"],
            **matches[0],
        }
        registry.validate_reference(reference)
        print(json.dumps(reference, sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
