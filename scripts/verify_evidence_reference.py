#!/usr/bin/env python3
"""Fetch and verify one registered regular evidence object and its paired bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import verify_production_release_admission as verifier

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--expected-kind", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        reference = verifier.load_json_argument(args.reference)
        if reference.get("kind") != args.expected_kind:
            raise ValueError("reference kind differs from expected kind")
        bundle_reference = verifier.derive_bundle_reference(reference)
        regular_raw, bundle_raw, value = verifier.fetch_pair(
            reference, bundle_reference
        )
        policy = json.loads(
            (ROOT / "production-evidence-policy.json").read_text(encoding="utf-8")
        )
        verifier.verify_sigstore(
            regular_raw, bundle_raw, kind=args.expected_kind, policy=policy
        )
        Path(args.output).write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
