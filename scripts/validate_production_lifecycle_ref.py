#!/usr/bin/env python3
"""Validate a closed lifecycle feed update against an exact local Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone

import production_trust as trust


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True
    ).stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-json", required=True)
    parser.add_argument("--trusted-main", required=True)
    args = parser.parse_args(argv)
    try:
        update = trust.validate_feed_update(json.loads(args.update_json))
        new_commit = update["new_commit"]
        commit = git("rev-parse", f"{new_commit}^{{commit}}").decode().strip()
        if commit != new_commit:
            raise trust.TrustError("new lifecycle commit is not exact")
        parent = git("rev-parse", f"{new_commit}^").decode().strip()
        if parent != args.trusted_main:
            raise trust.TrustError("new lifecycle commit is not based on current main")
        changed = git(
            "diff", "--name-only", "--diff-filter=ACMR", args.trusted_main, new_commit
        ).decode().splitlines()
        if changed != ["production-lifecycle-feed.json"]:
            raise trust.TrustError("lifecycle commit changes files outside the feed")
        feed_raw = git("show", f"{new_commit}:production-lifecycle-feed.json")
        if "sha256:" + hashlib.sha256(feed_raw).hexdigest() != update["feed_sha256"]:
            raise trust.TrustError("feed bytes differ from update digest")
        feed = trust.validate_feed(
            json.loads(feed_raw), now=datetime.now(timezone.utc)
        )
        if feed["expires_at"] != update["expires_at"] or feed["registry_head_sha256"] != update["registry_head_sha256"]:
            raise trust.TrustError("feed state differs from update payload")
        checkpoint_digests = {
            pair["checkpoint_reference"]["object_sha256"]
            for pair in feed["checkpoints"]
        }
        if update["checkpoint_sha256"] not in checkpoint_digests:
            raise trust.TrustError("update checkpoint is not selected by the feed")
        print("production lifecycle feed update is valid")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
