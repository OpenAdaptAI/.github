#!/usr/bin/env python3
"""Prepare an unsigned Flow 1.35.0 admission candidate from measured trials.

No key access, signatures, registry writes, or publication occur here. The
operator must review the exact candidate before the existing issuer uses it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import production_trust as trust  # noqa: E402

VERSION = "1.35.0"
SOURCE = "6d1f80aa4775e6aa398c3251c8d53e7ec61d0c0c"
REPOSITORY = "OpenAdaptAI/openadapt-flow"
RUNS = {
    "release": 33826859321,
    "qualification": 33822314626,
    "three_os_lifecycle": 33822325382,
}
DERIVED_FIELDS = {
    "task_condition_cell_count",
    "minimum_trials_per_cell",
    "observed_trial_count",
}
COUNTERS = trust.CAMPAIGN_COUNT_FIELDS - DERIVED_FIELDS


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_bytes())


def gh(path: str):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def observe_release() -> dict:
    with urlopen(
        f"https://pypi.org/pypi/openadapt-flow/{VERSION}/json", timeout=30
    ) as response:
        pypi = json.load(response)
    files = pypi["urls"]
    if len(files) != 2 or {f["packagetype"] for f in files} != {"bdist_wheel", "sdist"}:
        raise ValueError("the release must contain exactly one wheel and one sdist")
    release = gh(f"repos/{REPOSITORY}/releases/tags/v{VERSION}")
    if release["draft"] or release["prerelease"]:
        raise ValueError("the GitHub release is not a stable public release")
    ref = gh(f"repos/{REPOSITORY}/git/ref/tags/v{VERSION}")["object"]
    if ref["type"] != "tag":
        raise ValueError("expected the annotated release tag")
    tag = gh(f"repos/{REPOSITORY}/git/tags/{ref['sha']}")
    if tag["object"] != {
        "sha": SOURCE,
        "type": "commit",
        "url": f"https://api.github.com/repos/{REPOSITORY}/git/commits/{SOURCE}",
    }:
        raise ValueError("the release tag source changed")
    artifacts = []
    for item in sorted(files, key=lambda f: f["filename"]):
        if item["yanked"]:
            raise ValueError("a release artifact is yanked")
        asset = [a for a in release["assets"] if a["name"] == item["filename"]]
        expected_digest = "sha256:" + item["digests"]["sha256"]
        if (
            len(asset) != 1
            or asset[0]["state"] != "uploaded"
            or asset[0]["size"] != item["size"]
            or asset[0].get("digest") != expected_digest
        ):
            raise ValueError("GitHub and PyPI artifact inventory differs")
        artifacts.append(
            {
                "name": item["filename"],
                "sha256": expected_digest,
                "size_bytes": item["size"],
                "pypi_url": item["url"],
                "github_url": asset[0]["browser_download_url"],
                "kind": "python-wheel"
                if item["packagetype"] == "bdist_wheel"
                else "python-sdist",
            }
        )
    runs = {}
    for name, run_id in RUNS.items():
        run = gh(f"repos/{REPOSITORY}/actions/runs/{run_id}")
        if (
            run["head_sha"] != SOURCE
            or run["status"] != "completed"
            or run["conclusion"] != "success"
        ):
            raise ValueError(f"the exact-source {name} run did not pass")
        jobs = gh(f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100")
        if jobs["total_count"] != len(jobs["jobs"]) or any(
            j["conclusion"] not in {"success", "skipped"} for j in jobs["jobs"]
        ):
            raise ValueError(f"the {name} job inventory is incomplete or failed")
        if name != "release" and any(
            j["conclusion"] != "success" for j in jobs["jobs"]
        ):
            raise ValueError(
                "every exact-release qualification job must execute successfully"
            )
        runs[name] = {
            "id": run_id,
            "url": run["html_url"],
            "source_commit": run["head_sha"],
            "conclusion": run["conclusion"],
            "jobs": [
                {"name": j["name"], "conclusion": j["conclusion"]} for j in jobs["jobs"]
            ],
        }
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "source_commit": SOURCE,
        "tag": f"v{VERSION}",
        "tag_object": ref["sha"],
        "release_url": release["html_url"],
        "artifacts": artifacts,
        "runs": runs,
    }


def summarize(manifest_path: Path, wheel_digest: str) -> tuple[dict, dict]:
    root = manifest_path.resolve().parent
    raw = manifest_path.read_bytes()
    document = json.loads(raw)
    if (
        document["schema_version"] != "openadapt.measured-release-evidence/v1"
        or document["evidence_class"] != "remote-safe-synthetic"
    ):
        raise ValueError("wrong measured evidence schema or class")
    if document["runtime"] != {"version": VERSION, "wheel_sha256": wheel_digest}:
        raise ValueError("measured runtime does not match the published wheel")
    inventory = {}
    for item in document["artifacts"]:
        relative = Path(item["path"])
        path = (root / relative).resolve()
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not path.is_relative_to(root)
            or (root / relative).is_symlink()
        ):
            raise ValueError("evidence artifact path escapes its manifest")
        data = path.read_bytes()
        if len(data) != item["size_bytes"] or sha(data) != item["sha256"]:
            raise ValueError(f"artifact bytes differ: {relative}")
        if str(relative) in inventory:
            raise ValueError("duplicate evidence artifact path")
        inventory[str(relative)] = item
    reference_counts = Counter(
        reference["sha256"]
        for trial in document["trials"]
        for reference in {item["sha256"]: item for item in trial["artifacts"]}.values()
    )
    groups = defaultdict(list)
    seen = set()
    for trial in document["trials"]:
        key = (trial["class"], trial["task_id"], trial["condition"], trial["trial"])
        if (
            key in seen
            or trial["class"] not in trust.CAMPAIGN_CLASSES
            or trial["runtime_version"] != VERSION
        ):
            raise ValueError("duplicate, unknown-class, or wrong-runtime trial")
        seen.add(key)
        if not trial["artifacts"] or not any(
            reference_counts[reference["sha256"]] == 1
            for reference in trial["artifacts"]
        ):
            raise ValueError("a measured trial must retain unique observed evidence")
        for reference in trial["artifacts"]:
            if (
                inventory.get(reference["path"], {}).get("sha256")
                != reference["sha256"]
            ):
                raise ValueError("trial evidence is absent from the verified inventory")
        if set(trial["counters"]) != COUNTERS:
            raise ValueError(
                "every trial must explicitly observe every outcome counter"
            )
        if any(
            isinstance(n, bool) or not isinstance(n, int) or n < 0
            for n in trial["counters"].values()
        ):
            raise ValueError("trial counters must be nonnegative integers")
        groups[trial["class"]].append(trial)
    summary = {}
    for name in trust.CAMPAIGN_CLASSES:
        trials = groups[name]
        if not trials:
            raise ValueError(f"measured trials are missing for {name}")
        cells = Counter((t["task_id"], t["condition"]) for t in trials)
        counts = {key: sum(t["counters"][key] for t in trials) for key in COUNTERS}
        counts.update(
            task_condition_cell_count=len(cells),
            minimum_trials_per_cell=min(cells.values()),
            observed_trial_count=len(trials),
        )
        summary[name] = counts
    trust.validate_campaign_summary(summary)
    return summary, {
        "manifest_sha256": sha(raw),
        "artifact_count": len(inventory),
        "trial_count": len(seen),
        "task_count": len({t["task_id"] for t in document["trials"]}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measured-manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    observation = observe_release()
    wheel = next(a for a in observation["artifacts"] if a["kind"] == "python-wheel")
    ledger = read_json(ROOT / "production-lifecycle-admissions.json")
    previous = []
    for reference in ledger["admissions"]:
        raw = (ROOT / reference["object_path"]).read_bytes()
        if sha(raw) != reference["object_sha256"]:
            raise ValueError("previous admission bytes differ from the ledger")
        admission = json.loads(raw)
        if admission["target"] == "flow":
            previous.append(admission)
    if not previous:
        raise ValueError("previous Flow admission is absent")
    last = max(previous, key=lambda a: a["release_identity"]["sequence"])
    candidate = {
        "schema_version": "openadapt.unsigned-measured-release-candidate/v1",
        "target": "flow",
        "evidence_class": "remote-safe-synthetic",
        "state": "evidence-incomplete",
        "admission_issued": False,
        "proposed_release_identity": {
            "schema_version": "openadapt.monotonic-production-release/v1",
            "channel": "production",
            "sequence": last["release_identity"]["sequence"] + 1,
            "previous_admission_sha256": last["admission_id_sha256"],
        },
        "canonical_policy_commit": subprocess.check_output(
            ["git", "rev-parse", "origin/main"], cwd=ROOT, text=True
        ).strip(),
        "scope": "Executed local synthetic SQLite and pixel fixture; synthetic reviewer inputs; no customer qualification or actual human approval.",
        "release_observation": observation,
        "required_campaign_classes": list(trust.CAMPAIGN_CLASSES),
    }
    if args.measured_manifest:
        summary, measured = summarize(args.measured_manifest, wheel["sha256"])
        candidate.update(
            state="ready-for-review",
            campaign_summary=summary,
            measured_evidence=measured,
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "state": candidate["state"],
                "admission_issued": False,
                "candidate": str(args.out),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
