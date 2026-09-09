#!/usr/bin/env python3
"""Prepare an unsigned Flow release candidate from measured trials.

No key access, signatures, registry writes, or publication occur here. The
operator must review the exact candidate before the existing issuer uses it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import zipfile
from email.parser import BytesParser
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


def verify_trial_observation(
    trial: dict,
    inventory: dict,
    root: Path,
    version: str,
    wheel_digest: str,
    proofs: set[str],
) -> None:
    """Cross-check normalized counters against their retained native reports.

    Hashes establish byte identity. They do not prove that a process executed;
    review of the retained measurement code and provenance remains required.
    """

    def referenced(reference: dict) -> Path:
        if (
            not isinstance(reference.get("path"), str)
            or reference["path"] not in inventory
            or inventory[reference["path"]]["sha256"] != reference.get("sha256")
        ):
            raise ValueError("observation reference is absent from verified inventory")
        return root / reference["path"]

    observed = read_json(referenced(trial.get("observation", {})))
    if observed.get("schema_version") != "openadapt.observed-release-trial/v1":
        raise ValueError("wrong observed trial schema")
    for field in ("class", "task_id", "condition", "trial", "counters"):
        if observed.get(field) != trial[field]:
            raise ValueError(f"retained observation differs from trial {field}")
    runtime = observed.get("runtime", {})
    if runtime.get("version") != version or runtime.get("wheel_sha256") != wheel_digest:
        raise ValueError("observed runtime identity differs")
    proof_reference = runtime.get("installed_distribution_proof", {})
    proof_path = referenced(proof_reference)
    if proof_reference["sha256"] not in proofs:
        proof = read_json(proof_path)
        if (
            proof.get("schema_version") != "openadapt.installed-distribution-proof/v1"
            or proof.get("distribution") != "openadapt-flow"
            or proof.get("version") != version
            or proof.get("all_members_match") is not True
            or proof.get("installed_extra_files") != []
        ):
            raise ValueError("installed distribution proof is incomplete or mismatched")
        wheel_reference = proof.get("wheel", {})
        wheel_path = referenced(wheel_reference)
        if wheel_reference.get("sha256") != wheel_digest:
            raise ValueError("installed proof names another wheel")
        if wheel_reference.get("size_bytes") != wheel_path.stat().st_size:
            raise ValueError("installed proof wheel size differs")
        members = proof.get("members", [])
        indexed = {m["path"]: m for m in members}
        if len(indexed) != len(members):
            raise ValueError("duplicate installed member proof")
        with zipfile.ZipFile(wheel_path) as archive:
            names = [
                n
                for n in archive.namelist()
                if n.startswith("openadapt_flow/") and not n.endswith("/")
            ]
            if not names or len(names) != len(set(names)) or set(names) != set(indexed):
                raise ValueError(
                    "installed member proof does not cover the exact wheel"
                )
            for name in names:
                raw = archive.read(name)
                item = indexed[name]
                if (
                    item.get("size_bytes") != len(raw)
                    or item.get("wheel_sha256") != sha(raw)
                    or item.get("installed_sha256") != sha(raw)
                ):
                    raise ValueError("installed member differs from candidate wheel")
        proofs.add(proof_reference["sha256"])

    reports = observed.get("reports", [])
    if not reports or len({r["path"] for r in reports}) != len(reports):
        raise ValueError("observed trial needs distinct retained native reports")
    primary = []
    model_calls = 0
    for reference in reports:
        report = read_json(referenced(reference))
        for field in ("success", "transaction_outcome", "model_calls"):
            if field not in report or report[field] != reference.get(field):
                raise ValueError(
                    f"retained native report differs from observed {field}"
                )
        if not isinstance(report["success"], bool):
            raise ValueError("native report success must be a boolean")
        count = report["model_calls"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("native model calls must be observed nonnegative integers")
        model_calls += count
        if reference.get("role") == "primary":
            primary.append(report)
    if len(primary) != 1 or model_calls != trial["counters"]["model_call_count"]:
        raise ValueError("primary report or model call total differs")
    final = primary[0]
    if trial["class"] == "uncertain_delivery":
        expected = (
            not final["success"]
            and final["transaction_outcome"] == "RECONCILIATION_REQUIRED"
        )
    elif trial["class"] == "safe_halt":
        expected = not final["success"] and final["transaction_outcome"] != "VERIFIED"
    else:
        expected = final["success"] and final["transaction_outcome"] == "VERIFIED"
    if not expected:
        raise ValueError("primary native outcome does not satisfy its measured class")
    references = observed.get("verification_references", [])
    if not references:
        raise ValueError("observed trial has no retained verification references")
    for reference in references:
        referenced(reference)


def validate_trial_events(trial: dict) -> None:
    required = {
        "uncertain_delivery": ("reconciliation_required_count",),
        "declared_attended": (
            "authenticated_bound_decision_count",
            "live_target_revalidation_count",
        ),
        "governed_repair": (
            "policy_approved_repair_count",
            "approved_repair_count",
            "retained_repair_evidence_count",
            "live_target_revalidation_count",
        ),
    }
    if any(trial["counters"][field] != 1 for field in required.get(trial["class"], ())):
        raise ValueError(
            "each trial must satisfy its own required class events exactly once"
        )


def summarize(
    manifest_path: Path, wheel_digest: str, *, version: str = VERSION
) -> tuple[dict, dict]:
    root = manifest_path.resolve().parent
    raw = manifest_path.read_bytes()
    document = json.loads(raw)
    if (
        document["schema_version"] != "openadapt.measured-release-evidence/v1"
        or document["evidence_class"] != "remote-safe-synthetic"
    ):
        raise ValueError("wrong measured evidence schema or class")
    if document["runtime"] != {"version": version, "wheel_sha256": wheel_digest}:
        raise ValueError("measured runtime does not match the candidate wheel")
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
            or trial["runtime_version"] != version
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
    missing = [name for name in trust.CAMPAIGN_CLASSES if not groups[name]]
    if missing:
        raise ValueError("measured trials are missing for " + ", ".join(missing))
    normalizer = document.get("normalizer", {})
    if (
        not isinstance(normalizer.get("path"), str)
        or not normalizer["path"]
        or normalizer["path"] not in inventory
        or not isinstance(normalizer.get("sha256"), str)
        or inventory[normalizer["path"]]["sha256"] != normalizer["sha256"]
    ):
        raise ValueError("measurement normalizer is absent from verified inventory")
    proofs: set[str] = set()
    for trial in document["trials"]:
        validate_trial_events(trial)
        verify_trial_observation(trial, inventory, root, version, wheel_digest, proofs)
    summary = {}
    for name in trust.CAMPAIGN_CLASSES:
        trials = groups[name]
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


def observe_unpublished(wheel: Path, sdist: Path, source: str) -> dict:
    if len(source) != 40 or any(c not in "0123456789abcdef" for c in source):
        raise ValueError("candidate source must be an exact commit SHA")
    with zipfile.ZipFile(wheel) as archive:
        metadata_paths = [
            n for n in archive.namelist() if n.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise ValueError("wheel metadata is ambiguous")
        wheel_metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
    with tarfile.open(sdist, "r:gz") as archive:
        metadata_paths = [
            m
            for m in archive.getmembers()
            if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO")
        ]
        if len(metadata_paths) != 1 or not metadata_paths[0].isfile():
            raise ValueError("sdist metadata is ambiguous")
        stream = archive.extractfile(metadata_paths[0])
        assert stream is not None
        sdist_metadata = BytesParser().parsebytes(stream.read())
    version = wheel_metadata["Version"]
    if (
        wheel_metadata["Name"] != "openadapt-flow"
        or sdist_metadata["Name"] != "openadapt-flow"
        or sdist_metadata["Version"] != version
    ):
        raise ValueError("candidate package metadata differs")
    if version != "1.35.1":
        raise ValueError("this reviewed successor candidate must be version 1.35.1")
    return {
        "published": False,
        "version": version,
        "source_commit": source,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "required_external_gates": [
            "Review and merge the exact candidate",
            "Run the protected-main full qualification and three-OS lifecycle",
            "Publish and verify both immutable artifacts",
            "Issue and project the exact signed admission",
        ],
        "artifacts": [
            {
                "kind": kind,
                "name": path.name,
                "sha256": sha(path.read_bytes()),
                "size_bytes": path.stat().st_size,
            }
            for kind, path in (("python-wheel", wheel), ("python-sdist", sdist))
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measured-manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--unpublished-wheel", type=Path)
    parser.add_argument("--unpublished-sdist", type=Path)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    local_args = (args.unpublished_wheel, args.unpublished_sdist, args.source_commit)
    if any(local_args) and not all(local_args):
        parser.error(
            "unpublished wheel, sdist, and source commit must be supplied together"
        )
    observation = (
        observe_unpublished(*local_args) if all(local_args) else observe_release()
    )
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
        candidate["measured_manifest_sha256"] = sha(args.measured_manifest.read_bytes())
        measured_document = read_json(args.measured_manifest)
        candidate["measured_scope"] = measured_document.get("scope")
        candidate["limitations"] = measured_document.get("limitations", [])
        try:
            summary, measured = summarize(
                args.measured_manifest,
                wheel["sha256"],
                version=observation.get("version", VERSION),
            )
        except (ValueError, trust.TrustError) as exc:
            candidate["validation_errors"] = [str(exc)]
        else:
            if measured_document.get("candidate_ready") is not True:
                candidate["validation_errors"] = [
                    "measured evidence declares unresolved admission requirements"
                ]
            elif not candidate["measured_scope"]:
                candidate["validation_errors"] = ["measured scope must be explicit"]
            else:
                candidate.update(
                    state="ready-for-release-review"
                    if observation.get("published") is False
                    else "ready-for-review",
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
    return 1 if candidate.get("validation_errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
