#!/usr/bin/env python3
"""Bind every benchmark figure published on an org front page to its artifact.

Other guards in this organization assert that a page CONTAINS an attribution
string. None of them compares a published NUMBER to the measurement it came
from, so a figure can drift from its artifact while every guard stays green.

This checker closes that gap for `README.md` and `profile/README.md`:

1. Each pinned upstream artifact is vendored under `benchmark-claims/upstream/`
   and re-hashed on every run. A snapshot cannot be edited to bless a figure.
2. Every registered figure is rendered from the vendored artifact and must
   equal the exact text published on the page.
3. The pages are swept for figure-shaped tokens. A token that no registry entry
   claims is an error, so a new figure cannot land unregistered. Registering a
   figure, or exempting a non-benchmark one, is a deliberate reviewable edit.
4. `--online` re-fetches each pinned path from raw.githubusercontent.com and
   compares digests. An unreachable GitHub warns; a digest mismatch fails.

Scope: this is a transcription-fidelity guard, not a validity check. A green run
certifies that the published figure matches the artifact, never that the
measurement behind the artifact is sound.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "benchmark-claims.json"

REGISTRY_SCHEMA = "openadapt.benchmark-claim-binding/v1"
RAW_GITHUB_ORIGIN = "https://raw.githubusercontent.com"
FETCH_TIMEOUT_SECONDS = 30

# The sweep patterns live in code, not in the registry, so that editing the
# registry can never weaken the sweep that guards it.
FIGURE_PATTERNS = (
    r"\d+\s*/\s*\d+",
    r"\d+(?:\.\d+)?\s*%",
    r"\$\d+(?:\.\d+)?",
    r"\d+(?:\.\d+)?\s*s\b",
    r"\b\d+\s+of\s+\d+\b",
)
FIGURE_RE = re.compile("|".join(f"(?:{pattern})" for pattern in FIGURE_PATTERNS))

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

RENDERERS = ("ratio", "count_of", "percent", "seconds", "usd", "integer")
POINTER_COUNTS = {
    "ratio": 2,
    "count_of": 2,
    "percent": 1,
    "seconds": 1,
    "usd": 1,
    "integer": 1,
}
DECIMAL_RENDERERS = {"percent", "seconds", "usd"}

# A recorded drift is a dated exemption for a figure this repository publishes
# and does not own. It may never become an open-ended licence to be wrong.
MAX_DRIFT_DAYS = 60

REGISTRY_KEYS = {
    "$comment",
    "schema_version",
    "upstream",
    "surfaces",
    "claims",
    "non_benchmark_figures",
}
UPSTREAM_KEYS = {"repository", "commit", "sources"}
SOURCE_KEYS = {"id", "path", "git_blob", "sha256", "size_bytes", "snapshot"}
CLAIM_KEYS = {
    "id",
    "surface",
    "context",
    "text",
    "renderer",
    "decimals",
    "source",
    "pointers",
    "status",
    "drift",
}
DRIFT_KEYS = {
    "upstream_text",
    "recorded_on",
    "expires_on",
    "owner",
    "reason",
}
EXEMPTION_KEYS = {"id", "surface", "context", "text", "reason"}


class RegistryError(Exception):
    """The registry itself is malformed, so nothing can be trusted."""


def normalize(text: str) -> str:
    """Collapse Markdown line wrapping so a claim can span wrapped lines."""
    return " ".join(text.split())


def require(condition: object, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def require_relative(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    require(
        not path.is_absolute() and ".." not in path.parts and value == str(path),
        f"{label} is not a normalized relative path: {value!r}",
    )
    return path


def load_registry(path: Path) -> dict[str, Any]:
    """Parse and structurally validate the registry, rejecting unknown keys."""
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistryError(f"cannot read {path.name}: {exc}") from exc

    require(isinstance(registry, dict), "the registry is not a JSON object")
    require(
        set(registry) == REGISTRY_KEYS,
        f"registry keys are {sorted(registry)}; expected {sorted(REGISTRY_KEYS)}",
    )
    require(
        registry["schema_version"] == REGISTRY_SCHEMA,
        f"registry schema_version must be {REGISTRY_SCHEMA!r}",
    )
    require(
        isinstance(registry["$comment"], str) and registry["$comment"].strip(),
        "the registry must carry a non-empty $comment",
    )

    upstream = registry["upstream"]
    require(isinstance(upstream, dict), "upstream is not a JSON object")
    require(
        set(upstream) == UPSTREAM_KEYS,
        f"upstream keys are {sorted(upstream)}; expected {sorted(UPSTREAM_KEYS)}",
    )
    require(
        isinstance(upstream["repository"], str)
        and REPOSITORY.fullmatch(upstream["repository"]),
        "upstream.repository must be OWNER/NAME",
    )
    require(
        isinstance(upstream["commit"], str) and HEX40.fullmatch(upstream["commit"]),
        "upstream.commit must be an exact 40-character commit",
    )

    sources = upstream["sources"]
    require(
        isinstance(sources, list) and sources,
        "upstream.sources must be a non-empty list",
    )
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for source in sources:
        require(isinstance(source, dict), "an upstream source is not a JSON object")
        require(
            set(source) == SOURCE_KEYS,
            f"source keys are {sorted(source)}; expected {sorted(SOURCE_KEYS)}",
        )
        source_id = source["id"]
        require(
            isinstance(source_id, str) and IDENTIFIER.fullmatch(source_id),
            f"source id is not an identifier: {source_id!r}",
        )
        require(source_id not in seen_ids, f"duplicate source id: {source_id}")
        seen_ids.add(source_id)
        require_relative(source["path"], f"source {source_id} path")
        require(
            source["path"] not in seen_paths,
            f"duplicate upstream path: {source['path']}",
        )
        seen_paths.add(source["path"])
        require(
            isinstance(source["git_blob"], str)
            and HEX40.fullmatch(source["git_blob"]),
            f"source {source_id} git_blob must be a 40-character object name",
        )
        require(
            isinstance(source["sha256"], str) and SHA256.fullmatch(source["sha256"]),
            f"source {source_id} sha256 must be sha256:<64 hex>",
        )
        require(
            isinstance(source["size_bytes"], int) and source["size_bytes"] > 0,
            f"source {source_id} size_bytes must be a positive integer",
        )
        snapshot = require_relative(source["snapshot"], f"source {source_id} snapshot")
        require(
            snapshot.parts[0] == "benchmark-claims",
            f"source {source_id} snapshot must live under benchmark-claims/",
        )

    surfaces = registry["surfaces"]
    require(
        isinstance(surfaces, list) and surfaces,
        "surfaces must be a non-empty list",
    )
    for surface in surfaces:
        require(isinstance(surface, str), "a surface is not a string")
        require_relative(surface, "surface")
        require(surface.endswith(".md"), f"surface is not Markdown: {surface}")
    require(len(set(surfaces)) == len(surfaces), "surfaces contains a duplicate")

    claims = registry["claims"]
    require(isinstance(claims, list), "claims must be a list")
    seen_claim_ids: set[str] = set()
    for claim in claims:
        require(isinstance(claim, dict), "a claim is not a JSON object")
        require(
            set(claim) == CLAIM_KEYS,
            f"claim keys are {sorted(claim)}; expected {sorted(CLAIM_KEYS)}",
        )
        claim_id = claim["id"]
        require(
            isinstance(claim_id, str) and IDENTIFIER.fullmatch(claim_id),
            f"claim id is not an identifier: {claim_id!r}",
        )
        require(claim_id not in seen_claim_ids, f"duplicate claim id: {claim_id}")
        seen_claim_ids.add(claim_id)
        require(
            claim["surface"] in surfaces,
            f"claim {claim_id} names an unregistered surface: {claim['surface']!r}",
        )
        require(
            claim["source"] in seen_ids,
            f"claim {claim_id} names an unknown source: {claim['source']!r}",
        )
        require(
            isinstance(claim["text"], str) and claim["text"].strip(),
            f"claim {claim_id} has no published text",
        )
        require(
            isinstance(claim["context"], str) and claim["context"].strip(),
            f"claim {claim_id} has no context",
        )
        require(
            claim["text"] in claim["context"],
            f"claim {claim_id} context does not contain its text",
        )
        renderer = claim["renderer"]
        require(
            renderer in RENDERERS,
            f"claim {claim_id} renderer must be one of {list(RENDERERS)}",
        )
        pointers = claim["pointers"]
        require(
            isinstance(pointers, list)
            and len(pointers) == POINTER_COUNTS[renderer]
            and all(isinstance(item, str) for item in pointers),
            f"claim {claim_id} needs {POINTER_COUNTS[renderer]} JSON pointers",
        )
        for pointer in pointers:
            require(
                pointer.startswith("/"),
                f"claim {claim_id} pointer must start with '/': {pointer!r}",
            )
        decimals = claim["decimals"]
        if renderer in DECIMAL_RENDERERS:
            require(
                isinstance(decimals, int) and 0 <= decimals <= 6,
                f"claim {claim_id} needs decimals between 0 and 6",
            )
        else:
            require(
                decimals is None,
                f"claim {claim_id} renderer {renderer} does not take decimals",
            )
        require(
            claim["status"] in {"bound", "drift_open"},
            f"claim {claim_id} status must be 'bound' or 'drift_open'",
        )
        drift = claim["drift"]
        if claim["status"] == "bound":
            require(drift is None, f"claim {claim_id} is bound but records a drift")
            continue
        require(
            isinstance(drift, dict) and set(drift) == DRIFT_KEYS,
            f"claim {claim_id} drift keys must be {sorted(DRIFT_KEYS)}",
        )
        for field in ("upstream_text", "owner", "reason"):
            require(
                isinstance(drift[field], str) and drift[field].strip(),
                f"claim {claim_id} drift.{field} must be a non-empty string",
            )
        for field in ("recorded_on", "expires_on"):
            require(
                isinstance(drift[field], str) and DATE.fullmatch(drift[field]),
                f"claim {claim_id} drift.{field} must be YYYY-MM-DD",
            )
        recorded_on = date.fromisoformat(drift["recorded_on"])
        expires_on = date.fromisoformat(drift["expires_on"])
        require(
            expires_on > recorded_on,
            f"claim {claim_id} drift expires before it was recorded",
        )
        require(
            (expires_on - recorded_on).days <= MAX_DRIFT_DAYS,
            f"claim {claim_id} drift may not run more than {MAX_DRIFT_DAYS} days",
        )
        require(
            len(drift["reason"]) >= 40,
            f"claim {claim_id} drift.reason must state why the figure is wrong",
        )

    exemptions = registry["non_benchmark_figures"]
    require(isinstance(exemptions, list), "non_benchmark_figures must be a list")
    for exemption in exemptions:
        require(
            isinstance(exemption, dict) and set(exemption) == EXEMPTION_KEYS,
            f"exemption keys must be {sorted(EXEMPTION_KEYS)}",
        )
        exemption_id = exemption["id"]
        require(
            isinstance(exemption_id, str) and IDENTIFIER.fullmatch(exemption_id),
            f"exemption id is not an identifier: {exemption_id!r}",
        )
        require(
            exemption_id not in seen_claim_ids,
            f"exemption {exemption_id} reuses a claim id",
        )
        seen_claim_ids.add(exemption_id)
        require(
            exemption["surface"] in surfaces,
            f"exemption {exemption_id} names an unregistered surface",
        )
        for field in ("context", "text", "reason"):
            require(
                isinstance(exemption[field], str) and exemption[field].strip(),
                f"exemption {exemption_id} {field} must be a non-empty string",
            )
        require(
            exemption["text"] in exemption["context"],
            f"exemption {exemption_id} context does not contain its text",
        )
        require(
            len(exemption["reason"]) >= 20,
            f"exemption {exemption_id} reason must state why it is not a figure",
        )

    return registry


def resolve_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON pointer, raising KeyError when it is unbound."""
    current = document
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise KeyError(pointer)
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                raise KeyError(pointer)
            current = current[int(token)]
        else:
            raise KeyError(pointer)
    return current


def render(renderer: str, values: list[Any], decimals: int | None) -> str:
    """Render an upstream value the way a front page writes it."""
    if renderer in {"ratio", "count_of"}:
        for value in values:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{renderer} needs integers, found {value!r}")
        separator = "/" if renderer == "ratio" else " of "
        return f"{values[0]}{separator}{values[1]}"

    value = values[0]
    if renderer == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"integer needs an integer, found {value!r}")
        return str(value)

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{renderer} needs a number, found {value!r}")
    if renderer == "percent":
        return f"{float(value) * 100:.{decimals}f}%"
    if renderer == "seconds":
        return f"{float(value):.{decimals}f}s"
    return f"${float(value):.{decimals}f}"


def verify_snapshots(
    root: Path, registry: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    """Re-hash every vendored snapshot and parse the ones that survive."""
    documents: dict[str, Any] = {}
    for source in registry["upstream"]["sources"]:
        snapshot = root / source["snapshot"]
        try:
            payload = snapshot.read_bytes()
        except OSError as exc:
            errors.append(f"source {source['id']}: cannot read snapshot: {exc}")
            continue
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if digest != source["sha256"]:
            errors.append(
                f"source {source['id']}: snapshot {source['snapshot']} has digest "
                f"{digest}, but the registry pins {source['sha256']}. The vendored "
                "bytes were edited, or the pin is wrong. Re-vendor from "
                f"{registry['upstream']['repository']}@"
                f"{registry['upstream']['commit']}:{source['path']}."
            )
            continue
        if len(payload) != source["size_bytes"]:
            errors.append(
                f"source {source['id']}: snapshot is {len(payload)} bytes, but the "
                f"registry pins {source['size_bytes']}"
            )
            continue
        try:
            documents[source["id"]] = json.loads(payload)
        except ValueError as exc:
            errors.append(f"source {source['id']}: snapshot is not valid JSON: {exc}")
    return documents


def locate(
    entry: dict[str, Any], surface_text: str, errors: list[str]
) -> tuple[int, int] | None:
    """Find the exact span of a registered figure inside its surface."""
    label = f"{entry['surface']} {entry['id']}"
    occurrences = surface_text.count(entry["context"])
    if occurrences != 1:
        errors.append(
            f"{label}: the registered context appears {occurrences} times; it must "
            f"appear exactly once. Context: {entry['context']!r}"
        )
        return None
    context_start = surface_text.index(entry["context"])
    inner = entry["context"].count(entry["text"])
    if inner != 1:
        errors.append(
            f"{label}: the text {entry['text']!r} appears {inner} times inside its "
            "context; it must appear exactly once"
        )
        return None
    start = context_start + entry["context"].index(entry["text"])
    return start, start + len(entry["text"])


def check_claims(
    registry: dict[str, Any],
    documents: dict[str, Any],
    surfaces: dict[str, str],
    today: date,
    errors: list[str],
    drifts: list[str],
) -> dict[str, list[tuple[int, int, str]]]:
    """Compare every registered figure to the artifact it is bound to."""
    spans: dict[str, list[tuple[int, int, str]]] = {name: [] for name in surfaces}

    for claim in registry["claims"]:
        surface_text = surfaces[claim["surface"]]
        span = locate(claim, surface_text, errors)
        if span is not None:
            spans[claim["surface"]].append((span[0], span[1], claim["id"]))

        document = documents.get(claim["source"])
        if document is None:
            errors.append(
                f"claim {claim['id']}: source {claim['source']} did not verify"
            )
            continue
        try:
            values = [
                resolve_pointer(document, pointer) for pointer in claim["pointers"]
            ]
        except KeyError as exc:
            errors.append(
                f"claim {claim['id']}: pointer {exc.args[0]} is not present in "
                f"{claim['source']}"
            )
            continue
        try:
            upstream_text = render(claim["renderer"], values, claim["decimals"])
        except TypeError as exc:
            errors.append(f"claim {claim['id']}: {exc}")
            continue

        if claim["status"] == "bound":
            if upstream_text != claim["text"]:
                errors.append(
                    f"claim {claim['id']}: {claim['surface']} publishes "
                    f"{claim['text']!r}, but {claim['source']} "
                    f"{claim['pointers']} renders {upstream_text!r}"
                )
            continue

        drift = claim["drift"]
        if upstream_text != drift["upstream_text"]:
            errors.append(
                f"claim {claim['id']}: the recorded drift expects the artifact to "
                f"render {drift['upstream_text']!r}, but it renders "
                f"{upstream_text!r}. Re-adjudicate the drift before trusting it."
            )
            continue
        if upstream_text == claim["text"]:
            errors.append(
                f"claim {claim['id']}: the published figure now equals the artifact. "
                "Change status to 'bound' and delete the drift record."
            )
            continue
        expires_on = date.fromisoformat(drift["expires_on"])
        if today > expires_on:
            errors.append(
                f"claim {claim['id']}: the recorded drift expired on "
                f"{drift['expires_on']}. {claim['surface']} still publishes "
                f"{claim['text']!r} where the artifact says "
                f"{drift['upstream_text']!r}. Correct the published figure."
            )
            continue
        drifts.append(
            f"{claim['id']}: {claim['surface']} publishes {claim['text']!r}; "
            f"{claim['source']} says {drift['upstream_text']!r}; "
            f"owner {drift['owner']}; this exemption fails after "
            f"{drift['expires_on']}"
        )

    for exemption in registry["non_benchmark_figures"]:
        span = locate(exemption, surfaces[exemption["surface"]], errors)
        if span is not None:
            spans[exemption["surface"]].append((span[0], span[1], exemption["id"]))

    for surface, entries in spans.items():
        ordered = sorted(entries)
        for earlier, later in zip(ordered, ordered[1:]):
            if later[0] < earlier[1]:
                errors.append(
                    f"{surface}: registry entries {earlier[2]} and {later[2]} claim "
                    "overlapping text"
                )
    return spans


def sweep(
    surfaces: dict[str, str],
    spans: dict[str, list[tuple[int, int, str]]],
    errors: list[str],
) -> int:
    """Fail on any figure-shaped token that no registry entry claims."""
    claimed_total = 0
    for surface, text in surfaces.items():
        claimed = sorted(spans[surface])
        for match in FIGURE_RE.finditer(text):
            start, end = match.span()
            owner = next(
                (
                    entry_id
                    for entry_start, entry_end, entry_id in claimed
                    if entry_start <= start and end <= entry_end
                ),
                None,
            )
            if owner is None:
                window = text[max(0, start - 60) : end + 40]
                errors.append(
                    f"{surface}: the figure {match.group(0)!r} is not claimed by any "
                    "benchmark-claims.json entry. Bind it to its upstream artifact, "
                    "or record it in non_benchmark_figures with a reason. "
                    f"Context: ...{window}..."
                )
            else:
                claimed_total += 1

        for entry_start, entry_end, entry_id in claimed:
            fragment = text[entry_start:entry_end]
            if not FIGURE_RE.fullmatch(fragment):
                errors.append(
                    f"{surface}: registry entry {entry_id} claims {fragment!r}, which "
                    "the sweep does not read as a figure. Remove the stale entry."
                )
    return claimed_total


def cross_check_comparison(
    documents: dict[str, Any], errors: list[str]
) -> None:
    """Confirm the derived comparison artifact still agrees with its sources."""
    comparison = documents.get("comparison")
    if comparison is None:
        return
    fields = (
        "n",
        "success_count",
        "success_rate",
        "wall_s_p50",
        "wall_s_p95",
        "cost_usd_per_run",
        "cost_usd_total",
    )
    for name in ("openemr", "mockmed"):
        source = documents.get(name)
        if source is None:
            continue
        try:
            derived = comparison["benchmarks"][name]["arms"]
        except (KeyError, TypeError):
            errors.append(f"comparison artifact has no {name} arms")
            continue
        for arm in ("compiled", "agent"):
            for field in fields:
                try:
                    left = derived[arm][field]
                    right = source["arms"][arm][field]
                except (KeyError, TypeError):
                    errors.append(f"{name} {arm} {field} is missing from an artifact")
                    continue
                if left != right:
                    errors.append(
                        f"{name} {arm} {field}: the comparison artifact says {left!r}, "
                        f"but the measured results say {right!r}"
                    )


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "OpenAdapt-benchmark-claims/1"}
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        return response.read()


def check_online(
    registry: dict[str, Any], errors: list[str], warnings: list[str]
) -> int:
    """Re-fetch each pinned path and compare it to the vendored snapshot.

    GitHub being unreachable is an outage, not evidence of drift, so it warns.
    A successful fetch whose digest differs is drift, and it fails.
    """
    upstream = registry["upstream"]
    verified = 0
    for source in upstream["sources"]:
        url = (
            f"{RAW_GITHUB_ORIGIN}/{upstream['repository']}/"
            f"{upstream['commit']}/{source['path']}"
        )
        try:
            payload = fetch(url)
        except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            warnings.append(f"source {source['id']}: {url} is unreachable: {exc}")
            continue
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if digest != source["sha256"]:
            errors.append(
                f"source {source['id']}: {url} returned digest {digest}, but the "
                f"vendored snapshot is {source['sha256']}. The pin no longer "
                "describes the upstream bytes."
            )
            continue
        verified += 1
    return verified


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to check (default: this repository)",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="also re-fetch each pinned upstream path and compare digests",
    )
    parser.add_argument(
        "--allow-recorded-drift",
        action="store_true",
        help=(
            "exit 0 when the only failures are dated drift records already in the "
            "registry; every such record is still printed and still expires"
        ),
    )
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=datetime.now(timezone.utc).date(),
        help="evaluate drift expiry against this date (YYYY-MM-DD)",
    )
    arguments = parser.parse_args(argv)

    root: Path = arguments.root
    errors: list[str] = []
    warnings: list[str] = []
    drifts: list[str] = []

    try:
        registry = load_registry(root / REGISTRY_PATH.name)
    except RegistryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    documents = verify_snapshots(root, registry, errors)
    cross_check_comparison(documents, errors)

    surfaces: dict[str, str] = {}
    for surface in registry["surfaces"]:
        path = root / surface
        try:
            surfaces[surface] = normalize(path.read_text(encoding="utf-8"))
        except OSError as exc:
            errors.append(f"cannot read registered surface {surface}: {exc}")

    spans = check_claims(
        registry, documents, surfaces, arguments.today, errors, drifts
    )
    claimed = sweep(surfaces, spans, errors)

    verified_online = check_online(registry, errors, warnings) if arguments.online else 0

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for drift in drifts:
        print(f"DRIFT: {drift}", file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    if errors:
        return 1
    if drifts and not arguments.allow_recorded_drift:
        print(
            "ERROR: a published figure does not match its artifact. Pass "
            "--allow-recorded-drift only where a dated correction is already "
            "tracked.",
            file=sys.stderr,
        )
        return 1

    summary = (
        f"Bound {claimed} published figures across {len(surfaces)} surfaces to "
        f"{len(documents)} pinned artifacts"
    )
    if arguments.online:
        summary += f"; re-fetched {verified_online} of {len(documents)} upstream paths"
    if drifts:
        summary += f"; {len(drifts)} dated drift record(s) still open"
    print(summary + ".")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
