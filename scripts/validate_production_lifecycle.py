#!/usr/bin/env python3
"""Validate evidence-gated Production lifecycle assignments.

The public lifecycle is a derived state.  A repository or public surface can
appear in the Production group only while one exact, independently attested
admission is active.  The admission binds a release, its artifacts, and a
remote-safe acceptance summary.  The summary binds the private acceptance
certificate by digest only; it never publishes the private certificate or its
location.

No network request occurs while the admissions list is empty.  A Production
admission fails closed unless the referenced summary, attestation bundle, and
evidence manifest can all be fetched, hashed, and verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "production-lifecycle-policy.json"
ADMISSIONS_PATH = ROOT / "production-lifecycle-admissions.json"
LIFECYCLE_PATH = ROOT / "repository-lifecycle.yml"

POLICY_SCHEMA = "openadapt.production-lifecycle-policy/v1"
ADMISSIONS_SCHEMA = "openadapt.production-lifecycle-admissions/v1"
SUMMARY_SCHEMA = "openadapt.production-lifecycle-evidence-summary/v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
TARGET_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
GROUP_RE = re.compile(r"^  ([a-z_]+):(?: \[\])?$")
REPOSITORY_RE = re.compile(r"^    - (\S+)$")
MAX_REMOTE_BYTES = 2 * 1024 * 1024


class LifecycleError(ValueError):
    """The lifecycle state is not supported by its evidence."""


def _closed(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise LifecycleError(
            f"{label} must contain exactly {sorted(keys)}; got {actual}"
        )
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise LifecycleError(f"{label} must be a non-empty trimmed string")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise LifecycleError(f"{label} must be a lowercase sha256 digest")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or "." in value:
        raise LifecycleError(f"{label} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise LifecycleError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LifecycleError(f"{label} must use UTC")
    return parsed.astimezone(timezone.utc)


def _canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    return _bytes_digest(path.read_bytes())


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"{label} is missing or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must be a JSON object")
    return value


def _parse_group(text: str, heading: str) -> dict[str, list[str]]:
    section = text.split(f"{heading}:\n", maxsplit=1)
    if len(section) != 2:
        raise LifecycleError(f"repository-lifecycle.yml is missing {heading}")
    groups: dict[str, list[str]] = {}
    active: str | None = None
    for line in section[1].splitlines():
        if match := GROUP_RE.fullmatch(line):
            active = match.group(1)
            groups[active] = []
        elif match := REPOSITORY_RE.fullmatch(line):
            if active is None:
                raise LifecycleError(f"{heading} contains a subject outside a group")
            groups[active].append(match.group(1))
        elif line and not line.startswith(" "):
            break
    return groups


def load_lifecycle(
    path: Path = LIFECYCLE_PATH,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LifecycleError(f"repository-lifecycle.yml is missing: {exc}") from exc
    return _parse_group(text, "lifecycle"), _parse_group(text, "public_surfaces")


def _validate_policy(value: object) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    policy = _closed(
        value,
        {
            "$schema",
            "schema_version",
            "revision",
            "maximum_admission_days",
            "summary_authority",
            "targets",
        },
        "production lifecycle policy",
    )
    if policy["schema_version"] != POLICY_SCHEMA:
        raise LifecycleError("production lifecycle policy schema is not supported")
    if (
        not isinstance(policy["revision"], int)
        or isinstance(policy["revision"], bool)
        or policy["revision"] < 1
    ):
        raise LifecycleError("production lifecycle policy revision must be positive")
    maximum_days = policy["maximum_admission_days"]
    if (
        not isinstance(maximum_days, int)
        or isinstance(maximum_days, bool)
        or not 1 <= maximum_days <= 30
    ):
        raise LifecycleError("maximum_admission_days must be between 1 and 30")
    authority = _closed(
        policy["summary_authority"],
        {
            "repository",
            "workflow",
            "source_ref",
            "oidc_issuer",
            "certificate_identity",
            "summary_schema_version",
            "private_certificate_schema_version",
        },
        "summary authority",
    )
    if authority["summary_schema_version"] != SUMMARY_SCHEMA:
        raise LifecycleError("summary authority schema is not supported")
    if authority["source_ref"] != "refs/heads/main":
        raise LifecycleError("summary authority must use refs/heads/main")
    if authority["oidc_issuer"] != "https://token.actions.githubusercontent.com":
        raise LifecycleError("summary authority OIDC issuer is not approved")
    repository = _nonempty(authority["repository"], "summary authority repository")
    workflow = _nonempty(authority["workflow"], "summary authority workflow")
    expected_identity = f"https://github.com/{repository}/{workflow}@refs/heads/main"
    if authority["certificate_identity"] != expected_identity:
        raise LifecycleError("summary authority certificate identity is not exact")
    _nonempty(
        authority["private_certificate_schema_version"],
        "private certificate schema version",
    )

    targets_value = policy["targets"]
    if not isinstance(targets_value, list) or not targets_value:
        raise LifecycleError("production lifecycle policy must declare targets")
    targets: dict[str, dict[str, Any]] = {}
    memberships: set[tuple[str, str]] = set()
    for index, item in enumerate(targets_value):
        target = _closed(
            item,
            {
                "id",
                "display_name",
                "lifecycle_scope",
                "lifecycle_subject",
                "source_repository",
                "release_kind",
                "required_artifact_kinds",
            },
            f"target {index}",
        )
        target_id = _nonempty(target["id"], f"target {index} id")
        if TARGET_ID.fullmatch(target_id) is None or target_id in targets:
            raise LifecycleError(f"target id is invalid or duplicate: {target_id!r}")
        scope = target["lifecycle_scope"]
        if scope not in {"repository", "public_surface"}:
            raise LifecycleError(f"target {target_id} lifecycle_scope is invalid")
        subject = _nonempty(target["lifecycle_subject"], f"target {target_id} subject")
        membership = (scope, subject)
        if membership in memberships:
            raise LifecycleError(f"lifecycle subject is duplicate: {membership}")
        memberships.add(membership)
        _nonempty(target["display_name"], f"target {target_id} display name")
        source_repository = _nonempty(
            target["source_repository"], f"target {target_id} source repository"
        )
        if not source_repository.startswith("OpenAdaptAI/"):
            raise LifecycleError(
                f"target {target_id} source repository is not first-party"
            )
        release_kind = target["release_kind"]
        if release_kind not in {
            "public_package",
            "private_deployment",
            "public_deployment",
        }:
            raise LifecycleError(f"target {target_id} release kind is invalid")
        kinds = target["required_artifact_kinds"]
        if not isinstance(kinds, list) or not all(
            isinstance(kind, str) and kind for kind in kinds
        ):
            raise LifecycleError(
                f"target {target_id} required artifact kinds are invalid"
            )
        if kinds != sorted(set(kinds)):
            raise LifecycleError(
                f"target {target_id} required artifact kinds must be unique and sorted"
            )
        if release_kind == "private_deployment" and kinds:
            raise LifecycleError(
                f"private target {target_id} cannot require public artifacts"
            )
        if release_kind != "private_deployment" and not kinds:
            raise LifecycleError(f"public target {target_id} must require artifacts")
        targets[target_id] = target
    expected_ids = {"openadapt", "flow", "desktop", "cloud", "capture", "agent", "docs"}
    if set(targets) != expected_ids:
        raise LifecycleError(
            f"production target inventory must be exact: {sorted(expected_ids)}"
        )
    return policy, targets


def _validate_url(
    value: object, digest: str, label: str, source_commit: str | None = None
) -> str:
    url = _nonempty(value, label)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise LifecycleError(f"{label} must be a clean HTTPS URL")
    path_parts = [part for part in parsed.path.split("/") if part]
    digest_hex = digest.removeprefix("sha256:")
    digest_bound = any(digest_hex == part or digest_hex in part for part in path_parts)
    commit_bound = source_commit is not None and source_commit in path_parts
    if not digest_bound and not commit_bound:
        raise LifecycleError(f"{label} is not bound to its digest or source commit")
    return url


def _validate_artifacts(
    value: object,
    *,
    required_kinds: Sequence[str],
    source_commit: str,
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise LifecycleError(f"{label} must be a list")
    artifacts: list[dict[str, Any]] = []
    identities: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        artifact = _closed(
            item,
            {"name", "kind", "url", "sha256", "size_bytes"},
            f"{label} item {index}",
        )
        name = _nonempty(artifact["name"], f"{label} item {index} name")
        if ARTIFACT_NAME.fullmatch(name) is None:
            raise LifecycleError(f"{label} item {index} name is invalid")
        kind = _nonempty(artifact["kind"], f"{label} item {index} kind")
        digest = _digest(artifact["sha256"], f"{label} item {index} digest")
        _validate_url(
            artifact["url"], digest, f"{label} item {index} URL", source_commit
        )
        size = artifact["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise LifecycleError(f"{label} item {index} size must be positive")
        identities.append((kind, name))
        artifacts.append(artifact)
    if identities != sorted(set(identities)):
        raise LifecycleError(f"{label} must be unique and sorted by kind then name")
    present = {kind for kind, _ in identities}
    missing = sorted(set(required_kinds) - present)
    if missing:
        raise LifecycleError(f"{label} is missing required artifact kinds: {missing}")
    return artifacts


def _validate_release(value: object, target: Mapping[str, Any]) -> dict[str, Any]:
    target_id = target["id"]
    kind = target["release_kind"]
    if kind == "public_package":
        release = _closed(
            value,
            {
                "kind",
                "version",
                "tag",
                "source_commit",
                "immutable_release_url",
                "artifacts",
            },
            f"admission {target_id} release",
        )
        if (
            release["kind"] != kind
            or not isinstance(release["version"], str)
            or SEMVER.fullmatch(release["version"]) is None
        ):
            raise LifecycleError(
                f"admission {target_id} public package version is invalid"
            )
        if release["tag"] not in {f"v{release['version']}", release["version"]}:
            raise LifecycleError(
                f"admission {target_id} release tag does not match version"
            )
        source_commit = release["source_commit"]
        if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
            raise LifecycleError(f"admission {target_id} source commit is invalid")
        source_digest = (
            "sha256:" + hashlib.sha256(source_commit.encode("ascii")).hexdigest()
        )
        release_url = _validate_url(
            release["immutable_release_url"],
            source_digest,
            f"admission {target_id} immutable release URL",
            source_commit,
        )
        parsed_release = urlsplit(release_url)
        expected_prefix = f"/{target['source_repository']}/commit/{source_commit}"
        if (
            parsed_release.netloc != "github.com"
            or parsed_release.path.rstrip("/") != expected_prefix
        ):
            raise LifecycleError(
                f"admission {target_id} immutable release URL is not the exact source commit"
            )
        _validate_artifacts(
            release["artifacts"],
            required_kinds=target["required_artifact_kinds"],
            source_commit=source_commit,
            label=f"admission {target_id} artifacts",
        )
        return release
    if kind == "public_deployment":
        release = _closed(
            value,
            {
                "kind",
                "deployment_id",
                "deployment_sha256",
                "source_commit",
                "immutable_release_url",
                "artifacts",
            },
            f"admission {target_id} release",
        )
        if release["kind"] != kind:
            raise LifecycleError(
                f"admission {target_id} release kind differs from policy"
            )
        _nonempty(release["deployment_id"], f"admission {target_id} deployment id")
        _digest(
            release["deployment_sha256"], f"admission {target_id} deployment digest"
        )
        source_commit = release["source_commit"]
        if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
            raise LifecycleError(f"admission {target_id} source commit is invalid")
        release_url = _validate_url(
            release["immutable_release_url"],
            release["deployment_sha256"],
            f"admission {target_id} immutable release URL",
            source_commit,
        )
        parsed_release = urlsplit(release_url)
        expected_prefix = f"/{target['source_repository']}/commit/{source_commit}"
        if (
            parsed_release.netloc != "github.com"
            or parsed_release.path.rstrip("/") != expected_prefix
        ):
            raise LifecycleError(
                f"admission {target_id} immutable release URL is not the exact source commit"
            )
        _validate_artifacts(
            release["artifacts"],
            required_kinds=target["required_artifact_kinds"],
            source_commit=source_commit,
            label=f"admission {target_id} artifacts",
        )
        return release
    release = _closed(
        value,
        {
            "kind",
            "deployment_release_id",
            "deployment_release_sha256",
            "manifest_sha256",
        },
        f"admission {target_id} release",
    )
    if release["kind"] != "private_deployment":
        raise LifecycleError(f"admission {target_id} release kind differs from policy")
    _nonempty(
        release["deployment_release_id"], f"admission {target_id} deployment release id"
    )
    _digest(
        release["deployment_release_sha256"],
        f"admission {target_id} deployment release digest",
    )
    _digest(
        release["manifest_sha256"], f"admission {target_id} deployment manifest digest"
    )
    return release


def _fetch_url(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "openadapt-production-lifecycle-validator/1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > MAX_REMOTE_BYTES:
            raise LifecycleError("remote lifecycle evidence exceeds the size limit")
        body = response.read(MAX_REMOTE_BYTES + 1)
    if len(body) > MAX_REMOTE_BYTES:
        raise LifecycleError("remote lifecycle evidence exceeds the size limit")
    return body


def _verify_attestation(
    summary: bytes,
    bundle: bytes,
    authority: Mapping[str, Any],
    source_commit: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="openadapt-lifecycle-") as directory:
        root = Path(directory)
        summary_path = root / "production-lifecycle-evidence-summary.json"
        bundle_path = root / "production-lifecycle-evidence-summary.sigstore.json"
        summary_path.write_bytes(summary)
        bundle_path.write_bytes(bundle)
        command = [
            "gh",
            "attestation",
            "verify",
            str(summary_path),
            "--repo",
            authority["repository"],
            "--bundle",
            str(bundle_path),
            "--cert-identity",
            authority["certificate_identity"],
            "--cert-oidc-issuer",
            authority["oidc_issuer"],
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ]
        try:
            completed = subprocess.run(
                command, check=False, capture_output=True, text=True
            )
        except OSError as exc:
            raise LifecycleError(
                f"summary attestation verifier could not run: {exc}"
            ) from exc
        if completed.returncode != 0:
            detail = (
                completed.stderr or completed.stdout or "verification failed"
            ).strip()
            raise LifecycleError(
                f"summary attestation is invalid: {detail.splitlines()[-1]}"
            )
        try:
            result = json.loads(completed.stdout)
            if not isinstance(result, list) or len(result) != 1:
                raise LifecycleError(
                    "summary attestation must contain one verified statement"
                )
            verification = result[0]["verificationResult"]
            certificate = verification["signature"]["certificate"]
            statement = verification["statement"]
            workflow_sha = certificate["githubWorkflowSHA"]
            source_digest = certificate["sourceRepositoryDigest"]
            workflow_ref = certificate["githubWorkflowRef"]
            workflow_repository = certificate["githubWorkflowRepository"]
            dependencies = statement["predicate"]["buildDefinition"][
                "resolvedDependencies"
            ]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LifecycleError(
                "summary attestation verifier returned an invalid statement"
            ) from exc
        if workflow_sha != source_commit or source_digest != source_commit:
            raise LifecycleError("summary attestation source commit differs")
        if (
            workflow_ref != authority["source_ref"]
            or workflow_repository != authority["repository"]
        ):
            raise LifecycleError("summary attestation workflow identity differs")
        expected_dependency = {
            "uri": f"git+https://github.com/{authority['repository']}@{authority['source_ref']}",
            "digest": {"gitCommit": source_commit},
        }
        if dependencies != [expected_dependency]:
            raise LifecycleError("summary attestation source dependency differs")


def _validate_remote_summary(
    admission: Mapping[str, Any],
    release: Mapping[str, Any],
    authority: Mapping[str, Any],
    *,
    fetch: Callable[[str], bytes],
    verify_attestation: Callable[[bytes, bytes, Mapping[str, Any], str], None],
) -> None:
    target_id = admission["target"]
    reference = _closed(
        admission["acceptance_evidence"],
        {
            "summary_url",
            "summary_sha256",
            "attestation_bundle_url",
            "attestation_bundle_sha256",
            "authority_source_commit",
        },
        f"admission {target_id} acceptance evidence",
    )
    summary_digest = _digest(
        reference["summary_sha256"], f"admission {target_id} summary digest"
    )
    bundle_digest = _digest(
        reference["attestation_bundle_sha256"],
        f"admission {target_id} attestation digest",
    )
    authority_commit = reference["authority_source_commit"]
    if (
        not isinstance(authority_commit, str)
        or HEX40.fullmatch(authority_commit) is None
    ):
        raise LifecycleError(
            f"admission {target_id} authority source commit is invalid"
        )
    summary_url = _validate_url(
        reference["summary_url"],
        summary_digest,
        f"admission {target_id} summary URL",
        authority_commit,
    )
    bundle_url = _validate_url(
        reference["attestation_bundle_url"],
        bundle_digest,
        f"admission {target_id} attestation bundle URL",
        authority_commit,
    )
    try:
        summary_bytes = fetch(summary_url)
        bundle_bytes = fetch(bundle_url)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise LifecycleError(
            f"admission {target_id} evidence could not be fetched: {exc}"
        ) from exc
    if _bytes_digest(summary_bytes) != summary_digest:
        raise LifecycleError(f"admission {target_id} summary digest changed")
    if _bytes_digest(bundle_bytes) != bundle_digest:
        raise LifecycleError(f"admission {target_id} attestation bundle digest changed")
    verify_attestation(summary_bytes, bundle_bytes, authority, authority_commit)
    try:
        summary_value = json.loads(summary_bytes)
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"admission {target_id} summary is not JSON") from exc
    summary = _closed(
        summary_value,
        {
            "schema_version",
            "target",
            "verdict",
            "release_sha256",
            "artifact_inventory_sha256",
            "private_certificate_binding",
            "evidence_manifest",
            "issued_at",
            "expires_at",
            "revoked_at",
        },
        f"admission {target_id} remote-safe summary",
    )
    if summary["schema_version"] != authority["summary_schema_version"]:
        raise LifecycleError(f"admission {target_id} summary schema is not supported")
    if summary["target"] != target_id or summary["verdict"] != "accepted":
        raise LifecycleError(
            f"admission {target_id} summary did not accept the exact target"
        )
    if summary["release_sha256"] != _canonical_digest(release):
        raise LifecycleError(f"admission {target_id} summary release digest differs")
    artifacts = release.get("artifacts", [])
    if summary["artifact_inventory_sha256"] != _canonical_digest(artifacts):
        raise LifecycleError(
            f"admission {target_id} summary artifact inventory differs"
        )
    certificate = _closed(
        summary["private_certificate_binding"],
        {"schema_version", "sha256", "signer_provenance_sha256"},
        f"admission {target_id} private certificate binding",
    )
    if certificate["schema_version"] != authority["private_certificate_schema_version"]:
        raise LifecycleError(
            f"admission {target_id} private certificate schema differs"
        )
    _digest(certificate["sha256"], f"admission {target_id} private certificate digest")
    _digest(
        certificate["signer_provenance_sha256"],
        f"admission {target_id} private certificate signer provenance",
    )
    manifest = _closed(
        summary["evidence_manifest"],
        {"schema_version", "url", "sha256"},
        f"admission {target_id} evidence manifest",
    )
    manifest_schema = _nonempty(
        manifest["schema_version"], f"admission {target_id} evidence manifest schema"
    )
    manifest_digest = _digest(
        manifest["sha256"], f"admission {target_id} evidence manifest digest"
    )
    manifest_url = _validate_url(
        manifest["url"], manifest_digest, f"admission {target_id} evidence manifest URL"
    )
    try:
        manifest_bytes = fetch(manifest_url)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise LifecycleError(
            f"admission {target_id} evidence manifest could not be fetched: {exc}"
        ) from exc
    if _bytes_digest(manifest_bytes) != manifest_digest:
        raise LifecycleError(f"admission {target_id} evidence manifest digest changed")
    try:
        manifest_value = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise LifecycleError(
            f"admission {target_id} evidence manifest is not JSON"
        ) from exc
    if (
        not isinstance(manifest_value, dict)
        or manifest_value.get("schema_version") != manifest_schema
    ):
        raise LifecycleError(f"admission {target_id} evidence manifest schema differs")
    for key in ("issued_at", "expires_at", "revoked_at"):
        if summary[key] != admission[key]:
            raise LifecycleError(
                f"admission {target_id} {key} differs from signed summary"
            )


def validate(
    policy_value: object,
    admissions_value: object,
    repository_lifecycle: Mapping[str, Sequence[str]],
    surface_lifecycle: Mapping[str, Sequence[str]],
    *,
    policy_sha256: str,
    now: datetime | None = None,
    fetch: Callable[[str], bytes] = _fetch_url,
    verify_attestation: Callable[
        [bytes, bytes, Mapping[str, Any], str], None
    ] = _verify_attestation,
) -> dict[str, str]:
    """Validate the complete lifecycle state and return target to admission IDs."""

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    policy, targets = _validate_policy(policy_value)
    admissions_doc = _closed(
        admissions_value,
        {"$schema", "schema_version", "policy_sha256", "admissions"},
        "production lifecycle admissions",
    )
    if admissions_doc["schema_version"] != ADMISSIONS_SCHEMA:
        raise LifecycleError("production lifecycle admissions schema is not supported")
    if admissions_doc["policy_sha256"] != policy_sha256:
        raise LifecycleError("production lifecycle admissions policy digest differs")
    admissions_value_list = admissions_doc["admissions"]
    if not isinstance(admissions_value_list, list):
        raise LifecycleError("production lifecycle admissions must be a list")
    active: dict[str, str] = {}
    admission_ids: set[str] = set()
    for index, item in enumerate(admissions_value_list):
        admission = _closed(
            item,
            {
                "admission_id",
                "target",
                "policy_revision",
                "release",
                "acceptance_evidence",
                "issued_at",
                "expires_at",
                "revoked_at",
            },
            f"admission {index}",
        )
        admission_id = _nonempty(admission["admission_id"], f"admission {index} id")
        if admission_id in admission_ids:
            raise LifecycleError(
                f"production admission id is duplicate: {admission_id!r}"
            )
        admission_ids.add(admission_id)
        target_id = _nonempty(admission["target"], f"admission {index} target")
        if target_id not in targets:
            raise LifecycleError(
                f"production admission target is not eligible: {target_id!r}"
            )
        if target_id in active:
            raise LifecycleError(
                f"production target has multiple active records: {target_id!r}"
            )
        if admission["policy_revision"] != policy["revision"]:
            raise LifecycleError(f"admission {target_id} policy revision differs")
        issued_at = _timestamp(
            admission["issued_at"], f"admission {target_id} issued_at"
        )
        expires_at = _timestamp(
            admission["expires_at"], f"admission {target_id} expires_at"
        )
        if issued_at > now:
            raise LifecycleError(f"admission {target_id} is not valid yet")
        if expires_at <= issued_at or expires_at > issued_at + timedelta(
            days=policy["maximum_admission_days"]
        ):
            raise LifecycleError(
                f"admission {target_id} validity window is outside policy"
            )
        if expires_at <= now:
            raise LifecycleError(f"admission {target_id} is expired")
        revoked_at = admission["revoked_at"]
        if revoked_at is not None:
            revoked = _timestamp(revoked_at, f"admission {target_id} revoked_at")
            if revoked < issued_at or revoked > now:
                raise LifecycleError(
                    f"admission {target_id} revocation timestamp is invalid"
                )
            raise LifecycleError(f"admission {target_id} is revoked")
        release = _validate_release(admission["release"], targets[target_id])
        _validate_remote_summary(
            admission,
            release,
            policy["summary_authority"],
            fetch=fetch,
            verify_attestation=verify_attestation,
        )
        active[target_id] = admission_id

    expected_repositories = sorted(
        target["lifecycle_subject"]
        for target_id, target in targets.items()
        if target_id in active and target["lifecycle_scope"] == "repository"
    )
    expected_surfaces = sorted(
        target["lifecycle_subject"]
        for target_id, target in targets.items()
        if target_id in active and target["lifecycle_scope"] == "public_surface"
    )
    actual_repositories = sorted(repository_lifecycle.get("production", []))
    actual_surfaces = sorted(surface_lifecycle.get("production", []))
    if actual_repositories != expected_repositories:
        raise LifecycleError(
            "Production repository memberships differ from active admissions: "
            f"expected {expected_repositories}, got {actual_repositories}"
        )
    if actual_surfaces != expected_surfaces:
        raise LifecycleError(
            "Production public-surface memberships differ from active admissions: "
            f"expected {expected_surfaces}, got {actual_surfaces}"
        )
    for target_id, target in targets.items():
        lifecycle = (
            repository_lifecycle
            if target["lifecycle_scope"] == "repository"
            else surface_lifecycle
        )
        memberships = [
            group
            for group, subjects in lifecycle.items()
            if target["lifecycle_subject"] in subjects
        ]
        expected_group = "production" if target_id in active else None
        if len(memberships) != 1:
            raise LifecycleError(
                f"target {target_id} must have exactly one lifecycle membership; got {memberships}"
            )
        if expected_group is not None and memberships != [expected_group]:
            raise LifecycleError(
                f"target {target_id} active admission requires Production membership"
            )
    return active


def validate_files(root: Path = ROOT, *, now: datetime | None = None) -> dict[str, str]:
    policy_path = root / POLICY_PATH.name
    admissions_path = root / ADMISSIONS_PATH.name
    policy = _load_json(policy_path, policy_path.name)
    admissions = _load_json(admissions_path, admissions_path.name)
    repositories, surfaces = load_lifecycle(root / LIFECYCLE_PATH.name)
    return validate(
        policy,
        admissions,
        repositories,
        surfaces,
        policy_sha256=_file_digest(policy_path),
        now=now,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        active = validate_files(args.root)
    except LifecycleError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(
        "Validated evidence-gated Production lifecycle: "
        f"{len(active)} active admission(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
