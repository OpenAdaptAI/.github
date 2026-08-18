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
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "production-lifecycle-policy.json"
ADMISSIONS_PATH = ROOT / "production-lifecycle-admissions.json"
LIFECYCLE_PATH = ROOT / "repository-lifecycle.yml"

POLICY_SCHEMA = "openadapt.production-lifecycle-policy/v1"
ADMISSIONS_SCHEMA = "openadapt.production-lifecycle-admissions/v1"
SUMMARY_SCHEMA = "openadapt.production-lifecycle-evidence-summary/v1"
RELEASE_IDENTITY_SCHEMA = "openadapt.monotonic-production-release/v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
TARGET_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
GROUP_RE = re.compile(r"^  ([a-z_]+):(?: \[\])?$")
REPOSITORY_RE = re.compile(r"^    - (\S+)$")
MAX_REMOTE_BYTES = 2 * 1024 * 1024
FAILURE_TAXONOMY_KEYS = {
    "collateral_effect",
    "duplicate_effect",
    "healthy_path_model_call",
    "operator_intervention",
    "over_halt",
    "platform_failure",
    "safe_halt",
    "silent_incorrect_success",
    "uncertain_delivery",
    "verified",
    "wrong_record",
}
RELIABILITY_TO_TAXONOMY = {
    "silent_incorrect_success_count": "silent_incorrect_success",
    "over_halt_count": "over_halt",
    "wrong_record_count": "wrong_record",
    "duplicate_effect_count": "duplicate_effect",
    "collateral_effect_count": "collateral_effect",
    "operator_intervention_count": "operator_intervention",
    "uncertain_delivery_count": "uncertain_delivery",
    "model_call_count": "healthy_path_model_call",
}
RETENTION_DIGEST_KEYS = {
    "ciphertext_sha256",
    "candidate_sha256",
    "private_envelope_sha256",
    "store_attestation_sha256",
    "storage_identity_sha256",
    "object_version_sha256",
    "private_locator_version_sha256",
    "kms_key_identity_sha256",
    "uploader_identity_sha256",
}
EXPECTED_AUTHORITY = {
    "repository": "OpenAdaptAI/openadapt-evals",
    "workflow": ".github/workflows/production-lifecycle-evidence.yml",
    "source_ref": "refs/heads/main",
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "certificate_identity": (
        "https://github.com/OpenAdaptAI/openadapt-evals/.github/workflows/"
        "production-lifecycle-evidence.yml@refs/heads/main"
    ),
    "summary_schema_version": SUMMARY_SCHEMA,
    "private_certificate_schema_version": "openadapt.execute-live-acceptance-record/v2",
    "evidence_manifest_schema_version": ("openadapt.production-acceptance/v1"),
    "release_identity_schema_version": RELEASE_IDENTITY_SCHEMA,
    "production_channel": "production",
    "signer_provenance_digest_domain": (
        "OpenAdapt production certificate signer provenance v1\0"
    ),
}
EXPECTED_TARGETS = {
    "agent": {
        "display_name": "OpenAdapt Agent",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "openadapt-agent",
        "source_repository": "OpenAdaptAI/openadapt-agent",
        "release_kind": "public_package",
        "required_claim_scope": "qualified_agent_bridge_release",
        "required_artifact_kinds": ["sdist", "wheel"],
        "package_index_project": "openadapt-agent",
        "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
    },
    "capture": {
        "display_name": "OpenAdapt Capture",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "openadapt-capture",
        "source_repository": "OpenAdaptAI/openadapt-capture",
        "release_kind": "public_package",
        "required_claim_scope": "qualified_native_recorder_release",
        "required_artifact_kinds": ["sdist", "wheel"],
        "package_index_project": "openadapt-capture",
        "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
    },
    "cloud": {
        "display_name": "OpenAdapt Cloud",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "openadapt-cloud",
        "source_repository": "OpenAdaptAI/openadapt-cloud",
        "release_kind": "private_deployment",
        "required_claim_scope": "qualified_workflow_control_plane_deployment",
        "required_artifact_kinds": [],
        "package_index_project": None,
        "artifact_authority_by_kind": {},
    },
    "desktop": {
        "display_name": "OpenAdapt Desktop",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "openadapt-desktop",
        "source_repository": "OpenAdaptAI/openadapt-desktop",
        "release_kind": "public_package",
        "required_claim_scope": "qualified_native_workflow_desktop_release",
        "required_artifact_kinds": [
            "linux-installer",
            "macos-installer",
            "sdist",
            "wheel",
            "windows-installer",
        ],
        "package_index_project": "openadapt-desktop",
        "artifact_authority_by_kind": {
            "linux-installer": "github_release",
            "macos-installer": "github_release",
            "sdist": "pypi",
            "wheel": "pypi",
            "windows-installer": "github_release",
        },
    },
    "docs": {
        "display_name": "OpenAdapt Documentation",
        "lifecycle_scope": "public_surface",
        "lifecycle_subject": "docs.openadapt.ai",
        "source_repository": "OpenAdaptAI/openadapt-ops",
        "release_kind": "public_deployment",
        "required_claim_scope": "production_documentation_deployment",
        "required_artifact_kinds": ["deployment-manifest", "site-archive"],
        "package_index_project": None,
        "artifact_authority_by_kind": {
            "deployment-manifest": "managed_evidence",
            "site-archive": "managed_evidence",
        },
    },
    "flow": {
        "display_name": "OpenAdapt Flow",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "openadapt-flow",
        "source_repository": "OpenAdaptAI/openadapt-flow",
        "release_kind": "public_package",
        "required_claim_scope": "qualified_workflow_runtime_release",
        "required_artifact_kinds": ["sdist", "wheel"],
        "package_index_project": "openadapt-flow",
        "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
    },
    "openadapt": {
        "display_name": "OpenAdapt",
        "lifecycle_scope": "repository",
        "lifecycle_subject": "OpenAdapt",
        "source_repository": "OpenAdaptAI/OpenAdapt",
        "release_kind": "public_package",
        "required_claim_scope": "qualified_workflow_launcher_release",
        "required_artifact_kinds": ["sdist", "wheel"],
        "package_index_project": "openadapt",
        "artifact_authority_by_kind": {"sdist": "pypi", "wheel": "pypi"},
    },
}


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
            "evidence_manifest_schema_version",
            "release_identity_schema_version",
            "production_channel",
            "signer_provenance_digest_domain",
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
    if authority["evidence_manifest_schema_version"] != (
        "openadapt.production-acceptance/v1"
    ):
        raise LifecycleError("evidence manifest schema is not supported")
    if authority["signer_provenance_digest_domain"] != (
        "OpenAdapt production certificate signer provenance v1\0"
    ):
        raise LifecycleError("signer provenance digest domain is not supported")
    if authority != EXPECTED_AUTHORITY:
        raise LifecycleError("summary authority differs from the pinned trust root")

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
                "required_claim_scope",
                "required_artifact_kinds",
                "package_index_project",
                "artifact_authority_by_kind",
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
        claim_scope = _nonempty(
            target["required_claim_scope"],
            f"target {target_id} required claim scope",
        )
        if re.fullmatch(r"^[a-z][a-z0-9_]{2,127}$", claim_scope) is None:
            raise LifecycleError(f"target {target_id} required claim scope is invalid")
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
        package_project = target["package_index_project"]
        if package_project is not None and (
            not isinstance(package_project, str)
            or re.fullmatch(r"^[a-z0-9][a-z0-9._-]+$", package_project) is None
        ):
            raise LifecycleError(f"target {target_id} package project is invalid")
        authorities = target["artifact_authority_by_kind"]
        if not isinstance(authorities, dict) or set(authorities) != set(kinds):
            raise LifecycleError(
                f"target {target_id} artifact authority map differs from artifact kinds"
            )
        if not all(
            value in {"pypi", "github_release", "managed_evidence"}
            for value in authorities.values()
        ):
            raise LifecycleError(f"target {target_id} artifact authority is invalid")
        if ("pypi" in authorities.values()) != (package_project is not None):
            raise LifecycleError(
                f"target {target_id} package project does not match PyPI authority"
            )
        targets[target_id] = target
    actual_targets = {
        target_id: {key: value for key, value in target.items() if key != "id"}
        for target_id, target in targets.items()
    }
    if actual_targets != EXPECTED_TARGETS:
        raise LifecycleError("production target map differs from the pinned target map")
    return policy, targets


def _clean_https_url(value: object, label: str) -> str:
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
    return url


def _validate_url(
    value: object, digest: str, label: str, source_commit: str | None = None
) -> str:
    url = _clean_https_url(value, label)
    parsed = urlsplit(url)
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
    authority_by_kind: Mapping[str, str],
    source_repository: str,
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise LifecycleError(f"{label} must be a list")
    artifacts: list[dict[str, Any]] = []
    identities: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        artifact = _closed(
            item,
            {"name", "kind", "authority", "url", "sha256", "size_bytes"},
            f"{label} item {index}",
        )
        name = _nonempty(artifact["name"], f"{label} item {index} name")
        if ARTIFACT_NAME.fullmatch(name) is None:
            raise LifecycleError(f"{label} item {index} name is invalid")
        kind = _nonempty(artifact["kind"], f"{label} item {index} kind")
        artifact_authority = artifact["authority"]
        if artifact_authority != authority_by_kind.get(kind):
            raise LifecycleError(f"{label} item {index} authority differs from policy")
        digest = _digest(artifact["sha256"], f"{label} item {index} digest")
        artifact_url = _clean_https_url(artifact["url"], f"{label} item {index} URL")
        parsed_artifact_url = urlsplit(artifact_url)
        if artifact_authority == "pypi" and (
            parsed_artifact_url.netloc != "files.pythonhosted.org"
        ):
            raise LifecycleError(f"{label} item {index} is not a PyPI artifact")
        if artifact_authority == "github_release":
            expected_prefix = f"/repos/{source_repository}/releases/assets/"
            asset_id = parsed_artifact_url.path.removeprefix(expected_prefix)
            if (
                parsed_artifact_url.netloc != "api.github.com"
                or not parsed_artifact_url.path.startswith(expected_prefix)
                or not asset_id.isdigit()
            ):
                raise LifecycleError(
                    f"{label} item {index} is not an exact GitHub release asset"
                )
        if artifact_authority == "managed_evidence" and (
            parsed_artifact_url.netloc != "evidence.openadapt.ai"
            or digest.removeprefix("sha256:")
            not in [part for part in parsed_artifact_url.path.split("/") if part]
        ):
            raise LifecycleError(
                f"{label} item {index} is not content-addressed managed evidence"
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


def _validate_release_identity(
    value: object, authority: Mapping[str, Any], label: str
) -> dict[str, Any]:
    identity = _closed(
        value,
        {"schema_version", "channel", "sequence", "previous_admission_sha256"},
        label,
    )
    if identity["schema_version"] != authority["release_identity_schema_version"]:
        raise LifecycleError(f"{label} schema is not supported")
    if identity["channel"] != authority["production_channel"]:
        raise LifecycleError(f"{label} channel is not Production")
    sequence = identity["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise LifecycleError(f"{label} sequence must be a positive integer")
    previous = identity["previous_admission_sha256"]
    if previous is not None:
        _digest(previous, f"{label} predecessor")
    return identity


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
            authority_by_kind=target["artifact_authority_by_kind"],
            source_repository=target["source_repository"],
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
            authority_by_kind=target["artifact_authority_by_kind"],
            source_repository=target["source_repository"],
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


def _fetch_json_object(
    url: str, label: str, fetch: Callable[[str], bytes]
) -> dict[str, Any]:
    try:
        payload = fetch(url)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise LifecycleError(f"{label} could not be fetched: {exc}") from exc
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"{label} is not JSON") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must be a JSON object")
    return value


def _verify_artifact_authorities(
    release: Mapping[str, Any],
    target: Mapping[str, Any],
    fetch: Callable[[str], bytes],
) -> None:
    artifacts = release.get("artifacts", [])
    pypi_artifacts = [item for item in artifacts if item["authority"] == "pypi"]
    if pypi_artifacts:
        project = target["package_index_project"]
        version = release["version"]
        metadata_url = (
            f"https://pypi.org/pypi/{quote(project, safe='')}/"
            f"{quote(version, safe='')}/json"
        )
        metadata = _fetch_json_object(metadata_url, "PyPI release metadata", fetch)
        if metadata.get("info", {}).get("version") != version:
            raise LifecycleError("PyPI release metadata version differs")
        files = metadata.get("urls")
        if not isinstance(files, list):
            raise LifecycleError("PyPI release metadata files are invalid")
        for artifact in pypi_artifacts:
            matches = [
                item
                for item in files
                if isinstance(item, dict)
                and item.get("filename") == artifact["name"]
                and item.get("url") == artifact["url"]
                and item.get("size") == artifact["size_bytes"]
                and item.get("digests", {}).get("sha256")
                == artifact["sha256"].removeprefix("sha256:")
                and item.get("yanked") is False
            ]
            if len(matches) != 1:
                raise LifecycleError(
                    f"PyPI does not verify exact artifact {artifact['name']}"
                )

    github_artifacts = [
        item for item in artifacts if item["authority"] == "github_release"
    ]
    if github_artifacts:
        repository = target["source_repository"]
        tag = release["tag"]
        metadata_url = (
            f"https://api.github.com/repos/{repository}/releases/tags/"
            f"{quote(tag, safe='')}"
        )
        metadata = _fetch_json_object(metadata_url, "GitHub release metadata", fetch)
        if (
            metadata.get("tag_name") != tag
            or metadata.get("draft") is not False
            or metadata.get("prerelease") is not False
            or metadata.get("immutable") is not True
        ):
            raise LifecycleError("GitHub release is not an exact immutable release")
        assets = metadata.get("assets")
        if not isinstance(assets, list):
            raise LifecycleError("GitHub release assets are invalid")
        for artifact in github_artifacts:
            matches = [
                item
                for item in assets
                if isinstance(item, dict)
                and item.get("name") == artifact["name"]
                and item.get("url") == artifact["url"]
                and item.get("size") == artifact["size_bytes"]
                and item.get("digest") == artifact["sha256"]
                and item.get("state") == "uploaded"
            ]
            if len(matches) != 1:
                raise LifecycleError(
                    f"GitHub does not verify exact artifact {artifact['name']}"
                )

    managed_artifacts = [
        item for item in artifacts if item["authority"] == "managed_evidence"
    ]
    for artifact in managed_artifacts:
        digest_hex = artifact["sha256"].removeprefix("sha256:")
        metadata_url = (
            "https://evidence.openadapt.ai/api/v1/objects/sha256/" + digest_hex
        )
        metadata = _fetch_json_object(
            metadata_url, "managed evidence object metadata", fetch
        )
        metadata = _closed(
            metadata,
            {
                "schema_version",
                "exists",
                "artifact_url",
                "sha256",
                "size_bytes",
                "object_version_sha256",
                "head_verified",
            },
            "managed evidence object metadata",
        )
        expected = {
            "schema_version": "openadapt.managed-artifact-head/v1",
            "exists": True,
            "artifact_url": artifact["url"],
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
            "head_verified": True,
        }
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise LifecycleError(
                f"managed evidence does not verify exact artifact {artifact['name']}"
            )
        _digest(
            metadata.get("object_version_sha256"),
            f"managed evidence artifact {artifact['name']} object version",
        )


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


def _count(value: object, label: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise LifecycleError(f"{label} must be an integer of at least {minimum}")
    return value


def _validate_manifest(
    value: object,
    *,
    admission: Mapping[str, Any],
    summary: Mapping[str, Any],
    authority: Mapping[str, Any],
    authority_commit: str,
    now: datetime,
) -> None:
    target_id = admission["target"]
    manifest = _closed(
        value,
        {
            "schema_version",
            "target",
            "claim_scope",
            "verdict",
            "policy_sha256",
            "target_release_sha256",
            "target_artifact_inventory_sha256",
            "evidence_identity_sha256",
            "source_evidence",
            "qualification",
            "failure_taxonomy_counts",
            "reliability",
            "retention",
        },
        f"admission {target_id} evidence manifest",
    )
    expected_bindings = {
        "schema_version": authority["evidence_manifest_schema_version"],
        "target": target_id,
        "claim_scope": admission["claim_scope"],
        "verdict": "accepted",
        "policy_sha256": summary["policy_sha256"],
        "target_release_sha256": summary["release_sha256"],
        "target_artifact_inventory_sha256": summary["artifact_inventory_sha256"],
        "evidence_identity_sha256": summary["evidence_identity_sha256"],
    }
    for key, expected in expected_bindings.items():
        if manifest[key] != expected:
            raise LifecycleError(
                f"admission {target_id} evidence manifest {key} differs"
            )

    source = _closed(
        manifest["source_evidence"],
        {
            "private_certificate_schema_version",
            "private_certificate_sha256",
            "signer_provenance_sha256",
            "qualification_admission_sha256",
            "campaign_sha256",
            "verified_authority_source_commit",
        },
        f"admission {target_id} source evidence",
    )
    certificate = summary["private_certificate_binding"]
    if (
        source["private_certificate_schema_version"] != certificate["schema_version"]
        or source["private_certificate_sha256"] != certificate["sha256"]
        or source["signer_provenance_sha256"] != certificate["signer_provenance_sha256"]
        or source["verified_authority_source_commit"] != authority_commit
    ):
        raise LifecycleError(f"admission {target_id} source evidence differs")
    _digest(
        source["qualification_admission_sha256"],
        f"admission {target_id} qualification admission digest",
    )
    _digest(source["campaign_sha256"], f"admission {target_id} campaign digest")

    qualification = _closed(
        manifest["qualification"],
        {
            "oracle_contract_sha256",
            "task_count",
            "condition_count",
            "required_trial_count",
            "observed_trial_count",
            "minimum_trials_per_condition",
            "conditions",
        },
        f"admission {target_id} qualification",
    )
    _digest(
        qualification["oracle_contract_sha256"],
        f"admission {target_id} oracle contract digest",
    )
    _count(qualification["task_count"], f"admission {target_id} task count", 1)
    condition_count = _count(
        qualification["condition_count"],
        f"admission {target_id} condition count",
        1,
    )
    required_trials = _count(
        qualification["required_trial_count"],
        f"admission {target_id} required trial count",
        3,
    )
    observed_trials = _count(
        qualification["observed_trial_count"],
        f"admission {target_id} observed trial count",
        required_trials,
    )
    minimum_trials = _count(
        qualification["minimum_trials_per_condition"],
        f"admission {target_id} minimum trials per condition",
        3,
    )
    conditions_value = qualification["conditions"]
    if (
        not isinstance(conditions_value, list)
        or len(conditions_value) != condition_count
    ):
        raise LifecycleError(f"admission {target_id} condition inventory differs")
    condition_identities: list[str] = []
    condition_required = 0
    condition_observed = 0
    for index, item in enumerate(conditions_value):
        condition = _closed(
            item,
            {
                "task_condition_identity_sha256",
                "required_trial_count",
                "observed_trial_count",
            },
            f"admission {target_id} condition {index}",
        )
        identity = _digest(
            condition["task_condition_identity_sha256"],
            f"admission {target_id} condition {index} identity",
        )
        required = _count(
            condition["required_trial_count"],
            f"admission {target_id} condition {index} required trials",
            minimum_trials,
        )
        observed = _count(
            condition["observed_trial_count"],
            f"admission {target_id} condition {index} observed trials",
            required,
        )
        condition_identities.append(identity)
        condition_required += required
        condition_observed += observed
    if condition_identities != sorted(set(condition_identities)):
        raise LifecycleError(
            f"admission {target_id} conditions are not unique and sorted"
        )
    if condition_required != required_trials or condition_observed != observed_trials:
        raise LifecycleError(f"admission {target_id} trial inventory totals differ")

    taxonomy = _closed(
        manifest["failure_taxonomy_counts"],
        FAILURE_TAXONOMY_KEYS,
        f"admission {target_id} failure taxonomy",
    )
    for key, value_count in taxonomy.items():
        _count(value_count, f"admission {target_id} failure taxonomy {key}")
    if sum(taxonomy.values()) != observed_trials:
        raise LifecycleError(
            f"admission {target_id} failure taxonomy does not account for every trial"
        )
    reliability = _closed(
        manifest["reliability"],
        set(RELIABILITY_TO_TAXONOMY),
        f"admission {target_id} reliability",
    )
    for reliability_key, taxonomy_key in RELIABILITY_TO_TAXONOMY.items():
        count = _count(
            reliability[reliability_key],
            f"admission {target_id} reliability {reliability_key}",
        )
        if count != taxonomy[taxonomy_key]:
            raise LifecycleError(
                f"admission {target_id} reliability and taxonomy differ"
            )
    for key in (
        "silent_incorrect_success_count",
        "wrong_record_count",
        "duplicate_effect_count",
        "collateral_effect_count",
        "uncertain_delivery_count",
        "model_call_count",
    ):
        if reliability[key] != 0:
            raise LifecycleError(
                f"admission {target_id} unsafe reliability count {key} is nonzero"
            )

    retention = _closed(
        manifest["retention"],
        {
            "receipt_id",
            *RETENTION_DIGEST_KEYS,
            "retention_mode",
            "retention_until",
            "retained_at",
            "upload_verified",
            "head_verified",
            "object_lock_verified",
            "private_locator_recorded",
            "acceptance_verified_at",
            "provenance_attestation",
        },
        f"admission {target_id} retention",
    )
    receipt = retention["receipt_id"]
    if (
        not isinstance(receipt, str)
        or re.fullmatch(r"retention:[0-9a-f]{32}", receipt) is None
    ):
        raise LifecycleError(f"admission {target_id} retention receipt is invalid")
    for key in RETENTION_DIGEST_KEYS:
        _digest(retention[key], f"admission {target_id} retention {key}")
    if retention["retention_mode"] != "COMPLIANCE":
        raise LifecycleError(f"admission {target_id} retention mode is invalid")
    for key in (
        "upload_verified",
        "head_verified",
        "object_lock_verified",
        "private_locator_recorded",
    ):
        if retention[key] is not True:
            raise LifecycleError(f"admission {target_id} retention {key} is not true")
    if retention["provenance_attestation"] != "github-artifact-attestation-v4":
        raise LifecycleError(f"admission {target_id} retention provenance is invalid")
    accepted_at = _timestamp(
        retention["acceptance_verified_at"],
        f"admission {target_id} acceptance verification time",
    )
    retained_at = _timestamp(
        retention["retained_at"], f"admission {target_id} retained time"
    )
    retention_until = _timestamp(
        retention["retention_until"], f"admission {target_id} retention end"
    )
    if not accepted_at <= retained_at < retention_until:
        raise LifecycleError(f"admission {target_id} retention chronology is invalid")
    admission_issued_at = _timestamp(
        admission["issued_at"], f"admission {target_id} issued_at"
    )
    if retained_at > admission_issued_at or retained_at > now:
        raise LifecycleError(
            f"admission {target_id} retention verification is in the future"
        )
    duration = retention_until - retained_at
    if not timedelta(days=365) <= duration <= timedelta(days=3650):
        raise LifecycleError(f"admission {target_id} retention duration is invalid")
    if retention_until <= now:
        raise LifecycleError(f"admission {target_id} retained evidence is expired")


def _validate_remote_summary(
    admission: Mapping[str, Any],
    release: Mapping[str, Any],
    authority: Mapping[str, Any],
    policy_sha256: str,
    now: datetime,
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
            "claim_scope",
            "policy_sha256",
            "release_identity",
            "release_sha256",
            "artifact_inventory_sha256",
            "evidence_identity_sha256",
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
    if summary["claim_scope"] != admission["claim_scope"]:
        raise LifecycleError(f"admission {target_id} signed claim scope differs")
    if summary["policy_sha256"] != policy_sha256:
        raise LifecycleError(f"admission {target_id} signed policy digest differs")
    summary_identity = _validate_release_identity(
        summary["release_identity"],
        authority,
        f"admission {target_id} signed release identity",
    )
    if summary_identity != admission["release_identity"]:
        raise LifecycleError(f"admission {target_id} signed release identity differs")
    if summary["release_sha256"] != _canonical_digest(release):
        raise LifecycleError(f"admission {target_id} summary release digest differs")
    artifacts = release.get("artifacts", [])
    if summary["artifact_inventory_sha256"] != _canonical_digest(artifacts):
        raise LifecycleError(
            f"admission {target_id} summary artifact inventory differs"
        )
    _digest(
        summary["evidence_identity_sha256"],
        f"admission {target_id} evidence identity",
    )
    certificate = _closed(
        summary["private_certificate_binding"],
        {
            "schema_version",
            "sha256",
            "signer_provenance_sha256",
            "evidence_identity_sha256",
            "target",
            "target_release_sha256",
            "target_artifact_inventory_sha256",
        },
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
    _digest(
        certificate["evidence_identity_sha256"],
        f"admission {target_id} private evidence identity",
    )
    if certificate["evidence_identity_sha256"] != summary["evidence_identity_sha256"]:
        raise LifecycleError(f"admission {target_id} evidence identity differs")
    if certificate["target"] != target_id:
        raise LifecycleError(f"admission {target_id} private evidence target differs")
    if certificate["target_release_sha256"] != summary["release_sha256"]:
        raise LifecycleError(f"admission {target_id} private release binding differs")
    if (
        certificate["target_artifact_inventory_sha256"]
        != summary["artifact_inventory_sha256"]
    ):
        raise LifecycleError(f"admission {target_id} private artifact binding differs")
    manifest = _closed(
        summary["evidence_manifest"],
        {"schema_version", "url", "sha256"},
        f"admission {target_id} evidence manifest",
    )
    manifest_schema = manifest["schema_version"]
    if manifest_schema != authority["evidence_manifest_schema_version"]:
        raise LifecycleError(
            f"admission {target_id} evidence manifest schema is not supported"
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
    _validate_manifest(
        manifest_value,
        admission=admission,
        summary=summary,
        authority=authority,
        authority_commit=authority_commit,
        now=now,
    )
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
    records_by_target: dict[
        str,
        list[
            tuple[dict[str, Any], dict[str, Any], datetime, datetime, datetime | None]
        ],
    ] = {}
    for index, item in enumerate(admissions_value_list):
        admission = _closed(
            item,
            {
                "admission_id",
                "target",
                "claim_scope",
                "release_identity",
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
        if admission["policy_revision"] != policy["revision"]:
            raise LifecycleError(f"admission {target_id} policy revision differs")
        if admission["claim_scope"] != targets[target_id]["required_claim_scope"]:
            raise LifecycleError(
                f"admission {target_id} claim scope differs from policy"
            )
        _validate_release_identity(
            admission["release_identity"],
            policy["summary_authority"],
            f"admission {target_id} release identity",
        )
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
        revoked_at = admission["revoked_at"]
        revoked: datetime | None = None
        if revoked_at is not None:
            revoked = _timestamp(revoked_at, f"admission {target_id} revoked_at")
            if revoked < issued_at or revoked > now:
                raise LifecycleError(
                    f"admission {target_id} revocation timestamp is invalid"
                )
        release = _validate_release(admission["release"], targets[target_id])
        records_by_target.setdefault(target_id, []).append(
            (admission, release, issued_at, expires_at, revoked)
        )

    for target_id, records in records_by_target.items():
        records.sort(key=lambda item: item[0]["release_identity"]["sequence"])
        previous_digest: str | None = None
        previous_issued_at: datetime | None = None
        release_digests: set[str] = set()
        for expected_sequence, (admission, release, issued_at, *_times) in enumerate(
            records, start=1
        ):
            identity = admission["release_identity"]
            if identity["sequence"] != expected_sequence:
                raise LifecycleError(
                    f"admission {target_id} release sequence is not continuous"
                )
            if identity["previous_admission_sha256"] != previous_digest:
                raise LifecycleError(f"admission {target_id} predecessor hash differs")
            if previous_issued_at is not None and issued_at <= previous_issued_at:
                raise LifecycleError(
                    f"admission {target_id} release time is not monotonic"
                )
            release_digest = _canonical_digest(release)
            if release_digest in release_digests:
                raise LifecycleError(
                    f"admission {target_id} repeats an earlier release"
                )
            release_digests.add(release_digest)
            previous_digest = _canonical_digest(admission)
            previous_issued_at = issued_at

        latest, latest_release, _issued_at, expires_at, revoked = records[-1]
        if revoked is not None or expires_at <= now:
            continue
        _verify_artifact_authorities(latest_release, targets[target_id], fetch)
        _validate_remote_summary(
            latest,
            latest_release,
            policy["summary_authority"],
            policy_sha256,
            now,
            fetch=fetch,
            verify_attestation=verify_attestation,
        )
        active[target_id] = latest["admission_id"]

    if repository_lifecycle.get("production", []):
        raise LifecycleError(
            "static Production repository membership is not permitted; "
            "derive it from active admissions"
        )
    if surface_lifecycle.get("production", []):
        raise LifecycleError(
            "static Production public-surface membership is not permitted; "
            "derive it from active admissions"
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
            if group != "production" and target["lifecycle_subject"] in subjects
        ]
        if len(memberships) != 1:
            raise LifecycleError(
                f"target {target_id} must have exactly one baseline lifecycle "
                f"membership; got {memberships}"
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


def validate_append_only_history(previous_value: object, current_value: object) -> None:
    """Reject release-ledger rollback while allowing one-way current revocation."""

    if not isinstance(previous_value, dict) or not isinstance(current_value, dict):
        raise LifecycleError("Production admission history must be JSON objects")
    previous = previous_value.get("admissions")
    current = current_value.get("admissions")
    if not isinstance(previous, list) or not isinstance(current, list):
        raise LifecycleError(
            "Production admission history must contain admission lists"
        )
    if len(current) < len(previous):
        raise LifecycleError("Production admission history cannot remove records")
    latest_previous_index_by_target: dict[str, int] = {}
    for index, record in enumerate(previous):
        if isinstance(record, dict) and isinstance(record.get("target"), str):
            latest_previous_index_by_target[record["target"]] = index
    for index, old_record in enumerate(previous):
        new_record = current[index]
        if new_record == old_record:
            continue
        if not isinstance(old_record, dict) or not isinstance(new_record, dict):
            raise LifecycleError("Production admission history changed a record")
        old_without_revocation = dict(old_record)
        new_without_revocation = dict(new_record)
        old_revocation = old_without_revocation.pop("revoked_at", None)
        new_revocation = new_without_revocation.pop("revoked_at", None)
        one_way_current_revocation = (
            index == latest_previous_index_by_target.get(old_record.get("target"))
            and old_without_revocation == new_without_revocation
            and old_revocation is None
            and isinstance(new_revocation, str)
        )
        if not one_way_current_revocation:
            raise LifecycleError(
                "Production admission history can only append records or revoke "
                "the current record once"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--previous-admissions", type=Path)
    args = parser.parse_args()
    try:
        active = validate_files(args.root)
        if args.previous_admissions is not None:
            previous = _load_json(
                args.previous_admissions, "previous Production lifecycle admissions"
            )
            current = _load_json(
                args.root / ADMISSIONS_PATH.name,
                "current Production lifecycle admissions",
            )
            validate_append_only_history(previous, current)
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
