#!/usr/bin/env python3
"""Closed validators and digest rules for OpenAdapt Production trust objects."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import validate_evidence_registry as evidence

ROOT = Path(__file__).resolve().parents[1]
SUPPORT_POLICY_PATH = ROOT / "support-release-policy.json"

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
DECIMAL_ID = re.compile(r"^[1-9][0-9]*$")
ENTITY_CLASS = re.compile(r"^[a-z][a-z0-9 -]{0,63}$")
BUNDLE_VERSION = re.compile(
    r"^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\."
    r"(0|[1-9][0-9]{0,9})(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
)
RELEASE_TAG = re.compile(
    r"^v(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\."
    r"(0|[1-9][0-9]{0,9})(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
)

TARGETS = ("agent", "capture", "cloud", "desktop", "docs", "flow", "openadapt")
# Sequential work order (STATUS.md 2026-08-27): admit Flow first. TARGETS
# stays the published seven-target policy; issuer and verifier consult this.
ADMISSION_GATE_TARGETS = ("flow",)
TARGET_CONTRACTS = {
    "agent": {
        "claim_scope": "production_agent",
        "repository": "OpenAdaptAI/openadapt-agent",
        "repository_id": "1136136670",
        "release_kind": "package",
        "artifacts": {
            "python-sdist": ("application/gzip", ("github-release", "pypi")),
            "python-wheel": ("application/zip", ("github-release", "pypi")),
        },
    },
    "capture": {
        "claim_scope": "production_capture",
        "repository": "OpenAdaptAI/openadapt-capture",
        "repository_id": "1115283835",
        "release_kind": "package",
        "artifacts": {
            "chrome-extension-zip": ("application/zip", ("github-release",)),
            "python-sdist": ("application/gzip", ("github-release", "pypi")),
            "python-wheel": ("application/zip", ("github-release", "pypi")),
            "spdx-sbom": ("application/spdx+json", ("github-release",)),
        },
    },
    "cloud": {
        "claim_scope": "production_cloud",
        "repository": "OpenAdaptAI/openadapt-cloud",
        "repository_id": "1300570990",
        "release_kind": "deployment",
        "artifacts": {
            "deployment-manifest": (
                "application/vnd.openadapt.production-deployment-manifest+json;version=1",
                ("deployment",),
            ),
        },
    },
    "desktop": {
        "claim_scope": "production_desktop",
        "repository": "OpenAdaptAI/openadapt-desktop",
        "repository_id": "1171291730",
        "release_kind": "hybrid",
        "artifacts": {
            "cyclonedx-sbom": (
                "application/vnd.cyclonedx+json",
                ("github-release",),
            ),
            "linux-appimage": ("application/vnd.appimage", ("github-release",)),
            "linux-deb": (
                "application/vnd.debian.binary-package",
                ("github-release",),
            ),
            "macos-dmg-arm64": (
                "application/x-apple-diskimage",
                ("github-release",),
            ),
            "macos-dmg-x86-64": (
                "application/x-apple-diskimage",
                ("github-release",),
            ),
            "python-sdist": ("application/gzip", ("github-release", "pypi")),
            "python-wheel": ("application/zip", ("github-release", "pypi")),
            "release-checksums": ("text/plain", ("github-release",)),
            "verification-metadata-linux-x86-64": (
                "application/vnd.openadapt.desktop-platform-verification+json;version=1",
                ("github-release",),
            ),
            "verification-metadata-macos-arm64": (
                "application/vnd.openadapt.desktop-platform-verification+json;version=1",
                ("github-release",),
            ),
            "verification-metadata-macos-x86-64": (
                "application/vnd.openadapt.desktop-platform-verification+json;version=1",
                ("github-release",),
            ),
            "verification-metadata-windows-x86-64": (
                "application/vnd.openadapt.desktop-platform-verification+json;version=1",
                ("github-release",),
            ),
            "windows-msi": ("application/x-msi", ("github-release",)),
            "windows-nsis": (
                "application/vnd.microsoft.portable-executable",
                ("github-release",),
            ),
        },
    },
    "docs": {
        "claim_scope": "production_docs",
        "repository": "OpenAdaptAI/openadapt-ops",
        "repository_id": "1172011294",
        "release_kind": "deployment",
        "artifacts": {
            "deployment-manifest": (
                "application/vnd.openadapt.production-deployment-manifest+json;version=1",
                ("deployment",),
            ),
            "site-archive": ("application/gzip", ("deployment",)),
        },
    },
    "flow": {
        "claim_scope": "production_flow",
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "release_kind": "package",
        "artifacts": {
            "python-sdist": ("application/gzip", ("github-release", "pypi")),
            "python-wheel": ("application/zip", ("github-release", "pypi")),
        },
    },
    "openadapt": {
        "claim_scope": "production_openadapt",
        "repository": "OpenAdaptAI/OpenAdapt",
        "repository_id": "627024850",
        "release_kind": "package",
        "artifacts": {
            "python-sdist": ("application/gzip", ("github-release", "pypi")),
            "python-wheel": ("application/zip", ("github-release", "pypi")),
        },
    },
}
CAMPAIGN_CLASSES = (
    "healthy",
    "safe_halt",
    "idempotency_replay",
    "uncertain_delivery",
    "declared_attended",
    "governed_repair",
)
CAMPAIGN_COUNT_FIELDS = {
    "task_condition_cell_count",
    "minimum_trials_per_cell",
    "observed_trial_count",
    "silent_incorrect_success_count",
    "over_halt_count",
    "unsafe_effect_count",
    "blind_retry_count",
    "replay_dispatch_count",
    "model_call_count",
    "unplanned_intervention_count",
    "reconciliation_required_count",
    "authenticated_bound_decision_count",
    "live_target_revalidation_count",
    "policy_approved_repair_count",
    "approved_repair_count",
    "retained_repair_evidence_count",
    "unverified_direct_action_count",
}

ARTIFACT_INVENTORY_DOMAIN = b"OpenAdapt production release artifact inventory v1\0"
RELEASE_DOMAIN = b"OpenAdapt production release candidate v1\0"
RELEASE_ADMISSION_DOMAIN = b"OpenAdapt qualification release admission v2\0"
STAGING_DOMAIN = b"OpenAdapt production release staging evidence v1\0"
TAG_RULESETS_DOMAIN = b"OpenAdapt production release tag rulesets v1\0"
IMMUTABLE_RELEASES_DOMAIN = b"OpenAdapt production immutable releases response v1\0"
TAG_REF_STATE_DOMAIN = b"OpenAdapt production release tag ref state v1\0"
PUBLICATION_RECOVERY_AUTHORIZATION_DOMAIN = (
    b"OpenAdapt production publication recovery authorization v2\0"
)
PUBLICATION_RECOVERY_IDEMPOTENCY_DOMAIN = (
    b"OpenAdapt production publication recovery idempotency v1\0"
)
ADMISSION_DOMAIN = b"OpenAdapt qualification admission v4\0"
CHECKPOINT_DOMAIN = b"OpenAdapt production lifecycle checkpoint v2\0"
PROJECTION_DOMAIN = b"OpenAdapt production lifecycle projection v2\0"
RELEASE_SET_DOMAIN = b"OpenAdapt production release admission set v1\0"
WORKFLOW_SET_DOMAIN = b"OpenAdapt production workflow admission set v1\0"
AUTHORITY_STATE_IDENTITY_DOMAIN = (
    b"OpenAdapt qualification authority state identity v2\0"
)
REVOCATION_STATE_IDENTITY_DOMAIN = (
    b"OpenAdapt qualification revocation state identity v1\0"
)
PRODUCTION_EVIDENCE_IDENTITY_DOMAIN = (
    b"OpenAdapt production acceptance evidence identity v3\0"
)
DECISION_RECEIPT_SIGNATURE_DOMAIN = (
    b"OpenAdapt qualification evidence decision receipt v2\0"
)
AUTHORITY_STATE_SIGNATURE_DOMAIN = (
    b"OpenAdapt qualification authority state receipt v2\0"
)
REVOCATION_STATE_SIGNATURE_DOMAIN = (
    b"OpenAdapt qualification revocation state receipt v1\0"
)
SUPPORT_RELEASE_DOMAIN = b"OpenAdapt Support release candidate v1\0"
SUPPORT_ARTIFACT_INVENTORY_DOMAIN = b"OpenAdapt Support release artifact inventory v1\0"
SUPPORT_RELEASE_ADMISSION_DOMAIN = b"OpenAdapt Support release admission v1\0"
SUPPORT_POLICY_DOMAIN = b"OpenAdapt Support release policy v1\0"
CLOUD_AUTHORIZATION_DOMAIN = b"OpenAdapt production Cloud deploy authorization v1\0"
CLOUD_HANDOFF_DOMAIN = b"OpenAdapt production Cloud deployment handoff v1\0"
CLOUD_SOURCE_PROOF_REQUEST_DOMAIN = (
    b"OpenAdapt production secret source proof request v2\0"
)
CLOUD_SOURCE_COMMIT_DOMAIN = b"OpenAdapt Cloud source commit commitment v1\0"
CLOUD_PROVIDER_IDEMPOTENCY_DOMAIN = (
    b"OpenAdapt production Cloud provider idempotency v1\0"
)
CLOUD_PUBLIC_VALUES_DOMAIN = b"OpenAdapt production Cloud public values v1\0"
CLOUD_LIVE_SOURCE_NAMES = (
    "BUSINESS_DECISION_ANSWER_HMAC_KEY",
    "BUSINESS_DECISION_ANSWER_HMAC_KEY_ID",
    "BUSINESS_DECISION_CLOUD_POLICY_HMAC_KEYS_JSON",
    "BUSINESS_DECISION_PRINCIPAL_ALIAS_HMAC_KEY",
    "BUSINESS_DECISION_QUALIFICATION_HMAC_KEYS_JSON",
    "BUSINESS_DECISION_ROLE_MAPPING_HMAC_KEY",
    "BUSINESS_DECISION_RUNNER_RECEIPT_HMAC_KEYS_JSON",
    "BUSINESS_DECISION_SESSION_BINDING_HMAC_KEY",
    "BUSINESS_DECISION_TASK_HMAC_KEYS_JSON",
    "EXECUTE_ACCEPTANCE_CAMPAIGN_PROVISIONER_TOKEN",
    "EXECUTE_ACCEPTANCE_OBSERVER_BEARER_TOKEN",
    "EXECUTE_ACCEPTANCE_OBSERVER_SIGNING_PRIVATE_KEY",
    "EXECUTE_ACCEPTANCE_TARGET_SIGNING_SECRET",
)
CLOUD_PUBLIC_SOURCE_NAME = "BUSINESS_DECISION_ANSWER_HMAC_KEY_ID"
CLOUD_SECRET_SOURCE_NAMES = tuple(
    name for name in CLOUD_LIVE_SOURCE_NAMES if name != CLOUD_PUBLIC_SOURCE_NAME
)
FEED_UPDATE_IDEMPOTENCY_DOMAIN = (
    b"OpenAdapt production lifecycle feed update idempotency v2\0"
)


class TrustError(ValueError):
    """A Production trust object is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_bytes(domain: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + canonical(value)).hexdigest()


def closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise TrustError(f"{label} must contain exactly {sorted(fields)}; got {actual}")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise TrustError(f"{label} must be a lowercase sha256 digest")
    return value


def require_raw_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or RAW_DIGEST.fullmatch(value) is None:
        raise TrustError(f"{label} must be lowercase raw sha256 hex")
    return value


def require_decimal_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or DECIMAL_ID.fullmatch(value) is None:
        raise TrustError(f"{label} must be a decimal string")
    return value


def require_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise TrustError(f"{label} must be an exact UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TrustError(f"{label} is not a calendar timestamp") from exc


def require_positive_int(value: Any, label: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TrustError(f"{label} must be an integer of at least {minimum}")
    return value


def validate_window(
    value: Mapping[str, Any], *, maximum: timedelta, now: datetime | None = None
) -> None:
    issued = require_timestamp(value["issued_at"], "issued_at")
    not_before = require_timestamp(value["not_before"], "not_before")
    expires = require_timestamp(value["expires_at"], "expires_at")
    if not not_before <= issued < expires <= not_before + maximum:
        raise TrustError("validity window is invalid")
    if now is not None and not not_before <= now < expires:
        raise TrustError("object is not active at the requested time")


def validate_staging_observation_age(
    staging: Mapping[str, Any], admission: Mapping[str, Any]
) -> None:
    observed = require_timestamp(staging["observed_at"], "staging observed_at")
    issued = require_timestamp(admission["issued_at"], "admission issued_at")
    if not observed <= issued <= observed + timedelta(hours=1):
        raise TrustError(
            "publication staging observation is stale or postdates admission"
        )


def validate_reference_pair(
    regular: Any, bundle: Any, *, kind: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        regular_ref = evidence.validate_reference(regular)
        bundle_ref = evidence.validate_reference(bundle)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    if regular_ref["kind"] != kind:
        raise TrustError(f"regular reference kind must be {kind}")
    if bundle_ref["kind"] != f"{kind}-sigstore-bundle":
        raise TrustError(f"bundle reference kind must be {kind}-sigstore-bundle")
    if (
        bundle_ref["registry_source_commit"] != regular_ref["registry_source_commit"]
        or bundle_ref["registry_revision"] != regular_ref["registry_revision"]
        or bundle_ref["registry_head_sha256"] != regular_ref["registry_head_sha256"]
        or bundle_ref["subject_sha256"] != regular_ref["object_sha256"]
    ):
        raise TrustError("reference pair does not share a registry or bind its subject")
    return regular_ref, bundle_ref


def validate_campaign_summary(value: Any) -> dict[str, Any]:
    summary = closed(value, set(CAMPAIGN_CLASSES), "campaign summary")
    for campaign_class in CAMPAIGN_CLASSES:
        counts = closed(
            summary[campaign_class], CAMPAIGN_COUNT_FIELDS, f"{campaign_class} counts"
        )
        for key, count in counts.items():
            require_positive_int(
                count,
                f"{campaign_class} {key}",
                minimum=3 if key == "minimum_trials_per_cell" else 0,
            )
        cells = counts["task_condition_cell_count"]
        trials = counts["observed_trial_count"]
        if cells < 1 or trials < cells * counts["minimum_trials_per_cell"]:
            raise TrustError(f"{campaign_class} does not have three trials per cell")
        if (
            counts["unsafe_effect_count"]
            or counts["silent_incorrect_success_count"]
            or counts["blind_retry_count"]
        ):
            raise TrustError(f"{campaign_class} contains a forbidden failure")
    for campaign_class in ("healthy", "idempotency_replay"):
        counts = summary[campaign_class]
        if counts["model_call_count"] or counts["unplanned_intervention_count"]:
            raise TrustError(f"{campaign_class} is not a zero-model healthy path")
    uncertain = summary["uncertain_delivery"]
    if uncertain["observed_trial_count"] < 3:
        raise TrustError("uncertain delivery requires at least three fault trials")
    if uncertain["reconciliation_required_count"] != uncertain["observed_trial_count"]:
        raise TrustError("every uncertain-delivery trial must require reconciliation")
    if uncertain["replay_dispatch_count"]:
        raise TrustError("uncertain delivery cannot replay dispatch")
    attended = summary["declared_attended"]
    if (
        attended["authenticated_bound_decision_count"]
        != attended["observed_trial_count"]
        or attended["live_target_revalidation_count"]
        != attended["observed_trial_count"]
    ):
        raise TrustError("attended trials require a bound decision and revalidation")
    repair = summary["governed_repair"]
    for field in (
        "policy_approved_repair_count",
        "approved_repair_count",
        "retained_repair_evidence_count",
        "live_target_revalidation_count",
    ):
        if repair[field] != repair["observed_trial_count"]:
            raise TrustError("governed repair evidence is incomplete")
    if repair["unverified_direct_action_count"]:
        raise TrustError("governed repair contains an unverified direct action")
    return summary


def validate_artifacts(
    value: Any, *, target: str | None = None
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TrustError("artifact inventory must be a non-empty list")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    folded: set[str] = set()
    for index, artifact_value in enumerate(value):
        artifact = closed(
            artifact_value,
            {
                "name",
                "kind",
                "sha256",
                "size_bytes",
                "media_type",
                "publish_destinations",
            },
            f"artifact {index}",
        )
        name = artifact["name"]
        if (
            not isinstance(name, str)
            or not name
            or name != Path(name).name
            or "/" in name
            or "\\" in name
        ):
            raise TrustError(f"artifact {index} name is unsafe")
        if name in names or name.casefold() in folded:
            raise TrustError("artifact names must be unique under case folding")
        names.add(name)
        folded.add(name.casefold())
        if not isinstance(artifact["kind"], str) or not artifact["kind"]:
            raise TrustError(f"artifact {index} kind is invalid")
        require_digest(artifact["sha256"], f"artifact {index} digest")
        require_positive_int(artifact["size_bytes"], f"artifact {index} size")
        if (
            not isinstance(artifact["media_type"], str)
            or "/" not in artifact["media_type"]
        ):
            raise TrustError(f"artifact {index} media type is invalid")
        destinations = artifact["publish_destinations"]
        if (
            not isinstance(destinations, list)
            or not destinations
            or destinations != sorted(set(destinations))
            or any(
                item not in {"deployment", "github-release", "pypi"}
                for item in destinations
            )
        ):
            raise TrustError(f"artifact {index} publish destinations are invalid")
        result.append(artifact)
    if result != sorted(
        result, key=lambda item: (item["kind"], item["name"], item["sha256"])
    ):
        raise TrustError("artifacts must be sorted by kind, name, and digest")
    if target is not None:
        contract = TARGET_CONTRACTS.get(target)
        if contract is None:
            raise TrustError("artifact target is invalid")
        profile = contract["artifacts"]
        if [item["kind"] for item in result] != sorted(profile):
            raise TrustError(f"{target} artifact kinds differ from the target profile")
        for artifact in result:
            media_type, destinations = profile[artifact["kind"]]
            if artifact["media_type"] != media_type or artifact[
                "publish_destinations"
            ] != list(destinations):
                raise TrustError(
                    f"{target} {artifact['kind']} media type or destinations differ"
                )
    return result


def validate_artifact_inventory(value: Any) -> dict[str, Any]:
    inventory = closed(
        value,
        {"schema_version", "target", "claim_scope", "artifacts"},
        "artifact inventory",
    )
    if (
        inventory["schema_version"]
        != "openadapt.production-release-artifact-inventory/v1"
    ):
        raise TrustError("artifact inventory schema is not supported")
    if inventory["target"] not in TARGETS:
        raise TrustError("artifact inventory target is invalid")
    if not isinstance(inventory["claim_scope"], str) or not inventory["claim_scope"]:
        raise TrustError("artifact inventory claim scope is invalid")
    validate_artifacts(inventory["artifacts"], target=inventory["target"])
    return inventory


def artifact_inventory_digest(value: Mapping[str, Any]) -> str:
    return digest_bytes(
        ARTIFACT_INVENTORY_DOMAIN,
        {
            "target": value["target"],
            "claim_scope": value["claim_scope"],
            "artifacts": value["artifacts"],
        },
    )


def validate_tag_rulesets(
    value: Any, *, repository: str, repository_id: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise TrustError("tag rulesets must contain creation and immutability rulesets")
    roles = ["creation_authority", "immutability"]
    for index, ruleset_value in enumerate(value):
        ruleset = closed(
            ruleset_value,
            {
                "schema_version",
                "role",
                "repository",
                "repository_id",
                "ruleset_id",
                "name",
                "target",
                "enforcement",
                "bypass_actors",
                "conditions",
                "rules",
            },
            f"tag ruleset {index}",
        )
        if ruleset["schema_version"] != "openadapt.production-release-tag-ruleset/v1":
            raise TrustError("tag ruleset schema is not supported")
        if (
            ruleset["role"] != roles[index]
            or ruleset["repository"] != repository
            or ruleset["repository_id"] != repository_id
        ):
            raise TrustError("tag ruleset identity differs")
        require_decimal_id(ruleset["ruleset_id"], "tag ruleset id")
        if ruleset["target"] != "tag" or ruleset["enforcement"] != "active":
            raise TrustError("tag ruleset is not active for tags")
        expected_name = (
            "OpenAdapt policy: release tag creation"
            if index == 0
            else "OpenAdapt policy: immutable release tags"
        )
        if ruleset["name"] != expected_name:
            raise TrustError("tag ruleset name differs from policy")
        actors = ruleset["bypass_actors"]
        expected_actors = (
            []
            if index
            else [
                {
                    "actor_id": "4730708",
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ]
        )
        if actors != expected_actors:
            raise TrustError("tag ruleset bypass authority differs")
        conditions = closed(
            ruleset["conditions"], {"ref_name"}, "tag ruleset conditions"
        )
        ref_name = closed(
            conditions["ref_name"], {"include", "exclude"}, "tag ref conditions"
        )
        for key in ("include", "exclude"):
            items = ref_name[key]
            if (
                not isinstance(items, list)
                or items != sorted(set(items))
                or any(not isinstance(item, str) or not item for item in items)
            ):
                raise TrustError("tag ref patterns must be sorted unique strings")
        if ref_name != {"include": ["refs/tags/v*"], "exclude": []}:
            raise TrustError("tag ruleset must match exactly refs/tags/v*")
        rules = ruleset["rules"]
        expected_rules = (
            [{"type": "creation"}]
            if index == 0
            else [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                },
            ]
        )
        if rules != expected_rules:
            raise TrustError("tag ruleset rules differ from immutable policy")
    return value


def validate_staging(value: Any) -> dict[str, Any]:
    staging = closed(
        value,
        {
            "schema_version",
            "repository",
            "repository_id",
            "draft_release_id",
            "tag",
            "target_commitish",
            "draft",
            "prerelease",
            "release_app_id",
            "release_app_installation_id",
            "release_app_bot_user_id",
            "release_author_login",
            "assets",
            "immutable_releases",
            "immutable_releases_sha256",
            "tag_rulesets",
            "tag_rulesets_sha256",
            "tag_ref_state",
            "tag_ref_state_sha256",
            "observed_at",
        },
        "publication staging",
    )
    if staging["schema_version"] != "openadapt.production-release-staging-evidence/v1":
        raise TrustError("publication staging schema is not supported")
    for field in (
        "repository_id",
        "draft_release_id",
        "release_app_id",
        "release_app_installation_id",
        "release_app_bot_user_id",
    ):
        require_decimal_id(staging[field], f"publication staging {field}")
    if (
        staging["draft"] is not True
        or staging["prerelease"] is not False
        or staging["release_app_id"] != "4730708"
        or staging["release_app_installation_id"] != "156835568"
        or staging["release_app_bot_user_id"] != "321543906"
        or staging["release_author_login"] != "openadapt-release[bot]"
    ):
        raise TrustError("publication staging authority or state differs")
    immutable_releases = closed(
        staging["immutable_releases"],
        {"enabled", "enforced_by_owner"},
        "immutable releases response",
    )
    if immutable_releases["enabled"] is not True or not isinstance(
        immutable_releases["enforced_by_owner"], bool
    ):
        raise TrustError("immutable releases are not enabled")
    if staging["immutable_releases_sha256"] != digest_bytes(
        IMMUTABLE_RELEASES_DOMAIN, immutable_releases
    ):
        raise TrustError("immutable releases response digest is invalid")
    tag_ref_state = closed(staging["tag_ref_state"], {"ref", "exists"}, "tag ref state")
    if tag_ref_state != {"ref": f"refs/tags/{staging['tag']}", "exists": False}:
        raise TrustError("release tag must not exist when the draft is staged")
    if staging["tag_ref_state_sha256"] != digest_bytes(
        TAG_REF_STATE_DOMAIN, tag_ref_state
    ):
        raise TrustError("tag ref state digest is invalid")
    if (
        not isinstance(staging["target_commitish"], str)
        or HEX40.fullmatch(staging["target_commitish"]) is None
    ):
        raise TrustError("publication staging target commit must be exact")
    if not isinstance(staging["tag"], str) or not staging["tag"]:
        raise TrustError("publication staging tag is invalid")
    assets = staging["assets"]
    if not isinstance(assets, list) or not assets:
        raise TrustError("publication staging assets are required")
    names: set[str] = set()
    ids: set[str] = set()
    for index, asset_value in enumerate(assets):
        asset = closed(
            asset_value,
            {
                "asset_id",
                "name",
                "kind",
                "sha256",
                "size_bytes",
                "media_type",
                "publish_destinations",
                "uploader_id",
                "uploader_login",
            },
            f"staged asset {index}",
        )
        require_decimal_id(asset["asset_id"], f"staged asset {index} id")
        require_digest(asset["sha256"], f"staged asset {index} digest")
        require_positive_int(asset["size_bytes"], f"staged asset {index} size")
        if not isinstance(asset["media_type"], str) or "/" not in asset["media_type"]:
            raise TrustError("staged asset media type is invalid")
        destinations = asset["publish_destinations"]
        if (
            not isinstance(destinations, list)
            or not destinations
            or destinations != sorted(set(destinations))
            or any(
                item not in {"deployment", "github-release", "pypi"}
                for item in destinations
            )
        ):
            raise TrustError("staged asset publish destinations are invalid")
        if (
            asset["uploader_id"] != "321543906"
            or asset["uploader_login"] != "openadapt-release[bot]"
        ):
            raise TrustError("staged asset uploader is not the release App")
        if asset["name"] in names or asset["asset_id"] in ids:
            raise TrustError("staged asset names and ids must be unique")
        names.add(asset["name"])
        ids.add(asset["asset_id"])
    if assets != sorted(assets, key=lambda item: (item["name"], item["asset_id"])):
        raise TrustError("staged assets must be sorted")
    validate_tag_rulesets(
        staging["tag_rulesets"],
        repository=staging["repository"],
        repository_id=staging["repository_id"],
    )
    if staging["tag_rulesets_sha256"] != digest_bytes(
        TAG_RULESETS_DOMAIN, staging["tag_rulesets"]
    ):
        raise TrustError("tag rulesets digest is invalid")
    require_timestamp(staging["observed_at"], "publication staging observed_at")
    return staging


def staging_digest(value: Mapping[str, Any]) -> str:
    return digest_bytes(STAGING_DOMAIN, value)


def validate_release(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    release_admission = closed(
        value,
        {
            "schema_version",
            "admission_id_sha256",
            "evidence_class",
            "target",
            "verdict",
            "claim_scope",
            "release_identity",
            "release",
            "release_sha256",
            "artifact_inventory_sha256",
            "publication_staging",
            "publication_staging_sha256",
            "production_acceptance_summary_reference",
            "production_acceptance_summary_bundle_reference",
            "authority_state_sha256",
            "revocation_state_sha256",
            "signer_registry_sha256",
            "publication_policy_sha256",
            "issued_at",
            "not_before",
            "expires_at",
            "issuer",
        },
        "qualification release",
    )
    if (
        release_admission["schema_version"] != "openadapt.qualification-release/v2"
        or release_admission["verdict"] != "accepted"
    ):
        raise TrustError("qualification release schema or verdict is invalid")
    if release_admission["evidence_class"] not in {
        "private-customer",
        "remote-safe-synthetic",
    }:
        raise TrustError("qualification release evidence class is invalid")
    if release_admission["target"] not in TARGETS:
        raise TrustError("qualification release target is invalid")
    target_contract = TARGET_CONTRACTS[release_admission["target"]]
    if release_admission["claim_scope"] != target_contract["claim_scope"]:
        raise TrustError("qualification release claim scope differs from target policy")
    identity = closed(
        release_admission["release_identity"],
        {"schema_version", "channel", "sequence", "previous_admission_sha256"},
        "release identity",
    )
    if (
        identity["schema_version"] != "openadapt.monotonic-production-release/v1"
        or identity["channel"] != "production"
    ):
        raise TrustError("release identity schema or channel is invalid")
    require_positive_int(identity["sequence"], "release sequence")
    if identity["previous_admission_sha256"] is not None:
        require_digest(
            identity["previous_admission_sha256"], "previous release admission"
        )
    release = closed(
        release_admission["release"],
        {
            "schema_version",
            "kind",
            "source_repository",
            "source_repository_id",
            "source_commit",
            "version",
            "tag",
            "deployment_id",
            "deployment_sha256",
            "artifacts",
        },
        "release candidate",
    )
    if release[
        "schema_version"
    ] != "openadapt.production-release-candidate/v1" or release["kind"] not in {
        "package",
        "deployment",
        "hybrid",
    }:
        raise TrustError("release candidate schema or kind is invalid")
    if (
        release["kind"] != target_contract["release_kind"]
        or release["source_repository"] != target_contract["repository"]
        or release["source_repository_id"] != target_contract["repository_id"]
    ):
        raise TrustError("release candidate differs from the target policy")
    require_decimal_id(release["source_repository_id"], "release source repository id")
    if (
        not isinstance(release["source_commit"], str)
        or HEX40.fullmatch(release["source_commit"]) is None
    ):
        raise TrustError("release source commit must be exact")
    if release["kind"] != "deployment" and (
        not isinstance(release["version"], str)
        or BUNDLE_VERSION.fullmatch(release["version"]) is None
        or not isinstance(release["tag"], str)
        or RELEASE_TAG.fullmatch(release["tag"]) is None
        or release["tag"] != f"v{release['version']}"
    ):
        raise TrustError("release package version or tag is invalid")
    if release["kind"] == "package":
        if (
            release["deployment_id"] is not None
            or release["deployment_sha256"] is not None
        ):
            raise TrustError("package release identity fields are invalid")
    elif release["kind"] == "deployment":
        if (
            release["version"] is not None
            or release["tag"] is not None
            or require_decimal_id(release["deployment_id"], "deployment id") is None
        ):
            raise TrustError("deployment release identity fields are invalid")
        require_digest(release["deployment_sha256"], "deployment digest")
    else:
        require_decimal_id(release["deployment_id"], "deployment id")
        require_digest(release["deployment_sha256"], "deployment digest")
    artifacts = validate_artifacts(
        release["artifacts"], target=release_admission["target"]
    )
    if release_admission["target"] == "desktop":
        if any(
            token in item["name"].casefold()
            for item in artifacts
            for token in ("beta", "candidate", "adhoc", "unsigned")
        ):
            raise TrustError("Desktop release filenames contain a non-production label")
        version = release["version"]
        expected_metadata_names = {
            "verification-metadata-linux-x86-64": (
                f"OpenAdapt-Desktop-v{version}-linux-x86_64-verification.json"
            ),
            "verification-metadata-macos-arm64": (
                f"OpenAdapt-Desktop-v{version}-macos-arm64-verification.json"
            ),
            "verification-metadata-macos-x86-64": (
                f"OpenAdapt-Desktop-v{version}-macos-x86_64-verification.json"
            ),
            "verification-metadata-windows-x86-64": (
                f"OpenAdapt-Desktop-v{version}-windows-x86_64-verification.json"
            ),
        }
        for artifact in artifacts:
            expected_name = expected_metadata_names.get(artifact["kind"])
            if expected_name is not None and artifact["name"] != expected_name:
                raise TrustError("Desktop verification metadata filename differs")
    inventory = {
        "target": release_admission["target"],
        "claim_scope": release_admission["claim_scope"],
        "artifacts": artifacts,
    }
    if release_admission["artifact_inventory_sha256"] != digest_bytes(
        ARTIFACT_INVENTORY_DOMAIN, inventory
    ):
        raise TrustError("release artifact inventory digest is invalid")
    if release_admission["release_sha256"] != digest_bytes(
        RELEASE_DOMAIN,
        {
            "target": release_admission["target"],
            "claim_scope": release_admission["claim_scope"],
            "release": release,
        },
    ):
        raise TrustError("release candidate digest is invalid")
    staging = validate_staging(release_admission["publication_staging"])
    if release_admission["publication_staging_sha256"] != staging_digest(staging):
        raise TrustError("publication staging digest is invalid")
    expected_staging_tag = release["tag"] or (
        f"v0.0.0-deployment.{release['deployment_id']}"
    )
    if (
        staging["repository"] != release["source_repository"]
        or staging["repository_id"] != release["source_repository_id"]
        or staging["target_commitish"] != release["source_commit"]
        or staging["tag"] != expected_staging_tag
    ):
        raise TrustError("publication staging differs from the release candidate")
    bound_fields = (
        "name",
        "kind",
        "sha256",
        "size_bytes",
        "media_type",
        "publish_destinations",
    )
    staged = [
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in staging["assets"]
    ]
    admitted = [
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in artifacts
    ]
    if sorted(staged) != sorted(admitted):
        raise TrustError(
            "publication staging assets differ from the admitted inventory"
        )
    validate_reference_pair(
        release_admission["production_acceptance_summary_reference"],
        release_admission["production_acceptance_summary_bundle_reference"],
        kind="production-acceptance-summary",
    )
    for field in (
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "publication_policy_sha256",
    ):
        require_digest(release_admission[field], field)
    issuer = closed(
        release_admission["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "release issuer",
    )
    if (
        issuer
        != {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-release-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": issuer["source_commit"],
            "environment": "production-release-admission",
        }
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("release issuer identity differs")
    validate_window(release_admission, maximum=timedelta(days=30), now=now)
    validate_staging_observation_age(staging, release_admission)
    projection = dict(release_admission)
    admission_id = projection.pop("admission_id_sha256")
    if admission_id != digest_bytes(RELEASE_ADMISSION_DOMAIN, projection):
        raise TrustError("qualification release admission id is invalid")
    return release_admission


def verify_local_artifacts(root: Path, artifacts: Sequence[Mapping[str, Any]]) -> None:
    if not root.is_dir():
        raise TrustError("artifact root is not a directory")
    actual_files = sorted(path.name for path in root.iterdir() if path.is_file())
    expected_files = sorted(item["name"] for item in artifacts)
    if actual_files != expected_files:
        raise TrustError("candidate artifact contains missing or extra files")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise TrustError("candidate artifact cannot contain symlinks")
    if any(path.is_file() and path.parent != root for path in root.rglob("*")):
        raise TrustError("candidate artifact files must be at the artifact root")
    for artifact in artifacts:
        path = root / artifact["name"]
        raw = path.read_bytes()
        if (
            len(raw) != artifact["size_bytes"]
            or "sha256:" + hashlib.sha256(raw).hexdigest() != artifact["sha256"]
        ):
            raise TrustError(f"candidate artifact bytes differ: {artifact['name']}")


def validate_support_release(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "admission_id_sha256",
        "lifecycle_state",
        "support_target",
        "verdict",
        "claim_scope",
        "release_identity",
        "release",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "support_policy_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    admission = closed(value, fields, "Support release admission")
    if (
        admission["schema_version"] != "openadapt.support-release-admission/v1"
        or admission["lifecycle_state"] != "Support"
        or admission["support_target"] != "openadapt-tray"
        or admission["verdict"] != "accepted"
        or admission["claim_scope"] != "support_openadapt_tray"
    ):
        raise TrustError("Support release admission identity differs")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(admission[field], field)
    try:
        support_policy = json.loads(SUPPORT_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustError("Support release policy is unavailable") from exc
    expected_support_policy = {
        "$schema": "schemas/support-release-policy.schema.json",
        "schema_version": "openadapt.support-release-policy/v1",
        "lifecycle_state": "Support",
        "production_projection": False,
        "maximum_admission_days": 7,
        "release_authority": {
            "app_id": "4730708",
            "app_slug": "openadapt-release",
            "installation_id": "156835568",
            "bot_user_id": "321543906",
            "bot_login": "openadapt-release[bot]",
            "admission_environment": "support-release-admission",
            "effect_environment": "release-identity",
            "tag_creation_ruleset": "OpenAdapt policy: release tag creation",
            "tag_immutability_ruleset": "OpenAdapt policy: immutable release tags",
        },
        "targets": [
            {
                "id": "openadapt-tray",
                "repository": "OpenAdaptAI/openadapt-tray",
                "repository_id": "1136122737",
                "claim_scope": "support_openadapt_tray",
                "release_kind": "package",
                "tag_pattern": "refs/tags/v*",
                "artifacts": [
                    {
                        "kind": "python-sdist",
                        "media_type": "application/gzip",
                        "publish_destinations": ["github-release", "pypi"],
                    },
                    {
                        "kind": "python-wheel",
                        "media_type": "application/zip",
                        "publish_destinations": ["github-release", "pypi"],
                    },
                ],
            }
        ],
    }
    if support_policy != expected_support_policy or admission[
        "support_policy_sha256"
    ] != digest_bytes(SUPPORT_POLICY_DOMAIN, support_policy):
        raise TrustError("Support release policy binding differs")
    identity = closed(
        admission["release_identity"],
        {"schema_version", "channel", "sequence", "previous_admission_sha256"},
        "Support release identity",
    )
    if (
        identity["schema_version"] != "openadapt.monotonic-support-release/v1"
        or identity["channel"] != "support"
    ):
        raise TrustError("Support release identity schema differs")
    sequence = require_positive_int(identity["sequence"], "Support release sequence")
    if sequence == 1:
        if identity["previous_admission_sha256"] is not None:
            raise TrustError("first Support release cannot have a previous admission")
    else:
        require_digest(
            identity["previous_admission_sha256"], "previous Support release admission"
        )
    release = closed(
        admission["release"],
        {
            "schema_version",
            "kind",
            "source_repository",
            "source_repository_id",
            "source_commit",
            "version",
            "tag",
            "deployment_id",
            "deployment_sha256",
            "artifacts",
        },
        "Support release candidate",
    )
    if (
        release["schema_version"] != "openadapt.production-release-candidate/v1"
        or release["kind"] != "package"
        or release["source_repository"] != "OpenAdaptAI/openadapt-tray"
        or release["source_repository_id"] != "1136122737"
        or not isinstance(release["source_commit"], str)
        or HEX40.fullmatch(release["source_commit"]) is None
        or not isinstance(release["version"], str)
        or not release["version"]
        or release["tag"] != f"v{release['version']}"
        or release["deployment_id"] is not None
        or release["deployment_sha256"] is not None
    ):
        raise TrustError("Support release candidate differs from openadapt-tray")
    artifacts = validate_artifacts(release["artifacts"])
    if [item["kind"] for item in artifacts] != ["python-sdist", "python-wheel"]:
        raise TrustError("openadapt-tray Support release must contain wheel and sdist")
    expected_profiles = {
        "python-sdist": ("application/gzip", ["github-release", "pypi"]),
        "python-wheel": ("application/zip", ["github-release", "pypi"]),
    }
    for artifact in artifacts:
        media_type, destinations = expected_profiles[artifact["kind"]]
        if (
            artifact["media_type"] != media_type
            or artifact["publish_destinations"] != destinations
        ):
            raise TrustError("openadapt-tray Support artifact profile differs")
    inventory = {
        "support_target": admission["support_target"],
        "claim_scope": admission["claim_scope"],
        "artifacts": artifacts,
    }
    if admission["artifact_inventory_sha256"] != digest_bytes(
        SUPPORT_ARTIFACT_INVENTORY_DOMAIN, inventory
    ):
        raise TrustError("Support artifact inventory digest is invalid")
    if admission["release_sha256"] != digest_bytes(
        SUPPORT_RELEASE_DOMAIN,
        {
            "support_target": admission["support_target"],
            "claim_scope": admission["claim_scope"],
            "release": release,
        },
    ):
        raise TrustError("Support release candidate digest is invalid")
    staging = validate_staging(admission["publication_staging"])
    if (
        admission["publication_staging_sha256"] != staging_digest(staging)
        or staging["repository"] != release["source_repository"]
        or staging["repository_id"] != release["source_repository_id"]
        or staging["target_commitish"] != release["source_commit"]
        or staging["tag"] != release["tag"]
    ):
        raise TrustError("Support publication staging differs from the release")
    bound_fields = (
        "name",
        "kind",
        "sha256",
        "size_bytes",
        "media_type",
        "publish_destinations",
    )
    staged = sorted(
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in staging["assets"]
    )
    admitted = sorted(
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in artifacts
    )
    if staged != admitted:
        raise TrustError("Support staged assets differ from the admitted inventory")
    issuer = closed(
        admission["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "Support release issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/.github"
        or issuer["repository_id"] != "858454062"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/issue-support-release-admission.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "support-release-admission"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("Support release issuer differs")
    validate_window(admission, maximum=timedelta(days=7), now=now)
    validate_staging_observation_age(staging, admission)
    projection = dict(admission)
    identity_digest = projection.pop("admission_id_sha256")
    if identity_digest != digest_bytes(SUPPORT_RELEASE_ADMISSION_DOMAIN, projection):
        raise TrustError("Support release admission id is invalid")
    return admission


def validate_publication_recovery_authorization(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "authorization_id_sha256",
        "qualification_release_reference",
        "qualification_release_object_sha256",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging_sha256",
        "repository",
        "repository_id",
        "target",
        "tag",
        "tag_ref",
        "tag_object_id",
        "target_commit",
        "draft_release_id",
        "requested_effect",
        "run_id",
        "run_attempt",
        "dispatcher_actor_id",
        "environment",
        "release_app",
        "idempotency_key",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    authorization = closed(
        value, fields, "production publication recovery authorization"
    )
    if (
        authorization["schema_version"]
        != "openadapt.production-publication-recovery-authorization/v2"
        or authorization["run_attempt"] != "1"
        or authorization["dispatcher_actor_id"] != "774615"
    ):
        raise TrustError("publication recovery authorization identity differs")
    target = authorization["target"]
    contract = TARGET_CONTRACTS.get(target)
    if contract is None or contract["release_kind"] != "package":
        raise TrustError("publication recovery applies only to package targets")
    if (
        authorization["repository"] != contract["repository"]
        or authorization["repository_id"] != contract["repository_id"]
    ):
        raise TrustError("publication recovery target repository differs")
    for field in (
        "authorization_id_sha256",
        "qualification_release_object_sha256",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging_sha256",
    ):
        require_digest(authorization[field], field)
    reference = evidence.validate_reference(
        authorization["qualification_release_reference"]
    )
    if (
        reference["kind"] != "qualification-release"
        or reference["object_schema_version"] != "openadapt.qualification-release/v2"
        or reference["object_media_type"]
        != "application/vnd.openadapt.qualification-release+json;version=2"
        or reference["subject_sha256"] is not None
        or reference["object_sha256"]
        != authorization["qualification_release_object_sha256"]
    ):
        raise TrustError("publication recovery release reference differs")
    if (
        not isinstance(authorization["tag"], str)
        or RELEASE_TAG.fullmatch(authorization["tag"]) is None
        or authorization["tag_ref"] != f"refs/tags/{authorization['tag']}"
        or not isinstance(authorization["tag_object_id"], str)
        or HEX40.fullmatch(authorization["tag_object_id"]) is None
        or not isinstance(authorization["target_commit"], str)
        or HEX40.fullmatch(authorization["target_commit"]) is None
    ):
        raise TrustError("publication recovery immutable tag binding differs")
    require_decimal_id(authorization["draft_release_id"], "draft release id")
    require_decimal_id(authorization["run_id"], "recovery run id")
    effect = authorization["requested_effect"]
    effect_environments = {
        "stage-draft-assets": "release-identity",
        "publish-pypi": "pypi",
        "publish-github-release": "release-identity",
        "publish-mcp-registry": "mcp-registry",
    }
    if (
        effect not in effect_environments
        or authorization["environment"] != effect_environments[effect]
        or (effect == "publish-mcp-registry" and target != "agent")
    ):
        raise TrustError("publication recovery effect or environment differs")
    release_app = closed(
        authorization["release_app"],
        {"app_id", "installation_id", "bot_user_id", "bot_login"},
        "publication recovery release App",
    )
    if release_app != {
        "app_id": "4730708",
        "installation_id": "156835568",
        "bot_user_id": "321543906",
        "bot_login": "openadapt-release[bot]",
    }:
        raise TrustError("publication recovery release App differs")
    idempotency_projection = {
        field: authorization[field]
        for field in (
            "qualification_release_object_sha256",
            "release_sha256",
            "artifact_inventory_sha256",
            "publication_staging_sha256",
            "repository",
            "repository_id",
            "target",
            "tag",
            "tag_ref",
            "tag_object_id",
            "target_commit",
            "draft_release_id",
            "requested_effect",
            "run_id",
            "run_attempt",
            "dispatcher_actor_id",
            "environment",
            "release_app",
        )
    }
    expected_idempotency = (
        "publication-recovery:"
        + hashlib.sha256(
            PUBLICATION_RECOVERY_IDEMPOTENCY_DOMAIN + canonical(idempotency_projection)
        ).hexdigest()
    )
    if authorization["idempotency_key"] != expected_idempotency:
        raise TrustError("publication recovery idempotency key differs")
    issuer = closed(
        authorization["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "publication recovery issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/.github"
        or issuer["repository_id"] != "858454062"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"]
        != ".github/workflows/issue-production-publication-recovery.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != authorization["environment"]
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("publication recovery issuer differs")
    validate_window(authorization, maximum=timedelta(minutes=5), now=now)
    projection = dict(authorization)
    identity = projection.pop("authorization_id_sha256")
    if identity != digest_bytes(PUBLICATION_RECOVERY_AUTHORIZATION_DOMAIN, projection):
        raise TrustError("publication recovery authorization id differs")
    return authorization


def validate_publication_recovery_replay(
    previous_value: Any,
    current_value: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Refuse expired effects and any changed one-use recovery claim."""

    previous = validate_publication_recovery_authorization(previous_value)
    current = validate_publication_recovery_authorization(current_value)
    if canonical(previous) == canonical(current):
        return validate_publication_recovery_authorization(
            current, now=now or datetime.now(timezone.utc)
        )
    previous_consumption = (
        previous["repository_id"],
        previous["tag_ref"],
        previous["requested_effect"],
    )
    current_consumption = (
        current["repository_id"],
        current["tag_ref"],
        current["requested_effect"],
    )
    if (
        previous["idempotency_key"] == current["idempotency_key"]
        or previous_consumption == current_consumption
    ):
        raise TrustError("publication recovery one-use claim conflicts")
    return validate_publication_recovery_authorization(
        current, now=now or datetime.now(timezone.utc)
    )


def _validate_receipt_structure(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "evidence_class",
        "decision_identity_sha256",
        "decision_revision",
        "decision_commitment_sha256",
        "evidence_manifest_sha256",
        "evidence_manifest_readback_sha256",
        "campaign_artifact_sha256",
        "organization_id_sha256",
        "workflow_id_sha256",
        "workflow_version_id_sha256",
        "bundle_version",
        "bundle_sha256",
        "admitted_runtime_sha256",
        "application_contract_sha256",
        "environment_contract_sha256",
        "input_contract_sha256",
        "action_contract_sha256",
        "identity_contract_sha256",
        "effect_contract_sha256",
        "policy_contract_sha256",
        "evidence_authority_contract_sha256",
        "campaign_permit_sha256",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "entity_class",
        "campaign_summary",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "algorithm",
        "signing_statement",
        "signature",
        "issuer",
    }
    receipt = closed(value, fields, "qualification evidence decision receipt")
    if (
        receipt["schema_version"]
        != "openadapt.qualification-evidence-decision-receipt/v2"
        or receipt["verdict"] != "ADMIT"
    ):
        raise TrustError("decision receipt schema or verdict is invalid")
    evidence_class = receipt["evidence_class"]
    if evidence_class not in {
        "private-customer",
        "remote-safe-synthetic",
    }:
        raise TrustError("decision receipt evidence class is invalid")
    digest_fields = fields - {
        "schema_version",
        "evidence_class",
        "decision_revision",
        "bundle_version",
        "entity_class",
        "campaign_summary",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "algorithm",
        "signing_statement",
        "signature",
        "issuer",
    }
    for field in digest_fields:
        require_digest(receipt[field], field)
    if (
        len(
            {
                receipt["decision_commitment_sha256"],
                receipt["evidence_manifest_sha256"],
                receipt["evidence_manifest_readback_sha256"],
                receipt["campaign_artifact_sha256"],
            }
        )
        != 4
    ):
        raise TrustError(
            "decision, final manifest, and campaign commitments must be distinct"
        )
    require_positive_int(receipt["decision_revision"], "decision revision")
    if (
        not isinstance(receipt["bundle_version"], str)
        or len(receipt["bundle_version"]) > 64
        or BUNDLE_VERSION.fullmatch(receipt["bundle_version"]) is None
    ):
        raise TrustError("bundle version is not canonical")
    if (
        not isinstance(receipt["entity_class"], str)
        or ENTITY_CLASS.fullmatch(receipt["entity_class"]) is None
    ):
        raise TrustError("entity class is not remote-safe")
    campaign_summary = closed(
        receipt["campaign_summary"],
        {
            "schema_version",
            "minimum_trials_per_task_condition",
            "task_count",
            "classes",
        },
        "decision receipt campaign summary",
    )
    if (
        campaign_summary["schema_version"]
        != "openadapt.qualification-evidence-decision-campaign-summary/v1"
        or campaign_summary["minimum_trials_per_task_condition"] != 3
    ):
        raise TrustError("decision receipt campaign summary identity differs")
    require_positive_int(campaign_summary["task_count"], "campaign task count")
    validate_campaign_summary(campaign_summary["classes"])
    if any(
        counts["task_condition_cell_count"] < campaign_summary["task_count"]
        for counts in campaign_summary["classes"].values()
    ):
        raise TrustError("decision receipt campaign summary omits a task/class cell")
    if (
        receipt["algorithm"] != "ed25519"
        or not isinstance(receipt["issuer_key_id"], str)
        or evidence.KEY_ID.fullmatch(receipt["issuer_key_id"]) is None
    ):
        raise TrustError("decision receipt signer is invalid")
    signature = receipt["signature"]
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature) is None
    ):
        raise TrustError("decision receipt signature must be canonical padded base64")
    try:
        raw_signature = evidence.base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise TrustError("decision receipt signature is invalid") from exc
    if len(raw_signature) != 64:
        raise TrustError("decision receipt signature must contain 64 bytes")
    validate_signing_statement(
        receipt,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v2",
        signature_domain=DECISION_RECEIPT_SIGNATURE_DOMAIN,
    )
    issuer = closed(
        receipt["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "decision receipt issuer",
    )
    expected_issuer = (
        {
            "repository": "OpenAdaptAI/openadapt-internal",
            "repository_id": "1170060695",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-private-qualification-evidence-decision.yml"
            ),
            "ref": "refs/heads/main",
            "environment": "private-qualification-evidence-decision",
        }
        if evidence_class == "private-customer"
        else {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-synthetic-qualification-evidence-decision.yml"
            ),
            "ref": "refs/heads/main",
            "environment": "synthetic-qualification-evidence-decision",
        }
    )
    actual_issuer = dict(issuer)
    source_commit = actual_issuer.pop("source_commit")
    if (
        actual_issuer != expected_issuer
        or not isinstance(source_commit, str)
        or HEX40.fullmatch(source_commit) is None
    ):
        raise TrustError("decision receipt issuer differs")
    validate_window(receipt, maximum=timedelta(days=7), now=now)
    return receipt


def validate_receipt(
    value: Any,
    *,
    signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate the receipt bytes and its active registered Ed25519 signature."""

    receipt = _validate_receipt_structure(value, now=now)
    try:
        registry = evidence.validate_signer_registry(signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    if receipt["signer_registry_sha256"] != evidence.signer_registry_identity_digest(
        registry
    ):
        raise TrustError("decision receipt signer registry identity differs")
    verify_embedded_signature(
        receipt,
        signer_registry=registry,
        object_schema_version=("openadapt.qualification-evidence-decision-receipt/v2"),
        signature_domain=DECISION_RECEIPT_SIGNATURE_DOMAIN,
        usage="qualification-evidence-decision-receipt",
        now=now,
    )
    return receipt


def signing_statement(
    value: Mapping[str, Any],
    *,
    object_schema_version: str,
    signature_domain: bytes,
) -> dict[str, Any]:
    unsigned = dict(value)
    unsigned.pop("signature", None)
    unsigned.pop("signing_statement", None)
    unsigned_bytes = canonical(unsigned) + b"\n"
    return {
        "schema_version": "openadapt.qualification-evidence-signing-statement/v1",
        "object_schema_version": object_schema_version,
        "signature_domain": signature_domain.decode("utf-8"),
        "unsigned_object_sha256": (
            "sha256:" + hashlib.sha256(unsigned_bytes).hexdigest()
        ),
        "unsigned_size_bytes": len(unsigned_bytes),
        "commitment_scheme": "sha256-canonical-json-lf",
    }


def validate_signing_statement(
    value: Mapping[str, Any],
    *,
    object_schema_version: str,
    signature_domain: bytes,
) -> dict[str, Any]:
    statement = closed(
        value.get("signing_statement"),
        {
            "schema_version",
            "object_schema_version",
            "signature_domain",
            "unsigned_object_sha256",
            "unsigned_size_bytes",
            "commitment_scheme",
        },
        "qualification evidence signing statement",
    )
    expected = signing_statement(
        value,
        object_schema_version=object_schema_version,
        signature_domain=signature_domain,
    )
    if statement != expected:
        raise TrustError("qualification evidence signing statement differs")
    return statement


def verify_embedded_signature(
    value: Mapping[str, Any],
    *,
    signer_registry: Any,
    object_schema_version: str,
    signature_domain: bytes,
    usage: str,
    now: datetime | None = None,
) -> None:
    try:
        registry = evidence.validate_signer_registry(signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    requested_time = now or datetime.now(timezone.utc)
    generated = evidence._timestamp(registry["generated_at"], "generated_at")
    expires = evidence._timestamp(registry["expires_at"], "expires_at")
    if not generated <= requested_time < expires:
        raise TrustError("signer registry is not active")
    key_id = value.get("issuer_key_id")
    matches = [item for item in registry["signers"] if item["key_id"] == key_id]
    if len(matches) != 1 or matches[0]["status"] != "active":
        raise TrustError("embedded signature key is not an active registered signer")
    signer = matches[0]
    if usage not in signer["allowed_usages"]:
        raise TrustError("embedded signature usage is not allowed for the key")
    issuer = value.get("issuer")
    if not isinstance(issuer, dict):
        raise TrustError("signed object has no issuer identity")
    workflow_identity = (
        f"https://github.com/{issuer['repository']}/{issuer['workflow']}"
        f"@{issuer['ref']}"
    )
    if workflow_identity not in signer["allowed_workflows"]:
        raise TrustError("embedded signature workflow is not allowed for the key")
    if (
        "allowed_environments" in signer
        and issuer.get("environment") not in signer["allowed_environments"]
    ):
        raise TrustError("embedded signature environment is not allowed for the key")
    ref = issuer["ref"]
    if not any(
        ref == prefix or ref.startswith(prefix.rstrip("/") + "/")
        for prefix in signer["allowed_ref_prefixes"]
    ):
        raise TrustError("embedded signature ref is not allowed for the key")
    if signer["statement_schema_versions"] != [
        "openadapt.qualification-evidence-signing-statement/v1"
    ]:
        raise TrustError("embedded signature statement schema is not allowed")
    statement = validate_signing_statement(
        value,
        object_schema_version=object_schema_version,
        signature_domain=signature_domain,
    )
    statement_bytes = canonical(statement) + b"\n"
    try:
        public_key = evidence.base64.urlsafe_b64decode(
            signer["public_key"] + "=" * (-len(signer["public_key"]) % 4)
        )
        signature = evidence.base64.b64decode(value["signature"], validate=True)
    except Exception as exc:
        raise TrustError("embedded signature bytes are invalid") from exc
    spki = bytes.fromhex("302a300506032b6570032100") + public_key
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        key_path = directory / "key.der"
        statement_path = directory / "statement.json"
        signature_path = directory / "signature.bin"
        key_path.write_bytes(spki)
        statement_path.write_bytes(statement_bytes)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(statement_path),
                "-sigfile",
                str(signature_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode:
        raise TrustError("embedded Ed25519 signing statement verification failed")


def _validate_embedded_signature(
    value: Mapping[str, Any],
    label: str,
    *,
    object_schema_version: str,
    signature_domain: bytes,
) -> None:
    if (
        value["algorithm"] != "ed25519"
        or not isinstance(value["issuer_key_id"], str)
        or evidence.KEY_ID.fullmatch(value["issuer_key_id"]) is None
    ):
        raise TrustError(f"{label} signer is invalid")
    signature = value["signature"]
    if (
        not isinstance(signature, str)
        or re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature) is None
    ):
        raise TrustError(f"{label} signature must be canonical padded base64")
    try:
        raw = evidence.base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise TrustError(f"{label} signature is invalid") from exc
    if len(raw) != 64:
        raise TrustError(f"{label} signature must contain 64 bytes")
    validate_signing_statement(
        value,
        object_schema_version=object_schema_version,
        signature_domain=signature_domain,
    )


def validate_authority_state(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "authority_state_sha256",
        "status",
        "signer_registry_sha256",
        "signer_registry_identity_sha256",
        "signer_registry_revision",
        "evidence_authority_sha256",
        "observed_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "algorithm",
        "signing_statement",
        "signature",
        "issuer",
    }
    state = closed(value, fields, "qualification authority state receipt")
    if (
        state["schema_version"] != "openadapt.qualification-authority-state-receipt/v2"
        or state["status"] != "active"
    ):
        raise TrustError("qualification authority state is not active")
    for field in (
        "signer_registry_sha256",
        "signer_registry_identity_sha256",
        "evidence_authority_sha256",
    ):
        require_digest(state[field], field)
    require_positive_int(state["signer_registry_revision"], "signer registry revision")
    projection = dict(state)
    identity = projection.pop("authority_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    if identity != digest_bytes(AUTHORITY_STATE_IDENTITY_DOMAIN, projection):
        raise TrustError("qualification authority state identity is invalid")
    _validate_embedded_signature(
        state,
        "qualification authority state",
        object_schema_version="openadapt.qualification-authority-state-receipt/v2",
        signature_domain=AUTHORITY_STATE_SIGNATURE_DOMAIN,
    )
    issuer = closed(
        state["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "authority state issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-ops"
        or issuer["repository_id"] != "1172011294"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/qualification-authority-state.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "qualification-authority-state"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("authority state issuer differs")
    validate_window(
        {
            "issued_at": state["observed_at"],
            "not_before": state["not_before"],
            "expires_at": state["expires_at"],
        },
        maximum=timedelta(days=7),
        now=now,
    )
    return state


def validate_revocation_state(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "revocation_state_sha256",
        "previous_revocation_state_sha256",
        "revision",
        "status",
        "authority_state_sha256",
        "signer_registry_sha256",
        "revocations",
        "observed_at",
        "not_before",
        "expires_at",
        "issuer_key_id",
        "algorithm",
        "signing_statement",
        "signature",
        "issuer",
    }
    state = closed(value, fields, "qualification revocation state receipt")
    if (
        state["schema_version"] != "openadapt.qualification-revocation-state-receipt/v1"
        or state["status"] != "current"
    ):
        raise TrustError("qualification revocation state is not current")
    for field in ("authority_state_sha256", "signer_registry_sha256"):
        require_digest(state[field], field)
    if state["previous_revocation_state_sha256"] is not None:
        require_digest(
            state["previous_revocation_state_sha256"], "previous revocation state"
        )
    require_positive_int(state["revision"], "revocation state revision")
    revocations = state["revocations"]
    if not isinstance(revocations, list):
        raise TrustError("revocations must be an array")
    identities: list[tuple[str, str]] = []
    for index, item_value in enumerate(revocations):
        item = closed(
            item_value,
            {"subject_kind", "subject_id", "revoked_at", "reason_code"},
            f"revocation {index}",
        )
        if not all(
            isinstance(item[field], str) and item[field]
            for field in ("subject_kind", "subject_id", "reason_code")
        ):
            raise TrustError("revocation identity or reason is invalid")
        if (
            item["subject_kind"] == "qualification-campaign-permit"
            and DIGEST.fullmatch(item["subject_id"]) is None
        ):
            raise TrustError("campaign permit revocation subject must be opaque")
        require_timestamp(item["revoked_at"], "revoked_at")
        identities.append((item["subject_kind"], item["subject_id"]))
    if identities != sorted(set(identities)):
        raise TrustError("revocations must be sorted and unique")
    projection = dict(state)
    identity = projection.pop("revocation_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    if identity != digest_bytes(REVOCATION_STATE_IDENTITY_DOMAIN, projection):
        raise TrustError("qualification revocation state identity is invalid")
    _validate_embedded_signature(
        state,
        "qualification revocation state",
        object_schema_version="openadapt.qualification-revocation-state-receipt/v1",
        signature_domain=REVOCATION_STATE_SIGNATURE_DOMAIN,
    )
    issuer = closed(
        state["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "revocation state issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-ops"
        or issuer["repository_id"] != "1172011294"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/qualification-revocation-state.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "qualification-revocation-state"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("revocation state issuer differs")
    validate_window(
        {
            "issued_at": state["observed_at"],
            "not_before": state["not_before"],
            "expires_at": state["expires_at"],
        },
        maximum=timedelta(days=7),
        now=now,
    )
    return state


def validate_admission_current_state(
    admission_value: Any,
    *,
    admission_reference: Any,
    authority_state: Any,
    revocation_state: Any,
    signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind one release/workflow admission to the exact active trust state."""

    verification_time = now or datetime.now(timezone.utc)
    schema = (
        admission_value.get("schema_version")
        if isinstance(admission_value, dict)
        else None
    )
    if schema == "openadapt.qualification-release/v2":
        admission = validate_release(admission_value, now=verification_time)
        expected_kind = "qualification-release"
    elif schema == "openadapt.support-release-admission/v1":
        admission = validate_support_release(admission_value, now=verification_time)
        expected_kind = "support-release-admission"
    elif schema == "openadapt.qualification-admission/v4":
        admission = validate_qualification_admission(
            admission_value, now=verification_time
        )
        expected_kind = "qualification-admission"
    else:
        raise TrustError("admission schema is not current-state aware")
    reference = evidence.validate_reference(admission_reference)
    if (
        reference["kind"] != expected_kind
        or reference["subject_sha256"] is not None
        or reference["object_sha256"]
        != "sha256:" + hashlib.sha256(canonical(admission) + b"\n").hexdigest()
        or reference["semantic_identity_sha256"]
        != evidence.semantic_identity_digest(
            kind=expected_kind,
            object_schema_version=reference["object_schema_version"],
            object_value=admission,
            object_sha256=reference["object_sha256"],
        )
    ):
        raise TrustError("admission reference differs from the signed object")
    try:
        registry = evidence.validate_signer_registry(signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    authority = validate_authority_state(authority_state, now=verification_time)
    revocation = validate_revocation_state(revocation_state, now=verification_time)
    registry_identity = evidence.signer_registry_identity_digest(registry)
    registry_raw_sha = (
        "sha256:" + hashlib.sha256(evidence.canonical(registry) + b"\n").hexdigest()
    )
    if (
        authority["signer_registry_sha256"] != registry_raw_sha
        or authority["signer_registry_identity_sha256"] != registry_identity
        or authority["signer_registry_revision"] != registry["revision"]
        or revocation["signer_registry_sha256"] != registry_identity
        or revocation["authority_state_sha256"] != authority["authority_state_sha256"]
        or admission["signer_registry_sha256"] != registry_identity
        or admission["revocation_state_sha256"] != revocation["revocation_state_sha256"]
    ):
        raise TrustError("admission current trust state differs")
    if "authority_state_sha256" in admission and (
        admission["authority_state_sha256"] != authority["authority_state_sha256"]
    ):
        raise TrustError("admission current authority state differs")
    verify_embedded_signature(
        authority,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-authority-state-receipt/v2",
        signature_domain=AUTHORITY_STATE_SIGNATURE_DOMAIN,
        usage="qualification-authority-state-receipt",
        now=verification_time,
    )
    verify_embedded_signature(
        revocation,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-revocation-state-receipt/v1",
        signature_domain=REVOCATION_STATE_SIGNATURE_DOMAIN,
        usage="qualification-revocation-state-receipt",
        now=verification_time,
    )
    revoked = {
        (item["subject_kind"], item["subject_id"]) for item in revocation["revocations"]
    }
    if (reference["kind"], reference["semantic_identity_sha256"]) in revoked:
        raise TrustError("admission is revoked")
    for signer in registry["signers"]:
        if (
            signer["status"] == "active"
            and ("qualification-signer-key", signer["public_key_sha256"]) in revoked
        ):
            raise TrustError("an active signer key is revoked")
    return admission


def validate_local_identity_opening(value: Any) -> dict[str, Any]:
    opening = closed(
        value,
        {
            "schema_version",
            "algorithm",
            "required",
            "customer_controlled_secret_required",
            "exact_contract_match_required",
            "revalidation_before_actuation",
            "maximum_age_seconds",
        },
        "local identity opening",
    )
    if opening != {
        "schema_version": "openadapt.qualification-local-identity-opening/v1",
        "algorithm": "hmac-sha256",
        "required": True,
        "customer_controlled_secret_required": True,
        "exact_contract_match_required": True,
        "revalidation_before_actuation": True,
        "maximum_age_seconds": 60,
    }:
        raise TrustError("local customer-bound identity opening contract differs")
    return opening


def validate_qualification_admission(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "admission_id_sha256",
        "evidence_class",
        "organization_id_sha256",
        "workflow_id_sha256",
        "workflow_version_id_sha256",
        "bundle_version",
        "bundle_sha256",
        "admitted_runtime_sha256",
        "application_contract_sha256",
        "environment_contract_sha256",
        "input_contract_sha256",
        "action_contract_sha256",
        "identity_contract_sha256",
        "effect_contract_sha256",
        "policy_contract_sha256",
        "evidence_authority_sha256",
        "campaign_artifact_sha256",
        "campaign_permit_sha256",
        "decision_receipt_reference",
        "decision_receipt_bundle_reference",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "entity_class",
        "campaign_summary",
        "local_identity_opening",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    admission = closed(value, fields, "qualification admission")
    if (
        admission["schema_version"] != "openadapt.qualification-admission/v4"
        or admission["verdict"] != "accepted"
    ):
        raise TrustError("qualification admission schema or verdict is invalid")
    if admission["evidence_class"] not in {
        "private-customer",
        "remote-safe-synthetic",
    }:
        raise TrustError("qualification admission evidence class is invalid")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(admission[field], field)
    if (
        not isinstance(admission["bundle_version"], str)
        or len(admission["bundle_version"]) > 64
        or BUNDLE_VERSION.fullmatch(admission["bundle_version"]) is None
    ):
        raise TrustError("qualification admission bundle version is not canonical")
    if (
        not isinstance(admission["entity_class"], str)
        or ENTITY_CLASS.fullmatch(admission["entity_class"]) is None
    ):
        raise TrustError("qualification admission entity class is not remote-safe")
    validate_campaign_summary(admission["campaign_summary"])
    validate_local_identity_opening(admission["local_identity_opening"])
    receipt_ref, _ = validate_reference_pair(
        admission["decision_receipt_reference"],
        admission["decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    if admission["campaign_artifact_sha256"] == receipt_ref["object_sha256"]:
        raise TrustError("campaign commitment cannot alias the receipt object")
    issuer = closed(
        admission["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "qualification admission issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/.github"
        or issuer["repository_id"] != "858454062"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/issue-qualification-admission.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "qualification-admission"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("qualification admission issuer differs")
    validate_window(admission, maximum=timedelta(days=7), now=now)
    projection = dict(admission)
    admission_id = projection.pop("admission_id_sha256")
    if admission_id != digest_bytes(ADMISSION_DOMAIN, projection):
        raise TrustError("qualification admission id is invalid")
    return admission


def _validate_release_identity(value: Any) -> dict[str, Any]:
    identity = closed(
        value,
        {
            "schema_version",
            "channel",
            "sequence",
            "previous_admission_sha256",
        },
        "release identity",
    )
    if (
        identity["schema_version"] != "openadapt.monotonic-production-release/v1"
        or identity["channel"] != "production"
    ):
        raise TrustError("release identity schema or channel is invalid")
    sequence = require_positive_int(identity["sequence"], "release sequence")
    previous = identity["previous_admission_sha256"]
    if sequence == 1:
        if previous is not None:
            raise TrustError(
                "the first release identity previous admission must be null"
            )
    else:
        require_digest(previous, "previous release admission")
    return identity


def _validate_acceptance_issuer(value: Any) -> dict[str, Any]:
    issuer = closed(
        value,
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "production acceptance issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-evals"
        or issuer["repository_id"] != "1135998197"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/issue-production-acceptance.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "production-acceptance"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("production acceptance issuer differs")
    return issuer


def _validate_receipt_admission_binding(
    receipt_value: Any,
    admission_value: Any,
    *,
    signer_registry: Any,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = validate_receipt(receipt_value, signer_registry=signer_registry, now=now)
    admission = validate_qualification_admission(admission_value, now=now)
    validate_reference_pair(
        admission["decision_receipt_reference"],
        admission["decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    bindings = {
        "evidence_class": "evidence_class",
        "organization_id_sha256": "organization_id_sha256",
        "workflow_id_sha256": "workflow_id_sha256",
        "workflow_version_id_sha256": "workflow_version_id_sha256",
        "bundle_version": "bundle_version",
        "bundle_sha256": "bundle_sha256",
        "admitted_runtime_sha256": "admitted_runtime_sha256",
        "application_contract_sha256": "application_contract_sha256",
        "environment_contract_sha256": "environment_contract_sha256",
        "input_contract_sha256": "input_contract_sha256",
        "action_contract_sha256": "action_contract_sha256",
        "identity_contract_sha256": "identity_contract_sha256",
        "effect_contract_sha256": "effect_contract_sha256",
        "policy_contract_sha256": "policy_contract_sha256",
        "evidence_authority_sha256": "evidence_authority_contract_sha256",
        "campaign_artifact_sha256": "campaign_artifact_sha256",
        "campaign_permit_sha256": "campaign_permit_sha256",
        "signer_registry_sha256": "signer_registry_sha256",
        "revocation_state_sha256": "revocation_state_sha256",
        "entity_class": "entity_class",
    }
    for admission_field, receipt_field in bindings.items():
        if admission[admission_field] != receipt[receipt_field]:
            raise TrustError(
                f"qualification admission {admission_field} differs from the receipt"
            )
    if admission["campaign_summary"] != receipt["campaign_summary"]["classes"]:
        raise TrustError(
            "qualification admission campaign summary differs from the receipt"
        )
    receipt_not_before = require_timestamp(receipt["not_before"], "receipt not_before")
    receipt_issued = require_timestamp(receipt["issued_at"], "receipt issued_at")
    receipt_expires = require_timestamp(receipt["expires_at"], "receipt expires_at")
    admission_not_before = require_timestamp(
        admission["not_before"], "qualification admission not_before"
    )
    admission_issued = require_timestamp(
        admission["issued_at"], "qualification admission issued_at"
    )
    admission_expires = require_timestamp(
        admission["expires_at"], "qualification admission expires_at"
    )
    if not (
        receipt_not_before <= receipt_issued <= admission_issued
        and admission_not_before >= receipt_not_before
        and admission_expires <= receipt_expires
    ):
        raise TrustError("qualification admission validity exceeds the receipt")
    return receipt, admission


def validate_acceptance_manifest(
    value: Any,
    *,
    receipt: Any,
    qualification_admission: Any,
    receipt_signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "target",
        "verdict",
        "claim_scope",
        "acceptance_policy_sha256",
        "lifecycle_policy_sha256",
        "release_identity",
        "release",
        "release_sha256",
        "artifact_inventory",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "qualification_evidence_decision_receipt_reference",
        "qualification_evidence_decision_receipt_bundle_reference",
        "qualification_admission_reference",
        "qualification_admission_bundle_reference",
        "campaign_summary",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    manifest = closed(value, fields, "production acceptance manifest")
    if (
        manifest["schema_version"] != "openadapt.production-acceptance/v3"
        or manifest["verdict"] != "accepted"
        or manifest["target"] not in TARGETS
        or manifest["claim_scope"]
        != TARGET_CONTRACTS[manifest["target"]]["claim_scope"]
    ):
        raise TrustError("production acceptance manifest identity differs")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(manifest[field], field)
    _validate_release_identity(manifest["release_identity"])
    _validate_acceptance_issuer(manifest["issuer"])
    release = closed(
        manifest["release"],
        {
            "schema_version",
            "kind",
            "source_repository",
            "source_repository_id",
            "source_commit",
            "version",
            "tag",
            "deployment_id",
            "deployment_sha256",
            "artifacts",
        },
        "manifest release candidate",
    )
    contract = TARGET_CONTRACTS[manifest["target"]]
    if (
        release["schema_version"] != "openadapt.production-release-candidate/v1"
        or release["kind"] != contract["release_kind"]
        or release["source_repository"] != contract["repository"]
        or release["source_repository_id"] != contract["repository_id"]
        or not isinstance(release["source_commit"], str)
        or HEX40.fullmatch(release["source_commit"]) is None
    ):
        raise TrustError("manifest release candidate differs from the target policy")
    artifacts = validate_artifacts(release["artifacts"], target=manifest["target"])
    if manifest["release_sha256"] != digest_bytes(
        RELEASE_DOMAIN,
        {
            "target": manifest["target"],
            "claim_scope": manifest["claim_scope"],
            "release": release,
        },
    ):
        raise TrustError("manifest release candidate digest is invalid")
    inventory = validate_artifact_inventory(manifest["artifact_inventory"])
    if (
        inventory["target"] != manifest["target"]
        or inventory["claim_scope"] != manifest["claim_scope"]
        or inventory["artifacts"] != artifacts
        or manifest["artifact_inventory_sha256"] != artifact_inventory_digest(inventory)
    ):
        raise TrustError("manifest artifact inventory differs from the release")
    staging = validate_staging(manifest["publication_staging"])
    if (
        manifest["publication_staging_sha256"] != staging_digest(staging)
        or staging["repository"] != release["source_repository"]
        or staging["repository_id"] != release["source_repository_id"]
        or staging["target_commitish"] != release["source_commit"]
        or (release["tag"] is not None and staging["tag"] != release["tag"])
    ):
        raise TrustError("manifest publication staging differs from the release")
    bound_fields = (
        "name",
        "kind",
        "sha256",
        "size_bytes",
        "media_type",
        "publish_destinations",
    )
    staged_projection = sorted(
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in staging["assets"]
    )
    admitted_projection = sorted(
        tuple(
            item[field] if field != "publish_destinations" else tuple(item[field])
            for field in bound_fields
        )
        for item in artifacts
    )
    if staged_projection != admitted_projection:
        raise TrustError("manifest staged assets differ from the release inventory")
    validate_reference_pair(
        manifest["qualification_evidence_decision_receipt_reference"],
        manifest["qualification_evidence_decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    validate_reference_pair(
        manifest["qualification_admission_reference"],
        manifest["qualification_admission_bundle_reference"],
        kind="qualification-admission",
    )
    bound_receipt, bound_admission = _validate_receipt_admission_binding(
        receipt,
        qualification_admission,
        signer_registry=receipt_signer_registry,
        now=now,
    )
    if (
        manifest["qualification_evidence_decision_receipt_reference"]
        != bound_admission["decision_receipt_reference"]
        or manifest["qualification_evidence_decision_receipt_bundle_reference"]
        != bound_admission["decision_receipt_bundle_reference"]
        or manifest["campaign_summary"] != bound_receipt["campaign_summary"]["classes"]
        or manifest["signer_registry_sha256"] != bound_receipt["signer_registry_sha256"]
        or manifest["revocation_state_sha256"]
        != bound_receipt["revocation_state_sha256"]
    ):
        raise TrustError("production acceptance manifest evidence bindings differ")
    validate_campaign_summary(manifest["campaign_summary"])
    validate_window(manifest, maximum=timedelta(days=7), now=now)
    issued = require_timestamp(manifest["issued_at"], "manifest issued_at")
    not_before = require_timestamp(manifest["not_before"], "manifest not_before")
    expires = require_timestamp(manifest["expires_at"], "manifest expires_at")
    if (
        require_timestamp(
            manifest["publication_staging"]["observed_at"], "staging observed_at"
        )
        > issued
    ):
        raise TrustError("publication staging was observed after manifest issuance")
    for child, label in ((bound_receipt, "receipt"), (bound_admission, "admission")):
        if (
            not_before < require_timestamp(child["not_before"], f"{label} not_before")
            or issued < require_timestamp(child["issued_at"], f"{label} issued_at")
            or expires > require_timestamp(child["expires_at"], f"{label} expires_at")
        ):
            raise TrustError(f"manifest validity exceeds the {label}")
    return manifest


def acceptance_summary_identity(value: Mapping[str, Any]) -> str:
    projection = {
        field: value[field]
        for field in (
            "target",
            "claim_scope",
            "release_identity",
            "release_sha256",
            "artifact_inventory_sha256",
            "publication_staging_sha256",
            "qualification_evidence_decision_receipt_reference",
            "qualification_admission_reference",
            "production_acceptance_manifest_reference",
            "campaign_summary",
            "authority_state_sha256",
            "revocation_state_sha256",
            "signer_registry_sha256",
            "issuer",
        )
    }
    return digest_bytes(PRODUCTION_EVIDENCE_IDENTITY_DOMAIN, projection)


def validate_acceptance_summary(
    value: Any,
    *,
    manifest: Any,
    receipt: Any,
    qualification_admission: Any,
    receipt_signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "target",
        "verdict",
        "claim_scope",
        "acceptance_policy_sha256",
        "lifecycle_policy_sha256",
        "release_identity",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "evidence_identity_sha256",
        "qualification_evidence_decision_receipt_reference",
        "qualification_evidence_decision_receipt_bundle_reference",
        "qualification_admission_reference",
        "qualification_admission_bundle_reference",
        "production_acceptance_manifest_reference",
        "production_acceptance_manifest_bundle_reference",
        "campaign_summary",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    summary = closed(value, fields, "production acceptance summary")
    if (
        summary["schema_version"]
        != "openadapt.production-lifecycle-evidence-summary/v3"
        or summary["verdict"] != "accepted"
        or summary["target"] not in TARGETS
        or summary["claim_scope"] != TARGET_CONTRACTS[summary["target"]]["claim_scope"]
    ):
        raise TrustError("production acceptance summary identity differs")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(summary[field], field)
    _validate_release_identity(summary["release_identity"])
    _validate_acceptance_issuer(summary["issuer"])
    validate_reference_pair(
        summary["qualification_evidence_decision_receipt_reference"],
        summary["qualification_evidence_decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    validate_reference_pair(
        summary["qualification_admission_reference"],
        summary["qualification_admission_bundle_reference"],
        kind="qualification-admission",
    )
    validate_reference_pair(
        summary["production_acceptance_manifest_reference"],
        summary["production_acceptance_manifest_bundle_reference"],
        kind="production-acceptance-manifest",
    )
    bound_manifest = validate_acceptance_manifest(
        manifest,
        receipt=receipt,
        qualification_admission=qualification_admission,
        receipt_signer_registry=receipt_signer_registry,
        now=now,
    )
    for field in (
        "target",
        "claim_scope",
        "acceptance_policy_sha256",
        "lifecycle_policy_sha256",
        "release_identity",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "qualification_evidence_decision_receipt_reference",
        "qualification_evidence_decision_receipt_bundle_reference",
        "qualification_admission_reference",
        "qualification_admission_bundle_reference",
        "campaign_summary",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
        "issuer",
    ):
        if summary[field] != bound_manifest[field]:
            raise TrustError(
                f"production acceptance summary {field} differs from the manifest"
            )
    validate_window(summary, maximum=timedelta(days=7), now=now)
    summary_not_before = require_timestamp(summary["not_before"], "summary not_before")
    summary_issued = require_timestamp(summary["issued_at"], "summary issued_at")
    summary_expires = require_timestamp(summary["expires_at"], "summary expires_at")
    if (
        summary_not_before
        < require_timestamp(bound_manifest["not_before"], "manifest not_before")
        or summary_issued
        < require_timestamp(bound_manifest["issued_at"], "manifest issued_at")
        or summary_expires
        > require_timestamp(bound_manifest["expires_at"], "manifest expires_at")
    ):
        raise TrustError("summary validity exceeds the manifest")
    if summary["evidence_identity_sha256"] != acceptance_summary_identity(summary):
        raise TrustError("production acceptance evidence identity differs")
    return summary


def validate_release_evidence_chain(
    release_value: Any,
    *,
    summary: Any,
    manifest: Any,
    receipt: Any,
    qualification_admission: Any,
    receipt_signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    release = validate_release(release_value, now=now)
    bound_summary = validate_acceptance_summary(
        summary,
        manifest=manifest,
        receipt=receipt,
        qualification_admission=qualification_admission,
        receipt_signer_registry=receipt_signer_registry,
        now=now,
    )
    bound_manifest = dict(manifest)
    receipt_class = receipt.get("evidence_class") if isinstance(receipt, dict) else None
    if release["evidence_class"] != receipt_class:
        raise TrustError("release admission evidence class differs from its receipt")
    for field in (
        "target",
        "claim_scope",
        "release_identity",
        "release_sha256",
        "artifact_inventory_sha256",
        "publication_staging",
        "publication_staging_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "signer_registry_sha256",
    ):
        if release[field] != bound_summary[field]:
            raise TrustError(
                f"release admission {field} differs from its evidence chain"
            )
    if release["release"] != bound_manifest["release"]:
        raise TrustError("release admission candidate differs from its manifest")
    if (
        bound_manifest["artifact_inventory"]["target"] != release["target"]
        or bound_manifest["artifact_inventory"]["claim_scope"] != release["claim_scope"]
        or bound_manifest["artifact_inventory"]["artifacts"]
        != release["release"]["artifacts"]
    ):
        raise TrustError("release admission inventory differs from its manifest")
    if (
        release["publication_policy_sha256"]
        != bound_summary["acceptance_policy_sha256"]
    ):
        raise TrustError("release publication policy differs from acceptance policy")
    release_not_before = require_timestamp(release["not_before"], "release not_before")
    release_issued = require_timestamp(release["issued_at"], "release issued_at")
    release_expires = require_timestamp(release["expires_at"], "release expires_at")
    if (
        release_not_before
        < require_timestamp(bound_summary["not_before"], "summary not_before")
        or release_issued
        < require_timestamp(bound_summary["issued_at"], "summary issued_at")
        or release_expires
        > require_timestamp(bound_summary["expires_at"], "summary expires_at")
    ):
        raise TrustError("release validity exceeds its acceptance summary")
    return release


def validate_cloud_deploy_authorization(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "authorization_sha256",
        "deployment_intent_sha256",
        "profile_repository",
        "profile_repository_id",
        "profile_commit",
        "profile_workflow",
        "profile_run_id",
        "profile_run_attempt",
        "cloud_source_commitment_sha256",
        "expected_live_attestation_sha256",
        "provider_idempotency_key",
        "audience",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    authorization = closed(value, fields, "production Cloud deploy authorization")
    if (
        authorization["schema_version"]
        != "openadapt.production-cloud-deploy-authorization/v1"
        or authorization["audience"] != "openadapt-public-cloud-source-proof"
        or authorization["profile_run_attempt"] != 1
    ):
        raise TrustError("production Cloud deploy authorization identity differs")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(authorization[field], field)
    for field in ("profile_repository_id", "profile_run_id"):
        require_decimal_id(authorization[field], field)
    if HEX40.fullmatch(authorization["profile_commit"]) is None:
        raise TrustError("Cloud profile commit must be exact")
    if (
        not isinstance(authorization["provider_idempotency_key"], str)
        or re.fullmatch(
            r"cloud-deploy:[0-9a-f]{64}", authorization["provider_idempotency_key"]
        )
        is None
    ):
        raise TrustError("Cloud provider idempotency key is invalid")
    issuer = closed(
        authorization["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "Cloud authorization issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-ops"
        or issuer["repository_id"] != "1172011294"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"]
        != ".github/workflows/production-cloud-deploy-authorization.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "production-cloud-deploy-authorization"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("Cloud authorization issuer differs")
    validate_window(authorization, maximum=timedelta(minutes=5), now=now)
    projection = dict(authorization)
    identity = projection.pop("authorization_sha256")
    if identity != digest_bytes(CLOUD_AUTHORIZATION_DOMAIN, projection):
        raise TrustError("Cloud deploy authorization identity is invalid")
    return authorization


def validate_cloud_deployment_handoff(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    fields = {
        "schema_version",
        "handoff_id_sha256",
        "authorization_reference",
        "authorization_bundle_reference",
        "authorization_sha256",
        "cloud_source_commitment_sha256",
        "profile_commit",
        "profile_run_id",
        "profile_run_attempt",
        "source_proof_request",
        "source_proof_request_sha256",
        "source_proof_response",
        "source_proof_response_sha256",
        "reviewed_public_values_sha256",
        "expected_live_attestation_sha256",
        "live_attestation_sha256",
        "provider_idempotency_key",
        "audience",
        "signer_registry_sha256",
        "revocation_state_sha256",
        "verdict",
        "issued_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    handoff = closed(value, fields, "production Cloud deployment handoff")
    if (
        handoff["schema_version"] != "openadapt.production-cloud-deployment-result/v1"
        or handoff["audience"] != "openadapt-private-cloud-production-deploy"
        or handoff["verdict"] != "accepted"
        or handoff["profile_run_attempt"] != "1"
    ):
        raise TrustError("production Cloud deployment handoff identity differs")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(handoff[field], field)
    require_decimal_id(handoff["profile_run_id"], "profile run id")
    if HEX40.fullmatch(handoff["profile_commit"]) is None:
        raise TrustError("Cloud handoff profile commit must be exact")
    validate_reference_pair(
        handoff["authorization_reference"],
        handoff["authorization_bundle_reference"],
        kind="production-cloud-deploy-authorization",
    )
    request_fields = {
        "schema_version",
        "authorization_sha256",
        "cloud_source_commit",
        "expected_live_attestation_sha256",
        "expires_at",
        "issued_at",
        "nonce",
        "production_origin",
        "profile_commit",
        "profile_environment",
        "profile_repository",
        "profile_workflow_ref",
        "run_attempt",
        "run_id",
        "site_id",
        "source_names",
    }
    request = closed(
        handoff["source_proof_request"], request_fields, "Cloud source proof request"
    )
    if (
        request["schema_version"]
        != "openadapt.production-secret-source-proof-request/v2"
        or request["run_attempt"] != "1"
        or HEX40.fullmatch(request["cloud_source_commit"]) is None
        or request["production_origin"] != "https://app.openadapt.ai"
        or request["site_id"] != "ccf1a48a-d934-48ea-a9a8-36cbddf27cb5"
        or request["profile_repository"] != "OpenAdaptAI/.github"
        or request["profile_environment"] != "production-cloud-deploy"
        or request["profile_workflow_ref"]
        != (
            "OpenAdaptAI/.github/.github/workflows/"
            "production-cloud-deploy.yml@refs/heads/main"
        )
    ):
        raise TrustError("Cloud source proof request identity differs")
    for field in ("authorization_sha256", "expected_live_attestation_sha256"):
        require_raw_digest(request[field], f"Cloud request {field}")
    nonce = request["nonce"]
    if not isinstance(nonce, str) or "=" in nonce:
        raise TrustError("Cloud source proof nonce is not canonical base64url")
    try:
        nonce_bytes = evidence.base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    except Exception as exc:
        raise TrustError("Cloud source proof nonce is not canonical base64url") from exc
    if (
        len(nonce_bytes) != 32
        or evidence.base64.urlsafe_b64encode(nonce_bytes).decode().rstrip("=") != nonce
    ):
        raise TrustError("Cloud source proof nonce must encode exactly 32 bytes")
    source_names = request["source_names"]
    if not isinstance(source_names, list) or source_names != list(
        CLOUD_LIVE_SOURCE_NAMES
    ):
        raise TrustError("Cloud source names differ from the frozen live source set")
    if handoff["source_proof_request_sha256"] != digest_bytes(
        CLOUD_SOURCE_PROOF_REQUEST_DOMAIN, request
    ):
        raise TrustError("Cloud source proof request digest differs")
    expected_idempotency = (
        "cloud-deploy:"
        + hashlib.sha256(
            CLOUD_PROVIDER_IDEMPOTENCY_DOMAIN
            + canonical(
                {
                    "authorization_sha256": handoff["authorization_sha256"],
                    "source_proof_request_sha256": handoff[
                        "source_proof_request_sha256"
                    ],
                    "profile_run_id": handoff["profile_run_id"],
                    "profile_run_attempt": handoff["profile_run_attempt"],
                }
            )
        ).hexdigest()
    )
    if handoff["provider_idempotency_key"] != expected_idempotency:
        raise TrustError("Cloud provider idempotency key differs")
    commitment = (
        "sha256:"
        + hashlib.sha256(
            CLOUD_SOURCE_COMMIT_DOMAIN + request["cloud_source_commit"].encode("ascii")
        ).hexdigest()
    )
    if handoff["cloud_source_commitment_sha256"] != commitment:
        raise TrustError("Cloud source commit commitment differs")
    response_fields = {
        "schema_version",
        "request_sha256",
        "authorization_sha256",
        "live_attestation_sha256",
        "live_deployment",
        "oidc_identity_sha256",
        "production_origin",
        "proofs",
        "public_values",
        "site_id",
    }
    response = closed(
        handoff["source_proof_response"], response_fields, "Cloud source proof response"
    )
    if (
        response["schema_version"]
        != "openadapt.production-secret-source-proof-response/v2"
    ):
        raise TrustError("Cloud source proof response schema differs")
    for field in response_fields:
        if field.endswith("_sha256"):
            require_raw_digest(response[field], field)
    live_deployment = closed(
        response["live_deployment"],
        {"build_id", "source_commit"},
        "Cloud live deployment",
    )
    if (
        not isinstance(live_deployment["build_id"], str)
        or DIGEST.fullmatch(live_deployment["build_id"]) is None
        or not isinstance(live_deployment["source_commit"], str)
        or HEX40.fullmatch(live_deployment["source_commit"]) is None
    ):
        raise TrustError("Cloud live deployment identity differs")
    proofs = response["proofs"]
    if not isinstance(proofs, dict) or sorted(proofs) != list(
        CLOUD_SECRET_SOURCE_NAMES
    ):
        raise TrustError("Cloud source proof set differs from the request")
    for digest in proofs.values():
        require_raw_digest(digest, "Cloud HMAC proof")
    public_values = response["public_values"]
    if (
        not isinstance(public_values, dict)
        or set(public_values) != {CLOUD_PUBLIC_SOURCE_NAME}
        or not isinstance(public_values[CLOUD_PUBLIC_SOURCE_NAME], str)
        or not public_values[CLOUD_PUBLIC_SOURCE_NAME]
    ):
        raise TrustError("reviewed public values differ")
    if sorted([*proofs, *public_values]) != list(CLOUD_LIVE_SOURCE_NAMES):
        raise TrustError("Cloud source proof partition differs from the request")
    if handoff["reviewed_public_values_sha256"] != digest_bytes(
        CLOUD_PUBLIC_VALUES_DOMAIN, public_values
    ):
        raise TrustError("reviewed public values digest differs")
    if (
        handoff["source_proof_response_sha256"]
        != "sha256:" + hashlib.sha256(canonical(response)).hexdigest()
    ):
        raise TrustError("Cloud source proof response digest differs")
    equalities = {
        "authorization_sha256": handoff["authorization_sha256"].removeprefix("sha256:"),
        "profile_commit": handoff["profile_commit"],
        "run_id": handoff["profile_run_id"],
        "run_attempt": handoff["profile_run_attempt"],
        "expected_live_attestation_sha256": handoff[
            "expected_live_attestation_sha256"
        ].removeprefix("sha256:"),
        "issued_at": handoff["issued_at"],
        "expires_at": handoff["expires_at"],
    }
    if any(request[field] != expected for field, expected in equalities.items()):
        raise TrustError("Cloud source proof request differs from the handoff")
    if (
        "sha256:" + response["request_sha256"] != handoff["source_proof_request_sha256"]
        or "sha256:" + response["authorization_sha256"]
        != handoff["authorization_sha256"]
        or "sha256:" + request["authorization_sha256"]
        != handoff["authorization_sha256"]
        or "sha256:" + request["expected_live_attestation_sha256"]
        != handoff["expected_live_attestation_sha256"]
        or "sha256:" + response["live_attestation_sha256"]
        != handoff["live_attestation_sha256"]
        or response["production_origin"] != request["production_origin"]
        or response["site_id"] != request["site_id"]
        or live_deployment["source_commit"] != request["cloud_source_commit"]
    ):
        raise TrustError("Cloud source proof response differs from the handoff")
    issuer = closed(
        handoff["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "Cloud handoff issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/.github"
        or issuer["repository_id"] != "858454062"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/production-cloud-deploy.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "production-cloud-deploy"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("Cloud handoff issuer differs")
    validate_window(handoff, maximum=timedelta(minutes=5), now=now)
    projection = dict(handoff)
    identity = projection.pop("handoff_id_sha256")
    if identity != digest_bytes(CLOUD_HANDOFF_DOMAIN, projection):
        raise TrustError("Cloud deployment handoff identity differs")
    return handoff


def validate_current_default(
    value: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    current = closed(
        value,
        {
            "schema_version",
            "default_set_revision",
            "previous_default_set_sha256",
            "targets",
            "issued_at",
            "not_before",
            "expires_at",
            "issuer",
        },
        "production current default",
    )
    if current["schema_version"] != "openadapt.production-current-default/v1":
        raise TrustError("current default schema is not supported")
    require_positive_int(current["default_set_revision"], "default set revision")
    if current["previous_default_set_sha256"] is not None:
        require_digest(current["previous_default_set_sha256"], "previous default set")
    targets = current["targets"]
    if not isinstance(targets, list) or [
        item.get("target") for item in targets if isinstance(item, dict)
    ] != list(TARGETS):
        raise TrustError("current default must contain all seven targets in order")
    for index, target_value in enumerate(targets):
        target = closed(
            target_value,
            {
                "target",
                "release_sha256",
                "artifact_inventory_sha256",
                "version",
                "tag",
                "deployment_id",
                "deployment_sha256",
                "qualification_release_sha256",
                "default_identity_sha256",
            },
            f"current default target {index}",
        )
        for field in (
            "release_sha256",
            "artifact_inventory_sha256",
            "qualification_release_sha256",
            "default_identity_sha256",
        ):
            require_digest(target[field], field)
        if target["deployment_sha256"] is not None:
            require_digest(target["deployment_sha256"], "deployment digest")
        if target["deployment_id"] is not None:
            require_decimal_id(target["deployment_id"], "deployment id")
    issuer = closed(
        current["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
        },
        "current default issuer",
    )
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-ops"
        or issuer["repository_id"] != "1172011294"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/production-current-default.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "production-current-default"
        or not isinstance(issuer["source_commit"], str)
        or HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise TrustError("current default issuer differs")
    validate_window(current, maximum=timedelta(days=7), now=now)
    return current


def validate_projection(value: Any) -> dict[str, Any]:
    projection = closed(
        value, {"schema_version", "overall_state", "targets"}, "lifecycle projection"
    )
    if projection[
        "schema_version"
    ] != "openadapt.production-lifecycle-projection/v2" or projection[
        "overall_state"
    ] not in {"Production", "not actively admitted"}:
        raise TrustError("lifecycle projection schema or state is invalid")
    targets = projection["targets"]
    if not isinstance(targets, list) or [
        item.get("target") for item in targets if isinstance(item, dict)
    ] != list(TARGETS):
        raise TrustError("lifecycle projection must contain all seven targets in order")
    all_production = True
    for index, target_value in enumerate(targets):
        target = closed(
            target_value,
            {
                "target",
                "state",
                "claim_scope",
                "release_sha256",
                "artifact_inventory_sha256",
                "release_admission_object_sha256",
                "default_identity_sha256",
                "not_before",
                "expires_at",
                "reason_codes",
            },
            f"lifecycle projection target {index}",
        )
        if target["state"] not in {"Production", "not actively admitted"}:
            raise TrustError("target lifecycle state is invalid")
        all_production = all_production and target["state"] == "Production"
        for field in (
            "release_sha256",
            "artifact_inventory_sha256",
            "release_admission_object_sha256",
            "default_identity_sha256",
        ):
            require_digest(target[field], field)
        require_timestamp(target["not_before"], "target not_before")
        require_timestamp(target["expires_at"], "target expires_at")
        reasons = target["reason_codes"]
        if (
            not isinstance(reasons, list)
            or reasons != sorted(set(reasons))
            or any(not isinstance(reason, str) or not reason for reason in reasons)
        ):
            raise TrustError("reason codes must be sorted unique strings")
        if target["state"] == "Production" and reasons:
            raise TrustError("Production target cannot have reason codes")
    if (projection["overall_state"] == "Production") != all_production:
        raise TrustError("overall lifecycle state differs from target states")
    return projection


def _validate_reference_pair_array(
    value: Any, *, release: bool
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TrustError("admission reference set is empty")
    for index, item_value in enumerate(value):
        fields = (
            {"target", "admission_reference", "admission_bundle_reference"}
            if release
            else {"admission_reference", "admission_bundle_reference"}
        )
        item = closed(item_value, fields, f"admission reference pair {index}")
        validate_reference_pair(
            item["admission_reference"],
            item["admission_bundle_reference"],
            kind="qualification-release" if release else "qualification-admission",
        )
    if release:
        if [item["target"] for item in value] != list(TARGETS):
            raise TrustError(
                "release admission set must contain all seven targets in order"
            )
    else:
        digests = [item["admission_reference"]["object_sha256"] for item in value]
        if digests != sorted(set(digests)):
            raise TrustError("workflow admission set must be sorted and unique")
    return value


def validate_checkpoint(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    fields = {
        "schema_version",
        "checkpoint_id_sha256",
        "checkpoint_revision",
        "previous_checkpoint_sha256",
        "registry_source_commit",
        "registry_revision",
        "registry_head_sha256",
        "signer_registry",
        "lifecycle_policy_sha256",
        "current_default_reference",
        "current_default_bundle_reference",
        "lifecycle_projection",
        "lifecycle_projection_sha256",
        "release_admissions",
        "release_admission_set_sha256",
        "workflow_admissions",
        "workflow_admission_set_sha256",
        "authority_state_reference",
        "authority_state_bundle_reference",
        "authority_state_sha256",
        "revocation_state_reference",
        "revocation_state_bundle_reference",
        "revocation_state_sha256",
        "generated_at",
        "not_before",
        "expires_at",
        "issuer",
    }
    checkpoint = closed(value, fields, "production lifecycle checkpoint")
    if checkpoint["schema_version"] != "openadapt.production-lifecycle-checkpoint/v2":
        raise TrustError("lifecycle checkpoint schema is not supported")
    require_positive_int(checkpoint["checkpoint_revision"], "checkpoint revision")
    if checkpoint["previous_checkpoint_sha256"] is not None:
        require_digest(checkpoint["previous_checkpoint_sha256"], "previous checkpoint")
    if (
        not isinstance(checkpoint["registry_source_commit"], str)
        or HEX40.fullmatch(checkpoint["registry_source_commit"]) is None
    ):
        raise TrustError("checkpoint registry commit must be exact")
    require_positive_int(
        checkpoint["registry_revision"], "checkpoint registry revision"
    )
    require_digest(checkpoint["registry_head_sha256"], "checkpoint registry head")
    if not isinstance(checkpoint["signer_registry"], dict):
        raise TrustError("checkpoint signer registry pointer is required")
    projection = validate_projection(checkpoint["lifecycle_projection"])
    if checkpoint["lifecycle_projection_sha256"] != digest_bytes(
        PROJECTION_DOMAIN, projection
    ):
        raise TrustError("lifecycle projection digest is invalid")
    release_set = _validate_reference_pair_array(
        checkpoint["release_admissions"], release=True
    )
    if checkpoint["release_admission_set_sha256"] != digest_bytes(
        RELEASE_SET_DOMAIN, release_set
    ):
        raise TrustError("release admission set digest is invalid")
    workflow_set = _validate_reference_pair_array(
        checkpoint["workflow_admissions"], release=False
    )
    if checkpoint["workflow_admission_set_sha256"] != digest_bytes(
        WORKFLOW_SET_DOMAIN, workflow_set
    ):
        raise TrustError("workflow admission set digest is invalid")
    validate_reference_pair(
        checkpoint["current_default_reference"],
        checkpoint["current_default_bundle_reference"],
        kind="production-current-default",
    )
    authority, _ = validate_reference_pair(
        checkpoint["authority_state_reference"],
        checkpoint["authority_state_bundle_reference"],
        kind="qualification-authority-state-receipt",
    )
    revocation, _ = validate_reference_pair(
        checkpoint["revocation_state_reference"],
        checkpoint["revocation_state_bundle_reference"],
        kind="qualification-revocation-state-receipt",
    )
    if (
        checkpoint["authority_state_sha256"] != authority["object_sha256"]
        or checkpoint["revocation_state_sha256"] != revocation["object_sha256"]
    ):
        raise TrustError("checkpoint state digests differ from their references")
    require_digest(checkpoint["lifecycle_policy_sha256"], "lifecycle policy digest")
    require_timestamp(checkpoint["generated_at"], "checkpoint generated_at")
    issuer = closed(
        checkpoint["issuer"],
        {
            "repository",
            "repository_id",
            "repository_owner_id",
            "workflow",
            "ref",
            "source_commit",
            "environment",
            "policy_repository",
            "policy_repository_id",
            "policy_source_commit",
            "policy_path",
        },
        "checkpoint issuer",
    )
    for field in ("source_commit", "policy_source_commit"):
        if not isinstance(issuer[field], str) or HEX40.fullmatch(issuer[field]) is None:
            raise TrustError("checkpoint issuer commit must be exact")
    if (
        issuer["repository"] != "OpenAdaptAI/openadapt-ops"
        or issuer["repository_id"] != "1172011294"
        or issuer["repository_owner_id"] != "132681217"
        or issuer["workflow"] != ".github/workflows/production-lifecycle-checkpoint.yml"
        or issuer["ref"] != "refs/heads/main"
        or issuer["environment"] != "production-lifecycle-checkpoint"
        or issuer["policy_repository"] != "OpenAdaptAI/.github"
        or issuer["policy_repository_id"] != "858454062"
        or issuer["policy_source_commit"] != checkpoint["registry_source_commit"]
        or issuer["policy_path"] != "production-lifecycle-policy.json"
    ):
        raise TrustError("checkpoint lifecycle policy source differs")
    generated = require_timestamp(checkpoint["generated_at"], "checkpoint generated_at")
    not_before = require_timestamp(checkpoint["not_before"], "checkpoint not_before")
    expires = require_timestamp(checkpoint["expires_at"], "checkpoint expires_at")
    if not generated <= not_before < expires <= generated + timedelta(days=7):
        raise TrustError("checkpoint scheduled validity window is invalid")
    if now is not None and not not_before <= now < expires:
        raise TrustError("checkpoint is not active at the requested time")
    projection_without_id = dict(checkpoint)
    checkpoint_id = projection_without_id.pop("checkpoint_id_sha256")
    if checkpoint_id != digest_bytes(CHECKPOINT_DOMAIN, projection_without_id):
        raise TrustError("checkpoint id is invalid")
    return checkpoint


def validate_checkpoint_expiry_containment(
    checkpoint_value: Any,
    *,
    signer_registry: Any,
    current_default: Any,
    release_admissions: Sequence[Any],
    workflow_admissions: Sequence[Any],
    authority_state: Any,
    revocation_state: Any,
    acceptance_summaries: Sequence[Any] = (),
    acceptance_manifests: Sequence[Any] = (),
    decision_receipts: Sequence[Any] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Require the retained checkpoint window to fit every verified child.

    ``now`` selects an active checkpoint for a runtime read.  Issuance callers
    omit it so that they can construct a checkpoint before its scheduled
    ``not_before``.  A child must already exist when the checkpoint is issued,
    and its complete validity window must contain the checkpoint window.
    """

    checkpoint = validate_checkpoint(checkpoint_value, now=now)
    try:
        registry = evidence.validate_signer_registry(signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    current = validate_current_default(current_default)
    releases = [validate_release(item) for item in release_admissions]
    workflows = [validate_qualification_admission(item) for item in workflow_admissions]
    authority = validate_authority_state(authority_state)
    revocation = validate_revocation_state(revocation_state)
    summaries = list(acceptance_summaries)
    manifests = list(acceptance_manifests)
    receipts = [_validate_receipt_structure(item) for item in decision_receipts]
    if len(releases) != len(checkpoint["release_admissions"]):
        raise TrustError("checkpoint release object count differs")
    if len(workflows) != len(checkpoint["workflow_admissions"]):
        raise TrustError("checkpoint workflow object count differs")

    checkpoint_not_before = require_timestamp(
        checkpoint["not_before"], "checkpoint not_before"
    )
    checkpoint_expires = require_timestamp(
        checkpoint["expires_at"], "checkpoint expires_at"
    )
    checkpoint_generated = require_timestamp(
        checkpoint["generated_at"], "checkpoint generated_at"
    )
    windows = [
        (
            evidence._timestamp(registry["generated_at"], "generated_at"),
            evidence._timestamp(registry["expires_at"], "expires_at"),
            evidence._timestamp(registry["generated_at"], "generated_at"),
            "signer registry",
        ),
        (
            require_timestamp(current["not_before"], "current default not_before"),
            require_timestamp(current["expires_at"], "current default expires_at"),
            require_timestamp(current["issued_at"], "current default issued_at"),
            "current default",
        ),
        (
            require_timestamp(authority["not_before"], "authority not_before"),
            require_timestamp(authority["expires_at"], "authority expires_at"),
            require_timestamp(authority["observed_at"], "authority observed_at"),
            "authority state",
        ),
        (
            require_timestamp(revocation["not_before"], "revocation not_before"),
            require_timestamp(revocation["expires_at"], "revocation expires_at"),
            require_timestamp(revocation["observed_at"], "revocation observed_at"),
            "revocation state",
        ),
    ]
    windows.extend(
        (
            require_timestamp(item["not_before"], "release not_before"),
            require_timestamp(item["expires_at"], "release expires_at"),
            require_timestamp(item["issued_at"], "release issued_at"),
            f"{item['target']} release",
        )
        for item in releases
    )
    windows.extend(
        (
            require_timestamp(item["not_before"], "workflow not_before"),
            require_timestamp(item["expires_at"], "workflow expires_at"),
            require_timestamp(item["issued_at"], "workflow issued_at"),
            "workflow admission",
        )
        for item in workflows
    )
    for items, label in (
        (summaries, "acceptance summary"),
        (manifests, "acceptance manifest"),
        (receipts, "qualification decision receipt"),
    ):
        windows.extend(
            (
                require_timestamp(item["not_before"], f"{label} not_before"),
                require_timestamp(item["expires_at"], f"{label} expires_at"),
                require_timestamp(item["issued_at"], f"{label} issued_at"),
                label,
            )
            for item in items
        )
    for child_not_before, child_expires, child_issued, label in windows:
        if child_issued > checkpoint_generated:
            raise TrustError(f"{label} was issued after the checkpoint")
        if (
            checkpoint_not_before < child_not_before
            or checkpoint_expires > child_expires
        ):
            raise TrustError(f"checkpoint validity exceeds {label} validity")
    return checkpoint


def validate_feed(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    feed = closed(
        value,
        {
            "schema_version",
            "repository",
            "repository_id",
            "repository_owner_id",
            "ref",
            "feed_revision",
            "generated_at",
            "expires_at",
            "registry_source_commit",
            "registry_revision",
            "registry_head_sha256",
            "signer_registry",
            "checkpoints",
        },
        "production lifecycle feed",
    )
    if (
        feed["schema_version"] != "openadapt.production-lifecycle-feed/v2"
        or feed["repository"] != "OpenAdaptAI/.github"
        or feed["repository_id"] != "858454062"
        or feed["repository_owner_id"] != "132681217"
        or feed["ref"] != "refs/heads/production-lifecycle-feed"
    ):
        raise TrustError("lifecycle feed identity differs")
    require_positive_int(feed["feed_revision"], "feed revision")
    if (
        not isinstance(feed["registry_source_commit"], str)
        or HEX40.fullmatch(feed["registry_source_commit"]) is None
    ):
        raise TrustError("feed registry commit must be exact")
    require_positive_int(feed["registry_revision"], "feed registry revision")
    require_digest(feed["registry_head_sha256"], "feed registry head")
    if not isinstance(feed["signer_registry"], dict):
        raise TrustError("feed signer registry pointer is required")
    checkpoints = feed["checkpoints"]
    if not isinstance(checkpoints, list) or len(checkpoints) not in {1, 2}:
        raise TrustError("feed must select one or two checkpoints")
    for index, pair_value in enumerate(checkpoints):
        pair = closed(
            pair_value,
            {"checkpoint_reference", "checkpoint_bundle_reference"},
            f"feed checkpoint {index}",
        )
        validate_reference_pair(
            pair["checkpoint_reference"],
            pair["checkpoint_bundle_reference"],
            kind="production-lifecycle-checkpoint",
        )
    generated = require_timestamp(feed["generated_at"], "feed generated_at")
    expires = require_timestamp(feed["expires_at"], "feed expires_at")
    if not generated < expires <= generated + timedelta(days=7):
        raise TrustError("feed lifetime is invalid")
    if now is not None and not generated <= now < expires:
        raise TrustError("feed is not current")
    return feed


def validate_feed_expiry_containment(
    feed_value: Any,
    *,
    checkpoints: Sequence[Any],
    signer_registry: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate one active checkpoint or one exact future rotation.

    Two-checkpoint feeds are newest-first.  The older checkpoint is active at
    feed issuance.  The newer checkpoint starts at the exact instant that the
    older checkpoint expires.  Signed validity intervals are half-open and do
    not use clock-skew grace.
    """

    feed = validate_feed(feed_value, now=now)
    try:
        registry = evidence.validate_signer_registry(signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise TrustError(str(exc)) from exc
    pointer = evidence._validate_signer_pointer(feed["signer_registry"])
    assert pointer is not None
    registry_raw = evidence.canonical(registry) + b"\n"
    if (
        pointer["object_sha256"] != "sha256:" + hashlib.sha256(registry_raw).hexdigest()
        or pointer["registry_identity_sha256"]
        != evidence.signer_registry_identity_digest(registry)
        or pointer["registry_revision"] != registry["revision"]
    ):
        raise TrustError("feed signer registry pointer differs from the registry")
    if len(checkpoints) != len(feed["checkpoints"]):
        raise TrustError("feed checkpoint object count differs")
    # A two-checkpoint feed intentionally contains a checkpoint whose
    # not-before is in the future.  Validate structure here and select the
    # active checkpoint against the feed/runtime time below.
    resolved = [validate_checkpoint(item) for item in checkpoints]
    revisions = [item["checkpoint_revision"] for item in resolved]
    if revisions != sorted(set(revisions), reverse=True):
        raise TrustError("feed checkpoints must be ordered by decreasing revision")
    if len(resolved) == 2:
        older_reference = feed["checkpoints"][1]["checkpoint_reference"]
        if (
            revisions[0] != revisions[1] + 1
            or resolved[0]["previous_checkpoint_sha256"]
            != older_reference["object_sha256"]
        ):
            raise TrustError("feed checkpoints are not one exact raw hash-chain step")

    generated = require_timestamp(feed["generated_at"], "feed generated_at")
    expires = require_timestamp(feed["expires_at"], "feed expires_at")
    registry_generated = evidence._timestamp(
        registry["generated_at"], "signer registry generated_at"
    )
    registry_expires = evidence._timestamp(
        registry["expires_at"], "signer registry expires_at"
    )
    if generated < registry_generated or expires > registry_expires:
        raise TrustError("feed validity exceeds signer registry validity")

    checkpoint_windows: list[tuple[datetime, datetime]] = []
    for index, (pair, checkpoint) in enumerate(
        zip(feed["checkpoints"], resolved, strict=True)
    ):
        reference = pair["checkpoint_reference"]
        raw = canonical(checkpoint) + b"\n"
        if reference["object_sha256"] != ("sha256:" + hashlib.sha256(raw).hexdigest()):
            raise TrustError(f"feed checkpoint {index} bytes differ from its reference")
        checkpoint_not_before = require_timestamp(
            checkpoint["not_before"], "checkpoint not_before"
        )
        checkpoint_expires = require_timestamp(
            checkpoint["expires_at"], "checkpoint expires_at"
        )
        checkpoint_generated = require_timestamp(
            checkpoint["generated_at"], "checkpoint generated_at"
        )
        if checkpoint_generated > generated:
            raise TrustError(f"feed predates checkpoint {index}")
        checkpoint_windows.append((checkpoint_not_before, checkpoint_expires))

    if len(checkpoint_windows) == 1:
        checkpoint_not_before, checkpoint_expires = checkpoint_windows[0]
        if generated < checkpoint_not_before or expires > checkpoint_expires:
            raise TrustError("feed validity exceeds checkpoint 0 validity")
    else:
        newer_not_before, newer_expires = checkpoint_windows[0]
        older_not_before, older_expires = checkpoint_windows[1]
        if older_expires != newer_not_before:
            raise TrustError("feed checkpoint handoff has an overlap or gap")
        if not older_not_before <= generated < older_expires:
            raise TrustError("older checkpoint is not active at feed issuance")
        if not newer_not_before < expires <= newer_expires:
            raise TrustError("feed does not cross the exact checkpoint handoff")

    if now is not None:
        active = [
            index
            for index, (not_before, checkpoint_expires) in enumerate(checkpoint_windows)
            if not_before <= now < checkpoint_expires
        ]
        if len(active) != 1:
            raise TrustError("feed does not select exactly one active checkpoint")

    current = resolved[0]
    current_reference = feed["checkpoints"][0]["checkpoint_reference"]
    if (
        feed["registry_source_commit"] != current["registry_source_commit"]
        or feed["registry_revision"] != current["registry_revision"]
        or feed["registry_head_sha256"] != current["registry_head_sha256"]
        or feed["signer_registry"] != current["signer_registry"]
        or current_reference["registry_source_commit"] != feed["registry_source_commit"]
        or current_reference["registry_revision"] != feed["registry_revision"]
        or current_reference["registry_head_sha256"] != feed["registry_head_sha256"]
    ):
        raise TrustError("feed current checkpoint or registry binding differs")
    return feed


def validate_feed_transition(previous_value: Any, current_value: Any) -> dict[str, Any]:
    """Reject feed revision, registry, and checkpoint rollback.

    The protected ref compare-and-swap binds the exact previous commit.  This
    function binds the state transition inside those two commits.
    """

    previous = validate_feed(previous_value)
    current = validate_feed(current_value)
    if current["feed_revision"] != previous["feed_revision"] + 1:
        raise TrustError("feed revision is not one exact forward step")
    if require_timestamp(current["generated_at"], "current feed generated_at") <= (
        require_timestamp(previous["generated_at"], "previous feed generated_at")
    ):
        raise TrustError("feed generation time did not advance")
    if current["registry_revision"] < previous["registry_revision"]:
        raise TrustError("feed signer registry revision rolled back")
    if (
        current["registry_revision"] == previous["registry_revision"]
        and current["signer_registry"] != previous["signer_registry"]
    ):
        raise TrustError("feed signer registry changed without a new revision")

    previous_reference = previous["checkpoints"][0]["checkpoint_reference"]
    current_reference = current["checkpoints"][0]["checkpoint_reference"]
    previous_revision = previous_reference["semantic_identity_sha256"]
    current_revision = current_reference["semantic_identity_sha256"]
    # The semantic identities need not be ordered.  Exact equality means the
    # same checkpoint is retained.  Any replacement must retain the prior raw
    # checkpoint in the two-entry rotation until its validity ends.
    if current_reference["object_sha256"] == previous_reference["object_sha256"]:
        if current_revision != previous_revision:
            raise TrustError("retained checkpoint semantic identity changed")
    else:
        retained = [
            pair["checkpoint_reference"]["object_sha256"]
            for pair in current["checkpoints"][1:]
        ]
        if retained != [previous_reference["object_sha256"]]:
            raise TrustError("feed checkpoint transition skips or forks history")
    return current


def validate_feed_update(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "event_type",
        "source_repository",
        "source_repository_id",
        "source_ref",
        "source_commit",
        "target_repository",
        "target_repository_id",
        "target_ref",
        "expected_old_commit",
        "new_commit",
        "feed_path",
        "feed_sha256",
        "checkpoint_sha256",
        "registry_head_sha256",
        "expires_at",
        "idempotency_key",
    }
    update = closed(value, fields, "lifecycle feed update")
    constants = {
        "schema_version": "openadapt.production-lifecycle-feed-update/v1",
        "event_type": "production_lifecycle_feed_updated",
        "source_repository": "OpenAdaptAI/openadapt-ops",
        "source_repository_id": "1172011294",
        "source_ref": "refs/heads/main",
        "target_repository": "OpenAdaptAI/.github",
        "target_repository_id": "858454062",
        "target_ref": "refs/heads/production-lifecycle-feed",
        "feed_path": "production-lifecycle-feed.json",
    }
    for field, expected in constants.items():
        if update[field] != expected:
            raise TrustError(f"lifecycle feed update {field} differs")
    for field in ("source_commit", "new_commit"):
        if not isinstance(update[field], str) or HEX40.fullmatch(update[field]) is None:
            raise TrustError(f"lifecycle feed update {field} must be exact")
    if update["expected_old_commit"] is not None and (
        not isinstance(update["expected_old_commit"], str)
        or HEX40.fullmatch(update["expected_old_commit"]) is None
    ):
        raise TrustError("lifecycle feed expected old commit is invalid")
    for field in ("feed_sha256", "checkpoint_sha256", "registry_head_sha256"):
        require_digest(update[field], field)
    require_timestamp(update["expires_at"], "feed update expires_at")
    projection = dict(update)
    idempotency_key = projection.pop("idempotency_key")
    expected_key = (
        "lifecycle-feed-update:"
        + hashlib.sha256(
            FEED_UPDATE_IDEMPOTENCY_DOMAIN + canonical(projection)
        ).hexdigest()
    )
    if idempotency_key != expected_key:
        raise TrustError("lifecycle feed update idempotency key is invalid")
    return update
