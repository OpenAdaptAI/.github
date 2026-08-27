#!/usr/bin/env python3
"""Closed validators and digest rules for OpenAdapt Production trust objects."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import validate_evidence_registry as evidence

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
DECIMAL_ID = re.compile(r"^[1-9][0-9]*$")
ENTITY_CLASS = re.compile(r"^[a-z][a-z0-9 -]{0,63}$")

TARGETS = ("agent", "capture", "cloud", "desktop", "docs", "flow", "openadapt")
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
RELEASE_ADMISSION_DOMAIN = b"OpenAdapt qualification release admission v1\0"
STAGING_DOMAIN = b"OpenAdapt production release staging evidence v1\0"
TAG_RULESETS_DOMAIN = b"OpenAdapt production release tag rulesets v1\0"
ADMISSION_DOMAIN = b"OpenAdapt qualification admission v3\0"
CHECKPOINT_DOMAIN = b"OpenAdapt production lifecycle checkpoint v1\0"
PROJECTION_DOMAIN = b"OpenAdapt production lifecycle projection v2\0"
RELEASE_SET_DOMAIN = b"OpenAdapt production release admission set v1\0"
WORKFLOW_SET_DOMAIN = b"OpenAdapt production workflow admission set v1\0"
FEED_UPDATE_IDEMPOTENCY_DOMAIN = (
    b"OpenAdapt production lifecycle feed update idempotency v1\0"
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
    if not issued <= not_before < expires <= issued + maximum:
        raise TrustError("validity window is invalid")
    if now is not None and not not_before <= now < expires:
        raise TrustError("object is not active at the requested time")


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
        if counts["unsafe_effect_count"] or counts["silent_incorrect_success_count"] or counts["blind_retry_count"]:
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
        attended["authenticated_bound_decision_count"] != attended["observed_trial_count"]
        or attended["live_target_revalidation_count"] != attended["observed_trial_count"]
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


def validate_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TrustError("artifact inventory must be a non-empty list")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    folded: set[str] = set()
    for index, artifact_value in enumerate(value):
        artifact = closed(
            artifact_value,
            {"name", "kind", "sha256", "size_bytes", "media_type", "publish_destinations"},
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
        if not isinstance(artifact["media_type"], str) or "/" not in artifact["media_type"]:
            raise TrustError(f"artifact {index} media type is invalid")
        destinations = artifact["publish_destinations"]
        if (
            not isinstance(destinations, list)
            or not destinations
            or destinations != sorted(set(destinations))
            or any(item not in {"deployment", "github-release", "pypi"} for item in destinations)
        ):
            raise TrustError(f"artifact {index} publish destinations are invalid")
        result.append(artifact)
    if result != sorted(result, key=lambda item: (item["kind"], item["name"], item["sha256"])):
        raise TrustError("artifacts must be sorted by kind, name, and digest")
    return result


def validate_artifact_inventory(value: Any) -> dict[str, Any]:
    inventory = closed(
        value, {"schema_version", "target", "claim_scope", "artifacts"}, "artifact inventory"
    )
    if inventory["schema_version"] != "openadapt.production-release-artifact-inventory/v1":
        raise TrustError("artifact inventory schema is not supported")
    if inventory["target"] not in TARGETS:
        raise TrustError("artifact inventory target is invalid")
    if not isinstance(inventory["claim_scope"], str) or not inventory["claim_scope"]:
        raise TrustError("artifact inventory claim scope is invalid")
    validate_artifacts(inventory["artifacts"])
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


def validate_tag_rulesets(value: Any, *, repository: str, repository_id: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 2:
        raise TrustError("tag rulesets must contain creation and immutability rulesets")
    roles = ["creation_authority", "immutability"]
    for index, ruleset_value in enumerate(value):
        ruleset = closed(
            ruleset_value,
            {
                "schema_version", "role", "repository", "repository_id", "ruleset_id",
                "name", "target", "enforcement", "bypass_actors", "conditions", "rules",
            },
            f"tag ruleset {index}",
        )
        if ruleset["schema_version"] != "openadapt.production-release-tag-ruleset/v1":
            raise TrustError("tag ruleset schema is not supported")
        if ruleset["role"] != roles[index] or ruleset["repository"] != repository or ruleset["repository_id"] != repository_id:
            raise TrustError("tag ruleset identity differs")
        require_decimal_id(ruleset["ruleset_id"], "tag ruleset id")
        if ruleset["target"] != "tag" or ruleset["enforcement"] != "active":
            raise TrustError("tag ruleset is not active for tags")
        expected_name = (
            "Production release tags: creation authority"
            if index == 0
            else "Production release tags: immutable"
        )
        if ruleset["name"] != expected_name:
            raise TrustError("tag ruleset name differs from policy")
        actors = ruleset["bypass_actors"]
        expected_actors = [] if index else [{"actor_id": "4730708", "actor_type": "Integration", "bypass_mode": "always"}]
        if actors != expected_actors:
            raise TrustError("tag ruleset bypass authority differs")
        conditions = closed(ruleset["conditions"], {"ref_name"}, "tag ruleset conditions")
        ref_name = closed(conditions["ref_name"], {"include", "exclude"}, "tag ref conditions")
        for key in ("include", "exclude"):
            items = ref_name[key]
            if not isinstance(items, list) or items != sorted(set(items)) or any(not isinstance(item, str) or not item for item in items):
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
            "schema_version", "repository", "repository_id", "draft_release_id", "tag",
            "target_commitish", "draft", "prerelease", "release_app_id",
            "release_app_installation_id", "release_app_bot_user_id",
            "release_author_login", "assets", "immutable_releases_enabled",
            "tag_rulesets", "tag_rulesets_sha256", "observed_at",
        },
        "publication staging",
    )
    if staging["schema_version"] != "openadapt.production-release-staging-evidence/v1":
        raise TrustError("publication staging schema is not supported")
    for field in ("repository_id", "draft_release_id", "release_app_id", "release_app_installation_id", "release_app_bot_user_id"):
        require_decimal_id(staging[field], f"publication staging {field}")
    if (
        staging["draft"] is not True
        or staging["prerelease"] is not False
        or staging["release_app_id"] != "4730708"
        or staging["release_app_installation_id"] != "156835568"
        or staging["release_app_bot_user_id"] != "321543906"
        or staging["release_author_login"] != "openadapt-release[bot]"
        or staging["immutable_releases_enabled"] is not True
    ):
        raise TrustError("publication staging authority or state differs")
    if not isinstance(staging["target_commitish"], str) or HEX40.fullmatch(staging["target_commitish"]) is None:
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
                "asset_id", "name", "kind", "sha256", "size_bytes", "media_type",
                "publish_destinations", "uploader_id", "uploader_login",
            },
            f"staged asset {index}",
        )
        require_decimal_id(asset["asset_id"], f"staged asset {index} id")
        require_digest(asset["sha256"], f"staged asset {index} digest")
        require_positive_int(asset["size_bytes"], f"staged asset {index} size")
        if not isinstance(asset["media_type"], str) or "/" not in asset["media_type"]:
            raise TrustError("staged asset media type is invalid")
        destinations = asset["publish_destinations"]
        if not isinstance(destinations, list) or not destinations or destinations != sorted(set(destinations)) or any(item not in {"deployment", "github-release", "pypi"} for item in destinations):
            raise TrustError("staged asset publish destinations are invalid")
        if asset["uploader_id"] != "321543906" or asset["uploader_login"] != "openadapt-release[bot]":
            raise TrustError("staged asset uploader is not the release App")
        if asset["name"] in names or asset["asset_id"] in ids:
            raise TrustError("staged asset names and ids must be unique")
        names.add(asset["name"])
        ids.add(asset["asset_id"])
    if assets != sorted(assets, key=lambda item: (item["name"], item["asset_id"])):
        raise TrustError("staged assets must be sorted")
    validate_tag_rulesets(staging["tag_rulesets"], repository=staging["repository"], repository_id=staging["repository_id"])
    if staging["tag_rulesets_sha256"] != digest_bytes(TAG_RULESETS_DOMAIN, staging["tag_rulesets"]):
        raise TrustError("tag rulesets digest is invalid")
    require_timestamp(staging["observed_at"], "publication staging observed_at")
    return staging


def staging_digest(value: Mapping[str, Any]) -> str:
    return digest_bytes(STAGING_DOMAIN, value)


def validate_release(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    release_admission = closed(
        value,
        {
            "schema_version", "admission_id_sha256", "target", "verdict", "claim_scope",
            "release_identity", "release", "release_sha256", "artifact_inventory_sha256",
            "publication_staging", "publication_staging_sha256",
            "production_acceptance_summary_reference",
            "production_acceptance_summary_bundle_reference", "authority_state_sha256",
            "revocation_state_sha256", "signer_registry_sha256",
            "publication_policy_sha256", "issued_at", "not_before", "expires_at", "issuer",
        },
        "qualification release",
    )
    if release_admission["schema_version"] != "openadapt.qualification-release/v1" or release_admission["verdict"] != "accepted":
        raise TrustError("qualification release schema or verdict is invalid")
    if release_admission["target"] not in TARGETS:
        raise TrustError("qualification release target is invalid")
    identity = closed(release_admission["release_identity"], {"schema_version", "channel", "sequence", "previous_admission_sha256"}, "release identity")
    if identity["schema_version"] != "openadapt.monotonic-production-release/v1" or identity["channel"] != "production":
        raise TrustError("release identity schema or channel is invalid")
    require_positive_int(identity["sequence"], "release sequence")
    if identity["previous_admission_sha256"] is not None:
        require_digest(identity["previous_admission_sha256"], "previous release admission")
    release = closed(release_admission["release"], {"schema_version", "kind", "source_repository", "source_repository_id", "source_commit", "version", "tag", "deployment_id", "deployment_sha256", "artifacts"}, "release candidate")
    if release["schema_version"] != "openadapt.production-release-candidate/v1" or release["kind"] not in {"package", "deployment", "hybrid"}:
        raise TrustError("release candidate schema or kind is invalid")
    require_decimal_id(release["source_repository_id"], "release source repository id")
    if not isinstance(release["source_commit"], str) or HEX40.fullmatch(release["source_commit"]) is None:
        raise TrustError("release source commit must be exact")
    artifacts = validate_artifacts(release["artifacts"])
    inventory = {"target": release_admission["target"], "claim_scope": release_admission["claim_scope"], "artifacts": artifacts}
    if release_admission["artifact_inventory_sha256"] != digest_bytes(ARTIFACT_INVENTORY_DOMAIN, inventory):
        raise TrustError("release artifact inventory digest is invalid")
    if release_admission["release_sha256"] != digest_bytes(RELEASE_DOMAIN, {"target": release_admission["target"], "claim_scope": release_admission["claim_scope"], "release": release}):
        raise TrustError("release candidate digest is invalid")
    staging = validate_staging(release_admission["publication_staging"])
    if release_admission["publication_staging_sha256"] != staging_digest(staging):
        raise TrustError("publication staging digest is invalid")
    if staging["repository"] != release["source_repository"] or staging["repository_id"] != release["source_repository_id"] or staging["target_commitish"] != release["source_commit"] or staging["tag"] != release["tag"]:
        raise TrustError("publication staging differs from the release candidate")
    bound_fields = ("name", "kind", "sha256", "size_bytes", "media_type", "publish_destinations")
    staged = [tuple(item[field] if field != "publish_destinations" else tuple(item[field]) for field in bound_fields) for item in staging["assets"]]
    admitted = [tuple(item[field] if field != "publish_destinations" else tuple(item[field]) for field in bound_fields) for item in artifacts]
    if sorted(staged) != sorted(admitted):
        raise TrustError("publication staging assets differ from the admitted inventory")
    validate_reference_pair(release_admission["production_acceptance_summary_reference"], release_admission["production_acceptance_summary_bundle_reference"], kind="production-acceptance-summary")
    for field in ("authority_state_sha256", "revocation_state_sha256", "signer_registry_sha256", "publication_policy_sha256"):
        require_digest(release_admission[field], field)
    issuer = closed(release_admission["issuer"], {"repository", "repository_id", "repository_owner_id", "workflow", "ref", "source_commit", "environment"}, "release issuer")
    if issuer != {
        "repository": "OpenAdaptAI/.github", "repository_id": "858454062", "repository_owner_id": "132681217",
        "workflow": ".github/workflows/issue-production-release-admission.yml", "ref": "refs/heads/main",
        "source_commit": issuer["source_commit"], "environment": "production-release-admission",
    } or not isinstance(issuer["source_commit"], str) or HEX40.fullmatch(issuer["source_commit"]) is None:
        raise TrustError("release issuer identity differs")
    validate_window(release_admission, maximum=timedelta(days=30), now=now)
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
        if len(raw) != artifact["size_bytes"] or "sha256:" + hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            raise TrustError(f"candidate artifact bytes differ: {artifact['name']}")


def validate_receipt(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    fields = {
        "schema_version", "decision_commitment_sha256", "evidence_manifest_sha256",
        "campaign_artifact_sha256", "organization_id_sha256", "workflow_id_sha256",
        "workflow_version_id_sha256", "bundle_version", "bundle_sha256",
        "admitted_runtime_sha256", "application_contract_sha256",
        "environment_contract_sha256", "input_contract_sha256", "action_contract_sha256",
        "identity_contract_sha256", "effect_contract_sha256", "policy_contract_sha256",
        "evidence_authority_sha256", "campaign_permit_sha256", "signer_registry_sha256",
        "revocation_state_sha256", "entity_class", "campaign_summary", "verdict",
        "issued_at", "not_before", "expires_at", "issuer_key_id", "algorithm", "signature",
    }
    receipt = closed(value, fields, "qualification evidence decision receipt")
    if receipt["schema_version"] != "openadapt.qualification-evidence-decision-receipt/v1" or receipt["verdict"] != "accepted":
        raise TrustError("decision receipt schema or verdict is invalid")
    digest_fields = fields - {
        "schema_version", "bundle_version", "entity_class", "campaign_summary", "verdict",
        "issued_at", "not_before", "expires_at", "issuer_key_id", "algorithm", "signature",
    }
    for field in digest_fields:
        require_digest(receipt[field], field)
    if len({receipt["decision_commitment_sha256"], receipt["evidence_manifest_sha256"], receipt["campaign_artifact_sha256"]}) != 3:
        raise TrustError("decision, final manifest, and campaign commitments must be distinct")
    require_positive_int(receipt["bundle_version"], "bundle version")
    if not isinstance(receipt["entity_class"], str) or ENTITY_CLASS.fullmatch(receipt["entity_class"]) is None:
        raise TrustError("entity class is not remote-safe")
    validate_campaign_summary(receipt["campaign_summary"])
    if receipt["algorithm"] != "ed25519" or not isinstance(receipt["issuer_key_id"], str) or evidence.KEY_ID.fullmatch(receipt["issuer_key_id"]) is None:
        raise TrustError("decision receipt signer is invalid")
    signature = receipt["signature"]
    if not isinstance(signature, str) or "=" in signature:
        raise TrustError("decision receipt signature must be unpadded base64url")
    try:
        raw_signature = evidence.base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except Exception as exc:
        raise TrustError("decision receipt signature is invalid") from exc
    if len(raw_signature) != 64:
        raise TrustError("decision receipt signature must contain 64 bytes")
    validate_window(receipt, maximum=timedelta(days=7), now=now)
    return receipt


def validate_local_identity_opening(value: Any) -> dict[str, Any]:
    opening = closed(
        value,
        {
            "schema_version", "algorithm", "required", "customer_controlled_secret_required",
            "exact_contract_match_required", "revalidation_before_actuation",
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
        "schema_version", "admission_id_sha256", "organization_id_sha256",
        "workflow_id_sha256", "workflow_version_id_sha256", "bundle_version",
        "bundle_sha256", "admitted_runtime_sha256", "application_contract_sha256",
        "environment_contract_sha256", "input_contract_sha256", "action_contract_sha256",
        "identity_contract_sha256", "effect_contract_sha256", "policy_contract_sha256",
        "evidence_authority_sha256", "campaign_artifact_sha256", "campaign_permit_sha256",
        "decision_receipt_reference", "decision_receipt_bundle_reference",
        "signer_registry_sha256", "revocation_state_sha256", "entity_class",
        "campaign_summary", "local_identity_opening", "verdict", "issued_at",
        "not_before", "expires_at", "issuer",
    }
    admission = closed(value, fields, "qualification admission")
    if admission["schema_version"] != "openadapt.qualification-admission/v3" or admission["verdict"] != "accepted":
        raise TrustError("qualification admission schema or verdict is invalid")
    for field in fields:
        if field.endswith("_sha256"):
            require_digest(admission[field], field)
    require_positive_int(admission["bundle_version"], "bundle version")
    if not isinstance(admission["entity_class"], str) or ENTITY_CLASS.fullmatch(admission["entity_class"]) is None:
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
        {"repository", "repository_id", "repository_owner_id", "workflow", "ref", "source_commit", "environment"},
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


def validate_current_default(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    current = closed(
        value,
        {
            "schema_version", "default_set_revision", "previous_default_set_sha256",
            "targets", "issued_at", "not_before", "expires_at", "issuer",
        },
        "production current default",
    )
    if current["schema_version"] != "openadapt.production-current-default/v1":
        raise TrustError("current default schema is not supported")
    require_positive_int(current["default_set_revision"], "default set revision")
    if current["previous_default_set_sha256"] is not None:
        require_digest(current["previous_default_set_sha256"], "previous default set")
    targets = current["targets"]
    if not isinstance(targets, list) or [item.get("target") for item in targets if isinstance(item, dict)] != list(TARGETS):
        raise TrustError("current default must contain all seven targets in order")
    for index, target_value in enumerate(targets):
        target = closed(
            target_value,
            {
                "target", "release_sha256", "artifact_inventory_sha256", "version", "tag",
                "deployment_id", "deployment_sha256", "qualification_release_sha256",
                "default_identity_sha256",
            },
            f"current default target {index}",
        )
        for field in ("release_sha256", "artifact_inventory_sha256", "qualification_release_sha256", "default_identity_sha256"):
            require_digest(target[field], field)
        if target["deployment_sha256"] is not None:
            require_digest(target["deployment_sha256"], "deployment digest")
        if target["deployment_id"] is not None:
            require_decimal_id(target["deployment_id"], "deployment id")
    closed(current["issuer"], {"repository", "repository_id", "workflow", "ref", "source_commit"}, "current default issuer")
    validate_window(current, maximum=timedelta(days=7), now=now)
    return current


def validate_projection(value: Any) -> dict[str, Any]:
    projection = closed(value, {"schema_version", "overall_state", "targets"}, "lifecycle projection")
    if projection["schema_version"] != "openadapt.production-lifecycle-projection/v2" or projection["overall_state"] not in {"Production", "not actively admitted"}:
        raise TrustError("lifecycle projection schema or state is invalid")
    targets = projection["targets"]
    if not isinstance(targets, list) or [item.get("target") for item in targets if isinstance(item, dict)] != list(TARGETS):
        raise TrustError("lifecycle projection must contain all seven targets in order")
    all_production = True
    for index, target_value in enumerate(targets):
        target = closed(
            target_value,
            {
                "target", "state", "claim_scope", "release_sha256",
                "artifact_inventory_sha256", "release_admission_object_sha256",
                "default_identity_sha256", "not_before", "expires_at", "reason_codes",
            },
            f"lifecycle projection target {index}",
        )
        if target["state"] not in {"Production", "not actively admitted"}:
            raise TrustError("target lifecycle state is invalid")
        all_production = all_production and target["state"] == "Production"
        for field in ("release_sha256", "artifact_inventory_sha256", "release_admission_object_sha256", "default_identity_sha256"):
            require_digest(target[field], field)
        require_timestamp(target["not_before"], "target not_before")
        require_timestamp(target["expires_at"], "target expires_at")
        reasons = target["reason_codes"]
        if not isinstance(reasons, list) or reasons != sorted(set(reasons)) or any(not isinstance(reason, str) or not reason for reason in reasons):
            raise TrustError("reason codes must be sorted unique strings")
        if target["state"] == "Production" and reasons:
            raise TrustError("Production target cannot have reason codes")
    if (projection["overall_state"] == "Production") != all_production:
        raise TrustError("overall lifecycle state differs from target states")
    return projection


def _validate_reference_pair_array(value: Any, *, release: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TrustError("admission reference set is empty")
    for index, item_value in enumerate(value):
        fields = {"target", "admission_reference", "admission_bundle_reference"} if release else {"admission_reference", "admission_bundle_reference"}
        item = closed(item_value, fields, f"admission reference pair {index}")
        validate_reference_pair(
            item["admission_reference"], item["admission_bundle_reference"],
            kind="qualification-release" if release else "qualification-admission",
        )
    if release:
        if [item["target"] for item in value] != list(TARGETS):
            raise TrustError("release admission set must contain all seven targets in order")
    else:
        digests = [item["admission_reference"]["object_sha256"] for item in value]
        if digests != sorted(set(digests)):
            raise TrustError("workflow admission set must be sorted and unique")
    return value


def validate_checkpoint(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    fields = {
        "schema_version", "checkpoint_id_sha256", "checkpoint_revision",
        "previous_checkpoint_sha256", "registry_source_commit", "registry_revision",
        "registry_head_sha256", "signer_registry", "lifecycle_policy_sha256",
        "current_default_reference", "current_default_bundle_reference",
        "lifecycle_projection", "lifecycle_projection_sha256", "release_admissions",
        "release_admission_set_sha256", "workflow_admissions",
        "workflow_admission_set_sha256", "authority_state_reference",
        "authority_state_bundle_reference", "authority_state_sha256",
        "revocation_state_reference", "revocation_state_bundle_reference",
        "revocation_state_sha256", "generated_at", "not_before", "expires_at", "issuer",
    }
    checkpoint = closed(value, fields, "production lifecycle checkpoint")
    if checkpoint["schema_version"] != "openadapt.production-lifecycle-checkpoint/v1":
        raise TrustError("lifecycle checkpoint schema is not supported")
    require_positive_int(checkpoint["checkpoint_revision"], "checkpoint revision")
    if checkpoint["previous_checkpoint_sha256"] is not None:
        require_digest(checkpoint["previous_checkpoint_sha256"], "previous checkpoint")
    if not isinstance(checkpoint["registry_source_commit"], str) or HEX40.fullmatch(checkpoint["registry_source_commit"]) is None:
        raise TrustError("checkpoint registry commit must be exact")
    require_positive_int(checkpoint["registry_revision"], "checkpoint registry revision")
    require_digest(checkpoint["registry_head_sha256"], "checkpoint registry head")
    if not isinstance(checkpoint["signer_registry"], dict):
        raise TrustError("checkpoint signer registry pointer is required")
    projection = validate_projection(checkpoint["lifecycle_projection"])
    if checkpoint["lifecycle_projection_sha256"] != digest_bytes(PROJECTION_DOMAIN, projection):
        raise TrustError("lifecycle projection digest is invalid")
    release_set = _validate_reference_pair_array(checkpoint["release_admissions"], release=True)
    if checkpoint["release_admission_set_sha256"] != digest_bytes(RELEASE_SET_DOMAIN, release_set):
        raise TrustError("release admission set digest is invalid")
    workflow_set = _validate_reference_pair_array(checkpoint["workflow_admissions"], release=False)
    if checkpoint["workflow_admission_set_sha256"] != digest_bytes(WORKFLOW_SET_DOMAIN, workflow_set):
        raise TrustError("workflow admission set digest is invalid")
    validate_reference_pair(checkpoint["current_default_reference"], checkpoint["current_default_bundle_reference"], kind="production-current-default")
    authority, _ = validate_reference_pair(checkpoint["authority_state_reference"], checkpoint["authority_state_bundle_reference"], kind="qualification-authority-state-receipt")
    revocation, _ = validate_reference_pair(checkpoint["revocation_state_reference"], checkpoint["revocation_state_bundle_reference"], kind="qualification-revocation-state-receipt")
    if checkpoint["authority_state_sha256"] != authority["object_sha256"] or checkpoint["revocation_state_sha256"] != revocation["object_sha256"]:
        raise TrustError("checkpoint state digests differ from their references")
    require_digest(checkpoint["lifecycle_policy_sha256"], "lifecycle policy digest")
    require_timestamp(checkpoint["generated_at"], "checkpoint generated_at")
    issuer = closed(
        checkpoint["issuer"],
        {
            "repository", "repository_id", "workflow", "ref", "source_commit",
            "policy_repository", "policy_repository_id", "policy_source_commit", "policy_path",
        },
        "checkpoint issuer",
    )
    for field in ("source_commit", "policy_source_commit"):
        if not isinstance(issuer[field], str) or HEX40.fullmatch(issuer[field]) is None:
            raise TrustError("checkpoint issuer commit must be exact")
    if issuer["policy_repository"] != "OpenAdaptAI/.github" or issuer["policy_repository_id"] != "858454062" or issuer["policy_path"] != "production-lifecycle-policy.json":
        raise TrustError("checkpoint lifecycle policy source differs")
    pseudo = {"issued_at": checkpoint["generated_at"], "not_before": checkpoint["not_before"], "expires_at": checkpoint["expires_at"]}
    validate_window(pseudo, maximum=timedelta(days=7), now=now)
    projection_without_id = dict(checkpoint)
    checkpoint_id = projection_without_id.pop("checkpoint_id_sha256")
    if checkpoint_id != digest_bytes(CHECKPOINT_DOMAIN, projection_without_id):
        raise TrustError("checkpoint id is invalid")
    return checkpoint


def validate_feed(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    feed = closed(
        value,
        {
            "schema_version", "repository", "repository_id", "repository_owner_id", "ref",
            "feed_revision", "generated_at", "expires_at", "registry_source_commit",
            "registry_revision", "registry_head_sha256", "signer_registry", "checkpoints",
        },
        "production lifecycle feed",
    )
    if feed["schema_version"] != "openadapt.production-lifecycle-feed/v1" or feed["repository"] != "OpenAdaptAI/.github" or feed["repository_id"] != "858454062" or feed["repository_owner_id"] != "132681217" or feed["ref"] != "refs/heads/production-lifecycle-feed":
        raise TrustError("lifecycle feed identity differs")
    require_positive_int(feed["feed_revision"], "feed revision")
    if not isinstance(feed["registry_source_commit"], str) or HEX40.fullmatch(feed["registry_source_commit"]) is None:
        raise TrustError("feed registry commit must be exact")
    require_positive_int(feed["registry_revision"], "feed registry revision")
    require_digest(feed["registry_head_sha256"], "feed registry head")
    if not isinstance(feed["signer_registry"], dict):
        raise TrustError("feed signer registry pointer is required")
    checkpoints = feed["checkpoints"]
    if not isinstance(checkpoints, list) or len(checkpoints) not in {1, 2}:
        raise TrustError("feed must select one or two checkpoints")
    for index, pair_value in enumerate(checkpoints):
        pair = closed(pair_value, {"checkpoint_reference", "checkpoint_bundle_reference"}, f"feed checkpoint {index}")
        validate_reference_pair(pair["checkpoint_reference"], pair["checkpoint_bundle_reference"], kind="production-lifecycle-checkpoint")
    generated = require_timestamp(feed["generated_at"], "feed generated_at")
    expires = require_timestamp(feed["expires_at"], "feed expires_at")
    if not generated < expires <= generated + timedelta(days=7):
        raise TrustError("feed lifetime is invalid")
    if now is not None and not generated <= now < expires:
        raise TrustError("feed is not current")
    return feed


def validate_feed_update(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version", "event_type", "source_repository", "source_repository_id",
        "source_ref", "source_commit", "target_repository", "target_repository_id",
        "target_ref", "expected_old_commit", "new_commit", "feed_path", "feed_sha256",
        "checkpoint_sha256", "registry_head_sha256", "expires_at", "idempotency_key",
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
    if update["expected_old_commit"] is not None and (not isinstance(update["expected_old_commit"], str) or HEX40.fullmatch(update["expected_old_commit"]) is None):
        raise TrustError("lifecycle feed expected old commit is invalid")
    for field in ("feed_sha256", "checkpoint_sha256", "registry_head_sha256"):
        require_digest(update[field], field)
    require_timestamp(update["expires_at"], "feed update expires_at")
    projection = dict(update)
    idempotency_key = projection.pop("idempotency_key")
    expected_key = "lifecycle-feed-update:" + hashlib.sha256(
        FEED_UPDATE_IDEMPOTENCY_DOMAIN + canonical(projection)
    ).hexdigest()
    if idempotency_key != expected_key:
        raise TrustError("lifecycle feed update idempotency key is invalid")
    return update
