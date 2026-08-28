#!/usr/bin/env python3
"""Validate a closed lifecycle feed update against an exact local Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import production_trust as trust
import validate_evidence_registry as evidence
from verify_production_release_admission import verify_bytes, verify_sigstore

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads(
    (ROOT / "production-evidence-policy.json").read_text(encoding="utf-8")
)


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True
    ).stdout


def ensure_commit(commit: str) -> None:
    try:
        git("cat-file", "-e", f"{commit}^{{commit}}")
    except subprocess.CalledProcessError:
        subprocess.run(
            ["git", "fetch", "--no-tags", "origin", commit], check=True
        )


def git_file(commit: str, path: str) -> bytes:
    ensure_commit(commit)
    return git("show", f"{commit}:{path}")


def registered_object(
    reference: dict[str, object], *, label: str
) -> tuple[bytes, dict[str, object]]:
    validated = evidence.validate_reference(reference)
    commit = validated["registry_source_commit"]
    registry_raw = git_file(commit, "evidence-registry.json")
    try:
        registry_value = json.loads(registry_raw)
        entries = evidence.validate_registry(registry_value)
    except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
        raise trust.TrustError(f"{label} registry is invalid") from exc
    if (
        registry_value["revision"] != validated["registry_revision"]
        or registry_value["registry_head_sha256"]
        != validated["registry_head_sha256"]
    ):
        raise trust.TrustError(f"{label} registry identity differs")
    try:
        evidence.require_registered(entries, reference=validated, label=label)
    except evidence.EvidenceRegistryError as exc:
        raise trust.TrustError(str(exc)) from exc
    raw = git_file(commit, validated["object_path"])
    value = verify_bytes(raw, validated, label)
    if not isinstance(value, dict):
        raise trust.TrustError(f"{label} must be one JSON object")
    return raw, value


def registered_pair(
    pair: dict[str, object], *, kind: str, prefix: str
) -> dict[str, object]:
    regular_reference, bundle_reference = trust.validate_reference_pair(
        pair["checkpoint_reference"]
        if kind == "production-lifecycle-checkpoint"
        else pair["admission_reference"],
        pair["checkpoint_bundle_reference"]
        if kind == "production-lifecycle-checkpoint"
        else pair["admission_bundle_reference"],
        kind=kind,
    )
    regular_raw, regular = registered_object(
        regular_reference, label=f"{prefix} object"
    )
    bundle_raw, _ = registered_object(
        bundle_reference, label=f"{prefix} bundle"
    )
    verify_sigstore(
        regular_raw,
        bundle_raw,
        kind=kind,
        object_value=regular,
        policy=POLICY,
    )
    return regular


def reference_pair(
    regular_reference: dict[str, object],
    bundle_reference: dict[str, object],
    *,
    kind: str,
    prefix: str,
) -> dict[str, object]:
    regular, bundle = trust.validate_reference_pair(
        regular_reference, bundle_reference, kind=kind
    )
    regular_raw, value = registered_object(regular, label=f"{prefix} object")
    bundle_raw, _ = registered_object(bundle, label=f"{prefix} bundle")
    verify_sigstore(
        regular_raw,
        bundle_raw,
        kind=kind,
        object_value=value,
        policy=POLICY,
    )
    return value


def signer_registry(feed: dict[str, object]) -> dict[str, object]:
    commit = feed["registry_source_commit"]
    registry_document = json.loads(git_file(commit, "evidence-registry.json"))
    evidence.validate_registry(registry_document)
    pointer = evidence._validate_signer_pointer(feed["signer_registry"])
    if pointer is None or registry_document["signer_registry"] != pointer:
        raise trust.TrustError("feed signer registry pointer differs")
    raw = git_file(commit, pointer["object_path"])
    if (
        "sha256:" + hashlib.sha256(raw).hexdigest()
        != pointer["object_sha256"]
        or raw[-1:] != b"\n"
    ):
        raise trust.TrustError("feed signer registry bytes differ")
    value = evidence.validate_signer_registry(json.loads(raw))
    if (
        evidence.canonical(value) + b"\n" != raw
        or evidence.signer_registry_identity_digest(value)
        != pointer["registry_identity_sha256"]
        or value["revision"] != pointer["registry_revision"]
    ):
        raise trust.TrustError("feed signer registry identity differs")
    return value


def historical_signer_registry(
    reference: dict[str, object], object_value: dict[str, object]
) -> dict[str, object]:
    commit = reference["registry_source_commit"]
    registry_document = json.loads(git_file(commit, "evidence-registry.json"))
    evidence.validate_registry(registry_document)
    identity = object_value.get("signer_registry_identity_sha256")
    if identity is None:
        identity = object_value.get("signer_registry_sha256")
    matches = [
        pointer
        for pointer in registry_document["signer_registry_history"]
        if pointer["registry_identity_sha256"] == identity
    ]
    if len(matches) != 1:
        raise trust.TrustError(
            "signed object registry is not in append-only pointer history"
        )
    pointer = matches[0]
    raw = git_file(commit, pointer["object_path"])
    if (
        "sha256:" + hashlib.sha256(raw).hexdigest() != pointer["object_sha256"]
        or raw[-1:] != b"\n"
    ):
        raise trust.TrustError("historical signer registry bytes differ")
    value = evidence.validate_signer_registry(json.loads(raw))
    if (
        evidence.canonical(value) + b"\n" != raw
        or evidence.signer_registry_identity_digest(value)
        != pointer["registry_identity_sha256"]
        or value["revision"] != pointer["registry_revision"]
    ):
        raise trust.TrustError("historical signer registry identity differs")
    return value


def checkpoint_children(checkpoint: dict[str, object]) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    dict[str, object],
    dict[str, object],
]:
    current = reference_pair(
        checkpoint["current_default_reference"],
        checkpoint["current_default_bundle_reference"],
        kind="production-current-default",
        prefix="current default",
    )
    releases = [
        reference_pair(
            item["admission_reference"],
            item["admission_bundle_reference"],
            kind="qualification-release",
            prefix=f"{item['target']} release admission",
        )
        for item in checkpoint["release_admissions"]
    ]
    workflows = [
        reference_pair(
            item["admission_reference"],
            item["admission_bundle_reference"],
            kind="qualification-admission",
            prefix="workflow admission",
        )
        for item in checkpoint["workflow_admissions"]
    ]
    authority = reference_pair(
        checkpoint["authority_state_reference"],
        checkpoint["authority_state_bundle_reference"],
        kind="qualification-authority-state-receipt",
        prefix="authority state",
    )
    revocation = reference_pair(
        checkpoint["revocation_state_reference"],
        checkpoint["revocation_state_bundle_reference"],
        kind="qualification-revocation-state-receipt",
        prefix="revocation state",
    )
    return current, releases, workflows, authority, revocation


def resolve_release_chain(
    release: dict[str, object],
    *,
    active_signer_registry: dict[str, object],
    verification_time: datetime,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    summary = reference_pair(
        release["production_acceptance_summary_reference"],
        release["production_acceptance_summary_bundle_reference"],
        kind="production-acceptance-summary",
        prefix=f"{release['target']} production acceptance summary",
    )
    manifest = reference_pair(
        summary["production_acceptance_manifest_reference"],
        summary["production_acceptance_manifest_bundle_reference"],
        kind="production-acceptance-manifest",
        prefix=f"{release['target']} production acceptance manifest",
    )
    receipt = reference_pair(
        summary["qualification_evidence_decision_receipt_reference"],
        summary["qualification_evidence_decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
        prefix=f"{release['target']} qualification decision receipt",
    )
    admission = reference_pair(
        summary["qualification_admission_reference"],
        summary["qualification_admission_bundle_reference"],
        kind="qualification-admission",
        prefix=f"{release['target']} workflow admission",
    )
    receipt_signer_registry = historical_signer_registry(
        summary["qualification_evidence_decision_receipt_reference"], receipt
    )
    trust.verify_embedded_signature(
        receipt,
        signer_registry=receipt_signer_registry,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v1",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        usage="qualification-evidence-decision-receipt",
        now=trust.require_timestamp(receipt["issued_at"], "receipt issued_at"),
    )
    trust.verify_embedded_signature(
        receipt,
        signer_registry=active_signer_registry,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v1",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        usage="qualification-evidence-decision-receipt",
        now=verification_time,
    )
    trust.validate_release_evidence_chain(
        release,
        summary=summary,
        manifest=manifest,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=active_signer_registry,
        now=verification_time,
    )
    return summary, manifest, receipt, admission


def resolve_workflow_receipt(
    admission: dict[str, object],
    *,
    active_signer_registry: dict[str, object],
    verification_time: datetime,
) -> dict[str, object]:
    receipt = reference_pair(
        admission["decision_receipt_reference"],
        admission["decision_receipt_bundle_reference"],
        kind="qualification-evidence-decision-receipt",
        prefix="workflow qualification decision receipt",
    )
    receipt_signer_registry = historical_signer_registry(
        admission["decision_receipt_reference"], receipt
    )
    trust.verify_embedded_signature(
        receipt,
        signer_registry=receipt_signer_registry,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v1",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        usage="qualification-evidence-decision-receipt",
        now=trust.require_timestamp(receipt["issued_at"], "receipt issued_at"),
    )
    trust.verify_embedded_signature(
        receipt,
        signer_registry=active_signer_registry,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v1",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        usage="qualification-evidence-decision-receipt",
        now=verification_time,
    )
    trust._validate_receipt_admission_binding(
        receipt,
        admission,
        signer_registry=active_signer_registry,
        now=verification_time,
    )
    return receipt


def refuse_revoked(
    revocation: dict[str, object],
    *,
    subject_kind: str,
    subject_id: str,
) -> None:
    if any(
        item["subject_kind"] == subject_kind and item["subject_id"] == subject_id
        for item in revocation["revocations"]
    ):
        raise trust.TrustError(f"{subject_kind} is revoked")


def revocation_ancestry(
    feed: dict[str, object],
    current_state: dict[str, object],
    *,
    active_signer_registry: dict[str, object],
    verification_time: datetime,
) -> set[str]:
    """Resolve the complete signed revocation chain from the current registry."""

    commit = feed["registry_source_commit"]
    document = json.loads(git_file(commit, "evidence-registry.json"))
    entries = evidence.validate_registry(document)
    regular_by_identity = {
        entry["semantic_identity_sha256"]: (index, entry)
        for index, entry in enumerate(entries)
        if entry["kind"] == "qualification-revocation-state-receipt"
    }
    seen: set[str] = set()
    state = current_state
    while True:
        identity = state["revocation_state_sha256"]
        if identity in seen:
            raise trust.TrustError("revocation state history contains a cycle")
        seen.add(identity)
        previous_identity = state["previous_revocation_state_sha256"]
        if previous_identity is None:
            if state["revision"] != 1:
                raise trust.TrustError("initial revocation state revision is not one")
            return seen
        match = regular_by_identity.get(previous_identity)
        if match is None:
            raise trust.TrustError("revocation state history is incomplete")
        index, regular_entry = match
        if index + 1 >= len(entries):
            raise trust.TrustError("revocation state bundle is missing")
        bundle_entry = entries[index + 1]
        reference_common = {
            "schema_version": evidence.REFERENCE_SCHEMA,
            "repository": evidence.REPOSITORY,
            "repository_id": evidence.REPOSITORY_ID,
            "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
            "registry_source_commit": commit,
            "registry_revision": document["revision"],
            "registry_head_sha256": document["registry_head_sha256"],
        }
        regular_reference = {**reference_common, **regular_entry}
        bundle_reference = {**reference_common, **bundle_entry}
        previous_state = reference_pair(
            regular_reference,
            bundle_reference,
            kind="qualification-revocation-state-receipt",
            prefix=f"revocation state revision {state['revision'] - 1}",
        )
        if (
            previous_state["revocation_state_sha256"] != previous_identity
            or previous_state["revision"] != state["revision"] - 1
        ):
            raise trust.TrustError("revocation state history skips or forks")
        previous_revocations = {
            (item["subject_kind"], item["subject_id"], item["revoked_at"], item["reason_code"])
            for item in previous_state["revocations"]
        }
        current_revocations = {
            (item["subject_kind"], item["subject_id"], item["revoked_at"], item["reason_code"])
            for item in state["revocations"]
        }
        if not previous_revocations <= current_revocations:
            raise trust.TrustError("revocation state removed an earlier revocation")
        historical_registry = historical_signer_registry(
            regular_reference, previous_state
        )
        trust.verify_embedded_signature(
            previous_state,
            signer_registry=historical_registry,
            object_schema_version=(
                "openadapt.qualification-revocation-state-receipt/v1"
            ),
            signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
            usage="qualification-revocation-state-receipt",
            now=trust.require_timestamp(
                previous_state["observed_at"], "revocation observed_at"
            ),
        )
        trust.verify_embedded_signature(
            previous_state,
            signer_registry=active_signer_registry,
            object_schema_version=(
                "openadapt.qualification-revocation-state-receipt/v1"
            ),
            signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
            usage="qualification-revocation-state-receipt",
            now=verification_time,
        )
        state = previous_state


def validate_resolved_feed(
    feed: dict[str, object], *, verification_time: datetime
) -> dict[str, object]:
    """Resolve the complete v2 chain and return its active signed projection."""

    active_signer_registry = signer_registry(feed)
    checkpoints = [
        registered_pair(
            pair,
            kind="production-lifecycle-checkpoint",
            prefix=f"lifecycle checkpoint {index}",
        )
        for index, pair in enumerate(feed["checkpoints"])
    ]
    decision_series: dict[tuple[str, int], str] = {}
    for checkpoint in checkpoints:
        current, releases, workflows, authority, revocation = checkpoint_children(
            checkpoint
        )
        registry_identity = evidence.signer_registry_identity_digest(
            active_signer_registry
        )
        signer_pointer = evidence._validate_signer_pointer(
            checkpoint["signer_registry"]
        )
        assert signer_pointer is not None
        if (
            signer_pointer["registry_identity_sha256"] != registry_identity
            or authority["signer_registry_identity_sha256"] != registry_identity
            or authority["signer_registry_sha256"] != signer_pointer["object_sha256"]
            or authority["signer_registry_revision"]
            != active_signer_registry["revision"]
            or revocation["signer_registry_sha256"] != registry_identity
            or revocation["authority_state_sha256"]
            != authority["authority_state_sha256"]
        ):
            raise trust.TrustError(
                "checkpoint authority, revocation, or signer registry binding differs"
            )
        trust.verify_embedded_signature(
            authority,
            signer_registry=active_signer_registry,
            object_schema_version=(
                "openadapt.qualification-authority-state-receipt/v2"
            ),
            signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
            usage="qualification-authority-state-receipt",
            now=verification_time,
        )
        trust.verify_embedded_signature(
            revocation,
            signer_registry=active_signer_registry,
            object_schema_version=(
                "openadapt.qualification-revocation-state-receipt/v1"
            ),
            signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
            usage="qualification-revocation-state-receipt",
            now=verification_time,
        )
        for signer in active_signer_registry["signers"]:
            if signer["status"] == "active":
                refuse_revoked(
                    revocation,
                    subject_kind="qualification-signer-key",
                    subject_id=signer["public_key_sha256"],
                )

        summaries: list[dict[str, object]] = []
        manifests: list[dict[str, object]] = []
        receipts: list[dict[str, object]] = []
        for release, pair_value in zip(
            releases, checkpoint["release_admissions"], strict=True
        ):
            summary, manifest, receipt, admission = resolve_release_chain(
                release,
                active_signer_registry=active_signer_registry,
                verification_time=verification_time,
            )
            summaries.append(summary)
            manifests.append(manifest)
            receipts.append(receipt)
            for item_reference in (
                pair_value["admission_reference"],
                summary["qualification_admission_reference"],
                summary["qualification_evidence_decision_receipt_reference"],
            ):
                refuse_revoked(
                    revocation,
                    subject_kind=item_reference["kind"],
                    subject_id=item_reference["semantic_identity_sha256"],
                )
            if (
                release["authority_state_sha256"]
                != authority["authority_state_sha256"]
                or release["revocation_state_sha256"]
                != revocation["revocation_state_sha256"]
                or release["signer_registry_sha256"] != registry_identity
            ):
                raise trust.TrustError("release chain current authority state differs")

        for admission, pair_value in zip(
            workflows, checkpoint["workflow_admissions"], strict=True
        ):
            receipt = resolve_workflow_receipt(
                admission,
                active_signer_registry=active_signer_registry,
                verification_time=verification_time,
            )
            receipts.append(receipt)
            for item_reference in (
                pair_value["admission_reference"],
                admission["decision_receipt_reference"],
            ):
                refuse_revoked(
                    revocation,
                    subject_kind=item_reference["kind"],
                    subject_id=item_reference["semantic_identity_sha256"],
                )
            if (
                admission["revocation_state_sha256"]
                != revocation["revocation_state_sha256"]
                or admission["signer_registry_sha256"] != registry_identity
            ):
                raise trust.TrustError("workflow admission current trust state differs")

        for receipt in receipts:
            series = (
                receipt["decision_identity_sha256"],
                receipt["decision_revision"],
            )
            object_sha = "sha256:" + hashlib.sha256(
                evidence.canonical(receipt) + b"\n"
            ).hexdigest()
            previous_sha = decision_series.setdefault(series, object_sha)
            if previous_sha != object_sha:
                raise trust.TrustError(
                    "one qualification decision series has conflicting receipts"
                )
            if (
                receipt["revocation_state_sha256"]
                != revocation["revocation_state_sha256"]
                or receipt["signer_registry_sha256"] != registry_identity
            ):
                raise trust.TrustError(
                    "qualification decision receipt current trust state differs"
                )

        for default_target, release in zip(current["targets"], releases, strict=True):
            if (
                default_target["target"] != release["target"]
                or default_target["release_sha256"] != release["release_sha256"]
                or default_target["artifact_inventory_sha256"]
                != release["artifact_inventory_sha256"]
                or default_target["qualification_release_sha256"]
                != checkpoint["release_admissions"][
                    trust.TARGETS.index(release["target"])
                ]["admission_reference"]["object_sha256"]
            ):
                raise trust.TrustError(
                    "current default differs from its release admission"
                )
        trust.validate_checkpoint_expiry_containment(
            checkpoint,
            signer_registry=active_signer_registry,
            current_default=current,
            release_admissions=releases,
            workflow_admissions=workflows,
            authority_state=authority,
            revocation_state=revocation,
            acceptance_summaries=summaries,
            acceptance_manifests=manifests,
            decision_receipts=receipts,
        )
    trust.validate_feed_expiry_containment(
        feed,
        checkpoints=checkpoints,
        signer_registry=active_signer_registry,
        now=verification_time,
    )
    active = [
        checkpoint
        for checkpoint in checkpoints
        if trust.require_timestamp(checkpoint["not_before"], "checkpoint not_before")
        <= verification_time
        < trust.require_timestamp(checkpoint["expires_at"], "checkpoint expires_at")
    ]
    if len(active) != 1:
        raise trust.TrustError("lifecycle feed does not select one active checkpoint")
    return active[0]["lifecycle_projection"]


def validate_feed_commit(
    feed_commit: str,
    *,
    trusted_main: str,
    verification_time: datetime | None = None,
) -> tuple[dict[str, object], dict[str, object], bytes]:
    """Validate an exact protected feed commit and its complete v2 chain."""

    if trust.HEX40.fullmatch(feed_commit) is None:
        raise trust.TrustError("lifecycle feed commit must be exact")
    if trust.HEX40.fullmatch(trusted_main) is None:
        raise trust.TrustError("trusted main commit must be exact")
    ensure_commit(feed_commit)
    ensure_commit(trusted_main)
    commit = git("rev-parse", f"{feed_commit}^{{commit}}").decode().strip()
    if commit != feed_commit:
        raise trust.TrustError("lifecycle feed commit is not exact")
    parent = git("rev-parse", f"{feed_commit}^").decode().strip()
    if parent != trusted_main:
        raise trust.TrustError("lifecycle feed commit is not based on current main")
    changed = git(
        "diff", "--name-only", "--diff-filter=ACMR", trusted_main, feed_commit
    ).decode().splitlines()
    if changed != ["production-lifecycle-feed.json"]:
        raise trust.TrustError("lifecycle commit changes files outside the feed")
    feed_raw = git_file(feed_commit, "production-lifecycle-feed.json")
    now = verification_time or datetime.now(timezone.utc)
    feed = trust.validate_feed(json.loads(feed_raw), now=now)
    if feed_raw != evidence.canonical(feed) + b"\n":
        raise trust.TrustError("feed is not canonical JSON followed by one LF")
    if feed["registry_source_commit"] != trusted_main:
        raise trust.TrustError("feed registry commit is not current protected main")
    projection = validate_resolved_feed(feed, verification_time=now)
    return feed, projection, feed_raw


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
        verification_time = datetime.now(timezone.utc)
        feed = trust.validate_feed(json.loads(feed_raw), now=verification_time)
        if feed_raw != evidence.canonical(feed) + b"\n":
            raise trust.TrustError("feed is not canonical JSON followed by one LF")
        expected_old = update["expected_old_commit"]
        if expected_old is None:
            if feed["feed_revision"] != 1:
                raise trust.TrustError("initial lifecycle feed revision must be one")
        else:
            previous_raw = git("show", f"{expected_old}:production-lifecycle-feed.json")
            previous = json.loads(previous_raw)
            if previous_raw != evidence.canonical(previous) + b"\n":
                raise trust.TrustError("previous feed bytes are not canonical")
            trust.validate_feed_transition(previous, feed)
        if feed["registry_source_commit"] != args.trusted_main:
            raise trust.TrustError("feed registry commit is not current protected main")
        if feed["expires_at"] != update["expires_at"] or feed["registry_head_sha256"] != update["registry_head_sha256"]:
            raise trust.TrustError("feed state differs from update payload")
        checkpoint_digests = {
            pair["checkpoint_reference"]["object_sha256"]
            for pair in feed["checkpoints"]
        }
        if update["checkpoint_sha256"] not in checkpoint_digests:
            raise trust.TrustError("update checkpoint is not selected by the feed")
        active_signer_registry = signer_registry(feed)
        checkpoints = [
            registered_pair(
                pair,
                kind="production-lifecycle-checkpoint",
                prefix=f"lifecycle checkpoint {index}",
            )
            for index, pair in enumerate(feed["checkpoints"])
        ]
        decision_series: dict[tuple[str, int], str] = {}
        for checkpoint in checkpoints:
            current, releases, workflows, authority, revocation = (
                checkpoint_children(checkpoint)
            )
            registry_identity = evidence.signer_registry_identity_digest(
                active_signer_registry
            )
            signer_pointer = evidence._validate_signer_pointer(
                checkpoint["signer_registry"]
            )
            assert signer_pointer is not None
            if (
                signer_pointer["registry_identity_sha256"] != registry_identity
                or authority["signer_registry_identity_sha256"]
                != registry_identity
                or authority["signer_registry_sha256"]
                != signer_pointer["object_sha256"]
                or authority["signer_registry_revision"]
                != active_signer_registry["revision"]
                or revocation["signer_registry_sha256"] != registry_identity
                or revocation["authority_state_sha256"]
                != authority["authority_state_sha256"]
            ):
                raise trust.TrustError(
                    "checkpoint authority, revocation, or signer registry binding differs"
                )
            trust.verify_embedded_signature(
                authority,
                signer_registry=active_signer_registry,
                object_schema_version=(
                    "openadapt.qualification-authority-state-receipt/v2"
                ),
                signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
                usage="qualification-authority-state-receipt",
                now=verification_time,
            )
            trust.verify_embedded_signature(
                revocation,
                signer_registry=active_signer_registry,
                object_schema_version=(
                    "openadapt.qualification-revocation-state-receipt/v1"
                ),
                signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
                usage="qualification-revocation-state-receipt",
                now=verification_time,
            )
            for signer in active_signer_registry["signers"]:
                if signer["status"] == "active":
                    refuse_revoked(
                        revocation,
                        subject_kind="qualification-signer-key",
                        subject_id=signer["public_key_sha256"],
                    )

            summaries: list[dict[str, object]] = []
            manifests: list[dict[str, object]] = []
            receipts: list[dict[str, object]] = []
            for release, pair_value in zip(
                releases, checkpoint["release_admissions"], strict=True
            ):
                summary, manifest, receipt, admission = resolve_release_chain(
                    release,
                    active_signer_registry=active_signer_registry,
                    verification_time=verification_time,
                )
                summaries.append(summary)
                manifests.append(manifest)
                receipts.append(receipt)
                for item, item_reference in (
                    (release, pair_value["admission_reference"]),
                    (admission, summary["qualification_admission_reference"]),
                    (
                        receipt,
                        summary[
                            "qualification_evidence_decision_receipt_reference"
                        ],
                    ),
                ):
                    refuse_revoked(
                        revocation,
                        subject_kind=item_reference["kind"],
                        subject_id=item_reference["semantic_identity_sha256"],
                    )
                if (
                    release["authority_state_sha256"]
                    != authority["authority_state_sha256"]
                    or release["revocation_state_sha256"]
                    != revocation["revocation_state_sha256"]
                    or release["signer_registry_sha256"] != registry_identity
                ):
                    raise trust.TrustError(
                        "release chain current authority state differs"
                    )

            for admission, pair_value in zip(
                workflows, checkpoint["workflow_admissions"], strict=True
            ):
                receipt = resolve_workflow_receipt(
                    admission,
                    active_signer_registry=active_signer_registry,
                    verification_time=verification_time,
                )
                receipts.append(receipt)
                for item_reference in (
                    pair_value["admission_reference"],
                    admission["decision_receipt_reference"],
                ):
                    refuse_revoked(
                        revocation,
                        subject_kind=item_reference["kind"],
                        subject_id=item_reference["semantic_identity_sha256"],
                    )
                if (
                    admission["revocation_state_sha256"]
                    != revocation["revocation_state_sha256"]
                    or admission["signer_registry_sha256"] != registry_identity
                ):
                    raise trust.TrustError(
                        "workflow admission current trust state differs"
                    )

            for receipt in receipts:
                series = (
                    receipt["decision_identity_sha256"],
                    receipt["decision_revision"],
                )
                object_sha = "sha256:" + hashlib.sha256(
                    evidence.canonical(receipt) + b"\n"
                ).hexdigest()
                previous_sha = decision_series.setdefault(series, object_sha)
                if previous_sha != object_sha:
                    raise trust.TrustError(
                        "one qualification decision series has conflicting receipts"
                    )
                if (
                    receipt["revocation_state_sha256"]
                    != revocation["revocation_state_sha256"]
                    or receipt["signer_registry_sha256"] != registry_identity
                ):
                    raise trust.TrustError(
                        "qualification decision receipt current trust state differs"
                    )

            for default_target, release in zip(
                current["targets"], releases, strict=True
            ):
                if (
                    default_target["target"] != release["target"]
                    or default_target["release_sha256"] != release["release_sha256"]
                    or default_target["artifact_inventory_sha256"]
                    != release["artifact_inventory_sha256"]
                    or default_target["qualification_release_sha256"]
                    != checkpoint["release_admissions"][
                        trust.TARGETS.index(release["target"])
                    ]["admission_reference"]["object_sha256"]
                ):
                    raise trust.TrustError(
                        "current default differs from its release admission"
                    )
            trust.validate_checkpoint_expiry_containment(
                checkpoint,
                signer_registry=active_signer_registry,
                current_default=current,
                release_admissions=releases,
                workflow_admissions=workflows,
                authority_state=authority,
                revocation_state=revocation,
                acceptance_summaries=summaries,
                acceptance_manifests=manifests,
                decision_receipts=receipts,
            )
        trust.validate_feed_expiry_containment(
            feed,
            checkpoints=checkpoints,
            signer_registry=active_signer_registry,
            now=verification_time,
        )
        print("production lifecycle feed update is valid")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
