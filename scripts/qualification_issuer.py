#!/usr/bin/env python3
"""Build canonical release-v1 and workflow-v3 admission candidates.

The command consumes both a caller-supplied opaque request handle and the exact
semantic evidence reference before it emits an admission. A failed output step
is therefore an uncertain effect. The caller must reconcile it and must not
retry with the same or a different handle.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Protocol, TypedDict

import production_trust as trust
import validate_evidence_registry as evidence
import verify_production_release_admission as verifier


REQUEST_HANDLE = re.compile(r"^qair_[A-Za-z0-9_-]{43}$")
REQUEST_DOMAIN = b"OpenAdapt qualification admission issue request v1\0"
CONSUMPTION_DOMAIN = b"OpenAdapt qualification one-use effect v1\0"
LOCAL_IDENTITY_OPENING = {
    "schema_version": "openadapt.qualification-local-identity-opening/v1",
    "algorithm": "hmac-sha256",
    "required": True,
    "customer_controlled_secret_required": True,
    "exact_contract_match_required": True,
    "revalidation_before_actuation": True,
    "maximum_age_seconds": 60,
}


class IssuerError(ValueError):
    """An issue request cannot produce a canonical admission."""


class WorkflowIssueRequest(TypedDict):
    schema_version: str
    request_handle: str
    evidence_class: str
    decision_receipt_reference: dict[str, Any]


class ReleaseIssueRequest(TypedDict):
    schema_version: str
    request_handle: str
    evidence_class: str
    production_acceptance_summary_reference: dict[str, Any]


class ResolvedEvidence(TypedDict):
    value: dict[str, Any]
    reference: dict[str, Any]
    bundle_reference: dict[str, Any]
    bound_signer_registry: dict[str, Any]
    current_signer_registry: dict[str, Any]


class EvidenceResolver(Protocol):
    """Resolve registered bytes and verify their adjacent outer signature."""

    def resolve(
        self, reference: Mapping[str, Any], *, kind: str
    ) -> ResolvedEvidence: ...

    def current_trust_state(
        self, *, registry_source_commit: str
    ) -> tuple[ResolvedEvidence, ResolvedEvidence]: ...


class GitHubEvidenceResolver:
    """Resolve exact central-registry objects through the canonical verifier."""

    def __init__(self, policy: Mapping[str, Any]) -> None:
        self.policy = dict(policy)

    def resolve(self, reference: Mapping[str, Any], *, kind: str) -> ResolvedEvidence:
        regular = evidence.validate_reference(reference)
        bundle = verifier.derive_bundle_reference(regular)
        value, bound_registry, current_registry = verifier.resolve_pair(
            regular,
            bundle,
            kind=kind,
            policy=self.policy,
        )
        return {
            "value": value,
            "reference": regular,
            "bundle_reference": bundle,
            "bound_signer_registry": bound_registry,
            "current_signer_registry": current_registry,
        }

    def current_trust_state(
        self, *, registry_source_commit: str
    ) -> tuple[ResolvedEvidence, ResolvedEvidence]:
        registry_raw = verifier.fetch(
            verifier.raw_url(registry_source_commit, "evidence-registry.json")
        )
        try:
            registry = json.loads(registry_raw)
            entries = evidence.validate_registry(registry)
        except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
            raise IssuerError("current evidence registry is invalid") from exc
        references: dict[str, dict[str, Any]] = {}
        wanted = {
            "qualification-authority-state-receipt",
            "qualification-revocation-state-receipt",
        }
        for entry in entries:
            if entry["kind"] in wanted:
                references[entry["kind"]] = {
                    "schema_version": evidence.REFERENCE_SCHEMA,
                    "repository": evidence.REPOSITORY,
                    "repository_id": evidence.REPOSITORY_ID,
                    "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
                    "registry_source_commit": registry_source_commit,
                    "registry_revision": registry["revision"],
                    "registry_head_sha256": registry["registry_head_sha256"],
                    **entry,
                }
        if set(references) != wanted:
            raise IssuerError("current authority or revocation receipt is absent")
        return (
            self.resolve(
                references["qualification-authority-state-receipt"],
                kind="qualification-authority-state-receipt",
            ),
            self.resolve(
                references["qualification-revocation-state-receipt"],
                kind="qualification-revocation-state-receipt",
            ),
        )


class OneUseConsumer(Protocol):
    """Atomically persist one handle, semantic effect, and retrievable result."""

    def commit_once(
        self,
        *,
        request_handle: str,
        operation: str,
        request_sha256: str,
        effect_sha256: str,
        result: bytes,
    ) -> dict[str, Any]: ...

    def reconcile(self, *, request_handle: str) -> dict[str, Any]: ...


class SqliteOneUseConsumer:
    """Atomic single-host adapter for a SQLite file on durable storage."""

    def __init__(self, database: Path) -> None:
        self.database = database

    def commit_once(
        self,
        *,
        request_handle: str,
        operation: str,
        request_sha256: str,
        effect_sha256: str,
        result: bytes,
    ) -> dict[str, Any]:
        _request_handle(request_handle)
        request_sha256 = trust.require_digest(request_sha256, "one-use request digest")
        effect_sha256 = trust.require_digest(effect_sha256, "one-use effect digest")
        record = {
            "schema_version": "openadapt.qualification-one-use-effect/v1",
            "request_handle": request_handle,
            "operation": operation,
            "request_sha256": request_sha256,
            "effect_sha256": effect_sha256,
            "result_sha256": "sha256:" + hashlib.sha256(result).hexdigest(),
            "result_base64": base64.b64encode(result).decode("ascii"),
            "retry_policy": "reconcile-never-retry",
        }
        record["effect_id_sha256"] = trust.digest_bytes(CONSUMPTION_DOMAIN, record)
        raw = evidence.canonical(record) + b"\n"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(self.database) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS one_use_effects (
                        request_handle TEXT PRIMARY KEY,
                        effect_sha256 TEXT NOT NULL UNIQUE,
                        request_sha256 TEXT NOT NULL,
                        operation TEXT NOT NULL,
                        result BLOB NOT NULL,
                        receipt BLOB NOT NULL
                    )
                    """
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO one_use_effects (
                        request_handle, effect_sha256, request_sha256,
                        operation, result, receipt
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_handle,
                        effect_sha256,
                        request_sha256,
                        operation,
                        result,
                        raw,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise IssuerError(
                "request handle or semantic effect was already consumed"
            ) from exc
        return record

    def reconcile(self, *, request_handle: str) -> dict[str, Any]:
        _request_handle(request_handle)
        try:
            with sqlite3.connect(self.database) as connection:
                row = connection.execute(
                    """
                    SELECT request_handle, effect_sha256, request_sha256,
                           operation, result, receipt
                    FROM one_use_effects
                    WHERE request_handle = ?
                    """,
                    (request_handle,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise IssuerError("one-use reconciliation store is unavailable") from exc
        if row is None:
            raise IssuerError("request handle has no committed result")
        try:
            record = json.loads(row[5])
        except (TypeError, json.JSONDecodeError) as exc:
            raise IssuerError("stored one-use receipt is invalid") from exc
        fields = {
            "schema_version",
            "request_handle",
            "operation",
            "request_sha256",
            "effect_sha256",
            "result_sha256",
            "result_base64",
            "retry_policy",
            "effect_id_sha256",
        }
        try:
            trust.closed(record, fields, "stored one-use receipt")
            stored_result = base64.b64decode(record["result_base64"], validate=True)
        except (KeyError, TypeError, ValueError, trust.TrustError) as exc:
            raise IssuerError("stored one-use receipt is invalid") from exc
        projection = dict(record)
        effect_id = projection.pop("effect_id_sha256")
        if (
            record["schema_version"] != "openadapt.qualification-one-use-effect/v1"
            or record["retry_policy"] != "reconcile-never-retry"
            or row[0] != request_handle
            or record["request_handle"] != row[0]
            or record["effect_sha256"] != row[1]
            or record["request_sha256"] != row[2]
            or record["operation"] != row[3]
            or not isinstance(row[4], bytes)
            or stored_result != row[4]
            or base64.b64encode(stored_result).decode("ascii")
            != record["result_base64"]
            or "sha256:" + hashlib.sha256(stored_result).hexdigest()
            != record["result_sha256"]
            or trust.digest_bytes(CONSUMPTION_DOMAIN, projection) != effect_id
            or evidence.canonical(record) + b"\n" != row[5]
        ):
            raise IssuerError("stored one-use result binding differs")
        try:
            trust.require_digest(record["request_sha256"], "stored request digest")
            trust.require_digest(record["effect_sha256"], "stored effect digest")
            trust.require_digest(record["result_sha256"], "stored result digest")
            trust.require_digest(effect_id, "stored effect identity")
        except trust.TrustError as exc:
            raise IssuerError("stored one-use result binding differs") from exc
        return record


def _request_handle(value: Any) -> str:
    if not isinstance(value, str) or REQUEST_HANDLE.fullmatch(value) is None:
        raise IssuerError("request handle is invalid")
    return value


def _source_commit(value: Any) -> str:
    if not isinstance(value, str) or trust.HEX40.fullmatch(value) is None:
        raise IssuerError("issuer source commit must be exact")
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IssuerError("issue time must use UTC")
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request_digest(value: Mapping[str, Any]) -> str:
    return trust.digest_bytes(REQUEST_DOMAIN, value)


def _reference_matches_object(
    value: Mapping[str, Any],
    reference: Mapping[str, Any],
    bundle_reference: Mapping[str, Any],
    *,
    kind: str,
) -> None:
    regular, _ = trust.validate_reference_pair(reference, bundle_reference, kind=kind)
    raw = evidence.canonical(value) + b"\n"
    object_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    if regular["object_sha256"] != object_sha256 or regular["size_bytes"] != len(raw):
        raise IssuerError(f"{kind} bytes differ from the exact reference")
    identity = evidence.semantic_identity_digest(
        kind=kind,
        object_schema_version=regular["object_schema_version"],
        object_value=value,
        object_sha256=object_sha256,
    )
    if regular["semantic_identity_sha256"] != identity:
        raise IssuerError(f"{kind} identity differs from the exact reference")


def _reference_matches_resolved(
    value: Mapping[str, Any],
    reference: Mapping[str, Any],
    bundle_reference: Mapping[str, Any],
    *,
    resolved: ResolvedEvidence,
    kind: str,
) -> None:
    """Require signed nested references to select the verified exact pair."""

    _reference_matches_object(value, reference, bundle_reference, kind=kind)
    if (
        dict(reference) != resolved["reference"]
        or dict(bundle_reference) != resolved["bundle_reference"]
    ):
        raise IssuerError(f"{kind} nested reference differs from the verified pair")


def _active_trust_state(
    *,
    current_signer_registry: Mapping[str, Any],
    authority_evidence: ResolvedEvidence,
    revocation_evidence: ResolvedEvidence,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], datetime]:
    try:
        registry = evidence.validate_signer_registry(current_signer_registry)
    except evidence.EvidenceRegistryError as exc:
        raise IssuerError(str(exc)) from exc
    authority = trust.validate_authority_state(authority_evidence["value"], now=now)
    revocation = trust.validate_revocation_state(revocation_evidence["value"], now=now)
    registry_identity = evidence.signer_registry_identity_digest(registry)
    registry_raw_sha256 = (
        "sha256:" + hashlib.sha256(evidence.canonical(registry) + b"\n").hexdigest()
    )
    if (
        authority["signer_registry_sha256"] != registry_raw_sha256
        or authority["signer_registry_identity_sha256"] != registry_identity
        or authority["signer_registry_revision"] != registry["revision"]
        or revocation["signer_registry_sha256"] != registry_identity
        or revocation["authority_state_sha256"] != authority["authority_state_sha256"]
        or evidence.signer_registry_identity_digest(
            authority_evidence["current_signer_registry"]
        )
        != registry_identity
        or evidence.signer_registry_identity_digest(
            revocation_evidence["current_signer_registry"]
        )
        != registry_identity
    ):
        raise IssuerError("current authority, revocation, and signer state differ")
    trust.verify_embedded_signature(
        authority,
        signer_registry=authority_evidence["bound_signer_registry"],
        object_schema_version="openadapt.qualification-authority-state-receipt/v2",
        signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
        usage="qualification-authority-state-receipt",
        now=now,
    )
    trust.verify_embedded_signature(
        revocation,
        signer_registry=revocation_evidence["bound_signer_registry"],
        object_schema_version=("openadapt.qualification-revocation-state-receipt/v1"),
        signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
        usage="qualification-revocation-state-receipt",
        now=now,
    )
    revoked = {
        (item["subject_kind"], item["subject_id"]) for item in revocation["revocations"]
    }
    for signer in registry["signers"]:
        if (
            signer["status"] == "active"
            and (
                "qualification-signer-key",
                signer["public_key_sha256"],
            )
            in revoked
        ):
            raise IssuerError("an active signer key is revoked")
    expiry = min(
        evidence._timestamp(registry["expires_at"], "signer registry expires_at"),
        trust.require_timestamp(authority["expires_at"], "authority expires_at"),
        trust.require_timestamp(revocation["expires_at"], "revocation expires_at"),
    )
    return registry, authority, revocation, expiry


def _revoked(
    revocation: Mapping[str, Any], *, subject_kind: str, subject_id: str
) -> bool:
    return any(
        item["subject_kind"] == subject_kind and item["subject_id"] == subject_id
        for item in revocation["revocations"]
    )


def _require_not_revoked(
    revocation: Mapping[str, Any], *, subject_kind: str, subject_id: str
) -> None:
    if _revoked(revocation, subject_kind=subject_kind, subject_id=subject_id):
        raise IssuerError(f"{subject_kind} is revoked")


def _require_synthetic_kms_signer(
    receipt: Mapping[str, Any], signer_registry: Mapping[str, Any]
) -> None:
    matches = [
        signer
        for signer in signer_registry["signers"]
        if signer["key_id"] == receipt["issuer_key_id"]
    ]
    if (
        len(matches) != 1
        or matches[0].get("key_origin") != "aws-kms"
        or matches[0].get("kms_key_arn") is None
    ):
        raise IssuerError("synthetic decision receipt requires the AWS KMS signer")


def _consume(
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    operation: str,
    consumer: OneUseConsumer,
) -> dict[str, Any]:
    semantic_request = dict(request)
    semantic_request.pop("request_handle", None)
    result_bytes = evidence.canonical(result) + b"\n"
    return consumer.commit_once(
        request_handle=_request_handle(request["request_handle"]),
        operation=operation,
        request_sha256=_request_digest(request),
        effect_sha256=trust.digest_bytes(
            CONSUMPTION_DOMAIN,
            {"operation": operation, "semantic_request": semantic_request},
        ),
        result=result_bytes,
    )


def issue_workflow_admission(
    request: WorkflowIssueRequest,
    *,
    resolver: EvidenceResolver,
    issuer_source_commit: str,
    now: datetime,
    consumer: OneUseConsumer,
) -> dict[str, Any]:
    """Issue one remote-safe synthetic workflow admission candidate."""

    fields = {
        "schema_version",
        "request_handle",
        "evidence_class",
        "decision_receipt_reference",
    }
    trust.closed(request, fields, "workflow admission issue request")
    if (
        request["schema_version"]
        != "openadapt.qualification-admission-issue-request/v1"
        or request["evidence_class"] != "remote-safe-synthetic"
    ):
        raise IssuerError("workflow issue request is not remote-safe synthetic")
    _request_handle(request["request_handle"])
    source_commit = _source_commit(issuer_source_commit)
    receipt_evidence = resolver.resolve(
        request["decision_receipt_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    if dict(request["decision_receipt_reference"]) != receipt_evidence["reference"]:
        raise IssuerError("decision receipt request reference differs after resolution")
    if receipt_evidence["reference"]["registry_source_commit"] != source_commit:
        raise IssuerError("decision receipt is not in the issuer source registry")
    authority_evidence, revocation_evidence = resolver.current_trust_state(
        registry_source_commit=source_commit
    )
    registry, authority, revocation, trust_expiry = _active_trust_state(
        current_signer_registry=receipt_evidence["current_signer_registry"],
        authority_evidence=authority_evidence,
        revocation_evidence=revocation_evidence,
        now=now,
    )
    receipt = trust.validate_receipt(
        receipt_evidence["value"],
        signer_registry=receipt_evidence["bound_signer_registry"],
        now=now,
    )
    if receipt.get("evidence_class") != "remote-safe-synthetic":
        raise IssuerError(
            "the synthetic issuer cannot accept private customer evidence"
        )
    _require_synthetic_kms_signer(receipt, receipt_evidence["bound_signer_registry"])
    _reference_matches_resolved(
        receipt,
        receipt_evidence["reference"],
        receipt_evidence["bundle_reference"],
        resolved=receipt_evidence,
        kind="qualification-evidence-decision-receipt",
    )
    registry_identity = evidence.signer_registry_identity_digest(registry)
    if (
        receipt["signer_registry_sha256"] != registry_identity
        or receipt["revocation_state_sha256"] != revocation["revocation_state_sha256"]
        or receipt["evidence_authority_contract_sha256"]
        != authority["evidence_authority_sha256"]
    ):
        raise IssuerError("decision receipt current trust state differs")
    receipt_reference = receipt_evidence["reference"]
    for subject_kind, subject_id in (
        (
            "qualification-evidence-decision-receipt",
            receipt_reference["semantic_identity_sha256"],
        ),
        ("qualification-campaign-permit", receipt["campaign_permit_sha256"]),
        (
            "qualification-evidence-authority",
            receipt["evidence_authority_contract_sha256"],
        ),
    ):
        _require_not_revoked(
            revocation, subject_kind=subject_kind, subject_id=subject_id
        )

    issue_time = now.replace(microsecond=0)
    expiry = min(
        issue_time + timedelta(days=7),
        trust_expiry,
        trust.require_timestamp(receipt["expires_at"], "receipt expires_at"),
    )
    if expiry <= issue_time:
        raise IssuerError("workflow admission has no positive active window")
    admission = {
        "schema_version": "openadapt.qualification-admission/v4",
        "admission_id_sha256": "sha256:" + "0" * 64,
        "evidence_class": "remote-safe-synthetic",
        "organization_id_sha256": receipt["organization_id_sha256"],
        "workflow_id_sha256": receipt["workflow_id_sha256"],
        "workflow_version_id_sha256": receipt["workflow_version_id_sha256"],
        "bundle_version": receipt["bundle_version"],
        "bundle_sha256": receipt["bundle_sha256"],
        "admitted_runtime_sha256": receipt["admitted_runtime_sha256"],
        "application_contract_sha256": receipt["application_contract_sha256"],
        "environment_contract_sha256": receipt["environment_contract_sha256"],
        "input_contract_sha256": receipt["input_contract_sha256"],
        "action_contract_sha256": receipt["action_contract_sha256"],
        "identity_contract_sha256": receipt["identity_contract_sha256"],
        "effect_contract_sha256": receipt["effect_contract_sha256"],
        "policy_contract_sha256": receipt["policy_contract_sha256"],
        "evidence_authority_sha256": receipt["evidence_authority_contract_sha256"],
        "campaign_artifact_sha256": receipt["campaign_artifact_sha256"],
        "campaign_permit_sha256": receipt["campaign_permit_sha256"],
        "decision_receipt_reference": receipt_evidence["reference"],
        "decision_receipt_bundle_reference": receipt_evidence["bundle_reference"],
        "signer_registry_sha256": registry_identity,
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "entity_class": receipt["entity_class"],
        "campaign_summary": receipt["campaign_summary"]["classes"],
        "local_identity_opening": dict(LOCAL_IDENTITY_OPENING),
        "verdict": "accepted",
        "issued_at": _timestamp(issue_time),
        "not_before": _timestamp(issue_time),
        "expires_at": _timestamp(expiry),
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-qualification-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": source_commit,
            "environment": "qualification-admission",
        },
    }
    projection = dict(admission)
    projection.pop("admission_id_sha256")
    admission["admission_id_sha256"] = trust.digest_bytes(
        trust.ADMISSION_DOMAIN, projection
    )
    trust._validate_receipt_admission_binding(
        receipt, admission, signer_registry=registry, now=now
    )
    _consume(
        request,
        admission,
        operation="issue-qualification-admission",
        consumer=consumer,
    )
    return admission


def issue_release_admission(
    request: ReleaseIssueRequest,
    *,
    resolver: EvidenceResolver,
    issuer_source_commit: str,
    now: datetime,
    consumer: OneUseConsumer,
) -> dict[str, Any]:
    """Issue one remote-safe synthetic release admission candidate."""

    fields = {
        "schema_version",
        "request_handle",
        "evidence_class",
        "production_acceptance_summary_reference",
    }
    trust.closed(request, fields, "release admission issue request")
    if (
        request["schema_version"] != "openadapt.qualification-release-issue-request/v1"
        or request["evidence_class"] != "remote-safe-synthetic"
    ):
        raise IssuerError("release issue request is not remote-safe synthetic")
    _request_handle(request["request_handle"])
    source_commit = _source_commit(issuer_source_commit)
    summary_evidence = resolver.resolve(
        request["production_acceptance_summary_reference"],
        kind="production-acceptance-summary",
    )
    if (
        dict(request["production_acceptance_summary_reference"])
        != summary_evidence["reference"]
    ):
        raise IssuerError(
            "acceptance summary request reference differs after resolution"
        )
    if summary_evidence["reference"]["registry_source_commit"] != source_commit:
        raise IssuerError("acceptance summary is not in the issuer source registry")
    summary = summary_evidence["value"]
    if (
        summary.get("target") != "flow"
        or summary.get("claim_scope") != "production_flow"
    ):
        raise IssuerError("release issuer accepts only the Flow production target")
    manifest_evidence = resolver.resolve(
        summary["production_acceptance_manifest_reference"],
        kind="production-acceptance-manifest",
    )
    receipt_evidence = resolver.resolve(
        summary["qualification_evidence_decision_receipt_reference"],
        kind="qualification-evidence-decision-receipt",
    )
    admission_evidence = resolver.resolve(
        summary["qualification_admission_reference"],
        kind="qualification-admission",
    )
    authority_evidence, revocation_evidence = resolver.current_trust_state(
        registry_source_commit=source_commit
    )
    registry, authority, revocation, trust_expiry = _active_trust_state(
        current_signer_registry=summary_evidence["current_signer_registry"],
        authority_evidence=authority_evidence,
        revocation_evidence=revocation_evidence,
        now=now,
    )
    receipt = trust.validate_receipt(
        receipt_evidence["value"],
        signer_registry=receipt_evidence["bound_signer_registry"],
        now=now,
    )
    if receipt.get("evidence_class") != "remote-safe-synthetic":
        raise IssuerError(
            "the synthetic issuer cannot accept private customer evidence"
        )
    _require_synthetic_kms_signer(receipt, receipt_evidence["bound_signer_registry"])
    admission = trust.validate_qualification_admission(
        admission_evidence["value"], now=now
    )
    if admission["evidence_class"] != "remote-safe-synthetic":
        raise IssuerError("qualification admission evidence class differs")
    manifest = manifest_evidence["value"]
    _reference_matches_resolved(
        receipt,
        admission["decision_receipt_reference"],
        admission["decision_receipt_bundle_reference"],
        resolved=receipt_evidence,
        kind="qualification-evidence-decision-receipt",
    )
    _reference_matches_resolved(
        receipt,
        manifest["qualification_evidence_decision_receipt_reference"],
        manifest["qualification_evidence_decision_receipt_bundle_reference"],
        resolved=receipt_evidence,
        kind="qualification-evidence-decision-receipt",
    )
    _reference_matches_resolved(
        receipt,
        summary["qualification_evidence_decision_receipt_reference"],
        summary["qualification_evidence_decision_receipt_bundle_reference"],
        resolved=receipt_evidence,
        kind="qualification-evidence-decision-receipt",
    )
    _reference_matches_resolved(
        admission,
        manifest["qualification_admission_reference"],
        manifest["qualification_admission_bundle_reference"],
        resolved=admission_evidence,
        kind="qualification-admission",
    )
    _reference_matches_resolved(
        admission,
        summary["qualification_admission_reference"],
        summary["qualification_admission_bundle_reference"],
        resolved=admission_evidence,
        kind="qualification-admission",
    )
    _reference_matches_resolved(
        manifest,
        summary["production_acceptance_manifest_reference"],
        summary["production_acceptance_manifest_bundle_reference"],
        resolved=manifest_evidence,
        kind="production-acceptance-manifest",
    )
    _reference_matches_resolved(
        summary,
        summary_evidence["reference"],
        summary_evidence["bundle_reference"],
        resolved=summary_evidence,
        kind="production-acceptance-summary",
    )
    registry_identity = evidence.signer_registry_identity_digest(registry)
    if (
        summary["authority_state_sha256"] != authority["authority_state_sha256"]
        or summary["revocation_state_sha256"] != revocation["revocation_state_sha256"]
        or summary["signer_registry_sha256"] != registry_identity
        or receipt["signer_registry_sha256"] != registry_identity
        or receipt["revocation_state_sha256"] != revocation["revocation_state_sha256"]
        or receipt["evidence_authority_contract_sha256"]
        != authority["evidence_authority_sha256"]
    ):
        raise IssuerError("acceptance summary current trust state differs")
    for subject_kind, subject_id in (
        (
            "qualification-evidence-decision-receipt",
            receipt_evidence["reference"]["semantic_identity_sha256"],
        ),
        (
            "qualification-admission",
            admission_evidence["reference"]["semantic_identity_sha256"],
        ),
        (
            "production-acceptance-manifest",
            manifest_evidence["reference"]["semantic_identity_sha256"],
        ),
        (
            "production-acceptance-summary",
            summary_evidence["reference"]["semantic_identity_sha256"],
        ),
        ("qualification-campaign-permit", receipt["campaign_permit_sha256"]),
        (
            "qualification-evidence-authority",
            receipt["evidence_authority_contract_sha256"],
        ),
    ):
        _require_not_revoked(
            revocation, subject_kind=subject_kind, subject_id=subject_id
        )

    issue_time = now.replace(microsecond=0)
    expiry = min(
        issue_time + timedelta(days=30),
        trust_expiry,
        trust.require_timestamp(summary["expires_at"], "summary expires_at"),
    )
    if expiry <= issue_time:
        raise IssuerError("release admission has no positive active window")
    release = {
        "schema_version": "openadapt.qualification-release/v2",
        "admission_id_sha256": "sha256:" + "0" * 64,
        "evidence_class": "remote-safe-synthetic",
        "target": summary["target"],
        "verdict": "accepted",
        "claim_scope": summary["claim_scope"],
        "release_identity": summary["release_identity"],
        "release": manifest["release"],
        "release_sha256": summary["release_sha256"],
        "artifact_inventory_sha256": summary["artifact_inventory_sha256"],
        "publication_staging": summary["publication_staging"],
        "publication_staging_sha256": summary["publication_staging_sha256"],
        "production_acceptance_summary_reference": summary_evidence["reference"],
        "production_acceptance_summary_bundle_reference": summary_evidence[
            "bundle_reference"
        ],
        "authority_state_sha256": authority["authority_state_sha256"],
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "signer_registry_sha256": registry_identity,
        "publication_policy_sha256": summary["acceptance_policy_sha256"],
        "issued_at": _timestamp(issue_time),
        "not_before": _timestamp(issue_time),
        "expires_at": _timestamp(expiry),
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-release-admission.yml",
            "ref": "refs/heads/main",
            "source_commit": source_commit,
            "environment": "production-release-admission",
        },
    }
    projection = dict(release)
    projection.pop("admission_id_sha256")
    release["admission_id_sha256"] = trust.digest_bytes(
        trust.RELEASE_ADMISSION_DOMAIN, projection
    )
    trust.validate_release_evidence_chain(
        release,
        summary=summary,
        manifest=manifest,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=receipt_evidence["bound_signer_registry"],
        now=now,
    )
    _consume(
        request,
        release,
        operation="issue-qualification-release",
        consumer=consumer,
    )
    return release


def interface_contract() -> dict[str, Any]:
    """Return the closed controls required before either issuer can activate."""

    return {
        "schema_version": "openadapt.qualification-admission-issuer-interface/v1",
        "activation_state": "inactive",
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "ref": "refs/heads/main",
        "runner_environment": "github-hosted",
        "accepted_evidence_class": "remote-safe-synthetic",
        "workflow_request_schema": (
            "openadapt.qualification-admission-issue-request/v1"
        ),
        "release_request_schema": "openadapt.qualification-release-issue-request/v1",
        "workflow_output_schema": "openadapt.qualification-admission/v4",
        "release_output_schema": "openadapt.qualification-release/v2",
        "workflow_maximum_lifetime_seconds": 7 * 24 * 60 * 60,
        "release_maximum_lifetime_seconds": 30 * 24 * 60 * 60,
        "registry_resolution": "exact-commit-registered-adjacent-bundle-verified",
        "one_use_effect": "durable-atomic-result-bound-reconciliation-required",
        "retry_policy": "reconcile-never-retry",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("interface",))
    parser.parse_args(argv)
    print(evidence.canonical(interface_contract()).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
