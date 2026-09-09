#!/usr/bin/env python3
"""Verify one exact Production release admission and its local candidate bytes."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import production_trust as trust
import public_trust_kms as public_trust
import public_trust_resolver as public_resolver
import validate_evidence_registry as evidence

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "production-evidence-policy.json"
VERIFICATION_RECEIPT_DOMAIN = (
    b"OpenAdapt qualification release verification receipt v1\0"
)
VERIFICATION_RECEIPT_V2_DOMAIN = (
    b"OpenAdapt qualification release verification receipt v2\0"
)


def load_json_argument(value: str) -> Any:
    path = Path(value)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(value)


def fetch(url: str, *, headers: dict[str, str] | None = None) -> bytes:
    request_headers = {"User-Agent": "OpenAdapt-trust/1"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def raw_url(commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/OpenAdaptAI/.github/{commit}/{path}"


def protected_main_commit() -> str:
    """Resolve the current protected main commit through the GitHub API."""

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = fetch(
        "https://api.github.com/repos/OpenAdaptAI/.github/git/ref/heads/main",
        headers=headers,
    )
    try:
        value = json.loads(raw)
        commit = value["object"]["sha"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise trust.TrustError(
            "current protected main commit response is invalid"
        ) from exc
    if not isinstance(commit, str) or trust.HEX40.fullmatch(commit) is None:
        raise trust.TrustError("current protected main commit is not exact")
    return commit


def current_registered_reference(commit: str, *, kind: str) -> dict[str, Any]:
    """Select the last registered current-state object of one exact kind."""

    registry_raw = fetch(raw_url(commit, "evidence-registry.json"))
    try:
        registry_value = json.loads(registry_raw)
        entries = evidence.validate_registry(registry_value)
    except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
        raise trust.TrustError("current protected-main registry is invalid") from exc
    matches = [entry for entry in entries if entry["kind"] == kind]
    if not matches:
        raise trust.TrustError(f"current protected-main registry has no {kind}")
    return {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": commit,
        "registry_revision": registry_value["revision"],
        "registry_head_sha256": registry_value["registry_head_sha256"],
        **matches[-1],
    }


def current_admission_state(
    admission: dict[str, Any],
    *,
    admission_reference: dict[str, Any],
    policy: dict[str, Any],
    now: datetime,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Resolve and verify the current authority, revocation, and signer state."""

    commit = protected_main_commit()
    authority_reference = current_registered_reference(
        commit, kind="qualification-authority-state-receipt"
    )
    revocation_reference = current_registered_reference(
        commit, kind="qualification-revocation-state-receipt"
    )
    authority, _, authority_current_registry = resolve_pair(
        authority_reference,
        derive_bundle_reference(authority_reference),
        kind="qualification-authority-state-receipt",
        policy=policy,
    )
    revocation, _, revocation_current_registry = resolve_pair(
        revocation_reference,
        derive_bundle_reference(revocation_reference),
        kind="qualification-revocation-state-receipt",
        policy=policy,
    )
    authority_registry_identity = evidence.signer_registry_identity_digest(
        authority_current_registry
    )
    if authority_registry_identity != evidence.signer_registry_identity_digest(
        revocation_current_registry
    ):
        raise trust.TrustError("current authority and revocation signer state differs")
    trust.validate_admission_current_state(
        admission,
        admission_reference=admission_reference,
        authority_state=authority,
        revocation_state=revocation,
        signer_registry=authority_current_registry,
        now=now,
    )
    return commit, authority, revocation, authority_current_registry


def _timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def verification_receipt(
    *,
    admission: dict[str, Any],
    admission_reference: dict[str, Any],
    admission_bundle_reference: dict[str, Any],
    summary: dict[str, Any],
    qualification_admission: dict[str, Any],
    verified_at: datetime,
    trust_state_source_commit: str,
) -> dict[str, Any]:
    """Build the closed machine-consumable result of complete verification."""

    receipt = {
        "schema_version": ("openadapt.qualification-release-verification-receipt/v1"),
        "verification_id_sha256": "sha256:" + "0" * 64,
        "verdict": "verified",
        "evidence_class": admission["evidence_class"],
        "target": admission["target"],
        "claim_scope": admission["claim_scope"],
        "admission_object_sha256": admission_reference["object_sha256"],
        "admission_bundle_object_sha256": admission_bundle_reference["object_sha256"],
        "admission_id_sha256": admission["admission_id_sha256"],
        "release_sha256": admission["release_sha256"],
        "artifact_inventory_sha256": admission["artifact_inventory_sha256"],
        "release_identity": admission["release_identity"],
        "source_repository": admission["release"]["source_repository"],
        "source_repository_id": admission["release"]["source_repository_id"],
        "source_commit": admission["release"]["source_commit"],
        "version": admission["release"]["version"],
        "tag": admission["release"]["tag"],
        "draft_release_id": admission["publication_staging"]["draft_release_id"],
        "publication_staging_sha256": admission["publication_staging_sha256"],
        "authority_state_sha256": admission["authority_state_sha256"],
        "revocation_state_sha256": admission["revocation_state_sha256"],
        "signer_registry_sha256": admission["signer_registry_sha256"],
        "acceptance_summary_object_sha256": admission[
            "production_acceptance_summary_reference"
        ]["object_sha256"],
        "acceptance_manifest_object_sha256": summary[
            "production_acceptance_manifest_reference"
        ]["object_sha256"],
        "decision_receipt_object_sha256": summary[
            "qualification_evidence_decision_receipt_reference"
        ]["object_sha256"],
        "qualification_admission_object_sha256": summary[
            "qualification_admission_reference"
        ]["object_sha256"],
        "qualification_admission_id_sha256": qualification_admission[
            "admission_id_sha256"
        ],
        "workflow_version_id_sha256": qualification_admission[
            "workflow_version_id_sha256"
        ],
        "workflow_bundle_sha256": qualification_admission["bundle_sha256"],
        "admitted_runtime_sha256": qualification_admission["admitted_runtime_sha256"],
        "verified_at": _timestamp(verified_at),
        "expires_at": admission["expires_at"],
        "registry_source_commit": admission_reference["registry_source_commit"],
        "registry_revision": admission_reference["registry_revision"],
        "registry_head_sha256": admission_reference["registry_head_sha256"],
        "trust_state_source_commit": trust_state_source_commit,
    }
    receipt_domain = VERIFICATION_RECEIPT_DOMAIN
    if admission["target"] != "flow":
        receipt.update(
            schema_version=(
                "openadapt.qualification-release-verification-receipt/v2"
            ),
            release_kind=admission["release"]["kind"],
            deployment_id=admission["release"]["deployment_id"],
            deployment_sha256=admission["release"]["deployment_sha256"],
        )
        receipt_domain = VERIFICATION_RECEIPT_V2_DOMAIN
    projection = dict(receipt)
    projection.pop("verification_id_sha256")
    receipt["verification_id_sha256"] = trust.digest_bytes(
        receipt_domain, projection
    )
    return receipt


def caller_release_identity(
    args: argparse.Namespace, release: dict[str, Any], *, target: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Close the caller's expected package, deployment, or hybrid identity."""

    optional = {
        "version": args.expected_version or None,
        "tag": args.expected_tag or None,
        "deployment_id": args.expected_deployment_id or None,
        "deployment_sha256": args.expected_deployment_sha256 or None,
    }
    kind = release["kind"]
    if kind == "package" and (
        optional["version"] is None
        or optional["tag"] is None
        or optional["deployment_id"] is not None
        or optional["deployment_sha256"] is not None
    ):
        raise trust.TrustError("caller package identity expectations are incomplete")
    if kind == "deployment" and (
        optional["version"] is not None
        or optional["tag"] is not None
        or optional["deployment_id"] is None
        or optional["deployment_sha256"] is None
    ):
        raise trust.TrustError(
            "caller deployment identity expectations are incomplete"
        )
    if kind == "hybrid" and any(value is None for value in optional.values()):
        raise trust.TrustError("caller hybrid identity expectations are incomplete")
    expected = {
        "target": target,
        "repository": args.expected_repository,
        "repository_id": args.expected_repository_id,
        "source_commit": args.expected_source_commit,
        **optional,
    }
    actual = {
        "target": target,
        "repository": release["source_repository"],
        "repository_id": release["source_repository_id"],
        "source_commit": release["source_commit"],
        "version": release["version"],
        "tag": release["tag"],
        "deployment_id": release["deployment_id"],
        "deployment_sha256": release["deployment_sha256"],
    }
    return expected, actual


def verify_bytes(raw: bytes, reference: dict[str, Any], label: str) -> Any:
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != reference["object_sha256"] or len(raw) != reference["size_bytes"]:
        raise trust.TrustError(f"{label} bytes or size differ from the reference")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise trust.TrustError(f"{label} is not JSON") from exc
    identity_value = (
        reference["subject_sha256"]
        if reference["kind"].endswith("-sigstore-bundle")
        else value
    )
    if (
        not reference["kind"].endswith("-sigstore-bundle")
        and raw != evidence.canonical(value) + b"\n"
    ):
        raise trust.TrustError(f"{label} is not canonical JSON followed by one LF")
    expected_identity = evidence.semantic_identity_digest(
        kind=reference["kind"],
        object_schema_version=reference["object_schema_version"],
        object_value=identity_value,
        object_sha256=reference["object_sha256"],
    )
    if expected_identity != reference["semantic_identity_sha256"]:
        raise trust.TrustError(f"{label} semantic identity differs")
    return value


def fetch_pair(
    regular_reference: dict[str, Any], bundle_reference: dict[str, Any]
) -> tuple[
    bytes,
    bytes,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    regular, bundle = trust.validate_reference_pair(
        regular_reference,
        bundle_reference,
        kind=regular_reference.get("kind", ""),
    )
    commit = regular["registry_source_commit"]
    registry_raw = fetch(raw_url(commit, "evidence-registry.json"))
    try:
        registry_value = json.loads(registry_raw)
        entries = evidence.validate_registry(registry_value)
    except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
        raise trust.TrustError("the referenced registry is invalid") from exc
    if (
        registry_value["revision"] != regular["registry_revision"]
        or registry_value["registry_head_sha256"] != regular["registry_head_sha256"]
    ):
        raise trust.TrustError("reference registry revision or head differs")
    try:
        evidence.require_registered(entries, reference=regular, label="regular object")
        evidence.require_registered(entries, reference=bundle, label="bundle object")
    except evidence.EvidenceRegistryError as exc:
        raise trust.TrustError(str(exc)) from exc
    current_pointer = registry_value["signer_registry"]
    if current_pointer is None:
        raise trust.TrustError("the referenced registry has no signer registry")
    regular_raw = fetch(raw_url(commit, regular["object_path"]))
    bundle_raw = fetch(raw_url(commit, bundle["object_path"]))
    value = verify_bytes(regular_raw, regular, "regular object")
    verify_bytes(bundle_raw, bundle, "bundle object")

    def load_signer(pointer: dict[str, Any], *, require_active: bool) -> dict[str, Any]:
        signer_raw = fetch(raw_url(commit, pointer["object_path"]))
        if (
            "sha256:" + hashlib.sha256(signer_raw).hexdigest()
            != pointer["object_sha256"]
            or signer_raw[-1:] != b"\n"
        ):
            raise trust.TrustError("signer registry bytes differ")
        try:
            signer_value = evidence.validate_signer_registry(json.loads(signer_raw))
        except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
            raise trust.TrustError("signer registry is invalid") from exc
        if (
            evidence.canonical(signer_value) + b"\n" != signer_raw
            or evidence.signer_registry_identity_digest(signer_value)
            != pointer["registry_identity_sha256"]
            or signer_value["revision"] != pointer["registry_revision"]
        ):
            raise trust.TrustError("signer registry identity differs")
        if require_active:
            now = datetime.now(timezone.utc)
            generated = evidence._timestamp(signer_value["generated_at"], "generated_at")
            expires = evidence.optional_timestamp(
                signer_value["expires_at"], "expires_at"
            )
            if now < generated or (expires is not None and now >= expires):
                raise trust.TrustError("current signer registry is not active")
        return signer_value

    current_signer_registry = load_signer(current_pointer, require_active=True)
    # Authority v2 commits registry bytes and semantic identity separately.
    bound_identity = value.get(
        "signer_registry_identity_sha256"
        if value.get("schema_version")
        == "openadapt.qualification-authority-state-receipt/v2"
        else "signer_registry_sha256"
    )
    if bound_identity is None:
        bound_pointer = current_pointer
    else:
        matches = [
            item
            for item in registry_value["signer_registry_history"]
            if item["registry_identity_sha256"] == bound_identity
        ]
        if len(matches) != 1:
            raise trust.TrustError(
                "object signer registry is not in append-only pointer history"
            )
        bound_pointer = matches[0]
    bound_signer_registry = (
        current_signer_registry
        if bound_pointer == current_pointer
        else load_signer(bound_pointer, require_active=False)
    )
    return (
        regular_raw,
        bundle_raw,
        value,
        bound_signer_registry,
        current_signer_registry,
    )


def resolve_pair(
    regular_reference: dict[str, Any],
    bundle_reference: dict[str, Any],
    *,
    kind: str,
    policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if regular_reference.get("kind") != kind:
        raise trust.TrustError(f"the referenced object is not {kind}")
    regular_raw, bundle_raw, value, bound_signer_registry, current_signer_registry = (
        fetch_pair(regular_reference, bundle_reference)
    )
    verify_registered_signature(
        regular_reference,
        bundle_reference,
        (regular_raw, bundle_raw, value, bound_signer_registry, current_signer_registry),
        policy=policy,
    )
    return value, bound_signer_registry, current_signer_registry


def derive_bundle_reference(regular_reference: dict[str, Any]) -> dict[str, Any]:
    regular = evidence.validate_reference(regular_reference)
    commit = regular["registry_source_commit"]
    registry_value = json.loads(fetch(raw_url(commit, "evidence-registry.json")))
    entries = evidence.validate_registry(registry_value)
    for index, entry in enumerate(entries):
        if entry["registry_entry_sha256"] != regular["registry_entry_sha256"]:
            continue
        if index + 1 >= len(entries):
            break
        bundle_entry = entries[index + 1]
        return {
            "schema_version": evidence.REFERENCE_SCHEMA,
            "repository": evidence.REPOSITORY,
            "repository_id": evidence.REPOSITORY_ID,
            "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
            "registry_source_commit": commit,
            "registry_revision": regular["registry_revision"],
            "registry_head_sha256": regular["registry_head_sha256"],
            **bundle_entry,
        }
    raise trust.TrustError(
        "the admission bundle does not immediately follow its object"
    )


def _registered_state_pairs(
    reference: dict[str, Any],
    *,
    kind: str,
    identity: str | None = None,
    authority_identity: str | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any], tuple]]:
    """Resolve historical state from the object's exact containing registry."""

    commit = reference["registry_source_commit"]
    registry = json.loads(fetch(raw_url(commit, "evidence-registry.json")))
    entries = evidence.validate_registry(registry)
    if (
        registry["revision"] != reference["registry_revision"]
        or registry["registry_head_sha256"] != reference["registry_head_sha256"]
    ):
        raise trust.TrustError("state reference registry revision or head differs")
    matches = []
    for entry in entries:
        if entry["kind"] != kind or (
            identity is not None and entry["semantic_identity_sha256"] != identity
        ):
            continue
        regular = {
            **{field: reference[field] for field in (
                "schema_version", "repository", "repository_id",
                "repository_owner_id", "registry_source_commit",
                "registry_revision", "registry_head_sha256",
            )},
            **entry,
        }
        bundle = derive_bundle_reference(regular)
        pair = fetch_pair(regular, bundle)
        if authority_identity is not None and (
            pair[2].get("authority_state_sha256") != authority_identity
        ):
            continue
        matches.append((regular, bundle, pair))
    return matches


def _registered_state_pair(reference: dict[str, Any], **selectors: Any) -> tuple:
    matches = _registered_state_pairs(reference, **selectors)
    if len(matches) != 1:
        raise trust.TrustError("exactly one bound state must be registered")
    return matches[0]


def _software_signer(registry: dict[str, Any], statement: dict[str, Any]) -> dict:
    matches = [signer for signer in registry["signers"] if (
        signer["key_id"] == statement["key_id"]
        and signer["algorithm"] == "ed25519"
        and signer.get("key_origin") == "software"
    )]
    if len(matches) != 1:
        raise trust.TrustError("software bundle does not select one registered signer")
    return matches[0]


def _verify_software_pair(
    reference: dict[str, Any],
    bundle_reference: dict[str, Any],
    pair: tuple,
    *,
    authority: dict[str, Any],
    revocation: dict[str, Any],
    now: datetime,
) -> None:
    raw, bundle_raw, value, bound_registry, current_registry = pair
    bundle = json.loads(bundle_raw)
    statement = public_trust.statement_from_bundle(bundle)
    if statement["signature_profile"] != public_trust.SOFTWARE_SIGNATURE_PROFILE:
        raise trust.TrustError("registered software route rejects this signature profile")
    bound_raw = evidence.canonical(bound_registry) + b"\n"
    bound_identity = evidence.signer_registry_identity_digest(bound_registry)
    signed_at = trust.require_timestamp(statement["issued_at"], "statement issued_at")
    expectations = {
        "expected_signer_registry_sha256": bound_identity,
        "expected_authority_state_sha256": authority["authority_state_sha256"],
        "expected_revocation_state_sha256": revocation["revocation_state_sha256"],
    }
    if value.get("schema_version") == (
        "openadapt.qualification-authority-state-receipt/v2"
    ):
        # This existing schema and its outer statement bind the raw registry
        # digest. Do not relabel it as the independent semantic identity.
        if raw != evidence.canonical(value) + b"\n" or (
            bundle_raw != evidence.canonical(bundle) + b"\n"
        ):
            raise trust.TrustError("authority pair must be canonical JSON plus LF")
        generated = evidence._timestamp(bound_registry["generated_at"], "registry generated_at")
        expires = evidence.optional_timestamp(bound_registry["expires_at"], "registry expires_at")
        if signed_at < generated or (expires is not None and signed_at >= expires):
            raise trust.TrustError("authority bound signer registry is not active at statement time")
        if value["signer_registry_identity_sha256"] != bound_identity:
            raise trust.TrustError("authority signer registry identity differs")
        expectations["expected_signer_registry_sha256"] = (
            "sha256:" + hashlib.sha256(bound_raw).hexdigest()
        )
        public_trust.validate_statement_object_binding(
            statement,
            object_raw=raw,
            object_value=value,
            object_kind=reference["kind"],
            object_schema_version=reference["object_schema_version"],
            object_media_type=reference["object_media_type"],
            semantic_identity_sha256=reference["semantic_identity_sha256"],
            **expectations,
        )
        public_trust.verify_bundle(
            bundle, expected_statement=statement,
            signer=_software_signer(bound_registry, statement), now=signed_at,
        )
    else:
        public_resolver.verify_registered_public_trust_pair(
            object_raw=raw, object_reference=reference,
            bundle_raw=bundle_raw, bundle_reference=bundle_reference,
            signer_registry_raw=bound_raw, now=signed_at, **expectations,
        )
    # Historical bindings do not grant a revoked key present-day authority.
    public_trust.verify_bundle(
        bundle, expected_statement=statement,
        signer=_software_signer(current_registry, statement), now=now,
    )


def _verify_embedded_state(
    state_pair: tuple,
    *,
    bound_registry: dict[str, Any],
    current_registry: dict[str, Any],
    now: datetime,
) -> None:
    reference, _, fetched = state_pair
    state, state_bound, state_current = fetched[2:]
    if (
        evidence.signer_registry_identity_digest(state_bound)
        != evidence.signer_registry_identity_digest(bound_registry)
        or evidence.signer_registry_identity_digest(state_current)
        != evidence.signer_registry_identity_digest(current_registry)
    ):
        raise trust.TrustError("registered trust-state signer registries differ")
    if reference["kind"] == "qualification-authority-state-receipt":
        validator = trust.validate_authority_state
        domain = trust.AUTHORITY_STATE_SIGNATURE_DOMAIN
    elif reference["kind"] == "qualification-revocation-state-receipt":
        validator = trust.validate_revocation_state
        domain = trust.REVOCATION_STATE_SIGNATURE_DOMAIN
    else:
        raise trust.TrustError("registered state has an unsupported kind")
    observed_at = trust.require_timestamp(state["observed_at"], "state observed_at")
    validator(state, now=observed_at)
    for registry, instant in ((state_bound, observed_at), (state_current, now)):
        trust.verify_embedded_signature(
            state, signer_registry=registry,
            object_schema_version=reference["object_schema_version"],
            signature_domain=domain, usage=reference["kind"], now=instant,
        )


def _validate_registered_state_links(
    authority: dict[str, Any],
    revocation: dict[str, Any],
    *,
    bound_registry: dict[str, Any],
    current_registry: dict[str, Any],
) -> None:
    identity = evidence.signer_registry_identity_digest(bound_registry)
    if (
        authority["signer_registry_identity_sha256"] != identity
        or authority["signer_registry_sha256"]
        != "sha256:" + hashlib.sha256(evidence.canonical(bound_registry) + b"\n").hexdigest()
        or authority["signer_registry_revision"] != bound_registry["revision"]
        or revocation["signer_registry_sha256"] != identity
        or revocation["authority_state_sha256"] != authority["authority_state_sha256"]
    ):
        raise trust.TrustError("registered bound authority and signer state differ")
    revoked = {(item["subject_kind"], item["subject_id"])
               for item in revocation["revocations"]}
    if any(signer["status"] == "active" and (
        "qualification-signer-key", signer["public_key_sha256"]
    ) in revoked for signer in current_registry["signers"]):
        raise trust.TrustError("an active signer key is revoked")


def _verify_authority_pair(
    authority_pair: tuple,
    *,
    bound_registry: dict[str, Any],
    current_registry: dict[str, Any],
    now: datetime,
) -> tuple:
    """Find the independently verified historical reverse link missing in v2."""

    reference, bundle_reference, pair = authority_pair
    authority = pair[2]
    matches = []
    for candidate in _registered_state_pairs(
        reference, kind="qualification-revocation-state-receipt",
        authority_identity=authority["authority_state_sha256"],
    ):
        revocation = candidate[2][2]
        try:
            _verify_embedded_state(candidate, bound_registry=bound_registry,
                                   current_registry=current_registry, now=now)
            _validate_registered_state_links(authority, revocation,
                                             bound_registry=bound_registry,
                                             current_registry=current_registry)
            _verify_software_pair(*candidate, authority=authority,
                                  revocation=revocation, now=now)
            _verify_software_pair(reference, bundle_reference, pair,
                                  authority=authority, revocation=revocation, now=now)
        except (trust.TrustError, public_trust.PublicTrustKmsError,
                public_resolver.PublicTrustResolutionError,
                evidence.EvidenceRegistryError, KeyError, TypeError,
                json.JSONDecodeError):
            continue
        matches.append(candidate)
    if len(matches) != 1:
        raise trust.TrustError("authority must bind exactly one verified registered revocation")
    return matches[0]


def verify_registered_signature(
    reference: dict[str, Any],
    bundle_reference: dict[str, Any],
    pair: tuple,
    *,
    policy: dict[str, Any],
) -> None:
    """Route registered software DSSE without changing any keyless profile."""

    raw, bundle_raw, value, bound_registry, current_registry = pair
    bundle = json.loads(bundle_raw)
    envelope = bundle.get("dsseEnvelope", {}) if isinstance(bundle, dict) else {}
    material = bundle.get("verificationMaterial", {}) if isinstance(bundle, dict) else {}
    is_public_trust = (
        isinstance(envelope, dict)
        and envelope.get("payloadType") == public_trust.STATEMENT_MEDIA_TYPE
    ) or (isinstance(material, dict) and "publicKey" in material)
    if not is_public_trust:
        verify_sigstore(raw, bundle_raw, kind=reference["kind"],
                       object_value=value, policy=policy)
        return
    try:
        statement = public_trust.statement_from_bundle(bundle)
        if statement["signature_profile"] != public_trust.SOFTWARE_SIGNATURE_PROFILE:
            raise trust.TrustError("registered software route rejects this signature profile")
        now = datetime.now(timezone.utc)
        if value.get("schema_version") == (
            "openadapt.qualification-authority-state-receipt/v2"
        ):
            authority_pair = (reference, bundle_reference, pair)
            _verify_embedded_state(authority_pair, bound_registry=bound_registry,
                                   current_registry=current_registry, now=now)
            _verify_authority_pair(authority_pair, bound_registry=bound_registry,
                                   current_registry=current_registry, now=now)
            return
        # Select the target's states from registered object commitments,
        # never from an outer DSSE statement.
        revocation_pair = _registered_state_pair(
            reference, kind="qualification-revocation-state-receipt",
            identity=value.get("revocation_state_sha256"),
            authority_identity=value.get("authority_state_sha256"),
        )
        revocation = revocation_pair[2][2]
        authority_pair = _registered_state_pair(
            reference, kind="qualification-authority-state-receipt",
            identity=revocation["authority_state_sha256"],
        )
        authority = authority_pair[2][2]
        for state_pair in (authority_pair, revocation_pair):
            _verify_embedded_state(state_pair, bound_registry=bound_registry,
                                   current_registry=current_registry, now=now)
        _validate_registered_state_links(authority, revocation,
                                         bound_registry=bound_registry,
                                         current_registry=current_registry)
        # The authority outer signature keeps its own historical reverse link
        # when a later revocation retains the same authority identity.
        _verify_authority_pair(authority_pair, bound_registry=bound_registry,
                               current_registry=current_registry, now=now)
        _verify_software_pair(*revocation_pair, authority=authority,
                              revocation=revocation, now=now)
        _verify_software_pair(reference, bundle_reference, pair,
                              authority=authority, revocation=revocation, now=now)
    except (public_trust.PublicTrustKmsError,
            public_resolver.PublicTrustResolutionError,
            evidence.EvidenceRegistryError, KeyError, TypeError,
            json.JSONDecodeError) as exc:
        raise trust.TrustError(f"registered software DSSE verification failed: {exc}") from exc


def verify_sigstore(
    regular_raw: bytes,
    bundle_raw: bytes,
    *,
    kind: str,
    object_value: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    sigstore = policy["sigstore"]
    evidence_class = (
        object_value.get("evidence_class", "private-customer")
        if kind == "qualification-evidence-decision-receipt"
        else "not-applicable"
    )
    identities = [
        item
        for item in sigstore["certificate_identities"]
        if item["kind"] == kind and item.get("evidence_class") == evidence_class
    ]
    if len(identities) != 1:
        raise trust.TrustError(
            f"exactly one keyless identity must be registered for {kind}"
        )
    identity = identities[0]
    profile = identity.get("bundle_profile")
    if profile == "sigstore-message-signature":
        verify_message_signature(
            regular_raw,
            bundle_raw,
            kind=kind,
            object_value=object_value,
            identity=identity,
            policy=policy,
        )
        return
    if profile != "github-attestation":
        raise trust.TrustError(f"{kind} has an unsupported Sigstore profile")
    version = subprocess.run(
        ["gh", "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    if version != f"gh version {sigstore['version']} (2026-08-20)":
        raise trust.TrustError(
            f"GitHub CLI version differs; required {sigstore['version']}; got {version}"
        )
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        subject = directory / "subject.json"
        bundle = directory / "bundle.json"
        subject.write_bytes(regular_raw)
        bundle.write_bytes(bundle_raw)
        command = [
            "gh",
            "attestation",
            "verify",
            str(subject),
            "--bundle",
            str(bundle),
            "--repo",
            identity["issuer_repository"],
            "--cert-identity",
            identity["certificate_identity"],
            "--cert-oidc-issuer",
            sigstore["cert_oidc_issuer"],
            "--deny-self-hosted-runners",
            "--no-public-good",
            "--format",
            "json",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise trust.TrustError(
                "Sigstore bundle verification failed: " + result.stderr.strip()
            )
        try:
            results = json.loads(result.stdout)
            if not isinstance(results, list) or len(results) != 1:
                raise trust.TrustError(
                    "Sigstore verifier must return exactly one verified statement"
                )
            verification = results[0]["verificationResult"]
            statement = verification["statement"]
            certificate = verification["signature"]["certificate"]
            subjects = statement["subject"]
            predicate_type = statement["predicateType"]
            dependencies = statement["predicate"]["buildDefinition"][
                "resolvedDependencies"
            ]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise trust.TrustError("Sigstore verifier output is not JSON") from exc
        if (
            predicate_type != "https://slsa.dev/provenance/v1"
            or not isinstance(subjects, list)
            or len(subjects) != 1
            or subjects[0].get("digest")
            != {"sha256": hashlib.sha256(regular_raw).hexdigest()}
        ):
            raise trust.TrustError("Sigstore statement subject or predicate differs")
        issuer = object_value.get("issuer")
        if not isinstance(issuer, dict):
            raise trust.TrustError("signed object has no closed issuer identity")
        source_commit = issuer.get("source_commit")
        source_ref = issuer.get("ref")
        if (
            certificate.get("githubWorkflowSHA") != source_commit
            or certificate.get("sourceRepositoryDigest") != source_commit
            or certificate.get("githubWorkflowRef") != source_ref
            or certificate.get("githubWorkflowRepository")
            != identity["issuer_repository"]
        ):
            raise trust.TrustError("Sigstore certificate source identity differs")
        expected_dependency = {
            "uri": (
                f"git+https://github.com/{identity['issuer_repository']}@{source_ref}"
            ),
            "digest": {"gitCommit": source_commit},
        }
        if dependencies != [expected_dependency]:
            raise trust.TrustError("Sigstore resolved source dependency differs")


def _canonical_base64(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise trust.TrustError(f"{label} is not base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise trust.TrustError(f"{label} is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise trust.TrustError(f"{label} is not canonical base64")
    return raw


def verify_message_signature(
    regular_raw: bytes,
    bundle_raw: bytes,
    *,
    kind: str,
    object_value: dict[str, Any],
    identity: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Verify the exact raw v0.3 messageSignature profile."""

    try:
        bundle = json.loads(bundle_raw)
        if set(bundle) != {"mediaType", "verificationMaterial", "messageSignature"}:
            raise trust.TrustError("messageSignature bundle top-level fields differ")
        if bundle["mediaType"] != evidence.BUNDLE_MEDIA_TYPE:
            raise trust.TrustError("messageSignature bundle media type differs")
        message = bundle["messageSignature"]
        if not isinstance(message, dict) or set(message) != {
            "messageDigest",
            "signature",
        }:
            raise trust.TrustError("messageSignature fields differ")
        digest = message["messageDigest"]
        if not isinstance(digest, dict) or set(digest) != {"algorithm", "digest"}:
            raise trust.TrustError("messageSignature digest fields differ")
        if digest["algorithm"] != "SHA2_256":
            raise trust.TrustError("messageSignature digest algorithm differs")
        if _canonical_base64(digest["digest"], label="messageSignature digest") != (
            hashlib.sha256(regular_raw).digest()
        ):
            raise trust.TrustError("messageSignature digest differs from the object")
        signature = _canonical_base64(
            message["signature"], label="messageSignature signature"
        )
        if not signature:
            raise trust.TrustError("messageSignature signature is empty")
        material = bundle["verificationMaterial"]
        if not isinstance(material, dict) or "certificate" not in material:
            raise trust.TrustError("messageSignature certificate is missing")
        tlog_entries = material.get("tlogEntries")
        if not isinstance(tlog_entries, list) or not tlog_entries:
            raise trust.TrustError("messageSignature transparency log proof is missing")
        certificate = material["certificate"]
        if not isinstance(certificate, dict) or set(certificate) != {"rawBytes"}:
            raise trust.TrustError("messageSignature certificate fields differ")
        if not _canonical_base64(
            certificate["rawBytes"], label="messageSignature certificate"
        ):
            raise trust.TrustError("messageSignature certificate is empty")
    except json.JSONDecodeError as exc:
        raise trust.TrustError("messageSignature bundle is not JSON") from exc

    message_policy = policy["message_signature"]
    cosign_path = shutil.which("cosign")
    if cosign_path is None:
        raise trust.TrustError("the pinned Cosign verifier is not installed")
    cosign_raw = Path(cosign_path).read_bytes()
    if (
        len(cosign_raw) != message_policy["size_bytes"]
        or "sha256:" + hashlib.sha256(cosign_raw).hexdigest()
        != message_policy["sha256"]
    ):
        raise trust.TrustError("Cosign binary bytes differ from policy")
    trusted_root_path = os.environ.get("OPENADAPT_SIGSTORE_TRUSTED_ROOT")
    if not trusted_root_path:
        raise trust.TrustError("the pinned Sigstore trusted root is not configured")
    trusted_root = Path(trusted_root_path)
    trusted_root_raw = trusted_root.read_bytes()
    root_policy = message_policy["trusted_root"]
    if (
        len(trusted_root_raw) != root_policy["size_bytes"]
        or "sha256:" + hashlib.sha256(trusted_root_raw).hexdigest()
        != root_policy["sha256"]
    ):
        raise trust.TrustError("Sigstore trusted root bytes differ from policy")
    issuer = object_value.get("issuer")
    if not isinstance(issuer, dict):
        raise trust.TrustError("messageSignature object has no signed issuer")
    if (
        issuer.get("repository") != identity["issuer_repository"]
        or issuer.get("ref") != "refs/heads/main"
        or not isinstance(issuer.get("source_commit"), str)
        or trust.HEX40.fullmatch(issuer["source_commit"]) is None
    ):
        raise trust.TrustError("messageSignature signed issuer differs")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        subject_path = directory / "subject.json"
        bundle_path = directory / "bundle.json"
        subject_path.write_bytes(regular_raw)
        bundle_path.write_bytes(bundle_raw)
        result = subprocess.run(
            [
                cosign_path,
                "verify-blob",
                "--allow-certificate-chain",
                "--bundle",
                str(bundle_path),
                "--trusted-root",
                str(trusted_root),
                "--certificate-identity",
                identity["certificate_identity"],
                "--certificate-oidc-issuer",
                policy["sigstore"]["cert_oidc_issuer"],
                "--certificate-github-workflow-repository",
                identity["issuer_repository"],
                "--certificate-github-workflow-ref",
                issuer["ref"],
                "--certificate-github-workflow-sha",
                issuer["source_commit"],
                "--certificate-github-workflow-trigger",
                "workflow_dispatch",
                str(subject_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode:
        raise trust.TrustError(
            "messageSignature verification failed: " + result.stderr.strip()
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission-reference", required=True)
    parser.add_argument("--admission-bundle-reference")
    parser.add_argument("--artifact-inventory", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-repository-id", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-version", default="")
    parser.add_argument("--expected-tag", default="")
    parser.add_argument("--expected-deployment-id", default="")
    parser.add_argument("--expected-deployment-sha256", default="")
    parser.add_argument("--github-output")
    args = parser.parse_args(argv)
    try:
        reference = load_json_argument(args.admission_reference)
        bundle_reference = (
            load_json_argument(args.admission_bundle_reference)
            if args.admission_bundle_reference
            else derive_bundle_reference(reference)
        )
        inventory = trust.validate_artifact_inventory(
            load_json_argument(args.artifact_inventory)
        )
        (
            regular_raw,
            bundle_raw,
            admission_value,
            release_signer_registry,
            _current_signer_registry,
        ) = fetch_pair(reference, bundle_reference)
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if reference.get("kind") != "qualification-release":
            raise trust.TrustError("the referenced object is not qualification-release")
        verify_registered_signature(
            reference,
            bundle_reference,
            (regular_raw, bundle_raw, admission_value,
             release_signer_registry, _current_signer_registry),
            policy=policy,
        )
        now = datetime.now(timezone.utc)
        admission = trust.validate_release(admission_value)
        target_contract = trust.TARGET_CONTRACTS.get(admission["target"])
        if (
            admission["target"] not in trust.ADMISSION_GATE_TARGETS
            or admission["evidence_class"] != "remote-safe-synthetic"
            or target_contract is None
            or admission["claim_scope"] != target_contract["claim_scope"]
        ):
            raise trust.TrustError(
                "release verifier accepts only remote-safe synthetic evidence "
                "for the current admission-gate target"
            )
        if admission[
            "signer_registry_sha256"
        ] != evidence.signer_registry_identity_digest(release_signer_registry):
            raise trust.TrustError("release signer registry identity differs")
        summary, _, _ = resolve_pair(
            admission["production_acceptance_summary_reference"],
            admission["production_acceptance_summary_bundle_reference"],
            kind="production-acceptance-summary",
            policy=policy,
        )
        manifest, _, _ = resolve_pair(
            summary["production_acceptance_manifest_reference"],
            summary["production_acceptance_manifest_bundle_reference"],
            kind="production-acceptance-manifest",
            policy=policy,
        )
        receipt, receipt_signer_registry, receipt_current_signer_registry = (
            resolve_pair(
                summary["qualification_evidence_decision_receipt_reference"],
                summary["qualification_evidence_decision_receipt_bundle_reference"],
                kind="qualification-evidence-decision-receipt",
                policy=policy,
            )
        )
        qualification_admission, _, _ = resolve_pair(
            summary["qualification_admission_reference"],
            summary["qualification_admission_bundle_reference"],
            kind="qualification-admission",
            policy=policy,
        )
        if receipt[
            "signer_registry_sha256"
        ] != evidence.signer_registry_identity_digest(receipt_signer_registry):
            raise trust.TrustError("decision receipt signer registry identity differs")
        trust.verify_embedded_signature(
            receipt,
            signer_registry=receipt_signer_registry,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v2"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
            usage="qualification-evidence-decision-receipt",
            now=trust.require_timestamp(receipt["issued_at"], "receipt issued_at"),
        )
        trust.verify_embedded_signature(
            receipt,
            signer_registry=receipt_current_signer_registry,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v2"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
            usage="qualification-evidence-decision-receipt",
            now=now,
        )
        admission = trust.validate_release_evidence_chain(
            admission,
            summary=summary,
            manifest=manifest,
            receipt=receipt,
            qualification_admission=qualification_admission,
            receipt_signer_registry=receipt_current_signer_registry,
            now=now,
        )
        trust_state_commit, _authority, revocation, _active_signer_registry = (
            current_admission_state(
                admission,
                admission_reference=reference,
                policy=policy,
                now=now,
            )
        )
        revoked = {
            (item["subject_kind"], item["subject_id"])
            for item in revocation["revocations"]
        }
        for subject_kind, subject_id in (
            (
                "production-acceptance-summary",
                admission["production_acceptance_summary_reference"][
                    "semantic_identity_sha256"
                ],
            ),
            (
                "production-acceptance-manifest",
                summary["production_acceptance_manifest_reference"][
                    "semantic_identity_sha256"
                ],
            ),
            (
                "qualification-evidence-decision-receipt",
                summary["qualification_evidence_decision_receipt_reference"][
                    "semantic_identity_sha256"
                ],
            ),
            (
                "qualification-admission",
                summary["qualification_admission_reference"][
                    "semantic_identity_sha256"
                ],
            ),
            ("qualification-campaign-permit", receipt["campaign_permit_sha256"]),
            (
                "qualification-evidence-authority",
                receipt["evidence_authority_contract_sha256"],
            ),
        ):
            if (subject_kind, subject_id) in revoked:
                raise trust.TrustError(f"{subject_kind} is revoked")
        release = admission["release"]
        expected, actual = caller_release_identity(
            args, release, target=args.expected_target
        )
        actual["target"] = admission["target"]
        if actual != expected:
            raise trust.TrustError("release identity differs from caller expectations")
        if (
            inventory["target"] != admission["target"]
            or inventory["claim_scope"] != admission["claim_scope"]
            or inventory["artifacts"] != release["artifacts"]
            or trust.artifact_inventory_digest(inventory)
            != admission["artifact_inventory_sha256"]
        ):
            raise trust.TrustError("caller artifact inventory differs from admission")
        trust.verify_local_artifacts(Path(args.artifact_root), release["artifacts"])
        receipt_output = verification_receipt(
            admission=admission,
            admission_reference=reference,
            admission_bundle_reference=bundle_reference,
            summary=summary,
            qualification_admission=qualification_admission,
            verified_at=now,
            trust_state_source_commit=trust_state_commit,
        )
        outputs = {
            "verification_json": evidence.canonical(receipt_output).decode("utf-8"),
            "verification_id_sha256": receipt_output["verification_id_sha256"],
            "evidence_class": receipt_output["evidence_class"],
            "target": receipt_output["target"],
            "claim_scope": receipt_output["claim_scope"],
            "admission_object_sha256": reference["object_sha256"],
            "release_sha256": admission["release_sha256"],
            "artifact_inventory_sha256": admission["artifact_inventory_sha256"],
            "publication_staging_json": trust.canonical(
                admission["publication_staging"]
            ).decode("utf-8"),
            "publication_staging_sha256": admission["publication_staging_sha256"],
            "draft_release_id": admission["publication_staging"]["draft_release_id"],
            "version": release["version"] or "",
            "tag": release["tag"] or "",
            "deployment_id": release["deployment_id"] or "",
            "deployment_sha256": release["deployment_sha256"] or "",
            "authority_state_sha256": admission["authority_state_sha256"],
            "revocation_state_sha256": admission["revocation_state_sha256"],
            "signer_registry_sha256": admission["signer_registry_sha256"],
            "admitted_runtime_sha256": qualification_admission[
                "admitted_runtime_sha256"
            ],
            "verified_at": receipt_output["verified_at"],
            "expires_at": admission["expires_at"],
            "registry_source_commit": reference["registry_source_commit"],
            "trust_state_source_commit": trust_state_commit,
        }
        if args.github_output:
            with Path(args.github_output).open("a", encoding="utf-8") as handle:
                handle.writelines(f"{key}={value}\n" for key, value in outputs.items())
        print(evidence.canonical(receipt_output).decode("utf-8"))
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
