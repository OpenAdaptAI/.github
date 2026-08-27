#!/usr/bin/env python3
"""Verify one exact Production release admission and its local candidate bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import production_trust as trust
import validate_evidence_registry as evidence

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "production-evidence-policy.json"


def load_json_argument(value: str) -> Any:
    path = Path(value)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(value)


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "OpenAdapt-trust/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def raw_url(commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/OpenAdaptAI/.github/{commit}/{path}"


def verify_bytes(raw: bytes, reference: dict[str, Any], label: str) -> Any:
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != reference["object_sha256"] or len(raw) != reference["size_bytes"]:
        raise trust.TrustError(f"{label} bytes or size differ from the reference")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise trust.TrustError(f"{label} is not JSON") from exc
    identity_value = reference["subject_sha256"] if reference["kind"].endswith("-sigstore-bundle") else value
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
) -> tuple[bytes, bytes, dict[str, Any]]:
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
    signer_pointer = registry_value["signer_registry"]
    if signer_pointer is None:
        raise trust.TrustError("the referenced registry has no signer registry")
    signer_raw = fetch(raw_url(commit, signer_pointer["object_path"]))
    if "sha256:" + hashlib.sha256(signer_raw).hexdigest() != signer_pointer["object_sha256"]:
        raise trust.TrustError("signer registry bytes differ")
    try:
        signer_registry = evidence.validate_signer_registry(json.loads(signer_raw))
    except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
        raise trust.TrustError("signer registry is invalid") from exc
    if evidence.signer_registry_identity_digest(signer_registry) != signer_pointer["registry_identity_sha256"]:
        raise trust.TrustError("signer registry identity differs")
    now = datetime.now(timezone.utc)
    if not evidence._timestamp(signer_registry["generated_at"], "generated_at") <= now < evidence._timestamp(signer_registry["expires_at"], "expires_at"):
        raise trust.TrustError("signer registry is not active")
    regular_raw = fetch(raw_url(commit, regular["object_path"]))
    bundle_raw = fetch(raw_url(commit, bundle["object_path"]))
    value = verify_bytes(regular_raw, regular, "regular object")
    verify_bytes(bundle_raw, bundle, "bundle object")
    return regular_raw, bundle_raw, value


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
    raise trust.TrustError("the admission bundle does not immediately follow its object")


def verify_sigstore(
    regular_raw: bytes, bundle_raw: bytes, *, kind: str, policy: dict[str, Any]
) -> None:
    sigstore = policy["sigstore"]
    version = subprocess.run(
        ["gh", "--version"], check=True, capture_output=True, text=True
    ).stdout.splitlines()[0]
    if version != f"gh version {sigstore['version']} (2026-08-20)":
        raise trust.TrustError(
            f"GitHub CLI version differs; required {sigstore['version']}; got {version}"
        )
    identities = {
        item["kind"]: item for item in sigstore["certificate_identities"]
    }
    identity = identities.get(kind)
    if identity is None:
        raise trust.TrustError(f"no keyless identity is registered for {kind}")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        subject = directory / "subject.json"
        bundle = directory / "bundle.json"
        subject.write_bytes(regular_raw)
        bundle.write_bytes(bundle_raw)
        command = [
            "gh", "attestation", "verify", str(subject), "--bundle", str(bundle),
            "--repo", identity["issuer_repository"], "--cert-identity",
            identity["certificate_identity"], "--cert-oidc-issuer",
            sigstore["cert_oidc_issuer"], "--deny-self-hosted-runners",
            "--no-public-good", "--format", "json",
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise trust.TrustError(
                "Sigstore bundle verification failed: " + result.stderr.strip()
            )
        try:
            statement = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise trust.TrustError("Sigstore verifier output is not JSON") from exc
        if not statement:
            raise trust.TrustError("Sigstore verifier returned no verified statement")


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
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-tag", required=True)
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
        regular_raw, bundle_raw, admission_value = fetch_pair(
            reference, bundle_reference
        )
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        verify_sigstore(
            regular_raw, bundle_raw, kind="qualification-release", policy=policy
        )
        admission = trust.validate_release(
            admission_value, now=datetime.now(timezone.utc)
        )
        release = admission["release"]
        expected = {
            "target": args.expected_target,
            "repository": args.expected_repository,
            "repository_id": args.expected_repository_id,
            "source_commit": args.expected_source_commit,
            "version": args.expected_version,
            "tag": args.expected_tag,
        }
        actual = {
            "target": admission["target"],
            "repository": release["source_repository"],
            "repository_id": release["source_repository_id"],
            "source_commit": release["source_commit"],
            "version": release["version"],
            "tag": release["tag"],
        }
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
        outputs = {
            "admission_object_sha256": reference["object_sha256"],
            "release_sha256": admission["release_sha256"],
            "artifact_inventory_sha256": admission["artifact_inventory_sha256"],
            "publication_staging_json": trust.canonical(
                admission["publication_staging"]
            ).decode("utf-8"),
            "publication_staging_sha256": admission["publication_staging_sha256"],
            "draft_release_id": admission["publication_staging"]["draft_release_id"],
            "expires_at": admission["expires_at"],
            "registry_source_commit": reference["registry_source_commit"],
        }
        if args.github_output:
            with Path(args.github_output).open("a", encoding="utf-8") as handle:
                for key, value in outputs.items():
                    handle.write(f"{key}={value}\n")
        print(json.dumps(outputs, sort_keys=True))
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
