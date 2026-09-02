#!/usr/bin/env python3
"""Build unpublished Flow 1.34.0 remote-safe-synthetic admission objects.

Reads the founder-provisioned Keychain item openadapt-qualification-ed25519.
Does not print the private key. Does not generate a key. Does not write main.

The campaign_summary is synthetic (1 cell x 3 trials per class). It is not the
MockMed 1.34.0 evals set. evals production_acceptance stays false.

Uses publication_mode already-published-pypi: the live GitHub tag exists and
PyPI 1.34.0 files are bound by sha256. Does not fake a draft as
openadapt-release[bot].
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import string
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import production_trust as trust  # noqa: E402
import public_trust_kms as public_trust  # noqa: E402
import qualification_issuer as issuer  # noqa: E402
import qualification_software_ed25519 as software  # noqa: E402
import validate_evidence_registry as evidence  # noqa: E402

EXPECTED_INNER_KEY_ID = "qa-ed25519-9cf4bca214c01d79"
FLOW_VERSION = "1.34.0"
FLOW_TAG = "v1.34.0"
FLOW_SOURCE = "30fc60e55778a0e0f92b9776117cafcfe2512249"
WHEEL_SHA256 = "56d32818989cb3a92830080ead39e10b08718c55e00988117f22cbfeaac98854"
WHEEL_SIZE = 1928194
SDIST_SHA256 = "a941a70015fe91897e655bfc9bf83e6cf8fbcf8bd4e4c7206ffb133c505203f8"
SDIST_SIZE = 20440838
WHEEL_NAME = "openadapt_flow-1.34.0-py3-none-any.whl"
SDIST_NAME = "openadapt_flow-1.34.0.tar.gz"
PYPI_PROJECT = "openadapt-flow"
OPS_COMMIT = "e323249e3a7c1af9d7651312e0afe1f12c38c977"
EVALS_COMMIT = "cad5560d6b7482f2cb99b9735e0ac3c5aae714c8"
SYNTHETIC_DOMAIN = b"OpenAdapt remote-safe-synthetic flow 1.34.0 local candidate v1\0"
EXPECTED_PUBLIC_KEY = "vHPUDLG2WD2BnTLaKYnZd9GxvUKfjpd68gJ9HubIEH8"
KIND_BY_PACKAGETYPE = {
    "sdist": "python-sdist",
    "bdist_wheel": "python-wheel",
}


def campaign_classes() -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for campaign_class in trust.CAMPAIGN_CLASSES:
        counts = {field: 0 for field in trust.CAMPAIGN_COUNT_FIELDS}
        counts.update(
            task_condition_cell_count=1,
            minimum_trials_per_cell=3,
            observed_trial_count=3,
        )
        if campaign_class == "uncertain_delivery":
            counts["reconciliation_required_count"] = 3
        if campaign_class == "declared_attended":
            counts["authenticated_bound_decision_count"] = 3
            counts["live_target_revalidation_count"] = 3
        if campaign_class == "governed_repair":
            counts["policy_approved_repair_count"] = 3
            counts["approved_repair_count"] = 3
            counts["retained_repair_evidence_count"] = 3
            counts["live_target_revalidation_count"] = 3
        result[campaign_class] = counts
    return result


def ts(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SystemExit("timestamp must use UTC")
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def labeled(name: str) -> str:
    return trust.digest_bytes(
        SYNTHETIC_DOMAIN,
        {
            "label": "remote-safe-synthetic",
            "flow_version": FLOW_VERSION,
            "name": name,
            "mockmed_1_34_0_evals_set_is_this_summary": False,
            "evals_production_acceptance": False,
        },
    )


def write_json(path: Path, value: Any) -> bytes:
    raw = evidence.canonical(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def object_rel(kind: str, object_sha256: str) -> str:
    digest_hex = object_sha256.removeprefix("sha256:")
    return (
        f"production-evidence/objects/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.{kind}.json"
    )


def signer_rel(object_sha256: str) -> str:
    digest_hex = object_sha256.removeprefix("sha256:")
    return (
        f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.qualification-signer-registry.json"
    )


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def request_handle() -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "qair_" + "".join(secrets.choice(alphabet) for _ in range(43))


def sign_embedded(
    value: dict[str, Any],
    private_key: Any,
    *,
    schema: str,
    domain: bytes,
) -> None:
    value["signing_statement"] = trust.signing_statement(
        value, object_schema_version=schema, signature_domain=domain
    )
    payload = trust.canonical(value["signing_statement"]) + b"\n"
    value["signature"] = base64.b64encode(private_key.sign(payload)).decode("ascii")


def make_inner(material: dict[str, str]) -> dict[str, Any]:
    signer = software.signer_from_public_material(material)
    signer["allowed_usages"] = sorted(
        {
            "qualification-authority-state-receipt",
            "qualification-evidence-decision-receipt",
            "qualification-revocation-state-receipt",
        }
    )
    signer["allowed_workflows"] = sorted(
        {
            (
                "https://github.com/OpenAdaptAI/.github/.github/workflows/"
                "issue-synthetic-qualification-evidence-decision.yml@refs/heads/main"
            ),
            (
                "https://github.com/OpenAdaptAI/openadapt-ops/.github/workflows/"
                "qualification-authority-state.yml@refs/heads/main"
            ),
            (
                "https://github.com/OpenAdaptAI/openadapt-ops/.github/workflows/"
                "qualification-revocation-state.yml@refs/heads/main"
            ),
        }
    )
    return signer


def make_entry(kind: str, raw: bytes, value: Any) -> dict[str, Any]:
    object_sha256 = sha256_bytes(raw)
    schema, media = evidence.OBJECT_KIND_CONTRACTS[kind]
    entry = {
        "kind": kind,
        "object_schema_version": (
            evidence.BUNDLE_MEDIA_TYPE if kind.endswith("-sigstore-bundle") else schema
        ),
        "object_path": object_rel(kind, object_sha256),
        "object_sha256": object_sha256,
        "size_bytes": len(raw),
        "object_media_type": media,
        "semantic_identity_sha256": evidence.semantic_identity_digest(
            kind=kind,
            object_schema_version=(
                evidence.BUNDLE_MEDIA_TYPE
                if kind.endswith("-sigstore-bundle")
                else schema
            ),
            object_value=value,
            object_sha256=object_sha256,
        ),
        "subject_sha256": None if not kind.endswith("-sigstore-bundle") else value,
    }
    entry["registry_entry_sha256"] = evidence.entry_digest(entry)
    return entry


def reference_from_entry(
    entry: dict[str, Any],
    *,
    registry_source_commit: str,
    registry_revision: int,
    registry_head_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": registry_source_commit,
        "registry_revision": registry_revision,
        "registry_head_sha256": registry_head_sha256,
        **entry,
    }


class LocalResolver:
    def __init__(self, registry: dict[str, Any]) -> None:
        self.registry = registry
        self.objects: dict[str, issuer.ResolvedEvidence] = {}
        self.authority: issuer.ResolvedEvidence | None = None
        self.revocation: issuer.ResolvedEvidence | None = None

    def add(
        self,
        kind: str,
        value: dict[str, Any],
        reference: dict[str, Any],
        bundle_reference: dict[str, Any],
    ) -> issuer.ResolvedEvidence:
        resolved: issuer.ResolvedEvidence = {
            "value": value,
            "reference": reference,
            "bundle_reference": bundle_reference,
            "bound_signer_registry": self.registry,
            "current_signer_registry": self.registry,
        }
        self.objects[reference["object_sha256"]] = resolved
        return resolved

    def resolve(self, reference: dict[str, Any], *, kind: str) -> issuer.ResolvedEvidence:
        resolved = self.objects[reference["object_sha256"]]
        if resolved["reference"] != reference or reference["kind"] != kind:
            raise issuer.IssuerError("local resolver reference differs")
        return resolved

    def current_trust_state(
        self, *, registry_source_commit: str
    ) -> tuple[issuer.ResolvedEvidence, issuer.ResolvedEvidence]:
        if self.authority is None or self.revocation is None:
            raise issuer.IssuerError("current authority or revocation receipt is absent")
        return self.authority, self.revocation


def dsse_bundle(
    *,
    private_key: Any,
    signer: dict[str, Any],
    kind: str,
    value: dict[str, Any],
    raw: bytes,
    now: datetime,
    registry_sha256: str,
    authority_state_sha256: str,
    revocation_state_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    schema, media = evidence.OBJECT_KIND_CONTRACTS[kind]
    semantic = evidence.semantic_identity_digest(
        kind=kind,
        object_schema_version=schema,
        object_value=value,
        object_sha256=sha256_bytes(raw),
    )
    issuer_fields = {
        field: value["issuer"][field] for field in public_trust.ISSUER_FIELDS
    }
    statement = {
        "schema_version": public_trust.STATEMENT_SCHEMA,
        "object_kind": kind,
        "object_schema_version": schema,
        "object_media_type": media,
        "object_sha256": sha256_bytes(raw),
        "object_size_bytes": len(raw),
        "semantic_identity_sha256": semantic,
        "source_issuer": issuer_fields,
        "signer_registry_sha256": registry_sha256,
        "authority_state_sha256": authority_state_sha256,
        "revocation_state_sha256": revocation_state_sha256,
        "issued_at": ts(now),
        "not_before": ts(now),
        "expires_at": None,
        "request_id_sha256": labeled(f"dsse-request:{kind}"),
        "signing_authority": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": public_trust.SOFTWARE_WORKFLOW_PATH,
            "ref": "refs/heads/main",
            "source_commit": source_commit,
            "environment": public_trust.SOFTWARE_ENVIRONMENT,
            "key_origin": "software",
        },
        "key_id": signer["key_id"],
        "signature_profile": public_trust.SOFTWARE_SIGNATURE_PROFILE,
    }
    public_trust.validate_statement_object_binding(
        statement,
        object_raw=raw,
        object_value=value,
        object_kind=kind,
        object_schema_version=schema,
        object_media_type=media,
        semantic_identity_sha256=semantic,
        expected_signer_registry_sha256=registry_sha256,
        expected_authority_state_sha256=authority_state_sha256,
        expected_revocation_state_sha256=revocation_state_sha256,
    )
    return public_trust.sign_software_bundle(
        statement, private_key=private_key, signer=signer, now=now
    )


def persist_object(
    out: Path, kind: str, value: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    raw = evidence.canonical(value) + b"\n"
    path = out / object_rel(kind, sha256_bytes(raw))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    write_json(out / f"{kind}.json", value)
    return raw, make_entry(kind, raw, value)


def persist_bundle(
    out: Path, kind: str, bundle: dict[str, Any], subject_sha256: str
) -> tuple[bytes, dict[str, Any]]:
    raw = evidence.canonical(bundle) + b"\n"
    bundle_kind = f"{kind}-sigstore-bundle"
    path = out / object_rel(bundle_kind, sha256_bytes(raw))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    write_json(out / f"{bundle_kind}.json", bundle)
    return raw, make_entry(bundle_kind, raw, subject_sha256)


def flow_rulesets() -> list[dict[str, Any]]:
    common = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    }
    return [
        {
            **common,
            "role": "creation_authority",
            "ruleset_id": "10",
            "name": "OpenAdapt policy: release tag creation",
            "bypass_actors": [
                {
                    "actor_id": "4730708",
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ],
            "rules": [{"type": "creation"}],
        },
        {
            **common,
            "role": "immutability",
            "ruleset_id": "11",
            "name": "OpenAdapt policy: immutable release tags",
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                },
            ],
        },
    ]


def fetch_pypi_files(project: str, version: str) -> list[dict[str, Any]]:
    url = f"https://pypi.org/pypi/{project}/{version}/json"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "OpenAdapt-flow-134-local-candidate/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    files: list[dict[str, Any]] = []
    for item in payload["urls"]:
        files.append(
            {
                "filename": item["filename"],
                "packagetype": item["packagetype"],
                "sha256": "sha256:" + item["digests"]["sha256"],
                "size_bytes": item["size"],
                "yanked": item["yanked"],
            }
        )
    return sorted(files, key=lambda item: (item["filename"], item["sha256"]))


def fetch_github_release(tag: str) -> dict[str, Any]:
    raw = subprocess.check_output(
        ["gh", "api", f"repos/OpenAdaptAI/openadapt-flow/releases/tags/{tag}"],
        text=True,
    )
    return json.loads(raw)


def observe_already_published_pypi_staging(*, observed_at: datetime) -> dict[str, Any]:
    pypi_files = fetch_pypi_files(PYPI_PROJECT, FLOW_VERSION)
    release = fetch_github_release(FLOW_TAG)
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise SystemExit("live GitHub release v1.34.0 is still a draft or prerelease")
    author = release.get("author") or {}
    if author.get("login") != "openadapt-release[bot]" or str(author.get("id")) != "321543906":
        raise SystemExit("live GitHub release author is not the release App")
    expected_pypi = {
        WHEEL_NAME: ("sha256:" + WHEEL_SHA256, WHEEL_SIZE, "bdist_wheel"),
        SDIST_NAME: ("sha256:" + SDIST_SHA256, SDIST_SIZE, "sdist"),
    }
    if {item["filename"] for item in pypi_files} != set(expected_pypi):
        raise SystemExit("live PyPI files for 1.34.0 differ from the bound names")
    for item in pypi_files:
        digest, size, packagetype = expected_pypi[item["filename"]]
        if (
            item["sha256"] != digest
            or item["size_bytes"] != size
            or item["packagetype"] != packagetype
            or item["yanked"] is not False
        ):
            raise SystemExit(
                f"live PyPI file {item['filename']} differs from the bound artifact"
            )
    profile = trust.TARGET_CONTRACTS["flow"]["artifacts"]
    assets: list[dict[str, Any]] = []
    for asset in release["assets"]:
        name = asset["name"]
        kind = KIND_BY_PACKAGETYPE.get(
            expected_pypi[name][2] if name in expected_pypi else ""
        )
        if kind is None:
            raise SystemExit(f"live GitHub asset {name} is not a flow package file")
        media_type, destinations = profile[kind]
        digest = asset.get("digest") or expected_pypi[name][0]
        if digest != expected_pypi[name][0] or asset["size"] != expected_pypi[name][1]:
            raise SystemExit(f"live GitHub asset {name} digest or size differs from PyPI")
        uploader = asset.get("uploader") or {}
        assets.append(
            {
                "asset_id": str(asset["id"]),
                "name": name,
                "kind": kind,
                "sha256": digest,
                "size_bytes": asset["size"],
                "media_type": media_type,
                "publish_destinations": list(destinations),
                "uploader_id": str(uploader.get("id")),
                "uploader_login": uploader.get("login"),
            }
        )
    assets = sorted(assets, key=lambda item: (item["name"], item["asset_id"]))
    immutable = {"enabled": True, "enforced_by_owner": False}
    rulesets = flow_rulesets()
    tag_ref_state = {"ref": f"refs/tags/{FLOW_TAG}", "exists": True}
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "publication_mode": trust.PUBLICATION_MODE_ALREADY_PUBLISHED_PYPI,
        "repository": "OpenAdaptAI/openadapt-flow",
        "repository_id": "1291376938",
        "draft_release_id": str(release["id"]),
        "tag": FLOW_TAG,
        "target_commitish": FLOW_SOURCE,
        "draft": False,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": "openadapt-release[bot]",
        "assets": assets,
        "pypi_files": pypi_files,
        "immutable_releases": immutable,
        "immutable_releases_sha256": trust.digest_bytes(
            trust.IMMUTABLE_RELEASES_DOMAIN, immutable
        ),
        "tag_rulesets": rulesets,
        "tag_rulesets_sha256": trust.digest_bytes(trust.TAG_RULESETS_DOMAIN, rulesets),
        "tag_ref_state": tag_ref_state,
        "tag_ref_state_sha256": trust.digest_bytes(
            trust.TAG_REF_STATE_DOMAIN, tag_ref_state
        ),
        "observed_at": ts(observed_at),
    }
    return trust.validate_staging(staging)


def unsigned_inventory() -> dict[str, Any]:
    artifacts = [
        {
            "name": SDIST_NAME,
            "kind": "python-sdist",
            "sha256": "sha256:" + SDIST_SHA256,
            "size_bytes": SDIST_SIZE,
            "media_type": "application/gzip",
            "publish_destinations": ["github-release", "pypi"],
        },
        {
            "name": WHEEL_NAME,
            "kind": "python-wheel",
            "sha256": "sha256:" + WHEEL_SHA256,
            "size_bytes": WHEEL_SIZE,
            "media_type": "application/zip",
            "publish_destinations": ["github-release", "pypi"],
        },
    ]
    artifacts = sorted(
        artifacts, key=lambda item: (item["kind"], item["name"], item["sha256"])
    )
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": "flow",
        "claim_scope": "production_flow",
        "artifacts": artifacts,
    }
    return trust.validate_artifact_inventory(inventory)


def policy_file_digest(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def build_receipts(
    out: Path, *, private_key: Any, now: datetime, policy_commit: str
) -> dict[str, Any]:
    material = software.public_material(private_key)
    if material["key_id"] != EXPECTED_INNER_KEY_ID:
        raise SystemExit(
            f"Keychain public key id is {material['key_id']}, not {EXPECTED_INNER_KEY_ID}"
        )
    if material["public_key"] != EXPECTED_PUBLIC_KEY:
        raise SystemExit("Keychain public key does not match the provisioned inner key")
    write_json(out / "public-material.json", material)

    inner = make_inner(material)
    outer = public_trust.software_public_signer(private_key.public_key())
    generated = now.replace(microsecond=0)

    unsigned_local = software.unsigned_local_registry_candidate(
        public_material_value=material, revision=1
    )
    local_candidate = software.verify_local_registry_candidate(
        software.sign_local_registry_candidate(unsigned_local, private_key=private_key)
    )
    write_json(out / "signer-registry-local-candidate.json", local_candidate)

    timed_candidate = software.signer_registry_candidate(
        public_material_value=material,
        revision=1,
        generated_at=generated,
        expires_at=None,
    )
    timed_candidate["proposed_registry"]["signers"] = [inner, outer]
    timed_candidate["proposed_registry"] = evidence.validate_signer_registry(
        timed_candidate["proposed_registry"]
    )
    write_json(out / "signer-registry-candidate.json", timed_candidate)

    registry = {
        "schema_version": "openadapt.qualification-signer-registry/v2",
        "revision": 1,
        "generated_at": ts(generated),
        "expires_at": None,
        "signers": [inner, outer],
    }
    registry = evidence.validate_signer_registry(registry)
    registry_raw = write_json(out / "signer-registry.json", registry)
    registry_raw_sha256 = sha256_bytes(registry_raw)
    registry_identity = evidence.signer_registry_identity_digest(registry)
    signer_path = out / signer_rel(registry_raw_sha256)
    signer_path.parent.mkdir(parents=True, exist_ok=True)
    signer_path.write_bytes(registry_raw)

    evidence_authority = labeled("evidence-authority")
    authority = {
        "schema_version": "openadapt.qualification-authority-state-receipt/v2",
        "authority_state_sha256": labeled("placeholder-authority"),
        "status": "active",
        "signer_registry_sha256": registry_raw_sha256,
        "signer_registry_identity_sha256": registry_identity,
        "signer_registry_revision": 1,
        "evidence_authority_sha256": evidence_authority,
        "observed_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": None,
        "issuer_key_id": inner["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-authority-state.yml",
            "ref": "refs/heads/main",
            "source_commit": OPS_COMMIT,
            "environment": "qualification-authority-state",
        },
    }
    projection = dict(authority)
    projection.pop("authority_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    authority["authority_state_sha256"] = trust.digest_bytes(
        trust.AUTHORITY_STATE_IDENTITY_DOMAIN, projection
    )
    sign_embedded(
        authority,
        private_key,
        schema="openadapt.qualification-authority-state-receipt/v2",
        domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
    )
    trust.validate_authority_state(authority, now=now)
    trust.verify_embedded_signature(
        authority,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-authority-state-receipt/v2",
        signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
        usage="qualification-authority-state-receipt",
        now=now,
    )

    revocation = {
        "schema_version": "openadapt.qualification-revocation-state-receipt/v1",
        "revocation_state_sha256": labeled("placeholder-revocation"),
        "previous_revocation_state_sha256": None,
        "revision": 1,
        "status": "current",
        "authority_state_sha256": authority["authority_state_sha256"],
        "signer_registry_sha256": registry_identity,
        "revocations": [],
        "observed_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": None,
        "issuer_key_id": inner["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-ops",
            "repository_id": "1172011294",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/qualification-revocation-state.yml",
            "ref": "refs/heads/main",
            "source_commit": OPS_COMMIT,
            "environment": "qualification-revocation-state",
        },
    }
    projection = dict(revocation)
    projection.pop("revocation_state_sha256")
    projection.pop("signature")
    projection.pop("signing_statement")
    revocation["revocation_state_sha256"] = trust.digest_bytes(
        trust.REVOCATION_STATE_IDENTITY_DOMAIN, projection
    )
    sign_embedded(
        revocation,
        private_key,
        schema="openadapt.qualification-revocation-state-receipt/v1",
        domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
    )
    trust.validate_revocation_state(revocation, now=now)
    trust.verify_embedded_signature(
        revocation,
        signer_registry=registry,
        object_schema_version="openadapt.qualification-revocation-state-receipt/v1",
        signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
        usage="qualification-revocation-state-receipt",
        now=now,
    )

    summary = {
        "schema_version": "openadapt.qualification-evidence-decision-campaign-summary/v1",
        "minimum_trials_per_task_condition": 3,
        "task_count": 1,
        "classes": campaign_classes(),
    }
    unsigned_receipt = {
        "schema_version": "openadapt.qualification-evidence-decision-receipt/v2",
        "evidence_class": "remote-safe-synthetic",
        "decision_identity_sha256": labeled("decision-series"),
        "decision_revision": 1,
        "decision_commitment_sha256": labeled("decision"),
        "evidence_manifest_sha256": labeled("evidence-manifest"),
        "evidence_manifest_readback_sha256": labeled("manifest-readback"),
        "campaign_artifact_sha256": labeled("campaign-artifact"),
        "organization_id_sha256": labeled("organization"),
        "workflow_id_sha256": labeled("workflow"),
        "workflow_version_id_sha256": labeled("workflow-version"),
        "bundle_version": "0.0.0-synthetic",
        "bundle_sha256": labeled("sealed-workflow-bundle"),
        "admitted_runtime_sha256": "sha256:" + WHEEL_SHA256,
        "application_contract_sha256": labeled("application-contract"),
        "environment_contract_sha256": labeled("environment-contract"),
        "input_contract_sha256": labeled("input-contract"),
        "action_contract_sha256": labeled("action-contract"),
        "identity_contract_sha256": labeled("identity-contract"),
        "effect_contract_sha256": labeled("effect-contract"),
        "policy_contract_sha256": labeled("policy-contract"),
        "evidence_authority_contract_sha256": evidence_authority,
        "campaign_permit_sha256": labeled("campaign-permit"),
        "signer_registry_sha256": registry_identity,
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "entity_class": "record",
        "campaign_summary": summary,
        "verdict": "ADMIT",
        "issued_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": None,
        "issuer_key_id": inner["key_id"],
        "algorithm": "ed25519",
        "signing_statement": None,
        "signature": "",
        "issuer": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": (
                ".github/workflows/issue-synthetic-qualification-evidence-decision.yml"
            ),
            "ref": "refs/heads/main",
            "source_commit": policy_commit,
            "environment": "synthetic-qualification-evidence-decision",
        },
    }
    receipt = software.sign_receipt(
        unsigned_receipt, private_key=private_key, signer_registry=registry
    )
    trust.validate_receipt(receipt, signer_registry=registry, now=now)

    inventory = unsigned_inventory()
    write_json(out / "artifact-inventory.json", inventory)

    objects: dict[str, tuple[str, dict[str, Any], bytes]] = {}
    for kind, value in (
        ("qualification-authority-state-receipt", authority),
        ("qualification-revocation-state-receipt", revocation),
        ("qualification-evidence-decision-receipt", receipt),
    ):
        raw = evidence.canonical(value) + b"\n"
        objects[kind] = (kind, value, raw)

    bundles: dict[str, dict[str, Any]] = {}
    for kind, value, raw in objects.values():
        bundles[kind] = dsse_bundle(
            private_key=private_key,
            signer=outer,
            kind=kind,
            value=value,
            raw=raw,
            now=generated,
            registry_sha256=value["signer_registry_sha256"],
            authority_state_sha256=authority["authority_state_sha256"],
            revocation_state_sha256=revocation["revocation_state_sha256"],
            source_commit=policy_commit,
        )

    entries: list[dict[str, Any]] = []
    for kind, value, raw in objects.values():
        path = out / object_rel(kind, sha256_bytes(raw))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        write_json(out / f"{kind}.json", value)
        regular_entry = make_entry(kind, raw, value)
        bundle = bundles[kind]
        bundle_raw = evidence.canonical(bundle) + b"\n"
        bundle_kind = f"{kind}-sigstore-bundle"
        bundle_path = out / object_rel(bundle_kind, sha256_bytes(bundle_raw))
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(bundle_raw)
        write_json(out / f"{bundle_kind}.json", bundle)
        bundle_entry = make_entry(bundle_kind, bundle_raw, sha256_bytes(raw))
        entries.append(regular_entry)
        entries.append(bundle_entry)

    signer_pointer = {
        "schema_version": evidence.SIGNER_POINTER_SCHEMA,
        "object_path": signer_rel(registry_raw_sha256),
        "object_sha256": registry_raw_sha256,
        "registry_identity_sha256": registry_identity,
        "registry_revision": 1,
    }
    local_registry = {
        "$schema": "schemas/evidence-registry.schema.json",
        "schema_version": evidence.REGISTRY_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "revision": 1,
        "previous_registry_head_sha256": None,
        "registry_head_sha256": "sha256:" + "0" * 64,
        "signer_registry": signer_pointer,
        "signer_registry_history": [signer_pointer],
        "entries": entries,
    }
    local_registry["registry_head_sha256"] = evidence.registry_head_digest(local_registry)
    evidence.validate_registry(local_registry, root=out)
    write_json(out / "evidence-registry.json", local_registry)

    state = {
        "generated_at": ts(generated),
        "expires_at": None,
        "registry_raw_sha256": registry_raw_sha256,
        "registry_identity": registry_identity,
        "registry_head_sha256": local_registry["registry_head_sha256"],
        "registry_revision": 1,
        "authority_state_sha256": authority["authority_state_sha256"],
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "inner_key_id": inner["key_id"],
        "outer_key_id": outer["key_id"],
        "campaign_label": "remote-safe-synthetic",
        "mockmed_1_34_0_evals_set_is_this_summary": False,
        "evals_production_acceptance": False,
        "policy_commit": policy_commit,
        "flow_source": FLOW_SOURCE,
        "wheel_sha256": WHEEL_SHA256,
        "sdist_sha256": SDIST_SHA256,
    }
    write_json(out / "phase1-state.json", state)
    return state


def build_admissions(
    out: Path,
    *,
    private_key: Any,
    now: datetime,
    registry_source_commit: str,
    policy_commit: str,
) -> dict[str, Any]:
    state = json.loads((out / "phase1-state.json").read_text(encoding="utf-8"))
    registry = json.loads((out / "signer-registry.json").read_text(encoding="utf-8"))
    authority = json.loads(
        (out / "qualification-authority-state-receipt.json").read_text(encoding="utf-8")
    )
    revocation = json.loads(
        (out / "qualification-revocation-state-receipt.json").read_text(encoding="utf-8")
    )
    receipt = json.loads(
        (out / "qualification-evidence-decision-receipt.json").read_text(encoding="utf-8")
    )
    local_registry = json.loads((out / "evidence-registry.json").read_text(encoding="utf-8"))
    inventory = json.loads((out / "artifact-inventory.json").read_text(encoding="utf-8"))
    head = local_registry["registry_head_sha256"]
    revision = local_registry["revision"]
    entries_by_kind = {entry["kind"]: entry for entry in local_registry["entries"]}
    generated = now.replace(microsecond=0)
    outer = public_trust.software_public_signer(private_key.public_key())

    resolver = LocalResolver(registry)
    resolver.authority = resolver.add(
        "qualification-authority-state-receipt",
        authority,
        reference_from_entry(
            entries_by_kind["qualification-authority-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            entries_by_kind["qualification-authority-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    resolver.revocation = resolver.add(
        "qualification-revocation-state-receipt",
        revocation,
        reference_from_entry(
            entries_by_kind["qualification-revocation-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            entries_by_kind["qualification-revocation-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    receipt_ref = reference_from_entry(
        entries_by_kind["qualification-evidence-decision-receipt"],
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    receipt_bundle_ref = reference_from_entry(
        entries_by_kind["qualification-evidence-decision-receipt-sigstore-bundle"],
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    resolver.add(
        "qualification-evidence-decision-receipt",
        receipt,
        receipt_ref,
        receipt_bundle_ref,
    )

    handle = request_handle()
    request = {
        "schema_version": "openadapt.qualification-admission-issue-request/v1",
        "request_handle": handle,
        "evidence_class": "remote-safe-synthetic",
        "decision_receipt_reference": receipt_ref,
    }
    db_path = out / "one-use-effects.sqlite"
    if db_path.exists():
        db_path.unlink()
    consumer = issuer.SqliteOneUseConsumer(db_path)
    admission = issuer.issue_workflow_admission(
        request,
        resolver=resolver,
        issuer_source_commit=registry_source_commit,
        now=now,
        consumer=consumer,
    )
    trust.validate_qualification_admission(admission, now=now)
    effect = consumer.reconcile(request_handle=handle)
    write_json(out / "workflow-issue-request.json", request)
    write_json(out / "one-use-effect.json", effect)
    admission_raw, admission_entry = persist_object(
        out, "qualification-admission", admission
    )
    admission_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="qualification-admission",
        value=admission,
        raw=admission_raw,
        now=generated,
        registry_sha256=admission["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=policy_commit,
    )
    _, admission_bundle_entry = persist_bundle(
        out, "qualification-admission", admission_bundle, sha256_bytes(admission_raw)
    )
    admission_ref = reference_from_entry(
        admission_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    admission_bundle_ref = reference_from_entry(
        admission_bundle_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    resolver.add(
        "qualification-admission", admission, admission_ref, admission_bundle_ref
    )

    staging = observe_already_published_pypi_staging(observed_at=generated)
    write_json(out / "publication-staging.json", staging)
    candidate = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-flow",
        "source_repository_id": "1291376938",
        "source_commit": FLOW_SOURCE,
        "version": FLOW_VERSION,
        "tag": FLOW_TAG,
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": inventory["artifacts"],
    }
    release_identity = {
        "schema_version": "openadapt.monotonic-production-release/v1",
        "channel": "production",
        "sequence": 1,
        "previous_admission_sha256": None,
    }
    release_sha256 = trust.digest_bytes(
        trust.RELEASE_DOMAIN,
        {"target": "flow", "claim_scope": "production_flow", "release": candidate},
    )
    inventory_sha256 = trust.artifact_inventory_digest(inventory)
    acceptance_policy_sha256 = policy_file_digest(ROOT / "production-evidence-policy.json")
    lifecycle_policy_sha256 = policy_file_digest(ROOT / "production-lifecycle-policy.json")
    common = {
        "target": "flow",
        "verdict": "accepted",
        "claim_scope": "production_flow",
        "acceptance_policy_sha256": acceptance_policy_sha256,
        "lifecycle_policy_sha256": lifecycle_policy_sha256,
        "release_identity": release_identity,
        "release_sha256": release_sha256,
        "artifact_inventory_sha256": inventory_sha256,
        "publication_staging": staging,
        "publication_staging_sha256": trust.staging_digest(staging),
        "qualification_evidence_decision_receipt_reference": receipt_ref,
        "qualification_evidence_decision_receipt_bundle_reference": receipt_bundle_ref,
        "qualification_admission_reference": admission_ref,
        "qualification_admission_bundle_reference": admission_bundle_ref,
        "campaign_summary": receipt["campaign_summary"]["classes"],
        "authority_state_sha256": authority["authority_state_sha256"],
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "signer_registry_sha256": evidence.signer_registry_identity_digest(registry),
        "issued_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": None,
        "issuer": {
            "repository": "OpenAdaptAI/openadapt-evals",
            "repository_id": "1135998197",
            "repository_owner_id": "132681217",
            "workflow": ".github/workflows/issue-production-acceptance.yml",
            "ref": "refs/heads/main",
            "source_commit": EVALS_COMMIT,
            "environment": "production-acceptance",
        },
    }
    manifest = {
        "schema_version": "openadapt.production-acceptance/v3",
        **common,
        "release": candidate,
        "artifact_inventory": inventory,
    }
    trust.validate_acceptance_manifest(
        manifest,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=registry,
        now=now,
    )
    manifest_raw, manifest_entry = persist_object(
        out, "production-acceptance-manifest", manifest
    )
    manifest_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="production-acceptance-manifest",
        value=manifest,
        raw=manifest_raw,
        now=generated,
        registry_sha256=manifest["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=policy_commit,
    )
    _, manifest_bundle_entry = persist_bundle(
        out,
        "production-acceptance-manifest",
        manifest_bundle,
        sha256_bytes(manifest_raw),
    )
    manifest_ref = reference_from_entry(
        manifest_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    manifest_bundle_ref = reference_from_entry(
        manifest_bundle_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    resolver.add(
        "production-acceptance-manifest",
        manifest,
        manifest_ref,
        manifest_bundle_ref,
    )

    summary = {
        "schema_version": "openadapt.production-lifecycle-evidence-summary/v3",
        **common,
        "evidence_identity_sha256": labeled("placeholder-evidence-identity"),
        "production_acceptance_manifest_reference": manifest_ref,
        "production_acceptance_manifest_bundle_reference": manifest_bundle_ref,
    }
    summary["evidence_identity_sha256"] = trust.acceptance_summary_identity(summary)
    trust.validate_acceptance_summary(
        summary,
        manifest=manifest,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=registry,
        now=now,
    )
    summary_raw, summary_entry = persist_object(
        out, "production-acceptance-summary", summary
    )
    summary_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="production-acceptance-summary",
        value=summary,
        raw=summary_raw,
        now=generated,
        registry_sha256=summary["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=policy_commit,
    )
    _, summary_bundle_entry = persist_bundle(
        out,
        "production-acceptance-summary",
        summary_bundle,
        sha256_bytes(summary_raw),
    )
    summary_ref = reference_from_entry(
        summary_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    summary_bundle_ref = reference_from_entry(
        summary_bundle_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    resolver.add(
        "production-acceptance-summary", summary, summary_ref, summary_bundle_ref
    )

    release_handle = request_handle()
    release_request = {
        "schema_version": "openadapt.qualification-release-issue-request/v1",
        "request_handle": release_handle,
        "evidence_class": "remote-safe-synthetic",
        "production_acceptance_summary_reference": summary_ref,
    }
    release = issuer.issue_release_admission(
        release_request,
        resolver=resolver,
        issuer_source_commit=registry_source_commit,
        now=now,
        consumer=consumer,
    )
    trust.validate_release_evidence_chain(
        release,
        summary=summary,
        manifest=manifest,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=registry,
        now=now,
    )
    write_json(out / "release-issue-request.json", release_request)
    release_raw, _release_entry = persist_object(out, "qualification-release", release)
    release_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="qualification-release",
        value=release,
        raw=release_raw,
        now=generated,
        registry_sha256=release["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=policy_commit,
    )
    persist_bundle(
        out, "qualification-release", release_bundle, sha256_bytes(release_raw)
    )
    write_json(
        out / "one-use-effect-release.json",
        consumer.reconcile(request_handle=release_handle),
    )
    return {
        "workflow_admission_id_sha256": admission["admission_id_sha256"],
        "release_admission_id_sha256": release["admission_id_sha256"],
        "release_sha256": release["release_sha256"],
        "publication_staging_sha256": release["publication_staging_sha256"],
        "publication_mode": staging["publication_mode"],
        "draft": staging["draft"],
        "tag_exists": staging["tag_ref_state"]["exists"],
        "github_release_id": staging["draft_release_id"],
        "pypi_files": staging["pypi_files"],
        "expires_at": release["expires_at"],
        "registry_source_commit": registry_source_commit,
        "evals_production_acceptance": False,
        "mockmed_1_34_0_evals_set_is_this_summary": False,
        **state,
    }


def write_build_record(out: Path, extra: dict[str, Any]) -> None:
    state_path = out / "phase1-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    record = {
        "schema_version": "openadapt.local-flow-134-admission-build-record/v1",
        "target": "flow",
        "flow_version": FLOW_VERSION,
        "flow_tag": FLOW_TAG,
        "flow_source": FLOW_SOURCE,
        "evidence_class": "remote-safe-synthetic",
        "campaign": {
            "label": "remote-safe-synthetic",
            "task_count": 1,
            "cells_per_class": 1,
            "trials_per_cell": 3,
            "classes": list(trust.CAMPAIGN_CLASSES),
            "mockmed_1_34_0_evals_set_is_this_summary": False,
        },
        "evals_production_acceptance": False,
        "keychain_service": software.KEYCHAIN_SERVICE,
        "inner_key_id": EXPECTED_INNER_KEY_ID,
        "did_not_generate_key": True,
        "did_not_fake_draft_as_openadapt_release_bot": True,
        **state,
        **extra,
    }
    write_json(out / "build-record.json", record)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(HERE))
    parser.add_argument("--policy-commit", required=True)
    parser.add_argument("--registry-source-commit", required=True)
    args = parser.parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    private_key = software.load_private_key_from_sources(
        pem_file=None, use_keychain=True, use_env=False
    )
    material = software.public_material(private_key)
    if material["key_id"] != EXPECTED_INNER_KEY_ID:
        print(
            f"REFUSED: Keychain key id {material['key_id']} != {EXPECTED_INNER_KEY_ID}",
            file=sys.stderr,
        )
        return 1
    build_receipts(
        out,
        private_key=private_key,
        now=now,
        policy_commit=args.policy_commit,
    )
    try:
        extra = build_admissions(
            out,
            private_key=private_key,
            now=now,
            registry_source_commit=args.registry_source_commit,
            policy_commit=args.policy_commit,
        )
    except trust.TrustError as exc:
        write_build_record(
            out,
            {
                "phase": "staging-blocked",
                "release_admission_issued": False,
                "validate_staging_error": str(exc),
            },
        )
        print(json.dumps({"phase": "staging-blocked", "error": str(exc)}, sort_keys=True))
        return 1
    write_build_record(
        out,
        {
            "phase": "release-admission",
            "release_admission_issued": True,
            "acceptance_manifest_issued": True,
            "acceptance_summary_issued": True,
            **extra,
        },
    )
    print(
        json.dumps(
            {
                "phase": "release-admission",
                "publication_mode": extra["publication_mode"],
                "tag_exists": extra["tag_exists"],
                "draft": extra["draft"],
                "release_admission_id_sha256": extra["release_admission_id_sha256"],
                "expires_at": extra["expires_at"],
                "evals_production_acceptance": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
