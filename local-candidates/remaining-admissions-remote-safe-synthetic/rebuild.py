#!/usr/bin/env python3
"""Issue remaining remote-safe-synthetic Production admissions.

Reads the founder-provisioned Keychain item openadapt-qualification-ed25519.
Does not print the private key. Does not generate a key. Does not replace
the Flow 1.34.0 signer registry.

The campaign_summary is synthetic (1 cell x 3 trials per class). It is not
MockMed production_acceptance.

Package targets use already-published-pypi and bind live PyPI sha256s.
Cloud and docs use already-published-deployment and bind the live SHA and URL.
"""

from __future__ import annotations

import argparse
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
EXPECTED_PUBLIC_KEY = "vHPUDLG2WD2BnTLaKYnZd9GxvUKfjpd68gJ9HubIEH8"
EVALS_COMMIT = "cad5560d6b7482f2cb99b9735e0ac3c5aae714c8"
SIGNER_PATH = (
    ROOT
    / "production-evidence/signer-registries/sha256/7a/"
    "7a81bf3d213c74673f3c6b5fa179234cbee534c9432aaea6ae09e455562f96b6"
    ".qualification-signer-registry.json"
)
AUTHORITY_PATH = (
    ROOT
    / "production-evidence/objects/sha256/a2/"
    "a22f9815ec0f7c56f7629aeabfd21d14bc6d739efcfb7f7a073ce9987e19479e"
    ".qualification-authority-state-receipt.json"
)
REVOCATION_PATH = (
    ROOT
    / "production-evidence/objects/sha256/18/"
    "18633b8cc243f686706606162bfa249a29733811563f63b9e68cc7c4a3507676"
    ".qualification-revocation-state-receipt.json"
)
KIND_BY_PACKAGETYPE = {
    "sdist": "python-sdist",
    "bdist_wheel": "python-wheel",
}
PACKAGE_TARGETS = {
    "openadapt": {
        "version": "1.16.0",
        "pypi_project": "openadapt",
        "wheel_name": "openadapt-1.16.0-py3-none-any.whl",
        "wheel_sha256": "371693e7607d1cdc1ea360ef5d657c1af791a0af39677fa2ce5933e7ba712719",
        "wheel_size": 22539,
        "sdist_name": "openadapt-1.16.0.tar.gz",
        "sdist_sha256": "39d01612417dff5981b536b324a63498df1ea6f0128c723276609ebbe18d9a18",
        "sdist_size": 47028,
        "source_commit": "089c27c046f5cd972d299361f9d68285c1896c71",
    },
    "capture": {
        "version": "1.2.2",
        "pypi_project": "openadapt-capture",
        "wheel_name": "openadapt_capture-1.2.2-py3-none-any.whl",
        "wheel_sha256": "550fffe50990fa8431d332bdd5fe4755976d83baa7ad62553f50ad9e4ddcd1ae",
        "wheel_size": 202545,
        "sdist_name": "openadapt_capture-1.2.2.tar.gz",
        "sdist_sha256": "6f4298d3daadf9cced8994207e34b3116a79209ef792e98f778a0770e2f3406c",
        "sdist_size": 974499,
        "source_commit": "06ade22948c12dcc6608bd54b5cca5c9c306e77c",
    },
    "desktop": {
        "version": "0.16.0",
        "pypi_project": "openadapt-desktop",
        "wheel_name": "openadapt_desktop-0.16.0-py3-none-any.whl",
        "wheel_sha256": "06e608a934deef56c93ee1ca8de511d6daba08459626e8245bd0db4c391e64e9",
        "wheel_size": 293557,
        "sdist_name": "openadapt_desktop-0.16.0.tar.gz",
        "sdist_sha256": "15f0c59a4d481328da76f3e5aa6a29ab8cdced8ab183c97346d69b4c14c996ff",
        "sdist_size": 1461442,
        "source_commit": "7c59750d37be09a2871cd1bada8cb0bce946d363",
    },
    "agent": {
        "version": "2.0.1",
        "pypi_project": "openadapt-agent",
        "wheel_name": "openadapt_agent-2.0.1-py3-none-any.whl",
        "wheel_sha256": "5c5f6e3eca4c127d87b3affb8944223c0836916e0df57d0c6b8ba737b3bc8b5a",
        "wheel_size": 34183,
        "sdist_name": "openadapt_agent-2.0.1.tar.gz",
        "sdist_sha256": "67e05b299a4f035a0482b3032decc151fafc22de9a12bb3d8f884f37ea4cc937",
        "sdist_size": 61814,
        "source_commit": "d9f16b2946dfdd0228eeb2660047347df9dce8d8",
    },
}
DEPLOYMENT_TARGETS = {
    "cloud": {
        "deployment_id": "33570255673",
        "source_commit": "e2db34a82f8c52e69b1b51e8c60ba45299491f53",
        "deployment_url": "https://app.openadapt.ai",
        "workflow": ".github/workflows/deploy.yml",
        "workflow_run_url": (
            "https://github.com/OpenAdaptAI/openadapt-cloud/actions/runs/33570255673"
        ),
        "run_started_at": "2026-09-01T23:16:22Z",
        "completed_at": "2026-09-01T23:23:37Z",
        "environment": None,
    },
    "docs": {
        "deployment_id": "6226957122",
        "source_commit": "e323249e3a7c1af9d7651312e0afe1f12c38c977",
        "deployment_url": "https://docs.openadapt.ai",
        "workflow": None,
        "workflow_run_url": None,
        "run_started_at": "2026-09-02T16:27:14Z",
        "completed_at": "2026-09-02T16:27:14Z",
        "environment": "github-pages",
    },
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


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def request_handle() -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "qair_" + "".join(secrets.choice(alphabet) for _ in range(43))


def labeled(target: str, version: str, name: str) -> str:
    return trust.digest_bytes(
        f"OpenAdapt remote-safe-synthetic {target} {version} local candidate v1\0".encode(),
        {
            "label": "remote-safe-synthetic",
            "target": target,
            "version": version,
            "name": name,
            "mockmed_production_acceptance": False,
            "evals_production_acceptance": False,
        },
    )


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
        "request_id_sha256": trust.digest_bytes(
            b"OpenAdapt remaining-admissions dsse request v1\0",
            {"kind": kind, "object_sha256": sha256_bytes(raw)},
        ),
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


def tag_rulesets(repository: str, repository_id: str) -> list[dict[str, Any]]:
    common = {
        "schema_version": "openadapt.production-release-tag-ruleset/v1",
        "repository": repository,
        "repository_id": repository_id,
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
        headers={"User-Agent": "OpenAdapt-remaining-admissions/1.0"},
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


def fetch_github_release(repository: str, tag: str) -> dict[str, Any] | None:
    completed = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases/tags/{tag}"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        if "Not Found" in completed.stderr or "Not Found" in completed.stdout:
            return None
        raise SystemExit(completed.stderr or completed.stdout or "gh api release failed")
    return json.loads(completed.stdout)


def observe_package_staging(
    target: str, spec: dict[str, Any], *, observed_at: datetime
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = trust.TARGET_CONTRACTS[target]
    version = spec["version"]
    tag = f"v{version}"
    pypi_files = fetch_pypi_files(spec["pypi_project"], version)
    expected = {
        spec["wheel_name"]: (
            "sha256:" + spec["wheel_sha256"],
            spec["wheel_size"],
            "bdist_wheel",
        ),
        spec["sdist_name"]: (
            "sha256:" + spec["sdist_sha256"],
            spec["sdist_size"],
            "sdist",
        ),
    }
    if {item["filename"] for item in pypi_files} != set(expected):
        raise SystemExit(f"live PyPI files for {spec['pypi_project']} {version} differ")
    for item in pypi_files:
        digest, size, packagetype = expected[item["filename"]]
        if (
            item["sha256"] != digest
            or item["size_bytes"] != size
            or item["packagetype"] != packagetype
            or item["yanked"] is not False
        ):
            raise SystemExit(f"live PyPI file {item['filename']} differs")
    profile = contract["artifacts"]
    release = fetch_github_release(contract["repository"], tag)
    assets: list[dict[str, Any]] = []
    if release is not None:
        if release.get("draft") is not False or release.get("prerelease") is not False:
            raise SystemExit(f"{contract['repository']} {tag} is still a draft")
        by_name = {asset["name"]: asset for asset in release.get("assets") or []}
        for filename, (digest, size, packagetype) in expected.items():
            kind = KIND_BY_PACKAGETYPE[packagetype]
            media_type, destinations = profile[kind]
            gh_asset = by_name.get(filename)
            asset_id = None
            uploader_id = None
            uploader_login = None
            if gh_asset is not None:
                gh_digest = gh_asset.get("digest") or digest
                if gh_digest != digest or gh_asset["size"] != size:
                    raise SystemExit(
                        f"GitHub asset {filename} digest or size differs from PyPI"
                    )
                asset_id = str(gh_asset["id"])
                uploader = gh_asset.get("uploader") or {}
                uploader_id = str(uploader["id"]) if uploader.get("id") is not None else None
                uploader_login = uploader.get("login")
            assets.append(
                {
                    "asset_id": asset_id,
                    "name": filename,
                    "kind": kind,
                    "sha256": digest,
                    "size_bytes": size,
                    "media_type": media_type,
                    "publish_destinations": list(destinations),
                    "uploader_id": uploader_id,
                    "uploader_login": uploader_login,
                }
            )
        author = release.get("author") or {}
        draft_release_id = str(release["id"])
        release_author_login = author.get("login")
    else:
        for filename, (digest, size, packagetype) in expected.items():
            kind = KIND_BY_PACKAGETYPE[packagetype]
            media_type, destinations = profile[kind]
            assets.append(
                {
                    "asset_id": None,
                    "name": filename,
                    "kind": kind,
                    "sha256": digest,
                    "size_bytes": size,
                    "media_type": media_type,
                    "publish_destinations": list(destinations),
                    "uploader_id": None,
                    "uploader_login": None,
                }
            )
        draft_release_id = None
        release_author_login = None
    assets = sorted(assets, key=lambda item: (item["name"], item["asset_id"] or ""))
    immutable = {"enabled": True, "enforced_by_owner": False}
    rulesets = tag_rulesets(contract["repository"], contract["repository_id"])
    tag_ref_state = {"ref": f"refs/tags/{tag}", "exists": True}
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "publication_mode": trust.PUBLICATION_MODE_ALREADY_PUBLISHED_PYPI,
        "repository": contract["repository"],
        "repository_id": contract["repository_id"],
        "draft_release_id": draft_release_id,
        "tag": tag,
        "target_commitish": spec["source_commit"],
        "draft": False,
        "prerelease": False,
        "release_app_id": "4730708",
        "release_app_installation_id": "156835568",
        "release_app_bot_user_id": "321543906",
        "release_author_login": release_author_login,
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
    inventory_artifacts = [
        {
            "name": item["name"],
            "kind": item["kind"],
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
            "media_type": item["media_type"],
            "publish_destinations": item["publish_destinations"],
        }
        for item in assets
    ]
    inventory_artifacts = sorted(
        inventory_artifacts, key=lambda item: (item["kind"], item["name"], item["sha256"])
    )
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": target,
        "claim_scope": contract["claim_scope"],
        "artifacts": inventory_artifacts,
    }
    return trust.validate_staging(staging), trust.validate_artifact_inventory(inventory)


def observe_deployment_staging(
    target: str, spec: dict[str, Any], *, observed_at: datetime
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    contract = trust.TARGET_CONTRACTS[target]
    manifest = {
        "schema_version": "openadapt.production-deployment-manifest/v1",
        "target": target,
        "source_repository": contract["repository"],
        "source_repository_id": contract["repository_id"],
        "source_commit": spec["source_commit"],
        "deployment_id": spec["deployment_id"],
        "deployment_url": spec["deployment_url"],
        "conclusion": "success",
        "environment": spec["environment"],
        "workflow": spec["workflow"],
        "workflow_run_url": spec["workflow_run_url"],
        "run_started_at": spec["run_started_at"],
        "completed_at": spec["completed_at"],
    }
    manifest_raw = evidence.canonical(manifest) + b"\n"
    manifest_sha256 = sha256_bytes(manifest_raw)
    media_type, destinations = contract["artifacts"]["deployment-manifest"]
    artifact = {
        "name": (
            f"openadapt-{target}-{spec['source_commit']}.deployment-manifest.json"
        ),
        "kind": "deployment-manifest",
        "sha256": manifest_sha256,
        "size_bytes": len(manifest_raw),
        "media_type": media_type,
        "publish_destinations": list(destinations),
    }
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": target,
        "claim_scope": contract["claim_scope"],
        "artifacts": [artifact],
    }
    staging = {
        "schema_version": "openadapt.production-release-staging-evidence/v1",
        "publication_mode": trust.PUBLICATION_MODE_ALREADY_PUBLISHED_DEPLOYMENT,
        "repository": contract["repository"],
        "repository_id": contract["repository_id"],
        "tag": f"v0.0.0-deployment.{spec['deployment_id']}",
        "target_commitish": spec["source_commit"],
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "asset_id": None,
                "name": artifact["name"],
                "kind": artifact["kind"],
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "media_type": artifact["media_type"],
                "publish_destinations": artifact["publish_destinations"],
                "uploader_id": None,
                "uploader_login": None,
            }
        ],
        "pypi_files": None,
        "deployment_id": spec["deployment_id"],
        "deployment_url": spec["deployment_url"],
        "observed_at": ts(observed_at),
    }
    return (
        trust.validate_staging(staging),
        trust.validate_artifact_inventory(inventory),
        manifest,
    )


def policy_file_digest(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_existing_trust() -> dict[str, Any]:
    registry = json.loads(SIGNER_PATH.read_text(encoding="utf-8"))
    authority = json.loads(AUTHORITY_PATH.read_text(encoding="utf-8"))
    revocation = json.loads(REVOCATION_PATH.read_text(encoding="utf-8"))
    authority_bundle_path = ROOT / object_rel(
        "qualification-authority-state-receipt-sigstore-bundle",
        "sha256:0f97c284b10f8dc0153dbab0da5deccc5069bb5609982d45b890617783687830",
    )
    revocation_bundle_path = ROOT / object_rel(
        "qualification-revocation-state-receipt-sigstore-bundle",
        "sha256:4e0a052726ba440c9f6a19726b004f948c36087b2702d614a398728b428dcd5f",
    )
    return {
        "registry": evidence.validate_signer_registry(registry),
        "registry_raw": SIGNER_PATH.read_bytes(),
        "authority": authority,
        "authority_raw": AUTHORITY_PATH.read_bytes(),
        "authority_bundle": json.loads(authority_bundle_path.read_text(encoding="utf-8")),
        "authority_bundle_raw": authority_bundle_path.read_bytes(),
        "revocation": revocation,
        "revocation_raw": REVOCATION_PATH.read_bytes(),
        "revocation_bundle": json.loads(
            revocation_bundle_path.read_text(encoding="utf-8")
        ),
        "revocation_bundle_raw": revocation_bundle_path.read_bytes(),
    }


def install_reused(out: Path, existing: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for kind, raw, value in (
        (
            "qualification-authority-state-receipt",
            existing["authority_raw"],
            existing["authority"],
        ),
        (
            "qualification-revocation-state-receipt",
            existing["revocation_raw"],
            existing["revocation"],
        ),
    ):
        dest = out / object_rel(kind, sha256_bytes(raw))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        write_json(out / f"{kind}.json", value)
        entries[kind] = make_entry(kind, raw, value)
    for kind, raw, subject_kind in (
        (
            "qualification-authority-state-receipt-sigstore-bundle",
            existing["authority_bundle_raw"],
            "qualification-authority-state-receipt",
        ),
        (
            "qualification-revocation-state-receipt-sigstore-bundle",
            existing["revocation_bundle_raw"],
            "qualification-revocation-state-receipt",
        ),
    ):
        dest = out / object_rel(kind, sha256_bytes(raw))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        write_json(out / f"{kind}.json", json.loads(raw))
        entries[kind] = make_entry(kind, raw, entries[subject_kind]["object_sha256"])
    signer_raw = existing["registry_raw"]
    digest_hex = sha256_bytes(signer_raw).removeprefix("sha256:")
    signer_rel = (
        f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
        f"{digest_hex}.qualification-signer-registry.json"
    )
    signer_path = out / signer_rel
    signer_path.parent.mkdir(parents=True, exist_ok=True)
    signer_path.write_bytes(signer_raw)
    write_json(out / "signer-registry.json", existing["registry"])
    return entries


def build_target(
    target: str,
    *,
    out: Path,
    private_key: Any,
    existing: dict[str, Any],
    now: datetime,
    policy_commit: str,
    registry_source_commit: str,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    contract = trust.TARGET_CONTRACTS[target]
    generated = now.replace(microsecond=0)
    registry = existing["registry"]
    authority = existing["authority"]
    revocation = existing["revocation"]
    outer = next(
        signer
        for signer in registry["signers"]
        if signer["key_id"].startswith("oa-public-trust-ed25519-")
    )
    reused = install_reused(out, existing)
    version_label = (
        PACKAGE_TARGETS[target]["version"]
        if target in PACKAGE_TARGETS
        else DEPLOYMENT_TARGETS[target]["source_commit"][:12]
    )
    if target in PACKAGE_TARGETS:
        staging, inventory = observe_package_staging(
            target, PACKAGE_TARGETS[target], observed_at=generated
        )
        spec = PACKAGE_TARGETS[target]
        candidate = {
            "schema_version": "openadapt.production-release-candidate/v1",
            "kind": "package",
            "source_repository": contract["repository"],
            "source_repository_id": contract["repository_id"],
            "source_commit": spec["source_commit"],
            "version": spec["version"],
            "tag": f"v{spec['version']}",
            "deployment_id": None,
            "deployment_sha256": None,
            "artifacts": inventory["artifacts"],
        }
        admitted_runtime = "sha256:" + spec["wheel_sha256"]
        write_json(out / "publication-staging.json", staging)
        write_json(out / "artifact-inventory.json", inventory)
    else:
        staging, inventory, manifest = observe_deployment_staging(
            target, DEPLOYMENT_TARGETS[target], observed_at=generated
        )
        spec = DEPLOYMENT_TARGETS[target]
        write_json(out / "deployment-manifest.json", manifest)
        candidate = {
            "schema_version": "openadapt.production-release-candidate/v1",
            "kind": "deployment",
            "source_repository": contract["repository"],
            "source_repository_id": contract["repository_id"],
            "source_commit": spec["source_commit"],
            "version": None,
            "tag": None,
            "deployment_id": spec["deployment_id"],
            "deployment_sha256": inventory["artifacts"][0]["sha256"],
            "artifacts": inventory["artifacts"],
        }
        admitted_runtime = inventory["artifacts"][0]["sha256"]
        write_json(out / "publication-staging.json", staging)
        write_json(out / "artifact-inventory.json", inventory)

    evidence_authority = authority["evidence_authority_sha256"]
    registry_identity = evidence.signer_registry_identity_digest(registry)
    unsigned_receipt = {
        "schema_version": "openadapt.qualification-evidence-decision-receipt/v2",
        "evidence_class": "remote-safe-synthetic",
        "decision_identity_sha256": labeled(target, version_label, "decision-series"),
        "decision_revision": 1,
        "decision_commitment_sha256": labeled(target, version_label, "decision"),
        "evidence_manifest_sha256": labeled(target, version_label, "evidence-manifest"),
        "evidence_manifest_readback_sha256": labeled(
            target, version_label, "manifest-readback"
        ),
        "campaign_artifact_sha256": labeled(target, version_label, "campaign-artifact"),
        "organization_id_sha256": labeled(target, version_label, "organization"),
        "workflow_id_sha256": labeled(target, version_label, "workflow"),
        "workflow_version_id_sha256": labeled(target, version_label, "workflow-version"),
        "bundle_version": "0.0.0-synthetic",
        "bundle_sha256": labeled(target, version_label, "sealed-workflow-bundle"),
        "admitted_runtime_sha256": admitted_runtime,
        "application_contract_sha256": labeled(
            target, version_label, "application-contract"
        ),
        "environment_contract_sha256": labeled(
            target, version_label, "environment-contract"
        ),
        "input_contract_sha256": labeled(target, version_label, "input-contract"),
        "action_contract_sha256": labeled(target, version_label, "action-contract"),
        "identity_contract_sha256": labeled(target, version_label, "identity-contract"),
        "effect_contract_sha256": labeled(target, version_label, "effect-contract"),
        "policy_contract_sha256": labeled(target, version_label, "policy-contract"),
        "evidence_authority_contract_sha256": evidence_authority,
        "campaign_permit_sha256": labeled(target, version_label, "campaign-permit"),
        "signer_registry_sha256": registry_identity,
        "revocation_state_sha256": revocation["revocation_state_sha256"],
        "entity_class": "record",
        "campaign_summary": {
            "schema_version": "openadapt.qualification-evidence-decision-campaign-summary/v1",
            "minimum_trials_per_task_condition": 3,
            "task_count": 1,
            "classes": campaign_classes(),
        },
        "verdict": "ADMIT",
        "issued_at": ts(generated),
        "not_before": ts(generated),
        "expires_at": None,
        "issuer_key_id": EXPECTED_INNER_KEY_ID,
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

    objects: dict[str, tuple[str, dict[str, Any], bytes]] = {}
    for kind, value in (
        ("qualification-authority-state-receipt", authority),
        ("qualification-revocation-state-receipt", revocation),
        ("qualification-evidence-decision-receipt", receipt),
    ):
        raw = evidence.canonical(value) + b"\n"
        objects[kind] = (kind, value, raw)

    receipt_raw = objects["qualification-evidence-decision-receipt"][2]
    receipt_path = out / object_rel(
        "qualification-evidence-decision-receipt", sha256_bytes(receipt_raw)
    )
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(receipt_raw)
    write_json(out / "qualification-evidence-decision-receipt.json", receipt)
    receipt_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="qualification-evidence-decision-receipt",
        value=receipt,
        raw=receipt_raw,
        now=generated,
        registry_sha256=receipt["signer_registry_sha256"],
        authority_state_sha256=authority["authority_state_sha256"],
        revocation_state_sha256=revocation["revocation_state_sha256"],
        source_commit=policy_commit,
    )
    persist_bundle(
        out,
        "qualification-evidence-decision-receipt",
        receipt_bundle,
        sha256_bytes(receipt_raw),
    )
    receipt_entry = make_entry(
        "qualification-evidence-decision-receipt", receipt_raw, receipt
    )
    receipt_bundle_entry = make_entry(
        "qualification-evidence-decision-receipt-sigstore-bundle",
        evidence.canonical(receipt_bundle) + b"\n",
        sha256_bytes(receipt_raw),
    )

    signer_raw_sha256 = sha256_bytes(existing["registry_raw"])
    digest_hex = signer_raw_sha256.removeprefix("sha256:")
    signer_pointer = {
        "schema_version": evidence.SIGNER_POINTER_SCHEMA,
        "object_path": (
            f"production-evidence/signer-registries/sha256/{digest_hex[:2]}/"
            f"{digest_hex}.qualification-signer-registry.json"
        ),
        "object_sha256": signer_raw_sha256,
        "registry_identity_sha256": registry_identity,
        "registry_revision": 1,
    }
    local_entries = [
        reused["qualification-authority-state-receipt"],
        reused["qualification-authority-state-receipt-sigstore-bundle"],
        reused["qualification-revocation-state-receipt"],
        reused["qualification-revocation-state-receipt-sigstore-bundle"],
        receipt_entry,
        receipt_bundle_entry,
    ]
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
        "entries": local_entries,
    }
    local_registry["registry_head_sha256"] = evidence.registry_head_digest(local_registry)
    write_json(out / "evidence-registry.json", local_registry)

    head = local_registry["registry_head_sha256"]
    revision = local_registry["revision"]
    resolver = LocalResolver(registry)
    resolver.authority = resolver.add(
        "qualification-authority-state-receipt",
        authority,
        reference_from_entry(
            reused["qualification-authority-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            reused["qualification-authority-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    resolver.revocation = resolver.add(
        "qualification-revocation-state-receipt",
        revocation,
        reference_from_entry(
            reused["qualification-revocation-state-receipt"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
        reference_from_entry(
            reused["qualification-revocation-state-receipt-sigstore-bundle"],
            registry_source_commit=registry_source_commit,
            registry_revision=revision,
            registry_head_sha256=head,
        ),
    )
    receipt_ref = reference_from_entry(
        receipt_entry,
        registry_source_commit=registry_source_commit,
        registry_revision=revision,
        registry_head_sha256=head,
    )
    receipt_bundle_ref = reference_from_entry(
        receipt_bundle_entry,
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
    write_json(out / "workflow-issue-request.json", request)
    write_json(out / "one-use-effect.json", consumer.reconcile(request_handle=handle))
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

    release_identity = {
        "schema_version": "openadapt.monotonic-production-release/v1",
        "channel": "production",
        "sequence": 1,
        "previous_admission_sha256": None,
    }
    release_sha256 = trust.digest_bytes(
        trust.RELEASE_DOMAIN,
        {
            "target": target,
            "claim_scope": contract["claim_scope"],
            "release": candidate,
        },
    )
    inventory_sha256 = trust.artifact_inventory_digest(inventory)
    acceptance_policy_sha256 = policy_file_digest(ROOT / "production-evidence-policy.json")
    lifecycle_policy_sha256 = policy_file_digest(ROOT / "production-lifecycle-policy.json")
    common = {
        "target": target,
        "verdict": "accepted",
        "claim_scope": contract["claim_scope"],
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
        "signer_registry_sha256": registry_identity,
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
    manifest_obj = {
        "schema_version": "openadapt.production-acceptance/v3",
        **common,
        "release": candidate,
        "artifact_inventory": inventory,
    }
    trust.validate_acceptance_manifest(
        manifest_obj,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=registry,
        now=now,
    )
    manifest_raw, manifest_entry = persist_object(
        out, "production-acceptance-manifest", manifest_obj
    )
    manifest_bundle = dsse_bundle(
        private_key=private_key,
        signer=outer,
        kind="production-acceptance-manifest",
        value=manifest_obj,
        raw=manifest_raw,
        now=generated,
        registry_sha256=manifest_obj["signer_registry_sha256"],
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
        manifest_obj,
        manifest_ref,
        manifest_bundle_ref,
    )

    summary = {
        "schema_version": "openadapt.production-lifecycle-evidence-summary/v3",
        **common,
        "evidence_identity_sha256": labeled(
            target, version_label, "placeholder-evidence-identity"
        ),
        "production_acceptance_manifest_reference": manifest_ref,
        "production_acceptance_manifest_bundle_reference": manifest_bundle_ref,
    }
    summary["evidence_identity_sha256"] = trust.acceptance_summary_identity(summary)
    trust.validate_acceptance_summary(
        summary,
        manifest=manifest_obj,
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
        out, "production-acceptance-summary", summary_bundle, sha256_bytes(summary_raw)
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
        manifest=manifest_obj,
        receipt=receipt,
        qualification_admission=admission,
        receipt_signer_registry=registry,
        now=now,
    )
    write_json(out / "release-issue-request.json", release_request)
    release_raw, release_entry = persist_object(out, "qualification-release", release)
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
    persist_bundle(out, "qualification-release", release_bundle, sha256_bytes(release_raw))
    write_json(
        out / "one-use-effect-release.json",
        consumer.reconcile(request_handle=release_handle),
    )

    # Rebuild the local registry with every issued object so validate_registry
    # can check the candidate in isolation.
    issued_kinds = [
        "qualification-evidence-decision-receipt",
        "qualification-admission",
        "production-acceptance-manifest",
        "production-acceptance-summary",
        "qualification-release",
    ]
    entries = [
        reused["qualification-authority-state-receipt"],
        reused["qualification-authority-state-receipt-sigstore-bundle"],
        reused["qualification-revocation-state-receipt"],
        reused["qualification-revocation-state-receipt-sigstore-bundle"],
    ]
    for kind in issued_kinds:
        value = json.loads((out / f"{kind}.json").read_text(encoding="utf-8"))
        raw = evidence.canonical(value) + b"\n"
        bundle = json.loads(
            (out / f"{kind}-sigstore-bundle.json").read_text(encoding="utf-8")
        )
        bundle_raw = evidence.canonical(bundle) + b"\n"
        entries.append(make_entry(kind, raw, value))
        entries.append(
            make_entry(f"{kind}-sigstore-bundle", bundle_raw, sha256_bytes(raw))
        )
    local_registry["entries"] = entries
    local_registry["registry_head_sha256"] = evidence.registry_head_digest(local_registry)
    evidence.validate_registry(local_registry, root=out)
    write_json(out / "evidence-registry.json", local_registry)

    record = {
        "schema_version": "openadapt.local-remaining-admission-build-record/v1",
        "target": target,
        "evidence_class": "remote-safe-synthetic",
        "campaign": {
            "label": "remote-safe-synthetic",
            "task_count": 1,
            "cells_per_class": 1,
            "trials_per_cell": 3,
            "classes": list(trust.CAMPAIGN_CLASSES),
            "mockmed_production_acceptance": False,
        },
        "evals_production_acceptance": False,
        "keychain_service": software.KEYCHAIN_SERVICE,
        "inner_key_id": EXPECTED_INNER_KEY_ID,
        "did_not_generate_key": True,
        "did_not_replace_flow_signer": True,
        "publication_mode": staging["publication_mode"],
        "release_admission_id_sha256": release["admission_id_sha256"],
        "expires_at": release["expires_at"],
        "source_commit": candidate["source_commit"],
        "generated_at": ts(generated),
    }
    write_json(out / "build-record.json", record)
    return {
        "target": target,
        "out": str(out),
        "release_admission_id_sha256": release["admission_id_sha256"],
        "publication_mode": staging["publication_mode"],
        "release_entry": release_entry,
        "new_object_kinds": issued_kinds,
    }


def candidate_dir(target: str) -> Path:
    if target in PACKAGE_TARGETS:
        version = PACKAGE_TARGETS[target]["version"]
        return ROOT / "local-candidates" / f"{target}-{version}-remote-safe-synthetic"
    commit = DEPLOYMENT_TARGETS[target]["source_commit"][:7]
    return ROOT / "local-candidates" / f"{target}-{commit}-remote-safe-synthetic"


def merge_into_main(results: list[dict[str, Any]], *, registry_source_commit: str) -> None:
    registry_path = ROOT / "evidence-registry.json"
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    evidence.validate_registry(document, root=ROOT)
    previous_head = document["registry_head_sha256"]
    existing = {item["object_sha256"] for item in document["entries"]}
    added = 0
    for result in results:
        out = Path(result["out"])
        local = json.loads((out / "evidence-registry.json").read_text(encoding="utf-8"))
        for entry in local["entries"]:
            if entry["object_sha256"] in existing:
                continue
            source = out / entry["object_path"]
            dest = ROOT / entry["object_path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            raw = source.read_bytes()
            if dest.exists() and dest.read_bytes() != raw:
                raise SystemExit(f"content-addressed collision at {entry['object_path']}")
            dest.write_bytes(raw)
            document["entries"].append(entry)
            existing.add(entry["object_sha256"])
            added += 1
    document["revision"] += 1
    document["previous_registry_head_sha256"] = previous_head
    document["registry_head_sha256"] = evidence.registry_head_digest(document)
    evidence.validate_registry(document, root=ROOT)
    registry_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    admissions = []
    for entry in document["entries"]:
        if entry["kind"] != "qualification-release":
            continue
        admissions.append(
            reference_from_entry(
                entry,
                registry_source_commit=registry_source_commit,
                registry_revision=document["revision"],
                registry_head_sha256=document["registry_head_sha256"],
            )
        )
    ledger = {
        "$schema": "schemas/production-lifecycle-admissions.schema.json",
        "schema_version": "openadapt.production-lifecycle-admissions/v1",
        "policy_sha256": (
            "sha256:e1444a08ce6b16736168cce027ce9d48abb2e0e246fc0cd79c0772fa8e423e11"
        ),
        "admissions": admissions,
    }
    (ROOT / "production-lifecycle-admissions.json").write_text(
        json.dumps(ledger, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "merged_objects": added,
                "registry_revision": document["revision"],
                "registry_head_sha256": document["registry_head_sha256"],
                "admissions": len(admissions),
            },
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-commit", required=True)
    parser.add_argument("--registry-source-commit", required=True)
    parser.add_argument(
        "--targets",
        default="agent,capture,cloud,desktop,docs,openadapt",
        help="comma-separated targets",
    )
    args = parser.parse_args(argv)
    targets = [item.strip() for item in args.targets.split(",") if item.strip()]
    unknown = [item for item in targets if item not in {*PACKAGE_TARGETS, *DEPLOYMENT_TARGETS}]
    if unknown:
        print(f"REFUSED: unknown targets {unknown}", file=sys.stderr)
        return 1
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
    if material["public_key"] != EXPECTED_PUBLIC_KEY:
        print("REFUSED: Keychain public key does not match the provisioned inner key", file=sys.stderr)
        return 1
    existing = load_existing_trust()
    now = datetime.now(timezone.utc)
    results = []
    for target in targets:
        out = candidate_dir(target)
        result = build_target(
            target,
            out=out,
            private_key=private_key,
            existing=existing,
            now=now,
            policy_commit=args.policy_commit,
            registry_source_commit=args.registry_source_commit,
        )
        results.append(result)
        print(
            json.dumps(
                {
                    "target": target,
                    "publication_mode": result["publication_mode"],
                    "release_admission_id_sha256": result["release_admission_id_sha256"],
                    "out": result["out"],
                },
                sort_keys=True,
            )
        )
    merge_into_main(results, registry_source_commit=args.registry_source_commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
