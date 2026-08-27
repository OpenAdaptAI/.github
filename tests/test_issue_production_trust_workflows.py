from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import issue_production_trust_object as issuer
import validate_evidence_registry as evidence

WORKFLOWS = {
    "qualification-admission": (
        ".github/workflows/issue-qualification-admission.yml",
        "qualification-admission",
    ),
    "qualification-release": (
        ".github/workflows/issue-production-release-admission.yml",
        "production-release-admission",
    ),
    "support-release-admission": (
        ".github/workflows/issue-support-release-admission.yml",
        "support-release-admission",
    ),
}


def test_admission_issuers_use_only_the_central_kms_profile() -> None:
    configure_pin = (
        "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c"
    )
    for kind, (relative, environment) in WORKFLOWS.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert f"environment: {environment}" in source
        assert configure_pin in source
        assert (
            "arn:aws:iam::992382684924:role/openadapt-production-trust-signer" in source
        )
        assert "alias/openadapt-production-trust-v1" in source
        assert f"--kind {kind}" in source
        assert "issue-candidate" in source
        assert "actions/attest" not in source
        assert "cosign sign" not in source.lower()
        assert "attestations: write" not in source
        assert "id-token: write" in source
        assert "AWS_ACCESS_KEY_ID=" in source
        assert "git ls-remote --exit-code --heads origin refs/heads/main" in source
        assert "--draft" in source
        assert "gh pr merge" not in source
        assert "gh_2.98.0_linux_amd64.tar.gz" in source
    for kind in ("qualification-admission", "qualification-release"):
        source = (ROOT / WORKFLOWS[kind][0]).read_text(encoding="utf-8")
        assert "cosign-release: v3.1.3" in source
        assert "OPENADAPT_SIGSTORE_TRUSTED_ROOT" in source


def test_recovery_contract_is_single_effect_and_fail_closed() -> None:
    source = (
        ROOT / ".github/workflows/issue-production-publication-recovery.yml"
    ).read_text(encoding="utf-8")
    for effect in (
        "stage-draft-assets",
        "publish-pypi",
        "publish-github-release",
        "publish-mcp-registry",
    ):
        assert effect in source
    assert "requested_effect:" in source
    assert "requested_effects" not in source
    assert "test \"$RUN_ATTEMPT\" = '1'" in source
    assert source.count("timeout-minutes: 5") == 2
    assert "environment: release-identity" in source
    assert "environment: mcp-registry" in source
    assert "environment: pypi" not in source
    assert "PyPI Trusted Publishing cannot run in a reusable workflow." in source
    assert (
        source.count(
            "The isolated publication authority action is not present in this commit."
        )
        == 2
    )
    assert "id-token: write" not in source
    assert "contents: write" not in source


def test_dsse_bundle_binds_exact_canonical_lf_subject(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.der"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    spki = public_key.read_bytes()
    kms_public_key = {
        "key_arn": (
            "arn:aws:kms:us-east-1:992382684924:key/"
            "00000000-0000-4000-8000-000000000000"
        ),
        "key_alias_arn": issuer.KMS_ALIAS_ARN,
        "key_spec": issuer.KMS_KEY_SPEC,
        "key_usage": issuer.KMS_KEY_USAGE,
        "signing_algorithm": issuer.KMS_SIGNING_ALGORITHM,
        "public_key_spki": spki,
        "public_key_spki_sha256": issuer.sha256(spki),
    }
    signer_identity = "sha256:" + "1" * 64
    authority_identity = "sha256:" + "2" * 64
    revocation_identity = "sha256:" + "3" * 64
    source_commit = "a" * 40
    subject_value = {
        "schema_version": "openadapt.qualification-admission/v3",
        "admission_id_sha256": "sha256:" + "4" * 64,
        "signer_registry_sha256": signer_identity,
        "revocation_state_sha256": revocation_identity,
        "issued_at": "2026-08-27T12:00:00Z",
        "not_before": "2026-08-27T12:00:00Z",
        "expires_at": "2026-08-28T12:00:00Z",
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
    subject_raw = evidence.canonical(subject_value) + b"\n"
    trust_state = {
        "registry_source_commit": source_commit,
        "registry_revision": 8,
        "registry_head_sha256": "sha256:" + "5" * 64,
        "signer_registry_object_sha256": "sha256:" + "6" * 64,
        "signer_registry_identity_sha256": signer_identity,
        "signer_registry_revision": 3,
        "authority_state_sha256": authority_identity,
        "authority_state_semantic_identity_sha256": "sha256:" + "7" * 64,
        "revocation_state_sha256": revocation_identity,
        "revocation_state_semantic_identity_sha256": "sha256:" + "8" * 64,
    }
    statement = issuer.signing_statement(
        subject_raw=subject_raw,
        subject_value=subject_value,
        kind="qualification-admission",
        trust_state=trust_state,
        kms_public_key=kms_public_key,
    )
    payload = evidence.canonical(statement)
    pae = issuer.dsse_pae(issuer.DSSE_PAYLOAD_TYPE, payload)
    message = tmp_path / "pae.bin"
    signature = tmp_path / "signature.der"
    message.write_bytes(pae)
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature),
            str(message),
        ],
        check=True,
        capture_output=True,
    )
    bundle_raw = issuer.bundle_bytes(
        payload=payload,
        signature=signature.read_bytes(),
        kms_public_key=kms_public_key,
    )
    result = issuer.validate_kms_bundle(
        subject_raw=subject_raw,
        subject_value=subject_value,
        kind="qualification-admission",
        bundle_raw=bundle_raw,
        kms_public_key=kms_public_key,
        expected_trust_state=trust_state,
    )
    assert result["subject_sha256"] == issuer.sha256(subject_raw)
    assert result["bundle_sha256"] == issuer.sha256(bundle_raw)
    assert bundle_raw == evidence.canonical(json.loads(bundle_raw)) + b"\n"

    with pytest.raises(issuer.IssuerError, match="exact subject"):
        issuer.validate_kms_bundle(
            subject_raw=subject_raw + b" ",
            subject_value=subject_value,
            kind="qualification-admission",
            bundle_raw=bundle_raw,
            kms_public_key=kms_public_key,
            expected_trust_state=trust_state,
        )


def test_effect_environment_mapping_is_closed() -> None:
    assert issuer.recovery_environment("stage-draft-assets") == "release-identity"
    assert issuer.recovery_environment("publish-pypi") == "pypi"
    assert issuer.recovery_environment("publish-github-release") == "release-identity"
    assert (
        issuer.recovery_environment("publish-mcp-registry", target="agent")
        == "mcp-registry"
    )
    with pytest.raises(issuer.IssuerError):
        issuer.recovery_environment("publish-mcp-registry", target="flow")
    with pytest.raises(issuer.IssuerError):
        issuer.recovery_environment("anything-else")


def test_bundle_profile_dispatch_keeps_registered_legacy_profiles() -> None:
    kms_shape = (
        evidence.canonical(
            {
                "mediaType": evidence.BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"publicKey": {"hint": "sha256:" + "1" * 64}},
                "dsseEnvelope": {},
            }
        )
        + b"\n"
    )
    github_shape = (
        evidence.canonical(
            {
                "mediaType": evidence.BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"certificate": {}},
                "dsseEnvelope": {},
            }
        )
        + b"\n"
    )
    message_shape = (
        evidence.canonical(
            {
                "mediaType": evidence.BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"certificate": {}},
                "messageSignature": {},
            }
        )
        + b"\n"
    )

    assert issuer.is_kms_dsse_bundle(kms_shape)
    assert not issuer.is_kms_dsse_bundle(github_shape)
    assert not issuer.is_kms_dsse_bundle(message_shape)
    assert not issuer.is_kms_dsse_bundle(b"not-json\n")


def test_dsse_pae_has_exact_lengths() -> None:
    payload = b"abc"
    result = issuer.dsse_pae(issuer.DSSE_PAYLOAD_TYPE, payload)
    assert result == (b"DSSEv1 28 application/vnd.in-toto+json 3 " + payload)
    assert hashlib.sha256(result).digest()
