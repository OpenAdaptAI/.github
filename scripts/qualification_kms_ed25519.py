#!/usr/bin/env python3
"""Prepare the inactive AWS KMS Ed25519 qualification-signing interface.

This module does not call AWS. It converts an exact KMS public key into a
closed signer-registry candidate and prepares the exact request for KMS Sign.
The caller must obtain AWS credentials through the bound GitHub OIDC identity.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import production_trust as trust
import validate_evidence_registry as evidence


AWS_ACCOUNT_ID = "992382684924"
AWS_REGION = "us-east-1"
KMS_KEY_SPEC = "ECC_NIST_EDWARDS25519"
KMS_SIGNING_ALGORITHM = "ED25519_SHA_512"
KMS_MESSAGE_TYPE = "RAW"
ROLE_ARN = "arn:aws:iam::992382684924:role/openadapt-synthetic-qualification-signer"
WORKFLOW = (
    "https://github.com/OpenAdaptAI/.github/.github/workflows/"
    "issue-synthetic-qualification-evidence-decision.yml@refs/heads/main"
)
ENVIRONMENT = "synthetic-qualification-evidence-decision"
OIDC_SUBJECT = f"repo:OpenAdaptAI/.github:environment:{ENVIRONMENT}"
KMS_KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:992382684924:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class KmsEd25519Error(ValueError):
    """The inactive KMS signing interface input is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise KmsEd25519Error("timestamp must use UTC")
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def interface_contract() -> dict[str, Any]:
    """Return the external controls that an active workflow must satisfy."""

    return {
        "schema_version": "openadapt.qualification-kms-ed25519-interface/v1",
        "activation_state": "inactive",
        "aws_account_id": AWS_ACCOUNT_ID,
        "aws_region": AWS_REGION,
        "role_arn": ROLE_ARN,
        "kms_key_spec": KMS_KEY_SPEC,
        "kms_signing_algorithm": KMS_SIGNING_ALGORITHM,
        "kms_message_type": KMS_MESSAGE_TYPE,
        "kms_key_usage": "SIGN_VERIFY",
        "kms_get_public_key_projection_fields": [
            "KeyId",
            "KeySpec",
            "KeyUsage",
            "PublicKey",
            "SigningAlgorithms",
        ],
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "oidc_audience": "sts.amazonaws.com",
        "oidc_subject": OIDC_SUBJECT,
        "workflow": WORKFLOW,
        "environment": ENVIRONMENT,
        "allowed_evidence_class": "remote-safe-synthetic",
        "allowed_usage": "qualification-evidence-decision-receipt",
    }


def _public_key(spki_der: bytes) -> tuple[Ed25519PublicKey, bytes]:
    try:
        key = serialization.load_der_public_key(spki_der)
    except (TypeError, ValueError) as exc:
        raise KmsEd25519Error("public key is not valid DER SPKI") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KmsEd25519Error("KMS public key must be Ed25519")
    raw = key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    expected_spki = bytes.fromhex("302a300506032b6570032100") + raw
    if spki_der != expected_spki:
        raise KmsEd25519Error("KMS public key SPKI is not canonical Ed25519")
    return key, raw


def signer_registry_candidate(
    *,
    kms_public_key_projection: Mapping[str, Any],
    revision: int,
    generated_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build an inactive candidate from an exact KMS GetPublicKey projection."""

    if set(kms_public_key_projection) != {
        "KeyId",
        "PublicKey",
        "KeySpec",
        "KeyUsage",
        "SigningAlgorithms",
    }:
        raise KmsEd25519Error("KMS GetPublicKey fields differ")
    kms_key_arn = kms_public_key_projection["KeyId"]
    if not isinstance(kms_key_arn, str) or KMS_KEY_ARN.fullmatch(kms_key_arn) is None:
        raise KmsEd25519Error(
            "KMS key must be an exact key ARN in the OpenAdapt account"
        )
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise KmsEd25519Error("registry revision must be a positive integer")
    if not generated_at < expires_at <= generated_at + timedelta(days=7):
        raise KmsEd25519Error("signer registry lifetime must be at most seven days")
    if (
        kms_public_key_projection["KeySpec"] != KMS_KEY_SPEC
        or kms_public_key_projection["KeyUsage"] != "SIGN_VERIFY"
        or kms_public_key_projection["SigningAlgorithms"] != [KMS_SIGNING_ALGORITHM]
        or not isinstance(kms_public_key_projection["PublicKey"], str)
    ):
        raise KmsEd25519Error("KMS GetPublicKey signing metadata differs")
    try:
        spki_der = base64.b64decode(
            kms_public_key_projection["PublicKey"], validate=True
        )
    except (ValueError, TypeError) as exc:
        raise KmsEd25519Error("KMS GetPublicKey public key is invalid") from exc
    if (
        base64.b64encode(spki_der).decode("ascii")
        != kms_public_key_projection["PublicKey"]
    ):
        raise KmsEd25519Error("KMS GetPublicKey public key is not canonical base64")
    _, raw = _public_key(spki_der)
    signer = {
        "algorithm": "ed25519",
        "key_id": "qa-ed25519-" + hashlib.sha256(raw).hexdigest()[:16],
        "key_origin": "aws-kms",
        "kms_key_arn": kms_key_arn,
        "public_key": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "public_key_spki_der_base64": base64.b64encode(spki_der).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(spki_der).hexdigest(),
        "signature_encoding": "raw-64-base64-rfc4648-padded",
        "statement_schema_versions": [
            "openadapt.qualification-evidence-signing-statement/v1"
        ],
        "allowed_usages": ["qualification-evidence-decision-receipt"],
        "allowed_workflows": [WORKFLOW],
        "allowed_ref_prefixes": ["refs/heads/main"],
        "allowed_environments": [ENVIRONMENT],
        "status": "active",
        "revoked_at": None,
    }
    proposed_registry = {
        "schema_version": "openadapt.qualification-signer-registry/v2",
        "revision": revision,
        "generated_at": format_timestamp(generated_at),
        "expires_at": format_timestamp(expires_at),
        "signers": [signer],
    }
    try:
        proposed_registry = evidence.validate_signer_registry(proposed_registry)
    except evidence.EvidenceRegistryError as exc:
        raise KmsEd25519Error(str(exc)) from exc
    interface = interface_contract()
    return {
        "schema_version": "openadapt.qualification-signer-registry-candidate/v1",
        "activation_state": "not-installed",
        "interface_sha256": "sha256:"
        + hashlib.sha256(
            b"OpenAdapt qualification KMS Ed25519 interface v1\0" + canonical(interface)
        ).hexdigest(),
        "proposed_registry": proposed_registry,
    }


def validate_oidc_claims(
    claims: Mapping[str, Any], *, workflow_source_commit: str
) -> dict[str, Any]:
    """Validate the claims that the AWS role trust policy must bind."""

    if HEX40.fullmatch(workflow_source_commit) is None:
        raise KmsEd25519Error("workflow source commit must be exact")
    expected = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "sts.amazonaws.com",
        "sub": OIDC_SUBJECT,
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "job_workflow_ref": WORKFLOW,
        "job_workflow_sha": workflow_source_commit,
        "runner_environment": "github-hosted",
    }
    for name, expected_value in expected.items():
        if claims.get(name) != expected_value:
            raise KmsEd25519Error(f"OIDC claim {name} differs")
    return dict(claims)


def kms_sign_request(
    receipt: Mapping[str, Any],
    *,
    signer_registry: Mapping[str, Any],
    kms_key_arn: str,
) -> dict[str, str]:
    """Prepare KMS Sign only for one validated synthetic decision receipt."""

    if not isinstance(kms_key_arn, str) or KMS_KEY_ARN.fullmatch(kms_key_arn) is None:
        raise KmsEd25519Error(
            "KMS key must be an exact key ARN in the OpenAdapt account"
        )
    if receipt.get("signature") != "":
        raise KmsEd25519Error("receipt signature slot must be empty")
    candidate = dict(receipt)
    candidate["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
    try:
        trust._validate_receipt_structure(candidate)
        statement = trust.validate_signing_statement(
            receipt,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v2"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        registry = evidence.validate_signer_registry(signer_registry)
    except (trust.TrustError, evidence.EvidenceRegistryError) as exc:
        raise KmsEd25519Error(str(exc)) from exc
    if receipt.get("evidence_class") != "remote-safe-synthetic":
        raise KmsEd25519Error("KMS signer accepts only remote-safe synthetic evidence")
    matches = [
        signer
        for signer in registry["signers"]
        if signer["key_id"] == receipt["issuer_key_id"]
    ]
    if (
        len(matches) != 1
        or matches[0].get("key_origin") != "aws-kms"
        or matches[0].get("kms_key_arn") != kms_key_arn
        or matches[0]["status"] != "active"
    ):
        raise KmsEd25519Error("receipt does not select the active KMS signer")
    raw = canonical(statement) + b"\n"
    return {
        "KeyId": kms_key_arn,
        "Message": base64.b64encode(raw).decode("ascii"),
        "MessageType": KMS_MESSAGE_TYPE,
        "SigningAlgorithm": KMS_SIGNING_ALGORITHM,
    }


def verify_kms_signature(
    *, statement: Mapping[str, Any], signature: bytes, spki_der: bytes
) -> str:
    """Verify a returned raw Ed25519 signature before it enters a receipt."""

    if len(signature) != 64:
        raise KmsEd25519Error("KMS Ed25519 signature must contain 64 bytes")
    key, _ = _public_key(spki_der)
    try:
        key.verify(signature, canonical(statement) + b"\n")
    except InvalidSignature as exc:
        raise KmsEd25519Error("KMS Ed25519 signature verification failed") from exc
    return base64.b64encode(signature).decode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry_parser = subparsers.add_parser("registry-candidate")
    registry_parser.add_argument("--kms-public-key-projection", required=True)
    registry_parser.add_argument("--revision", required=True, type=int)
    registry_parser.add_argument("--generated-at", required=True)
    registry_parser.add_argument("--expires-at", required=True)

    sign_parser = subparsers.add_parser("sign-request")
    sign_parser.add_argument("--receipt", required=True)
    sign_parser.add_argument("--signer-registry", required=True)
    sign_parser.add_argument("--kms-key-arn", required=True)

    subparsers.add_parser("interface")
    args = parser.parse_args(argv)
    try:
        if args.command == "interface":
            result = interface_contract()
        elif args.command == "registry-candidate":
            result = signer_registry_candidate(
                kms_public_key_projection=json.loads(
                    Path(args.kms_public_key_projection).read_text(encoding="utf-8")
                ),
                revision=args.revision,
                generated_at=datetime.strptime(
                    args.generated_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc),
                expires_at=datetime.strptime(
                    args.expires_at, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc),
            )
        else:
            receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
            signer_registry = json.loads(
                Path(args.signer_registry).read_text(encoding="utf-8")
            )
            result = kms_sign_request(
                receipt,
                signer_registry=signer_registry,
                kms_key_arn=args.kms_key_arn,
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
