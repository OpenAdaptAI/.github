#!/usr/bin/env python3
"""GitHub-secret Ed25519 qualification signer with a local Keychain backup.

This module does not call AWS. The live private half is the GitHub environment
secret. The recoverable copy is the macOS Keychain item. GitHub cannot return a
secret after it is set, so the Keychain copy is the only restore path.

The issuer workflows stay inactive until the founder provisions the key and a
later change arms them. An agent must not mint this trust root: run `provision`
on the founder's Mac.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import production_trust as trust
import validate_evidence_registry as evidence


REPOSITORY = "OpenAdaptAI/.github"
ENVIRONMENT = "synthetic-qualification-evidence-decision"
WORKFLOW = (
    "https://github.com/OpenAdaptAI/.github/.github/workflows/"
    "issue-synthetic-qualification-evidence-decision.yml@refs/heads/main"
)
GITHUB_SECRET_NAME = "OPENADAPT_QUALIFICATION_ED25519_PRIVATE_KEY"
KEYCHAIN_SERVICE = "openadapt-qualification-ed25519"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
DECISION_USAGE = "qualification-evidence-decision-receipt"


class SoftwareEd25519Error(ValueError):
    """The software Ed25519 signing interface input is invalid."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SoftwareEd25519Error("timestamp must use UTC")
    return value.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def interface_contract() -> dict[str, Any]:
    """Return the external controls that an active workflow must satisfy."""

    return {
        "schema_version": "openadapt.qualification-software-ed25519-interface/v1",
        "activation_state": "inactive",
        "aws_required": False,
        "algorithm": "ed25519",
        "key_format": "pkcs8-pem-unencrypted",
        "github_repository": REPOSITORY,
        "github_environment": ENVIRONMENT,
        "github_secret_name": GITHUB_SECRET_NAME,
        "keychain_service": KEYCHAIN_SERVICE,
        "custody": ["github-environment-secret", "local-keychain-backup"],
        "restore_path": "keychain-to-github-only",
        "workflow": WORKFLOW,
        "allowed_evidence_class": "remote-safe-synthetic",
        "allowed_usage": DECISION_USAGE,
    }


def _raw_public_key(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def public_material(private_key: Ed25519PrivateKey) -> dict[str, str]:
    raw = _raw_public_key(private_key.public_key())
    spki = SPKI_PREFIX + raw
    return {
        "algorithm": "ed25519",
        "key_id": "qa-ed25519-" + hashlib.sha256(raw).hexdigest()[:16],
        "public_key": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "public_key_spki_der_base64": base64.b64encode(spki).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(spki).hexdigest(),
    }


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as exc:
        raise SoftwareEd25519Error("private key PEM is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SoftwareEd25519Error("private key must be Ed25519")
    return key


def private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def signer_from_public_material(material: Mapping[str, str]) -> dict[str, Any]:
    return {
        "algorithm": "ed25519",
        "key_id": material["key_id"],
        "public_key": material["public_key"],
        "public_key_spki_der_base64": material["public_key_spki_der_base64"],
        "public_key_sha256": material["public_key_sha256"],
        "statement_schema_versions": [
            "openadapt.qualification-evidence-signing-statement/v1"
        ],
        "allowed_usages": [DECISION_USAGE],
        "allowed_workflows": [WORKFLOW],
        "allowed_ref_prefixes": ["refs/heads/main"],
        "status": "active",
        "revoked_at": None,
    }


def signer_registry_candidate(
    *,
    public_material_value: Mapping[str, str],
    revision: int,
    generated_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build an inactive candidate from the founder-held public half."""

    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise SoftwareEd25519Error("registry revision must be a positive integer")
    if not generated_at < expires_at <= generated_at + timedelta(days=7):
        raise SoftwareEd25519Error("signer registry lifetime must be at most seven days")
    signer = signer_from_public_material(public_material_value)
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
        raise SoftwareEd25519Error(str(exc)) from exc
    interface = interface_contract()
    return {
        "schema_version": "openadapt.qualification-signer-registry-candidate/v1",
        "activation_state": "not-installed",
        "custody": list(interface["custody"]),
        "interface_sha256": "sha256:"
        + hashlib.sha256(
            b"OpenAdapt qualification software Ed25519 interface v1\0"
            + canonical(interface)
        ).hexdigest(),
        "proposed_registry": proposed_registry,
    }


def sign_receipt(
    receipt: Mapping[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    signer_registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Sign one synthetic decision receipt with the software Ed25519 key."""

    candidate = dict(receipt)
    candidate["signature"] = ""
    candidate["signing_statement"] = trust.signing_statement(
        candidate,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v2",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
    )
    if candidate.get("evidence_class") != "remote-safe-synthetic":
        raise SoftwareEd25519Error(
            "software signer accepts only remote-safe synthetic evidence"
        )
    material = public_material(private_key)
    existing_key_id = candidate.get("issuer_key_id")
    if existing_key_id not in {None, "", material["key_id"]}:
        raise SoftwareEd25519Error("receipt issuer_key_id does not match the key")
    candidate["issuer_key_id"] = material["key_id"]
    candidate["algorithm"] = "ed25519"
    candidate["signing_statement"] = trust.signing_statement(
        candidate,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v2",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
    )
    statement = trust.validate_signing_statement(
        candidate,
        object_schema_version="openadapt.qualification-evidence-decision-receipt/v2",
        signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
    )
    signature = private_key.sign(canonical(statement) + b"\n")
    candidate["signature"] = base64.b64encode(signature).decode("ascii")
    try:
        trust.verify_embedded_signature(
            candidate,
            signer_registry=signer_registry,
            object_schema_version="openadapt.qualification-evidence-decision-receipt/v2",
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
            usage=DECISION_USAGE,
        )
    except trust.TrustError as exc:
        raise SoftwareEd25519Error(str(exc)) from exc
    return candidate


def _keychain_account() -> str:
    account = os.environ.get("USER") or os.environ.get("LOGNAME")
    if not account:
        raise SoftwareEd25519Error("Keychain account is absent")
    return account


def keychain_read() -> bytes:
    result = subprocess.run(
        [
            "security",
            "find-generic-password",
            "-a",
            _keychain_account(),
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise SoftwareEd25519Error("Keychain backup is absent")
    return result.stdout


def keychain_write(pem: bytes) -> None:
    try:
        keychain_read()
    except SoftwareEd25519Error:
        pass
    else:
        raise SoftwareEd25519Error("Keychain backup already exists; refuse overwrite")
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
        path = handle.name
    try:
        os.chmod(path, 0o600)
        result = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-a",
                _keychain_account(),
                "-s",
                KEYCHAIN_SERVICE,
                "-w",
                Path(path).read_text(encoding="utf-8"),
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise SoftwareEd25519Error("Keychain write failed")
    finally:
        try:
            Path(path).write_bytes(os.urandom(len(pem)))
        finally:
            os.unlink(path)


def github_secret_write(pem: bytes) -> None:
    create = subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "PUT",
            f"repos/{REPOSITORY}/environments/{ENVIRONMENT}",
        ],
        capture_output=True,
        check=False,
    )
    if create.returncode != 0:
        raise SoftwareEd25519Error("GitHub environment create failed")
    result = subprocess.run(
        [
            "gh",
            "secret",
            "set",
            GITHUB_SECRET_NAME,
            "-R",
            REPOSITORY,
            "--env",
            ENVIRONMENT,
        ],
        input=pem,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SoftwareEd25519Error("GitHub secret write failed")


def load_private_key_from_sources(
    *, pem_file: Path | None, use_keychain: bool, use_env: bool
) -> Ed25519PrivateKey:
    if pem_file is not None:
        return load_private_key(pem_file.read_bytes())
    if use_env:
        value = os.environ.get(GITHUB_SECRET_NAME)
        if not value:
            raise SoftwareEd25519Error("GitHub secret environment variable is absent")
        return load_private_key(value.encode("utf-8"))
    if use_keychain:
        return load_private_key(keychain_read())
    raise SoftwareEd25519Error("no private key source")


def provision(*, restore_github: bool) -> dict[str, str]:
    """Create or restore the GitHub secret from a Keychain-backed Ed25519 key."""

    if restore_github:
        private_key = load_private_key(keychain_read())
        github_secret_write(private_key_pem(private_key))
        material = public_material(private_key)
        material["action"] = "restored-github-from-keychain"
        return material
    try:
        keychain_read()
    except SoftwareEd25519Error:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key_pem(private_key)
        keychain_write(pem)
        github_secret_write(pem)
        material = public_material(private_key)
        material["action"] = "provisioned"
        return material
    raise SoftwareEd25519Error(
        "Keychain backup already exists; use --restore-github to refill GitHub"
    )


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("interface")

    registry_parser = subparsers.add_parser("registry-candidate")
    registry_parser.add_argument("--public-material", required=True)
    registry_parser.add_argument("--revision", required=True, type=int)
    registry_parser.add_argument("--generated-at", required=True)
    registry_parser.add_argument("--expires-at", required=True)

    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--receipt", required=True)
    sign_parser.add_argument("--signer-registry", required=True)
    sign_parser.add_argument("--pem-file")
    sign_parser.add_argument("--from-env", action="store_true")
    sign_parser.add_argument("--from-keychain", action="store_true")

    public_parser = subparsers.add_parser("public")
    public_parser.add_argument("--pem-file")
    public_parser.add_argument("--from-env", action="store_true")
    public_parser.add_argument("--from-keychain", action="store_true")

    provision_parser = subparsers.add_parser("provision")
    provision_parser.add_argument("--restore-github", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "interface":
            result: Any = interface_contract()
        elif args.command == "registry-candidate":
            result = signer_registry_candidate(
                public_material_value=json.loads(
                    Path(args.public_material).read_text(encoding="utf-8")
                ),
                revision=args.revision,
                generated_at=_parse_timestamp(args.generated_at),
                expires_at=_parse_timestamp(args.expires_at),
            )
        elif args.command == "sign":
            sources = [args.pem_file, args.from_env, args.from_keychain]
            if sum(bool(item) for item in sources) != 1:
                raise SoftwareEd25519Error("choose one private key source")
            private_key = load_private_key_from_sources(
                pem_file=Path(args.pem_file) if args.pem_file else None,
                use_keychain=args.from_keychain,
                use_env=args.from_env,
            )
            receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
            registry = json.loads(
                Path(args.signer_registry).read_text(encoding="utf-8")
            )
            result = sign_receipt(
                receipt, private_key=private_key, signer_registry=registry
            )
        elif args.command == "public":
            sources = [args.pem_file, args.from_env, args.from_keychain]
            if sum(bool(item) for item in sources) != 1:
                raise SoftwareEd25519Error("choose one private key source")
            private_key = load_private_key_from_sources(
                pem_file=Path(args.pem_file) if args.pem_file else None,
                use_keychain=args.from_keychain,
                use_env=args.from_env,
            )
            result = public_material(private_key)
        else:
            result = provision(restore_github=args.restore_github)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
