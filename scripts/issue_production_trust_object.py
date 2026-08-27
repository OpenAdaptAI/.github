"""Prepare and check exact objects emitted by the protected v2 issuers."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import production_trust as trust
import validate_evidence_registry as evidence
import verify_production_release_admission as legacy_verifier

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "production-evidence-policy.json"

AWS_ACCOUNT_ID = "992382684924"
AWS_REGION = "us-east-1"
KMS_ALIAS_ARN = "arn:aws:kms:us-east-1:992382684924:alias/openadapt-production-trust-v1"
KMS_KEY_ARN_PREFIX = "arn:aws:kms:us-east-1:992382684924:key/"
KMS_KEY_SPEC = "ECC_NIST_P256"
KMS_KEY_USAGE = "SIGN_VERIFY"
KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://openadapt.ai/attestations/production-trust-signing/v1"
SIGNING_STATEMENT_SCHEMA = "openadapt.production-trust-signing-statement/v1"
SIGNING_PROFILE = "aws-kms-dsse-p256-sha256"
LIFECYCLE_ACTOR_ID = "774615"

ISSUER_CONTRACTS = {
    "qualification-admission": {
        "workflow": ".github/workflows/issue-qualification-admission.yml",
        "environment": "qualification-admission",
        "validator": trust.validate_qualification_admission,
    },
    "qualification-release": {
        "workflow": ".github/workflows/issue-production-release-admission.yml",
        "environment": "production-release-admission",
        "validator": trust.validate_release,
    },
    "support-release-admission": {
        "workflow": ".github/workflows/issue-support-release-admission.yml",
        "environment": "support-release-admission",
        "validator": trust.validate_support_release,
    },
}

RECOVERY_ENVIRONMENTS = {
    "stage-draft-assets": "release-identity",
    "publish-pypi": "pypi",
    "publish-github-release": "release-identity",
    "publish-mcp-registry": "mcp-registry",
}


class IssuerError(ValueError):
    """The issuer input or trust state is invalid."""


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical_base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_canonical_base64(value: str, *, label: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IssuerError(f"{label} is not canonical base64") from exc
    if canonical_base64(raw) != value:
        raise IssuerError(f"{label} is not canonical base64")
    return raw


def load_candidate_from_environment(
    *, environment_name: str, expected_sha256: str, expected_size_bytes: int
) -> tuple[bytes, dict[str, Any]]:
    encoded = os.environ.get(environment_name)
    if encoded is None:
        raise IssuerError(f"{environment_name} is not set")
    raw = decode_canonical_base64(encoded, label="candidate")
    if len(raw) != expected_size_bytes or sha256(raw) != expected_sha256:
        raise IssuerError("candidate bytes or size differ from the request")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IssuerError("candidate is not JSON") from exc
    if not isinstance(value, dict) or raw != evidence.canonical(value) + b"\n":
        raise IssuerError("candidate must be canonical JSON followed by one LF")
    return raw, value


def git_bytes(root: Path, commit: str, path: str) -> bytes:
    if trust.HEX40.fullmatch(commit) is None:
        raise IssuerError("registry source commit is not exact lowercase hex")
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise IssuerError(f"cannot read {path} from exact commit {commit}")
    return result.stdout


def require_ancestor(root: Path, older: str, newer: str) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise IssuerError("reference registry commit is not in protected main history")


def exact_reference(
    entry: Mapping[str, Any], *, document: Mapping[str, Any], commit: str
) -> dict[str, Any]:
    return {
        "schema_version": evidence.REFERENCE_SCHEMA,
        "repository": evidence.REPOSITORY,
        "repository_id": evidence.REPOSITORY_ID,
        "repository_owner_id": evidence.REPOSITORY_OWNER_ID,
        "registry_source_commit": commit,
        "registry_revision": document["revision"],
        "registry_head_sha256": document["registry_head_sha256"],
        **entry,
    }


def verify_registered_bytes(
    raw: bytes, reference: Mapping[str, Any], label: str
) -> Any:
    if sha256(raw) != reference["object_sha256"] or len(raw) != reference["size_bytes"]:
        raise IssuerError(f"{label} bytes or size differ from the reference")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IssuerError(f"{label} is not JSON") from exc
    identity_value: Any = (
        reference["subject_sha256"]
        if reference["kind"].endswith("-sigstore-bundle")
        else value
    )
    if (
        not reference["kind"].endswith("-sigstore-bundle")
        and raw != evidence.canonical(value) + b"\n"
    ):
        raise IssuerError(f"{label} is not canonical JSON followed by one LF")
    expected_identity = evidence.semantic_identity_digest(
        kind=reference["kind"],
        object_schema_version=reference["object_schema_version"],
        object_value=identity_value,
        object_sha256=reference["object_sha256"],
    )
    if expected_identity != reference["semantic_identity_sha256"]:
        raise IssuerError(f"{label} semantic identity differs")
    return value


class CurrentTrust:
    """Resolve exact historical references against one current protected commit."""

    def __init__(
        self,
        *,
        root: Path,
        source_commit: str,
        now: datetime,
        kms_public_key: Mapping[str, Any],
    ) -> None:
        self.root = root.resolve()
        self.source_commit = source_commit
        self.now = now
        self.kms_public_key = kms_public_key
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if head != source_commit:
            raise IssuerError("issuer source commit is not the checked-out commit")
        self.registry_path = self.root / "evidence-registry.json"
        self.document = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.entries = evidence.validate_registry(self.document, root=self.root)
        self.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        self.signer_pointer, self.signer_registry = self._load_current_signers()
        self.authority_reference, self.authority = self._load_current_state(
            "qualification-authority-state-receipt"
        )
        self.revocation_reference, self.revocation = self._load_current_state(
            "qualification-revocation-state-receipt"
        )
        self._validate_current_state()

    def _load_current_signers(self) -> tuple[dict[str, Any], dict[str, Any]]:
        pointer = evidence._validate_signer_pointer(self.document["signer_registry"])
        if pointer is None:
            raise IssuerError("current registry has no signer registry")
        raw = (self.root / pointer["object_path"]).read_bytes()
        try:
            value = evidence.validate_signer_registry(json.loads(raw))
        except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
            raise IssuerError("current signer registry is invalid") from exc
        if (
            raw != evidence.canonical(value) + b"\n"
            or sha256(raw) != pointer["object_sha256"]
            or evidence.signer_registry_identity_digest(value)
            != pointer["registry_identity_sha256"]
            or value["revision"] != pointer["registry_revision"]
        ):
            raise IssuerError("current signer registry bytes or identity differ")
        generated = evidence._timestamp(value["generated_at"], "generated_at")
        expires = evidence._timestamp(value["expires_at"], "expires_at")
        if not generated <= self.now < expires:
            raise IssuerError("current signer registry is not active")
        return pointer, value

    def _load_current_state(self, kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
        indexes = [
            index for index, entry in enumerate(self.entries) if entry["kind"] == kind
        ]
        if not indexes:
            raise IssuerError(f"current registry has no {kind}")
        index = indexes[-1]
        if index + 1 >= len(self.entries):
            raise IssuerError(f"current {kind} has no adjacent bundle")
        regular = exact_reference(
            self.entries[index], document=self.document, commit=self.source_commit
        )
        bundle = exact_reference(
            self.entries[index + 1],
            document=self.document,
            commit=self.source_commit,
        )
        value = self.resolve_pair(regular, bundle, kind=kind)
        return regular, value

    def _validate_current_state(self) -> None:
        pointer = self.signer_pointer
        signer_identity = pointer["registry_identity_sha256"]
        authority = trust.validate_authority_state(self.authority, now=self.now)
        revocation = trust.validate_revocation_state(self.revocation, now=self.now)
        if (
            authority["signer_registry_sha256"] != pointer["object_sha256"]
            or authority["signer_registry_identity_sha256"] != signer_identity
            or authority["signer_registry_revision"] != pointer["registry_revision"]
            or revocation["signer_registry_sha256"] != signer_identity
            or revocation["authority_state_sha256"]
            != authority["authority_state_sha256"]
        ):
            raise IssuerError(
                "current authority, revocation, or signer binding differs"
            )
        trust.verify_embedded_signature(
            authority,
            signer_registry=self.signer_registry,
            object_schema_version=(
                "openadapt.qualification-authority-state-receipt/v2"
            ),
            signature_domain=trust.AUTHORITY_STATE_SIGNATURE_DOMAIN,
            usage="qualification-authority-state-receipt",
            now=self.now,
        )
        trust.verify_embedded_signature(
            revocation,
            signer_registry=self.signer_registry,
            object_schema_version=(
                "openadapt.qualification-revocation-state-receipt/v1"
            ),
            signature_domain=trust.REVOCATION_STATE_SIGNATURE_DOMAIN,
            usage="qualification-revocation-state-receipt",
            now=self.now,
        )
        for signer in self.signer_registry["signers"]:
            if signer["status"] == "active":
                self.refuse_revoked(
                    "qualification-signer-key", signer["public_key_sha256"]
                )

    def refuse_revoked(self, subject_kind: str, subject_id: str) -> None:
        for item in self.revocation["revocations"]:
            if (
                item["subject_kind"] == subject_kind
                and item["subject_id"] == subject_id
            ):
                raise IssuerError(f"{subject_kind} is revoked")

    def _historical_registry(
        self, reference: Mapping[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        commit = reference["registry_source_commit"]
        require_ancestor(self.root, commit, self.source_commit)
        raw = git_bytes(self.root, commit, "evidence-registry.json")
        try:
            document = json.loads(raw)
            entries = evidence.validate_registry(document)
        except (json.JSONDecodeError, evidence.EvidenceRegistryError) as exc:
            raise IssuerError("reference registry is invalid") from exc
        if (
            document["revision"] != reference["registry_revision"]
            or document["registry_head_sha256"] != reference["registry_head_sha256"]
        ):
            raise IssuerError("reference registry revision or head differs")
        return document, entries

    def resolve_pair(
        self,
        regular_reference: Mapping[str, Any],
        bundle_reference: Mapping[str, Any],
        *,
        kind: str,
    ) -> dict[str, Any]:
        regular, bundle = trust.validate_reference_pair(
            regular_reference, bundle_reference, kind=kind
        )
        historical_document, historical_entries = self._historical_registry(regular)
        if bundle["registry_source_commit"] != regular["registry_source_commit"]:
            raise IssuerError("reference pair source commits differ")
        evidence.require_registered(
            historical_entries, reference=regular, label=f"{kind} object"
        )
        evidence.require_registered(
            historical_entries, reference=bundle, label=f"{kind} bundle"
        )
        evidence.require_registered(
            self.entries, reference=regular, label=f"current {kind} object"
        )
        evidence.require_registered(
            self.entries, reference=bundle, label=f"current {kind} bundle"
        )
        commit = regular["registry_source_commit"]
        regular_raw = git_bytes(self.root, commit, regular["object_path"])
        bundle_raw = git_bytes(self.root, commit, bundle["object_path"])
        value = verify_registered_bytes(regular_raw, regular, kind)
        verify_registered_bytes(bundle_raw, bundle, f"{kind} bundle")
        if not isinstance(value, dict):
            raise IssuerError(f"{kind} is not an object")
        if is_kms_dsse_bundle(bundle_raw):
            validate_kms_bundle(
                subject_raw=regular_raw,
                subject_value=value,
                kind=kind,
                bundle_raw=bundle_raw,
                kms_public_key=self.kms_public_key,
            )
        else:
            legacy_verifier.verify_sigstore(
                regular_raw,
                bundle_raw,
                kind=kind,
                object_value=value,
                policy=self.policy,
            )
        # Keep the full exact-commit validation above even though this value is
        # not otherwise needed. It prevents a current entry from laundering a
        # different historical registry head.
        del historical_document
        return value

    def derive_bundle_reference(
        self, regular_reference: Mapping[str, Any]
    ) -> dict[str, Any]:
        regular = evidence.validate_reference(regular_reference)
        document, entries = self._historical_registry(regular)
        for index, entry in enumerate(entries):
            if entry["registry_entry_sha256"] != regular["registry_entry_sha256"]:
                continue
            if index + 1 >= len(entries):
                break
            return exact_reference(
                entries[index + 1],
                document=document,
                commit=regular["registry_source_commit"],
            )
        raise IssuerError("registered object has no adjacent signature bundle")

    def receipt_for_admission(self, admission: Mapping[str, Any]) -> dict[str, Any]:
        receipt = self.resolve_pair(
            admission["decision_receipt_reference"],
            admission["decision_receipt_bundle_reference"],
            kind="qualification-evidence-decision-receipt",
        )
        trust.verify_embedded_signature(
            receipt,
            signer_registry=self.signer_registry,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v1"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
            usage="qualification-evidence-decision-receipt",
            now=self.now,
        )
        trust._validate_receipt_admission_binding(receipt, admission, now=self.now)
        self.refuse_revoked(
            "qualification-evidence-decision-receipt",
            admission["decision_receipt_reference"]["semantic_identity_sha256"],
        )
        return receipt

    def validate_qualification_admission(self, admission: Mapping[str, Any]) -> None:
        signer_identity = self.signer_pointer["registry_identity_sha256"]
        if (
            admission["signer_registry_sha256"] != signer_identity
            or admission["revocation_state_sha256"]
            != self.revocation["revocation_state_sha256"]
        ):
            raise IssuerError(
                "qualification admission does not bind current trust state"
            )
        self.receipt_for_admission(admission)

    def validate_release_chain(self, release: Mapping[str, Any]) -> None:
        signer_identity = self.signer_pointer["registry_identity_sha256"]
        if (
            release["signer_registry_sha256"] != signer_identity
            or release["authority_state_sha256"]
            != self.authority["authority_state_sha256"]
            or release["revocation_state_sha256"]
            != self.revocation["revocation_state_sha256"]
        ):
            raise IssuerError("release admission does not bind current trust state")
        summary = self.resolve_pair(
            release["production_acceptance_summary_reference"],
            release["production_acceptance_summary_bundle_reference"],
            kind="production-acceptance-summary",
        )
        manifest = self.resolve_pair(
            summary["production_acceptance_manifest_reference"],
            summary["production_acceptance_manifest_bundle_reference"],
            kind="production-acceptance-manifest",
        )
        receipt = self.resolve_pair(
            summary["qualification_evidence_decision_receipt_reference"],
            summary["qualification_evidence_decision_receipt_bundle_reference"],
            kind="qualification-evidence-decision-receipt",
        )
        admission = self.resolve_pair(
            summary["qualification_admission_reference"],
            summary["qualification_admission_bundle_reference"],
            kind="qualification-admission",
        )
        trust.verify_embedded_signature(
            receipt,
            signer_registry=self.signer_registry,
            object_schema_version=(
                "openadapt.qualification-evidence-decision-receipt/v1"
            ),
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
            usage="qualification-evidence-decision-receipt",
            now=self.now,
        )
        trust.validate_release_evidence_chain(
            release,
            summary=summary,
            manifest=manifest,
            receipt=receipt,
            qualification_admission=admission,
            now=self.now,
        )
        for reference in (
            release["production_acceptance_summary_reference"],
            summary["production_acceptance_manifest_reference"],
            summary["qualification_evidence_decision_receipt_reference"],
            summary["qualification_admission_reference"],
        ):
            self.refuse_revoked(
                reference["kind"], reference["semantic_identity_sha256"]
            )

    def validate_support_release(self, release: Mapping[str, Any]) -> None:
        signer_identity = self.signer_pointer["registry_identity_sha256"]
        if (
            release["signer_registry_sha256"] != signer_identity
            or release["authority_state_sha256"]
            != self.authority["authority_state_sha256"]
            or release["revocation_state_sha256"]
            != self.revocation["revocation_state_sha256"]
        ):
            raise IssuerError("Support release does not bind current trust state")


def semantic_identity(kind: str, value: Mapping[str, Any], raw: bytes) -> str:
    schema, _ = evidence.REGULAR_KIND_CONTRACTS[kind]
    return evidence.semantic_identity_digest(
        kind=kind,
        object_schema_version=schema,
        object_value=value,
        object_sha256=sha256(raw),
    )


def is_kms_dsse_bundle(raw: bytes) -> bool:
    """Identify the closed central KMS bundle shape without accepting it."""

    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return (
        isinstance(value, dict)
        and set(value) == {"mediaType", "verificationMaterial", "dsseEnvelope"}
        and isinstance(value.get("verificationMaterial"), dict)
        and set(value["verificationMaterial"]) == {"publicKey"}
        and "dsseEnvelope" in value
    )


def validate_candidate(
    *,
    kind: str,
    raw: bytes,
    value: dict[str, Any],
    source_commit: str,
    now: datetime,
    kms_public_key: Mapping[str, Any],
) -> CurrentTrust:
    contract = ISSUER_CONTRACTS[kind]
    validated = contract["validator"](value, now=now)
    issuer = validated["issuer"]
    expected_issuer = {
        "repository": "OpenAdaptAI/.github",
        "repository_id": "858454062",
        "repository_owner_id": "132681217",
        "workflow": contract["workflow"],
        "ref": "refs/heads/main",
        "source_commit": source_commit,
        "environment": contract["environment"],
    }
    if issuer != expected_issuer:
        raise IssuerError("candidate issuer does not bind this protected workflow")
    current = CurrentTrust(
        root=ROOT,
        source_commit=source_commit,
        now=now,
        kms_public_key=kms_public_key,
    )
    if kind == "qualification-admission":
        current.validate_qualification_admission(validated)
    elif kind == "qualification-release":
        current.validate_release_chain(validated)
    else:
        current.validate_support_release(validated)
    current.refuse_revoked(kind, semantic_identity(kind, value, raw))
    return current


def _hmac(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


class KmsClient:
    """Call only GetPublicKey and Sign with temporary AWS role credentials."""

    def __init__(self, credentials: Mapping[str, str] | None = None) -> None:
        source = os.environ if credentials is None else credentials
        try:
            self.access_key = source["AWS_ACCESS_KEY_ID"]
            self.secret_key = source["AWS_SECRET_ACCESS_KEY"]
            self.session_token = source["AWS_SESSION_TOKEN"]
        except KeyError as exc:
            raise IssuerError("temporary AWS role credentials are not present") from exc
        if not self.access_key or not self.secret_key or not self.session_token:
            raise IssuerError("temporary AWS role credentials are incomplete")
        self.host = f"kms.{AWS_REGION}.amazonaws.com"

    def request(self, target: str, value: Mapping[str, Any]) -> dict[str, Any]:
        body = evidence.canonical(value)
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = now.strftime("%Y%m%d")
        headers = {
            "content-type": "application/x-amz-json-1.1",
            "host": self.host,
            "x-amz-date": amz_date,
            "x-amz-security-token": self.session_token,
            "x-amz-target": target,
        }
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(
            f"{name}:{headers[name].strip()}\n" for name in sorted(headers)
        )
        canonical_request = "\n".join(
            (
                "POST",
                "/",
                "",
                canonical_headers,
                signed_headers,
                hashlib.sha256(body).hexdigest(),
            )
        )
        scope = f"{date}/{AWS_REGION}/kms/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            )
        )
        key_date = _hmac(("AWS4" + self.secret_key).encode("utf-8"), date)
        key_region = hmac.new(
            key_date, AWS_REGION.encode("utf-8"), hashlib.sha256
        ).digest()
        key_service = hmac.new(key_region, b"kms", hashlib.sha256).digest()
        key_signing = hmac.new(key_service, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(
            key_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        authorization = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        request = urllib.request.Request(
            f"https://{self.host}/",
            data=body,
            headers={**headers, "authorization": authorization},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise IssuerError(f"AWS KMS refused {target}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise IssuerError(f"AWS KMS request failed for {target}") from exc
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IssuerError("AWS KMS returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise IssuerError("AWS KMS returned a non-object response")
        return result

    def get_public_key(self) -> dict[str, Any]:
        value = self.request("TrentService.GetPublicKey", {"KeyId": KMS_ALIAS_ARN})
        try:
            key_arn = value["KeyId"]
            key_spec = value["KeySpec"]
            key_usage = value["KeyUsage"]
            algorithms = value["SigningAlgorithms"]
            spki = decode_canonical_base64(value["PublicKey"], label="KMS public key")
        except (KeyError, TypeError) as exc:
            raise IssuerError("AWS KMS public-key response is incomplete") from exc
        if (
            not isinstance(key_arn, str)
            or not key_arn.startswith(KMS_KEY_ARN_PREFIX)
            or key_arn == KMS_KEY_ARN_PREFIX
            or key_spec != KMS_KEY_SPEC
            or key_usage != KMS_KEY_USAGE
            or not isinstance(algorithms, list)
            or KMS_SIGNING_ALGORITHM not in algorithms
            or not spki
        ):
            raise IssuerError("AWS KMS key identity or signing contract differs")
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
            input=spki,
            capture_output=True,
            check=False,
        )
        key_text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        if result.returncode or not any(
            marker in key_text
            for marker in ("ASN1 OID: prime256v1", "NIST CURVE: P-256")
        ):
            raise IssuerError("AWS KMS public key is not a valid P-256 SPKI key")
        return {
            "key_arn": key_arn,
            "key_alias_arn": KMS_ALIAS_ARN,
            "key_spec": key_spec,
            "key_usage": key_usage,
            "signing_algorithm": KMS_SIGNING_ALGORITHM,
            "public_key_spki": spki,
            "public_key_spki_sha256": sha256(spki),
        }

    def sign_digest(self, digest: bytes, *, expected_key_arn: str) -> bytes:
        value = self.request(
            "TrentService.Sign",
            {
                "KeyId": KMS_ALIAS_ARN,
                "Message": canonical_base64(digest),
                "MessageType": "DIGEST",
                "SigningAlgorithm": KMS_SIGNING_ALGORITHM,
            },
        )
        if value.get("KeyId") != expected_key_arn:
            raise IssuerError("AWS KMS changed the resolved signing key")
        try:
            signature = decode_canonical_base64(
                value["Signature"], label="KMS signature"
            )
        except KeyError as exc:
            raise IssuerError("AWS KMS signature response is incomplete") from exc
        if not signature:
            raise IssuerError("AWS KMS returned an empty signature")
        return signature


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_raw = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(type_raw)).encode("ascii"),
            type_raw,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


def one_use_identity(value: Mapping[str, Any], semantic: str) -> dict[str, str]:
    for field in (
        "authorization_id_sha256",
        "admission_id_sha256",
        "decision_identity_sha256",
        "authority_state_sha256",
        "revocation_state_sha256",
        "checkpoint_id_sha256",
        "handoff_id_sha256",
    ):
        identity = value.get(field)
        if isinstance(identity, str) and identity:
            return {"field": field, "value": identity}
    return {"field": "semantic_identity_sha256", "value": semantic}


def object_contract(kind: str) -> tuple[str, str]:
    if kind == "production-publication-effect-authorization":
        return (
            "openadapt.production-publication-effect-authorization/v1",
            "application/vnd.openadapt.production-publication-effect-authorization+json;version=1",
        )
    contract = evidence.REGULAR_KIND_CONTRACTS.get(kind)
    if contract is None:
        raise IssuerError(f"{kind} is not a supported signing subject")
    return contract


def signing_snapshot(current: CurrentTrust) -> dict[str, Any]:
    return {
        "registry_source_commit": current.source_commit,
        "registry_revision": current.document["revision"],
        "registry_head_sha256": current.document["registry_head_sha256"],
        "signer_registry_object_sha256": current.signer_pointer["object_sha256"],
        "signer_registry_identity_sha256": current.signer_pointer[
            "registry_identity_sha256"
        ],
        "signer_registry_revision": current.signer_pointer["registry_revision"],
        "authority_state_sha256": current.authority["authority_state_sha256"],
        "authority_state_semantic_identity_sha256": current.authority_reference[
            "semantic_identity_sha256"
        ],
        "revocation_state_sha256": current.revocation["revocation_state_sha256"],
        "revocation_state_semantic_identity_sha256": current.revocation_reference[
            "semantic_identity_sha256"
        ],
    }


TRUST_STATE_FIELDS = {
    "registry_source_commit",
    "registry_revision",
    "registry_head_sha256",
    "signer_registry_object_sha256",
    "signer_registry_identity_sha256",
    "signer_registry_revision",
    "authority_state_sha256",
    "authority_state_semantic_identity_sha256",
    "revocation_state_sha256",
    "revocation_state_semantic_identity_sha256",
}


def validity_projection(value: Mapping[str, Any]) -> dict[str, str]:
    issued = value.get("issued_at", value.get("generated_at"))
    not_before = value.get("not_before", issued)
    expires = value.get("expires_at")
    if not all(
        isinstance(item, str) and item for item in (issued, not_before, expires)
    ):
        raise IssuerError("signed object has no complete validity window")
    return {"issued_at": issued, "not_before": not_before, "expires_at": expires}


def signing_statement(
    *,
    subject_raw: bytes,
    subject_value: Mapping[str, Any],
    kind: str,
    trust_state: Mapping[str, Any],
    kms_public_key: Mapping[str, Any],
) -> dict[str, Any]:
    schema, media = object_contract(kind)
    if subject_value.get("schema_version") != schema:
        raise IssuerError("signed object schema differs from its kind")
    issuer = subject_value.get("issuer")
    if not isinstance(issuer, dict):
        raise IssuerError("signed object has no closed source issuer")
    object_sha = sha256(subject_raw)
    semantic = (
        semantic_identity(kind, subject_value, subject_raw)
        if kind in evidence.REGULAR_KIND_CONTRACTS
        else trust.digest_bytes(
            b"OpenAdapt production transient trust object identity v1\0",
            {
                "kind": kind,
                "object_schema_version": schema,
                "object_sha256": object_sha,
                "object": subject_value,
            },
        )
    )
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": kind,
                "digest": {"sha256": object_sha.removeprefix("sha256:")},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "schema_version": SIGNING_STATEMENT_SCHEMA,
            "profile": SIGNING_PROFILE,
            "object": {
                "kind": kind,
                "schema_version": schema,
                "media_type": media,
                "sha256": object_sha,
                "size_bytes": len(subject_raw),
                "semantic_identity_sha256": semantic,
            },
            "source_issuer": issuer,
            "trust_state": dict(trust_state),
            "validity": validity_projection(subject_value),
            "one_use_identity": one_use_identity(subject_value, semantic),
            "signer": {
                "aws_account_id": AWS_ACCOUNT_ID,
                "aws_region": AWS_REGION,
                "kms_key_arn": kms_public_key["key_arn"],
                "kms_key_alias_arn": KMS_ALIAS_ARN,
                "public_key_spki_sha256": kms_public_key["public_key_spki_sha256"],
                "key_spec": KMS_KEY_SPEC,
                "key_usage": KMS_KEY_USAGE,
                "signing_algorithm": KMS_SIGNING_ALGORITHM,
            },
        },
    }


def verify_ecdsa_signature(
    *, public_key_spki: bytes, signature: bytes, signed_bytes: bytes
) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        public_key_path = directory / "public-key.der"
        signature_path = directory / "signature.der"
        message_path = directory / "message.bin"
        public_key_path.write_bytes(public_key_spki)
        signature_path.write_bytes(signature)
        message_path.write_bytes(signed_bytes)
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_path),
                "-keyform",
                "DER",
                "-signature",
                str(signature_path),
                str(message_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode or result.stdout.strip() != "Verified OK":
        raise IssuerError("AWS KMS DSSE signature verification failed")


def bundle_bytes(
    *, payload: bytes, signature: bytes, kms_public_key: Mapping[str, Any]
) -> bytes:
    key_id = kms_public_key["public_key_spki_sha256"]
    value = {
        "mediaType": evidence.BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {"publicKey": {"hint": key_id}},
        "dsseEnvelope": {
            "payload": canonical_base64(payload),
            "payloadType": DSSE_PAYLOAD_TYPE,
            "signatures": [{"keyid": key_id, "sig": canonical_base64(signature)}],
        },
    }
    return evidence.canonical(value) + b"\n"


def validate_kms_bundle(
    *,
    subject_raw: bytes,
    subject_value: Mapping[str, Any],
    kind: str,
    bundle_raw: bytes,
    kms_public_key: Mapping[str, Any],
    expected_trust_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        bundle = json.loads(bundle_raw)
    except json.JSONDecodeError as exc:
        raise IssuerError("signature bundle is not JSON") from exc
    if bundle_raw != evidence.canonical(bundle) + b"\n":
        raise IssuerError("signature bundle is not canonical JSON followed by one LF")
    if (
        not isinstance(bundle, dict)
        or set(bundle) != {"mediaType", "verificationMaterial", "dsseEnvelope"}
        or bundle["mediaType"] != evidence.BUNDLE_MEDIA_TYPE
    ):
        raise IssuerError("signature bundle top-level contract differs")
    key_id = kms_public_key["public_key_spki_sha256"]
    if bundle["verificationMaterial"] != {"publicKey": {"hint": key_id}}:
        raise IssuerError("signature bundle public-key identifier differs")
    envelope = bundle["dsseEnvelope"]
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"payloadType", "payload", "signatures"}
        or envelope["payloadType"] != DSSE_PAYLOAD_TYPE
    ):
        raise IssuerError("signature bundle DSSE envelope differs")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise IssuerError("signature bundle must contain exactly one signature")
    signature_value = signatures[0]
    if (
        not isinstance(signature_value, dict)
        or set(signature_value) != {"keyid", "sig"}
        or signature_value["keyid"] != key_id
    ):
        raise IssuerError("signature bundle signature identity differs")
    payload = decode_canonical_base64(envelope["payload"], label="DSSE payload")
    signature = decode_canonical_base64(signature_value["sig"], label="DSSE signature")
    if not signature:
        raise IssuerError("signature bundle contains an empty signature")
    try:
        statement = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise IssuerError("DSSE signing statement is not JSON") from exc
    if payload != evidence.canonical(statement):
        raise IssuerError("DSSE signing statement is not canonical JSON")
    if not isinstance(statement, dict) or set(statement) != {
        "_type",
        "subject",
        "predicateType",
        "predicate",
    }:
        raise IssuerError("DSSE signing statement fields differ")
    predicate = statement["predicate"]
    if not isinstance(predicate, dict) or set(predicate) != {
        "schema_version",
        "profile",
        "object",
        "source_issuer",
        "trust_state",
        "validity",
        "one_use_identity",
        "signer",
    }:
        raise IssuerError("DSSE signing predicate fields differ")
    trust_state = predicate["trust_state"]
    if not isinstance(trust_state, dict) or set(trust_state) != TRUST_STATE_FIELDS:
        raise IssuerError("DSSE signing trust state fields differ")
    issuer = subject_value.get("issuer")
    if (
        not isinstance(issuer, dict)
        or trust_state["registry_source_commit"] != issuer.get("source_commit")
        or (
            "signer_registry_sha256" in subject_value
            and subject_value["signer_registry_sha256"]
            != trust_state["signer_registry_identity_sha256"]
        )
        or (
            "authority_state_sha256" in subject_value
            and subject_value["authority_state_sha256"]
            != trust_state["authority_state_sha256"]
        )
        or (
            "revocation_state_sha256" in subject_value
            and subject_value["revocation_state_sha256"]
            != trust_state["revocation_state_sha256"]
        )
    ):
        raise IssuerError("DSSE signing object trust binding differs")
    if expected_trust_state is not None and trust_state != dict(expected_trust_state):
        raise IssuerError("DSSE signing trust state differs")
    expected = signing_statement(
        subject_raw=subject_raw,
        subject_value=subject_value,
        kind=kind,
        trust_state=trust_state,
        kms_public_key=kms_public_key,
    )
    if statement != expected:
        raise IssuerError("DSSE signing statement does not bind the exact subject")
    verify_ecdsa_signature(
        public_key_spki=kms_public_key["public_key_spki"],
        signature=signature,
        signed_bytes=dsse_pae(DSSE_PAYLOAD_TYPE, payload),
    )
    return {
        "subject_sha256": sha256(subject_raw),
        "subject_size_bytes": len(subject_raw),
        "bundle_sha256": sha256(bundle_raw),
        "bundle_size_bytes": len(bundle_raw),
        "bundle_base64": canonical_base64(bundle_raw),
        "kms_key_arn": kms_public_key["key_arn"],
        "kms_public_key_sha256": kms_public_key["public_key_spki_sha256"],
    }


def sign_subject(
    *,
    subject_raw: bytes,
    subject_value: Mapping[str, Any],
    kind: str,
    current: CurrentTrust,
    client: KmsClient,
    kms_public_key: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    snapshot = signing_snapshot(current)
    statement = signing_statement(
        subject_raw=subject_raw,
        subject_value=subject_value,
        kind=kind,
        trust_state=snapshot,
        kms_public_key=kms_public_key,
    )
    payload = evidence.canonical(statement)
    signature = client.sign_digest(
        hashlib.sha256(dsse_pae(DSSE_PAYLOAD_TYPE, payload)).digest(),
        expected_key_arn=kms_public_key["key_arn"],
    )
    raw = bundle_bytes(
        payload=payload, signature=signature, kms_public_key=kms_public_key
    )
    result = validate_kms_bundle(
        subject_raw=subject_raw,
        subject_value=subject_value,
        kind=kind,
        bundle_raw=raw,
        kms_public_key=kms_public_key,
        expected_trust_state=snapshot,
    )
    return raw, result


def recovery_environment(effect: str, *, target: str | None = None) -> str:
    environment = RECOVERY_ENVIRONMENTS.get(effect)
    if environment is None:
        raise IssuerError("recovery effect is not supported")
    if effect == "publish-mcp-registry" and target != "agent":
        raise IssuerError("only Agent can publish to the MCP registry")
    return environment


def recovery_request_reference(encoded: str) -> dict[str, Any]:
    raw = decode_canonical_base64(encoded, label="qualification release reference")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IssuerError("qualification release reference is not JSON") from exc
    if not isinstance(value, dict) or raw != evidence.canonical(value) + b"\n":
        raise IssuerError(
            "qualification release reference must be canonical JSON followed by one LF"
        )
    return evidence.validate_reference(value)


def append_outputs(path: Path, values: Mapping[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for name, value in values.items():
            if "\n" in str(value):
                raise IssuerError(f"output {name} contains a newline")
            handle.write(f"{name}={value}\n")


def command_issue_candidate(args: argparse.Namespace) -> None:
    raw, value = load_candidate_from_environment(
        environment_name=args.candidate_base64_env,
        expected_sha256=args.expected_sha256,
        expected_size_bytes=args.expected_size_bytes,
    )
    now = datetime.now(timezone.utc)
    client = KmsClient()
    kms_public_key = client.get_public_key()
    current = validate_candidate(
        kind=args.kind,
        raw=raw,
        value=value,
        source_commit=args.source_commit,
        now=now,
        kms_public_key=kms_public_key,
    )
    Path(args.output).write_bytes(raw)
    bundle_raw, result = sign_subject(
        subject_raw=raw,
        subject_value=value,
        kind=args.kind,
        current=current,
        client=client,
        kms_public_key=kms_public_key,
    )
    Path(args.bundle_output).write_bytes(bundle_raw)
    branch = f"trust-review/{args.kind}/{args.expected_sha256.removeprefix('sha256:')}"
    if args.github_output:
        append_outputs(Path(args.github_output), {"review_branch": branch, **result})


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    candidate = commands.add_parser("issue-candidate")
    candidate.add_argument("--kind", choices=sorted(ISSUER_CONTRACTS), required=True)
    candidate.add_argument("--candidate-base64-env", required=True)
    candidate.add_argument("--expected-sha256", required=True)
    candidate.add_argument("--expected-size-bytes", type=int, required=True)
    candidate.add_argument("--source-commit", required=True)
    candidate.add_argument("--output", required=True)
    candidate.add_argument("--bundle-output", required=True)
    candidate.add_argument("--github-output")
    candidate.set_defaults(function=command_issue_candidate)

    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.function(args)
    except (
        IssuerError,
        evidence.EvidenceRegistryError,
        trust.TrustError,
        KeyError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
