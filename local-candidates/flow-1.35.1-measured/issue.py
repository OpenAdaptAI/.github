#!/usr/bin/env python3
"""Prepare, then explicitly sign, a measured one-bundle Flow admission.

The private mapping and bundle verification proof are reviewed inputs, not a
public qualification harness. Every file reference is relative to its owning
JSON file and binds SHA-256 and size. Unsigned preparation is the default and
never reads a key, consumes a request, or changes a registry. Each later phase
requires the SHA-256 of its exact unsigned plan. Dependency references must name
pairs at actual containing commits. The immediate receipt/workflow and
summary/release edges require protected main. Other storage references may name
committed branches that the reviewed merge preserves. The caller keeps the state directory permanently, including unknown
outcomes. Re-running an interrupted request only reconciles the original result.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import production_trust as trust
import public_trust_kms as public_trust
import qualification_issuer as issuer
import qualification_software_ed25519 as software
import stage_production_evidence as stage
import validate_evidence_registry as evidence
import verify_production_release_admission as verifier

_SPEC = importlib.util.spec_from_file_location(
    "measured_flow_verifier", ROOT / "local-candidates/flow-1.35.0-measured/prepare.py"
)
assert _SPEC and _SPEC.loader
measured = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(measured)

SUBJECT_FIELDS = {
    "bundle_content_digest",
    "workflow_contract_sha256",
    "parameter_schema_sha256",
    "governed_policy_contract_sha256",
    "governed_runtime_inputs_digest",
    "governed_qualification_project_contract_sha256",
    "observed_application_sha256",
    "observed_application_version_sha256",
    "observed_environment_digest",
    "observed_environment_binding_sha256",
    "qualification_environment_observer_id",
    "qualification_environment_observer_contract_sha256",
}
# These are byte commitments. Existing authority, signer and revocation identities
# instead come from verified current signed state; they are not new measurements.
FILE_COMMITMENTS = {
    "decision_identity_sha256",
    "decision_commitment_sha256",
    "evidence_manifest_sha256",
    "evidence_manifest_readback_sha256",
    "campaign_artifact_sha256",
    "organization_id_sha256",
    "workflow_id_sha256",
    "workflow_version_id_sha256",
    "bundle_sha256",
    "admitted_runtime_sha256",
    "application_contract_sha256",
    "environment_contract_sha256",
    "input_contract_sha256",
    "action_contract_sha256",
    "identity_contract_sha256",
    "effect_contract_sha256",
    "policy_contract_sha256",
    "campaign_permit_sha256",
}
KINDS = {
    "receipt": "qualification-evidence-decision-receipt",
    "workflow": "qualification-admission",
    "manifest": "production-acceptance-manifest",
    "summary": "production-acceptance-summary",
    "release": "qualification-release",
}


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return evidence.canonical(value) + b"\n"


def fail(message: str) -> None:
    raise ValueError(message)


def checked_file(owner: Path, reference: dict) -> tuple[Path, bytes]:
    """Read an exact retained file without allowing traversal or symlink aliases."""
    if not isinstance(reference, dict):
        fail("file reference must be an object")
    relative = Path(reference.get("path", ""))
    base = owner.resolve().parent
    if not reference.get("path") or relative.is_absolute() or ".." in relative.parts:
        fail("file reference must remain inside its owning directory")
    path = base / relative
    if any(part.is_symlink() for part in (path, *path.parents) if part != base.parent):
        fail("file reference contains a symlink")
    if not path.resolve().is_relative_to(base) or not path.is_file():
        fail("file reference is not a retained regular file")
    raw = path.read_bytes()
    if (
        type(reference.get("size_bytes")) is not int
        or reference["size_bytes"] != len(raw)
        or reference.get("sha256") != sha(raw)
    ):
        fail("retained file bytes differ from their reviewed commitment")
    return path, raw


def checked_json(owner: Path, reference: dict) -> tuple[Path, dict]:
    path, raw = checked_file(owner, reference)
    return path, json.loads(raw)


def subject(value: dict) -> dict:
    trust.closed(value, SUBJECT_FIELDS, "native admitted subject")
    if any(not isinstance(v, str) or not v for v in value.values()):
        fail("every native subject field must be explicit and nonempty")
    return value


def verify_bundle(
    owner: Path, reference: dict, proof_reference: dict, expected: dict
) -> dict:
    archive_path, archive_raw = checked_file(owner, reference)
    proof_path, proof = checked_json(owner, proof_reference)
    if (
        proof.get("schema_version") != "openadapt.measured-bundle-verification/v1"
        or proof.get("verified") is not True
        or proof.get("bundle_archive_sha256") != sha(archive_raw)
        or subject(proof.get("admitted_subject")) != expected
    ):
        fail("reviewed encrypted-bundle verification does not bind this subject")
    checked_file(proof_path, proof.get("verifier"))
    members = proof.get("bundle_members", [])
    indexed = {item["path"]: item for item in members}
    if not indexed or len(indexed) != len(members):
        fail("encrypted bundle member inventory is empty or duplicated")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) != len(indexed) or {i.filename for i in infos} != set(indexed):
            fail("encrypted archive members differ from reviewed proof")
        for info in infos:
            path = Path(info.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or info.is_dir()
                or stat.S_ISLNK(info.external_attr >> 16)
            ):
                fail("encrypted bundle archive member is not a safe regular file")
            raw = archive.read(info)
            item = indexed[info.filename]
            if sha(raw) != item["sha256"] or len(raw) != item["size_bytes"]:
                fail("encrypted bundle member bytes differ")
    return proof


def replay_ledger_record(raw: bytes, *, key: str, primary: dict) -> tuple:
    """Read the verified snapshot bytes without opening or migrating a live ledger."""
    if not raw.startswith(b"SQLite format 3\x00"):
        fail("replay ledger snapshot must contain the actual SQLite v3 ledger")
    run_id = primary.get("run_id_sha256")
    if (
        not isinstance(run_id, str)
        or not run_id
        or primary.get("transaction_outcome") != "VERIFIED"
    ):
        fail("replay proof needs the actual verified initial run identity")
    try:
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(raw)
            connection.execute("PRAGMA query_only = ON")
            metadata = connection.execute(
                "SELECT schema_version, namespace, owner_path FROM ledger_metadata WHERE singleton = 1"
            ).fetchall()
            if (
                len(metadata) != 1
                or metadata[0][0] != "openadapt.idempotency-ledger/v3"
                or any(not isinstance(v, str) or not v for v in metadata[0])
            ):
                fail(
                    "retained replay ledger metadata differs from the native v3 schema"
                )
            rows = connection.execute(
                "SELECT run_id, reserved_at, outcome FROM reservations WHERE namespace = ? AND reservation_key = ?",
                (metadata[0][1], key),
            ).fetchall()
            if (
                len(rows) != 1
                or not isinstance(rows[0][0], str)
                or not rows[0][0]
                or hashlib.sha256(rows[0][0].encode("utf-8")).hexdigest() != run_id
                or rows[0][2] != "VERIFIED"
                or not isinstance(rows[0][1], str)
                or not rows[0][1]
            ):
                fail(
                    "retained replay ledger does not bind the same key to the verified initial run"
                )
            return (*metadata[0], *rows[0])
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValueError(
            "retained replay ledger is not a readable native SQLite snapshot"
        ) from exc


def verify_subjects(
    manifest_path: Path, manifest: dict, expected: dict, prior: dict | None
) -> None:
    if subject(manifest.get("admitted_subject")) != expected:
        fail("measured manifest admitted subject differs from mapping")
    tasks = {t["task_id"] for t in manifest["trials"]}
    if len(tasks) != 1:
        fail("this admission requires one task and one admitted bundle")
    inventory = {item["path"]: item for item in manifest["artifacts"]}
    seen_primary = set()

    def inventoried(ref):
        item = inventory.get(ref.get("path"))
        if item is None or item["sha256"] != ref.get("sha256"):
            fail("replay proof reference is absent from verified inventory")
        return checked_file(manifest_path, item)

    for trial in manifest["trials"]:
        _, observation = checked_json(
            manifest_path, inventory[trial["observation"]["path"]]
        )
        counter_source = observation.get("counter_source", {})
        _, source_raw = inventoried(counter_source.get("observation", {}))
        source_rows = json.loads(source_raw)
        row_index = counter_source.get("row_index")
        if (
            not isinstance(source_rows, list)
            or type(row_index) is not int
            or row_index < 0
            or row_index >= len(source_rows)
        ):
            fail("counter source must select an actual retained observation row")
        row = source_rows[row_index]
        if (
            row.get("passed") is not True
            or row.get("errors") != []
            or row.get("runtime_version") != manifest["runtime"]["version"]
            or any(
                row.get(k) != trial[k]
                for k in ("class", "task_id", "condition", "trial", "counters")
            )
        ):
            fail(
                "normalized counters or trial identity differ from the actual passing source row"
            )

        def report_bindings(reports):
            if not isinstance(reports, list) or not reports:
                fail("source row must retain its actual native reports")
            bindings = []
            for item in reports:
                if not isinstance(item, dict) or any(
                    not isinstance(item.get(k), str) or not item[k]
                    for k in ("path", "role", "bundle_role")
                ):
                    fail("native report source binding is incomplete")
                # Producer paths are campaign-root relative, unchanged by normalization.
                path = Path(item["path"])
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or str(path) != item["path"]
                ):
                    fail("native report source path is not canonical campaign-relative")
                bindings.append((item["path"], item["role"], item["bundle_role"]))
            if len({item[0] for item in bindings}) != len(bindings):
                fail("native report source binding contains duplicate paths")
            return sorted(bindings)

        if report_bindings(row.get("native_reports")) != report_bindings(
            observation["reports"]
        ):
            fail("normalized native reports do not belong to the counted source row")
        if trial["class"] == "governed_repair":
            if prior is None:
                fail("governed repair requires an explicit prior bundle subject")
            _, transition_raw = inventoried(
                observation.get("repair_transition_verification", {})
            )
            transition = json.loads(transition_raw)
            _, approval_raw = inventoried(transition["candidate_approval"])
            _, pointer_raw = inventoried(transition["active_pointer"])
            approval, pointer = json.loads(approval_raw), json.loads(pointer_raw)
            prior_digest = prior["bundle_content_digest"]
            admitted_digest = expected["bundle_content_digest"]
            if (
                transition.get("prior_bundle_content_digest") != prior_digest
                or transition.get("proposed_bundle_content_digest") != admitted_digest
                or transition.get("active_bundle_content_digest") != admitted_digest
                or approval.get("prior_content_digest") != prior_digest
                or approval.get("proposed_content_digest") != admitted_digest
                or not isinstance(approval.get("approved_by"), str)
                or not approval["approved_by"]
                or pointer.get("mode") != "active"
                or pointer.get("active_digest") != admitted_digest
            ):
                fail(
                    "actual repair approval and ACTIVE pointer do not bind prior and admitted bundles"
                )
        for ref in observation["reports"]:
            _, report = checked_json(manifest_path, inventory[ref["path"]])
            role = ref.get("bundle_role")
            if role == "admitted":
                bound = expected
            elif (
                role == "repair-prior"
                and trial["class"] == "governed_repair"
                and ref.get("role") != "primary"
                and prior is not None
            ):
                bound = prior
            else:
                fail("native report bundle role is missing or is outside its class")
            if ref.get("role") == "replay" and trial["class"] == "idempotency_replay":
                base_fields = {
                    "bundle_content_digest",
                    "workflow_contract_sha256",
                    "parameter_schema_sha256",
                }
                if (
                    role != "admitted"
                    or report.get("idempotent_replay") is not True
                    or report.get("success") is not False
                    or any(report.get(k) != expected[k] for k in base_fields)
                    or any(
                        report.get(k) is not None for k in SUBJECT_FIELDS - base_fields
                    )
                ):
                    fail("early replay refusal does not bind the admitted bundle")
                _, proof_raw = inventoried(
                    observation.get("replay_refusal_verification", {})
                )
                proof = json.loads(proof_raw)
                primary = [
                    r for r in observation["reports"] if r.get("role") == "primary"
                ]
                if (
                    proof.get("schema_version")
                    != "openadapt.idempotent-replay-refusal-verification/v1"
                    or proof.get("report_sha256") != ref["sha256"]
                    or len(primary) != 1
                    or proof.get("primary_report_sha256") != primary[0]["sha256"]
                    or proof.get("same_key") is not True
                    or proof.get("no_new_input") is not True
                ):
                    fail("early replay refusal has no bound same-key/no-input proof")
                _, primary_raw = inventoried(primary[0])
                primary_report = json.loads(primary_raw)
                key = report.get("idempotency_key")
                if (
                    not isinstance(key, str)
                    or not key
                    or primary_report.get("idempotency_key") != key
                ):
                    fail(
                        "primary and replay native idempotency keys must be nonempty and equal"
                    )
                ledger_records = [
                    replay_ledger_record(
                        inventoried(proof[field])[1], key=key, primary=primary_report
                    )
                    for field in ("ledger_before", "ledger_after")
                ]
                if ledger_records[0] != ledger_records[1]:
                    fail("replay changed its initial reservation or ledger authority")
                _, before = inventoried(proof["input_events_before"])
                _, after = inventoried(proof["input_events_after"])
                if before != after:
                    fail("replay refusal produced new input events")
            elif any(report.get(key) != value for key, value in bound.items()):
                fail(
                    "selected native report does not bind its exact declared bundle tuple"
                )
            if ref.get("role") == "primary":
                if role != "admitted" or ref["sha256"] in seen_primary:
                    fail("primary report must be distinct and bind the admitted bundle")
                seen_primary.add(ref["sha256"])


def gh(path: str):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def verify_publication(
    candidate: dict, staging: dict, files: dict, *, api=gh, fetch=verifier.fetch
) -> None:
    """Compare actual public bytes and current release controls with the retained observation."""
    observed = candidate["release_observation"]
    if observed.get("published") is not True:
        fail("an unpublished candidate cannot be admitted")
    trust.validate_staging(staging)
    repo = "OpenAdaptAI/openadapt-flow"
    version = observed["version"]
    tag = f"v{version}"
    release = api(f"repos/{repo}/releases/tags/{tag}")
    if (
        release["draft"]
        or release["prerelease"]
        or release["tag_name"] != tag
        or str(release["id"]) != staging["draft_release_id"]
        or release["author"]["login"] != staging["release_author_login"]
        or staging["target_commitish"] != observed["source_commit"]
        or staging["repository"] != repo
    ):
        fail("retained publication differs from the stable GitHub release")
    tag_object = api(f"repos/{repo}/git/ref/tags/{tag}")["object"]
    for _ in range(4):
        if tag_object["type"] != "tag":
            break
        tag_object = api(f"repos/{repo}/git/tags/{tag_object['sha']}")["object"]
    if tag_object["type"] != "commit" or tag_object["sha"] != observed["source_commit"]:
        fail("published tag source differs")
    immutable = api(f"repos/{repo}/immutable-releases")
    if {key: immutable[key] for key in staging["immutable_releases"]} != staging[
        "immutable_releases"
    ]:
        fail("immutable release controls changed")
    for expected in staging["tag_rulesets"]:
        live = api(f"repos/{repo}/rulesets/{expected['ruleset_id']}")
        projected = {
            "ruleset_id": str(live["id"]),
            **{
                k: live[k]
                for k in ("name", "target", "enforcement", "conditions", "rules")
            },
            "bypass_actors": [
                {**actor, "actor_id": str(actor["actor_id"])}
                for actor in live["bypass_actors"]
            ],
        }
        if any(expected[key] != value for key, value in projected.items()):
            fail("retained tag ruleset differs from current controls")
    pypi = json.loads(fetch(f"https://pypi.org/pypi/openadapt-flow/{version}/json"))
    indexed = {item["filename"]: item for item in pypi["urls"]}
    if len(indexed) != 2 or len(pypi["urls"]) != 2 or set(indexed) != set(files):
        fail("PyPI must expose the exact wheel and sdist")
    for item in observed["artifacts"]:
        name = item["name"]
        published = indexed[name]
        assets = [a for a in release["assets"] if a["name"] == name]
        staged = [a for a in staging["assets"] if a["name"] == name]
        if len(assets) != 1 or len(staged) != 1:
            fail("publication artifact is absent or duplicated")
        asset = assets[0]
        if (
            published["yanked"]
            or "sha256:" + published["digests"]["sha256"] != item["sha256"]
            or published["size"] != item["size_bytes"]
            or asset["state"] != "uploaded"
            or asset.get("digest") != item["sha256"]
            or asset["size"] != item["size_bytes"]
            or str(asset["id"]) != staged[0]["asset_id"]
            or asset["uploader"]["login"] != staged[0]["uploader_login"]
            or str(asset["uploader"]["id"]) != staged[0]["uploader_id"]
        ):
            fail("published artifact identity differs from the candidate")
        for url in (published["url"], asset["browser_download_url"]):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname not in {
                "files.pythonhosted.org",
                "github.com",
            }:
                fail("publication download URL is outside the expected hosts")
            if fetch(url) != files[name]:
                fail("actual published artifact bytes differ from retained bytes")


def prepare_inputs(
    mapping_path: Path, mapping_sha256: str, *, publication_check=verify_publication
) -> dict:
    raw = mapping_path.read_bytes()
    if sha(raw) != mapping_sha256:
        fail("private mapping bytes differ from reviewed hash")
    mapping = json.loads(raw)
    if mapping.get("schema_version") != "openadapt.measured-admission-mapping/v1":
        fail("unsupported measured admission mapping")
    expected = subject(mapping["admitted_subject"])
    prior = mapping.get("repair_prior_subject")
    if prior is not None:
        subject(prior)
        if prior == expected:
            fail("repair prior must differ from admitted subject")
    candidate_path, candidate = checked_json(mapping_path, mapping["candidate"])
    if (
        candidate.get("schema_version")
        != "openadapt.unsigned-measured-release-candidate/v1"
        or candidate.get("evidence_class") != "remote-safe-synthetic"
        or candidate.get("target") != "flow"
        or candidate.get("admission_issued") is not False
        or candidate.get("state") != "ready-for-review"
        or candidate.get("validation_errors")
    ):
        fail("wrong unsigned measured Flow candidate")
    trust.closed(
        mapping["commitments"], FILE_COMMITMENTS, "retained receipt commitments"
    )
    paths, commitments = {}, {}
    for field, reference in mapping["commitments"].items():
        path, data = checked_file(mapping_path, reference)
        paths[field] = path
        commitments[field] = sha(data)
    manifest_path = paths["evidence_manifest_sha256"]
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("candidate_ready") is not True:
        fail("measured manifest has unresolved admission requirements")
    observation = candidate["release_observation"]
    artifacts = observation["artifacts"]
    if len(artifacts) != 2 or {a["kind"] for a in artifacts} != {
        "python-wheel",
        "python-sdist",
    }:
        fail("candidate needs exactly one wheel and one sdist")
    files = {}
    for item in artifacts:
        _, data = checked_file(mapping_path, mapping["publication_files"][item["name"]])
        if sha(data) != item["sha256"] or len(data) != item["size_bytes"]:
            fail("retained publication file differs from candidate")
        files[item["name"]] = data
    wheel = next(a for a in artifacts if a["kind"] == "python-wheel")
    if commitments["admitted_runtime_sha256"] != wheel["sha256"]:
        fail("admitted runtime must commit the actual published wheel bytes")
    summary, measured_evidence = measured.summarize(
        manifest_path, wheel["sha256"], version=observation["version"]
    )
    if (
        candidate["campaign_summary"] != summary
        or candidate["measured_evidence"] != measured_evidence
        or candidate["measured_manifest_sha256"]
        != commitments["evidence_manifest_sha256"]
        or measured_evidence["task_count"] != 1
    ):
        fail(
            "candidate measured counts or manifest differ from the new one-task campaign"
        )
    verify_subjects(manifest_path, manifest, expected, prior)
    verify_bundle(
        mapping_path,
        mapping["commitments"]["bundle_sha256"],
        mapping["bundle_verification"],
        expected,
    )
    bridge_path, bridge = checked_json(mapping_path, mapping["contract_verification"])
    if (
        bridge.get("schema_version") != "openadapt.measured-contract-verification/v1"
        or bridge.get("verified") is not True
        or bridge.get("admitted_subject") != expected
        or bridge.get("bundle_verification_sha256")
        != mapping["bundle_verification"]["sha256"]
        or bridge.get("receipt_commitments") != commitments
    ):
        fail("reviewed contract mapping does not bind every actual receipt commitment")
    checked_file(bridge_path, bridge.get("verifier"))
    # The retained readback and campaign are separately hashed documents, and
    # must explicitly bind the same final manifest and native subject.
    for field in (
        "evidence_manifest_readback_sha256",
        "campaign_artifact_sha256",
        "decision_commitment_sha256",
    ):
        document = json.loads(paths[field].read_bytes())
        if (
            document.get("evidence_manifest_sha256")
            != commitments["evidence_manifest_sha256"]
            or document.get("admitted_subject") != expected
        ):
            fail(
                "retained campaign, decision or readback binds another manifest or subject"
            )
    _, staging = checked_json(mapping_path, mapping["publication_staging"])
    publication_check(candidate, staging, files)
    inventory = {
        "schema_version": "openadapt.production-release-artifact-inventory/v1",
        "target": "flow",
        "claim_scope": "production_flow",
        "artifacts": sorted(
            [
                {
                    **{k: a[k] for k in ("name", "kind", "sha256", "size_bytes")},
                    "media_type": "application/zip"
                    if a["kind"] == "python-wheel"
                    else "application/gzip",
                    "publish_destinations": ["github-release", "pypi"],
                }
                for a in artifacts
            ],
            key=lambda a: (a["kind"], a["name"], a["sha256"]),
        ),
    }
    trust.validate_artifact_inventory(inventory)
    release = {
        "schema_version": "openadapt.production-release-candidate/v1",
        "kind": "package",
        "source_repository": "OpenAdaptAI/openadapt-flow",
        "source_repository_id": "1291376938",
        "source_commit": observation["source_commit"],
        "version": observation["version"],
        "tag": f"v{observation['version']}",
        "deployment_id": None,
        "deployment_sha256": None,
        "artifacts": inventory["artifacts"],
    }
    return {
        "mapping_sha256": mapping_sha256,
        "candidate_sha256": sha(candidate_path.read_bytes()),
        "commitments": commitments,
        "campaign_summary": summary,
        "bundle_version": mapping["bundle_version"],
        "decision_revision": mapping["decision_revision"],
        "release_identity": candidate["proposed_release_identity"],
        "release": release,
        "artifact_inventory": inventory,
        "publication_staging": staging,
    }


class PreviewConsumer:
    """Evaluate the existing issuer without persisting or claiming issuance."""

    def commit_once(self, **_kwargs):
        return {"unsigned_preview": True}


def current_context(source_commit: str, now: datetime) -> dict:
    if verifier.protected_main_commit() != source_commit:
        fail("issuer source must be actual current protected main")
    policy_raw = verifier.fetch(
        verifier.raw_url(source_commit, "production-evidence-policy.json")
    )
    lifecycle_raw = verifier.fetch(
        verifier.raw_url(source_commit, "production-lifecycle-policy.json")
    )
    if (
        policy_raw != (ROOT / "production-evidence-policy.json").read_bytes()
        or lifecycle_raw != (ROOT / "production-lifecycle-policy.json").read_bytes()
    ):
        fail("local reviewed policies differ from current protected main")
    resolver = issuer.GitHubEvidenceResolver(json.loads(policy_raw))
    authority_evidence, revocation_evidence = resolver.current_trust_state(
        registry_source_commit=source_commit
    )
    registry, authority, revocation, expiry = issuer._active_trust_state(
        current_signer_registry=authority_evidence["current_signer_registry"],
        authority_evidence=authority_evidence,
        revocation_evidence=revocation_evidence,
        now=now,
    )
    return {
        "resolver": resolver,
        "registry": registry,
        "authority": authority,
        "revocation": revocation,
        "expiry": expiry,
        "authority_reference": authority_evidence["reference"],
        "revocation_reference": revocation_evidence["reference"],
        "acceptance_policy_sha256": sha(policy_raw),
        "lifecycle_policy_sha256": sha(lifecycle_raw),
    }


def check_release_identity(inputs: dict, source: str) -> None:
    ledger = json.loads(
        verifier.fetch(verifier.raw_url(source, "production-lifecycle-admissions.json"))
    )
    previous = []
    for ref in ledger["admissions"]:
        value = verifier.verify_bytes(
            verifier.fetch(verifier.raw_url(source, ref["object_path"])),
            ref,
            "ledger admission",
        )
        if value.get("target") == "flow":
            previous.append(value)
    if not previous:
        fail("current Flow admission history is missing")
    last = max(previous, key=lambda value: value["release_identity"]["sequence"])
    expected = {
        "schema_version": "openadapt.monotonic-production-release/v1",
        "channel": "production",
        "sequence": last["release_identity"]["sequence"] + 1,
        "previous_admission_sha256": last["admission_id_sha256"],
    }
    if inputs["release_identity"] != expected:
        fail("proposed release identity differs from the current committed ledger")


def resolve_dependency(context: dict, reference: dict, phase: str) -> dict:
    # The canonical resolver fetches the pair and containing registry at the
    # exact actual storage commit. A storage commit need not assert issuer main.
    return context["resolver"].resolve(reference, kind=KINDS[phase])


def receipt_binding(value: dict, inputs: dict, context: dict) -> None:
    for key, digest in inputs["commitments"].items():
        if value.get(key) != digest:
            fail("committed decision receipt differs from reviewed measured inputs")
    if (
        value["campaign_summary"]["classes"] != inputs["campaign_summary"]
        or value["campaign_summary"]["task_count"] != 1
        or value["bundle_version"] != inputs["bundle_version"]
        or value["evidence_authority_contract_sha256"]
        != context["authority"]["evidence_authority_sha256"]
        or value["signer_registry_sha256"]
        != evidence.signer_registry_identity_digest(context["registry"])
        or value["revocation_state_sha256"]
        != context["revocation"]["revocation_state_sha256"]
    ):
        fail("committed decision receipt tuple or current authority differs")


def issuer_identity(source: str, phase: str) -> dict:
    workflow, environment = {
        "receipt": (
            "issue-synthetic-qualification-evidence-decision",
            "synthetic-qualification-evidence-decision",
        ),
        "manifest": ("issue-production-acceptance", "production-acceptance"),
    }[phase]
    is_acceptance = phase == "manifest"
    return {
        "repository": "OpenAdaptAI/openadapt-evals"
        if is_acceptance
        else "OpenAdaptAI/.github",
        "repository_id": "1135998197" if is_acceptance else "858454062",
        "repository_owner_id": "132681217",
        "workflow": f".github/workflows/{workflow}.yml",
        "ref": "refs/heads/main",
        "source_commit": source,
        "environment": environment,
    }


def phase_object(
    inputs: dict, request: dict, context: dict, *, consumer=None
) -> tuple[dict, dict | None]:
    phase = request["phase"]
    source = request["issuer_source_commit"]
    now = trust.require_timestamp(request["issued_at"], "phase issued_at")
    expiry = trust.optional_timestamp(request["expires_at"], "phase expires_at")
    if not trust.expires_contained(expiry, context["expiry"]):
        fail("requested phase validity exceeds current trust")
    window = {k: request[k] for k in ("issued_at", "expires_at")}
    window["not_before"] = request["issued_at"]
    trust.validate_window(window, now=now)
    registry_identity = evidence.signer_registry_identity_digest(context["registry"])
    state = {
        "signer_registry_sha256": registry_identity,
        "authority_state_sha256": context["authority"]["authority_state_sha256"],
        "revocation_state_sha256": context["revocation"]["revocation_state_sha256"],
    }
    resolver = context["resolver"]
    references = request.get("references", {})
    if phase == "receipt":
        inner = [
            s
            for s in context["registry"]["signers"]
            if s["status"] == "active"
            and s["algorithm"] == "ed25519"
            and "qualification-evidence-decision-receipt" in s["allowed_usages"]
            and "https://github.com/OpenAdaptAI/.github/.github/workflows/issue-synthetic-qualification-evidence-decision.yml@refs/heads/main"
            in s["allowed_workflows"]
        ]
        if len(inner) != 1:
            fail("current authority must select exactly one existing decision signer")
        value = {
            "schema_version": "openadapt.qualification-evidence-decision-receipt/v2",
            "evidence_class": "remote-safe-synthetic",
            **inputs["commitments"],
            "decision_revision": inputs["decision_revision"],
            "bundle_version": inputs["bundle_version"],
            "evidence_authority_contract_sha256": context["authority"][
                "evidence_authority_sha256"
            ],
            "signer_registry_sha256": registry_identity,
            "revocation_state_sha256": state["revocation_state_sha256"],
            "entity_class": "record",
            "campaign_summary": {
                "schema_version": "openadapt.qualification-evidence-decision-campaign-summary/v1",
                "minimum_trials_per_task_condition": 3,
                "task_count": 1,
                "classes": inputs["campaign_summary"],
            },
            "verdict": "ADMIT",
            **window,
            "issuer_key_id": inner[0]["key_id"],
            "algorithm": "ed25519",
            "signature": "",
            "signing_statement": {},
            "issuer": issuer_identity(source, "receipt"),
        }
        value["signing_statement"] = trust.signing_statement(
            value,
            object_schema_version=value["schema_version"],
            signature_domain=trust.DECISION_RECEIPT_SIGNATURE_DOMAIN,
        )
        trust.require_positive_int(value["decision_revision"], "decision revision")
        if (
            not isinstance(value["bundle_version"], str)
            or trust.BUNDLE_VERSION.fullmatch(value["bundle_version"]) is None
        ):
            fail("bundle version must be canonical")
        if (
            len(
                {
                    value[k]
                    for k in (
                        "decision_commitment_sha256",
                        "evidence_manifest_sha256",
                        "evidence_manifest_readback_sha256",
                        "campaign_artifact_sha256",
                    )
                }
            )
            != 4
        ):
            fail(
                "decision, manifest, readback and campaign byte commitments must differ"
            )
        # Signature structure is checked only after real signing. The preview
        # deliberately contains an empty signature, never a fabricated one.
        return value, None
    if phase in {"workflow", "release"}:
        dependency = "receipt" if phase == "workflow" else "summary"
        resolved = resolve_dependency(context, references[dependency], dependency)
        if resolved["reference"]["registry_source_commit"] != source:
            fail(
                "immediate issuer dependency must already be committed to protected main"
            )
        if phase == "workflow":
            receipt_binding(resolved["value"], inputs, context)
        else:
            summary = resolved["value"]
            manifest = resolve_dependency(
                context, summary["production_acceptance_manifest_reference"], "manifest"
            )["value"]
            receipt = resolve_dependency(
                context,
                summary["qualification_evidence_decision_receipt_reference"],
                "receipt",
            )["value"]
            receipt_binding(receipt, inputs, context)
            if (
                manifest["release"] != inputs["release"]
                or summary["release_identity"] != inputs["release_identity"]
            ):
                fail("committed acceptance names another release")
        issue_request = {
            "schema_version": "openadapt.qualification-admission-issue-request/v1"
            if phase == "workflow"
            else "openadapt.qualification-release-issue-request/v1",
            "request_handle": request["request_handle"],
            "evidence_class": "remote-safe-synthetic",
            "decision_receipt_reference"
            if phase == "workflow"
            else "production_acceptance_summary_reference": resolved["reference"],
        }
        issue = (
            issuer.issue_workflow_admission
            if phase == "workflow"
            else issuer.issue_release_admission
        )
        value = issue(
            issue_request,
            resolver=resolver,
            issuer_source_commit=source,
            now=now,
            consumer=consumer or PreviewConsumer(),
        )
        # Issuer derives expiry from its signed dependencies; never override it.
        if value["expires_at"] != request["expires_at"]:
            fail("reviewed expiry differs from the existing issuer's dependency window")
        return value, issue_request
    if phase == "manifest":
        receipt = resolve_dependency(context, references["receipt"], "receipt")
        admission = resolve_dependency(context, references["workflow"], "workflow")
        receipt_binding(receipt["value"], inputs, context)
        if admission["value"]["decision_receipt_reference"] != receipt["reference"]:
            fail(
                "workflow admission must preserve its exact original receipt storage reference"
            )
        evals_source = request["acceptance_issuer_source_commit"]
        if (
            gh("repos/OpenAdaptAI/openadapt-evals/git/ref/heads/main")["object"]["sha"]
            != evals_source
        ):
            fail("acceptance issuer must be actual reviewed evals protected main")
        value = {
            "schema_version": "openadapt.production-acceptance/v3",
            "target": "flow",
            "verdict": "accepted",
            "claim_scope": "production_flow",
            **{
                k: context[k]
                for k in ("acceptance_policy_sha256", "lifecycle_policy_sha256")
            },
            "release_identity": inputs["release_identity"],
            "release": inputs["release"],
            "release_sha256": trust.digest_bytes(
                trust.RELEASE_DOMAIN,
                {
                    "target": "flow",
                    "claim_scope": "production_flow",
                    "release": inputs["release"],
                },
            ),
            "artifact_inventory": inputs["artifact_inventory"],
            "artifact_inventory_sha256": trust.artifact_inventory_digest(
                inputs["artifact_inventory"]
            ),
            "publication_staging": inputs["publication_staging"],
            "publication_staging_sha256": trust.staging_digest(
                inputs["publication_staging"]
            ),
            "qualification_evidence_decision_receipt_reference": receipt["reference"],
            "qualification_evidence_decision_receipt_bundle_reference": receipt[
                "bundle_reference"
            ],
            "qualification_admission_reference": admission["reference"],
            "qualification_admission_bundle_reference": admission["bundle_reference"],
            "campaign_summary": inputs["campaign_summary"],
            **state,
            **window,
            "issuer": issuer_identity(evals_source, "manifest"),
        }
        trust.validate_acceptance_manifest(
            value,
            receipt=receipt["value"],
            qualification_admission=admission["value"],
            receipt_signer_registry=receipt["bound_signer_registry"],
            now=now,
        )
        return value, None
    if phase == "summary":
        manifest = resolve_dependency(context, references["manifest"], "manifest")
        value = copy.deepcopy(manifest["value"])
        receipt = resolve_dependency(
            context,
            value["qualification_evidence_decision_receipt_reference"],
            "receipt",
        )
        admission = resolve_dependency(
            context, value["qualification_admission_reference"], "workflow"
        )
        receipt_binding(receipt["value"], inputs, context)
        if (
            value["release"] != inputs["release"]
            or value["release_identity"] != inputs["release_identity"]
            or any(value[k] != v for k, v in state.items())
        ):
            fail("committed acceptance manifest release or current trust differs")
        for field in ("release", "artifact_inventory"):
            value.pop(field)
        value.update(
            schema_version="openadapt.production-lifecycle-evidence-summary/v3",
            production_acceptance_manifest_reference=manifest["reference"],
            production_acceptance_manifest_bundle_reference=manifest[
                "bundle_reference"
            ],
            **window,
        )
        value["evidence_identity_sha256"] = trust.acceptance_summary_identity(value)
        trust.validate_acceptance_summary(
            value,
            manifest=manifest["value"],
            receipt=receipt["value"],
            qualification_admission=admission["value"],
            receipt_signer_registry=receipt["bound_signer_registry"],
            now=now,
        )
        return value, None
    fail("unsupported phase")


def write_exclusive(path: Path, raw: bytes) -> bool:
    """Durably create once; an existing file is never truncated or replaced."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != raw:
            fail("existing durable file differs; reconcile the original operation")
        return False
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def persist_once(plan: dict, state_dir: Path, perform) -> dict:
    """Unknown results never call the issuer again, even with another handle."""
    request = plan["phase_request"]
    issue_request = plan["issue_request"]
    if issue_request:
        dependency = next(
            v for k, v in issue_request.items() if k.endswith("_reference")
        )
        semantic = {
            "phase": request["phase"],
            "dependency_identity_sha256": dependency["semantic_identity_sha256"],
        }
    else:
        semantic = {
            "phase": request["phase"],
            "decision_identity_sha256": plan["inputs"]["commitments"][
                "decision_identity_sha256"
            ],
        }
    identity = sha(canonical(semantic)).removeprefix("sha256:")
    journal = state_dir / f"{identity}.request.json"
    first = write_exclusive(journal, canonical(plan))
    consumer = issuer.SqliteOneUseConsumer(state_dir / "one-use.sqlite3")
    handle = request["request_handle"]
    if first:
        value = perform(consumer)
        if not issue_request:
            consumer.commit_once(
                request_handle=handle,
                operation=f"measured-{request['phase']}",
                request_sha256=sha(canonical(plan)),
                effect_sha256="sha256:" + identity,
                result=canonical(value),
            )
    # Reconcile after every call, including success. A missing durable row is an
    # unknown outcome. Do not delete the journal or generate another request.
    record = consumer.reconcile(request_handle=handle)
    expected_request = (
        issuer._request_digest(issue_request) if issue_request else sha(canonical(plan))
    )
    if record["request_sha256"] != expected_request:
        fail("persistent consumption record belongs to another request")
    value = json.loads(base64.b64decode(record["result_base64"], validate=True))
    if value != plan["unsigned_object"]:
        fail("persisted result differs from the reviewed unsigned plan")
    return value


def sign_pair(
    value: dict, plan: dict, context: dict, *, private_key
) -> tuple[bytes, bytes]:
    request = plan["phase_request"]
    phase = request["phase"]
    now = trust.require_timestamp(request["issued_at"], "phase issued_at")
    if phase == "receipt":
        value = software.sign_receipt(
            value, private_key=private_key, signer_registry=context["registry"]
        )
        trust.validate_receipt(value, signer_registry=context["registry"], now=now)
    key_id = public_trust.software_public_key_id(private_key.public_key())
    signers = [s for s in context["registry"]["signers"] if s["key_id"] == key_id]
    if len(signers) != 1:
        fail("existing Keychain key is absent from current public trust registry")
    kind = KINDS[phase]
    raw = canonical(value)
    entry = stage.entry_for(raw, kind=kind, subject=None)
    statement = {
        "schema_version": public_trust.STATEMENT_SCHEMA,
        "object_kind": kind,
        "object_schema_version": entry["object_schema_version"],
        "object_media_type": entry["object_media_type"],
        "object_sha256": sha(raw),
        "object_size_bytes": len(raw),
        "semantic_identity_sha256": entry["semantic_identity_sha256"],
        "source_issuer": {
            field: value["issuer"][field] for field in public_trust.ISSUER_FIELDS
        },
        "signer_registry_sha256": evidence.signer_registry_identity_digest(
            context["registry"]
        ),
        "authority_state_sha256": context["authority"]["authority_state_sha256"],
        "revocation_state_sha256": context["revocation"]["revocation_state_sha256"],
        "issued_at": request["issued_at"],
        "not_before": request["issued_at"],
        "expires_at": request["expires_at"],
        "request_id_sha256": sha(canonical(plan)),
        "signing_authority": {
            "repository": "OpenAdaptAI/.github",
            "repository_id": "858454062",
            "repository_owner_id": "132681217",
            "workflow": public_trust.SOFTWARE_WORKFLOW_PATH,
            "ref": "refs/heads/main",
            "source_commit": request["issuer_source_commit"],
            "environment": public_trust.SOFTWARE_ENVIRONMENT,
            "key_origin": "software",
        },
        "key_id": key_id,
        "signature_profile": public_trust.SOFTWARE_SIGNATURE_PROFILE,
    }
    public_trust.validate_statement_object_binding(
        statement,
        object_raw=raw,
        object_value=value,
        object_kind=kind,
        object_schema_version=entry["object_schema_version"],
        object_media_type=entry["object_media_type"],
        semantic_identity_sha256=entry["semantic_identity_sha256"],
        expected_signer_registry_sha256=statement["signer_registry_sha256"],
        expected_authority_state_sha256=statement["authority_state_sha256"],
        expected_revocation_state_sha256=statement["revocation_state_sha256"],
    )
    bundle = public_trust.sign_software_bundle(
        statement, private_key=private_key, signer=signers[0], now=now
    )
    return raw, canonical(bundle)


def reconcile_journal(journal: Path, state_dir: Path) -> dict:
    """Read a persisted outcome without keys, network access, or issuer calls."""
    if journal.is_symlink() or not journal.is_file():
        fail("reconciliation requires the retained original request journal")
    plan = json.loads(journal.read_bytes())
    record = issuer.SqliteOneUseConsumer(state_dir / "one-use.sqlite3").reconcile(
        request_handle=plan["phase_request"]["request_handle"]
    )
    request = plan["issue_request"]
    expected = issuer._request_digest(request) if request else sha(canonical(plan))
    if (
        record["request_sha256"] != expected
        or json.loads(base64.b64decode(record["result_base64"], validate=True))
        != plan["unsigned_object"]
    ):
        fail("reconciled result differs from the original reviewed request")
    return {
        "schema_version": "openadapt.measured-admission-reconciliation/v1",
        "unsigned_result": True,
        "consumption_record": record,
    }


def validate_staging_registry(path: Path, source: str, context: dict) -> None:
    current = json.loads(
        verifier.fetch(verifier.raw_url(source, "evidence-registry.json"))
    )
    proposed = json.loads(path.read_bytes())
    evidence.validate_registry(current)
    evidence.validate_registry(proposed, root=path.resolve().parent)
    prefix = current["entries"]
    if (
        proposed["entries"][: len(prefix)] != prefix
        or proposed["signer_registry"] != current["signer_registry"]
        or proposed["signer_registry_history"] != current["signer_registry_history"]
        or proposed["signer_registry"]["registry_identity_sha256"]
        != evidence.signer_registry_identity_digest(context["registry"])
    ):
        fail("staging registry does not append to the verified current trust state")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", type=Path)
    parser.add_argument("--mapping-sha256")
    parser.add_argument("--phase-request", type=Path)
    parser.add_argument(
        "--reconcile-journal",
        type=Path,
        help="Read the original durable result only; no signing or retry",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Explicitly use the existing Keychain signer after exact-plan review",
    )
    parser.add_argument("--reviewed-plan-sha256")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument(
        "--stage-registry",
        type=Path,
        help="Explicit append-only staging after signing; never commits or pushes",
    )
    args = parser.parse_args(argv)
    try:
        if args.reconcile_journal:
            if args.sign or args.stage_registry or not args.state_dir:
                fail("reconciliation requires permanent state and cannot sign or stage")
            result = reconcile_journal(args.reconcile_journal, args.state_dir)
            write_exclusive(args.output, canonical(result))
            print(json.dumps({"reconciled": True, "unsigned_result": True}))
            return 0
        if not args.mapping or not args.mapping_sha256 or not args.phase_request:
            fail("preparation requires mapping, mapping hash, and phase request")
        if not args.sign and (
            args.stage_registry or args.state_dir or args.reviewed_plan_sha256
        ):
            fail("unsigned prepare cannot consume state, stage, or sign")
        if args.sign and (not args.state_dir or not args.reviewed_plan_sha256):
            fail(
                "signing requires exact reviewed plan hash and permanent one-use state directory"
            )
        request = json.loads(args.phase_request.read_bytes())
        if request.get("phase") not in KINDS:
            fail("phase must be receipt, workflow, manifest, summary, or release")
        issuer._request_handle(request["request_handle"])
        now = trust.require_timestamp(request["issued_at"], "phase issued_at")
        live_now = datetime.now(timezone.utc)
        if now > live_now or (live_now - now).total_seconds() > 3600:
            fail("reviewed issue time must be within the last hour")
        inputs = prepare_inputs(args.mapping, args.mapping_sha256)
        context = current_context(request["issuer_source_commit"], live_now)
        check_release_identity(inputs, request["issuer_source_commit"])
        value, issue_request = phase_object(inputs, request, context)
        plan = {
            "schema_version": "openadapt.measured-admission-unsigned-plan/v1",
            "inputs": inputs,
            "phase_request": request,
            "issue_request": issue_request,
            "unsigned_object": value,
            "authority_reference": context["authority_reference"],
            "revocation_reference": context["revocation_reference"],
        }
        raw = canonical(plan)
        if not args.sign:
            write_exclusive(args.output, raw)
            print(
                json.dumps(
                    {
                        "unsigned": True,
                        "plan_sha256": sha(raw),
                        "phase": request["phase"],
                    }
                )
            )
            return 0
        if sha(raw) != args.reviewed_plan_sha256:
            fail("unsigned plan changed after review; signing refused")
        if verifier.protected_main_commit() != request["issuer_source_commit"]:
            fail("protected main moved after verification; prepare and review again")
        if args.stage_registry:
            validate_staging_registry(
                args.stage_registry, request["issuer_source_commit"], context
            )
        value = persist_once(
            plan,
            args.state_dir,
            lambda consumer: phase_object(inputs, request, context, consumer=consumer)[
                0
            ],
        )
        private_key = software.load_private_key(software.keychain_read())
        object_raw, bundle_raw = sign_pair(
            value, plan, context, private_key=private_key
        )
        object_path, bundle_path = (
            args.output / "object.json",
            args.output / "bundle.json",
        )
        write_exclusive(object_path, object_raw)
        write_exclusive(bundle_path, bundle_raw)
        if args.stage_registry and stage.main(
            [
                "--registry",
                str(args.stage_registry),
                "--kind",
                KINDS[request["phase"]],
                "--object",
                str(object_path),
                "--bundle",
                str(bundle_path),
            ]
        ):
            fail(
                "append-only stage failed; reconcile the existing files before continuing"
            )
        print(
            json.dumps(
                {
                    "object_sha256": sha(object_raw),
                    "bundle_sha256": sha(bundle_raw),
                    "phase": request["phase"],
                    "storage_reference": None,
                    "next": "Commit the staged pair; use its actual containing commit for the next dependency reference.",
                }
            )
        )
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
