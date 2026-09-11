#!/usr/bin/env python3
"""Verify measured hosted evidence before using the existing admission issuer.

The fixed producer identity authenticates evidence derivation, not admission
issuance. Raw evidence and oracle recipes stay in private retained storage.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "measured_cloud_shared", ROOT / "local-candidates/flow-1.35.1-measured/issue.py"
)
assert _SPEC and _SPEC.loader
shared = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shared)
trust = shared.trust
PRODUCER_REPOSITORY = "OpenAdaptAI/openadapt-internal"
PRODUCER_REPOSITORY_ID = "1170060695"
PRODUCER_OWNER_ID = "132681217"
PRODUCER_WORKFLOW = ".github/workflows/production-qualification-admission.yml"
PRODUCER_REF = "refs/heads/main"
PRODUCER_IDENTITY = (
    f"https://github.com/{PRODUCER_REPOSITORY}/{PRODUCER_WORKFLOW}@{PRODUCER_REF}"
)
PRODUCER_FIELDS = {
    "repository",
    "repository_id",
    "repository_owner_id",
    "workflow",
    "ref",
    "source_commit",
    "run_id",
    "run_attempt",
}


def strict_json(raw: bytes):
    """Reject alternate interpretations of hash-bound JSON bytes."""

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                shared.fail("duplicate JSON key in retained evidence")
            result[key] = value
        return result

    def invalid_constant(_value):
        shared.fail("non-finite JSON value in retained evidence")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def checked_json(owner: Path, reference: dict):
    path, raw = shared.checked_file(owner, reference)
    return path, strict_json(raw)


def validate_producer(value: dict) -> dict:
    trust.closed(value, PRODUCER_FIELDS, "hosted evidence producer")
    if any(
        value[key] != expected
        for key, expected in {
            "repository": PRODUCER_REPOSITORY,
            "repository_id": PRODUCER_REPOSITORY_ID,
            "repository_owner_id": PRODUCER_OWNER_ID,
            "workflow": PRODUCER_WORKFLOW,
            "ref": PRODUCER_REF,
        }.items()
    ):
        shared.fail("hosted evidence producer differs from the fixed workflow")
    if not isinstance(value["source_commit"], str) or not trust.HEX40.fullmatch(
        value["source_commit"]
    ):
        shared.fail("hosted producer source must be exact")
    for key in ("run_id", "run_attempt"):
        trust.require_decimal_id(value[key], f"producer {key}")
    return value


def validate_provenance_result(result: dict, producer: dict) -> None:
    """Check additional fields only in an already verified SLSA statement."""
    validate_producer(producer)
    predicate = result["statement"]["predicate"]
    definition = predicate["buildDefinition"]
    expected_workflow = {
        "repository": f"https://github.com/{PRODUCER_REPOSITORY}",
        "path": PRODUCER_WORKFLOW,
        "ref": PRODUCER_REF,
    }
    if (
        definition["buildType"] != "https://actions.github.io/buildtypes/workflow/v1"
        or definition["externalParameters"] != {"workflow": expected_workflow}
        or definition["internalParameters"]
        != {
            "github": {
                "event_name": "workflow_dispatch",
                "repository_id": PRODUCER_REPOSITORY_ID,
                "repository_owner_id": PRODUCER_OWNER_ID,
                "runner_environment": "github-hosted",
            }
        }
        or predicate["runDetails"]["builder"] != {"id": PRODUCER_IDENTITY}
        or predicate["runDetails"]["metadata"]["invocationId"]
        != (
            f"https://github.com/{PRODUCER_REPOSITORY}/actions/runs/"
            f"{producer['run_id']}/attempts/{producer['run_attempt']}"
        )
    ):
        shared.fail("verified hosted provenance workflow or invocation differs")


def validate_producer_run(run: dict, producer: dict) -> None:
    validate_producer(producer)
    if (
        type(run.get("id")) is not int
        or str(run["id"]) != producer["run_id"]
        or type(run.get("run_attempt")) is not int
        or str(run["run_attempt"]) != producer["run_attempt"]
        or run.get("head_sha") != producer["source_commit"]
        or run.get("head_branch") != "main"
        or run.get("path") != PRODUCER_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("repository", {}).get("full_name") != PRODUCER_REPOSITORY
        or type(run.get("repository", {}).get("id")) is not int
        or str(run["repository"]["id"]) != PRODUCER_REPOSITORY_ID
        or type(run.get("repository", {}).get("owner", {}).get("id")) is not int
        or str(run["repository"]["owner"]["id"]) != PRODUCER_OWNER_ID
    ):
        shared.fail("actual hosted producer run or attempt differs")


def verify_derivative_provenance(
    owner: Path,
    derivative_raw: bytes,
    producer: dict,
    references: dict,
    *,
    gh=shared.gh,
) -> None:
    """Use fixed-workflow provenance and actual retained and live source readback."""
    validate_producer(producer)
    trust.closed(
        references,
        {
            "attestation",
            "workflow_source",
            "workflow_run",
            "protected_main",
        },
        "hosted derivative provenance references",
    )
    _, bundle_raw = shared.checked_file(owner, references["attestation"])
    _, workflow_raw = shared.checked_file(owner, references["workflow_source"])
    _, retained_run = checked_json(owner, references["workflow_run"])
    _, retained_main = checked_json(owner, references["protected_main"])
    validate_producer_run(retained_run, producer)
    if (
        retained_main.get("ref") != PRODUCER_REF
        or retained_main.get("object", {}).get("sha") != producer["source_commit"]
    ):
        shared.fail("retained producer main differs from the reviewed source")
    sigstore = strict_json((ROOT / "production-evidence-policy.json").read_bytes())[
        "sigstore"
    ]
    verified = shared.verifier.verify_github_attestation(
        derivative_raw,
        bundle_raw,
        identity={
            "issuer_repository": PRODUCER_REPOSITORY,
            "certificate_identity": PRODUCER_IDENTITY,
        },
        issuer_identity={
            "source_commit": producer["source_commit"],
            "ref": PRODUCER_REF,
        },
        sigstore=sigstore,
    )
    validate_provenance_result(verified, producer)
    live_main = gh(f"repos/{PRODUCER_REPOSITORY}/git/ref/heads/main")
    if live_main.get("object", {}).get("sha") != producer["source_commit"]:
        shared.fail("actual producer protected main changed after review")
    run = gh(
        f"repos/{PRODUCER_REPOSITORY}/actions/runs/{producer['run_id']}"
        f"/attempts/{producer['run_attempt']}"
    )
    validate_producer_run(run, producer)
    source = gh(
        f"repos/{PRODUCER_REPOSITORY}/contents/{PRODUCER_WORKFLOW}"
        f"?ref={producer['source_commit']}"
    )
    if (
        source.get("encoding") != "base64"
        or source.get("type") != "file"
        or source.get("path") != PRODUCER_WORKFLOW
        or base64.b64decode(source["content"].replace("\n", ""), validate=True)
        != workflow_raw
    ):
        shared.fail("actual producer workflow bytes differ from the reviewed file")


DERIVATIVE_FIELDS = {
    "schema_version",
    "target",
    "scope",
    "producer",
    "validator",
    "subject",
    "campaign_id",
    "receipt_commitments",
    "raw_evidence_refs",
    "groups",
}
SUBJECT_FIELDS = {
    "source_commit",
    "deployment_manifest_sha256",
    "runtime_build_identity_sha256",
    "runtime_manifest_sha256",
    "environment_digest",
    "evidence_identity_sha256",
    "bundle_artifact_sha256",
    "bundle_content_digest",
    "runtime_wheel_sha256",
}
GROUP_FIELDS = {
    "trial_id",
    "task",
    "condition",
    "campaign_class",
    "ordinal",
    "phases",
    "observer_before_sha256",
    "observer_after_sha256",
    "counts",
}
PHASE_FIELDS = {
    "phase",
    "qualification_run_id_sha256",
    "run_report_sha256",
    "runner_receipt_sha256",
    "input_sha256",
    "auxiliary_artifacts",
}
GROUP_COUNT_FIELDS = trust.CAMPAIGN_COUNT_FIELDS - {
    "task_condition_cell_count",
    "minimum_trials_per_cell",
    "observed_trial_count",
}
PHASES = {
    "healthy": ({"primary"}, "primary"),
    "safe_halt": ({"primary"}, "primary"),
    "idempotency_replay": ({"primary", "replay"}, "primary"),
    "uncertain_delivery": ({"primary"}, "primary"),
    "declared_attended": (
        {"primary", "attended_continuation"},
        "attended_continuation",
    ),
    "governed_repair": ({"repair_prior", "repair_canary"}, "repair_canary"),
}


def raw_digest(value, label: str) -> str:
    # The hosted grammar uses plain digests; canonical receipts add their prefix.
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        shared.fail(f"{label} must be a plain lowercase SHA-256 digest")
    return value


def strict_count(value, label: str, *, minimum=0) -> int:
    if type(value) is not int or not minimum <= value <= 9007199254740991:
        shared.fail(f"{label} must be an explicit safe integer")
    return value


def identifier(value, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        shared.fail(f"{label} must be explicit and bounded")
    return value


def uuid_identifier(value, label: str) -> str:
    from uuid import UUID

    if not isinstance(value, str) or str(UUID(value)) != value:
        shared.fail(f"{label} must be a canonical UUID")
    return value


def evidence_references(value: list) -> list[dict]:
    if not isinstance(value, list):
        shared.fail("evidence references must be an explicit list")
    keys = []
    for item in value:
        trust.closed(item, {"role", "sha256"}, "raw evidence reference")
        keys.append(
            (
                identifier(item["role"], "evidence role"),
                raw_digest(item["sha256"], "evidence hash"),
            )
        )
    if keys != sorted(set(keys)):
        shared.fail("evidence references must be sorted and unique")
    return value


def retained_inventory(owner: Path, references: list) -> dict[str, tuple[Path, bytes]]:
    if not isinstance(references, list) or not references:
        shared.fail("retained evidence inventory must be nonempty")
    result, paths = {}, set()
    for reference in references:
        trust.closed(
            reference, {"path", "sha256", "size_bytes"}, "retained evidence file"
        )
        path, raw = shared.checked_file(owner, reference)
        digest = shared.sha(raw).removeprefix("sha256:")
        if digest in result or path in paths:
            shared.fail("retained inventory must resolve each digest exactly once")
        paths.add(path)
        result[digest] = (path, raw)
    return result


def evidence_json(inventory: dict, digest: str):
    return strict_json(inventory[raw_digest(digest, "evidence file")][1])


def verify_derivative(derivative: dict, inventory: dict) -> dict:
    """Recompute six-class counts from the authenticated, byte-bound groups.

    The fixed private verifier proves scenario, signature and oracle semantics.
    This adapter checks its closed derivative and underlying byte inventory;
    it neither executes that verifier nor supplies any empirical rule or recipe.
    """
    trust.closed(derivative, DERIVATIVE_FIELDS, "hosted qualification derivative")
    if (
        derivative["schema_version"] != "openadapt.hosted-qualification-derivative/v1"
        or derivative["target"] != "cloud"
        or derivative["scope"] != "hosted-synthetic-qualification"
    ):
        shared.fail("unsupported hosted derivative target or scope")
    validate_producer(derivative["producer"])
    uuid_identifier(derivative["campaign_id"], "campaign id")
    subject = trust.closed(derivative["subject"], SUBJECT_FIELDS, "hosted subject")
    if not isinstance(subject["source_commit"], str) or not trust.HEX40.fullmatch(
        subject["source_commit"]
    ):
        shared.fail("hosted deployment source must be exact")
    for key in SUBJECT_FIELDS - {"source_commit"}:
        raw_digest(subject[key], key)
    validator = trust.closed(
        derivative["validator"],
        {
            "repository",
            "source_commit",
            "path",
            "sha256",
            "source_inventory_sha256",
        },
        "private verifier source identity",
    )
    if (
        validator["repository"] != trust.TARGET_CONTRACTS["cloud"]["repository"]
        or validator["source_commit"] != subject["source_commit"]
        or validator["path"] != "runner/qualification_issuer.py"
    ):
        shared.fail("private verifier does not bind the actual Cloud source")
    commitments = trust.closed(
        derivative["receipt_commitments"],
        shared.FILE_COMMITMENTS,
        "actual receipt byte commitments",
    )
    for key, value in commitments.items():
        raw_digest(value, key)
    if (
        commitments["bundle_sha256"] != subject["bundle_artifact_sha256"]
        or commitments["admitted_runtime_sha256"] != subject["runtime_wheel_sha256"]
    ):
        shared.fail("admitted bundle or runtime differs from actual retained bytes")
    refs = evidence_references(derivative["raw_evidence_refs"])
    raw_hashes = {item["sha256"] for item in refs}
    if raw_hashes != set(inventory):
        shared.fail("retained evidence inventory differs from the attested inventory")
    required = set(commitments.values()) | {
        subject["deployment_manifest_sha256"],
        validator["sha256"],
        validator["source_inventory_sha256"],
    }
    groups = derivative["groups"]
    if not isinstance(groups, list) or not groups:
        shared.fail("hosted derivative has no actual groups")
    grouped, tasks, trial_ids, reports, group_order = {}, set(), set(), set(), []
    for group in groups:
        trust.closed(group, GROUP_FIELDS, "hosted trial group")
        trial_id = uuid_identifier(group["trial_id"], "trial id")
        task = identifier(group["task"], "task")
        condition = identifier(group["condition"], "condition")
        campaign_class = group["campaign_class"]
        if campaign_class not in PHASES or trial_id in trial_ids:
            shared.fail("duplicate group or unsupported campaign class")
        ordinal = strict_count(group["ordinal"], "trial ordinal", minimum=1)
        group_order.append((task, condition, ordinal))
        trial_ids.add(trial_id)
        tasks.add(task)
        counts = trust.closed(
            group["counts"], GROUP_COUNT_FIELDS, "derived per-group counts"
        )
        for key, value in counts.items():
            strict_count(value, key)
        if campaign_class == "declared_attended" and any(
            counts[key] != 1
            for key in (
                "authenticated_bound_decision_count",
                "live_target_revalidation_count",
            )
        ):
            shared.fail(
                "each attended group requires its own bound decision and revalidation"
            )
        if campaign_class == "governed_repair" and any(
            counts[key] != 1
            for key in (
                "policy_approved_repair_count",
                "approved_repair_count",
                "retained_repair_evidence_count",
                "live_target_revalidation_count",
            )
        ):
            shared.fail(
                "each repair group requires its own approval and retained evidence"
            )
        phases = group["phases"]
        if not isinstance(phases, list):
            shared.fail("native phases must be an explicit list")
        expected_phases, principal = PHASES[campaign_class]
        seen_phases, native = set(), {}
        for phase in phases:
            trust.closed(phase, PHASE_FIELDS, "native phase reference")
            name = phase["phase"]
            if name in seen_phases or name not in expected_phases:
                shared.fail("missing, duplicate or unsupported native phase")
            seen_phases.add(name)
            for key in PHASE_FIELDS - {"phase", "auxiliary_artifacts"}:
                raw_digest(phase[key], key)
            for key in ("run_report_sha256", "runner_receipt_sha256", "input_sha256"):
                required.add(phase[key])
            required.update(
                item["sha256"]
                for item in evidence_references(phase["auxiliary_artifacts"])
            )
            report_hash = phase["run_report_sha256"]
            if report_hash in reports:
                shared.fail("native report is reused across measured phases")
            reports.add(report_hash)
            report = evidence_json(inventory, report_hash)
            same_bundle = (
                report.get("bundle_content_digest") == subject["bundle_content_digest"]
            )
            if same_bundle != (name != "repair_prior"):
                shared.fail(
                    "native phase binds the wrong principal or repair-prior bundle"
                )
            if report.get("run_id_sha256") != phase["qualification_run_id_sha256"]:
                shared.fail("native phase run differs from its retained report")
            native[name] = (phase, report)
        if seen_phases != expected_phases:
            shared.fail("native phase membership is incomplete")
        principal_report = native[principal][1]
        if (
            principal_report.get("qualification_evidence_only") is not True
            or principal_report.get("production_eligible") is not False
            or principal_report.get("run_id_sha256")
            != native[principal][0]["qualification_run_id_sha256"]
        ):
            shared.fail("principal report lacks exact qualification-only run binding")
        expected_outcome = {
            "safe_halt": "HALTED_BEFORE_EFFECT",
            "uncertain_delivery": "RECONCILIATION_REQUIRED",
        }.get(campaign_class, "VERIFIED")
        if principal_report.get(
            "transaction_outcome"
        ) != expected_outcome or principal_report.get("success") is not (
            expected_outcome == "VERIFIED"
        ):
            shared.fail("actual principal outcome does not satisfy its measured class")
        if counts["reconciliation_required_count"] != int(
            principal_report.get("transaction_outcome") == "RECONCILIATION_REQUIRED"
        ):
            shared.fail("reconciliation count differs from the actual principal report")
        if campaign_class == "idempotency_replay" and (
            native["primary"][0]["input_sha256"] != native["replay"][0]["input_sha256"]
            or native["primary"][0]["qualification_run_id_sha256"]
            == native["replay"][0]["qualification_run_id_sha256"]
        ):
            shared.fail(
                "replay must retain the same input and distinct native invocation"
            )
        if campaign_class == "idempotency_replay" and (
            not isinstance(native["primary"][1].get("idempotency_key"), str)
            or not native["primary"][1]["idempotency_key"]
            or native["primary"][1]["idempotency_key"]
            != native["replay"][1].get("idempotency_key")
            or native["replay"][1].get("idempotent_replay") is not True
            or native["replay"][1].get("success") is not False
        ):
            shared.fail(
                "actual replay lacks the same native idempotency key or refusal"
            )
        if campaign_class == "declared_attended" and (
            native["primary"][0]["qualification_run_id_sha256"]
            != native["attended_continuation"][0]["qualification_run_id_sha256"]
        ):
            shared.fail("attended continuation must bind the same durable run")
        for key in ("observer_before_sha256", "observer_after_sha256"):
            required.add(raw_digest(group[key], key))
        if group["observer_before_sha256"] == group["observer_after_sha256"]:
            shared.fail("one observer envelope cannot prove both before and after")
        grouped.setdefault(campaign_class, {}).setdefault((task, condition), []).append(
            group
        )
    if len(tasks) != 1 or set(grouped) != set(trust.CAMPAIGN_CLASSES):
        shared.fail("measured Cloud adapter requires one task and all six classes")
    if group_order != sorted(set(group_order)):
        shared.fail(
            "hosted groups must follow unique frozen task/condition/ordinal order"
        )
    if not required <= raw_hashes:
        shared.fail("attested inventory omits a referenced evidence or commitment file")
    summary = {}
    for name, cells in grouped.items():
        rows = [row for values in cells.values() for row in values]
        for values in cells.values():
            if [row["ordinal"] for row in values] != list(range(1, len(values) + 1)):
                shared.fail("trial cell ordinals are not contiguous")
        counts = {
            key: sum(row["counts"][key] for row in rows) for key in GROUP_COUNT_FIELDS
        }
        counts.update(
            task_condition_cell_count=len(cells),
            minimum_trials_per_cell=min(map(len, cells.values())),
            observed_trial_count=len(rows),
        )
        for key, value in counts.items():
            strict_count(value, key)
        summary[name] = counts
    return trust.validate_campaign_summary(summary)


def canonical_json(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def semantic_digest(value, domain=b"") -> str:
    return shared.sha(domain + canonical_json(value)).removeprefix("sha256:")


def role_file(derivative: dict, inventory: dict, role: str) -> tuple[Path, bytes]:
    matches = [
        item["sha256"]
        for item in derivative["raw_evidence_refs"]
        if item["role"] == role
    ]
    if len(matches) != 1:
        shared.fail(f"retained evidence must contain exactly one {role}")
    return inventory[matches[0]]


def role_json(derivative: dict, inventory: dict, role: str) -> dict:
    return strict_json(role_file(derivative, inventory, role)[1])


def verify_subject_openings(derivative: dict, inventory: dict) -> tuple[str, int]:
    """Open public identity interfaces; the attested verifier checks private contracts."""
    subject, commitments = derivative["subject"], derivative["receipt_commitments"]
    build = role_json(derivative, inventory, "runtime_build_identity")
    identity = role_json(derivative, inventory, "evidence_identity")
    runtime = role_json(derivative, inventory, "runtime_version")
    if (
        build.get("schema_version") != "openadapt.admitted-runtime-build/v1"
        or identity.get("schema_version")
        != "openadapt.production-acceptance-evidence-identity/v2"
        or semantic_digest(build, b"openadapt-admitted-runtime-build-v1\0")
        != subject["runtime_build_identity_sha256"]
        or semantic_digest(
            identity, b"OpenAdapt production acceptance evidence identity v2\0"
        )
        != subject["evidence_identity_sha256"]
        or semantic_digest(runtime) != subject["runtime_manifest_sha256"]
        or identity.get("runtime_build_identity") != build
    ):
        shared.fail(
            "semantic runtime or evidence identity differs from its retained opening"
        )
    if (
        build.get("substrate") != "web"
        or build.get("substrate_runtime", {}).get("transport") != "browser"
        or build.get("managed_browser")
        != {
            "playwright_version": runtime.get("playwright"),
            "browser_base_image": runtime.get("browser_base_image"),
        }
        or build.get("flow_wheel_sha256") != subject["runtime_wheel_sha256"]
        or build.get("flow_version") != runtime.get("openadapt_flow")
        or build.get("flow_release_commit") != runtime.get("release_commit")
        or build.get("flow_wheel_sha256") != runtime.get("wheel_sha256")
        or build.get("runner_build") != runtime.get("runner_build")
        or build.get("runner_artifact_sha256") != runtime.get("runner_artifact_sha256")
        or build.get("runtime_manifest_sha256")
        != semantic_digest(
            build.get("runtime_manifest"), b"openadapt-runtime-component-manifest-v1\0"
        )
    ):
        shared.fail("hosted runtime does not bind its actual Flow and browser build")
    for key in (
        "deployment_manifest_sha256",
        "bundle_artifact_sha256",
        "bundle_content_digest",
        "environment_digest",
    ):
        if identity.get(key) != subject[key]:
            shared.fail(f"expanded evidence identity differs at {key}")
    if identity.get("campaign_id") != derivative["campaign_id"]:
        shared.fail("expanded evidence identity names another campaign")
    for commitment, field in (
        ("organization_id_sha256", "tenant_id"),
        ("workflow_id_sha256", "workflow_id"),
        ("workflow_version_id_sha256", "workflow_version_id"),
    ):
        opening = evidence_json(inventory, commitments[commitment])
        if (
            uuid_identifier(opening.get("id"), field) != identity.get(field)
            or opening.get("admitted_subject") != subject
        ):
            shared.fail("identity opening differs from the exact hosted subject")
    version = evidence_json(inventory, commitments["workflow_version_id_sha256"])[
        "bundle_version"
    ]
    if (
        not isinstance(version, str)
        or len(version) > 64
        or not trust.BUNDLE_VERSION.fullmatch(version)
    ):
        shared.fail("declared sealed bundle version is invalid")
    decision = evidence_json(inventory, commitments["decision_identity_sha256"])
    uuid_identifier(decision.get("id"), "decision identity")
    revision = strict_count(
        decision.get("decision_revision"), "decision revision", minimum=1
    )
    for name in ("decision_commitment_sha256", "evidence_manifest_readback_sha256"):
        opening = evidence_json(inventory, commitments[name])
        if (
            opening.get("evidence_manifest_sha256")
            != commitments["evidence_manifest_sha256"]
            or opening.get("admitted_subject") != subject
        ):
            shared.fail(
                "decision or readback differs from the actual manifest and subject"
            )
        if name == "decision_commitment_sha256" and (
            opening.get("decision_revision") != revision
            or opening.get("decision_id") != decision["id"]
        ):
            shared.fail(
                "decision commitment differs from the immutable decision identity"
            )
    campaign = evidence_json(inventory, commitments["campaign_artifact_sha256"])
    if (
        campaign.get("schema_version") != "openadapt.qualification-campaign/v2"
        or campaign.get("campaign_id") != derivative["campaign_id"]
        or campaign.get("evidence_identity_sha256")
        != subject["evidence_identity_sha256"]
    ):
        shared.fail("retained campaign artifact names another hosted subject")
    return version, revision


DEPLOYMENT_WORKFLOW = ".github/workflows/deploy.yml"
DEPLOYMENT_REPOSITORY = trust.TARGET_CONTRACTS["cloud"]["repository"]


def validate_deployment_run(run: dict, authority: dict) -> None:
    if (
        type(run.get("id")) is not int
        or str(run["id"]) != authority["run_id"]
        or type(run.get("run_attempt")) is not int
        or str(run["run_attempt"]) != authority["run_attempt"]
        or run.get("head_sha") != authority["source_commit"]
        or run.get("head_branch") != "main"
        or run.get("path") != DEPLOYMENT_WORKFLOW
        or run.get("event") != authority["event_name"]
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("repository", {}).get("full_name") != DEPLOYMENT_REPOSITORY
        or type(run.get("repository", {}).get("id")) is not int
        or str(run["repository"]["id"])
        != trust.TARGET_CONTRACTS["cloud"]["repository_id"]
        or type(run.get("repository", {}).get("owner", {}).get("id")) is not int
        or str(run["repository"]["owner"]["id"]) != PRODUCER_OWNER_ID
    ):
        shared.fail(
            "deployment must bind the actual successful protected workflow attempt"
        )


def verify_deployment(
    derivative: dict, inventory: dict, release: dict, staging: dict, *, gh=shared.gh
) -> None:
    """Match attested deployment/provider bytes and the actual protected run.

    The fixed private producer verifies deployment signatures and provider
    readback. This consumer opens the committed identities and independently
    checks GitHub's completed run and source bytes. It does not execute a
    provider recipe or accept a caller's successful-deployment flag.
    """
    subject = derivative["subject"]
    manifest_raw = inventory[subject["deployment_manifest_sha256"]][1]
    manifest = strict_json(manifest_raw)
    if (
        manifest.get("schema_version")
        != "openadapt.cloud-production-deployment-manifest/v1"
        or canonical_json(manifest) != manifest_raw
    ):
        shared.fail(
            "deployment manifest must retain its exact canonical artifact bytes"
        )
    authority = manifest["build_authority"]
    if any(
        authority.get(key) != value
        for key, value in {
            "repository": DEPLOYMENT_REPOSITORY,
            "workflow": DEPLOYMENT_WORKFLOW,
            "source_ref": "refs/heads/main",
            "source_commit": subject["source_commit"],
            "workflow_ref": f"{DEPLOYMENT_REPOSITORY}/{DEPLOYMENT_WORKFLOW}@refs/heads/main",
            "certificate_identity": f"https://github.com/{DEPLOYMENT_REPOSITORY}/{DEPLOYMENT_WORKFLOW}@refs/heads/main",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "job": "deploy",
            "environment": "production",
            "environment_scope": "openadapt-cloud-production-v1",
        }.items()
    ) or authority.get("event_name") not in {"workflow_run", "workflow_dispatch"}:
        shared.fail(
            "deployment build authority differs from the fixed protected source"
        )
    for key in ("run_id", "run_attempt"):
        trust.require_decimal_id(authority.get(key), f"deployment {key}")
    if (
        manifest["source"]
        != {"repository": DEPLOYMENT_REPOSITORY, "commit": subject["source_commit"]}
        or release["source_commit"] != subject["source_commit"]
        or release["deployment_id"] != authority["run_id"]
        or release["deployment_sha256"]
        != "sha256:" + subject["deployment_manifest_sha256"]
        or manifest["target"]["environment_digest"]
        != "sha256:" + subject["environment_digest"]
    ):
        shared.fail("deployment release, source or environment identity differs")
    runtime = role_json(derivative, inventory, "runtime_version")
    expected_runtime = {
        "runtime_manifest_sha256": "sha256:" + subject["runtime_manifest_sha256"],
        "runner_source_artifact_sha256": "sha256:" + runtime["runner_artifact_sha256"],
        "runner_build": runtime["runner_build"],
        "modal_sdk_version": runtime["modal_sdk"],
        "fastapi_version": runtime["fastapi"],
        "starlette_version": runtime["starlette"],
        "sandbox_network_policy": runtime["sandbox_network_policy"],
        "flow": {
            "version": runtime["openadapt_flow"],
            "release_commit": runtime["release_commit"],
            "wheel_url": runtime["wheel_url"],
            "wheel_sha256": "sha256:" + runtime["wheel_sha256"],
            "sdist_sha256": "sha256:" + runtime["sdist_sha256"],
        },
        "browser": {
            "playwright_version": runtime["playwright"],
            "browser_base_image": runtime["browser_base_image"],
            "runtime_contract_sha256": "sha256:"
            + semantic_digest(
                {
                    "python_base_image": runtime["browser_base_image"],
                    "playwright_version": runtime["playwright"],
                    "browser_install_command": "python -m playwright install --with-deps chromium",
                },
                b"OpenAdapt managed browser image contract v1\0",
            ),
        },
    }
    if manifest["runtime"] != expected_runtime:
        shared.fail("deployment runtime differs from the measured build and wheel")
    readback = role_json(derivative, inventory, "deployment_readback")
    if (
        readback.get("schema_version")
        != "openadapt.cloud-production-deployment-readback/v1"
        or readback.get("source_commit") != subject["source_commit"]
        or readback.get("manifest_sha256") != release["deployment_sha256"]
        or readback.get("manifest_bytes_sha256") != release["deployment_sha256"]
        or readback.get("target_attestation_sha256") != manifest["target"]["sha256"]
        or readback.get("admission_activated") is not False
    ):
        shared.fail("provider readback differs from the actual deployment manifest")
    observed = readback["provider_observation"]
    github = observed["github"]
    if any(
        github.get(key) != authority[other]
        for key, other in (
            ("run_id", "run_id"),
            ("run_attempt", "run_attempt"),
            ("source_commit", "source_commit"),
            ("event", "event_name"),
        )
    ):
        shared.fail("in-job readback differs from the final deployment invocation")
    host, runner = manifest["deployment"]["host"], manifest["deployment"]["runner"]
    if (
        any(
            observed["host"].get(key) != host[key]
            for key in (
                "deploy_id",
                "immutable_url",
                "created_at",
                "published_at",
            )
        )
        or "sha256:"
        + semantic_digest(
            observed["host"].get("site_id"),
            b"OpenAdapt Netlify production site identity v1\0",
        )
        != host["site_identity_sha256"]
    ):
        shared.fail("actual host provider identity differs from the signed manifest")
    if any(
        observed["modal"].get(key) != runner[key]
        for key in (
            "environment",
            "app_id",
            "app_name",
            "app_version",
            "deployed_at",
        )
    ) or (
        observed["modal"].get("source_commit") != subject["source_commit"]
        or observed["modal"].get("source_dirty") is not False
        or observed["modal"].get("sdk_version") != runtime["modal_sdk"]
        or "sha256:"
        + semantic_digest(
            observed["modal"].get("endpoint_origin"),
            b"OpenAdapt Modal runner endpoint origin v1\0",
        )
        != runner["endpoint_origin_sha256"]
    ):
        shared.fail("actual runner provider identity differs from the signed manifest")
    context = readback["observed_runtime_context"]
    if (
        context.get("deployment_manifest_sha256")
        != subject["deployment_manifest_sha256"]
        or context.get("runtime_build_identity")
        != role_json(derivative, inventory, "runtime_build_identity")
        or observed.get("environment_contract_sha256")
        != host["environment_contract_sha256"]
    ):
        shared.fail("provider runtime context differs from the measured deployment")
    trust.validate_staging(staging)
    if (
        staging["publication_mode"] != "already-published-deployment"
        or staging["repository"] != DEPLOYMENT_REPOSITORY
        or staging["repository_id"] != trust.TARGET_CONTRACTS["cloud"]["repository_id"]
        or staging["target_commitish"] != subject["source_commit"]
        or staging["deployment_id"] != authority["run_id"]
        or staging["tag"] != f"v0.0.0-deployment.{authority['run_id']}"
        or staging["deployment_url"] != host["immutable_url"]
        or staging["assets"]
        != [
            {
                **release["artifacts"][0],
                "asset_id": None,
                "uploader_id": None,
                "uploader_login": None,
            }
        ]
    ):
        shared.fail("publication staging differs from the actual deployed artifact")
    retained_run = role_json(derivative, inventory, "deployment_workflow_run")
    validate_deployment_run(retained_run, authority)
    validate_deployment_run(
        gh(
            f"repos/{DEPLOYMENT_REPOSITORY}/actions/runs/{authority['run_id']}"
            f"/attempts/{authority['run_attempt']}"
        ),
        authority,
    )
    for path, raw in (
        (
            DEPLOYMENT_WORKFLOW,
            role_file(derivative, inventory, "deployment_workflow_source")[1],
        ),
        (
            "runner/runtime-version.json",
            role_file(derivative, inventory, "runtime_version")[1],
        ),
        (
            derivative["validator"]["path"],
            inventory[derivative["validator"]["sha256"]][1],
        ),
    ):
        source = gh(
            f"repos/{DEPLOYMENT_REPOSITORY}/contents/{path}?ref={subject['source_commit']}"
        )
        if (
            source.get("encoding") != "base64"
            or source.get("type") != "file"
            or source.get("path") != path
            or base64.b64decode(source["content"].replace("\n", ""), validate=True)
            != raw
        ):
            shared.fail("actual deployed source bytes differ from retained evidence")
        if (
            path == DEPLOYMENT_WORKFLOW
            and shared.sha(raw) != authority["workflow_sha256"]
        ):
            shared.fail(
                "deployment workflow source hash differs from its signed authority"
            )


def prepare_inputs(mapping_path: Path, mapping_sha256: str, *, gh=shared.gh) -> dict:
    raw = mapping_path.read_bytes()
    if shared.sha(raw) != mapping_sha256:
        shared.fail("Cloud mapping changed after review")
    mapping = trust.closed(
        strict_json(raw),
        {
            "schema_version",
            "candidate",
            "derivative",
            "provenance",
            "retained_files",
            "publication_staging",
        },
        "measured Cloud input mapping",
    )
    if mapping["schema_version"] != "openadapt.measured-cloud-admission-mapping/v1":
        shared.fail("unsupported Cloud input mapping")
    candidate_path, candidate = checked_json(mapping_path, mapping["candidate"])
    trust.closed(
        candidate,
        {
            "schema_version",
            "state",
            "target",
            "release",
            "artifact_inventory",
            "proposed_release_identity",
        },
        "measured Cloud candidate",
    )
    if (
        candidate["schema_version"] != "openadapt.measured-cloud-release-candidate/v1"
        or candidate["state"] != "ready-for-review"
        or candidate["target"] != "cloud"
    ):
        shared.fail("unsupported measured Cloud candidate target or state")
    inputs = {
        "release": candidate["release"],
        "artifact_inventory": candidate["artifact_inventory"],
    }
    if shared.prepared_target(inputs) != ("cloud", "production_cloud"):
        shared.fail("Cloud candidate inventory must select only the Cloud deployment")
    release = trust.closed(
        inputs["release"],
        {
            "schema_version",
            "kind",
            "source_repository",
            "source_repository_id",
            "source_commit",
            "version",
            "tag",
            "deployment_id",
            "deployment_sha256",
            "artifacts",
        },
        "Cloud release candidate",
    )
    if (
        release["version"] is not None
        or release["tag"] is not None
        or len(release["artifacts"]) != 1
    ):
        shared.fail("Cloud deployment cannot imply a package version or release tag")
    _, derivative_raw = shared.checked_file(mapping_path, mapping["derivative"])
    derivative = strict_json(derivative_raw)
    inventory = retained_inventory(mapping_path, mapping["retained_files"])
    summary = verify_derivative(derivative, inventory)
    artifact = release["artifacts"][0]
    manifest_raw = inventory[derivative["subject"]["deployment_manifest_sha256"]][1]
    if artifact["sha256"] != shared.sha(manifest_raw) or artifact["size_bytes"] != len(
        manifest_raw
    ):
        shared.fail(
            "Cloud artifact inventory differs from the actual signed manifest bytes"
        )
    bundle_version, revision = verify_subject_openings(derivative, inventory)
    # Provenance is required before any closed group can become issuer input.
    verify_derivative_provenance(
        mapping_path,
        derivative_raw,
        derivative["producer"],
        mapping["provenance"],
        gh=gh,
    )
    _, staging = checked_json(mapping_path, mapping["publication_staging"])
    verify_deployment(derivative, inventory, release, staging, gh=gh)
    inputs.update(
        mapping_sha256=mapping_sha256,
        candidate_sha256=shared.sha(candidate_path.read_bytes()),
        derivative_sha256=shared.sha(derivative_raw),
        commitments={
            key: "sha256:" + value
            for key, value in derivative["receipt_commitments"].items()
        },
        campaign_summary=summary,
        bundle_version=bundle_version,
        decision_revision=revision,
        release_identity=candidate["proposed_release_identity"],
        publication_staging=staging,
    )
    return inputs


def main(argv=None) -> int:
    return shared.main(argv, input_preparer=prepare_inputs, expected_target="cloud")


if __name__ == "__main__":
    raise SystemExit(main())
