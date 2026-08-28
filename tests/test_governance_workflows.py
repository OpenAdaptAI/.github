from __future__ import annotations

import json
import hashlib
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_lifecycle_change as prepare  # noqa: E402

LIFECYCLE_WORKFLOWS = {
    "production-lifecycle-activation.yml": "production-lifecycle-activation",
    "qualification-authority-state.yml": "qualification-authority-state",
    "qualification-revocation-state.yml": "qualification-revocation-state",
}
INACTIVE_ISSUER_WORKFLOWS = {
    "issue-qualification-admission.yml": {
        "interface_command": "python3 scripts/qualification_issuer.py interface",
        "interface_label": "admission issuer",
    },
    "issue-synthetic-qualification-evidence-decision.yml": {
        "interface_command": (
            "python3 scripts/qualification_kms_ed25519.py interface"
        ),
        "interface_label": "KMS issuer",
    },
}


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _legacy_entry_digest(entry: dict) -> str:
    projection = {
        field: entry[field]
        for field in (
            "kind", "prior_entry_sha256", "recorded_at", "sequence",
            "sha256", "size_bytes", "url",
        )
    }
    encoded = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(
        b"OpenAdapt production evidence registry entry v1\0" + encoded
    ).hexdigest()


def _legacy_build_entry(**fields: object) -> dict:
    entry = dict(fields)
    entry["entry_sha256"] = _legacy_entry_digest(entry)
    return entry


def _legacy_registry_adapter() -> types.SimpleNamespace:
    def validate_registry(value: dict) -> list[dict]:
        if value.get("schema_version") != "openadapt.production-evidence-registry/v1":
            raise ValueError("legacy registry schema differs")
        return value["entries"]

    def validate_append_only_history(previous: dict, current: dict) -> None:
        if current["entries"][:-1] != previous["entries"]:
            raise ValueError("legacy registry history changed")

    return types.SimpleNamespace(
        build_entry=_legacy_build_entry,
        validate_registry=validate_registry,
        validate_append_only_history=validate_append_only_history,
    )


class GovernanceWorkflowContractTests(unittest.TestCase):
    def test_profile_check_reports_on_every_pull_request(self) -> None:
        content = _read(".github/workflows/profile-consistency.yml")
        pull_request = content.split("  pull_request:", 1)[1].split("  push:", 1)[0]
        self.assertNotIn("paths:", pull_request)
        self.assertNotIn("paths-ignore:", pull_request)
        self.assertNotRegex(content, r"(?m)^ {4}paths(?:-ignore)?:")
        self.assertIn("  validate-profile:\n", content)
        self.assertIn("group: ${{ github.workflow }}-${{ github.event_name }}", content)
        self.assertIn("cancel-in-progress: false", content)

    def test_v1_release_history_gate_does_not_parse_the_v2_policy_as_v1(self) -> None:
        content = _read(".github/workflows/profile-consistency.yml")
        rollback_step = content.split(
            "      - name: Refuse Production release-ledger rollback\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn("--history-only", rollback_step)
        self.assertIn("--previous-admissions", rollback_step)
        self.assertNotIn("previous-production-lifecycle-policy", rollback_step)

    def test_profile_dispatch_refuses_the_lifecycle_app_in_every_job(self) -> None:
        content = _read(".github/workflows/profile-consistency.yml")
        self.assertIn("  reject-lifecycle-app:\n    permissions: {}", content)
        self.assertGreaterEqual(
            content.count("github.actor != 'openadapt-lifecycle[bot]'"), 2
        )
        self.assertGreaterEqual(
            content.count("github.triggering_actor != 'openadapt-lifecycle[bot]'"),
            2,
        )
        self.assertIn("needs: reject-lifecycle-app", content)
        self.assertIn(
            "needs: [reject-lifecycle-app, validate-profile]",
            content,
        )

    def test_dispatch_inventory_is_exact(self) -> None:
        discovered = set()
        for path in (ROOT / ".github" / "workflows").glob("*.y*ml"):
            content = path.read_text(encoding="utf-8")
            if re.search(
                r"(?m)^  (?:workflow_dispatch|repository_dispatch):\s*$",
                content,
            ):
                discovered.add(path.name)
        self.assertEqual(
            discovered,
            set(LIFECYCLE_WORKFLOWS)
            | set(INACTIVE_ISSUER_WORKFLOWS)
            | {"production-lifecycle-ref.yml", "profile-consistency.yml"},
        )

    def test_inactive_issuer_workflows_cannot_issue_or_acquire_authority(self) -> None:
        forbidden = (
            "environment:",
            "id-token: write",
            "attestations: write",
            "contents: write",
            "packages: write",
            "pull-requests: write",
            "${{ secrets.",
            "aws-actions/",
            "aws kms",
            "sign-request",
            "registry-candidate",
            "issue_workflow_admission",
            "issue_release_admission",
            "actions/upload-artifact",
            "gh api",
            "git push",
        )
        for filename, contract in INACTIVE_ISSUER_WORKFLOWS.items():
            content = _read(f".github/workflows/{filename}")
            self.assertIn("  workflow_dispatch:\n", content, filename)
            self.assertNotRegex(
                content,
                r"(?m)^  (?:pull_request|pull_request_target|push|release|schedule|repository_dispatch|workflow_call):\s*$",
                filename,
            )
            self.assertIn("permissions: {}", content, filename)
            self.assertIn("persist-credentials: false", content, filename)
            self.assertIn("github.repository", content, filename)
            self.assertIn("github.ref", content, filename)
            self.assertIn("github.sha", content, filename)
            self.assertIn("refs/heads/main", content, filename)
            self.assertIn("EXPECTED_ACTIVATION_STATE: inactive", content, filename)
            self.assertIn(contract["interface_command"], content, filename)
            self.assertIn(contract["interface_label"], content, filename)
            self.assertIn("exit 1", content, filename)
            self.assertIn("cancel-in-progress: false", content, filename)
            for marker in forbidden:
                self.assertNotIn(marker, content, f"{filename}: {marker}")

    def test_lifecycle_workflows_are_app_only_review_paths(self) -> None:
        for filename, environment in LIFECYCLE_WORKFLOWS.items():
            content = _read(f".github/workflows/{filename}")
            self.assertIn("  workflow_dispatch:\n", content, filename)
            self.assertNotRegex(
                content,
                r"(?m)^  (?:pull_request|pull_request_target|push|release|schedule|repository_dispatch|workflow_call):\s*$",
                filename,
            )
            self.assertIn(
                "github.repository == 'OpenAdaptAI/.github'", content, filename
            )
            self.assertIn("github.ref == 'refs/heads/main'", content, filename)
            self.assertIn("github.event_name == 'workflow_dispatch'", content, filename)
            self.assertIn(
                "github.actor == 'openadapt-lifecycle[bot]'", content, filename
            )
            self.assertIn(
                "github.triggering_actor == 'openadapt-lifecycle[bot]'",
                content,
                filename,
            )
            self.assertIn(
                "github.actor_id == vars.OPENADAPT_LIFECYCLE_ACTOR_ID",
                content,
                filename,
            )
            self.assertIn(f"environment: {environment}", content, filename)
            self.assertIn("vars.OPENADAPT_LIFECYCLE_APP_ID", content, filename)
            self.assertIn("vars.OPENADAPT_LIFECYCLE_INSTALLATION_ID", content, filename)
            self.assertIn(
                "secrets.OPENADAPT_LIFECYCLE_APP_PRIVATE_KEY",
                content,
                filename,
            )
            self.assertIn("actions/create-github-app-token@", content, filename)
            self.assertIn("permission-pull-requests: write", content, filename)
            self.assertIn("actions/attest@", content, filename)
            self.assertIn("github.token", content, filename)
            self.assertIn("gh pr create", content, filename)
            self.assertIn("cancel-in-progress: false", content, filename)
            self.assertNotRegex(content, r"git\s+push[^\n]*\bmain\b", filename)

    def test_third_party_actions_are_commit_pinned(self) -> None:
        pattern = re.compile(r"uses:\s*([^\s@]+)@([^\s#]+)")
        for path in (ROOT / ".github" / "workflows").glob("*.y*ml"):
            for action, ref in pattern.findall(path.read_text(encoding="utf-8")):
                self.assertRegex(ref, r"^[0-9a-f]{40}$", f"{path.name}: {action}")


class LifecycleCandidateTests(unittest.TestCase):
    SOURCE_COMMIT = "a" * 40

    def test_activation_appends_one_domain_bound_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = {
                "$schema": "schemas/production-lifecycle-admissions.schema.json",
                "schema_version": "openadapt.production-lifecycle-admissions/v1",
                "policy_sha256": "sha256:" + "b" * 64,
                "admissions": [],
            }
            _write_json(root / "production-lifecycle-admissions.json", ledger)
            admission = {
                "admission_id": "flow-1",
                "target": "flow",
                "revoked_at": None,
            }
            key = prepare.proposal_digest(
                prepare.ACTIVATION_DOMAIN,
                {"source_commit": self.SOURCE_COMMIT, "admission": admission},
            )
            branch = prepare.activate(
                root=root,
                source_commit=self.SOURCE_COMMIT,
                admission_json=json.dumps(admission),
                idempotency_key=key,
            )
            current = json.loads(
                (root / "production-lifecycle-admissions.json").read_text()
            )
            self.assertEqual(current["admissions"], [admission])
            self.assertEqual(
                branch,
                "automation/production-lifecycle-activation-" + key.split(":", 1)[1],
            )

    def test_authority_state_appends_one_hash_chained_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = {
                "$schema": "schemas/evidence-registry.schema.json",
                "schema_version": "openadapt.production-evidence-registry/v1",
                "head_entry_sha256": None,
                "entries": [],
            }
            _write_json(root / "evidence-registry.json", empty)
            entry = _legacy_build_entry(
                sequence=1,
                kind="evidence-summary",
                url="https://example.test/summary.json",
                sha256="sha256:" + "c" * 64,
                size_bytes=123,
                recorded_at="2026-08-26T20:00:00.000Z",
                prior_entry_sha256=None,
            )
            key = prepare.proposal_digest(
                prepare.AUTHORITY_DOMAIN,
                {"source_commit": self.SOURCE_COMMIT, "entry": entry},
            )
            with mock.patch.object(
                prepare, "evidence_registry", _legacy_registry_adapter()
            ):
                prepare.record_authority(
                    root=root,
                    source_commit=self.SOURCE_COMMIT,
                    kind=entry["kind"],
                    url=entry["url"],
                    sha256=entry["sha256"],
                    size_bytes=entry["size_bytes"],
                    recorded_at=entry["recorded_at"],
                    idempotency_key=key,
                )
            current = json.loads((root / "evidence-registry.json").read_text())
            self.assertEqual(current["entries"], [entry])
            self.assertEqual(current["head_entry_sha256"], entry["entry_sha256"])

    def test_revocation_changes_only_the_current_record_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "admission_id": "flow-1",
                "target": "flow",
                "revoked_at": None,
            }
            ledger = {"admissions": [record]}
            _write_json(root / "production-lifecycle-admissions.json", ledger)
            revoked_at = "2026-08-26T20:00:00Z"
            key = prepare.proposal_digest(
                prepare.REVOCATION_DOMAIN,
                {
                    "source_commit": self.SOURCE_COMMIT,
                    "admission_id": "flow-1",
                    "revoked_at": revoked_at,
                },
            )
            prepare.revoke(
                root=root,
                source_commit=self.SOURCE_COMMIT,
                admission_id="flow-1",
                revoked_at=revoked_at,
                idempotency_key=key,
            )
            current = json.loads(
                (root / "production-lifecycle-admissions.json").read_text()
            )
            self.assertEqual(current["admissions"][0]["revoked_at"], revoked_at)

    def test_bad_idempotency_key_does_not_mutate_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = {"admissions": []}
            path = root / "production-lifecycle-admissions.json"
            _write_json(path, ledger)
            before = path.read_bytes()
            with self.assertRaises(prepare.CandidateError):
                prepare.activate(
                    root=root,
                    source_commit=self.SOURCE_COMMIT,
                    admission_json=json.dumps(
                        {
                            "admission_id": "flow-1",
                            "target": "flow",
                            "revoked_at": None,
                        }
                    ),
                    idempotency_key="sha256:" + "0" * 64,
                )
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
