"""Test-only subprocess results exercise provenance checks without signatures."""

import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_production_release_admission as verifier


def verified_result(raw, repository, source, ref):
    return {
        "statement": {
            "subject": [
                {
                    "name": "test-only.json",
                    "digest": {
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    },
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {
                            "uri": f"git+https://github.com/{repository}@{ref}",
                            "digest": {"gitCommit": source},
                        }
                    ]
                }
            },
        },
        "signature": {
            "certificate": {
                "githubWorkflowSHA": source,
                "sourceRepositoryDigest": source,
                "githubWorkflowRef": ref,
                "githubWorkflowRepository": repository,
            }
        },
    }


class AttestationExtractionTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'{"test_only":true}\n'
        self.bundle = b'{"test_only": "mocked subprocess; not a signature"}'
        self.policy = json.loads(
            (ROOT / "production-evidence-policy.json").read_bytes()
        )
        self.identity = next(
            x
            for x in self.policy["sigstore"]["certificate_identities"]
            if x["kind"] == "qualification-release"
        )
        self.issuer = {"source_commit": "a" * 40, "ref": "refs/heads/main"}
        self.result = verified_result(
            self.raw,
            self.identity["issuer_repository"],
            self.issuer["source_commit"],
            self.issuer["ref"],
        )

    def runner(self, results=None, version="gh version 2.98.0 (2026-08-20)", status=0):
        self.commands = []

        def run(command, **kwargs):
            self.commands.append(command)
            if command == ["gh", "--version"]:
                return subprocess.CompletedProcess(command, 0, version + "\n", "")
            return subprocess.CompletedProcess(
                command,
                status,
                json.dumps(
                    results
                    if results is not None
                    else [{"verificationResult": self.result}]
                ),
                "test-only verification refusal" if status else "",
            )

        return run

    def verify(self):
        return verifier.verify_github_attestation(
            self.raw,
            self.bundle,
            identity=self.identity,
            issuer_identity=self.issuer,
            sigstore=self.policy["sigstore"],
        )

    def test_existing_policy_route_keeps_none_return_and_exact_flags(self):
        with mock.patch.object(verifier.subprocess, "run", side_effect=self.runner()):
            result = verifier.verify_sigstore(
                self.raw,
                self.bundle,
                kind="qualification-release",
                object_value={"issuer": self.issuer},
                policy=self.policy,
            )
        self.assertIsNone(result)
        command = self.commands[1]
        self.assertEqual(command[:3], ["gh", "attestation", "verify"])
        self.assertEqual(
            command[6:],
            [
                "--repo",
                self.identity["issuer_repository"],
                "--cert-identity",
                self.identity["certificate_identity"],
                "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--deny-self-hosted-runners",
                "--no-public-good",
                "--format",
                "json",
            ],
        )

    def test_helper_returns_only_the_verified_result(self):
        with mock.patch.object(verifier.subprocess, "run", side_effect=self.runner()):
            self.assertEqual(self.verify(), self.result)

    def test_wrong_subject_predicate_or_source_refuses(self):
        mutations = (
            lambda r: r["statement"]["subject"][0]["digest"].update(sha256="b" * 64),
            lambda r: r["statement"].update(predicateType="test-only/wrong"),
            lambda r: r["signature"]["certificate"].update(githubWorkflowSHA="b" * 40),
            lambda r: r["signature"]["certificate"].update(
                sourceRepositoryDigest="b" * 40
            ),
            lambda r: r["signature"]["certificate"].update(
                githubWorkflowRef="refs/heads/other"
            ),
            lambda r: r["signature"]["certificate"].update(
                githubWorkflowRepository="other/repo"
            ),
            lambda r: r["statement"]["predicate"]["buildDefinition"].update(
                resolvedDependencies=[]
            ),
        )
        for mutate in mutations:
            changed = copy.deepcopy(self.result)
            mutate(changed)
            with (
                self.subTest(mutation=mutate),
                mock.patch.object(
                    verifier.subprocess,
                    "run",
                    side_effect=self.runner([{"verificationResult": changed}]),
                ),
                self.assertRaises(verifier.trust.TrustError),
            ):
                self.verify()

    def test_multiple_results_failed_crypto_and_wrong_cli_refuse(self):
        for kwargs in (
            {"results": [{"verificationResult": self.result}] * 2},
            {"status": 1},
            {"version": "gh version 2.67.0 (2025-02-11)"},
        ):
            with (
                self.subTest(kwargs=kwargs),
                mock.patch.object(
                    verifier.subprocess,
                    "run",
                    side_effect=self.runner(**kwargs),
                ),
                self.assertRaises(verifier.trust.TrustError),
            ):
                self.verify()
        self.assertEqual(self.commands, [["gh", "--version"]])

    def test_existing_message_signature_route_is_unchanged(self):
        with (
            mock.patch.object(verifier, "verify_message_signature") as message,
            mock.patch.object(
                verifier.subprocess,
                "run",
                side_effect=AssertionError("wrong profile"),
            ),
        ):
            verifier.verify_sigstore(
                self.raw,
                self.bundle,
                kind="qualification-evidence-decision-receipt",
                object_value={"evidence_class": "private-customer"},
                policy=self.policy,
            )
        message.assert_called_once()
        self.assertEqual(
            message.call_args.kwargs["identity"]["bundle_profile"],
            "sigstore-message-signature",
        )


if __name__ == "__main__":
    unittest.main()
