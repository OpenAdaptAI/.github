"""Flow and agent release from the OpenAdapt monorepo under package tags.

Flow from 2.2.0 and agent from 2.2.1 come from OpenAdaptAI/OpenAdapt
(packages/flow, packages/agent) and carry openadapt-flow-v<version> and
openadapt-agent-v<version> tags, so they never share the launcher's v*
namespace there. Every earlier release stays bound to its standalone
repository and its plain v<version> tag. The version decides which; nothing
else can choose.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import test_qualification_issuer as samples  # noqa: E402
from test_production_trust import rulesets, trust  # noqa: E402

MONOREPO = {"repository": "OpenAdaptAI/OpenAdapt", "repository_id": "627024850"}
FLOW_REPO = {"repository": "OpenAdaptAI/openadapt-flow", "repository_id": "1291376938"}
AGENT_REPO = {"repository": "OpenAdaptAI/openadapt-agent", "repository_id": "1136136670"}


def package_rulesets(prefix: str, repository: dict) -> list[dict]:
    value = rulesets()
    names = trust.tag_ruleset_names(prefix)
    for index, ruleset in enumerate(value):
        ruleset.update(repository)
        ruleset["name"] = names[index]
        ruleset["conditions"]["ref_name"]["include"] = [trust.tag_ref_pattern(prefix)]
    return value


class ReleaseSourceTests(unittest.TestCase):
    def test_the_version_alone_selects_the_source(self) -> None:
        cases = [
            ("flow", "2.1.0", {**FLOW_REPO, "tag_prefix": ""}),
            ("flow", "2.2.0-rc.1", {**FLOW_REPO, "tag_prefix": ""}),
            ("flow", "2.2.0", {**MONOREPO, "tag_prefix": "openadapt-flow-"}),
            ("flow", "3.0.0", {**MONOREPO, "tag_prefix": "openadapt-flow-"}),
            ("agent", "2.2.0", {**AGENT_REPO, "tag_prefix": ""}),
            ("agent", "2.2.1", {**MONOREPO, "tag_prefix": "openadapt-agent-"}),
            ("openadapt", "1.17.0", {**MONOREPO, "tag_prefix": ""}),
            (
                "capture",
                "1.2.2",
                {
                    "repository": "OpenAdaptAI/openadapt-capture",
                    "repository_id": "1115283835",
                    "tag_prefix": "",
                },
            ),
        ]
        for target, version, expected in cases:
            with self.subTest(target=target, version=version):
                self.assertEqual(trust.release_source(target, version), expected)

    def test_release_tag_is_exact_per_target_and_version(self) -> None:
        self.assertEqual(trust.release_tag("flow", "2.2.0"), "openadapt-flow-v2.2.0")
        self.assertEqual(trust.release_tag("flow", "2.1.0"), "v2.1.0")
        self.assertEqual(trust.release_tag("agent", "2.2.1"), "openadapt-agent-v2.2.1")
        self.assertEqual(trust.release_tag("agent", "2.2.0"), "v2.2.0")
        self.assertEqual(trust.release_tag("openadapt", "1.17.0"), "v1.17.0")

    def test_a_tag_resolves_only_to_the_source_that_would_carry_it(self) -> None:
        self.assertEqual(
            trust.release_source_for_tag("flow", "openadapt-flow-v2.2.0"),
            {**MONOREPO, "tag_prefix": "openadapt-flow-"},
        )
        self.assertEqual(
            trust.release_source_for_tag("flow", "v2.1.0"),
            {**FLOW_REPO, "tag_prefix": ""},
        )
        for target, tag in [
            ("flow", "v2.2.0"),  # 2.2.0 is a monorepo release
            ("flow", "openadapt-flow-v2.1.0"),  # 2.1.0 came from openadapt-flow
            ("flow", "openadapt-agent-v2.2.1"),  # another package's tag
            ("flow", "openadapt-flow-2.2.0"),
            ("flow", "openadapt-flow-v2.2"),
            ("flow", "xopenadapt-flow-v2.2.0"),
            ("agent", "v2.2.1"),
            ("agent", "openadapt-agent-v2.2.0"),
            ("openadapt", "openadapt-flow-v2.2.0"),
            ("capture", "openadapt-capture-v1.2.2"),
            ("flow", None),
        ]:
            with self.subTest(target=target, tag=tag):
                self.assertIsNone(trust.release_source_for_tag(target, tag))

    def test_a_tag_prefix_is_an_exact_package_literal(self) -> None:
        for prefix in ("", "openadapt-flow-", "openadapt-agent-"):
            self.assertEqual(trust.require_tag_prefix(prefix), prefix)
        for prefix in ("*", "openadapt-*", "flow-", "openadapt-flow", "openadapt-flow-v", None):
            with self.subTest(prefix=prefix):
                with self.assertRaises(trust.TrustError):
                    trust.require_tag_prefix(prefix)

    def test_the_authority_policy_names_each_moved_target_exactly(self) -> None:
        policy = json.loads(
            (ROOT / "production-release-authority-policy.json").read_text()
        )
        by_target = {entry["target"]: entry for entry in policy["repositories"]}
        for target in ("agent", "flow"):
            with self.subTest(target=target):
                contract = trust.TARGET_CONTRACTS[target]
                entry = by_target[target]
                prefix = contract["tag_prefix"]
                self.assertEqual(entry["repository"], contract["repository"])
                self.assertEqual(entry["repository_id"], contract["repository_id"])
                self.assertEqual(entry["package_path"], contract["package_path"])
                self.assertEqual(entry["tag_pattern"], trust.tag_ref_pattern(prefix))
                self.assertEqual(
                    (entry["creation_ruleset"], entry["immutability_ruleset"]),
                    trust.tag_ruleset_names(prefix),
                )
        lifecycle = json.loads((ROOT / "production-lifecycle-policy.json").read_text())
        for target in lifecycle["targets"]:
            contract = trust.TARGET_CONTRACTS[target["id"]]
            self.assertEqual(target["source_repository"], contract["repository"])
            self.assertEqual(target["source_repository_id"], contract["repository_id"])


class PackageTagRulesetTests(unittest.TestCase):
    def test_the_exact_package_rulesets_pass(self) -> None:
        for prefix in ("openadapt-flow-", "openadapt-agent-"):
            with self.subTest(prefix=prefix):
                value = package_rulesets(prefix, MONOREPO)
                self.assertEqual(
                    trust.validate_tag_rulesets(value, **MONOREPO, tag_prefix=prefix),
                    value,
                )

    def test_any_other_pattern_or_name_is_refused(self) -> None:
        prefix = "openadapt-flow-"

        def refused(mutate) -> None:
            value = package_rulesets(prefix, MONOREPO)
            mutate(value)
            with self.assertRaises(trust.TrustError):
                trust.validate_tag_rulesets(value, **MONOREPO, tag_prefix=prefix)

        for include in (
            ["refs/tags/v*"],
            ["refs/tags/openadapt-*"],
            ["refs/tags/*"],
            ["refs/tags/openadapt-agent-v*"],
            ["refs/tags/openadapt-flow-v*", "refs/tags/v*"],
        ):
            with self.subTest(include=include):
                refused(
                    lambda value, include=include: [
                        ruleset["conditions"]["ref_name"].__setitem__(
                            "include", list(include)
                        )
                        for ruleset in value
                    ]
                )
        with self.subTest("launcher ruleset names"):
            refused(
                lambda value: [
                    ruleset.__setitem__("name", name)
                    for ruleset, name in zip(value, trust.DEFAULT_TAG_RULESET_NAMES)
                ]
            )
        with self.subTest("launcher rulesets for a package tag"):
            with self.assertRaises(trust.TrustError):
                trust.validate_tag_rulesets(
                    package_rulesets("", MONOREPO), **MONOREPO, tag_prefix=prefix
                )
        with self.subTest("package rulesets for a launcher tag"):
            with self.assertRaises(trust.TrustError):
                trust.validate_tag_rulesets(
                    package_rulesets(prefix, MONOREPO), **MONOREPO, tag_prefix=""
                )


class MonorepoFlowAdmissionTests(unittest.TestCase):
    def issue(self, version: str) -> dict:
        fixture = samples.trust_fixture()
        resolver = samples.RecordingResolver(fixture)
        workflow = samples.issuer.issue_workflow_admission(
            samples.workflow_request(fixture),
            resolver=resolver,
            issuer_source_commit=samples.WORKFLOW_REGISTRY_COMMIT,
            now=samples.NOW,
            consumer=samples.RecordingConsumer(),
        )
        request = samples.flow_release_inputs(
            fixture, workflow, resolver, version=version
        )
        return samples.issuer.issue_release_admission(
            request,
            resolver=resolver,
            issuer_source_commit=samples.RELEASE_REGISTRY_COMMIT,
            now=samples.NOW,
            consumer=samples.RecordingConsumer(),
        )

    def test_flow_2_2_0_is_admitted_from_the_monorepo_under_its_package_tag(self):
        release = self.issue("2.2.0")
        self.assertEqual(release["release"]["source_repository"], MONOREPO["repository"])
        self.assertEqual(release["release"]["tag"], "openadapt-flow-v2.2.0")
        staging = release["publication_staging"]
        self.assertEqual(staging["tag"], "openadapt-flow-v2.2.0")
        self.assertEqual(
            staging["tag_rulesets"][0]["conditions"]["ref_name"]["include"],
            ["refs/tags/openadapt-flow-v*"],
        )
        self.assertEqual(trust.validate_release(release, now=samples.NOW), release)
        schema = json.loads((ROOT / "schemas/qualification-release.schema.json").read_text())
        registry = Registry().with_resources(
            (path.name, Resource.from_contents(json.loads(path.read_text())))
            for path in (ROOT / "schemas").glob("*.schema.json")
        )
        self.assertEqual(
            list(Draft202012Validator(schema, registry=registry).iter_errors(release)), []
        )

    def test_a_monorepo_release_cannot_claim_the_old_repository_or_tag(self):
        release = self.issue("2.2.0")
        for field, value in (
            ("source_repository", FLOW_REPO["repository"]),
            ("source_repository_id", FLOW_REPO["repository_id"]),
            ("tag", "v2.2.0"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(release)
                changed["release"][field] = value
                with self.assertRaises(trust.TrustError):
                    trust.validate_release(changed, now=samples.NOW)

    def test_an_earlier_release_cannot_claim_the_monorepo(self):
        release = self.issue("1.35.0")
        self.assertEqual(release["release"]["source_repository"], FLOW_REPO["repository"])
        for field, value in (
            ("source_repository", MONOREPO["repository"]),
            ("source_repository_id", MONOREPO["repository_id"]),
            ("tag", "openadapt-flow-v1.35.0"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(release)
                changed["release"][field] = value
                with self.assertRaises(trust.TrustError):
                    trust.validate_release(changed, now=samples.NOW)


if __name__ == "__main__":
    unittest.main()
