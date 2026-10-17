"""Tests for the registry's public GitHub metadata and the script that applies it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_profile  # noqa: E402
import github_metadata as metadata_module  # noqa: E402
from github_metadata import (  # noqa: E402
    MetadataError,
    PublicMetadata,
    RepositoryMetadata,
    load_public_metadata,
    parse_public_metadata_mapping,
    render_apply_script,
    structural_errors,
)

BASH = shutil.which("bash")


def published() -> PublicMetadata:
    return load_public_metadata(ROOT / "repository-lifecycle.yml")


def product_repositories() -> set[str]:
    policy = json.loads(
        (ROOT / "production-lifecycle-policy.json").read_text(encoding="utf-8")
    )
    return check_profile.product_repository_names(policy)


def lifecycles() -> dict[str, str]:
    errors: list[str] = []
    groups = check_profile.parse_lifecycle_groups(
        (ROOT / "repository-lifecycle.yml").read_text(encoding="utf-8"), errors
    )
    assert not errors, errors
    return {name: group for group, names in groups.items() for name in names}


def with_repository(metadata: PublicMetadata, name: str, **changes: object) -> PublicMetadata:
    repositories = dict(metadata.repositories)
    repositories[name] = replace(repositories[name], **changes)
    return replace(metadata, repositories=repositories)


SAMPLE = """\
schema_version: 2
public_metadata:
  organization_description: >-
    Enters approved information and checks
    that it saved.
  organization_homepage: https://example.com/
  profile_headline: >-
    One plain line.
  pinned_repositories:
    - alpha
  repositories:
    alpha:
      description: >-
        Alpha's description.
      homepage: https://example.com/alpha
      topics:
        - one
        - two
    .github:
      description: >-
        Support: the profile.
      homepage: ""
      topics: []
lifecycle:
  support:
    - .github
"""


class ParserTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = Path(directory) / "repository-lifecycle.yml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_published_registry_loads(self) -> None:
        metadata = published()
        self.assertEqual(
            metadata.pinned_repositories, check_profile.EXPECTED_PINNED_REPOSITORIES
        )
        self.assertIn("ehr-integration-directory", metadata.repositories)

    def test_the_parser_agrees_with_a_full_yaml_parser(self) -> None:
        try:
            import yaml
        except ImportError:  # pragma: no cover - PyYAML is optional here
            self.skipTest("PyYAML isn't installed")
        text = (ROOT / "repository-lifecycle.yml").read_text(encoding="utf-8")
        self.assertEqual(
            parse_public_metadata_mapping(text), yaml.safe_load(text)["public_metadata"]
        )
        self.assertEqual(
            parse_public_metadata_mapping(SAMPLE), yaml.safe_load(SAMPLE)["public_metadata"]
        )

    def test_folded_text_empty_values_and_lists(self) -> None:
        metadata = load_public_metadata(self.write(SAMPLE))
        self.assertEqual(
            metadata.organization_description,
            "Enters approved information and checks that it saved.",
        )
        self.assertEqual(metadata.repositories["alpha"].topics, ("one", "two"))
        self.assertEqual(metadata.repositories[".github"].homepage, "")
        self.assertEqual(metadata.repositories[".github"].topics, ())

    def test_a_quoted_or_ambiguous_value_is_refused(self) -> None:
        for bad in (
            "      homepage: 'https://example.com'",
            "      homepage: https://example.com # comment",
            "      homepage: key: value",
        ):
            text = SAMPLE.replace("      homepage: https://example.com/alpha", bad)
            with self.subTest(bad=bad), self.assertRaises(MetadataError):
                load_public_metadata(self.write(text))

    def test_a_duplicate_key_is_refused(self) -> None:
        text = SAMPLE.replace(
            "      homepage: https://example.com/alpha\n",
            "      homepage: https://example.com/alpha\n"
            "      homepage: https://example.com/beta\n",
        )
        with self.assertRaisesRegex(MetadataError, "duplicate key"):
            load_public_metadata(self.write(text))

    def test_a_misindented_key_is_refused(self) -> None:
        text = SAMPLE.replace("      homepage: \"\"", "     homepage: \"\"")
        with self.assertRaises(MetadataError):
            load_public_metadata(self.write(text))

    def test_an_unknown_or_missing_key_is_refused(self) -> None:
        text = SAMPLE.replace("  profile_headline: >-\n    One plain line.\n", "")
        with self.assertRaisesRegex(MetadataError, "keys are"):
            load_public_metadata(self.write(text))

    def test_github_and_copy_rules(self) -> None:
        base = load_public_metadata(self.write(SAMPLE))
        cases = {
            "too many topics": with_repository(
                base, "alpha", topics=tuple(f"t{index}" for index in range(21))
            ),
            "invalid topic": with_repository(base, "alpha", topics=("Not_Valid",)),
            "repeated topic": with_repository(base, "alpha", topics=("one", "one")),
            "em dash": with_repository(base, "alpha", description="Alpha — beta."),
            "curly quote": with_repository(base, "alpha", description="Alpha’s app."),
            "too long": with_repository(base, "alpha", description="x" * 161),
            "http website": with_repository(base, "alpha", homepage="http://example.com"),
            "pin without entry": replace(base, pinned_repositories=("alpha", "missing")),
            "repeated pin": replace(base, pinned_repositories=("alpha", "alpha")),
            "seven pins": replace(base, pinned_repositories=("alpha",) * 7),
        }
        self.assertEqual(structural_errors(base), [])
        for label, metadata in cases.items():
            with self.subTest(label):
                self.assertTrue(structural_errors(metadata))


class CheckRuleTests(unittest.TestCase):
    def errors(self, metadata: PublicMetadata, groups: dict[str, str] | None = None) -> list[str]:
        return check_profile.metadata_errors(
            metadata, product_repositories(), lifecycles() if groups is None else groups
        )

    def test_the_published_metadata_passes(self) -> None:
        self.assertEqual(self.errors(published()), [])

    def test_a_research_repository_cannot_be_pinned(self) -> None:
        metadata = replace(
            published(),
            pinned_repositories=published().pinned_repositories[:5] + ("openadapt-evals",),
        )
        errors = self.errors(metadata)
        self.assertTrue(any("pins openadapt-evals, which is research" in e for e in errors))
        self.assertTrue(any("product pins do not match" in e for e in errors))

    def test_a_non_product_description_opens_with_its_lifecycle(self) -> None:
        metadata = with_repository(
            published(), "openadapt-ml", description="Optional model training."
        )
        self.assertTrue(
            any("must start with 'Research:'" in e for e in self.errors(metadata))
        )

    def test_a_label_must_match_the_lifecycle(self) -> None:
        metadata = with_repository(
            published(), "openadapt-viewer", description="Research: a viewer."
        )
        self.assertTrue(any("opens with 'Research'" in e for e in self.errors(metadata)))

    def test_a_product_description_carries_no_static_label(self) -> None:
        metadata = with_repository(
            published(), "openadapt-desktop", description="Experimental desktop app."
        )
        self.assertTrue(any("static lifecycle labels" in e for e in self.errors(metadata)))

    def test_a_described_repository_needs_a_lifecycle(self) -> None:
        groups = lifecycles()
        del groups["openadapt-wright"]
        self.assertTrue(
            any("openadapt-wright, which is neither" in e for e in self.errors(published(), groups))
        )

    def test_pinned_and_organization_copy_use_business_words(self) -> None:
        pinned = with_repository(
            published(),
            "openadapt-capture",
            description="Exposes governed workflows over MCP.",
        )
        errors = self.errors(pinned)
        self.assertTrue(any("'governed'" in e for e in errors))
        self.assertTrue(any("'MCP'" in e for e in errors))
        organization = replace(
            published(), organization_description="Reports VERIFIED after an oracle read."
        )
        self.assertEqual(
            len([e for e in self.errors(organization) if "organization_description" in e]), 2
        )

    def test_the_profile_business_section_uses_business_words(self) -> None:
        profile = (ROOT / "profile" / "README.md").read_text(encoding="utf-8")
        business, developer = profile.split(f"\n{check_profile.DEVELOPER_HEADING}\n", 1)
        self.assertEqual(
            check_profile.business_term_errors("business", check_profile.reader_words(business)),
            [],
        )
        # The technical terms live one level deeper, below the developer heading.
        self.assertIn("RECONCILIATION_REQUIRED", developer)
        self.assertIn("VERIFIED", developer)

    def test_link_destinations_and_code_are_not_prose(self) -> None:
        text = "See [the docs](https://example.com/governed).\n```\nopenadapt mcp\n```\n"
        self.assertEqual(
            check_profile.business_term_errors("x", check_profile.reader_words(text)), []
        )

    def test_the_profile_never_prints_the_misstated_fault_count(self) -> None:
        profile = " ".join(
            (ROOT / "profile" / "README.md").read_text(encoding="utf-8").split()
        )
        self.assertNotIn("54 of 90", profile)
        self.assertIn("54 of 72 (75.0%)", profile)

    def test_the_whole_profile_check_passes(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_profile.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


FAKE_GH = """\
#!{python}
import json, os, sys

state_path = os.environ["FAKE_GH_STATE"]
with open(os.environ["FAKE_GH_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
with open(state_path) as handle:
    state = json.load(handle)

def save():
    with open(state_path, "w") as handle:
        json.dump(state, handle)

args = sys.argv[1:]
if args[:2] == ["auth", "status"]:
    sys.exit(0 if state.get("signed_in", True) else 1)
assert args[0] == "api", args
method, jq, path, index = "GET", None, None, 1
while index < len(args):
    arg = args[index]
    if arg in ("--method", "--jq", "-f", "-F", "--input"):
        if arg == "--method":
            method = args[index + 1]
        elif arg == "--jq":
            jq = args[index + 1]
        index += 2
        continue
    if arg != "--paginate" and path is None:
        path = arg
    index += 1

if method + " " + path in state.get("fail", []):
    print("HTTP 403: refused", file=sys.stderr)
    sys.exit(1)
parts = path.split("/")
blank = {{"description": "", "homepage": "", "topics": []}}
if method == "PATCH" and parts[0] == "orgs":
    state["org"].update(json.load(sys.stdin))
elif method == "PATCH" and parts[0] == "repos":
    state["repos"].setdefault(parts[2], dict(blank)).update(json.load(sys.stdin))
elif method == "PUT" and parts[-1] == "topics":
    state["repos"].setdefault(parts[2], dict(blank))["topics"] = json.load(sys.stdin)["names"]
elif path.startswith("user/memberships/orgs/"):
    print(state["role"])
    sys.exit(0)
elif path == "graphql":
    assert jq == '[.data.organization.pinnedItems.nodes[].name] | join(",")', jq
    print(",".join(state["pins"]))
    sys.exit(0)
elif path.endswith("/repos?type=public&per_page=100"):
    print("\\n".join(state["public"]))
    sys.exit(0)
elif parts[0] == "orgs":
    field = {{'.description // ""': "description", '.blog // ""': "blog"}}[jq]
    print(state["org"].get(field) or "")
    sys.exit(0)
elif parts[0] == "repos":
    repository = state["repos"].get(parts[2])
    if repository is None:
        print("HTTP 404: Not Found", file=sys.stderr)
        sys.exit(1)
    if parts[-1] == "topics":
        assert jq == '.names | sort | join(",")', jq
        print(",".join(sorted(repository["topics"])))
    else:
        field = {{'.description // ""': "description", '.homepage // ""': "homepage"}}[jq]
        print(repository.get(field) or "")
    sys.exit(0)
else:
    print("unexpected call: " + " ".join(args), file=sys.stderr)
    sys.exit(3)
save()
"""

EXAMPLE = PublicMetadata(
    organization_description="Enters approved information and checks that it saved.",
    organization_homepage="https://example.com/",
    profile_headline="One plain line.",
    pinned_repositories=("alpha", "beta"),
    repositories={
        "alpha": RepositoryMetadata(
            "alpha", "Alpha's description.", "https://example.com/alpha", ("two", "one")
        ),
        "beta": RepositoryMetadata("beta", "Support: beta.", "", ()),
    },
)


@unittest.skipIf(BASH is None, "bash isn't installed")
class ApplyScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        self.directory = Path(directory)
        bin_directory = self.directory / "bin"
        bin_directory.mkdir()
        gh = bin_directory / "gh"
        gh.write_text(FAKE_GH.format(python=sys.executable), encoding="utf-8")
        gh.chmod(0o755)
        self.state_path = self.directory / "state.json"
        self.log_path = self.directory / "calls.log"
        self.log_path.write_text("", encoding="utf-8")
        self.script = self.directory / "APPLY.sh"
        self.script.write_text(
            render_apply_script(EXAMPLE, organization="ExampleOrg"), encoding="utf-8"
        )
        self.script.chmod(0o755)
        self.env = {
            "PATH": f"{bin_directory}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "TMPDIR": str(self.directory),
            "FAKE_GH_STATE": str(self.state_path),
            "FAKE_GH_LOG": str(self.log_path),
        }
        self.set_state()

    def set_state(self, **changes: object) -> None:
        state = {
            "role": "admin",
            "org": {"description": "Old.", "blog": "https://example.com/"},
            "repos": {
                "alpha": {"description": "Old alpha.", "homepage": "", "topics": ["old"]},
                "beta": {"description": "", "homepage": "https://old.example", "topics": []},
            },
            "pins": ["alpha", "beta"],
            "public": ["alpha", "beta", "stray-fork"],
            "fail": [],
        }
        state.update(changes)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    def run_script(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, str(self.script), *arguments],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=120,
        )

    def calls(self) -> list[list[str]]:
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    def writes(self) -> list[list[str]]:
        return [call for call in self.calls() if "--method" in call]

    def test_the_committed_script_matches_the_registry(self) -> None:
        script = metadata_module.APPLY_SCRIPT
        self.assertTrue(script.exists(), "render it with github_metadata.py render-apply")
        self.assertEqual(script.read_text(encoding="utf-8"), render_apply_script(published()))
        self.assertTrue(os.access(script, os.X_OK))
        completed = subprocess.run([BASH, "-n", str(script)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_committed_script_dry_run_calls_nothing(self) -> None:
        completed = subprocess.run(
            [BASH, str(metadata_module.APPLY_SCRIPT)],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.calls(), [])
        for name in published().repositories:
            self.assertIn(f"# {name}: description and website", completed.stdout)
        self.assertIn("Nothing was called or changed.", completed.stdout)

    def test_a_dry_run_prints_exact_commands_and_bodies(self) -> None:
        completed = self.run_script("--dry-run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.calls(), [])
        self.assertIn(
            "gh api --method PATCH repos/ExampleOrg/alpha --input - <<'JSON'\n"
            '{"description": "Alpha\'s description.", "homepage": "https://example.com/alpha"}\n'
            "JSON\n",
            completed.stdout,
        )
        self.assertIn('{"names": ["two", "one"]}', completed.stdout)

    def test_apply_writes_reads_back_and_reports_success_only_when_all_match(self) -> None:
        completed = self.run_script("--apply")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(state["repos"]["alpha"]["description"], "Alpha's description.")
        self.assertEqual(state["repos"]["alpha"]["topics"], ["two", "one"])
        self.assertEqual(state["repos"]["beta"]["homepage"], "")
        self.assertEqual(state["org"]["description"], EXAMPLE.organization_description)
        self.assertIn("GitHub matches repository-lifecycle.yml", completed.stdout)
        self.assertIn("note       stray-fork is public", completed.stdout)
        self.assertEqual(len(self.writes()), 5)

    def test_one_failed_write_fails_the_run_and_names_the_change(self) -> None:
        self.set_state(fail=["PATCH repos/ExampleOrg/alpha"])
        completed = self.run_script("--apply")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("FAILED     alpha: description and website", completed.stderr)
        self.assertIn("HTTP 403: refused", completed.stderr)
        self.assertIn("DIFFERS    alpha: description", completed.stderr)
        self.assertIn("1 of 5 changes failed", completed.stderr)
        self.assertNotIn("GitHub matches", completed.stdout)

    def test_an_unreadable_value_is_not_a_match(self) -> None:
        self.set_state(fail=["GET repos/ExampleOrg/beta/topics"])
        completed = self.run_script("--verify")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("UNREAD     beta: topics", completed.stderr)
        self.assertNotIn("GitHub matches", completed.stdout)

    def test_pins_left_for_an_owner_exit_two(self) -> None:
        self.set_state(pins=["beta", "alpha"])
        completed = self.run_script("--apply")
        self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
        self.assertIn("TO PIN", completed.stderr)
        self.assertNotIn("GitHub matches", completed.stdout)

    def test_apply_refuses_an_account_that_is_not_an_owner(self) -> None:
        self.set_state(role="member")
        completed = self.run_script("--apply")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("isn't an owner of ExampleOrg", completed.stderr)
        self.assertEqual(self.writes(), [])

    def test_apply_refuses_when_gh_is_signed_out(self) -> None:
        self.set_state(signed_in=False)
        completed = self.run_script("--apply")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(self.writes(), [])

    def test_verify_never_writes(self) -> None:
        completed = self.run_script("--verify")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(self.writes(), [])
        self.assertIn("DIFFERS    organization: description", completed.stderr)

    def test_an_unknown_option_is_a_usage_error(self) -> None:
        self.assertEqual(self.run_script("--force").returncode, 64)
        self.assertEqual(self.run_script("--apply", "--verify").returncode, 64)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
