"""The scheduled check fails while main can take unreviewed or forced pushes."""

from __future__ import annotations

import copy
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_branch_protection as check  # noqa: E402

REPOSITORY = "OpenAdaptAI/.github"
RULESET_ID = 1234567


def classic_protection() -> dict:
    """Classic protection in the shape GitHub returns to an admin token."""
    return {
        "required_status_checks": {
            "strict": False,
            "contexts": ["validate-profile"],
            "checks": [{"context": "validate-profile", "app_id": 15368}],
        },
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": False,
            "require_code_owner_reviews": False,
            "require_last_push_approval": False,
            "required_approving_review_count": 0,
        },
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def branch_rules(source_type: str = "Repository") -> list[dict]:
    """Ruleset rules in the shape of GET /repos/{repo}/rules/branches/main."""
    origin = {
        "ruleset_source_type": source_type,
        "ruleset_source": REPOSITORY,
        "ruleset_id": RULESET_ID,
    }
    return [
        {"type": "deletion", **origin},
        {"type": "non_fast_forward", **origin},
        {
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": False,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
            },
            **origin,
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "required_status_checks": [
                    {"context": "validate-profile", "integration_id": 15368}
                ],
            },
            **origin,
        },
    ]


def evaluate(rules=(), protection=check.NOT_PROTECTED, bypass=None):
    return check.evaluate(list(rules), protection, bypass or {})


class TodayTests(unittest.TestCase):
    """The state observed on 2026-10-09 must fail the check."""

    def test_unprotected_main_without_rulesets_fails_every_requirement(self) -> None:
        problems, _ = evaluate(rules=[], protection=check.NOT_PROTECTED)
        self.assertEqual(len(problems), len(check.REQUIREMENTS))
        text = "\n".join(problems)
        for requirement in check.REQUIREMENTS:
            self.assertIn(requirement, text)

    def test_unreadable_classic_protection_does_not_count_as_protection(self) -> None:
        problems, notes = evaluate(rules=[], protection=check.UNREADABLE)
        self.assertEqual(len(problems), len(check.REQUIREMENTS))
        self.assertTrue(any("Administration" in note for note in notes), notes)

    def test_command_exits_nonzero_on_the_observed_github_responses(self) -> None:
        responses = {
            f"/repos/{REPOSITORY}/rules/branches/main": (200, []),
            f"/repos/{REPOSITORY}/branches/main/protection": (
                404,
                {"message": "Branch not protected", "status": "404"},
            ),
        }
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = check.main(
                ["--repository", REPOSITORY, "--branch", "main"],
                fetch=lambda path: responses[path],
            )
        self.assertEqual(code, 1)
        self.assertIn("main", stderr.getvalue())
        self.assertIn("not protected", stderr.getvalue())


class ClassicProtectionTests(unittest.TestCase):
    def test_complete_classic_protection_passes(self) -> None:
        problems, notes = evaluate(protection=classic_protection())
        self.assertEqual(problems, [])
        self.assertEqual(notes, [])

    def test_each_missing_classic_setting_fails(self) -> None:
        mutations = {
            "pull request": lambda p: p.pop("required_pull_request_reviews"),
            "required check": lambda p: p.pop("required_status_checks"),
            "check from any app": lambda p: p["required_status_checks"]["checks"][
                0
            ].update(app_id=None),
            "other check": lambda p: p["required_status_checks"].update(
                checks=[{"context": "lint", "app_id": 15368}]
            ),
            "force push": lambda p: p["allow_force_pushes"].update(enabled=True),
            "deletion": lambda p: p["allow_deletions"].update(enabled=True),
            "missing force-push field": lambda p: p.pop("allow_force_pushes"),
            "admins bypass": lambda p: p["enforce_admins"].update(enabled=False),
            "pull request bypass allowance": lambda p: p[
                "required_pull_request_reviews"
            ].update(
                bypass_pull_request_allowances={
                    "users": [{"login": "maintainer", "id": 1}],
                    "teams": [],
                    "apps": [],
                }
            ),
            "malformed pull request bypass allowance": lambda p: p[
                "required_pull_request_reviews"
            ].update(bypass_pull_request_allowances=["maintainer"]),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                protection = classic_protection()
                mutate(protection)
                problems, _ = evaluate(protection=protection)
                self.assertNotEqual(problems, [])

    def test_pull_request_bypass_allowance_fails_only_that_requirement(self) -> None:
        protection = classic_protection()
        reviews = protection["required_pull_request_reviews"]
        reviews["bypass_pull_request_allowances"] = {
            "users": [],
            "teams": [],
            "apps": [{"slug": "some-app", "id": 2}],
        }
        problems, _ = evaluate(protection=protection)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(check.PULL_REQUEST, problems[0])
        self.assertIn("bypass", problems[0])

    def test_empty_pull_request_bypass_allowances_pass(self) -> None:
        protection = classic_protection()
        reviews = protection["required_pull_request_reviews"]
        reviews["bypass_pull_request_allowances"] = {
            "users": [],
            "teams": [],
            "apps": [],
        }
        self.assertEqual(evaluate(protection=protection)[0], [])

    def test_approval_floor_is_enforced(self) -> None:
        with mock.patch.object(check, "MINIMUM_APPROVALS", 1):
            problems, _ = evaluate(protection=classic_protection())
            self.assertTrue(any("pull request" in p for p in problems), problems)
            protection = classic_protection()
            protection["required_pull_request_reviews"][
                "required_approving_review_count"
            ] = 1
            self.assertEqual(evaluate(protection=protection)[0], [])


class RulesetTests(unittest.TestCase):
    def test_ruleset_with_readable_empty_bypass_list_passes(self) -> None:
        problems, notes = evaluate(rules=branch_rules(), bypass={RULESET_ID: []})
        self.assertEqual(problems, [])
        self.assertEqual(notes, [])

    def test_ruleset_bypass_list_unreadable_passes_with_a_note(self) -> None:
        problems, notes = evaluate(rules=branch_rules(), bypass={RULESET_ID: None})
        self.assertEqual(problems, [])
        self.assertTrue(notes)
        self.assertTrue(all("not checked" in note for note in notes), notes)

    def test_ruleset_with_a_bypass_actor_fails(self) -> None:
        actor = {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        problems, _ = evaluate(rules=branch_rules(), bypass={RULESET_ID: [actor]})
        self.assertEqual(len(problems), len(check.REQUIREMENTS))
        self.assertTrue(all("bypass" in p for p in problems), problems)

    def test_each_missing_ruleset_rule_fails(self) -> None:
        for index, rule in enumerate(branch_rules()):
            with self.subTest(rule=rule["type"]):
                rules = branch_rules()
                rules.pop(index)
                problems, _ = evaluate(rules=rules, bypass={RULESET_ID: []})
                self.assertEqual(len(problems), 1, problems)

    def test_status_check_must_come_from_github_actions(self) -> None:
        for check_entry in (
            {"context": "validate-profile"},
            {"context": "validate-profile", "integration_id": 1},
            {"context": "lint", "integration_id": 15368},
        ):
            with self.subTest(check_entry=check_entry):
                rules = branch_rules()
                rules[3]["parameters"]["required_status_checks"] = [check_entry]
                problems, _ = evaluate(rules=rules, bypass={RULESET_ID: []})
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("validate-profile", problems[0])

    def test_rules_split_across_ruleset_and_classic_protection_pass(self) -> None:
        protection = classic_protection()
        protection.pop("required_pull_request_reviews")
        protection["allow_deletions"]["enabled"] = True
        rules = [r for r in branch_rules() if r["type"] in {"pull_request", "deletion"}]
        problems, _ = evaluate(
            rules=rules, protection=protection, bypass={RULESET_ID: []}
        )
        self.assertEqual(problems, [])

    def test_command_reads_bypass_lists_by_ruleset_source(self) -> None:
        for source_type, detail_path in (
            ("Repository", f"/repos/{REPOSITORY}/rulesets/{RULESET_ID}"),
            ("Organization", f"/orgs/OpenAdaptAI/rulesets/{RULESET_ID}"),
        ):
            with self.subTest(source_type=source_type):
                rules = branch_rules(source_type)
                if source_type == "Organization":
                    for rule in rules:
                        rule["ruleset_source"] = "OpenAdaptAI"
                responses = {
                    f"/repos/{REPOSITORY}/rules/branches/main": (200, rules),
                    f"/repos/{REPOSITORY}/branches/main/protection": (
                        403,
                        {"message": "Resource not accessible by integration"},
                    ),
                    detail_path: (200, {"id": RULESET_ID, "bypass_actors": []}),
                }
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = check.main(
                        ["--repository", REPOSITORY],
                        fetch=lambda path: responses[path],
                    )
                self.assertEqual(code, 0)


class CommittedRulesetTests(unittest.TestCase):
    """Applying the committed ruleset body must satisfy the check."""

    def test_committed_ruleset_satisfies_the_check(self) -> None:
        body = json.loads((ROOT / "main-branch-ruleset.json").read_text())
        self.assertEqual(body["target"], "branch")
        self.assertEqual(body["enforcement"], "active")
        self.assertEqual(body["bypass_actors"], [])
        self.assertEqual(
            body["conditions"],
            {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        )
        origin = {
            "ruleset_source_type": "Repository",
            "ruleset_source": REPOSITORY,
            "ruleset_id": RULESET_ID,
        }
        rules = [{**copy.deepcopy(rule), **origin} for rule in body["rules"]]
        problems, notes = evaluate(rules=rules, bypass={RULESET_ID: []})
        self.assertEqual(problems, [])
        self.assertEqual(notes, [])


class WorkflowTests(unittest.TestCase):
    def test_profile_workflow_runs_the_check_on_schedule(self) -> None:
        content = (ROOT / ".github/workflows/profile-consistency.yml").read_text()
        job = content.split("  check-branch-protection:\n", 1)[1]
        job = job.split("\n  report-", 1)[0]
        self.assertIn("github.event_name == 'schedule'", job)
        self.assertIn("github.event_name == 'workflow_dispatch'", job)
        self.assertIn("github.actor != 'openadapt-lifecycle[bot]'", job)
        self.assertIn("python3 scripts/check_branch_protection.py", job)
        self.assertIn("github.token", job)
        self.assertIn("persist-credentials: false", job)
        self.assertNotIn("pull_request", job)
        self.assertIn("  report-unprotected-branch:\n", content)
        self.assertIn("needs.check-branch-protection.result == 'failure'", content)

    def test_required_check_fails_instead_of_skipping(self) -> None:
        # GitHub counts a skipped job as a passing required check. A pull
        # request the lifecycle App opens would then show the required check
        # as passed although validation never ran. So the job behind each
        # required check has no job-level condition or dependency that could
        # skip it, and it refuses the lifecycle App with a failing first step.
        body = json.loads((ROOT / "main-branch-ruleset.json").read_text())
        contexts = [
            item["context"]
            for rule in body["rules"]
            if rule["type"] == "required_status_checks"
            for item in rule["parameters"]["required_status_checks"]
        ]
        self.assertEqual(contexts, [check.REQUIRED_CHECK])
        content = (ROOT / ".github/workflows/profile-consistency.yml").read_text()
        for context in contexts:
            job = content.split(f"\n  {context}:\n", 1)[1]
            job = re.split(r"\n  (?=\S)", job, maxsplit=1)[0]
            self.assertNotRegex(job, r"(?m)^    if:", context)
            self.assertNotRegex(job, r"(?m)^    needs:", context)
            first_step = job.split("    steps:\n      - ", 1)[1]
            first_step = first_step.split("\n      - ", 1)[0]
            self.assertNotIn("uses:", first_step, context)
            self.assertIn("ACTOR: ${{ github.actor }}", first_step, context)
            self.assertIn(
                "TRIGGERING_ACTOR: ${{ github.triggering_actor }}", first_step, context
            )
            self.assertIn(
                "test \"$ACTOR\" != 'openadapt-lifecycle[bot]'", first_step, context
            )
            self.assertIn(
                "test \"$TRIGGERING_ACTOR\" != 'openadapt-lifecycle[bot]'",
                first_step,
                context,
            )


if __name__ == "__main__":
    unittest.main()
