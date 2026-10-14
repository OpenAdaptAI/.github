#!/usr/bin/env python3
"""Fail when the main branch of this repository is not protected.

This repository holds the admission ledgers, the evidence registry, and the
workflows that issue and verify admissions. Signed evidence fails verification
if someone edits it, but the workflows that define verification live on the
same branch. Without protection, anyone with write access can push to main,
force-push over its history, or delete it, with no review and no checks.

The check requires all of these on the branch:

1. Changes arrive through a pull request.
2. The `validate-profile` check, reported by GitHub Actions, must pass.
3. Force pushes are blocked.
4. Deleting the branch is blocked.

It also requires that nobody, administrators included, can bypass these
rules, whenever the token can read who may bypass them.

GitHub enforces repository rulesets and classic branch protection together, so
each requirement may come from either source:

- Rulesets that apply to the branch. Any token that can read the repository
  can read these rules. A ruleset's bypass list is readable only with
  administration access; without it, the run reports bypass as not checked.
- Classic branch protection. Reading it needs a token with read access to the
  repository's Administration settings. The default Actions token can't read
  it, so classic protection counts only when such a token is supplied.

To satisfy the check without an extra token, apply the committed ruleset:

    gh api -X POST repos/OpenAdaptAI/.github/rulesets \\
      --input main-branch-ruleset.json

The requirements live in this file, not in the ruleset body, so editing the
body can't weaken the check.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

API_ORIGIN = "https://api.github.com"
FETCH_TIMEOUT_SECONDS = 30
DEFAULT_REPOSITORY = "OpenAdaptAI/.github"
DEFAULT_BRANCH = "main"

REQUIRED_CHECK = "validate-profile"
GITHUB_ACTIONS_APP_ID = 15368
# A sole maintainer can't approve their own pull request, so the floor matches
# the other OpenAdapt repositories: a pull request is required, approval is not.
MINIMUM_APPROVALS = 0

PULL_REQUEST = "pull request required"
STATUS_CHECK = f"{REQUIRED_CHECK} check from GitHub Actions required"
FORCE_PUSH = "force pushes blocked"
DELETION = "deletion blocked"
REQUIREMENTS = (PULL_REQUEST, STATUS_CHECK, FORCE_PUSH, DELETION)

# Classic protection states other than a readable settings object.
NOT_PROTECTED = "not-protected"
UNREADABLE = "unreadable"

Fetch = Callable[[str], tuple[int, Any]]


def _approvals(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    count = value.get("required_approving_review_count")
    return (
        isinstance(count, int)
        and not isinstance(count, bool)
        and count >= MINIMUM_APPROVALS
    )


def _disabled(protection: dict, key: str) -> bool:
    setting = protection.get(key)
    return isinstance(setting, dict) and setting.get("enabled") is False


def _classic_pull_request_bypass(protection: dict) -> bool:
    """Return whether classic protection lets listed actors skip the pull request.

    Users, teams, or apps in `bypass_pull_request_allowances` can push to the
    branch without a pull request even when `enforce_admins` is on. An
    allowance in a shape this check doesn't recognize counts as a bypass.
    """
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict) or "bypass_pull_request_allowances" not in reviews:
        return False
    allowances = reviews["bypass_pull_request_allowances"]
    if not isinstance(allowances, dict):
        return True
    return any(allowances.values())


def classic_requirements(protection: Any) -> set[str]:
    """Return the requirements that readable classic protection satisfies."""
    if not isinstance(protection, dict):
        return set()
    met = set()
    if _approvals(protection.get("required_pull_request_reviews")):
        met.add(PULL_REQUEST)
    checks = protection.get("required_status_checks")
    checks = checks.get("checks") if isinstance(checks, dict) else None
    if isinstance(checks, list) and {
        "context": REQUIRED_CHECK,
        "app_id": GITHUB_ACTIONS_APP_ID,
    } in checks:
        met.add(STATUS_CHECK)
    if _disabled(protection, "allow_force_pushes"):
        met.add(FORCE_PUSH)
    if _disabled(protection, "allow_deletions"):
        met.add(DELETION)
    return met


def rule_requirement(rule: Any) -> str | None:
    """Return the requirement one ruleset rule satisfies, if any."""
    if not isinstance(rule, dict):
        return None
    kind = rule.get("type")
    parameters = rule.get("parameters")
    if kind == "pull_request" and _approvals(parameters):
        return PULL_REQUEST
    if kind == "required_status_checks" and isinstance(parameters, dict):
        checks = parameters.get("required_status_checks")
        if isinstance(checks, list) and any(
            isinstance(item, dict)
            and item.get("context") == REQUIRED_CHECK
            and item.get("integration_id") == GITHUB_ACTIONS_APP_ID
            for item in checks
        ):
            return STATUS_CHECK
    if kind == "non_fast_forward":
        return FORCE_PUSH
    if kind == "deletion":
        return DELETION
    return None


def evaluate(
    rules: list[Any],
    protection: Any,
    bypass_actors: dict[int, list | None],
) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for the observed protection of one branch.

    `rules` are the active ruleset rules for the branch. `protection` is the
    classic protection object, NOT_PROTECTED, or UNREADABLE. `bypass_actors`
    maps a ruleset id to its bypass list, or to None when it was unreadable.
    """
    classic = classic_requirements(protection)
    enforce_admins = (
        protection.get("enforce_admins") if isinstance(protection, dict) else None
    )
    classic_binds_admins = (
        isinstance(enforce_admins, dict) and enforce_admins.get("enabled") is True
    )
    problems: list[str] = []
    notes: list[str] = []
    for requirement in REQUIREMENTS:
        # Each source that enforces the requirement either binds
        # administrators ("bound"), lets someone bypass it ("bypass"), or has a
        # bypass list this token can't read ("unknown").
        outcomes = set()
        if requirement in classic:
            bound = classic_binds_admins and not (
                requirement == PULL_REQUEST and _classic_pull_request_bypass(protection)
            )
            outcomes.add("bound" if bound else "bypass")
        for rule in rules:
            if rule_requirement(rule) != requirement:
                continue
            actors = bypass_actors.get(rule.get("ruleset_id"))
            if actors is None:
                outcomes.add("unknown")
            else:
                outcomes.add("bypass" if actors else "bound")
        if not outcomes:
            problems.append(f"{requirement}: not set")
        elif "bound" in outcomes:
            continue
        elif "unknown" in outcomes:
            notes.append(
                f"{requirement}: set by a ruleset; whether anyone can bypass it "
                "was not checked, because this token can't read the bypass list"
            )
        else:
            problems.append(
                f"{requirement}: set, but administrators or listed actors can "
                "bypass it"
            )
    if problems and protection == UNREADABLE:
        notes.append(
            "This token can't read classic branch protection. Supply a token "
            "with read access to Administration, or apply main-branch-ruleset.json "
            "as a repository ruleset."
        )
    return problems, notes


def github_get(path: str) -> tuple[int, Any]:
    """GET one GitHub REST path and return (status, decoded JSON body)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "openadapt-branch-protection-check",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API_ORIGIN + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            body = json.load(error)
        except ValueError:
            body = None
        return error.code, body


def _ruleset_path(repository: str, rule: dict) -> str | None:
    ruleset_id = rule.get("ruleset_id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
        return None
    if rule.get("ruleset_source_type") == "Organization":
        organization = repository.split("/", 1)[0]
        return f"/orgs/{organization}/rulesets/{ruleset_id}"
    return f"/repos/{repository}/rulesets/{ruleset_id}"


def observe(repository: str, branch: str, fetch: Fetch):
    """Read the rules, classic protection, and bypass lists for a branch."""
    status, rules = fetch(f"/repos/{repository}/rules/branches/{branch}")
    if status != 200 or not isinstance(rules, list):
        raise RuntimeError(f"could not read the rules for {branch} (HTTP {status})")
    status, body = fetch(f"/repos/{repository}/branches/{branch}/protection")
    if status == 200 and isinstance(body, dict):
        protection: Any = body
    elif (
        status == 404
        and isinstance(body, dict)
        and body.get("message") == "Branch not protected"
    ):
        protection = NOT_PROTECTED
    else:
        protection = UNREADABLE
    bypass_actors: dict[int, list | None] = {}
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("ruleset_id") in bypass_actors:
            continue
        path = _ruleset_path(repository, rule)
        if path is None:
            continue
        status, detail = fetch(path)
        actors = detail.get("bypass_actors") if isinstance(detail, dict) else None
        bypass_actors[rule["ruleset_id"]] = (
            actors if status == 200 and isinstance(actors, list) else None
        )
    return rules, protection, bypass_actors


def main(argv: list[str] | None = None, fetch: Fetch = github_get) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY,
    )
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    args = parser.parse_args(argv)
    try:
        rules, protection, bypass_actors = observe(args.repository, args.branch, fetch)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    problems, notes = evaluate(rules, protection, bypass_actors)
    branch = f"Branch {args.branch} of {args.repository}"
    stream = sys.stderr if problems else sys.stdout
    if problems:
        print(f"{branch} is not protected as required:", file=stream)
        for problem in problems:
            print(f"- {problem}", file=stream)
    else:
        print(f"{branch} is protected as required.", file=stream)
    for note in notes:
        print(f"NOTE: {note}", file=stream)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
