#!/usr/bin/env python3
"""Check the public profile and its evidence-gated lifecycle."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from validate_production_lifecycle import LifecycleError, validate_files

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profile" / "README.md"
LIFECYCLE_DOC = ROOT / "REPOSITORY_LIFECYCLE.md"
LIFECYCLE_DATA = ROOT / "repository-lifecycle.yml"
MARKDOWN_FILES = (ROOT / "README.md", ROOT / "LAUNCH_PLAN.md", LIFECYCLE_DOC, PROFILE)
CANONICAL_TRUTH = (
    "OpenAdapt compiles demonstrations into governed workflows across browser, "
    "native desktop, RDP, and Citrix. The default healthy path executes "
    "deterministically and makes no generative-model API calls. Consequential "
    "actions are identity-gated, results are checked against the workflow's "
    "evidence contract, and uncertainty halts for review instead of being "
    "reported as success."
)
REQUIRED_PROFILE_LINKS = {
    "https://github.com/OpenAdaptAI/OpenAdapt",
    "https://github.com/OpenAdaptAI/openadapt-flow",
    "https://github.com/OpenAdaptAI/openadapt-desktop",
    "https://github.com/OpenAdaptAI/openadapt-capture",
    "https://github.com/OpenAdaptAI/openadapt-agent",
    "https://github.com/OpenAdaptAI/openadapt-ops",
    "https://github.com/OpenAdaptAI/openadapt-evals",
    "https://github.com/OpenAdaptAI/openadapt-flow/tree/main/docs/showcase",
    "https://openadapt.ai/",
    "https://app.openadapt.ai/",
    "https://docs.openadapt.ai",
    "https://docs.openadapt.ai/production-lifecycle.json",
}
REQUIRED_PROFILE_MARKERS = {
    "## Product Surfaces",
    "## Research and Labs",
    "A Production run also requires a separate active admission for the exact "
    "workflow.",
    "more than 1.6k stars",
}

EXPECTED_PINNED_REPOSITORIES = (
    "OpenAdapt",
    "openadapt-flow",
    "openadapt-desktop",
    "openadapt-capture",
    "openadapt-agent",
    "openadapt-evals",
)
LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^\s)]+)(?:\s+[^)]*)?\)")
PROFILE_TARGET_ROW_RE = re.compile(r"^\| `([a-z]+)` \|\s*(.*?)\s*\|$")
LIFECYCLE_GROUP_RE = re.compile(r"^  ([a-z_]+):(?: \[\])?$")
LIFECYCLE_REPOSITORY_RE = re.compile(r"^    - (\S+)$")
EXPECTED_LIFECYCLE_GROUPS = {
    "production",
    "support",
    "beta",
    "experimental",
    "research",
    "internal",
    "labs",
    "historical",
    "superseded",
    "deprecated",
    "archived",
}
EXPECTED_CRITICAL_LIFECYCLES = {
    ".github": "support",
    "openadapt-web": "support",
    "openadapt-ops": "support",
    "openadapt-blog": "support",
    "OpenAdapter": "archived",
    "OpenReflector": "archived",
}
FORBIDDEN_PUBLIC_OPERATIONS_MARKERS = (
    "/Users/",
    "~/",
    "dirty_worktree",
    "possible_credentials",
    ".pem",
    "accessKeys",
)


def check_link(source: Path, destination: str) -> str | None:
    destination = destination.strip("<>")
    parsed = urlsplit(destination)

    if parsed.scheme in {"http", "https"}:
        if not parsed.netloc or parsed.username or parsed.password:
            return f"invalid external URL: {destination}"
        if "utm_" in parsed.query.lower():
            return f"tracking parameters are not allowed: {destination}"
        return None

    if parsed.scheme == "mailto":
        return None if "@" in parsed.path else f"invalid email link: {destination}"
    if parsed.scheme:
        return f"unsupported link scheme: {destination}"
    if not parsed.path:
        return None if parsed.fragment else "empty link destination"

    target = (source.parent / unquote(parsed.path)).resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        return f"local link escapes the repository: {destination}"
    if not target.exists():
        return f"missing local target: {destination}"
    return None


def main() -> int:
    errors: list[str] = []
    profile_text = PROFILE.read_text(encoding="utf-8")
    normalized_profile = " ".join(profile_text.split())

    if not profile_text.startswith("# OpenAdapt\n"):
        errors.append("profile/README.md must use OpenAdapt as its title")

    if CANONICAL_TRUTH not in normalized_profile:
        errors.append("profile/README.md is missing the canonical product truth")

    for marker in REQUIRED_PROFILE_MARKERS:
        if marker not in normalized_profile:
            errors.append(f"profile/README.md is missing required marker: {marker}")

    canonical_quickstart = (
        "python -m pip install --upgrade 'openadapt[browser]'",
        "openadapt quickstart",
    )
    for command in canonical_quickstart:
        if command not in profile_text:
            errors.append(
                f"profile/README.md is missing canonical quickstart command: {command}"
            )
    if "openadapt flow demo-record --out rec" in profile_text:
        errors.append("profile/README.md publishes the superseded manual tutorial path")

    profile_links = set(LINK_RE.findall(profile_text))
    missing_links = sorted(REQUIRED_PROFILE_LINKS - profile_links)
    if missing_links:
        errors.append(f"profile/README.md is missing required links: {missing_links}")

    try:
        active_admissions = validate_files(ROOT)
    except LifecycleError as exc:
        errors.append(f"Production lifecycle refused: {exc}")
        active_admissions = {}

    policy = json.loads(
        (ROOT / "production-lifecycle-policy.json").read_text(encoding="utf-8")
    )
    expected_profile_targets = tuple(target["id"] for target in policy["targets"])
    product_section_parts = profile_text.split("## Product Surfaces\n", maxsplit=1)
    if len(product_section_parts) != 2:
        errors.append("profile/README.md is missing the Product Surfaces section")
    else:
        product_section = product_section_parts[1].split("\n## ", maxsplit=1)[0]
        profile_target_rows = [
            match.groups()
            for line in product_section.splitlines()
            if (match := PROFILE_TARGET_ROW_RE.fullmatch(line))
        ]
        profile_targets = tuple(target for target, _role in profile_target_rows)
        if (
            len(profile_targets) != len(expected_profile_targets)
            or set(profile_targets) != set(expected_profile_targets)
        ):
            errors.append(
                "profile/README.md product roles do not match the seven target "
                f"contract: {profile_targets}"
            )
        empty_roles = [
            target for target, role in profile_target_rows if not role.strip()
        ]
        if empty_roles:
            errors.append(
                f"profile/README.md has empty product roles: {empty_roles}"
            )
        if (
            "Current state" in product_section
            or "Not actively admitted" in product_section
        ):
            errors.append(
                "profile/README.md must link the machine lifecycle record instead "
                "of repeating target state labels"
            )

    lifecycle_doc_text = LIFECYCLE_DOC.read_text(encoding="utf-8")
    for target in policy["targets"]:
        target_id = target["id"]
        state = (
            "Production"
            if target_id in active_admissions
            else "Not actively admitted"
        )
        marker = f"| `{target_id}` | **{state}** |"
        if marker not in lifecycle_doc_text:
            errors.append(
                f"{LIFECYCLE_DOC.relative_to(ROOT)} does not match the derived state "
                f"for target {target_id}: {state}"
            )

    lifecycle_text = LIFECYCLE_DATA.read_text(encoding="utf-8")
    public_metadata_text = lifecycle_text.split("lifecycle:\n", maxsplit=1)[0]
    static_target_labels = sorted(
        label
        for label in ("Beta", "Experimental", "Early access", "Exploratory")
        if re.search(rf"\b{re.escape(label)}\b", public_metadata_text, re.IGNORECASE)
    )
    if static_target_labels:
        errors.append(
            "repository-lifecycle.yml public target metadata contains static "
            f"lifecycle labels: {static_target_labels}"
        )
    pinned_section = lifecycle_text.split("  pinned_repositories:\n", maxsplit=1)
    if len(pinned_section) != 2:
        errors.append("repository-lifecycle.yml is missing pinned_repositories")
    else:
        pinned: list[str] = []
        for line in pinned_section[1].splitlines():
            if match := LIFECYCLE_REPOSITORY_RE.fullmatch(line):
                pinned.append(match.group(1))
            elif line and not line.startswith("    "):
                break
        if tuple(pinned) != EXPECTED_PINNED_REPOSITORIES:
            errors.append(
                "repository-lifecycle.yml product pins do not match the public contract"
            )

    lifecycle_section = lifecycle_text.split("lifecycle:\n", maxsplit=1)
    if len(lifecycle_section) != 2:
        errors.append("repository-lifecycle.yml is missing its lifecycle mapping")
    else:
        groups: dict[str, list[str]] = {}
        active_group: str | None = None
        for line in lifecycle_section[1].splitlines():
            if match := LIFECYCLE_GROUP_RE.fullmatch(line):
                active_group = match.group(1)
                groups[active_group] = []
            elif match := LIFECYCLE_REPOSITORY_RE.fullmatch(line):
                if active_group is None:
                    errors.append(
                        "repository-lifecycle.yml has a repository outside a lifecycle group"
                    )
                else:
                    groups[active_group].append(match.group(1))
            elif line and not line.startswith(" "):
                break

        if set(groups) != EXPECTED_LIFECYCLE_GROUPS:
            errors.append(
                "repository-lifecycle.yml lifecycle groups do not match the public schema"
            )
        repositories = [
            repository for values in groups.values() for repository in values
        ]
        duplicates = sorted(
            repository
            for repository in set(repositories)
            if repositories.count(repository) > 1
        )
        if duplicates:
            errors.append(
                f"repository-lifecycle.yml assigns multiple lifecycles: {duplicates}"
            )
        actual_lifecycles = {
            repository: group
            for group, group_repositories in groups.items()
            for repository in group_repositories
        }
        for repository, expected_group in EXPECTED_CRITICAL_LIFECYCLES.items():
            if actual_lifecycles.get(repository) != expected_group:
                errors.append(
                    "repository-lifecycle.yml assigns "
                    f"{repository} to {actual_lifecycles.get(repository)!r}; "
                    f"expected {expected_group!r}"
                )

    public_operations_text = lifecycle_text + lifecycle_doc_text
    leaked_markers = sorted(
        marker
        for marker in FORBIDDEN_PUBLIC_OPERATIONS_MARKERS
        if marker in public_operations_text
    )
    if leaked_markers:
        errors.append(
            "public lifecycle registry contains machine-local or credential-response "
            f"details: {leaked_markers}"
        )

    for source in MARKDOWN_FILES:
        text = source.read_text(encoding="utf-8")
        links = LINK_RE.findall(text)
        if text.count("](") != len(links):
            errors.append(
                f"{source.relative_to(ROOT)} has malformed Markdown link syntax"
            )
        for destination in links:
            if error := check_link(source, destination):
                errors.append(f"{source.relative_to(ROOT)}: {error}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    link_count = sum(
        len(LINK_RE.findall(path.read_text(encoding="utf-8")))
        for path in MARKDOWN_FILES
    )
    print(f"Validated canonical product truth and {link_count} Markdown links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
