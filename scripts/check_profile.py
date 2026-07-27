#!/usr/bin/env python3
"""Check the public profile without making network requests."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profile" / "README.md"
LIFECYCLE_DOC = ROOT / "REPOSITORY_LIFECYCLE.md"
LIFECYCLE_DATA = ROOT / "repository-lifecycle.yml"
MARKDOWN_FILES = (ROOT / "README.md", ROOT / "LAUNCH_PLAN.md", LIFECYCLE_DOC, PROFILE)
CANONICAL_TRUTH = (
    "OpenAdapt compiles demonstrations into governed workflows across browser, "
    "native desktop, RDP, and Citrix. Healthy runs execute deterministically "
    "and make no model calls. Consequential actions are identity-gated, results "
    "are checked against the workflow's evidence contract, and uncertainty "
    "halts for review instead of being reported as success."
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
}
REQUIRED_PROFILE_MARKERS = {
    "## Product Surfaces",
    "## Research and Labs",
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
LIFECYCLE_GROUP_RE = re.compile(r"^  ([a-z_]+):$")
LIFECYCLE_REPOSITORY_RE = re.compile(r"^    - (\S+)$")
EXPECTED_LIFECYCLE_GROUPS = {
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

    if CANONICAL_TRUTH not in normalized_profile:
        errors.append("profile/README.md is missing the canonical product truth")

    for marker in REQUIRED_PROFILE_MARKERS:
        if marker not in profile_text:
            errors.append(f"profile/README.md is missing required marker: {marker}")

    profile_links = set(LINK_RE.findall(profile_text))
    missing_links = sorted(REQUIRED_PROFILE_LINKS - profile_links)
    if missing_links:
        errors.append(f"profile/README.md is missing required links: {missing_links}")

    lifecycle_text = LIFECYCLE_DATA.read_text(encoding="utf-8")
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
            errors.append("repository-lifecycle.yml product pins do not match the public contract")

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
        repositories = [repository for values in groups.values() for repository in values]
        duplicates = sorted(
            repository for repository in set(repositories) if repositories.count(repository) > 1
        )
        if duplicates:
            errors.append(
                f"repository-lifecycle.yml assigns multiple lifecycles: {duplicates}"
            )

    public_operations_text = lifecycle_text + LIFECYCLE_DOC.read_text(encoding="utf-8")
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
            errors.append(f"{source.relative_to(ROOT)} has malformed Markdown link syntax")
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
