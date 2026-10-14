#!/usr/bin/env python3
"""Check the public profile, its GitHub metadata, and its evidence-gated lifecycle."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from github_metadata import (
    APPLY_SCRIPT,
    MetadataError,
    PublicMetadata,
    load_public_metadata,
    render_apply_script,
)
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
    "https://github.com/OpenAdaptAI/ehr-integration-directory",
    "https://github.com/OpenAdaptAI/openadapt-flow/tree/main/docs/showcase",
    "https://openadapt.ai/",
    "https://openadapt.ai/book",
    "https://openadapt.ai/services",
    "https://app.openadapt.ai/",
    "https://app.openadapt.ai/demo",
    "https://docs.openadapt.ai",
    "https://docs.openadapt.ai/production-lifecycle.json",
}
# The business half of the profile comes first. Everything above
# DEVELOPER_HEADING is written for people who own a process.
DEVELOPER_HEADING = "## For developers"
PRODUCT_HEADING = "## Product surfaces"
PROFILE_HEADINGS = (
    "## What changes for your team",
    "## How a run ends",
    "## Two ways to start",
    "### Hand off a workflow",
    "### Run it yourself",
    DEVELOPER_HEADING,
    PRODUCT_HEADING,
    "## Research and labs",
)
REQUIRED_PROFILE_MARKERS = PROFILE_HEADINGS + (
    "Qualification is per workflow. A product release admission doesn't "
    "qualify any workflow.",
)
CANONICAL_QUICKSTART = (
    "python -m pip install --upgrade openadapt",
    "openadapt quickstart --break-it",
)
# Phrases that misstate a claim of record or publish a retired path. The fault
# test's screen-only check passed 54 of the 72 runs that left the record wrong;
# "54 of 90" pairs that count with every run, and pairing it with 75.0% is
# wrong arithmetic.
PROHIBITED_PROFILE_PHRASES = (
    "54 of 90",
    "openadapt flow demo-record --out rec",
)
# Terms that never appear where a business reader starts. The technical term
# stays available one level deeper: below DEVELOPER_HEADING, and in the
# developer repositories' own descriptions.
BUSINESS_FORBIDDEN_TERMS = (
    (re.compile(r"\bseals?\b", re.IGNORECASE), "Seal"),
    (re.compile(r"\badmi(?:t|ts|tted|tting|ssion|ssions)\b", re.IGNORECASE), "admission"),
    (
        re.compile(r"\bqualif(?:y|ied|ies|ying|ication|ications)\b", re.IGNORECASE),
        "qualification",
    ),
    (re.compile(r"\bgoverned\b", re.IGNORECASE), "governed"),
    (re.compile(r"\boracles?\b", re.IGNORECASE), "oracle"),
    (re.compile(r"\beffect contracts?\b", re.IGNORECASE), "effect contract"),
    (re.compile(r"\bsubstrates?\b", re.IGNORECASE), "substrate"),
    (re.compile(r"\bfixtures?\b", re.IGNORECASE), "fixture"),
    (re.compile(r"REST\+SQL", re.IGNORECASE), "REST+SQL parity"),
    (re.compile(r"non-target delta", re.IGNORECASE), "non-target delta"),
    (re.compile(r"\bsha256\b", re.IGNORECASE), "sha256"),
    (re.compile(r"\bstandard profile\b", re.IGNORECASE), "Standard profile"),
    (re.compile(r"program state console", re.IGNORECASE), "Program State Console"),
    (re.compile(r"\brunners?\b", re.IGNORECASE), "runner"),
    (re.compile(r"\bMCP\b"), "MCP"),
    (
        re.compile(r"\b(?:VERIFIED|HALTED|COMPLETED_UNVERIFIED|FAILED)\b"),
        "an all-caps run outcome",
    ),
    (
        re.compile(r"RECONCILIATION_REQUIRED|HALTED_BEFORE_EFFECT"),
        "a transaction outcome name",
    ),
)
DASHES = ("–", "—")

EXPECTED_PINNED_REPOSITORIES = (
    "OpenAdapt",
    "openadapt-flow",
    "openadapt-desktop",
    "openadapt-capture",
    "openadapt-agent",
    "ehr-integration-directory",
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
    "ehr-integration-directory": "support",
    "OpenAdapter": "archived",
    "OpenReflector": "archived",
}
# A product target's state is derived from signed admissions, so its
# repository description never carries a static lifecycle label. A described
# repository that a visitor could mistake for the product opens with its
# lifecycle label instead.
STATIC_TARGET_LABELS = ("Beta", "Experimental", "Early access", "Exploratory")
REQUIRED_DESCRIPTION_LABELS = {
    "experimental": "Experimental: ",
    "research": "Research: ",
    "labs": "Labs: ",
    "superseded": "Superseded by ",
    "deprecated": "Deprecated",
    "historical": "Historical",
    "archived": "Archived",
}
LEADING_LABEL_RE = re.compile(
    r"^(Production|Support|Beta|Experimental|Research|Internal|Labs|Historical|"
    r"Superseded|Deprecated|Archived)\b"
)
UNPINNABLE_GROUPS = {
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


def business_term_errors(label: str, text: str) -> list[str]:
    """Name every business-vocabulary rule that `text` breaks."""
    return [
        f"{label} uses {name!r}; business-facing copy uses the plain term"
        for pattern, name in BUSINESS_FORBIDDEN_TERMS
        if pattern.search(text)
    ]


def reader_words(markdown: str) -> str:
    """Drop link destinations and fenced code, which a reader doesn't read as prose."""
    without_code = re.sub(r"```.*?```", " ", markdown, flags=re.DOTALL)
    return re.sub(r"\]\([^)]*\)", "]", without_code)


def parse_lifecycle_groups(
    lifecycle_text: str, errors: list[str]
) -> dict[str, list[str]]:
    lifecycle_section = lifecycle_text.split("\nlifecycle:\n", maxsplit=1)
    if len(lifecycle_section) != 2:
        errors.append("repository-lifecycle.yml is missing its lifecycle mapping")
        return {}
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
    return groups


def metadata_errors(
    metadata: PublicMetadata,
    product_repositories: set[str],
    lifecycles: dict[str, str],
) -> list[str]:
    """Check the public metadata against the lifecycle and the copy rules."""
    errors: list[str] = []

    if metadata.pinned_repositories != EXPECTED_PINNED_REPOSITORIES:
        errors.append(
            "repository-lifecycle.yml product pins do not match the public contract: "
            f"{list(metadata.pinned_repositories)}"
        )

    for label, text in (
        ("organization_description", metadata.organization_description),
        ("profile_headline", metadata.profile_headline),
    ):
        errors += business_term_errors(f"repository-lifecycle.yml {label}", text)

    static_label_patterns = [
        (label, re.compile(rf"\b{re.escape(label)}\b", re.IGNORECASE))
        for label in STATIC_TARGET_LABELS
    ]
    for name, repository in metadata.repositories.items():
        group = lifecycles.get(name)
        is_product = name in product_repositories
        if group is None and not is_product:
            errors.append(
                f"repository-lifecycle.yml describes {name}, which is neither a "
                "product target repository nor in a lifecycle group"
            )

        if is_product or name in metadata.pinned_repositories:
            static = sorted(
                label
                for label, pattern in static_label_patterns
                if pattern.search(repository.description)
            )
            if static:
                errors.append(
                    f"repository-lifecycle.yml {name} description carries static "
                    f"lifecycle labels: {static}"
                )

        required = REQUIRED_DESCRIPTION_LABELS.get(group or "")
        if required and not repository.description.startswith(required):
            errors.append(
                f"repository-lifecycle.yml {name} is {group}, so its description "
                f"must start with {required.strip()!r}"
            )
        if match := LEADING_LABEL_RE.match(repository.description):
            if match.group(1).lower() != group:
                errors.append(
                    f"repository-lifecycle.yml {name} description opens with "
                    f"{match.group(1)!r}, but its lifecycle is {group!r}"
                )

    for name in metadata.pinned_repositories:
        group = lifecycles.get(name)
        if group in UNPINNABLE_GROUPS:
            errors.append(
                f"repository-lifecycle.yml pins {name}, which is {group}; pins are "
                "for product and public Support repositories"
            )
        if name in metadata.repositories:
            errors += business_term_errors(
                f"repository-lifecycle.yml pinned {name} description",
                metadata.repositories[name].description,
            )
    return errors


def main() -> int:
    errors: list[str] = []
    profile_text = PROFILE.read_text(encoding="utf-8")
    normalized_profile = " ".join(profile_text.split())

    if not profile_text.startswith("# OpenAdapt\n"):
        errors.append("profile/README.md must use OpenAdapt as its title")

    if CANONICAL_TRUTH not in normalized_profile:
        errors.append("profile/README.md is missing the canonical product truth")

    for marker in REQUIRED_PROFILE_MARKERS:
        if " ".join(marker.split()) not in normalized_profile:
            errors.append(f"profile/README.md is missing required marker: {marker}")
    heading_positions = [
        profile_text.find(f"\n{heading}\n") for heading in PROFILE_HEADINGS
    ]
    if -1 not in heading_positions and heading_positions != sorted(heading_positions):
        errors.append(
            "profile/README.md must keep its sections in order, with every "
            f"business section before {DEVELOPER_HEADING!r}"
        )

    for command in CANONICAL_QUICKSTART:
        if command not in profile_text:
            errors.append(
                f"profile/README.md is missing canonical quickstart command: {command}"
            )
    for phrase in PROHIBITED_PROFILE_PHRASES:
        if phrase in normalized_profile:
            errors.append(f"profile/README.md publishes a prohibited phrase: {phrase!r}")
    if any(dash in profile_text for dash in DASHES):
        errors.append("profile/README.md uses an en or em dash")

    business_section = profile_text.split(f"\n{DEVELOPER_HEADING}\n", maxsplit=1)[0]
    errors += business_term_errors(
        "profile/README.md business section", reader_words(business_section)
    )

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
    product_repositories = {
        target["source_repository"].split("/", 1)[1] for target in policy["targets"]
    }
    product_section_parts = profile_text.split(f"{PRODUCT_HEADING}\n", maxsplit=1)
    if len(product_section_parts) != 2:
        errors.append("profile/README.md is missing the Product surfaces section")
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

    for path in (PROFILE, ROOT / "README.md"):
        text = path.read_text(encoding="utf-8")
        if "1.6k" in text or "1.6k+" in text:
            errors.append(
                f"{path.relative_to(ROOT)} still flexes GitHub star count"
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
    groups = parse_lifecycle_groups(lifecycle_text, errors)
    if groups:
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

    metadata: PublicMetadata | None
    try:
        metadata = load_public_metadata(LIFECYCLE_DATA)
    except MetadataError as exc:
        errors.append(f"repository-lifecycle.yml public_metadata: {exc}")
        metadata = None
    if metadata is not None:
        errors += metadata_errors(metadata, product_repositories, actual_lifecycles)
        first_bold = next(
            (line for line in profile_text.splitlines() if line.startswith("**")), ""
        )
        if first_bold != f"**{metadata.profile_headline}**":
            errors.append(
                "profile/README.md must open with the profile_headline from "
                "repository-lifecycle.yml as its first bold line"
            )
        if APPLY_SCRIPT.exists():
            relative = APPLY_SCRIPT.relative_to(ROOT)
            if APPLY_SCRIPT.read_text(encoding="utf-8") != render_apply_script(metadata):
                errors.append(
                    f"{relative} does not match repository-lifecycle.yml. Run: "
                    f"python3 scripts/github_metadata.py render-apply --output {relative}"
                )
            if not os.access(APPLY_SCRIPT, os.X_OK):
                errors.append(f"{relative} is not executable")

    public_operations_text = lifecycle_text + lifecycle_doc_text
    if APPLY_SCRIPT.exists():
        public_operations_text += APPLY_SCRIPT.read_text(encoding="utf-8")
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

    if errors or metadata is None:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    link_count = sum(
        len(LINK_RE.findall(path.read_text(encoding="utf-8")))
        for path in MARKDOWN_FILES
    )
    print(
        "Validated canonical product truth, "
        f"{len(metadata.repositories)} repository descriptions, "
        f"{len(metadata.pinned_repositories)} pins, and {link_count} Markdown links."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
