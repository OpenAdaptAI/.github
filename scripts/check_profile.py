#!/usr/bin/env python3
"""Check the public profile without making network requests."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profile" / "README.md"
MARKDOWN_FILES = (ROOT / "README.md", PROFILE)
CANONICAL_TRUTH = (
    "OpenAdapt compiles demonstrated GUI workflows into deterministic, locally "
    "executable programs. Healthy runs make no model calls. When interfaces "
    "drift, OpenAdapt re-resolves from retained evidence or proposes a governed "
    "repair and halts when verification fails."
)
REQUIRED_PROFILE_LINKS = {
    "https://github.com/OpenAdaptAI/OpenAdapt",
    "https://github.com/OpenAdaptAI/openadapt-flow",
    "https://openadapt.ai/",
    "https://docs.openadapt.ai",
}
LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^\s)]+)(?:\s+[^)]*)?\)")


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

    profile_links = set(LINK_RE.findall(profile_text))
    missing_links = sorted(REQUIRED_PROFILE_LINKS - profile_links)
    if missing_links:
        errors.append(f"profile/README.md is missing required links: {missing_links}")

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
