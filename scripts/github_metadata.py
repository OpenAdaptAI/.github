#!/usr/bin/env python3
"""Read the public GitHub metadata in repository-lifecycle.yml and render it.

`public_metadata` in `repository-lifecycle.yml` is the source of truth for the
GitHub settings a visitor sees: the organization description and website, the
profile headline, the pinned repositories, and each listed repository's
description, website, and topics. GitHub doesn't read this file. An
organization owner applies it after merge with the script this module renders:

    python3 scripts/github_metadata.py render-apply --output .overhaul/APPLY.sh

The parser reads only the small, strict YAML subset the registry uses, so the
profile check needs no third-party YAML package. It refuses anything outside
that subset instead of guessing what it means.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_DATA = ROOT / "repository-lifecycle.yml"
APPLY_SCRIPT = ROOT / ".overhaul" / "APPLY.sh"
ORGANIZATION = "OpenAdaptAI"

METADATA_KEYS = (
    "organization_description",
    "organization_homepage",
    "profile_headline",
    "pinned_repositories",
    "repositories",
)
REPOSITORY_KEYS = ("description", "homepage", "topics")

# GitHub allows up to 20 topics per repository, each lowercase letters, digits,
# and hyphens, starting with a letter or digit, at most 50 characters.
MAX_TOPICS = 20
TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,49}$")
MAX_PINS = 6
# Our own limit, well under GitHub's: a description longer than this wraps
# onto a second line on pinned cards and in search results.
MAX_DESCRIPTION_LENGTH = 160
REPOSITORY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[A-Za-z0-9._~/-]*)?$")
PLAIN_SCALAR_RE = re.compile(r"^[A-Za-z0-9][^#'\"]*$")
KEY_LINE_RE = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9._-]+):(?: (?P<rest>.*))?$")
ITEM_LINE_RE = re.compile(r"^(?P<indent> *)- (?P<value>.*)$")
DASHES = ("–", "—")


class MetadataError(Exception):
    """The registry's public metadata is malformed or outside the subset."""


@dataclass(frozen=True)
class RepositoryMetadata:
    name: str
    description: str
    homepage: str
    topics: tuple[str, ...]


@dataclass(frozen=True)
class PublicMetadata:
    organization_description: str
    organization_homepage: str
    profile_headline: str
    pinned_repositories: tuple[str, ...]
    repositories: dict[str, RepositoryMetadata]


Value = str | list[str] | dict[str, "Value"]


def _block(text: str, key: str) -> list[tuple[int, str]]:
    """Return the numbered lines under a top-level key, without the key."""
    lines = text.splitlines()
    try:
        start = lines.index(f"{key}:")
    except ValueError as exc:
        raise MetadataError(f"repository-lifecycle.yml has no top-level {key}:") from exc
    block: list[tuple[int, str]] = []
    for number, line in enumerate(lines[start + 1 :], start=start + 2):
        if line and not line.startswith(" "):
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        block.append((number, line))
    return block


def _scalar(number: int, raw: str) -> str:
    if raw == '""':
        return ""
    if not PLAIN_SCALAR_RE.fullmatch(raw) or ": " in raw or raw.endswith(":"):
        raise MetadataError(
            f"line {number}: {raw!r} is not a plain value. Use a folded "
            "'>-' block for text, or '\"\"' for an empty value."
        )
    return raw


def _parse(lines: list[tuple[int, str]], indent: int) -> dict[str, Value]:
    """Parse one mapping level of the strict subset."""
    result: dict[str, Value] = {}
    index = 0
    while index < len(lines):
        number, line = lines[index]
        match = KEY_LINE_RE.fullmatch(line)
        if match is None or len(match.group("indent")) != indent:
            raise MetadataError(
                f"line {number}: expected a key indented {indent} spaces: {line!r}"
            )
        key = match.group("key")
        if key in result:
            raise MetadataError(f"line {number}: duplicate key {key!r}")
        rest = match.group("rest")
        index += 1
        children: list[tuple[int, str]] = []
        while index < len(lines):
            child_indent = len(lines[index][1]) - len(lines[index][1].lstrip(" "))
            if child_indent <= indent:
                break
            children.append(lines[index])
            index += 1

        if rest is None:
            if not children:
                raise MetadataError(f"line {number}: {key!r} has no value")
            if _lines_are_items(children):
                result[key] = _items(children, indent + 2)
            else:
                result[key] = _parse(children, indent + 2)
        elif rest == ">-":
            if not children:
                raise MetadataError(f"line {number}: {key!r} has an empty text block")
            result[key] = " ".join(child.strip() for _, child in children)
        else:
            if children:
                raise MetadataError(
                    f"line {number}: {key!r} has a value and an indented block"
                )
            result[key] = [] if rest == "[]" else _scalar(number, rest)
    return result


def _lines_are_items(lines: list[tuple[int, str]]) -> bool:
    return ITEM_LINE_RE.fullmatch(lines[0][1]) is not None


def _items(lines: list[tuple[int, str]], indent: int) -> list[str]:
    values: list[str] = []
    for number, line in lines:
        match = ITEM_LINE_RE.fullmatch(line)
        if match is None or len(match.group("indent")) != indent:
            raise MetadataError(
                f"line {number}: expected a list item indented {indent} spaces"
            )
        values.append(_scalar(number, match.group("value")))
    return values


def parse_public_metadata_mapping(text: str) -> dict[str, Value]:
    """Parse `public_metadata` into plain Python values."""
    return _parse(_block(text, "public_metadata"), 2)


def _text(value: Value, label: str) -> str:
    if not isinstance(value, str):
        raise MetadataError(f"{label} must be text")
    return value


def _names(value: Value, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise MetadataError(f"{label} must be a list")
    return tuple(value)


def load_public_metadata(path: Path = LIFECYCLE_DATA) -> PublicMetadata:
    """Load and structurally validate the registry's public metadata."""
    raw = parse_public_metadata_mapping(path.read_text(encoding="utf-8"))
    if tuple(raw) != METADATA_KEYS:
        raise MetadataError(
            f"public_metadata keys are {list(raw)}; expected {list(METADATA_KEYS)} "
            "in that order"
        )
    repositories_raw = raw["repositories"]
    if not isinstance(repositories_raw, dict) or not repositories_raw:
        raise MetadataError("public_metadata.repositories must be a non-empty mapping")
    repositories: dict[str, RepositoryMetadata] = {}
    for name, entry in repositories_raw.items():
        if not isinstance(entry, dict) or tuple(entry) != REPOSITORY_KEYS:
            raise MetadataError(
                f"repository {name} must have exactly {list(REPOSITORY_KEYS)}, "
                "in that order"
            )
        repositories[name] = RepositoryMetadata(
            name=name,
            description=_text(entry["description"], f"{name}.description"),
            homepage=_text(entry["homepage"], f"{name}.homepage"),
            topics=_names(entry["topics"], f"{name}.topics"),
        )
    metadata = PublicMetadata(
        organization_description=_text(
            raw["organization_description"], "organization_description"
        ),
        organization_homepage=_text(raw["organization_homepage"], "organization_homepage"),
        profile_headline=_text(raw["profile_headline"], "profile_headline"),
        pinned_repositories=_names(raw["pinned_repositories"], "pinned_repositories"),
        repositories=repositories,
    )
    errors = structural_errors(metadata)
    if errors:
        raise MetadataError("; ".join(errors))
    return metadata


def _text_errors(label: str, text: str, *, max_length: int | None) -> list[str]:
    errors: list[str] = []
    if not text.strip():
        errors.append(f"{label} is empty")
    if not text.isascii():
        errors.append(f"{label} has non-ASCII characters (curly quotes or dashes?)")
    if any(dash in text for dash in DASHES) or " -- " in text:
        errors.append(f"{label} uses a dash; short copy takes none")
    if max_length is not None and len(text) > max_length:
        errors.append(f"{label} is {len(text)} characters; the limit is {max_length}")
    return errors


def structural_errors(metadata: PublicMetadata) -> list[str]:
    """Check formats GitHub enforces, plus our own short-copy rules."""
    errors: list[str] = []
    errors += _text_errors(
        "organization_description",
        metadata.organization_description,
        max_length=MAX_DESCRIPTION_LENGTH,
    )
    errors += _text_errors("profile_headline", metadata.profile_headline, max_length=None)
    if not URL_RE.fullmatch(metadata.organization_homepage):
        errors.append("organization_homepage must be an https URL")

    pins = metadata.pinned_repositories
    if not pins or len(pins) > MAX_PINS:
        errors.append(f"pinned_repositories must list 1 to {MAX_PINS} repositories")
    if len(set(pins)) != len(pins):
        errors.append("pinned_repositories lists a repository twice")
    for name in pins:
        if name not in metadata.repositories:
            errors.append(f"pinned repository {name} has no entry under repositories")

    for name, repository in metadata.repositories.items():
        if not REPOSITORY_NAME_RE.fullmatch(name):
            errors.append(f"{name!r} is not a GitHub repository name")
        errors += _text_errors(
            f"{name}.description",
            repository.description,
            max_length=MAX_DESCRIPTION_LENGTH,
        )
        if repository.homepage and not URL_RE.fullmatch(repository.homepage):
            errors.append(f"{name}.homepage must be an https URL or \"\"")
        if len(repository.topics) > MAX_TOPICS:
            errors.append(f"{name} has {len(repository.topics)} topics; GitHub allows {MAX_TOPICS}")
        if len(set(repository.topics)) != len(repository.topics):
            errors.append(f"{name} lists a topic twice")
        for topic in repository.topics:
            if not TOPIC_RE.fullmatch(topic):
                errors.append(f"{name} topic {topic!r} isn't a valid GitHub topic")
    return errors


# The apply script ----------------------------------------------------------

PINS_QUERY = (
    "query($org: String!) { organization(login: $org) { "
    "pinnedItems(first: 6, types: REPOSITORY) { nodes { ... on Repository { name } } } } }"
)

SCRIPT_HEAD = """\
#!/usr/bin/env bash
# Apply the public GitHub metadata in repository-lifecycle.yml to the
# {org} organization: the organization description and website, and each
# listed repository's description, website, and topics.
#
# Generated by `python3 scripts/github_metadata.py render-apply` from
# repository-lifecycle.yml. Don't edit this file by hand. Edit the registry
# and render it again; scripts/check_profile.py fails when the two differ.
#
# Usage:
#   APPLY.sh             Dry run. Prints each command and request body.
#                        Calls nothing and changes nothing.
#   APPLY.sh --apply     Makes the changes, then reads GitHub back and
#                        compares every value with the registry.
#   APPLY.sh --verify    Reads GitHub back and compares. Changes nothing.
#
# Exit status: 0 when GitHub matches the registry. 1 when a command failed,
# a value couldn't be read, or a value differs. 2 when everything matches
# except the pinned repositories, which only an owner can set by hand.
# 64 for a usage error.
#
# Needs the GitHub CLI (gh) signed in as an owner of {org}, with a token
# that has the admin:org and repo scopes. To add them, run:
#   gh auth refresh -s admin:org,repo
#
# Each listed repository is set exactly: an empty website clears the field,
# and the topic list replaces every current topic.
#
# GitHub has no API for organization pins. On https://github.com/{org},
# choose "Customize pins" and pin these repositories in this order:
{pin_lines}

set -uo pipefail

ORG={org}
PINS={pins_csv}
REGISTERED={registered}

MODE=dry-run
if [ "$#" -gt 1 ]; then
  printf 'Use one option: --dry-run (the default), --apply, or --verify.\\n' >&2
  exit 64
fi
case "${{1:-}}" in
  "" | --dry-run) MODE=dry-run ;;
  --apply) MODE=apply ;;
  --verify) MODE=verify ;;
  -h | --help)
    sed -n '2,/^$/p' "$0"
    exit 0
    ;;
  *)
    printf 'Unknown option: %s. Use --dry-run, --apply, or --verify.\\n' "$1" >&2
    exit 64
    ;;
esac

ERR_FILE=$(mktemp "${{TMPDIR:-/tmp}}/openadapt-apply.XXXXXX") || exit 1
trap 'rm -f "$ERR_FILE"' EXIT

CHANGES=0
FAILED=0
CHECKED=0
DIFFERENT=0
PINS_PENDING=0

# change LABEL COMMAND...: run one write. The request body arrives on stdin.
change() {{
  local label=$1
  shift
  local body
  body=$(cat)
  CHANGES=$((CHANGES + 1))
  if [ "$MODE" = dry-run ]; then
    printf '\\n# %s\\n' "$label"
    printf '%q ' "$@"
    printf "<<'JSON'\\n%s\\nJSON\\n" "$body"
    return 0
  fi
  if printf '%s\\n' "$body" | "$@" >/dev/null 2>"$ERR_FILE"; then
    printf 'changed    %s\\n' "$label"
  else
    FAILED=$((FAILED + 1))
    printf 'FAILED     %s\\n' "$label" >&2
    sed 's/^/           /' "$ERR_FILE" >&2
  fi
}}

# read_value LABEL COMMAND...: print one value read from GitHub, or fail.
read_value() {{
  local label=$1
  shift
  if ! "$@" 2>"$ERR_FILE"; then
    printf 'UNREAD     %s\\n' "$label" >&2
    sed 's/^/           /' "$ERR_FILE" >&2
    return 1
  fi
}}

# expect LABEL EXPECTED COMMAND...: compare one value on GitHub with the registry.
expect() {{
  local label=$1 expected=$2 actual
  shift 2
  CHECKED=$((CHECKED + 1))
  if ! actual=$(read_value "$label" "$@"); then
    DIFFERENT=$((DIFFERENT + 1))
    return
  fi
  if [ "$actual" = "$expected" ]; then
    printf 'matches    %s\\n' "$label"
  else
    DIFFERENT=$((DIFFERENT + 1))
    printf 'DIFFERS    %s\\n           GitHub:   %s\\n           registry: %s\\n' \\
      "$label" "$actual" "$expected" >&2
  fi
}}

check_pins() {{
  local actual
  CHECKED=$((CHECKED + 1))
  # The GraphQL query names $org itself, so the shell must not expand it.
  # shellcheck disable=SC2016
  if ! actual=$(read_value "organization: pinned repositories" \\
    gh api graphql -F org="$ORG" -f query={pins_query} \\
    --jq '[.data.organization.pinnedItems.nodes[].name] | join(",")'); then
    DIFFERENT=$((DIFFERENT + 1))
    return
  fi
  if [ "$actual" = "$PINS" ]; then
    printf 'matches    organization: pinned repositories\\n'
  else
    PINS_PENDING=1
    printf 'TO PIN     organization: pinned repositories (set by hand)\\n           GitHub:   %s\\n           registry: %s\\n' \\
      "$actual" "$PINS" >&2
  fi
}}

# Public repositories that the registry doesn't describe. A note, not a failure.
note_unregistered() {{
  local names name
  if ! names=$(read_value "organization: public repositories" \\
    gh api --paginate "orgs/$ORG/repos?type=public&per_page=100" \\
    --jq '.[] | select(.archived | not) | .name'); then
    return
  fi
  for name in $names; do
    case " $REGISTERED " in
      *" $name "*) ;;
      *) printf 'note       %s is public but has no entry in repository-lifecycle.yml\\n' "$name" ;;
    esac
  done
}}

preflight() {{
  if ! command -v gh >/dev/null 2>&1; then
    printf "The GitHub CLI (gh) isn't installed. Nothing was changed.\\n" >&2
    exit 1
  fi
  if ! gh auth status >/dev/null 2>&1; then
    printf "gh isn't signed in. Run gh auth login, then try again. Nothing was changed.\\n" >&2
    exit 1
  fi
  if [ "$MODE" = apply ]; then
    local role
    role=$(gh api "user/memberships/orgs/$ORG" --jq .role 2>/dev/null) || role=""
    if [ "$role" != admin ]; then
      printf "This gh account isn't an owner of %s (role: %s). Nothing was changed.\\n" \\
        "$ORG" "${{role:-none}}" >&2
      exit 1
    fi
  fi
}}
"""

SCRIPT_TAIL = """\

if [ "$MODE" = dry-run ]; then
  apply_changes
  printf '\\nDry run: %s changes listed. Nothing was called or changed.\\n' "$CHANGES"
  printf 'Run with --apply to make them, then pin the repositories by hand.\\n'
  exit 0
fi

preflight
if [ "$MODE" = apply ]; then
  apply_changes
  printf '\\n'
fi
verify_github
note_unregistered

if [ "$FAILED" -gt 0 ]; then
  printf '\\n%s of %s changes failed. GitHub may be partly updated; the checks above show what differs.\\n' \\
    "$FAILED" "$CHANGES" >&2
  exit 1
fi
if [ "$DIFFERENT" -gt 0 ]; then
  printf '\\n%s of %s values on GitHub differ from the registry or could not be read.\\n' \\
    "$DIFFERENT" "$CHECKED" >&2
  exit 1
fi
if [ "$PINS_PENDING" -gt 0 ]; then
  printf '\\nEvery other value matches. Pin the repositories by hand, in this order: %s\\n' \\
    "$PINS" >&2
  exit 2
fi
printf '\\nGitHub matches repository-lifecycle.yml. All %s values checked.\\n' "$CHECKED"
exit 0
"""


def _body(payload: dict[str, object]) -> str:
    # One line of JSON always starts with "{", so it can't end the heredoc.
    return json.dumps(payload, ensure_ascii=True)


def render_apply_script(
    metadata: PublicMetadata, organization: str = ORGANIZATION
) -> str:
    """Render the reviewed bash script that applies `metadata` to GitHub."""
    pins_csv = ",".join(metadata.pinned_repositories)
    head = SCRIPT_HEAD.format(
        org=organization,
        pin_lines="\n".join(
            f"#   {index}. {name}"
            for index, name in enumerate(metadata.pinned_repositories, start=1)
        ),
        pins_csv=shlex.quote(pins_csv),
        registered=shlex.quote(" ".join(metadata.repositories)),
        pins_query=shlex.quote(PINS_QUERY),
    )

    writes = ["", "apply_changes() {"]
    writes += [
        '  change "organization: description and website" \\',
        '    gh api --method PATCH "orgs/$ORG" --input - <<\'JSON\'',
        _body(
            {
                "description": metadata.organization_description,
                "blog": metadata.organization_homepage,
            }
        ),
        "JSON",
    ]
    for name, repository in metadata.repositories.items():
        quoted = shlex.quote(f"{name}: description and website")
        writes += [
            f"  change {quoted} \\",
            f'    gh api --method PATCH "repos/$ORG/{name}" --input - <<\'JSON\'',
            _body(
                {
                    "description": repository.description,
                    "homepage": repository.homepage,
                }
            ),
            "JSON",
            f"  change {shlex.quote(f'{name}: topics')} \\",
            f'    gh api --method PUT "repos/$ORG/{name}/topics" --input - <<\'JSON\'',
            _body({"names": list(repository.topics)}),
            "JSON",
        ]
    writes.append("}")

    reads = ["", "verify_github() {"]
    reads += [
        "  expect 'organization: description' \\",
        f"    {shlex.quote(metadata.organization_description)} \\",
        "    gh api \"orgs/$ORG\" --jq '.description // \"\"'",
        "  expect 'organization: website' \\",
        f"    {shlex.quote(metadata.organization_homepage)} \\",
        "    gh api \"orgs/$ORG\" --jq '.blog // \"\"'",
    ]
    for name, repository in metadata.repositories.items():
        reads += [
            f"  expect {shlex.quote(f'{name}: description')} \\",
            f"    {shlex.quote(repository.description)} \\",
            f"    gh api \"repos/$ORG/{name}\" --jq '.description // \"\"'",
            f"  expect {shlex.quote(f'{name}: website')} \\",
            f"    {shlex.quote(repository.homepage)} \\",
            f"    gh api \"repos/$ORG/{name}\" --jq '.homepage // \"\"'",
            f"  expect {shlex.quote(f'{name}: topics')} \\",
            f"    {shlex.quote(','.join(sorted(repository.topics)))} \\",
            f"    gh api \"repos/$ORG/{name}/topics\" --jq '.names | sort | join(\",\")'",
        ]
    reads += ["  check_pins", "}"]

    return head + "\n".join(writes) + "\n" + "\n".join(reads) + "\n" + SCRIPT_TAIL


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser(
        "render-apply", help="print the script that applies the registry to GitHub"
    )
    render.add_argument(
        "--output",
        type=Path,
        help="write the script here (mode 0755) instead of printing it",
    )
    commands.add_parser("check", help="validate the registry's public metadata")
    arguments = parser.parse_args(argv)

    try:
        metadata = load_public_metadata()
    except MetadataError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if arguments.command == "check":
        print(
            f"public_metadata is valid: {len(metadata.repositories)} repositories, "
            f"{len(metadata.pinned_repositories)} pins."
        )
        return 0

    script = render_apply_script(metadata)
    if arguments.output is None:
        sys.stdout.write(script)
        return 0
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(script, encoding="utf-8")
    arguments.output.chmod(0o755)
    print(f"Wrote {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
