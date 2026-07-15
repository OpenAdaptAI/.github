# OpenAdapt Repository Lifecycle Registry

Last reviewed: 2026-07-15

This registry separates the product from experiments and records whether local
checkouts can be relocated to `/Users/abrichr/oa/src/_deprecated`. It does not
authorize moving a directory or archiving a GitHub repository by itself.

The user referred to `~/os/src`; this registry assumes that was a typo for the
current workspace, `/Users/abrichr/oa/src`. Reconfirm that assumption before any
filesystem operation.

The machine-readable source is [`repository-lifecycle.yml`](repository-lifecycle.yml).

## Lifecycle Definitions

| Status | Meaning |
|--------|---------|
| **Beta** | Active product surface with compatibility intent, but not a blanket production-readiness claim |
| **Experimental** | Active prototype or optional component with no production support promise |
| **Research** | Evidence-generating work, not required by the product runtime |
| **Internal** | Team tooling or private strategy, not a public product surface |
| **Labs** | Standalone experiment, fork, or adjacent library; not automatically deprecated |
| **Historical** | Earlier direction retained for context; retirement still requires an explicit decision |
| **Superseded** | Functionality has a named successor; new integrations use the successor |
| **Deprecated** | Superseded; migration fixes only, no new integrations |
| **Archived** | Historical and read-only |

## Current Product Boundary

| Repository | Lifecycle | Role |
|------------|-----------|------|
| `OpenAdapt` | **Beta** | Launcher/meta-package and unified CLI |
| `openadapt-flow` | **Beta** | Canonical compiler and governed runtime |
| `openadapt-desktop` | **Experimental** | Desktop authoring and teaching surface |
| `openadapt-cloud` | **Beta** | Hosted browser-workflow control plane, execution, billing, structural reports, and validated replacement activation; authoring and repair remain local |
| `openadapt-capture` | **Experimental** | Optional native recorder |
| `openadapt-privacy` | **Experimental** | Optional scrubbing component |
| `openadapt-types` | **Experimental** | Interoperability schemas |
| `openadapt-web` | **Internal** | Marketing website implementation |

## Research, Labs, and Internal Work

| Group | Repositories |
|-------|--------------|
| **Research** | `openadapt-ml`, `openadapt-evals`, `openadapt-retrieval`, `openadapt-grounding`, `openadapt-verifier` |
| **Internal** | `openadapt-ops`, `openadapt-wright`, `openadapt-herald`, `openadapt-crier`, `openadapt-consilium`, `openadapt-presenter`, `openadapt-telemetry`, `openadapt-viewer`, `openadapt-blog`, `openadapt-internal`, `openadapt-yc` |
| **Experimental UI/support** | `openadapt-console`, `openadapt-tray` |
| **Labs/forks** | `OmniMCP` (`omnimcp` locally), `SoM`, `PydanticPrompt` |
| **Historical directions** | `OpenAdapter`, `OpenReflector` |
| **Superseded** | `OpenSanitizer` (successor: `openadapt-privacy`) |

## Local Relocation Audit

Reference counts below are repository-name matches outside the checkout, not
proof of a runtime dependency. Runtime import checks were performed separately
for deprecated code where relevant.

### Ready to Relocate Now

| Local checkout | Evidence | External references | Recommended action |
|----------------|----------|---------------------|--------------------|
| `openadapt-gitbook` | **Archived**, clean, aligned with `origin/master`; last commit 2023-12-13; obsolete GitBook product docs | 8, all inventory/package-discovery references | Relocate to `_deprecated/openadapt-gitbook`; keep or add the GitHub archive notice |

`openadapt-gitbook` is the only reviewed checkout that is both clean and already
classified **Archived**. Cleanliness alone does not make the following
repositories ready for `_deprecated`.

### Clean Retirement Candidates Requiring a Decision

| Local checkout | Lifecycle | Evidence | Required decision before `_deprecated` |
|----------------|-----------|----------|-----------------------------------------|
| `OpenSanitizer` | **Superseded** | Clean; aligned with `origin/main`; last commit 2024-10-31; successor is `openadapt-privacy`; references are historical/inventory | Add a successor notice, explicitly retire/archive the repository, then relocate to `_deprecated/OpenSanitizer` |
| `OpenReflector` | **Historical** | Clean; aligned with `origin/main`; last commit 2024-10-31; earlier computer-use mirroring direction; references are historical/inventory | Decide Archive versus Labs. Only use `_deprecated/OpenReflector` if Archive is chosen. |
| `OpenAdapter` | **Historical** | Clean; aligned with `origin/main`; last commit 2024-11-02; earlier model-deployment/training direction; no runtime references | Decide Archive versus Labs. Only use `_deprecated/OpenAdapter` if Archive is chosen. |

### Duplicate Checkout Cleanup

| Local checkout | Evidence | Recommended action |
|----------------|----------|--------------------|
| `openadapt-hosted` | Clean; aligned with `origin/main`; same `openadapt-cloud` remote; HEAD is an ancestor of the active checkout | This is not a deprecated repository. After confirming no unique local objects, either remove the duplicate clone or park it under `_deprecated/_duplicate-checkouts/openadapt-hosted`; never archive `openadapt-cloud` because of this local duplicate. |

### Relocation Blocked

| Local checkout | Intended lifecycle | Blocker before move |
|----------------|--------------------|---------------------|
| `openadapt-agent` | **Deprecated** | Modified `CLAUDE.md`; preserve or discard intentionally. No `openadapt_agent` runtime imports were found outside the repository; most name matches are the unrelated Azure resource group `openadapt-agents`. |
| `openadapt-new` | **Archived** | Modified tracked files plus untracked migration/test artifacts. README already declares it archived. Preserve the local work before moving. |
| `openadapt-bootstrap` | **Internal/Labs, archive candidate** | Eight untracked redesign documents and five cross-workspace references, including active website package discovery. Decide whether Wright supersedes it, preserve artifacts, then remove discovery references. |
| `openadapt-maintenance` | **Internal duplicate checkout** | Clean tree, but checked out on a pushed held-docs branch with unique branch work. It shares the `openadapt-ops` remote; finish or merge the branch before deduplicating the checkout. Do not classify `openadapt-ops` as deprecated. |
| `PydanticPrompt` | **Labs** | Modified source/tests and multiple swap/cache files. Preserve work; relocate to Labs rather than `_deprecated` if maintained. |
| `OmniMCP` (`omnimcp`) | **Labs** | Multiple modified source files and extensive untracked experiment artifacts. `openadapt-types` has a compatibility test reference. Preserve and decouple before relocation. |
| `SoM` | **Labs/fork** | Extensive untracked artifacts, including `openadapt-key.pem` and `cirun_accessKeys.csv`. Treat as a credential incident: do not move, print, or commit these files; verify revocation/rotation first. |
| `openadapt-tray` | **Experimental UI** | Active hosted-loop branch with untracked docs/scripts; recent work and references from desktop. Not deprecated. |
| `openadapt-viewer` | **Internal support** | Large dirty feature tree with active work. Not deprecated. |

### Do Not Move to `_deprecated`

- `openadapt-flow-*` and `openadapt-web-wt-*` directories are registered Git
  worktrees. Retire them with `git worktree remove` only after their branches are
  merged or intentionally abandoned; moving their directories would corrupt
  worktree bookkeeping.
- `openadapt-cloud`, `openadapt-desktop`, `openadapt-console`, and
  `openadapt-verifier` contain current experimental work. Their maturity must be
  visible, but they are not archive candidates.
- Presenter, Herald, Crier, Consilium, Wright, telemetry, YC, and internal
  strategy repositories should be separated from the public product surface,
  not mislabeled as deprecated local code.

## Archive Procedure

1. Preserve or intentionally discard every tracked and untracked local change.
2. Confirm the branch is pushed and record the final commit.
3. Replace the repository README opening with an archive notice and a link to
   `openadapt-flow` or the named successor.
4. Remove active package discovery, CI, dependency, and documentation references.
5. Move the local checkout only after steps 1-4; then archive the GitHub
   repository and remove it from organization pins.

## Non-Executing Relocation Preflight

The following commands perform checks and print the proposed relocation for the
only ready checkout. They do **not** create `_deprecated`, move files, remove a
worktree, or change GitHub settings.

```bash
SRC=/Users/abrichr/oa/src/openadapt-gitbook
DST=/Users/abrichr/oa/src/_deprecated/openadapt-gitbook

test -d "$SRC/.git"
test ! -e "$DST"
test -z "$(git -C "$SRC" status --porcelain --untracked-files=all)"
test "$(git -C "$SRC" rev-parse HEAD)" = \
  "$(git -C "$SRC" rev-parse '@{upstream}')"
git -C "$SRC" remote -v
git -C "$SRC" log -1 --format='verified commit: %H %cs %s'
printf 'PREVIEW ONLY: %s -> %s\n' "$SRC" "$DST"
```

Before a separately approved move:

1. Confirm `/Users/abrichr/oa/src` is the intended workspace, not `~/os/src`.
2. Re-run the preflight immediately before relocation.
3. Record the verified commit shown by the preflight.
4. Confirm the repository has an archive notice and no active discovery,
   dependency, CI, or documentation role.
5. Obtain explicit approval for the filesystem move and GitHub archive action.
