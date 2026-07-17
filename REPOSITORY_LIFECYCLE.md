# OpenAdapt Repository Lifecycle Registry

Last reviewed: 2026-07-15

This public registry separates the product from experiments and records the
intended lifecycle of organization repositories. It does not authorize moving
a local directory or archiving a GitHub repository by itself. Machine-local
checkout state and credential-response details belong in private operations
records, not in this public repository.

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
| **Internal** | `openadapt-ops`, `openadapt-wright`, `openadapt-herald`, `openadapt-crier`, `openadapt-consilium`, `openadapt-presenter`, `openadapt-bootstrap`, `openadapt-telemetry`, `openadapt-viewer`, `openadapt-blog`, `openadapt-internal`, `openadapt-yc` |
| **Experimental UI/support** | `openadapt-console`, `openadapt-tray`, `openadapt-agent` |
| **Labs/forks** | `OmniMCP` (`omnimcp` locally), `SoM`, `PydanticPrompt` |
| **Historical directions** | `OpenAdapter`, `OpenReflector` |
| **Superseded** | `OpenSanitizer` (successor: `openadapt-privacy`) |

## Retirement Queue

| Repository | Lifecycle | Public action |
|------------|-----------|---------------|
| `openadapt-gitbook` | **Archived** | Keep an archive notice and route documentation traffic to `docs.openadapt.ai`. |
| `openadapt-new` | **Archived** | Keep read-only historical context and route product traffic to `OpenAdapt` and `openadapt-flow`. |
| `openadapt-agent` | **Experimental (repurposed v2)** | Agent-facing bridge: compiled `openadapt-flow` workflows exposed as MCP tools and Agent Skills; governed runs only. Legacy v1 at tag `v0.1.0`. |
| `OpenSanitizer` | **Superseded** | Add a successor notice for `openadapt-privacy`, then decide whether to archive. |
| `OpenReflector` | **Historical** | Decide Archive versus Labs before changing organization state. |
| `OpenAdapter` | **Historical** | Decide Archive versus Labs before changing organization state. |

Experimental, Research, Labs, and Internal repositories are not deprecated by
default. Moving local checkouts is a separate operational decision that must
use private, current evidence.

## Archive Procedure

1. Preserve or intentionally discard every tracked and untracked local change.
2. Confirm the branch is pushed and record the final commit in private
   operations evidence.
3. Replace the repository README opening with an archive notice and a link to
   `openadapt-flow` or the named successor.
4. Remove active package discovery, CI, dependency, and documentation references.
5. Move the local checkout only after steps 1-4; then archive the GitHub
   repository and remove it from organization pins.

Before a separately approved local move, re-run clean-tree, upstream, dependency,
credential, destination, and registered-worktree checks without publishing
machine-specific findings here.
