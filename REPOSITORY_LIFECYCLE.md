# OpenAdapt Repository Lifecycle Registry

Last reviewed: 2026-09-02

This public registry separates the product from experiments and records the
intended lifecycle of organization repositories. It does not authorize moving
a local directory or archiving a GitHub repository by itself. Machine-local
checkout state and credential-response details belong in private operations
records, not in this public repository.

The machine-readable source is [`repository-lifecycle.yml`](repository-lifecycle.yml).

## Lifecycle Definitions

| Status | Meaning |
|--------|---------|
| **Production** | Exact latest release in the signed Production channel with an active, unexpired, non-revoked, independently attested acceptance admission |
| **Support** | Current public dependency or operational tool |
| **Beta** | Active product surface with compatibility intent, but not a blanket production-readiness claim |
| **Experimental** | Active prototype or optional component with no production support promise |
| **Research** | Evidence-generating work, not required by the product runtime |
| **Internal** | Team tooling or private strategy, not a public product surface |
| **Labs** | Standalone experiment, fork, or adjacent library; not automatically deprecated |
| **Historical** | Earlier direction retained for context; retirement still requires an explicit decision |
| **Superseded** | Functionality has a named successor; new integrations use the successor |
| **Deprecated** | Superseded; migration fixes only, no new integrations |
| **Archived** | Historical and read-only |

## Production Admission

Production is a derived per-release state. It is not a static repository label.
A person cannot create it by changing a table or repository description. The canonical
[`production-lifecycle-policy.json`](production-lifecycle-policy.json) names
the seven eligible targets and their required release artifacts. The
[`production-lifecycle-admissions.json`](production-lifecycle-admissions.json)
file contains only admissions that pass the machine validator.

Each admission binds the exact public package release or deployment identity,
the complete required artifact inventory and hashes, and an independently
attested remote-safe evidence summary. The summary binds the private Cloud
acceptance certificate by schema, digest, and signer-provenance digest. It does
not publish the private certificate or its location. The summary also binds an
immutable public evidence-manifest URL and digest. A private Cloud deployment
uses an opaque release identity and digest. It does not require a public source
or artifact URL. Public artifacts use a pinned authority. The validator checks
current PyPI metadata, immutable GitHub release metadata, or content-addressed
managed evidence before it derives Production.

The signer-provenance digest uses the domain `OpenAdapt production certificate
signer provenance v1\0`. Its canonical input is the normalized, verified Cloud
GitHub provenance plus the qualification admission signer-registry digest and
revision. The private v2 evidence identity must bind the exact target release
or deployment and its complete artifact inventory. Each target has a distinct
claim scope. Evidence for one target cannot admit a different target. The
public evidence manifest must bind the same target, scope, policy, release,
artifact inventory, evidence identity, qualification, failure taxonomy,
reliability counts, oracle, trial inventory, and immutable retention record.

A qualified workflow is one exact compiled workflow version that passed its
declared qualification contract on its bound execution environment. The signed
qualification identity binds the workflow bundle, runtime release, dependency
set, environment, input schema, policy, required identity checks, required
effect checks, and verification rules. A run gate must reject an absent,
expired, revoked, or mismatched qualification. A new workflow version or a
change to a bound input requires a new qualification. A Production runtime must
accept only these exact qualified workflow identities.

Each target has an append-only hash chain of signed Production release
identities. The highest sequence is current. A new release cannot reuse an old
release identity. If the latest admission expires or is revoked, Production is
empty for that target. The validator does not fall back to an older release.
Static Production membership is forbidden. Consumers derive current Production
at read time from the signed admission, its expiry, and its revocation state.

## Admission-Gated Targets

The seven product targets do not have fallback lifecycle labels. A target that
doesn't have a current admission is **not actively admitted**. Expiry,
revocation, release drift, an authority failure, or missing evidence produces
the same state. The validator never restores an older admission or replaces
the state with Beta, Experimental, or Early access.

The signed ledger currently has an active remote-safe-synthetic admission for
each of the seven targets. Product-wide Production is true only while all
seven stay active. These admissions are not a MockMed
`production_acceptance` flip. Native Desktop Apple and Windows installers
remain unsigned and are not required. These are the derived states:

| Target | Current state | Role |
|------------|-----------|------|
| `openadapt` | **Production** | `OpenAdapt` launcher/meta-package and unified CLI |
| `flow` | **Production** | `openadapt-flow` compiler and governed runtime |
| `cloud` | **Production** | Proprietary control plane and hosted execution surface |
| `desktop` | **Production** | Desktop recording, qualification, execution, evidence, and repair cockpit |
| `capture` | **Production** | Native screen, input, timing, window, and media capture |
| `agent` | **Production** | Local MCP and Agent Skills bridge for governed Flow workflows |
| `docs` | **Production** | `docs.openadapt.ai` deployment sourced from `openadapt-ops` |

## Other Repository Lifecycles

| Group | Repositories |
|-------|--------------|
| **Support** | `.github`, `openadapt-web`, `openadapt-ops`, `openadapt-wright`, `openadapt-herald`, `openadapt-crier`, `openadapt-consilium`, `openadapt-telemetry`, `openadapt-viewer`, `openadapt-blog` |
| **Experimental** | `openadapt-privacy`, `openadapt-types`, `openadapt-console`, `openadapt-tray` |
| **Research** | `openadapt-ml`, `openadapt-evals`, `openadapt-retrieval`, `openadapt-grounding`, `openadapt-verifier` |
| **Internal** | `openadapt-bootstrap`, `openadapt-internal`, `openadapt-yc`, `openadapt-presenter` |
| **Labs/forks** | `OmniMCP` (`omnimcp` locally), `SoM`, `PydanticPrompt` |
| **Archived historical directions** | `OpenAdapter`, `OpenReflector` |
| **Superseded** | `OpenSanitizer` (successor: `openadapt-privacy`) |

## Retirement Queue

| Repository | Lifecycle | Public action |
|------------|-----------|---------------|
| `openadapt-gitbook` | **Archived** | Keep an archive notice and route documentation traffic to `docs.openadapt.ai`. |
| `openadapt-new` | **Archived** | Keep read-only historical context and route product traffic to `OpenAdapt` and `openadapt-flow`. |
| `OpenSanitizer` | **Superseded** | Add a successor notice for `openadapt-privacy`, then decide whether to archive. |
| `OpenReflector` | **Archived** | Retain its read-only history and route product traffic to `OpenAdapt` and `openadapt-flow`. |
| `OpenAdapter` | **Archived** | Retain its read-only history and route product traffic to `OpenAdapt` and `openadapt-flow`. |

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
