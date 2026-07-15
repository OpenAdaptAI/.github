# OpenAdapt Public Launch Plan

Last reviewed: 2026-07-15

## Objective

Launch the real hosted OpenAdapt product end to end. Development mocks may
remain available, but production execution, billing, artifact handling, and run
status must be backed by configured live services. A simulated run must never
be reported as a production success.

## Launch Gate

The launch candidate is accepted only when a clean account can complete this
workflow against production-like infrastructure:

1. Create an account and organization.
2. Select and purchase the configured plan through Stripe Checkout.
3. Record or import a workflow.
4. Produce a sanitized derivative, review it when policy requires, and approve
   its exact content hash.
5. Compile, lint, and certify the workflow.
6. Execute it through a real configured runner.
7. Receive authenticated callbacks and inspect the report and audit trail.
8. Halt on induced failure, teach or repair the workflow locally, validate and
   activate the replacement on the same hosted workflow, and rerun it.
9. Confirm entitlement, usage, and billing state.
10. Confirm that missing production dependencies cannot fall back to simulated
    success.

## Workstreams

| Workstream | Required outcome |
|---|---|
| Cloud mode | Explicit development/mock and production/live behavior with production dependency validation |
| Execution | Real storage, queue/runner dispatch, authenticated callbacks, reports, retries, resume, and failure recovery |
| Billing | Stripe test/live support, configured products and prices, checkout, portal, signed idempotent webhooks, entitlements, and usage metering |
| Artifact privacy | Type-complete sanitized derivatives, local review and correction, verification, manifest, and exact-hash approval |
| Runtime data | Parameters and secrets separated from templates; PHI-bearing observations retained inside the declared trusted boundary |
| Product surfaces | Website, docs, launcher, cloud, and GitHub profile describe the same shipped scope without invented claims or prices |
| Evidence | Bounded subsystem tests plus the clean-account production-like launch lifecycle |

## Fourteen-Step Execution Plan

1. Establish one public product description and canonical repository path.
2. Label every public component with an evidence-backed lifecycle state.
3. Freeze the launch substrate to the browser workflow until its complete gate
   passes; keep other backends visibly Experimental or Research.
4. Prove clean-machine install, record, compile, lint, certify, replay, induced
   drift, report inspection, and uninstall on every claimed operating system.
5. Produce sanitized derivatives from immutable source copies, inventory every
   file, refuse unsupported content, rescan, review locally, and approve exact
   hashes.
6. Bind runnable upload to source and bundle hashes, compiler/configuration,
   parameter schema, strict lint, certification, risk class, replay evidence,
   target boundary, one-time challenge, and deployment allowlists.
7. Make production mode explicit and validate every live dependency at
   readiness; never substitute simulated execution when configuration is
   absent.
8. Complete Stripe Checkout, portal, signed idempotent webhooks, subscription
   linkage, entitlements, metering, cancellation, and refund verification.
9. Dispatch immutable bundle/version/validation snapshots to the real runner;
   authenticate callbacks, verify downloaded bytes, isolate runtime parameters
   and secrets, require request idempotency and single-flight dispatch, retain
   ambiguous acknowledgements for operator reconciliation, reconcile only
   provably abandoned work, and meter terminal outcomes exactly once.
10. Complete governed failure handling: structured halt reports, local teaching
    or repair, validated replacement activation, checkpoint/resume, and rerun.
11. Publish the actual enterprise data boundary, threat model, credential and
    log handling, update/rollback design, audit limitations, and regulated
    deployment responsibilities.
12. Align the website, canonical journey-first docs, launcher, desktop surfaces,
    pricing, organization profile, examples, and lifecycle registry.
13. Run the clean-account production lifecycle, provider probes, nightly
    cross-platform lifecycle, real purchase/refund, backup/restore, incident,
    and one high-value fail-closed workflow qualification; release only the
    substrate that passes.
14. Publish reproducible evaluation artifacts, failure taxonomy, limitations,
    and an arXiv paper after author, disclosure, licensing, sanitized-artifact,
    release-identity, and evidence checks pass.

## Artifact And PHI Contract

- Scrubbing transforms a copy and never mutates the source artifact.
- Every file is inventoried and must have an explicit transformer or exclusion;
  unknown or unsuccessfully processed content is refused.
- The sanitized derivative is rescanned and accompanied by a versioned manifest
  containing source/result hashes, transformations, findings, and policy.
- Recordings and bundles containing or suspected of containing PHI require
  local review by default. Review can add redactions or reject the derivative.
- Approval is bound to the exact derivative hash. A later change requires new
  approval.
- Schema-minimized break reports may use an automatic policy.
- Automatic artifact approval is disabled by default. A deployment operator
  may enable it only for a fully covered, reviewed sanitizer policy; an upload
  request cannot enable that capability. Automatic approval must be signed by a
  deployment-controlled key in an explicit allowlist over the exact artifact
  and approval envelope; the ingest token alone is not sufficient.
- Sanitizing design-time artifacts does not sanitize live execution. Runtime
  screenshots or observations that reintroduce PHI remain inside the declared
  customer, BYOC, on-prem, or regulated managed boundary.

## Publication Order

1. Engine artifact policy and sanitized-derivative implementation.
2. Cloud live execution, production health, and billing.
3. Canonical product documentation and security architecture.
4. Website launch, checkout, and configured pricing surfaces.
5. Reproducible evaluation artifacts and failure taxonomy.
6. arXiv paper with methodology, identity/effect/refusal design, comparative
   evidence, silent incorrect success, over-halt, limitations, and a
   reproducibility checklist. Missing results must remain explicitly pending.
7. GitHub organization descriptions, pins, and lifecycle registry.
8. Repository archival and local relocation only after independent clean-tree,
   credential, dependency, and worktree checks.

## Evidence Standard

- Comparative claims require at least three trials per task and condition.
- Results must name the task, environment, oracle, run count, failure taxonomy,
  authoring effort, maintenance interventions, latency, model calls, cost,
  silent incorrect success, over-halt, and recovery time.
- Mock, synthetic, analog, and real-application results must be labeled
  separately.
- Code presence and a green UI are not evidence of a live remote execution.
- The arXiv paper and marketing pages may cite only checked-in, reproducible
  results and must preserve the limitations disclosed by the engine.

## Scope Control

Launch only the backends that pass the complete gate. Other backends remain
visible with their measured maturity. Do not add repositories or unrelated
features before the launch gate passes. Do not move dirty, credential-bearing,
or registered-worktree directories into `_deprecated`.
