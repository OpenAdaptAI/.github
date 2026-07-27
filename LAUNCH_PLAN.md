# OpenAdapt Launch Contract

Last reviewed: 2026-07-27

This is the durable public acceptance contract, not a chronological project
plan. Current progress, metrics, and provider state belong in the private
operating status. The product is not organized around a browser-only freeze:
browser, native desktop, RDP, and Citrix/VDI are execution surfaces under one
governed qualification contract.

## Product Outcome

OpenAdapt turns a bounded demonstration into an inspectable workflow, executes
healthy runs without model calls, verifies the declared business effect, and
halts for review when authorization, identity, state, target, or effect cannot
be proven.

The public launch path must let a user:

1. Install the launcher or Desktop cockpit.
2. Record a browser, native, RDP, or Citrix/VDI workflow using the canonical
   recorder for that surface.
3. Compile and inspect the workflow without editing internal JSON or Python.
4. Qualify risk, identity, effect strength, parameters, secrets, environment,
   and representative fault cases.
5. Certify, seal, encrypt, version, and deploy the exact artifact.
6. Execute it in managed or customer-controlled infrastructure with the
   required capabilities and data boundary.
7. Receive `VERIFIED`, `COMPLETED_UNVERIFIED`, `HALTED`, `FAILED`, or
   `ROLLED_BACK` with evidence; Standard and Regulated profiles never treat
   `COMPLETED_UNVERIFIED` as success.
8. Resolve attended decisions, validate repairs against the same qualification
   contract, promote or reject them, and roll back versions.
9. Inspect evidence, usage, billing, and immutable artifact lineage.

Production mode must use real configured dependencies. Missing storage,
runner, callback, verifier, billing, or authorization dependencies must fail
closed and must never produce simulated success.

## Surface Contract

- **Browser:** Playwright-native recording retains DOM identity, source-time
  secret redaction, field geometry, and ordered frames.
- **Native desktop:** `openadapt-capture` owns screen, input, timing, and
  window-scoped capture; live UIA, macOS Accessibility, or Linux AT-SPI evidence
  is retained at action time when available.
- **RDP and Citrix/VDI:** customer-controlled external black-box operation uses
  the same window-scoped capture path with OCR, relational anchors, identity
  regions, fresh-frame resolution, and two-phase consequential actuation. No
  software inside the remote session is required.
- **Cloud:** managed browser execution and the proprietary control plane support
  workflow, evidence, attended-operation, usage, and billing journeys.

Portable workflow intent remains separate from environment-specific bindings.
Every runner advertises its observation, actuation, identity, verification,
session, and security capabilities; admission refuses before actuation when the
selected runner cannot satisfy the artifact.

## Evidence Contract

- Comparative claims require at least three trials per task and condition.
- Results name the task, application, version, environment, oracle, run count,
  failure taxonomy, latency, model calls, silent incorrect success, and
  over-halt.
- Mock, synthetic, public-application, customer-qualified, and production
  evidence remain distinguishable.
- A screen banner or model judgment alone cannot produce `VERIFIED` for a
  consequential write.
- Artifact and live-observation privacy boundaries are evaluated separately;
  compiling a recording does not make it safe to upload.

The public website, documentation, launcher, engine, Desktop, Cloud, repository
descriptions, and organization profile must describe this same product.
