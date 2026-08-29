# OpenAdapt

**Automate the UI-only work your APIs can't reach.**

OpenAdapt compiles demonstrations into governed workflows across browser,
native desktop, RDP, and Citrix. The default healthy path executes
deterministically and makes no generative-model API calls. Consequential
actions are identity-gated, results are checked against the workflow's
evidence contract, and uncertainty halts for review instead of being reported
as success.

OpenAdapt is for repeated work trapped behind browser, desktop, and
virtual-desktop interfaces: too visual or variable for brittle selectors, but
too consequential to hand to a free-form computer-use agent on every run.

[Install OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt) ·
[Watch the live demo](https://app.openadapt.ai/demo) ·
[Read the docs](https://docs.openadapt.ai) ·
[Visit openadapt.ai](https://openadapt.ai/)

The installer is [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt).
The canonical engine is
[`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow).

## Start Locally

```bash
python -m pip install --upgrade 'openadapt[browser]'
openadapt quickstart
```

This runs the bundled MockMed lifecycle. It records, compiles, certifies,
replays, independently verifies the synthetic effect, and writes a
human-readable `REPORT.md`. Use the
[five-minute guide](https://docs.openadapt.ai/get-started/) to add lint, drift,
repair, and deployment.

## Evidence

Published head-to-head comparisons, each graded by an external success check
that is independent of every arm:

- **Live third-party EMR** (OpenEMR public demo, fake patients, 18-step
  add-patient-note workflow): compiled replay went **19/20 at 39.2s p50 with
  zero model calls**; the agent went 10/10 at 70.4s p50 at about $0.55 of model
  charge per run. Compiled run 20 didn't pass. The saved-row oracle, tightened
  on 2026-07-28, refuses to count a note still sitting in the unsaved entry
  form, and the replayer had already halted at step 17 rather than press on.
  Small sample on a shared, daily-resetting demo — not CI-reproducible.
  [Methodology and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/openemr/BENCHMARK.md).
- **Historical MockMed control** (bundled task): retained rows marked 100/100
  compiled runs and 20/20 agent runs successful under the 2026-07-08 OCR
  check. The final frames were not retained, so the current verifier cannot
  rescore those outcomes. Use these rows only for latency and estimated model
  API charge comparison. The compiled arm recorded 4.9s p50 and $0 per run in
  model API charges; the agent arm recorded 37.5s p50 and about $0.27 per run.
  [Methodology and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/BENCHMARK.md).
- **Independent effect verification** (fault-injection study, 90 runs per arm,
  end to end through the real replayer into an on-disk SQLite system of record,
  graded by a direct read-only database connection that bypasses the service):
  a screen-only "success banner" oracle silently accepted **75.0%** of the wrong
  effects that actually occurred (54 of 90 runs). Adding **one** out-of-band
  verifier that reads the system of record cut that to **12.5%** (9 of 90). A
  complete read path over every mutable surface reaches 0 of 90, but the
  realistic deployment number is the middle rung — one out-of-band oracle — not
  the 0%. All nine residual misses are a single named class: a collateral write
  to a surface the oracle does not read. Every run terminates in an explicit
  transaction outcome (VERIFIED, HALTED_BEFORE_EFFECT,
  RECONCILIATION_REQUIRED, and others), so uncertain delivery is surfaced for
  reconciliation, never reported as success.
  [Methodology and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/effect_e2e/EFFECT_E2E.md).

The recorded zero model API calls mean no generative-model API charge for that
benchmark run. The figure excludes authoring, review, maintenance, and
infrastructure, and it is not a production-reliability or clinical-safety
claim. Read the
[limits](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md)
before extrapolating either result.

## Product Surfaces

| Target | Role |
|---|---|
| `openadapt` | [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt) installs the unified CLI. |
| `flow` | [`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow) is the canonical compiler and governed runtime. |
| `cloud` | [`app.openadapt.ai`](https://app.openadapt.ai/) provides the control plane for managed browser and customer-controlled execution. Its implementation repository is private. |
| `desktop` | [`openadapt-desktop`](https://github.com/OpenAdaptAI/openadapt-desktop) provides local recording, qualification, execution, evidence review, and governed repair. |
| `capture` | [`openadapt-capture`](https://github.com/OpenAdaptAI/openadapt-capture) records native screen, input, timing, and window-scoped evidence for Desktop and Flow. |
| `agent` | [`openadapt-agent`](https://github.com/OpenAdaptAI/openadapt-agent) exposes governed Flow workflows as local MCP tools and Agent Skills. |
| `docs` | [`docs.openadapt.ai`](https://docs.openadapt.ai) is the canonical documentation site. [`openadapt-ops`](https://github.com/OpenAdaptAI/openadapt-ops) is its **Support** publishing source. |

[`openadapt-evals`](https://github.com/OpenAdaptAI/openadapt-evals) is a
Research repository. Runnable references live in
[`openadapt-flow/docs/showcase`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/docs/showcase),
with methods and evidence under
[`benchmark`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/benchmark).

These targets form one product across browser, Windows, macOS, Linux, RDP, and
Citrix/VDI. Qualification is per workflow, not a blanket Production claim.
Current signed admissions are in the
[live record](https://docs.openadapt.ai/production-lifecycle.json).

## Research and Labs

Model training, retrieval, grounding, and general computer-use work remain
Research: [`openadapt-ml`](https://github.com/OpenAdaptAI/openadapt-ml),
[`openadapt-retrieval`](https://github.com/OpenAdaptAI/openadapt-retrieval), and
[`openadapt-grounding`](https://github.com/OpenAdaptAI/openadapt-grounding).
They are not required for healthy deterministic replay.

OmniMCP, SoM, and PydanticPrompt are **Labs**, not product dependencies.
Historical, Superseded, Deprecated, Archived, and Internal repositories are
classified in the public
[lifecycle registry](https://github.com/OpenAdaptAI/.github/blob/main/REPOSITORY_LIFECYCLE.md)
rather than presented as the product.

## Contribute

Product-engine changes belong in
[`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow). Packaging and
launcher changes belong in [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt).
Use each repository's issues for scoped work, or visit
[`openadapt.ai`](https://openadapt.ai/) for deployment inquiries.

Unless a repository says otherwise, OpenAdapt code is MIT licensed.
